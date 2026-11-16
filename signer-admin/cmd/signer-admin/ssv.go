package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	adminapprover "github.com/lidofinance/tee-signer/signer-admin/approver"
	"github.com/lidofinance/tee-signer/signer-admin/internal/lockdown"
	remoteadmin "github.com/lidofinance/tee-signer/signer-admin/remote/admin"
	"github.com/lidofinance/tee-signer/signer-core/core"
	cloud "github.com/lidofinance/tee-signer/signer-protocol"
)

// ---- SSV: the operator key and the split of a keyshares file ----
//
// A dv_share signer behind an SSV node holds the operator's share of each
// validator and the operator's RSA key (gateway ssv_api). ssv-operator-key
// imports the key; ssv-split turns a keyshares file (ssv-keys, SSV DKG)
// into the split and shares files of the dv_share import. In a keyshares
// file each validator's shares data is the owner's signature (96 bytes),
// the n share public keys (48 bytes each) and the n shares encrypted to
// the operators' RSA keys, in the order of the operator IDs; a share's x
// coordinate is its operator's ID, and t is n - (n - 1) / 3.

// readOperatorKey reads an SSV operator key: ssv-node's encrypted keystore
// (generate-operator-keys --password-file: the EIP-2335 crypto at the top
// level over the PEM) with its password file, base64 of the PEM block RSA
// PRIVATE KEY, or the PEM itself. It returns the key and its PKCS #1 DER,
// which the caller clears.
func readOperatorKey(path, passwordFile string) (*rsa.PrivateKey, []byte, error) {
	if err := adminapprover.CheckPrivateFile(path); err != nil {
		return nil, nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	defer clear(raw)
	data := bytes.TrimSpace(raw)
	switch {
	case bytes.HasPrefix(data, []byte("{")):
		if passwordFile == "" {
			return nil, nil, fmt.Errorf("%s is an encrypted keystore: -password-file is required", path)
		}
		pw, err := os.ReadFile(passwordFile)
		if err != nil {
			return nil, nil, err
		}
		defer clear(pw)
		var c keystoreCrypto
		if err := json.Unmarshal(data, &c); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", path, err)
		}
		if data, err = c.open(bytes.TrimSpace(pw), 0); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", path, err)
		}
		defer clear(data)
	case !bytes.HasPrefix(data, []byte("-----BEGIN")):
		dec := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
		defer clear(dec)
		n, err := base64.StdEncoding.Decode(dec, data)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: not an SSV operator key (keystore, base64 PEM or PEM)", path)
		}
		data = dec[:n]
	}
	blk, _ := pem.Decode(data)
	if blk == nil || blk.Type != "RSA PRIVATE KEY" {
		return nil, nil, fmt.Errorf("%s: want a PEM block of type RSA PRIVATE KEY", path)
	}
	k, err := x509.ParsePKCS1PrivateKey(blk.Bytes)
	if err != nil {
		clear(blk.Bytes)
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	return k, blk.Bytes, nil
}

// operatorPublicText is the operator public key as the SSV network shows
// it: base64 of the PEM block RSA PUBLIC KEY over the PKIX DER.
func operatorPublicText(der []byte) string {
	return base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: der}))
}

func cmdSSVOperatorKey(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("ssv-operator-key", flag.ContinueOnError)
	cf := addClusterFlags(fs)
	target := fs.String("signer", "", "the dv_share signer of cluster.json that takes the key")
	keyPath := fs.String("operator-key", "", "the SSV operator key: ssv-node's encrypted keystore, base64 PEM or PEM")
	pwPath := fs.String("password-file", "", "the password file of an encrypted keystore")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *target == "" || *keyPath == "" {
		return errors.New("usage: signer-admin ssv-operator-key -cluster cluster.json -signer NAME -operator-key FILE [-password-file FILE]")
	}
	if err := lockdown.Secrets(os.Stderr); err != nil {
		return err
	}
	k, der, err := readOperatorKey(*keyPath, *pwPath)
	if err != nil {
		return err
	}
	defer clear(der)
	*cf.only = *target
	c, err := cf.load()
	if err != nil {
		return err
	}
	m := c.members[0]
	if m.setup.SigningMode != setupwire.SigningModeDVShare {
		return fmt.Errorf("%s: signing_mode = %s; the operator key goes to a dv_share signer", m.name, m.setup.SigningMode)
	}
	cl, err := connectAdmin(m, *cf.timeout)
	if err != nil {
		return err
	}
	defer cl.Close()
	ctx, cancel := context.WithTimeout(context.Background(), *cf.timeout)
	defer cancel()
	pub, err := remoteadmin.Wrap(cl.Client).ImportOperatorKey(ctx, der, cl.Verify)
	if err != nil {
		return fmt.Errorf("%s: %w", m.name, err)
	}
	want, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		return err
	}
	if !bytes.Equal(pub, want) {
		return fmt.Errorf("%s answers another public key than the key sent", m.name)
	}
	fprintf(out, "%s holds the SSV operator key (%d bits)\npublic key: %s\n", m.name, k.N.BitLen(), operatorPublicText(pub))
	return nil
}

// keysharesFile is the part of a keyshares file that ssv-split reads.
type keysharesFile struct {
	Shares []struct {
		Payload struct {
			PublicKey   cloud.Pubkey `json:"publicKey"`
			OperatorIDs []uint64     `json:"operatorIds"`
			SharesData  string       `json:"sharesData"`
		} `json:"payload"`
	} `json:"shares"`
}

// ssvShareLine is the length of a shares file line: secret, validator
// key, no index, share key (the format split writes).
const ssvShareLine = len("0x") + 64 + len(" ") + 98 + len(" - ") + 98 + len("\n")

// ssvSplit reads a keyshares file into a split file for the operator opID,
// whose shares it decrypts with k, and the shares file's lines, which the
// caller clears. For each validator of the operator it computes the
// commitments from the first t share keys at the operator IDs and checks
// the validator key, every share key, and the decrypted share against
// them. Validators without the operator are left out.
func ssvSplit(path string, opID uint64, k *rsa.PrivateKey) (*splitFile, []byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var f keysharesFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	sf := &splitFile{}
	// Sized up front: a buffer that grew would leave secrets in the old one.
	lines := make([]byte, 0, ssvShareLine*len(f.Shares))
	fail := func(v int, format string, a ...any) (*splitFile, []byte, error) {
		clear(lines[:cap(lines)])
		return nil, nil, fmt.Errorf("%s: validator %d: "+format, append([]any{path, v}, a...)...)
	}
	seen := map[cloud.Pubkey]bool{}
	for i, s := range f.Shares {
		ids := s.Payload.OperatorIDs
		pos := slices.Index(ids, opID)
		if pos < 0 {
			continue
		}
		if seen[s.Payload.PublicKey] {
			return fail(i+1, "%s is listed twice", s.Payload.PublicKey)
		}
		seen[s.Payload.PublicKey] = true
		n := len(ids)
		if n < 4 || (n-1)%3 != 0 || !slices.IsSorted(ids) || len(slices.Compact(slices.Clone(ids))) != n || ids[0] == 0 {
			return fail(i+1, "operator IDs %v: want 3f + 1 distinct IDs above 0, ascending", ids)
		}
		switch {
		case sf.N == 0:
			sf.T, sf.N = uint8(n-(n-1)/3), uint8(n)
		case int(sf.N) != n:
			return fail(i+1, "%d operators, the validators before %d: run ssv-split per cluster size", n, sf.N)
		}
		data, err := hex.DecodeString(strings.TrimPrefix(s.Payload.SharesData, "0x"))
		if err != nil {
			return fail(i+1, "sharesData: want hex")
		}
		enc := (len(data) - 96 - 48*n) / n
		if enc <= 0 || len(data) != 96+(48+enc)*n {
			return fail(i+1, "sharesData of %d bytes for %d operators", len(data), n)
		}
		pubs := make([]cloud.Pubkey, n)
		for j := range pubs {
			copy(pubs[j][:], data[96+48*j:])
		}
		comm, err := groupCommitments(s.Payload.PublicKey, ids, pubs, int(sf.T))
		if err != nil {
			return fail(i+1, "%v", err)
		}
		plain, err := rsa.DecryptPKCS1v15(rand.Reader, k, data[96+48*n+enc*pos:96+48*n+enc*(pos+1)])
		if err != nil {
			return fail(i+1, "the share of operator %d does not decrypt under this operator key", opID)
		}
		var sec [32]byte
		h := bytes.TrimPrefix(plain, []byte("0x"))
		_, err = hex.Decode(sec[:], h)
		clear(plain)
		if err != nil || len(h) != 64 {
			return fail(i+1, "the decrypted share is not 32 bytes of hex")
		}
		// PubkeyOf takes the secret by value: one copy this code cannot clear.
		if got, err := core.PubkeyOf(sec); err != nil || got != pubs[pos] {
			clear(sec[:])
			return fail(i+1, "the decrypted share is not the share key of operator %d", opID)
		}
		lines = append(lines, "0x"...)
		lines = hex.AppendEncode(lines, sec[:])
		clear(sec[:])
		lines = append(lines, ' ')
		lines = append(lines, s.Payload.PublicKey.String()...)
		lines = append(lines, " - "...)
		lines = append(lines, pubs[pos].String()...)
		lines = append(lines, '\n')
		sf.Validators = append(sf.Validators, splitValidator{Pubkey: s.Payload.PublicKey, Commitments: comm})
	}
	if len(sf.Validators) == 0 {
		return nil, nil, fmt.Errorf("%s: no validator has operator %d", path, opID)
	}
	return sf, lines, nil
}

func cmdSSVSplit(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("ssv-split", flag.ContinueOnError)
	ksPath := fs.String("keyshares", "", "the keyshares file (ssv-keys or SSV DKG output)")
	opID := fs.Uint64("operator-id", 0, "this operator's SSV operator ID")
	keyPath := fs.String("operator-key", "", "the SSV operator key that decrypts this operator's shares (as for ssv-operator-key)")
	pwPath := fs.String("password-file", "", "the password file of an encrypted operator keystore")
	target := fs.String("signer", "", "the dv_share signer of cluster.json that takes this operator's shares")
	outPath := fs.String("out", "split.json", "the split file to write, for import-draft and import")
	sharesPath := fs.String("shares", "", "the shares file to write, for import: a new file of mode 0600 on tmpfs")
	allowSwap := fs.Bool("allow-swap", false, "go on with swap active (the share secrets can reach the disk)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *ksPath == "" || *opID == 0 || *keyPath == "" || *target == "" || *sharesPath == "" {
		return errors.New("usage: signer-admin ssv-split -keyshares FILE -operator-id ID -operator-key FILE [-password-file FILE] -signer NAME -shares FILE [-out split.json] [-allow-swap]")
	}
	if err := lockdown.Secrets(os.Stderr); err != nil {
		return err
	}
	if err := splitOutFS(filepath.Dir(*sharesPath)); err != nil {
		return err
	}
	if err := checkSwap(splitSwaps, *allowSwap); err != nil {
		return err
	}
	k, der, err := readOperatorKey(*keyPath, *pwPath)
	if err != nil {
		return err
	}
	clear(der)
	sf, lines, err := ssvSplit(*ksPath, *opID, k)
	if err != nil {
		return err
	}
	defer clear(lines[:cap(lines)])
	sf.Shares = map[string]uint64{*target: *opID}
	js, err := json.MarshalIndent(sf, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*sharesPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(lines); err != nil {
		f.Close()
		os.Remove(*sharesPath)
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.WriteFile(*outPath, append(js, '\n'), 0o644); err != nil {
		return err
	}
	fprintf(out, "ssv-split %s: %d validators of operator %d, %d of %d; every share key agrees with the commitments and with its decrypted share\nwrote %s and %s (secrets, mode 0600)\n",
		*ksPath, len(sf.Validators), *opID, sf.T, sf.N, *outPath, *sharesPath)
	return nil
}
