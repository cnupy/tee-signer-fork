package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	cloud "github.com/lidofinance/tee-signer/signer-protocol"
)

// ssvCluster is an SSV cluster made here: validators split 3 of 4 with
// share i at operator ids[i], the operators' RSA keys, and the keyshares
// file that encrypts each share to its operator.
type ssvCluster struct {
	ids     []uint64
	groups  []cloud.Pubkey
	secrets [][][32]byte
	ops     []*rsa.PrivateKey
}

func newSSVCluster(t *testing.T, vals int, ids ...uint64) *ssvCluster {
	t.Helper()
	c := &ssvCluster{ids: ids}
	for range vals {
		sk, err := software.NewSecret()
		if err != nil {
			t.Fatal(err)
		}
		pk, err := core.PubkeyOf(sk)
		if err != nil {
			t.Fatal(err)
		}
		shares, _, err := software.SplitAt(sk, 3, ids)
		if err != nil {
			t.Fatal(err)
		}
		var secs [][32]byte
		for _, s := range shares {
			secs = append(secs, s.Secret)
		}
		c.groups, c.secrets = append(c.groups, pk), append(c.secrets, secs)
	}
	for range ids {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		c.ops = append(c.ops, k)
	}
	return c
}

func (c *ssvCluster) sharePub(t *testing.T, v, i int) cloud.Pubkey {
	t.Helper()
	pk, err := core.PubkeyOf(c.secrets[v][i])
	if err != nil {
		t.Fatal(err)
	}
	return pk
}

// keyshares writes the keyshares file; change, if set, edits each
// validator's shares data first.
func (c *ssvCluster) keyshares(t *testing.T, path string, change func(data []byte)) string {
	t.Helper()
	var shares []any
	for v := range c.groups {
		data := make([]byte, 96)
		for i := range c.ids {
			pk := c.sharePub(t, v, i)
			data = append(data, pk[:]...)
		}
		for i := range c.ids {
			ct, err := rsa.EncryptPKCS1v15(rand.Reader, &c.ops[i].PublicKey, fmt.Appendf(nil, "0x%x", c.secrets[v][i]))
			if err != nil {
				t.Fatal(err)
			}
			data = append(data, ct...)
		}
		if change != nil {
			change(data)
		}
		shares = append(shares, map[string]any{"payload": map[string]any{
			"publicKey": c.groups[v].String(), "operatorIds": c.ids, "sharesData": fmt.Sprintf("0x%x", data)}})
	}
	return writeJSONFile(t, path, map[string]any{"shares": shares})
}

// opKeyFile writes operator i's key as ssv-node's unencrypted form.
func (c *ssvCluster) opKeyFile(t *testing.T, path string, i int) string {
	t.Helper()
	p := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(c.ops[i])})
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(p)), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// opKeystoreFile writes operator i's key as ssv-node's encrypted keystore
// (keystorev4 crypto at the top level over the PEM) and its password file.
func (c *ssvCluster) opKeystoreFile(t *testing.T, path string, i int) (string, string) {
	t.Helper()
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(c.ops[i])})
	salt, iv := make([]byte, 32), make([]byte, 16)
	rand.Read(salt)
	rand.Read(iv)
	dk, err := pbkdf2.Key(sha256.New, "op-password", salt, 1024, 32)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := aes.NewCipher(dk[:16])
	ct := make([]byte, len(pemKey))
	cipher.NewCTR(blk, iv).XORKeyStream(ct, pemKey)
	sum := sha256.Sum256(append(slices.Clone(dk[16:]), ct...))
	pub, err := x509.MarshalPKIXPublicKey(&c.ops[i].PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	writeJSONFile(t, path, map[string]any{
		"kdf":      map[string]any{"function": "pbkdf2", "params": map[string]any{"dklen": 32, "c": 1024, "prf": "hmac-sha256", "salt": hex.EncodeToString(salt)}, "message": ""},
		"checksum": map[string]any{"function": "sha256", "params": map[string]any{}, "message": hex.EncodeToString(sum[:])},
		"cipher":   map[string]any{"function": "aes-128-ctr", "params": map[string]any{"iv": hex.EncodeToString(iv)}, "message": hex.EncodeToString(ct)},
		"pubkey":   operatorPublicText(pub),
	})
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, writeFile(t, path+".password", "op-password\n")
}

// noSecretChecks lets ssv-split write its shares file outside tmpfs, with
// no swap whatever the test host has.
func noSecretChecks(t *testing.T, dir string) {
	t.Helper()
	oldFS, oldSwaps := splitOutFS, splitSwaps
	t.Cleanup(func() { splitOutFS, splitSwaps = oldFS, oldSwaps })
	splitOutFS = func(string) error { return nil }
	splitSwaps = writeFile(t, filepath.Join(dir, "swaps"), "Filename\tType\tSize\tUsed\tPriority\n")
}

// ssv-split checks a keyshares file and decrypts one operator's shares,
// from a PEM key or from ssv-node's encrypted keystore. A file that fails
// writes nothing.
func TestSSVSplit(t *testing.T) {
	dir := t.TempDir()
	noSecretChecks(t, dir)
	c := newSSVCluster(t, 3, 1, 2, 3, 4)
	ks := c.keyshares(t, filepath.Join(dir, "keyshares.json"), nil)
	key := c.opKeyFile(t, filepath.Join(dir, "op2.key"), 1)
	ksKey, pw := c.opKeystoreFile(t, filepath.Join(dir, "op2.json"), 1)
	for _, k := range [][]string{{"-operator-key", key}, {"-operator-key", ksKey, "-password-file", pw}} {
		splitPath, sharesPath := filepath.Join(t.TempDir(), "split.json"), filepath.Join(t.TempDir(), "shares.txt")
		args := append([]string{"ssv-split", "-keyshares", ks, "-operator-id", "2", "-signer", "d1", "-out", splitPath, "-shares", sharesPath}, k...)
		wantIn(t, mustTool(t, args...), "3 validators of operator 2, 3 of 4")
		sf, err := readSplit(splitPath)
		if err != nil || sf.Shares["d1"] != 2 || len(sf.Validators) != 3 || sf.Validators[1].Pubkey != c.groups[1] {
			t.Fatalf("split: %+v, %v", sf, err)
		}
		shares, err := readShares(sharesPath)
		if err != nil || len(shares) != 3 || shares[0].pubkey != c.groups[0] || shares[0].sharePub != c.sharePub(t, 0, 1) || shares[0].secret != c.secrets[0][1] {
			t.Fatalf("shares file: %v", err)
		}
	}

	wrongPw := writeFile(t, filepath.Join(dir, "wrong.password"), "wrong\n")
	bad := c.keyshares(t, filepath.Join(dir, "bad.json"), func(data []byte) { data[96+48*3+5] ^= 1 })
	other := c.opKeyFile(t, filepath.Join(dir, "op3.key"), 2)
	var f struct{ Shares []any }
	if raw, err := os.ReadFile(ks); err != nil || json.Unmarshal(raw, &f) != nil {
		t.Fatal(err)
	}
	twice := writeJSONFile(t, filepath.Join(dir, "twice.json"), map[string]any{"shares": append(f.Shares, f.Shares[0])})
	for _, x := range []struct {
		name string
		args []string
		want string
	}{
		{"another operator's key", []string{"-keyshares", ks, "-operator-key", other}, "does not decrypt"},
		{"a wrong keystore password", []string{"-keyshares", ks, "-operator-key", ksKey, "-password-file", wrongPw}, "checksum mismatch"},
		{"a share key off the polynomial", []string{"-keyshares", bad, "-operator-key", key}, "not on the polynomial"},
		{"a validator listed twice", []string{"-keyshares", twice, "-operator-key", key}, "listed twice"},
		{"an operator of no validator", []string{"-keyshares", ks, "-operator-key", key, "-operator-id", "9"}, "no validator has operator 9"},
	} {
		splitPath, sharesPath := filepath.Join(t.TempDir(), "split.json"), filepath.Join(t.TempDir(), "shares.txt")
		args := append([]string{"ssv-split", "-operator-id", "2", "-signer", "d1", "-out", splitPath, "-shares", sharesPath}, x.args...)
		wantIn(t, failTool(t, args...), x.want)
		for _, p := range []string{splitPath, sharesPath} {
			if _, err := os.Stat(p); err == nil {
				t.Fatalf("%s: %s written", x.name, p)
			}
		}
	}
}
