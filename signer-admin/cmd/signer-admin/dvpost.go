//go:build dvt

package main

// dv-exit-post: sends the partial exits of dv-exit files to the Obol API,
// on the Charon host, where the operator's Charon ENR key lives. Written
// from the public obol-sdk (MIT; src/exits/exit.ts, the checks the API
// runs) and the Obol API reference ("DV Exit"):
//
//	POST {api}/exp/partial_exits/{lock_hash}
//	{"partial_exits": [{"public_key": "0x<group key>", "signed_exit_message":
//	  {"message": {"epoch": "E", "validator_index": "I"}, "signature": "0x<partial>"}}],
//	 "share_idx": N, "signature": "0x<r || s || v>"}
//
// signature is a secp256k1 signature, with the ENR key of operator
// share_idx - 1 of the lock, of the SSZ hash tree root of
// {partial_exits, share_idx} (obolExitsRoot). The API checks it against
// the operator's ENR in the lock, and each partial against the lock's
// public share of that operator in the Capella exit domain. This tool
// checks the same before it sends anything.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"github.com/lidofinance/tee-signer/signer-core/core"
	cloud "github.com/lidofinance/tee-signer/signer-protocol"
)

// obolAPI is the Obol API that Charon and lido-dv-exit post to by default.
const obolAPI = "https://api.obol.tech/v1"

// maxPartialExits is the length limit of partial_exits in the SSZ type
// the request's signature covers.
const maxPartialExits = 65536

// exitChains are the chains whose exit domain this tool knows by the
// lock's fork_version: the Capella fork version (EIP-7044) and the
// genesis validators root (obol-sdk EXIT_NETWORKS;
// governance/chains/mainnet.json and hoodi.json). Another chain needs
// -domain, or -fork-version with -genesis-root, which the files must
// agree with.
var exitChains = map[string]struct {
	name    string
	capella string
	gvr     string
}{
	"0x00000000": {"mainnet", "0x03000000", "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"},
	"0x10000910": {"hoodi", "0x40000910", "0x212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f"},
}

// apiLookup resolves the host of an http -api, and currentUID is the user
// the ENR key file must belong to; tests replace them.
var (
	apiLookup  = net.DefaultResolver.LookupIPAddr
	currentUID = os.Getuid
)

// obolExitsRequest is the body of POST /exp/partial_exits/{lock_hash}.
type obolExitsRequest struct {
	PartialExits []obolPartialExit `json:"partial_exits"`
	ShareIdx     uint64            `json:"share_idx"`
	Signature    string            `json:"signature"`
}

func cmdDVExitPost(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("dv-exit-post", flag.ContinueOnError)
	lockPath := fs.String("lock", "", "the Charon cluster-lock.json")
	keyPath := fs.String("enr-key", "", "the Charon ENR private key (.charon/charon-enr-private-key), mode 0600")
	api := fs.String("api", obolAPI, "the Obol API")
	yes := fs.Bool("yes", false, "post the batch without the question, for scripts")
	check := fs.Bool("check", false, "run every check and print the batch; sign and post nothing")
	forkArg := fs.String("fork-version", "", "the Capella fork version of the lock's chain; for a chain other than mainnet and hoodi give it with -genesis-root, or give -domain")
	rootArg := fs.String("genesis-root", "", "the genesis validators root of the lock's chain; for a chain other than mainnet and hoodi give it with -fork-version, or give -domain")
	domainArg := fs.String("domain", "", "the voluntary exit domain of the lock's chain; for a chain other than mainnet and hoodi give it, or -fork-version with -genesis-root")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 || *lockPath == "" || *keyPath == "" {
		return errors.New(dvExitPostUsage)
	}
	var wantFork cloud.Version
	if *forkArg != "" {
		if err := wantFork.UnmarshalText([]byte(*forkArg)); err != nil {
			return fmt.Errorf("-fork-version: %w", err)
		}
	}
	var wantRoot cloud.Root
	if *rootArg != "" {
		if err := wantRoot.UnmarshalText([]byte(*rootArg)); err != nil {
			return fmt.Errorf("-genesis-root: %w", err)
		}
	}
	var wantDomain cloud.Root
	if *domainArg != "" {
		if err := wantDomain.UnmarshalText([]byte(*domainArg)); err != nil {
			return fmt.Errorf("-domain: %w", err)
		}
	}
	if err := checkAPIURL(*api); err != nil {
		return err
	}
	lock, err := readDVLock(*lockPath)
	if err != nil {
		return err
	}

	// The files: one lock, one share index, one chain.
	var first dvPartialFile
	var exits []obolPartialExit
	for i, path := range fs.Args() {
		var f dvPartialFile
		if err := readStrictJSON(path, &f); err != nil {
			return err
		}
		if f.LockHash != lock.LockHash {
			return fmt.Errorf("%s has lock_hash %s, and %s has lock_hash %s", path, f.LockHash, *lockPath, lock.LockHash)
		}
		if i == 0 {
			first = f
		} else if f.ShareIdx != first.ShareIdx || f.VoluntaryExitForkVersion != first.VoluntaryExitForkVersion || f.GenesisValidatorsRoot != first.GenesisValidatorsRoot {
			return fmt.Errorf("%s: share_idx or chain values differ from %s", path, fs.Arg(0))
		}
		exits = append(exits, f.PartialExits...)
	}
	chain := "no chain this tool knows (fork_version " + lock.Definition.ForkVersion + ")"
	if c, ok := exitChains[strings.ToLower(lock.Definition.ForkVersion)]; ok {
		chain = c.name
		if got := hexOf(first.VoluntaryExitForkVersion[:]); got != c.capella {
			return fmt.Errorf("%s has voluntary_exit_fork_version %s, and the Capella fork version of the lock's chain (%s) is %s", fs.Arg(0), got, c.name, c.capella)
		}
		if got := first.GenesisValidatorsRoot.String(); got != c.gvr {
			return fmt.Errorf("%s has genesis_validators_root %s, and that of the lock's chain (%s) is %s", fs.Arg(0), got, c.name, c.gvr)
		}
	} else if *domainArg == "" && (*forkArg == "" || *rootArg == "") {
		// The files alone would set the domain the partials are checked in,
		// or half of it: the fork version and the genesis validators root
		// both go into it.
		return fmt.Errorf("the lock's fork_version %s is no chain this tool knows: give -domain (its voluntary exit domain), or -fork-version (the chain's Capella fork version) with -genesis-root (its genesis validators root)",
			lock.Definition.ForkVersion)
	}
	if *forkArg != "" && first.VoluntaryExitForkVersion != wantFork {
		return fmt.Errorf("%s has voluntary_exit_fork_version %s, and -fork-version is %s", fs.Arg(0), hexOf(first.VoluntaryExitForkVersion[:]), hexOf(wantFork[:]))
	}
	if *rootArg != "" && first.GenesisValidatorsRoot != wantRoot {
		return fmt.Errorf("%s has genesis_validators_root %s, and -genesis-root is %s", fs.Arg(0), first.GenesisValidatorsRoot, wantRoot)
	}
	domain := cloud.ComputeDomain(cloud.DomainVoluntaryExit, first.VoluntaryExitForkVersion, first.GenesisValidatorsRoot)
	if *domainArg != "" && domain != wantDomain {
		return fmt.Errorf("%s signs in the exit domain %s, and -domain is %s", fs.Arg(0), domain, wantDomain)
	}

	exits, err = checkPartialExits(lock, *lockPath, first, exits)
	if err != nil {
		return err
	}

	// The ENR key must be the key of operator share_idx - 1.
	key, err := readENRKey(*keyPath)
	if err != nil {
		return err
	}
	defer key.Zero()
	pub := key.PubKey().SerializeCompressed()
	op := -1
	for i, o := range lock.Definition.Operators {
		if p, err := enrPubkey(o.ENR); err == nil && bytes.Equal(p, pub) {
			op = i
		}
	}
	if op < 0 {
		return fmt.Errorf("the ENR key is no operator's in %s", *lockPath)
	}
	if uint64(op+1) != first.ShareIdx {
		return fmt.Errorf("the ENR key is operator %d's (share_idx %d), and %s has share_idx %d", op+1, op+1, fs.Arg(0), first.ShareIdx)
	}

	// Every check passed: the batch, then -check, -yes or the question.
	u := strings.TrimRight(*api, "/") + "/exp/partial_exits/" + lock.LockHash
	fprintf(out, "dv-exit-post batch: %d partial exits, share_idx %d, lock_hash %s, to POST %s\n", len(exits), first.ShareIdx, lock.LockHash, u)
	fprintf(out, "chain: %s, genesis_validators_root %s, voluntary_exit_fork_version %s, exit domain %s\n",
		chain, first.GenesisValidatorsRoot, hexOf(first.VoluntaryExitForkVersion[:]), domain)
	for _, e := range exits {
		m, err := e.message()
		if err != nil {
			return err
		}
		fprintf(out, "  validator index %d epoch %d %s\n", m.ValidatorIndex, m.Epoch, e.PublicKey)
	}
	fprintf(out, "%s", exitsForGood)
	if *check {
		fprintf(out, "-check: every check passed; nothing signed, nothing posted\n")
		return nil
	}
	if !*yes {
		if err := confirmExits(fmt.Sprintf("Type yes to post these %d partial exits to %s: ", len(exits), u), "posted"); err != nil {
			return err
		}
	}

	root, err := obolExitsRoot(exits, first.ShareIdx)
	if err != nil {
		return err
	}
	// SignCompact gives v || r || s with v = 27 + the recovery id; the API
	// takes r || s || v with v the recovery id, as Charon writes it.
	compact := ecdsa.SignCompact(key, root[:], false)
	sig := append(append([]byte{}, compact[1:]...), compact[0]-27)
	body, err := json.Marshal(obolExitsRequest{PartialExits: exits, ShareIdx: first.ShareIdx, Signature: hexOf(sig)})
	if err != nil {
		return err
	}

	cl := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if pu, err := url.Parse(u); err != nil || pu.Scheme != "https" {
		// url.Parse makes the scheme lower case; checkAPIURL let only
		// https and http through.
		cl.Transport = loopbackTransport()
	}
	resp, err := cl.Post(u, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	answer, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	status := shortText([]byte(resp.Status), 64)
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s: %s: %s", u, status, shortText(answer, 200))
	}
	fprintf(out, "posted %d partial exits of share_idx %d to %s: %s\n", len(exits), first.ShareIdx, u, status)
	return nil
}

// shortText is what the server sent, b, made safe for a terminal: line
// breaks and tabs become spaces, runs of spaces one space, every other
// character that is not printable (escape sequences, bidi controls) is
// dropped, and the rest is cut after limit runes.
func shortText(b []byte, limit int) string {
	s := strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			return ' '
		case !unicode.IsPrint(r):
			return -1
		}
		return r
	}, strings.ToValidUTF8(string(b), ""))
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > limit {
		return string(r[:limit]) + "..."
	}
	return s
}

// checkAPIURL takes an https URL, or an http one whose host is, or
// resolves only to, loopback addresses.
func checkAPIURL(s string) error {
	u, err := url.Parse(s)
	if err == nil && u.Scheme == "https" && u.Host != "" {
		return nil
	}
	if err == nil && u.Scheme == "http" && u.Hostname() != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err = loopbackIPs(ctx, u.Hostname()); err == nil {
			return nil
		}
	}
	if err != nil {
		return fmt.Errorf("-api: https only, or http to a loopback address (%q): %w", s, err)
	}
	return fmt.Errorf("-api: https only, or http to a loopback address (%q)", s)
}

// loopbackIPs is host's addresses (host itself for an IP), when every one
// of them is a loopback address.
func loopbackIPs(ctx context.Context, host string) ([]net.IP, error) {
	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = append(ips, ip)
	} else {
		addrs, err := apiLookup(ctx, host)
		if err != nil {
			return nil, err
		}
		for _, a := range addrs {
			ips = append(ips, a.IP)
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%s has no address", host)
	}
	for _, ip := range ips {
		if !ip.IsLoopback() {
			return nil, fmt.Errorf("%s: %s is not a loopback address", host, ip)
		}
	}
	return ips, nil
}

// loopbackTransport is the transport of an http -api: no proxy, and each
// connection resolves the host again, checks that every address is a
// loopback one and connects to one of those, so a name that moves off
// loopback after checkAPIURL gets no request.
func loopbackTransport() *http.Transport {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ips, err := loopbackIPs(ctx, host)
		if err != nil {
			return nil, err
		}
		var d net.Dialer
		return d.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
	}
	return tr
}

// checkPartialExits checks each partial exit as the Obol API does: the
// public key is a distributed_public_key of the lock, and the partial
// verifies under the lock's public share at share_idx in the files' exit
// domain. The same exit twice counts once; two signatures for one
// validator are refused. It returns the exits in validator index order.
func checkPartialExits(lock *dvLock, lockPath string, f dvPartialFile, exits []obolPartialExit) ([]obolPartialExit, error) {
	if len(exits) == 0 {
		return nil, errors.New("the files hold no partial exit")
	}
	shares := map[cloud.Pubkey][]cloud.Pubkey{}
	for _, v := range lock.Validators {
		shares[v.Group] = v.Shares
	}
	seen := map[cloud.Pubkey]obolPartialExit{}
	var uniq []obolPartialExit
	index := map[cloud.Pubkey]uint64{}
	for _, e := range exits {
		if prev, ok := seen[e.PublicKey]; ok {
			if prev != e {
				return nil, fmt.Errorf("validator %s has two different partial exits in the files", e.PublicKey)
			}
			continue
		}
		s, ok := shares[e.PublicKey]
		if !ok {
			return nil, fmt.Errorf("%s is not a validator of %s", e.PublicKey, lockPath)
		}
		if f.ShareIdx < 1 || f.ShareIdx > uint64(len(s)) {
			return nil, fmt.Errorf("share_idx %d: validator %s has %d public shares in %s", f.ShareIdx, e.PublicKey, len(s), lockPath)
		}
		msg, err := e.message()
		if err != nil {
			return nil, err
		}
		var sig cloud.Signature
		if err := sig.UnmarshalText([]byte(e.SignedExitMessage.Signature)); err != nil {
			return nil, fmt.Errorf("partial exit of %s: %w", e.PublicKey, err)
		}
		_, root, err := exitRoot(msg, f.VoluntaryExitForkVersion, f.GenesisValidatorsRoot)
		if err != nil {
			return nil, err
		}
		if !core.Verify(s[f.ShareIdx-1], root, sig) {
			return nil, fmt.Errorf("the partial exit of %s does not verify under public share %d of %s", e.PublicKey, f.ShareIdx, lockPath)
		}
		seen[e.PublicKey] = e
		index[e.PublicKey] = msg.ValidatorIndex
		uniq = append(uniq, e)
	}
	if len(uniq) > maxPartialExits {
		return nil, fmt.Errorf("%d partial exits, at most %d in one request", len(uniq), maxPartialExits)
	}
	sort.SliceStable(uniq, func(i, j int) bool { return index[uniq[i].PublicKey] < index[uniq[j].PublicKey] })
	return uniq, nil
}

// readENRKey reads a Charon ENR private key file: 32 bytes of hex (charon
// writes it without 0x). A file that others may read, or that another
// user owns, is refused. Errors never quote the file.
func readENRKey(path string) (*secp256k1.PrivateKey, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if m := st.Mode().Perm(); m&0o077 != 0 {
		return nil, fmt.Errorf("%s: mode %04o: others may read it; chmod 600", path, m)
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("%s: its owner is unknown", path)
	}
	if me := currentUID(); int64(sys.Uid) != int64(me) {
		// Not chown: Charon must keep reading its key.
		return nil, fmt.Errorf("%s: owned by uid %d, not by this user (uid %d); run dv-exit-post as that user", path, sys.Uid, me)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	text := bytes.TrimPrefix(bytes.TrimSpace(raw), []byte("0x"))
	notKey := fmt.Errorf("%s is not a hex secp256k1 private key", path)
	// The length first: hex.Decode does not check the size of b.
	if len(text) != 64 {
		return nil, notKey
	}
	var b [32]byte
	defer clear(b[:])
	n, err := hex.Decode(b[:], text)
	var s secp256k1.ModNScalar
	defer s.Zero()
	if err != nil || n != 32 || s.SetBytes(&b) != 0 || s.IsZero() {
		return nil, notKey
	}
	return secp256k1.NewPrivateKey(&s), nil
}

// enrPubkey is the compressed secp256k1 key of a v4 ENR in text form:
// "enr:" and the unpadded base64url of the RLP record [signature, seq,
// key, value, ...] (EIP-778). The record's signature is not checked: the
// lock is the source of its operators' ENRs.
func enrPubkey(s string) ([]byte, error) {
	b64, ok := strings.CutPrefix(s, "enr:")
	if !ok {
		return nil, errors.New("not an ENR: no enr: prefix")
	}
	raw, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil || len(raw) > 300 {
		return nil, errors.New("not an ENR: not base64url of at most 300 bytes")
	}
	list, rest, isList, err := rlpItem(raw)
	if err != nil || !isList || len(rest) != 0 {
		return nil, errors.New("not an ENR: not one RLP list")
	}
	var items [][]byte
	var lists []bool
	for len(list) > 0 {
		item, r, l, err := rlpItem(list)
		if err != nil {
			return nil, fmt.Errorf("not an ENR: %w", err)
		}
		items, lists, list = append(items, item), append(lists, l), r
	}
	// signature, seq, then key and value pairs.
	for i := 2; i+1 < len(items); i += 2 {
		if !lists[i] && string(items[i]) == "secp256k1" {
			if lists[i+1] || len(items[i+1]) != 33 || items[i+1][0] != 2 && items[i+1][0] != 3 {
				return nil, errors.New("ENR: secp256k1 is not a compressed key")
			}
			return items[i+1], nil
		}
	}
	return nil, errors.New("ENR: no secp256k1 key")
}

// rlpItem reads the first RLP item of b: its content, the bytes after it,
// and whether it is a list.
func rlpItem(b []byte) (content, rest []byte, isList bool, err error) {
	if len(b) == 0 {
		return nil, nil, false, errors.New("RLP: no item")
	}
	h := b[0]
	var off, n int
	switch {
	case h < 0x80:
		return b[:1], b[1:], false, nil
	case h < 0xb8:
		off, n = 1, int(h-0x80)
	case h < 0xc0:
		off, n, err = rlpLongLen(b, int(h-0xb7))
	case h < 0xf8:
		off, n, isList = 1, int(h-0xc0), true
	default:
		off, n, err = rlpLongLen(b, int(h-0xf7))
		isList = true
	}
	if err != nil {
		return nil, nil, false, err
	}
	if n > len(b)-off {
		return nil, nil, false, errors.New("RLP: item longer than its input")
	}
	return b[off : off+n], b[off+n:], isList, nil
}

// rlpLongLen reads the big-endian length of k bytes after b[0].
func rlpLongLen(b []byte, k int) (int, int, error) {
	if k > 2 || len(b) < 1+k {
		return 0, 0, errors.New("RLP: bad length")
	}
	n := 0
	for _, c := range b[1 : 1+k] {
		n = n<<8 | int(c)
	}
	if n < 56 {
		return 0, 0, errors.New("RLP: long form of a short length")
	}
	return 1 + k, n, nil
}

// obolExitsRoot is the SSZ hash tree root of the container
// {partial_exits: List[PartialExit, 65536], share_idx: uint64}, with
// PartialExit {public_key: Bytes48, signed_exit_message:
// SignedVoluntaryExit}: what the request's signature covers (obol-sdk
// SSZPartialExitsPayloadType).
func obolExitsRoot(exits []obolPartialExit, shareIdx uint64) ([32]byte, error) {
	if len(exits) > maxPartialExits {
		return [32]byte{}, fmt.Errorf("%d partial exits, at most %d", len(exits), maxPartialExits)
	}
	leaves := make([][32]byte, len(exits))
	for i, e := range exits {
		msg, err := e.message()
		if err != nil {
			return [32]byte{}, err
		}
		var sig cloud.Signature
		if err := sig.UnmarshalText([]byte(e.SignedExitMessage.Signature)); err != nil {
			return [32]byte{}, fmt.Errorf("partial exit of %s: %w", e.PublicKey, err)
		}
		msgRoot, err := cloud.HashTreeRoot(msg)
		if err != nil {
			return [32]byte{}, err
		}
		signed := sszPair(msgRoot, sszBytesRoot(sig[:]))
		leaves[i] = sszPair(sszBytesRoot(e.PublicKey[:]), signed)
	}
	// 65536 = 2^16 leaves.
	list := sszPair(sszMerkleize(leaves, 16), sszUint64(uint64(len(exits))))
	return sszPair(list, sszUint64(shareIdx)), nil
}

func sszPair(a, b [32]byte) [32]byte {
	var buf [64]byte
	copy(buf[:32], a[:])
	copy(buf[32:], b[:])
	return sha256.Sum256(buf[:])
}

func sszUint64(u uint64) [32]byte {
	var c [32]byte
	binary.LittleEndian.PutUint64(c[:], u)
	return c
}

// sszBytesRoot is the root of a fixed byte vector: its 32-byte chunks,
// the last one zero-padded, merkleized.
func sszBytesRoot(b []byte) [32]byte {
	var chunks [][32]byte
	for len(b) > 0 {
		var c [32]byte
		b = b[copy(c[:], b):]
		chunks = append(chunks, c)
	}
	depth := 0
	for 1<<depth < len(chunks) {
		depth++
	}
	return sszMerkleize(chunks, depth)
}

// sszMerkleize is the root of a tree of the given depth whose first
// leaves are chunks and the rest zero.
func sszMerkleize(chunks [][32]byte, depth int) [32]byte {
	layer := append([][32]byte(nil), chunks...)
	var zero [32]byte // the root of an all-zero subtree of the current height
	for range depth {
		if len(layer)%2 == 1 {
			layer = append(layer, zero)
		}
		next := make([][32]byte, len(layer)/2)
		for i := range next {
			next[i] = sszPair(layer[2*i], layer[2*i+1])
		}
		layer, zero = next, sszPair(zero, zero)
	}
	if len(layer) == 0 {
		return zero
	}
	return layer[0]
}
