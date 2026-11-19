//go:build dvt

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"

	"github.com/lidofinance/tee-signer/signer-core/core"
	cloud "github.com/lidofinance/tee-signer/signer-protocol"
)

// ---- the Obol API side, written here from obol-sdk (MIT) ----
//
// fakeObol checks a POST /exp/partial_exits/{lock_hash} as obol-sdk's
// Exit.validateExitBlobs describes the Obol API's checks
// (src/exits/exit.ts at 5b47254): the body is {partial_exits, share_idx,
// signature}; signature is 65 bytes of hex, r || s || v, a low-s
// secp256k1 signature of the SSZ hash tree root of {partial_exits,
// share_idx} under the ENR key of operator share_idx - 1
// (verifyExitPayloadSignature, secp256k1VerifyDigest); each public_key is
// a distributed_public_key of the lock, and each partial verifies under
// the lock's public share of that operator in the Capella exit domain of
// the lock's fork_version (processExitBlob, EIP-7044). The SSZ code below
// is a generic merkleization, not the tool's.

type fakeObol struct {
	srv      *httptest.Server
	lockHash string
	enrs     []*secp256k1.PublicKey // operator i's ENR key
	shares   map[string][]string    // group key to public shares
	capella  [4]byte                // the Capella fork version of the lock's chain
	gvr      [32]byte
	status   int    // the answer to a request that passes, 0: 201
	answer   string // its body

	mu       sync.Mutex
	requests int
	accepted []string // public keys of the partial exits it took
	failure  string   // why it refused the last request
}

func newFakeObol(t *testing.T, f *dvFake, enrs []*secp256k1.PublicKey) *fakeObol {
	t.Helper()
	o := &fakeObol{lockHash: hexOf(f.lockHash[:]), enrs: enrs, shares: map[string][]string{}}
	copy(o.capella[:], mustHex(t, "0x40000910")) // Hoodi's (obol-sdk CAPELLA_FORK_MAPPING)
	copy(o.gvr[:], mustHex(t, dvChains["hoodi"][1]))
	if f.forkVersion != dvChains["hoodi"][0] {
		// A chain obol-sdk does not know: the fake takes f's values.
		o.capella, o.gvr = [4]byte(f.cfg.VoluntaryExitForkVersion), [32]byte(f.cfg.GenesisValidatorsRoot)
	}
	for v, g := range f.c.groups {
		for i := range f.c.n {
			o.shares[g.String()] = append(o.shares[g.String()], f.c.sharePub(t, v, i).String())
		}
	}
	o.srv = httptest.NewServer(http.HandlerFunc(o.serve))
	t.Cleanup(o.srv.Close)
	return o
}

type obolRequest struct {
	PartialExits []testObolExit `json:"partial_exits"`
	ShareIdx     uint64         `json:"share_idx"`
	Signature    string         `json:"signature"`
}

var sigRE = regexp.MustCompile(`^0x[0-9a-fA-F]{130}$`)

func (o *fakeObol) serve(w http.ResponseWriter, r *http.Request) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.requests++
	refuse := func(why string) {
		o.failure = why
		http.Error(w, `{"message":"`+why+`"}`, http.StatusBadRequest)
	}
	if r.Method != http.MethodPost || r.URL.Path != "/exp/partial_exits/"+o.lockHash {
		refuse("method or path " + r.Method + " " + r.URL.Path)
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		refuse("content type " + r.Header.Get("Content-Type"))
		return
	}
	var req obolRequest
	d := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	d.DisallowUnknownFields()
	if err := d.Decode(&req); err != nil {
		refuse("body: " + err.Error())
		return
	}
	if len(req.PartialExits) == 0 || req.ShareIdx < 1 || int(req.ShareIdx) > len(o.enrs) || !sigRE.MatchString(req.Signature) {
		refuse("partial_exits, share_idx or signature")
		return
	}
	root, err := payloadRoot(req)
	if err != nil {
		refuse(err.Error())
		return
	}
	sig, _ := hex.DecodeString(req.Signature[2:])
	var rs, ss secp256k1.ModNScalar
	if rs.SetByteSlice(sig[:32]) || ss.SetByteSlice(sig[32:64]) || ss.IsOverHalfOrder() || sig[64] > 1 {
		refuse("not a low-s r || s || v signature")
		return
	}
	pub := o.enrs[req.ShareIdx-1]
	if !ecdsa.NewSignature(&rs, &ss).Verify(root[:], pub) {
		refuse("Incorrect payload signature for partial exits.")
		return
	}
	// charon's form: v is the recovery id.
	if rec, _, err := ecdsa.RecoverCompact(append([]byte{27 + sig[64]}, sig[:64]...), root[:]); err != nil || !rec.IsEqual(pub) {
		refuse("the recovery id does not give the ENR key")
		return
	}
	domain := cloud.ComputeDomain(cloud.DomainVoluntaryExit, cloud.Version(o.capella), cloud.Root(o.gvr))
	var took []string
	for _, e := range req.PartialExits {
		shares, ok := o.shares[e.PublicKey]
		if !ok {
			refuse("Public key " + e.PublicKey + " not found in the cluster's distributed validators.")
			return
		}
		epoch, err1 := strconv.ParseUint(e.SignedExitMessage.Message.Epoch, 10, 64)
		index, err2 := strconv.ParseUint(e.SignedExitMessage.Message.ValidatorIndex, 10, 64)
		var share cloud.Pubkey
		var bls cloud.Signature
		if err1 != nil || err2 != nil || share.UnmarshalText([]byte(shares[req.ShareIdx-1])) != nil ||
			bls.UnmarshalText([]byte(e.SignedExitMessage.Signature)) != nil {
			refuse("partial exit fields")
			return
		}
		obj, _ := cloud.HashTreeRoot(&cloud.VoluntaryExit{Epoch: epoch, ValidatorIndex: index})
		if !core.Verify(share, cloud.SigningRoot(obj, domain), bls) {
			refuse("Invalid partial exit signature for validator " + e.PublicKey)
			return
		}
		took = append(took, e.PublicKey)
	}
	o.accepted = append(o.accepted, took...)
	status := o.status
	if status == 0 {
		status = http.StatusCreated
	}
	w.WriteHeader(status)
	io.WriteString(w, o.answer)
}

// payloadRoot is the SSZ hash tree root of {partial_exits: List[
// {public_key: Bytes48, signed_exit_message: {message: {epoch: uint64,
// validator_index: uint64}, signature: Bytes96}}, 65536], share_idx:
// uint64}, obol-sdk's SSZPartialExitsPayloadType.
func payloadRoot(req obolRequest) ([32]byte, error) {
	var items [][32]byte
	for _, e := range req.PartialExits {
		pk, err := hex.DecodeString(strings.TrimPrefix(e.PublicKey, "0x"))
		if err != nil || len(pk) != 48 {
			return [32]byte{}, err
		}
		sig, err := hex.DecodeString(strings.TrimPrefix(e.SignedExitMessage.Signature, "0x"))
		if err != nil || len(sig) != 96 {
			return [32]byte{}, err
		}
		epoch, _ := strconv.ParseUint(e.SignedExitMessage.Message.Epoch, 10, 64)
		index, _ := strconv.ParseUint(e.SignedExitMessage.Message.ValidatorIndex, 10, 64)
		msg := merkle([][32]byte{uintChunk(epoch), uintChunk(index)}, 2)
		signed := merkle([][32]byte{msg, merkle(chunks(sig), 3)}, 2)
		items = append(items, merkle([][32]byte{merkle(chunks(pk), 2), signed}, 2))
	}
	list, n := merkle(items, 65536), uintChunk(uint64(len(items)))
	list = sha256.Sum256(append(list[:], n[:]...))
	return merkle([][32]byte{list, uintChunk(req.ShareIdx)}, 2), nil
}

// merkle is the SSZ merkleization of chunks with room for limit chunks.
func merkle(chunks [][32]byte, limit int) [32]byte {
	width := 1
	for width < limit {
		width *= 2
	}
	layer := make([][32]byte, width)
	copy(layer, chunks)
	for len(layer) > 1 {
		next := make([][32]byte, len(layer)/2)
		for i := range next {
			next[i] = sha256.Sum256(append(layer[2*i][:], layer[2*i+1][:]...))
		}
		layer = next
	}
	return layer[0]
}

func chunks(b []byte) [][32]byte {
	var out [][32]byte
	for len(b) > 0 {
		var c [32]byte
		n := copy(c[:], b)
		b = b[n:]
		out = append(out, c)
	}
	return out
}

func uintChunk(u uint64) [32]byte {
	var c [32]byte
	binary.LittleEndian.PutUint64(c[:], u)
	return c
}

// ---- ENRs (EIP-778) ----

func rlpHeader(base byte, n int) []byte {
	if n < 56 {
		return []byte{base + byte(n)}
	}
	var l []byte
	for x := n; x > 0; x >>= 8 {
		l = append([]byte{byte(x)}, l...)
	}
	return append([]byte{base + 55 + byte(len(l))}, l...)
}

func rlpBytes(b []byte) []byte {
	if len(b) == 1 && b[0] < 0x80 {
		return b
	}
	return append(rlpHeader(0x80, len(b)), b...)
}

func rlpList(items ...[]byte) []byte {
	payload := bytes.Join(items, nil)
	return append(rlpHeader(0xc0, len(payload)), payload...)
}

// testENR is the v4 ENR of key: seq 1, id v4, its compressed secp256k1
// key, signed with key over the keccak256 of the content.
func testENR(key *secp256k1.PrivateKey) string {
	kv := [][]byte{rlpBytes([]byte{1}), rlpBytes([]byte("id")), rlpBytes([]byte("v4")),
		rlpBytes([]byte("secp256k1")), rlpBytes(key.PubKey().SerializeCompressed())}
	h := sha3.NewLegacyKeccak256()
	h.Write(rlpList(kv...))
	sig := ecdsa.SignCompact(key, h.Sum(nil), false)
	return "enr:" + base64.RawURLEncoding.EncodeToString(rlpList(append([][]byte{rlpBytes(sig[1:])}, kv...)...))
}

// dvPost is a Hoodi dv_share fake cluster whose lock has the ENRs of four
// operator keys, the dv-exit file of s2 (share_idx 2) and a fake Obol API.
type dvPost struct {
	*dvFake
	keys     []*secp256k1.PrivateKey
	partials string
	api      *fakeObol
}

func newDVPost(t *testing.T) *dvPost {
	t.Helper()
	return newDVPostOn(t, "hoodi")
}

// newDVPostOn is newDVPost on chain; on a chain other than Hoodi the
// partials are of epoch 1.
func newDVPostOn(t *testing.T, chain string) *dvPost {
	t.Helper()
	f := newDVFake(t, chain)
	p := &dvPost{dvFake: f}
	var enrs []string
	var pubs []*secp256k1.PublicKey
	for range 4 {
		k, err := secp256k1.GeneratePrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		p.keys = append(p.keys, k)
		enrs = append(enrs, testENR(k))
		pubs = append(pubs, k.PubKey())
	}
	f.lock = dvLockFile(t, f.c, f.lock, f.forkVersion, f.lockHash, enrs)
	p.partials = f.fc.path("s2.partials.json")
	args := []string{"dv-exit", "-cluster", f.fc.cluster, "-signer", "s2", "-split", f.split, "-lock", f.lock,
		"-indices", writeIndexFile(t, f.fc.path("indices.json"), f.index), "-all", "-yes", "-out", p.partials}
	if chain != "hoodi" {
		args = append(args, "-epoch", "1")
	}
	mustTool(t, args...)
	p.api = newFakeObol(t, f, pubs)
	return p
}

// keyFile writes operator i's ENR private key as charon writes it: hex,
// mode 0600.
func (p *dvPost) keyFile(t *testing.T, i int, mode os.FileMode) string {
	t.Helper()
	path := p.fc.path("charon-enr-private-key-" + strconv.Itoa(i))
	k := p.keys[i].Key.Bytes()
	if err := os.WriteFile(path, []byte(hex.EncodeToString(k[:])), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

// dv-exit-post sends the partial exits of a dv-exit file to the Obol API
// in the request obol-sdk checks, signed with the ENR key of the file's
// share index; the fake API takes all three. The key never shows in the
// output.
func TestDVExitPost(t *testing.T) {
	p := newDVPost(t)
	key := p.keyFile(t, 1, 0o600)
	res := mustTool(t, "dv-exit-post", "-lock", p.lock, "-enr-key", key, "-api", p.api.srv.URL, "-yes", p.partials)
	t.Logf("dv-exit-post\n%s", res)
	wantIn(t, res, "posted 3 partial exits of share_idx 2 to "+p.api.srv.URL+"/exp/partial_exits/"+hexOf(p.lockHash[:])+": 201 Created")
	if p.api.requests != 1 || len(p.api.accepted) != 3 {
		t.Fatalf("API: %d requests, took %v; %s", p.api.requests, p.api.accepted, p.api.failure)
	}
	k := p.keys[1].Key.Bytes()
	if strings.Contains(strings.ToLower(res), hex.EncodeToString(k[:])) {
		t.Fatal("the output shows the ENR key")
	}
	// The same file again: the request is the same, and the API decides.
	p.api.status, p.api.answer = http.StatusBadRequest, `{"message":"already stored"}`
	wantIn(t, failTool(t, "dv-exit-post", "-lock", p.lock, "-enr-key", key, "-api", p.api.srv.URL, "-yes", p.partials),
		"400 Bad Request", "already stored")
}

// dv-exit-post refuses, before it sends anything: a file of another lock
// hash, the ENR key of another operator or of none, a key file that
// others may read or that is not a key, a partial that does not verify
// under the lock's public share, a public key that is no validator of
// the lock, chain values that are not the lock's chain's, and an http
// URL that is not a loopback one.
func TestDVExitPostRefusals(t *testing.T) {
	p := newDVPost(t)
	key := p.keyFile(t, 1, 0o600)
	fakeLookup(t, map[string][]string{"api.example.org": {"203.0.113.7"}}) // no DNS query in a test
	edit := func(name string, fn func(m map[string]any)) string {
		var m map[string]any
		if err := json.Unmarshal(mustRead(t, p.partials), &m); err != nil {
			t.Fatal(err)
		}
		fn(m)
		return writeJSONFile(t, p.fc.path(name), m)
	}
	exit0 := func(m map[string]any) map[string]any {
		return m["partial_exits"].([]any)[0].(map[string]any)
	}
	otherHash := p.lockHash
	otherHash[0] ^= 1
	otherLock := dvLockFile(t, p.c, p.fc.path("other-lock.json"), p.forkVersion, otherHash, nil)
	stranger, _ := secp256k1.GeneratePrivateKey()
	strangerFile := p.fc.path("stranger-key")
	sk := stranger.Key.Bytes()
	writeFile(t, strangerFile, hex.EncodeToString(sk[:]))
	os.Chmod(strangerFile, 0o600)
	garbage := writeFile(t, p.fc.path("garbage-key"), "not a key at all, a secret phrase")
	os.Chmod(garbage, 0o600)
	k1 := p.keys[1].Key.Bytes()
	// Operator 1's key with one byte too many: hex.Decode into 32 bytes
	// must not run past the end.
	long := writeFile(t, p.fc.path("long-key"), hex.EncodeToString(k1[:])+"00")
	os.Chmod(long, 0o600)

	for _, c := range []struct {
		name  string
		args  []string
		files []string
		want  string
	}{
		{"lock hash", []string{"-lock", otherLock}, nil, "lock_hash " + hexOf(p.lockHash[:]) + ", and " + otherLock + " has lock_hash " + hexOf(otherHash[:])},
		{"operator", []string{"-enr-key", p.keyFile(t, 0, 0o600)}, nil, "the ENR key is operator 1's (share_idx 1), and " + p.partials + " has share_idx 2"},
		{"no operator", []string{"-enr-key", strangerFile}, nil, "the ENR key is no operator's in " + p.lock},
		{"mode", []string{"-enr-key", p.keyFile(t, 2, 0o644)}, nil, "mode 0644: others may read it; chmod 600"},
		{"not a key", []string{"-enr-key", garbage}, nil, "is not a hex secp256k1 private key"},
		{"long key", []string{"-enr-key", long}, nil, long + " is not a hex secp256k1 private key"},
		{"bad partial", nil, []string{edit("bad.json", func(m map[string]any) {
			e1 := m["partial_exits"].([]any)[1].(map[string]any)["signed_exit_message"].(map[string]any)
			exit0(m)["signed_exit_message"].(map[string]any)["signature"] = e1["signature"]
		})}, "does not verify under public share 2 of " + p.lock},
		{"not in lock", nil, []string{edit("stranger.json", func(m map[string]any) {
			exit0(m)["public_key"] = p.c.sharePub(t, 0, 0).String()
		})}, p.c.sharePub(t, 0, 0).String() + " is not a validator of " + p.lock},
		{"chain", nil, []string{edit("chain.json", func(m map[string]any) {
			m["voluntary_exit_fork_version"] = "0x50000910"
		})}, "voluntary_exit_fork_version 0x50000910, and the Capella fork version of the lock's chain (hoodi) is 0x40000910"},
		{"http", []string{"-api", "http://api.example.org/v1"}, nil, "-api: https only, or http to a loopback address"},
	} {
		args := map[string]string{"-lock": p.lock, "-enr-key": key, "-api": p.api.srv.URL}
		for i := 0; i < len(c.args); i += 2 {
			args[c.args[i]] = c.args[i+1]
		}
		cmd := []string{"dv-exit-post", "-yes"}
		for k, v := range args {
			cmd = append(cmd, k, v)
		}
		files := c.files
		if files == nil {
			files = []string{p.partials}
		}
		res := failTool(t, append(cmd, files...)...)
		wantIn(t, res, c.want)
		if strings.Contains(res, "secret phrase") || strings.Contains(strings.ToLower(res), hex.EncodeToString(k1[:])) {
			t.Fatalf("%s: the output shows the key file's content:\n%s", c.name, res)
		}
		if p.api.requests != 0 {
			t.Fatalf("%s: a request reached the API", c.name)
		}
	}
}

// dv-exit-post prints the batch (count, share_idx, lock hash, the URL it
// posts to, chain, each validator's index, epoch and key) and posts only
// after the answer yes on a terminal, or with -yes. A stdin that is not a
// terminal, any other answer and EOF stop it before the request.
func TestDVExitPostConfirm(t *testing.T) {
	p := newDVPost(t)
	key := p.keyFile(t, 1, 0o600)
	post := func(extra ...string) []string {
		return append(append([]string{"dv-exit-post", "-lock", p.lock, "-enr-key", key, "-api", p.api.srv.URL}, extra...), p.partials)
	}
	u := p.api.srv.URL + "/exp/partial_exits/" + hexOf(p.lockHash[:])
	batch := []string{
		"dv-exit-post batch: 3 partial exits, share_idx 2, lock_hash " + hexOf(p.lockHash[:]) + ", to POST " + u,
		"chain: hoodi, genesis_validators_root " + dvChains["hoodi"][1] + ", voluntary_exit_fork_version 0x40000910",
	}
	for _, g := range p.c.groups {
		batch = append(batch, "validator index "+uitoa(p.index[g])+" epoch 256 "+g.String())
	}
	question := "Type yes to post these 3 partial exits to " + u + ": "
	for _, c := range []struct {
		terminal bool
		answer   string
		want     string
	}{
		{false, "yes\n", "stdin is not a terminal to confirm the batch: -yes confirms it, -check only checks it"},
		{true, "y\n", "not confirmed: nothing posted"},
		{true, "no\n", "not confirmed: nothing posted"},
		{true, "", "not confirmed: nothing posted"},
	} {
		asked := fakePrompt(t, c.terminal, c.answer)
		wantIn(t, failTool(t, post()...), append(batch, c.want)...)
		if prompted := strings.Contains(asked.String(), question); prompted != c.terminal {
			t.Fatalf("terminal %v: prompt %q", c.terminal, asked.String())
		}
		if p.api.requests != 0 {
			t.Fatalf("terminal %v, answer %q: a request reached the API", c.terminal, c.answer)
		}
	}
	asked := fakePrompt(t, true, "yes\n")
	wantIn(t, mustTool(t, post()...), append(batch, "posted 3 partial exits of share_idx 2")...)
	wantIn(t, asked.String(), question)
	if p.api.requests != 1 || len(p.api.accepted) != 3 {
		t.Fatalf("API: %d requests, took %v; %s", p.api.requests, p.api.accepted, p.api.failure)
	}
}

// dv-exit-post -check runs every check, the ENR key's too, prints the
// batch and posts nothing, without a question.
func TestDVExitPostCheck(t *testing.T) {
	p := newDVPost(t)
	asked := fakePrompt(t, false, "")
	res := mustTool(t, "dv-exit-post", "-lock", p.lock, "-enr-key", p.keyFile(t, 1, 0o600), "-api", p.api.srv.URL, "-check", p.partials)
	t.Logf("dv-exit-post -check\n%s", res)
	wantIn(t, res, "dv-exit-post batch: 3 partial exits, share_idx 2", "-check: every check passed; nothing signed, nothing posted")
	if asked.Len() != 0 || p.api.requests != 0 {
		t.Fatalf("-check: asked %q, %d requests", asked.String(), p.api.requests)
	}
	wantIn(t, failTool(t, "dv-exit-post", "-lock", p.lock, "-enr-key", p.keyFile(t, 0, 0o600), "-api", p.api.srv.URL, "-check", p.partials),
		"the ENR key is operator 1's (share_idx 1)")
	if p.api.requests != 0 {
		t.Fatal("-check: a request reached the API")
	}
}

// For a lock of a chain other than mainnet and Hoodi the exit domain is
// not the tool's to know: dv-exit-post refuses unless -domain (its
// voluntary exit domain), or -fork-version (the chain's Capella fork
// version) with -genesis-root (its genesis validators root), names it,
// and the files must agree with each one given. -fork-version or
// -genesis-root alone is refused: the files would set the other half of
// the domain. On Hoodi a flag that differs from the chain's value is
// refused too.
func TestDVExitPostOtherChain(t *testing.T) {
	p := newDVPostOn(t, "ci-test")
	key := p.keyFile(t, 1, 0o600)
	run := func(fail bool, extra ...string) string {
		t.Helper()
		args := append(append([]string{"dv-exit-post", "-lock", p.lock, "-enr-key", key, "-api", p.api.srv.URL, "-yes"}, extra...), p.partials)
		if fail {
			return failTool(t, args...)
		}
		return mustTool(t, args...)
	}
	domain := cloud.ComputeDomain(cloud.DomainVoluntaryExit, p.cfg.VoluntaryExitForkVersion, p.cfg.GenesisValidatorsRoot)
	other := domain
	other[31] ^= 1
	vefv, gvr := dvChains["ci-test"][2], dvChains["ci-test"][1]
	otherRoot := p.cfg.GenesisValidatorsRoot
	otherRoot[0] ^= 1

	const needed = " is no chain this tool knows: give -domain (its voluntary exit domain), or -fork-version (the chain's Capella fork version) with -genesis-root (its genesis validators root)"
	wantIn(t, run(true), "the lock's fork_version "+p.forkVersion+needed)
	wantIn(t, run(true, "-fork-version", vefv), "the lock's fork_version "+p.forkVersion+needed)
	wantIn(t, run(true, "-genesis-root", gvr), "the lock's fork_version "+p.forkVersion+needed)
	wantIn(t, run(true, "-fork-version", "0x04000011", "-genesis-root", gvr), p.partials+" has voluntary_exit_fork_version "+vefv+", and -fork-version is 0x04000011")
	wantIn(t, run(true, "-fork-version", vefv, "-genesis-root", otherRoot.String()),
		p.partials+" has genesis_validators_root "+gvr+", and -genesis-root is "+otherRoot.String())
	wantIn(t, run(true, "-domain", other.String()), p.partials+" signs in the exit domain "+domain.String()+", and -domain is "+other.String())
	wantIn(t, run(true, "-fork-version", "0x0400"), "-fork-version")
	wantIn(t, run(true, "-genesis-root", "0x00"), "-genesis-root")
	if p.api.requests != 0 {
		t.Fatal("a request reached the API")
	}
	wantIn(t, run(false, "-fork-version", vefv, "-genesis-root", gvr), "chain: no chain this tool knows (fork_version "+p.forkVersion+")", "exit domain "+domain.String(), "201 Created")
	wantIn(t, run(false, "-domain", domain.String()), "201 Created")
	if p.api.requests != 2 || len(p.api.accepted) != 6 {
		t.Fatalf("API: %d requests, took %v; %s", p.api.requests, p.api.accepted, p.api.failure)
	}

	h := newDVPost(t)
	wantIn(t, failTool(t, "dv-exit-post", "-lock", h.lock, "-enr-key", h.keyFile(t, 1, 0o600), "-api", h.api.srv.URL, "-yes", "-fork-version", "0x50000910", h.partials),
		h.partials+" has voluntary_exit_fork_version 0x40000910, and -fork-version is 0x50000910")
	wantIn(t, failTool(t, "dv-exit-post", "-lock", h.lock, "-enr-key", h.keyFile(t, 1, 0o600), "-api", h.api.srv.URL, "-yes", "-genesis-root", otherRoot.String(), h.partials),
		h.partials+" has genesis_validators_root "+dvChains["hoodi"][1]+", and -genesis-root is "+otherRoot.String())
	if h.api.requests != 0 {
		t.Fatal("hoodi: a request reached the API")
	}
}

// An error answer of the API is cut to a short length and stripped of
// control characters before it reaches the terminal.
func TestDVExitPostErrorBody(t *testing.T) {
	p := newDVPost(t)
	p.api.status = http.StatusBadRequest
	p.api.answer = "\x1b[2J\x1b]0;title\x07bad\r\nrequest\u202e" + strings.Repeat("A", 3000)
	res := failTool(t, "dv-exit-post", "-lock", p.lock, "-enr-key", p.keyFile(t, 1, 0o600), "-api", p.api.srv.URL, "-yes", p.partials)
	wantIn(t, res, "400 Bad Request", "[2J]0;titlebad request")
	for _, c := range []string{"\x1b", "\x07", "\r", "\u202e", strings.Repeat("A", 250)} {
		if strings.Contains(res, c) {
			t.Fatalf("the output holds %q:\n%q", c, res)
		}
	}
}

// dv-exit-post does not follow a redirect: the API's 307 to another
// server is an error, and that server gets nothing.
func TestDVExitPostNoRedirect(t *testing.T) {
	p := newDVPost(t)
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, p.api.srv.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redirect.Close)
	wantIn(t, failTool(t, "dv-exit-post", "-lock", p.lock, "-enr-key", p.keyFile(t, 1, 0o600), "-api", redirect.URL, "-yes", p.partials),
		"307 Temporary Redirect")
	if p.api.requests != 0 {
		t.Fatal("the redirect was followed")
	}
}
