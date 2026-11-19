//go:build dvt

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	cloud "github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
)

// testDVPartials is the file of dv-exit as the tests read it: the Obol
// API's partial_exits with the lock hash, the share index and the chain
// values the poster checks.
type testDVPartials struct {
	LockHash                 string         `json:"lock_hash"`
	ShareIdx                 uint64         `json:"share_idx"`
	Signer                   string         `json:"signer"`
	VoluntaryExitForkVersion string         `json:"voluntary_exit_fork_version"`
	GenesisValidatorsRoot    string         `json:"genesis_validators_root"`
	PartialExits             []testObolExit `json:"partial_exits"`
}

// testObolExit is one item of the Obol API's partial_exits.
type testObolExit struct {
	PublicKey         string `json:"public_key"`
	SignedExitMessage struct {
		Message struct {
			Epoch          string `json:"epoch"`
			ValidatorIndex string `json:"validator_index"`
		} `json:"message"`
		Signature string `json:"signature"`
	} `json:"signed_exit_message"`
}

func readDVPartials(t *testing.T, path string) testDVPartials {
	t.Helper()
	var p testDVPartials
	d := json.NewDecoder(bytes.NewReader(mustRead(t, path)))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return p
}

// checkPartials checks the dv-exit file at path: share index idx (signer
// name) of f's lock, the chain values of f, and one partial exit at epoch
// for each validator vals names, in validator index order, each verifying
// under that validator's share key at idx.
func (f *dvFake) checkPartials(t *testing.T, path, name string, idx int, epoch uint64, vals ...int) {
	t.Helper()
	p := readDVPartials(t, path)
	if p.LockHash != hexOf(f.lockHash[:]) || p.ShareIdx != uint64(idx) || p.Signer != name {
		t.Fatalf("lock_hash %s share_idx %d signer %s, want %s %d %s", p.LockHash, p.ShareIdx, p.Signer, hexOf(f.lockHash[:]), idx, name)
	}
	if p.VoluntaryExitForkVersion != hexOf(f.cfg.VoluntaryExitForkVersion[:]) || p.GenesisValidatorsRoot != hexOf(f.cfg.GenesisValidatorsRoot[:]) {
		t.Fatalf("chain values %s %s", p.VoluntaryExitForkVersion, p.GenesisValidatorsRoot)
	}
	if len(p.PartialExits) != len(vals) {
		t.Fatalf("%d partial exits, want %d", len(p.PartialExits), len(vals))
	}
	for i, v := range vals {
		e := p.PartialExits[i]
		g, index := f.c.groups[v], f.index[f.c.groups[v]]
		if e.PublicKey != g.String() || e.SignedExitMessage.Message.Epoch != uitoa(epoch) || e.SignedExitMessage.Message.ValidatorIndex != uitoa(index) {
			t.Fatalf("partial exit %d: %+v, want %s epoch %d index %d", i, e, g, epoch, index)
		}
		var sig cloud.Signature
		if err := sig.UnmarshalText([]byte(e.SignedExitMessage.Signature)); err != nil {
			t.Fatal(err)
		}
		root := f.exitRoot(epoch, index)
		if !core.Verify(f.c.sharePub(t, v, idx-1), root, sig) {
			t.Fatalf("partial exit %d does not verify under share key %d", i, idx)
		}
		if core.Verify(g, root, sig) {
			t.Fatalf("partial exit %d verifies under the group key", i)
		}
	}
}

// fakeIndexBeacon is a beacon node of the chain with these genesis values
// that knows the validators of index (group key to validator index).
func fakeIndexBeacon(t *testing.T, gvr, forkVersion string, index map[cloud.Pubkey]uint64) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/eth/v1/beacon/genesis":
			fmt.Fprintf(w, `{"data":{"genesis_time":"1742213400","genesis_validators_root":%q,"genesis_fork_version":%q}}`, gvr, forkVersion)
		case r.Method == http.MethodGet && r.URL.Path == "/eth/v1/node/syncing":
			fmt.Fprint(w, `{"data":{"head_slot":"100","sync_distance":"0","is_syncing":false,"is_optimistic":false,"el_offline":false}}`)
		case r.Method == http.MethodGet && r.URL.Path == "/eth/v1/beacon/states/head/validators":
			var data []string
			for _, k := range strings.Split(r.URL.Query().Get("id"), ",") {
				for pk, i := range index {
					if pk.String() == k {
						data = append(data, fmt.Sprintf(`{"index":"%d","balance":"32000000000","status":"active_ongoing","validator":{"pubkey":%q,"slashed":false}}`, i, k))
					}
				}
			}
			fmt.Fprintf(w, `{"execution_optimistic":false,"finalized":false,"data":[%s]}`, strings.Join(data, ","))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// writeIndexFile writes an index file in the beacon API's form for the keys
// of index.
func writeIndexFile(t *testing.T, path string, index map[cloud.Pubkey]uint64) string {
	t.Helper()
	var data []map[string]any
	for pk, i := range index {
		data = append(data, map[string]any{"index": uitoa(i), "status": "active_ongoing", "validator": map[string]any{"pubkey": pk.String()}})
	}
	return writeJSONFile(t, path, map[string]any{"data": data})
}

// dv-indices writes the index file of the lock's validators from a beacon
// node of the lock's chain. dv-exit signs, through one dv_share signer,
// the partial exit of each validator with the share key at the signer's
// share index, in the voluntary exit domain of the signer's chain, and
// writes the Obol API's partial_exits. -beacon gives the same file as the
// index file; -pubkeys takes part of the lock.
func TestDVExitBatch(t *testing.T) {
	f := newDVFake(t, "ci-test")
	beacon := fakeIndexBeacon(t, dvChains["ci-test"][1], f.forkVersion, f.index)
	idx := f.fc.path("indices.json")
	res := mustTool(t, "dv-indices", "-lock", f.lock, "-beacon", beacon.URL, "-out", idx)
	t.Logf("dv-indices\n%s", res)
	wantIn(t, res, "3 of 3 validators of "+f.lock+" have an index", "wrote "+idx)

	out := f.fc.path("s2.partials.json")
	args := []string{"dv-exit", "-cluster", f.fc.cluster, "-signer", "s2", "-split", f.split, "-lock", f.lock, "-epoch", "1", "-all", "-yes"}
	res = mustTool(t, append(args, "-indices", idx, "-out", out)...)
	t.Logf("dv-exit\n%s", res)
	wantIn(t, res, "3 partial exits of s2 (share_idx 2), epoch 1", "wrote "+out)
	f.checkPartials(t, out, "s2", 2, 1, 0, 1, 2)

	out2 := f.fc.path("s2.beacon.json")
	mustTool(t, append(args, "-beacon", beacon.URL, "-out", out2)...)
	if !bytes.Equal(mustRead(t, out), mustRead(t, out2)) {
		t.Fatal("dv-exit -beacon wrote another file than dv-exit -indices")
	}

	// Part of the lock, in any order: the file is in validator index order.
	pks := writeFile(t, f.fc.path("batch.txt"), f.c.groups[2].String()+"\n"+f.c.groups[0].String()+"\n")
	out3 := f.fc.path("s3.partials.json")
	res = mustTool(t, "dv-exit", "-cluster", f.fc.cluster, "-signer", "s3", "-split", f.split, "-lock", f.lock, "-epoch", "1", "-yes",
		"-indices", idx, "-pubkeys", pks, "-out", out3)
	wantIn(t, res, "2 partial exits of s3 (share_idx 3)")
	f.checkPartials(t, out3, "s3", 3, 1, 0, 2)
}

// The exit epoch: Hoodi's default is 256, the epoch Obol's Lido setup
// uses there; a chain without a default needs -epoch.
func TestDVExitEpochDefault(t *testing.T) {
	f := newDVFake(t, "hoodi")
	idx := writeIndexFile(t, f.fc.path("indices.json"), f.index)
	out := f.fc.path("s1.partials.json")
	res := mustTool(t, "dv-exit", "-cluster", f.fc.cluster, "-signer", "s1", "-split", f.split, "-lock", f.lock, "-indices", idx, "-all", "-yes", "-out", out)
	wantIn(t, res, "epoch 256 (the default on hoodi)")
	f.checkPartials(t, out, "s1", 1, 256, 0, 1, 2)

	g := newDVFake(t, "ci-test")
	idx = writeIndexFile(t, g.fc.path("indices.json"), g.index)
	out = g.fc.path("s1.partials.json")
	wantIn(t, failTool(t, "dv-exit", "-cluster", g.fc.cluster, "-signer", "s1", "-split", g.split, "-lock", g.lock, "-indices", idx, "-all", "-yes", "-out", out),
		"no default exit epoch for this chain; give -epoch")
	if _, err := os.Stat(out); err == nil {
		t.Fatal("a refused dv-exit wrote its file")
	}
}

// dv-exit refuses, before it signs anything and without writing a file:
// a share key where a validator's group key belongs, a key that is no
// validator of the lock, a validator without an index, a signer whose
// setup is not dv_share, a signer the split gives no share index, a lock
// that is not the split's, and a runner that lists the validator under
// its group key or does not hold the share.
func TestDVExitRefusals(t *testing.T) {
	f := newDVFake(t, "ci-test")
	idx := writeIndexFile(t, f.fc.path("indices.json"), f.index)
	share := f.c.sharePub(t, 1, 2)
	sk, _ := software.NewSecret()
	other, _ := core.PubkeyOf(sk)
	two := map[cloud.Pubkey]uint64{f.c.groups[0]: 100, f.c.groups[1]: 101}
	noS2, _ := os.CreateTemp(f.fc.dir, "split")
	noS2.Close()
	mustTool(t, "dv-split", "-lock", f.lock, "-signers", "s1=1,s3=3", "-out", noS2.Name())
	otherLock := dvLockFile(t, newCharonCluster(t, 3, 3, 4), f.fc.path("other-lock.json"), f.forkVersion, f.lockHash, nil)
	thr := newFakeCluster(t) // signing_mode = threshold

	for _, c := range []struct {
		name string
		args []string
		want string
	}{
		{"share key", []string{"-pubkeys", writeFile(t, f.fc.path("share.txt"), share.String()+"\n")},
			share.String() + " is share 3 of validator " + f.c.groups[1].String() + ": name each validator by its group key (distributed_public_key)"},
		{"other key", []string{"-pubkeys", writeFile(t, f.fc.path("other.txt"), other.String()+"\n")},
			other.String() + " is not a validator of " + f.lock},
		{"no index", []string{"-indices", writeIndexFile(t, f.fc.path("two.json"), two)},
			"validator " + f.c.groups[2].String() + " has no index in " + f.fc.path("two.json")},
		{"no share index", []string{"-split", noS2.Name()}, "s2 has no share index in " + noS2.Name()},
		{"other lock", []string{"-lock", otherLock}, "is not in " + otherLock},
		{"threshold signer", []string{"-cluster", thr.cluster}, "the setup of s2 says signing_mode = threshold; dv-exit needs signing_mode = dv_share"},
	} {
		out := f.fc.path("refused.json")
		args := map[string]string{"-cluster": f.fc.cluster, "-signer": "s2", "-split": f.split, "-lock": f.lock, "-indices": idx, "-epoch": "1", "-out": out}
		for i := 0; i < len(c.args); i += 2 {
			args[c.args[i]] = c.args[i+1]
		}
		cmd := []string{"dv-exit", "-yes"}
		if _, ok := args["-pubkeys"]; !ok {
			cmd = append(cmd, "-all")
		}
		for k, v := range args {
			cmd = append(cmd, k, v)
		}
		wantIn(t, failTool(t, cmd...), c.want)
		if _, err := os.Stat(out); err == nil {
			t.Fatalf("%s: a refused dv-exit wrote its file", c.name)
		}
	}

	// A runner that lists the validators under their group keys, as a
	// threshold signer does, and one that lacks the share of validator 2.
	for _, groupKeyed := range []bool{true, false} {
		r := newDVFakeBare(t, "ci-test")
		s, err := core.NewSigner(r.cfg, 16, 0, software.NewMemHooks())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Close)
		for v, g := range r.c.groups {
			pk := r.c.sharePub(t, v, 1)
			if groupKeyed {
				pk = g
			} else if v == 2 {
				continue
			}
			k, err := s.AddValidator(pk, r.c.secrets[v][1], r.index[g], nil)
			if err != nil {
				t.Fatal(err)
			}
			r.fc.runners["s2"].SetSigner(k, s.Sign)
		}
		want := "s2 does not hold share 2 " + r.c.sharePub(t, 2, 1).String() + " of validator " + r.c.groups[2].String()
		if groupKeyed {
			want = "s2 lists validator " + r.c.groups[0].String() + " under its group key, not under share 2 " +
				r.c.sharePub(t, 0, 1).String() + ": it is no dv_share signer"
		}
		out := r.fc.path("refused.json")
		wantIn(t, failTool(t, "dv-exit", "-cluster", r.fc.cluster, "-signer", "s2", "-split", r.split, "-lock", r.lock,
			"-indices", writeIndexFile(t, r.fc.path("indices.json"), r.index), "-epoch", "1", "-all", "-yes", "-out", out), want)
		if _, err := os.Stat(out); err == nil {
			t.Fatal("a refused dv-exit wrote its file")
		}
	}
}

// A runner that refuses one exit (here: the index file gives another
// validator index than the runner loaded): dv-exit writes the partials
// that verify, names the one that failed and exits non-zero.
func TestDVExitRunnerRefusesOne(t *testing.T) {
	f := newDVFake(t, "ci-test")
	bad := map[cloud.Pubkey]uint64{}
	for k, v := range f.index {
		bad[k] = v
	}
	bad[f.c.groups[0]] = 999
	out := f.fc.path("s1.partials.json")
	res := failTool(t, "dv-exit", "-cluster", f.fc.cluster, "-signer", "s1", "-split", f.split, "-lock", f.lock,
		"-indices", writeIndexFile(t, f.fc.path("bad.json"), bad), "-epoch", "1", "-all", "-yes", "-out", out)
	wantIn(t, res, "s1: validator "+f.c.groups[0].String()+" (index 999): ", "2 partial exits of s1 (share_idx 1)", "wrote "+out, errReported.Error())
	f.checkPartials(t, out, "s1", 1, 1, 1, 2)
}

// noSigned fails t when runner name got a sign request or the file at out
// exists.
func (f *dvFake) noSigned(t *testing.T, name, out, what string) {
	t.Helper()
	if n := f.fc.runners[name].Seen(wire.TypeSign); n != 0 {
		t.Fatalf("%s: %d sign requests reached %s", what, n, name)
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatalf("%s: dv-exit wrote %s", what, out)
	}
}

// dvExitBatchLines are the lines dv-exit prints for the batch of every
// validator of f, signed by s2 at epoch on Hoodi.
func (f *dvFake) dvExitBatchLines(epoch string) []string {
	lines := []string{
		"dv-exit batch: 3 partial exits, signer s2 (share_idx 2), epoch " + epoch + ", lock_hash " + hexOf(f.lockHash[:]),
		"chain: hoodi, genesis_validators_root " + dvChains["hoodi"][1] + ", voluntary_exit_fork_version " + dvChains["hoodi"][2],
	}
	for _, g := range f.c.groups {
		lines = append(lines, fmt.Sprintf("validator index %d %s", f.index[g], g))
	}
	return lines
}

// dv-exit signs only a batch named on the command line: -pubkeys FILE,
// or -all for every validator of the lock. With neither, or both, it
// refuses before it asks the signer anything.
func TestDVExitBatchNamed(t *testing.T) {
	f := newDVFake(t, "ci-test")
	idx := writeIndexFile(t, f.fc.path("indices.json"), f.index)
	pks := writeFile(t, f.fc.path("batch.txt"), f.c.groups[0].String()+"\n")
	out := f.fc.path("s2.partials.json")
	cmd := func(extra ...string) []string {
		return append([]string{"dv-exit", "-cluster", f.fc.cluster, "-signer", "s2", "-split", f.split, "-lock", f.lock,
			"-indices", idx, "-epoch", "1", "-yes", "-out", out}, extra...)
	}
	wantIn(t, failTool(t, cmd()...), "name the batch: -pubkeys FILE, or -all for every validator of "+f.lock)
	wantIn(t, failTool(t, cmd("-all", "-pubkeys", pks)...), "-pubkeys and -all: give one of them")
	f.noSigned(t, "s2", out, "no batch named")
}

// dv-exit prints the batch (count, signer and share_idx, epoch, lock
// hash, chain, each validator's index and key) and signs only after the
// answer yes on a terminal, or with -yes. A stdin that is not a terminal,
// any other answer and EOF stop it before the first signature.
func TestDVExitConfirm(t *testing.T) {
	f := newDVFake(t, "hoodi")
	idx := writeIndexFile(t, f.fc.path("indices.json"), f.index)
	out := f.fc.path("s2.partials.json")
	cmd := []string{"dv-exit", "-cluster", f.fc.cluster, "-signer", "s2", "-split", f.split, "-lock", f.lock, "-indices", idx, "-all", "-out", out}
	batch := f.dvExitBatchLines("256 (the default on hoodi)")
	const question = "Type yes to sign these 3 partial exits: "
	for _, c := range []struct {
		terminal bool
		answer   string
		want     string
	}{
		{false, "yes\n", "stdin is not a terminal to confirm the batch: -yes confirms it, -check only checks it"},
		{true, "y\n", "not confirmed: nothing signed"},
		{true, "YES\n", "not confirmed: nothing signed"},
		{true, "no\n", "not confirmed: nothing signed"},
		{true, "", "not confirmed: nothing signed"},
	} {
		asked := fakePrompt(t, c.terminal, c.answer)
		wantIn(t, failTool(t, cmd...), append(batch, c.want)...)
		if prompted := strings.Contains(asked.String(), question); prompted != c.terminal {
			t.Fatalf("terminal %v: prompt %q", c.terminal, asked.String())
		}
		f.noSigned(t, "s2", out, fmt.Sprintf("terminal %v, answer %q", c.terminal, c.answer))
	}

	asked := fakePrompt(t, true, "yes\n")
	wantIn(t, mustTool(t, cmd...), append(batch, "wrote "+out)...)
	wantIn(t, asked.String(), question)
	f.checkPartials(t, out, "s2", 2, 256, 0, 1, 2)

	// -yes, for scripts: no question.
	if err := os.Remove(out); err != nil {
		t.Fatal(err)
	}
	asked = fakePrompt(t, false, "")
	wantIn(t, mustTool(t, append(cmd, "-yes")...), append(batch, "wrote "+out)...)
	if asked.Len() != 0 {
		t.Fatalf("asked with -yes: %q", asked.String())
	}
	f.checkPartials(t, out, "s2", 2, 256, 0, 1, 2)
}

// dropOnRead is an answer to the question that takes long: before the
// answer arrives the runner drops every connection, as a runner does with
// one idle past its timeout.
type dropOnRead struct {
	drop   func()
	answer *strings.Reader
}

func (d *dropOnRead) Read(p []byte) (int, error) {
	if d.drop != nil {
		d.drop()
		d.drop = nil
	}
	return d.answer.Read(p)
}

// The answer yes can come after the runner dropped the connection dv-exit
// checked the shares on: dv-exit signs on a new connection, and every
// partial exit is signed.
func TestDVExitSlowAnswer(t *testing.T) {
	f := newDVFake(t, "hoodi")
	idx := writeIndexFile(t, f.fc.path("indices.json"), f.index)
	out := f.fc.path("s2.partials.json")
	asked := fakePrompt(t, true, "")
	confirmIn = &dropOnRead{drop: f.fc.runners["s2"].DropConns, answer: strings.NewReader("yes\n")}
	res := mustTool(t, "dv-exit", "-cluster", f.fc.cluster, "-signer", "s2", "-split", f.split, "-lock", f.lock, "-indices", idx, "-all", "-out", out)
	wantIn(t, res, "3 partial exits of s2 (share_idx 2)", "wrote "+out)
	wantIn(t, asked.String(), "Type yes to sign these 3 partial exits: ")
	f.checkPartials(t, out, "s2", 2, 256, 0, 1, 2)
}

// dv-exit -check runs every check, the signer's key list too, prints the
// batch and stops: no question, no sign request, no file. A batch that
// fails a check is refused as without -check.
func TestDVExitCheck(t *testing.T) {
	f := newDVFake(t, "hoodi")
	idx := writeIndexFile(t, f.fc.path("indices.json"), f.index)
	out := f.fc.path("s2.partials.json")
	asked := fakePrompt(t, false, "")
	res := mustTool(t, "dv-exit", "-cluster", f.fc.cluster, "-signer", "s2", "-split", f.split, "-lock", f.lock, "-indices", idx, "-all", "-check")
	t.Logf("dv-exit -check\n%s", res)
	wantIn(t, res, append(f.dvExitBatchLines("256 (the default on hoodi)"), "-check: every check passed; nothing signed, nothing written")...)
	if asked.Len() != 0 {
		t.Fatalf("asked with -check: %q", asked.String())
	}
	f.noSigned(t, "s2", out, "-check")
	if f.fc.runners["s2"].Seen(wire.TypePublicKeys) == 0 {
		t.Fatal("-check did not ask the signer for its keys")
	}

	two := writeIndexFile(t, f.fc.path("two.json"), map[cloud.Pubkey]uint64{f.c.groups[0]: 100, f.c.groups[1]: 101})
	wantIn(t, failTool(t, "dv-exit", "-cluster", f.fc.cluster, "-signer", "s2", "-split", f.split, "-lock", f.lock, "-indices", two, "-all", "-check"),
		"validator "+f.c.groups[2].String()+" has no index in "+two)
}

// The dvt build has the dv exit commands.
func TestDVTBuildHasDVExitCommands(t *testing.T) {
	all := failTool(t)
	for _, c := range []string{"dv-indices", "dv-exit", "dv-exit-post"} {
		wantIn(t, all, "signer-admin "+c+" ")
		wantIn(t, failTool(t, c), "usage: signer-admin "+c+" ")
	}
}

// dv-indices and dv-exit -beacon take only a 200 as the node's answer: a
// 404 ("state not found") must not read as "no key is a validator".
func TestDVExitBeaconIndicesNot200(t *testing.T) {
	c := newCharonCluster(t, 2, 3, 4)
	for _, code := range []int{http.StatusNotFound, http.StatusServiceUnavailable} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) }))
		f, err := beaconIndices(context.Background(), srv.URL, c.groups)
		srv.Close()
		if err == nil || !strings.Contains(err.Error(), fmt.Sprint(code)) {
			t.Fatalf("HTTP %d: indices %v, err %v", code, f, err)
		}
	}
}
