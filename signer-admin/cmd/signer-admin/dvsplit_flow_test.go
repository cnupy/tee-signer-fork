package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	cloud "github.com/lidofinance/tee-signer/signer-protocol"
)

// dvRun is a dev runner of a dv_share setup, with an import order for
// share 2 of a Charon cluster lock (3 of 4) that two approvers signed.
type dvRun struct {
	dir, cl, split, signed string
	c                      *charonCluster
	gvr                    string // the chain's genesis_validators_root, 0x hex
}

// startDVRun starts the runner of dvRun: a setup that says
// signing_mode = dv_share, dv-split from the lock, import-draft and two
// approvers. SIGNER_ADMIN_DVT_RUNNER names a dev runner binary of this
// repo built with the tag dvt (a default runner refuses a dv_share setup);
// without it the test is skipped. make test-dvt sets it.
func startDVRun(t *testing.T) *dvRun {
	t.Helper()
	bin := os.Getenv("SIGNER_ADMIN_DVT_RUNNER")
	if bin == "" {
		t.Skip("SIGNER_ADMIN_DVT_RUNNER is not set (a dev runner binary of this repo built with -tags dvt)")
	}
	dir := t.TempDir()
	pki, ca, cert, key := clientPKIWith(t, dir)
	signCert, signKey := filepath.Join(dir, "signing.pem"), filepath.Join(dir, "signing-key.pem")
	pki.issue(t, signCert, signKey, false)
	keys := approvers(t, dir, 3)
	genesis := genesisTime()
	text := strings.Replace(setupText(dir, ca, genesis, lockedText(keys, 2, 0, fee1), "d1"), "signing_mode = single", "signing_mode = dv_share", 1)
	conf := writeFile(t, filepath.Join(dir, "setup.conf"), text)
	hashes := setupHashes(mustTool(t, "setup", "-out", filepath.Join(dir, "setups"), conf))

	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	logPath := writeFile(t, filepath.Join(dir, "d1", "runner.log"), "")
	f, err := os.OpenFile(logPath, os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-platform", "dev", "-state-dir", filepath.Join(dir, "d1", "state"), "-listen", "tcp:"+addr,
		"-setup", "file:"+filepath.Join(dir, "setups", "d1.setup"))
	cmd.Stdout, cmd.Stderr = f, f
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		f.Close()
		if t.Failed() {
			t.Logf("---- %s ----\n%s", logPath, mustRead(t, logPath))
		}
	})
	waitTCP(t, addr)
	for _, c := range []struct{ name, cert, key string }{{"d1", cert, key}, {"d1-lane", signCert, signKey}} {
		writeJSONFile(t, filepath.Join(dir, c.name, "cloud.json"), map[string]any{
			"address": "tcp:" + addr, "client_cert": c.cert, "client_key": c.key,
			"attestation": map[string]any{"verifier": "dev", "setup_sha256": hashes["d1"]},
		})
	}
	cl := writeJSONFile(t, filepath.Join(dir, "cluster.json"), map[string]any{"signers": []map[string]string{
		{"name": "d1", "cloud": "d1/cloud.json", "setup": "setups/d1.setup"}}})

	c := newCharonCluster(t, 2, 3, 4)
	lock := c.lock(t, filepath.Join(dir, "cluster-lock.json"), nil)
	splitPath := filepath.Join(dir, "split.json")
	mustTool(t, "dv-split", "-lock", lock, "-signers", "d1=2", "-out", splitPath)

	setup, err := setupwire.DecodeSetup(mustRead(t, filepath.Join(dir, "setups", "d1.setup")))
	if err != nil {
		t.Fatal(err)
	}
	body := filepath.Join(dir, "import.bin")
	wantIn(t, failTool(t, "import-draft", "-cluster", cl, "-signer", "d1", "-split", splitPath, "-out", body), "-lock is required")
	other := newCharonCluster(t, 2, 3, 4).lock(t, filepath.Join(dir, "other-lock.json"), nil)
	wantIn(t, failTool(t, "import-draft", "-cluster", cl, "-signer", "d1", "-split", splitPath, "-lock", other, "-out", body), "is not in")
	var ids []string
	beacon := fakeBeaconOf(t, &setup.Chain, map[cloud.Pubkey]string{c.groups[0]: "active_ongoing", c.sharePub(t, 0, 1): "active_ongoing"}, &ids)
	wantIn(t, failTool(t, "import-draft", "-cluster", cl, "-signer", "d1", "-split", splitPath, "-lock", lock, "-beacon", beacon.URL, "-out", body),
		"is itself a validator")
	// No chain check: one question, which only y or yes passes.
	draft := []string{"import-draft", "-cluster", cl, "-signer", "d1", "-split", splitPath, "-lock", lock, "-out", body}
	asked := fakePrompt(t, true, "n\n")
	wantIn(t, failTool(t, draft...), "not confirmed")
	wantIn(t, asked.String(), "No chain check for these 2 keys")
	if _, err := os.Stat(body); err == nil {
		t.Fatal("the order was written without a yes")
	}
	fakePrompt(t, true, "")
	wantIn(t, failTool(t, draft...), "not confirmed")
	fakePrompt(t, false, "y\n")
	wantIn(t, failTool(t, draft...), "stdin is not a terminal")
	fakePrompt(t, true, "y\n")
	mustTool(t, draft...)
	// A beacon node that knows the group keys: no question.
	known := fakeBeaconOf(t, &setup.Chain, map[cloud.Pubkey]string{c.groups[0]: "active_ongoing", c.groups[1]: "active_ongoing"}, &ids)
	asked = fakePrompt(t, true, "")
	mustTool(t, append(draft, "-beacon", known.URL)...)
	if asked.Len() != 0 {
		t.Fatalf("asked with the keys on chain: %q", asked.String())
	}
	asked = fakePrompt(t, true, "")
	out := mustTool(t, append(draft, "-yes")...)
	wantIn(t, out, "share 2 of each is the lock's public share", "beacon check skipped")
	if asked.Len() != 0 {
		t.Fatalf("asked with -yes: %q", asked.String())
	}
	var sigs []string
	for _, i := range []int{0, 2} {
		mustTool(t, "sign", "-key", keys[i].file, "-expect-sha256", expectOf(t, body), body)
		sigs = append(sigs, fmt.Sprintf("%s.%s.sig", body, keys[i].pub[2:10]))
	}
	signed := filepath.Join(dir, "import.signed")
	mustTool(t, append([]string{"assemble", "-out", signed, body}, sigs...)...)
	return &dvRun{dir: dir, cl: cl, split: splitPath, signed: signed, c: c,
		gvr: "0x" + hex.EncodeToString(setup.Chain.GenesisValidatorsRoot[:])}
}

// sharesFile writes a shares file of share 2 of each validator; line
// gives each line's key.
func (r *dvRun) sharesFile(t *testing.T, name string, line func(v int) string) string {
	t.Helper()
	var lines strings.Builder
	for v := range r.c.groups {
		fmt.Fprintf(&lines, "%s %d 0x%x\n", line(v), 100+v, r.c.secrets[v][1])
	}
	path := filepath.Join(r.dir, name)
	if err := os.WriteFile(path, []byte(lines.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The dv_share track with a dev runner, and import from the shares file of
// a single-mode import (each share under its own key). The runner lists
// each share under its own key and signs its partial selection proof with
// it.
func TestDVShareDevRunner(t *testing.T) {
	r := startDVRun(t)
	dir, cl, c := r.dir, r.cl, r.c
	sharesPath := r.sharesFile(t, "shares.txt", func(v int) string { return c.sharePub(t, v, 1).String() })
	out := mustTool(t, "import", "-cluster", cl, "-signer", "d1", "-order", r.signed, "-shares", sharesPath, "-commitments", r.split)
	t.Logf("import\n%s", out)
	wantIn(t, out, "2 shares named by their own key", "imported 2 shares")

	conn, err := loadConn(filepath.Join(dir, "d1-lane", "cloud.json"))
	if err != nil {
		t.Fatal(err)
	}
	lane, err := conn.New(runnerclient.WithTimeout(10 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer lane.Close()
	ctx := context.Background()
	held, err := lane.PublicKeys(ctx)
	if err != nil || len(held) != 2 {
		t.Fatalf("PUBLIC_KEYS: %v, %v", held, err)
	}
	for v := range c.groups {
		sp := c.sharePub(t, v, 1)
		found := false
		for _, k := range held {
			found = found || k.Pubkey == sp && k.SharePubkey == sp
		}
		if !found {
			t.Fatalf("validator %d: the runner does not list share %s under its own key: %+v", v, sp, held)
		}
	}
}

// A shares file may name each share by its group key, the form of a
// threshold import. A dv_share runner lists the share under its own key,
// and a Charon validator client's slashing protection file names it so:
// -interchange looks each share up under its own key, and -skip-loaded
// skips the shares the runner lists, so a cut import can go on.
func TestDVShareDevRunnerGroupKeyLines(t *testing.T) {
	r := startDVRun(t)
	sharesPath := r.sharesFile(t, "shares.txt", func(v int) string { return r.c.groups[v].String() })
	var items []string
	for v := range r.c.groups {
		items = append(items, `{"pubkey":"`+r.c.sharePub(t, v, 1).String()+
			`","signed_blocks":[],"signed_attestations":[{"source_epoch":"1","target_epoch":"2"}]}`)
	}
	ic := writeFile(t, filepath.Join(r.dir, "ic.json"), `{"metadata":{"interchange_format_version":"5","genesis_validators_root":"`+
		r.gvr+`"},"data":[`+strings.Join(items, ",")+`]}`)
	args := []string{"import", "-cluster", r.cl, "-signer", "d1", "-order", r.signed, "-shares", sharesPath, "-commitments", r.split}
	out := mustTool(t, append(args, "-interchange", ic)...)
	t.Logf("import -interchange\n%s", out)
	wantIn(t, out, "source 1 target 2 (true)", "imported 2 shares")
	out = mustTool(t, append(args, "-skip-loaded")...)
	t.Logf("import -skip-loaded\n%s", out)
	wantIn(t, out, "imported 0 shares, skipped 2 already held")
}
