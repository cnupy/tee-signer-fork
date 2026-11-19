//go:build dvt

package main

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	cloud "github.com/lidofinance/tee-signer/signer-protocol"
)

// Exit route B on a dvt dev runner: through the admin role the runner
// signs the partial exit of its share (exit -partial-out with the group
// key, and dv-exit for the batch, which give the same signature); the
// signing role cannot. With the partials of shares 1 and 3, as their
// operators' keystores would sign them, exit-combine and the dv-split
// commitments give a full exit that verifies under the group key.
func TestDVShareDevRunnerExit(t *testing.T) {
	r := startDVRun(t)
	shares := r.sharesFile(t, "shares.txt", func(v int) string { return r.c.sharePub(t, v, 1).String() })
	mustTool(t, "import", "-cluster", r.cl, "-signer", "d1", "-order", r.signed, "-shares", shares, "-commitments", r.split)

	// The chain of setupText, the runner's.
	cfg := software.DevConfig(uint64(genesisTime()), secondsPerSlot, slotsPerEpoch)
	copy(cfg.GenesisValidatorsRoot[:], mustHex(t, r.gvr))
	copy(cfg.VoluntaryExitForkVersion[:], mustHex(t, "0x04000010"))
	g := r.c.groups[0]
	msg := &cloud.VoluntaryExit{Epoch: 1, ValidatorIndex: 100}
	domain := cloud.ComputeDomain(cloud.DomainVoluntaryExit, cfg.VoluntaryExitForkVersion, cfg.GenesisValidatorsRoot)
	obj, _ := cloud.HashTreeRoot(msg)
	root := cloud.SigningRoot(obj, domain)

	p2 := filepath.Join(r.dir, "d1.partial.json")
	res := mustTool(t, "exit", "-cluster", r.cl, "-signers", "d1", "-split", r.split, "-pubkey", g.String(),
		"-index", "100", "-epoch", "1", "-partial-out", p2)
	t.Logf("exit -partial-out\n%s", res)
	var part exitPartials
	if err := json.Unmarshal(mustRead(t, p2), &part); err != nil {
		t.Fatal(err)
	}
	if part.Pubkey != g || len(part.Partials) != 1 || part.Partials[0].ShareIndex != 2 ||
		!core.Verify(r.c.sharePub(t, 0, 1), root, part.Partials[0].Signature) {
		t.Fatalf("partial file %+v: want share 2 of %s, verifying under its share key", part, g)
	}

	// The signing role's certificate gets FORBIDDEN for the same exit.
	conn, err := loadConn(filepath.Join(r.dir, "d1-lane", "cloud.json"))
	if err != nil {
		t.Fatal(err)
	}
	lane, err := conn.New(runnerclient.WithTimeout(10 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer lane.Close()
	if _, err := lane.Sign(context.Background(), cloud.SignRequest{Pubkey: r.c.sharePub(t, 0, 1), Message: msg, Domain: domain}); cloud.StatusOf(err) != cloud.StatusForbidden {
		t.Fatalf("exit with the signing role: %v, want FORBIDDEN", err)
	}

	// The batch: the same partial for validator 0, and validator 1's.
	lock := dvLockFile(t, r.c, filepath.Join(r.dir, "cluster-lock.json"), "0x00000001", [32]byte{0x10, 0xc4}, nil)
	idx := filepath.Join(r.dir, "indices.json")
	writeJSONFile(t, idx, map[string]any{"data": []map[string]any{
		{"index": "100", "status": "active_ongoing", "validator": map[string]any{"pubkey": g.String()}},
		{"index": "101", "status": "active_ongoing", "validator": map[string]any{"pubkey": r.c.groups[1].String()}},
	}})
	batch := filepath.Join(r.dir, "d1.partials.json")
	res = mustTool(t, "dv-exit", "-cluster", r.cl, "-signer", "d1", "-split", r.split, "-lock", lock, "-indices", idx, "-epoch", "1", "-all", "-yes", "-out", batch)
	t.Logf("dv-exit\n%s", res)
	b := readDVPartials(t, batch)
	if len(b.PartialExits) != 2 || b.PartialExits[0].PublicKey != g.String() || b.PartialExits[0].SignedExitMessage.Signature != hexOf(part.Partials[0].Signature[:]) {
		t.Fatalf("batch %+v: want validator 0's partial %s first", b, part.Partials[0].Signature)
	}

	// Shares 1 and 3, from keystores. The split names all three holders.
	split3 := filepath.Join(r.dir, "split3.json")
	mustTool(t, "dv-split", "-lock", lock, "-signers", "k1=1,d1=2,k3=3", "-out", split3)
	files := []string{p2}
	for _, i := range []int{0, 2} {
		s, err := core.NewSigner(cfg, 1, 0, software.NewMemHooks())
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if _, err := s.AddValidator(r.c.sharePub(t, 0, i), r.c.secrets[0][i], 100, nil); err != nil {
			t.Fatal(err)
		}
		sig, err := s.Sign(cloud.SignRequest{Pubkey: r.c.sharePub(t, 0, i), Message: msg, Domain: domain})
		if err != nil {
			t.Fatal(err)
		}
		name := map[int]string{0: "k1", 2: "k3"}[i]
		files = append(files, writeJSONFile(t, filepath.Join(r.dir, name+".partial.json"), exitPartials{
			Pubkey: g, ValidatorIndex: 100, Epoch: 1, VoluntaryExitForkVersion: cfg.VoluntaryExitForkVersion,
			GenesisValidatorsRoot: cfg.GenesisValidatorsRoot, Partials: []exitPartialSig{{Signer: name, ShareIndex: uint64(i + 1), Signature: sig}}}))
	}
	full := filepath.Join(r.dir, "exit.json")
	res = mustTool(t, append([]string{"exit-combine", "-split", split3, "-out", full}, files...)...)
	t.Logf("exit-combine\n%s", res)
	var body exitJSON
	if err := json.Unmarshal(mustRead(t, full), &body); err != nil {
		t.Fatal(err)
	}
	var sig cloud.Signature
	if err := sig.UnmarshalText([]byte(body.Signature)); err != nil || body.Message.ValidatorIndex != "100" || body.Message.Epoch != "1" ||
		!core.Verify(g, root, sig) {
		t.Fatalf("full exit %+v does not verify under the group key %s (%v)", body, g, err)
	}
}
