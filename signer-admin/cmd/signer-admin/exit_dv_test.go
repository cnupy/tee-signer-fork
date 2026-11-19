package main

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	cloud "github.com/lidofinance/tee-signer/signer-protocol"
)

// exit on a dv_share cluster: -pubkey names the validator's group key,
// and each dv_share runner, which lists its share under the share's own
// key, signs with that key. The partials of exit -partial-out combine
// with exit-combine and the dv-split commitments into the exit of the
// one-run path, which verifies under the group key.
func TestExitDVShareGroupKey(t *testing.T) {
	f := newDVFake(t, "ci-test")
	g := f.c.groups[1]
	var parts []string
	for i, name := range names {
		p := f.fc.path(name + ".partial.json")
		res := mustTool(t, "exit", "-cluster", f.fc.cluster, "-signers", name, "-split", f.split,
			"-pubkey", g.String(), "-index", "101", "-epoch", "1", "-partial-out", p)
		wantIn(t, res, "signed by "+name+" (3 needed in all)", "wrote "+p)
		var e exitPartials
		if err := json.Unmarshal(mustRead(t, p), &e); err != nil {
			t.Fatal(err)
		}
		if e.Pubkey != g || len(e.Partials) != 1 || e.Partials[0].ShareIndex != uint64(i+1) {
			t.Fatalf("%s: partial file %+v, want group key %s and share index %d", name, e, g, i+1)
		}
		if !core.Verify(f.c.sharePub(t, 1, i), f.exitRoot(1, 101), e.Partials[0].Signature) {
			t.Fatalf("%s: the partial does not verify under share key %d", name, i+1)
		}
		parts = append(parts, p)
	}
	combined := f.fc.path("combined.json")
	res := mustTool(t, append([]string{"exit-combine", "-split", f.split, "-out", combined}, parts...)...)
	wantIn(t, res, "combined from s1,s2,s3 (3 needed); the signature verifies")
	f.checkExitFile(t, combined, 1, 1)

	one := f.fc.path("one.json")
	res = mustTool(t, "exit", "-cluster", f.fc.cluster, "-split", f.split, "-pubkey", g.String(), "-index", "101", "-epoch", "1", "-out", one)
	wantIn(t, res, "signed by s1,s2,s3 (3 needed)")
	if !bytes.Equal(mustRead(t, one), mustRead(t, combined)) {
		t.Fatal("the one-run exit differs from the combined one")
	}
}

// exit refuses a share key in -pubkey with a message that names the
// share index and the group key, and a key that is no validator of the
// split. It writes nothing.
func TestExitDVShareKeyRefused(t *testing.T) {
	f := newDVFake(t, "ci-test")
	share := f.c.sharePub(t, 0, 2)
	sk, _ := software.NewSecret()
	other, _ := core.PubkeyOf(sk)
	for _, c := range []struct {
		pk   cloud.Pubkey
		want []string
	}{
		{share, []string{"-pubkey " + share.String() + " is share 3 of validator " + f.c.groups[0].String(), "name the validator by its group key"}},
		{other, []string{"-pubkey " + other.String() + " is no validator of " + f.split}},
	} {
		for _, mode := range []string{"-out", "-partial-out"} {
			out := f.fc.path("refused.json")
			wantIn(t, failTool(t, "exit", "-cluster", f.fc.cluster, "-signers", "s3", "-split", f.split,
				"-pubkey", c.pk.String(), "-index", "100", "-epoch", "1", mode, out), c.want...)
			if _, err := os.Stat(out); err == nil {
				t.Fatalf("a refused exit wrote %s", out)
			}
		}
	}
}
