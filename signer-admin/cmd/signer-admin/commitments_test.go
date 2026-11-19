package main

import (
	"testing"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	cloud "github.com/lidofinance/tee-signer/signer-protocol"
)

// Commitments from t share public keys are the split's own Feldman
// commitments, whichever t shares they come from (a Charon cluster lock
// gives the share public keys and no commitments).
func TestCommitmentsFromShares(t *testing.T) {
	secret, _ := software.NewSecret()
	shares, want, err := software.SplitWithCommitments(secret, 3, 5)
	if err != nil {
		t.Fatal(err)
	}
	pub := map[uint64]cloud.Pubkey{}
	for _, s := range shares {
		pub[s.ID], _ = core.PubkeyOf(s.Secret)
	}
	for _, ids := range [][]uint64{{1, 2, 3}, {5, 1, 4}, {2, 4, 5}} {
		got, err := commitmentsFromShares(ids, []cloud.Pubkey{pub[ids[0]], pub[ids[1]], pub[ids[2]]})
		if err != nil || len(got) != 3 {
			t.Fatalf("%v: %v", ids, err)
		}
		for k := range want {
			if got[k] != want[k] {
				t.Fatalf("%v: commitment %d differs", ids, k)
			}
		}
	}
	if _, err := commitmentsFromShares([]uint64{1, 1}, []cloud.Pubkey{pub[1], pub[1]}); err == nil {
		t.Fatal("accepted a repeated id")
	}
	if _, err := commitmentsFromShares([]uint64{0, 1}, []cloud.Pubkey{pub[1], pub[2]}); err == nil {
		t.Fatal("accepted id 0")
	}
	if _, err := commitmentsFromShares([]uint64{1, 2}, []cloud.Pubkey{pub[1], {}}); err == nil {
		t.Fatal("accepted a malformed key")
	}
}
