//go:build !debugimport

package server

import (
	"math/big"
	"testing"

	"github.com/lidofinance/tee-signer/governance/importorder"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/sealedimport"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
)

// The test env of the key mode a build runs, for the tests of marks,
// floors, restarts, state copies and imports that hold in every mode. The
// dvt build runs dv_share setups only (CheckSigningMode), so there these
// tests run on a dv_share runner; the default build runs them as before.

// newVariantEnv is newTgtEnv in the default build, and newDVEnv's runner
// (the threshold dev sample with signing_mode = dv_share, changed by
// change) in the dvt build. importSealed imports a key into either.
func newVariantEnv(t *testing.T, platName string, change func(s *setupwire.Setup)) *tgtEnv {
	t.Helper()
	if !dvtBuild() {
		return newTgtEnv(t, platName, change)
	}
	return newTgtEnvOf(t, "setup-dev-threshold", platName, func(s *setupwire.Setup) {
		s.SigningMode = setupwire.SigningModeDVShare
		if change != nil {
			change(s)
		}
	})
}

// newVariantShareEnv is newShareTgtEnv in the default build, and
// newVariantEnv's dv_share runner in the dvt build.
func newVariantShareEnv(t *testing.T, platName string, change func(s *setupwire.Setup)) *tgtEnv {
	t.Helper()
	if !dvtBuild() {
		return newShareTgtEnv(t, platName, change)
	}
	return newVariantEnv(t, platName, change)
}

// blsOrder is r, the order of the BLS12-381 scalar field.
var blsOrder, _ = new(big.Int).SetString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)

// dvSplitOf is a 2-of-3 split of a fresh group key whose share 1 is sk:
// f(x) = g + (sk - g)x mod r, with g random. It returns the group key and
// the split's commitments, the public keys of g and sk - g.
func dvSplitOf(t *testing.T, sk [32]byte) (backend.Pubkey, []backend.Pubkey) {
	t.Helper()
	for {
		g, err := software.NewSecret()
		if err != nil {
			t.Fatal(err)
		}
		a := new(big.Int).Sub(new(big.Int).SetBytes(sk[:]), new(big.Int).SetBytes(g[:]))
		a.Mod(a, blsOrder)
		if a.Sign() == 0 {
			continue // g = sk: draw again
		}
		var a1 [32]byte
		a.FillBytes(a1[:])
		gpk, err := core.PubkeyOf(g)
		if err != nil {
			t.Fatal(err)
		}
		apk, err := core.PubkeyOf(a1)
		if err != nil {
			t.Fatal(err)
		}
		return gpk, []backend.Pubkey{gpk, apk}
	}
}

// dvImportRequest is the sealed import request of a dv_share runner for
// the key sk: share 1 of a fresh 2-of-3 split (dvSplitOf), under an order
// the approvers signed for the split's group key. Its share_pubkey is pk,
// the key the runner files and serves the share under; a pk that is not
// the key of sk makes a request the runner must refuse.
func (e *tgtEnv) dvImportRequest(pk backend.Pubkey, sk [32]byte, index uint64, interchange *backend.Watermark) backend.SealedImportRequest {
	e.t.Helper()
	group, commitments := dvSplitOf(e.t, sk)
	order := e.importOrder([]byte{1, 2}, group, func(b *importorder.Body) {
		b.T, b.N, b.ShareIndex = 2, 3, 1
		b.Validators[0].CommitmentsHash = importorder.CommitmentsHash(commitments)
	})
	return backend.SealedImportRequest{Pubkey: group, SharePubkey: pk, Index: index, Interchange: interchange,
		Order: order, T: 2, N: 3, ShareIndex: 1, Commitments: commitments}
}

// wantGroupKey fails the test unless pk's stored record carries a group
// key exactly when the setup says dv_share, so a test of newVariantEnv in
// the dvt build checks a dv_share key, not one of another mode.
func (e *tgtEnv) wantGroupKey(pk backend.Pubkey) {
	e.t.Helper()
	dv := e.setup.SigningMode == setupwire.SigningModeDVShare
	rec := e.recordOf(pk)
	if g := rec.groupKey(); (g != nil) != dv {
		e.t.Fatalf("key %s: group key %v, setup signing_mode = %s", pk.String()[:18], g, e.setup.SigningMode)
	}
}

// dvBatchPayload is batchPayload for a dv_share runner: each key sks[i] is
// share 1 of its own split (dvImportRequest), and the one order names the
// split's group keys. A key listed twice has one split.
func (e *tgtEnv) dvBatchPayload(sks [][32]byte, pks []backend.Pubkey, corrupt func(i int, r *backend.SealedImportRequest)) []byte {
	e.t.Helper()
	reqs := make([]backend.SealedImportRequest, len(pks))
	first := map[backend.Pubkey]int{}
	var entries []importorder.Entry
	for i, pk := range pks {
		r := &reqs[i]
		if j, ok := first[pk]; ok {
			*r = reqs[j]
			r.Index = uint64(100 + i)
		} else {
			first[pk] = i
			*r = e.dvImportRequest(pk, sks[i], uint64(100+i), nil)
			entries = append(entries, importorder.Entry{Pubkey: r.Pubkey, CommitmentsHash: importorder.CommitmentsHash(r.Commitments)})
		}
		r.Order = nil
	}
	order := e.importOrder([]byte{1, 2}, reqs[0].Pubkey, func(b *importorder.Body) {
		b.T, b.N, b.ShareIndex = 2, 3, 1
		b.Validators = entries
	})
	id := e.sealTo()
	for i := range reqs {
		r := &reqs[i]
		var err error
		if r.Sealed, err = sealedimport.Seal(id, r, &sks[i]); err != nil {
			e.t.Fatal(err)
		}
		if corrupt != nil {
			corrupt(i, r)
		}
	}
	p, err := wireadmin.EncodeImportBatch(order, reqs)
	if err != nil {
		e.t.Fatal(err)
	}
	return p
}

// addShareOf is srv.addShare as a sealed import calls it: under
// signing_mode = dv_share with the group key of a fresh split (dvSplitOf).
func (e *tgtEnv) addShareOf(pk backend.Pubkey, sk *[32]byte, index uint64, interchange *backend.Watermark) (backend.ValidatorKey, error) {
	e.t.Helper()
	if e.setup.SigningMode != setupwire.SigningModeDVShare {
		return e.srv.addShare(pk, sk, index, interchange, "sealed")
	}
	group, _ := dvSplitOf(e.t, *sk)
	return e.srv.addShareGroup(pk, sk, index, interchange, &group, "sealed")
}
