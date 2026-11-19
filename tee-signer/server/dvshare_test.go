//go:build dvt && !debugimport

package server

import (
	"math/big"
	"strings"
	"sync"
	"testing"

	"github.com/lidofinance/tee-signer/governance/importorder"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/sealedimport"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
)

// newDVEnv is a runner whose setup says signing_mode = dv_share.
func newDVEnv(t *testing.T) *tgtEnv {
	t.Helper()
	return newShareTgtEnv(t, "dev", func(s *setupwire.Setup) { s.SigningMode = setupwire.SigningModeDVShare })
}

// request is the IMPORT_SHARE_SEALED request of share (sk, index) of d,
// under an order the approvers signed for the group key.
func (e *tgtEnv) dvRequest(d *dvShare, sk [32]byte, index uint8) backend.SealedImportRequest {
	e.t.Helper()
	sp, _ := core.PubkeyOf(sk)
	order := e.importOrder([]byte{1, 2}, d.group, func(b *importorder.Body) {
		b.T, b.N, b.ShareIndex = 3, 4, index
		b.Validators[0].CommitmentsHash = importorder.CommitmentsHash(d.commitments)
	})
	req := backend.SealedImportRequest{Pubkey: d.group, SharePubkey: sp, Index: 9, Order: order,
		T: 3, N: 4, ShareIndex: index, Commitments: d.commitments}
	var err error
	if req.Sealed, err = sealedimport.Seal(e.sealTo(), &req, &sk); err != nil {
		e.t.Fatal(err)
	}
	return req
}

func (e *tgtEnv) importDV(d *dvShare) error {
	e.t.Helper()
	req := e.dvRequest(d, d.sk, d.index)
	p, err := wireadmin.EncodeImportSealed(&req)
	if err != nil {
		e.t.Fatal(err)
	}
	_, err = e.srv.dispatch(ctx, wire.Frame{Type: wireadmin.TypeImportSealed, Payload: p})
	return err
}

// A dv_share runner takes a share of a Charon split under the approvers'
// order for the group key, and serves it under the share's own key, the
// key the Charon validator client asks for. A contribution that carries
// the group's selection proof signs; the group key is no key of the
// runner. After a restart the sealed record brings the group key back.
func TestDVShareImportAndSign(t *testing.T) {
	e := newDVEnv(t)
	d := newDVShare(t)
	if err := e.importDV(d); err != nil {
		t.Fatalf("import: %v", err)
	}
	keys := e.srv.Signer.Keys()
	if len(keys) != 1 || keys[0].Pubkey != d.pk || keys[0].SharePubkey != d.pk {
		t.Fatalf("keys %+v, want the share key %s alone", keys, d.pk.String()[:18])
	}
	if rec := e.recordOf(d.pk); rec.GroupPubkey == nil || *rec.GroupPubkey != d.group {
		t.Fatalf("record group key %v, want %s", rec.GroupPubkey, d.group.String()[:18])
	}
	con := e.groupContribution(d.groupSk, d.group)
	if err := e.signMsg(d.pk, con); err != nil {
		t.Fatalf("contribution with the group's proof: %v", err)
	}
	if err := e.signMsg(d.group, con); backend.StatusOf(err) != backend.StatusUnknownValidator {
		t.Fatalf("sign under the group key: %v, want UNKNOWN_VALIDATOR", err)
	}
	// The protocol level stays 2: a client that does not know dv_share reads
	// the mode as unknown and refuses the keys (the gateway's whole-key gate).
	if h, err := e.srv.health(); err != nil || h.SigningMode != "dv_share" || h.EffectiveProtocol() != 2 {
		t.Fatalf("HEALTH signing_mode, protocol: %v, %v", h, err)
	}

	e.restart()
	if !hasKey(e.srv.Signer.Keys(), d.pk) {
		t.Fatal("the share did not load after a restart")
	}
	if err := e.signMsg(d.pk, e.groupContribution(d.groupSk, d.group)); err != nil {
		t.Fatalf("contribution after a restart: %v", err)
	}
}

// A dv_share runner signs an aggregate and a contribution with the share
// when the selection proof is the group's, the proof a Charon cluster
// combines from its partials. A proof the share key made alone is
// refused: no aggregator duty is the share's own.
func TestDVShareAggregateSelectionProof(t *testing.T) {
	e := newDVEnv(t)
	d := newDVShare(t)
	if err := e.importDV(d); err != nil {
		t.Fatalf("import: %v", err)
	}
	for _, c := range []struct {
		name string
		m    backend.Message
		ok   bool
	}{
		{"aggregate, the group's proof", e.groupAggregate(d.groupSk, d.group), true},
		{"aggregate, the share key's proof", e.groupAggregate(d.sk, d.pk), false},
		{"contribution, the group's proof", e.groupContribution(d.groupSk, d.group), true},
		{"contribution, the share key's proof", e.groupContribution(d.sk, d.pk), false},
	} {
		err := e.signMsg(d.pk, c.m)
		if c.ok && err != nil || !c.ok && backend.StatusOf(err) != backend.StatusSelectionProof {
			t.Errorf("%s: %v, want ok %v (else SELECTION_PROOF)", c.name, err, c.ok)
		}
	}
}

// A Charon client may register the group key with the builder: a dv_share
// runner signs a registration that names the share key or the group key,
// and refuses another key. A single-mode runner takes only its own key
// (TestSingleModeRefusesGroupRegistration, default build).
func TestDVShareRegistrationPubkey(t *testing.T) {
	e := newDVEnv(t)
	d := newDVShare(t)
	if err := e.importDV(d); err != nil {
		t.Fatal(err)
	}
	_, other := newKey(t)
	for _, c := range []struct {
		name string
		pk   backend.Pubkey
		ok   bool
	}{{"group key", d.group, true}, {"share key", d.pk, true}, {"another key", other, false}} {
		err := e.signMsg(d.pk, e.registration(c.pk))
		if c.ok && err != nil || !c.ok && backend.StatusOf(err) != backend.StatusPolicyPubkey {
			t.Errorf("dv_share, registration for the %s: %v, want ok %v", c.name, err, c.ok)
		}
	}
}

// The batch import takes dv_share shares the same way, under the share keys.
func TestDVShareBatch(t *testing.T) {
	e := newDVEnv(t)
	a, b := newDVShare(t), newDVShare(t)
	order := e.importOrder([]byte{1, 2}, a.group, func(o *importorder.Body) {
		o.T, o.N, o.ShareIndex = 3, 4, 2
		o.Validators = []importorder.Entry{
			{Pubkey: a.group, CommitmentsHash: importorder.CommitmentsHash(a.commitments)},
			{Pubkey: b.group, CommitmentsHash: importorder.CommitmentsHash(b.commitments)}}
		if string(b.group[:]) < string(a.group[:]) {
			o.Validators[0], o.Validators[1] = o.Validators[1], o.Validators[0]
		}
	})
	reqs := []backend.SealedImportRequest{e.dvRequest(a, a.sk, 2), e.dvRequest(b, b.sk, 2)}
	for i := range reqs {
		reqs[i].Order = nil
	}
	p, err := wireadmin.EncodeImportBatch(order, reqs)
	if err != nil {
		t.Fatal(err)
	}
	out, err := e.srv.dispatch(ctx, wire.Frame{Type: wireadmin.TypeImportBatch, Payload: p})
	if err != nil {
		t.Fatalf("batch: %v", err)
	}
	keys, err := wire.DecodeKeys(out)
	if err != nil || len(keys) != 2 || keys[0].Pubkey != a.pk || keys[1].Pubkey != b.pk {
		t.Fatalf("batch keys %+v, %v", keys, err)
	}
	if err := e.signMsg(b.pk, e.groupContribution(b.groupSk, b.group)); err != nil {
		t.Fatalf("contribution of the batch's second key: %v", err)
	}
	e.restart()
	if !hasKey(e.srv.Signer.Keys(), a.pk) || !hasKey(e.srv.Signer.Keys(), b.pk) {
		t.Fatal("the batch's keys did not load after a restart")
	}
}

// A dv_share key exists only with its group key: a key added without one
// (the debug plain import's path) is refused, and so is a stored record
// without one. A record with one under another mode never loads: the dvt
// build runs no other mode (CheckSigningMode), and the default build reads
// no group key (TestShareRecordWithGroupKeyRefused).
func TestDVShareNeedsGroupKey(t *testing.T) {
	e := newDVEnv(t)
	sk, pk := newKey(t)
	if _, err := e.srv.addShare(pk, &sk, 1, nil, "plaintext"); backend.StatusOf(err) != backend.StatusBadKey || !strings.Contains(err.Error(), "group key") {
		t.Fatalf("dv_share key without a group key: %v, want BAD_KEY", err)
	}
	blob, err := e.srv.sealRecord(shareRecord{Pubkey: pk, Secret: sk[:], Index: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.srv.putShare(pk, blob); err != nil {
		t.Fatal(err)
	}
	if n, err := e.srv.LoadListedShares([]string{shareKey(pk)}); n != 0 || err == nil || !strings.Contains(err.Error(), "group key") {
		t.Fatalf("load of a dv_share record without a group key: %d, %v", n, err)
	}
}

// The order's split check holds in dv_share mode: a share that is not the
// commitments' value at its index is refused, so the group key the runner
// keeps is the one the share belongs to.
func TestDVShareWrongIndexRefused(t *testing.T) {
	e := newDVEnv(t)
	d := newDVShare(t)
	// The share of index 3 sent under an order for index 2.
	req := e.dvRequest(d, d.otherSk, d.index)
	p, err := wireadmin.EncodeImportSealed(&req)
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.srv.dispatch(ctx, wire.Frame{Type: wireadmin.TypeImportSealed, Payload: p})
	if backend.StatusOf(err) != backend.StatusBadKey || hasKey(e.srv.Signer.Keys(), d.otherPk) {
		t.Fatalf("share of another index: %v, want BAD_KEY", err)
	}
}

// A dv_share runner holds one share of each distributed validator, as a
// threshold runner holds one share of each validator: with t shares it
// would hold the whole key. A second share of a group key it holds is
// refused by the sealed import, by the batch import and when its record
// loads.
func TestDVShareSecondShareRefused(t *testing.T) {
	e := newDVEnv(t)
	d := newDVShare(t)
	if err := e.importDV(d); err != nil {
		t.Fatal(err)
	}
	req := e.dvRequest(d, d.otherSk, d.otherIndex)
	p, err := wireadmin.EncodeImportSealed(&req)
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.srv.dispatch(ctx, wire.Frame{Type: wireadmin.TypeImportSealed, Payload: p})
	if backend.StatusOf(err) != backend.StatusDuplicate || hasKey(e.srv.Signer.Keys(), d.otherPk) {
		t.Fatalf("sealed import of a second share: %v, want DUPLICATE", err)
	}

	order := e.importOrder([]byte{1, 2}, d.group, func(o *importorder.Body) {
		o.T, o.N, o.ShareIndex = 3, 4, d.otherIndex
		o.Validators = []importorder.Entry{{Pubkey: d.group, CommitmentsHash: importorder.CommitmentsHash(d.commitments)}}
	})
	reqs := []backend.SealedImportRequest{e.dvRequest(d, d.otherSk, d.otherIndex)}
	reqs[0].Order = nil
	if p, err = wireadmin.EncodeImportBatch(order, reqs); err != nil {
		t.Fatal(err)
	}
	_, err = e.srv.dispatch(ctx, wire.Frame{Type: wireadmin.TypeImportBatch, Payload: p})
	if backend.StatusOf(err) != backend.StatusDuplicate || hasKey(e.srv.Signer.Keys(), d.otherPk) {
		t.Fatalf("batch import of a second share: %v, want DUPLICATE", err)
	}

	blob, err := e.srv.sealRecord(shareRecord{Pubkey: d.otherPk, Secret: d.otherSk[:], Index: 9, GroupPubkey: &d.group})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.srv.putShare(d.otherPk, blob); err != nil {
		t.Fatal(err)
	}
	e.looseLoad = true
	e.restart()
	keys := e.srv.Signer.Keys()
	if e.loadErr == nil || !strings.Contains(e.loadErr.Error(), "one share") || len(keys) != 1 {
		t.Fatalf("start with two shares of one validator stored: keys %d, %v", len(keys), e.loadErr)
	}
}

// SSI-STORAGE-01 for dv_share (TestShareAdmissionConcurrent is the other
// modes'): many imports at once, each of another share of one distributed
// validator. One wins (claimGroups); the store and the core hold its share
// alone, under the group key, also after a restart.
func TestDVShareAdmissionConcurrent(t *testing.T) {
	e := newDVEnv(t)
	gsk, group := newKey(t)
	const n = 8
	shares, err := software.Split(gsk, 3, n)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	won := make([]*backend.ValidatorKey, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sec := shares[i].Secret
			pk, err := core.PubkeyOf(sec)
			if err != nil {
				return
			}
			if k, err := e.srv.addShareGroup(pk, &sec, uint64(i), &testMark, &group, "sealed"); err == nil {
				won[i] = &k
			}
		}()
	}
	wg.Wait()
	w := -1
	for i, k := range won {
		if k != nil {
			if w >= 0 {
				t.Fatalf("requests %d and %d both stored a share of the validator", w, i)
			}
			w = i
		}
	}
	if w < 0 {
		t.Fatal("no request stored a share of the validator")
	}
	check := func(when string) {
		t.Helper()
		keys := e.signer.Keys()
		if len(keys) != 1 || keys[0].Pubkey != won[w].Pubkey || keys[0].Index != uint64(w) {
			t.Fatalf("%s: loaded %+v, the winner %+v", when, keys, won[w])
		}
		if stored, err := ListShares(e.store); err != nil || len(stored) != 1 {
			t.Fatalf("%s: stored %v, %v; want the winner's record alone", when, stored, err)
		}
		if g := e.recordOf(won[w].Pubkey).GroupPubkey; g == nil || *g != group {
			t.Fatalf("%s: the record's group key %v", when, g)
		}
	}
	check("before a restart")
	e.restart()
	check("after a restart")
}

// A dv_share runner holds one share of a split with n >= 2, never the
// validator key (TestThresholdModeRefusesAWholeKey is the threshold
// mode's): a 1 of 1 order and a key filed as its own group key are
// refused, and nothing is stored or loaded.
func TestDVShareRefusesAWholeKey(t *testing.T) {
	e := newDVEnv(t)
	sk, pk := newKey(t)
	req := backend.SealedImportRequest{Pubkey: pk, SharePubkey: pk, Index: 5, Order: e.importOrder([]byte{1, 2}, pk, nil),
		T: 1, N: 1, ShareIndex: 1, Commitments: []backend.Pubkey{pk}}
	var err error
	if req.Sealed, err = sealedimport.Seal(e.sealTo(), &req, &sk); err != nil {
		t.Fatal(err)
	}
	p, err := wireadmin.EncodeImportSealed(&req)
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.srv.dispatch(ctx, wire.Frame{Type: wireadmin.TypeImportSealed, Payload: p})
	if backend.StatusOf(err) != backend.StatusBadKey || !strings.Contains(err.Error(), "never a whole key") {
		t.Errorf("1 of 1: %v, want a BAD_KEY refusal", err)
	}
	if _, err := e.srv.addShareGroup(pk, &sk, 5, nil, &pk, "sealed"); backend.StatusOf(err) != backend.StatusBadKey || !strings.Contains(err.Error(), "its own group key") {
		t.Errorf("a key filed as its own group key: %v, want a BAD_KEY refusal", err)
	}
	if n := len(e.srv.Signer.Keys()); n != 0 {
		t.Fatalf("%d keys loaded", n)
	}
	if stored, err := ListShares(e.store); err != nil || len(stored) != 0 {
		t.Fatalf("stored %v, %v", stored, err)
	}
}

// A dv_share runner signs a voluntary exit with its share, for the
// validator index the import gave the share, and the partial verifies
// under the share key (signer-admin dv-exit asks for it through the admin
// role). Another index is refused, and the group key is no key of the
// runner.
func TestDVShareExit(t *testing.T) {
	e := newDVEnv(t)
	d := newDVShare(t)
	if err := e.importDV(d); err != nil {
		t.Fatalf("import: %v", err)
	}
	cfg := e.signer.Config()
	exit := func(pk backend.Pubkey, index uint64) (backend.Signature, backend.Root, error) {
		m := &backend.VoluntaryExit{Epoch: 1, ValidatorIndex: index}
		dom, err := cfg.MessageDomain(m)
		if err != nil {
			t.Fatal(err)
		}
		obj, _ := backend.HashTreeRoot(m)
		p, err := wire.EncodeSign(backend.SignRequest{Pubkey: pk, Message: m, Domain: dom})
		if err != nil {
			t.Fatal(err)
		}
		out, err := e.srv.dispatch(ctx, wire.Frame{Type: wire.TypeSign, Payload: p})
		var sig backend.Signature
		copy(sig[:], out)
		return sig, backend.SigningRoot(obj, dom), err
	}
	sig, root, err := exit(d.pk, 9)
	if err != nil {
		t.Fatalf("exit of the share: %v", err)
	}
	if !core.Verify(d.pk, root, sig) {
		t.Fatal("the partial exit does not verify under the share key")
	}
	if _, _, err := exit(d.pk, 8); err == nil {
		t.Fatal("exit for another validator index signed")
	}
	if _, _, err := exit(d.group, 9); backend.StatusOf(err) != backend.StatusUnknownValidator {
		t.Fatalf("exit under the group key: %v, want UNKNOWN_VALIDATOR", err)
	}
}

// dvSplitUnder is share 1 of a fresh 2-of-3 split of the key gsk:
// f(x) = gsk + a*x mod r, with a random. It returns the share and the
// split's commitments, the public keys of gsk and a.
func dvSplitUnder(t *testing.T, gsk [32]byte) ([32]byte, []backend.Pubkey) {
	t.Helper()
	a, err := software.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	s := new(big.Int).Add(new(big.Int).SetBytes(gsk[:]), new(big.Int).SetBytes(a[:]))
	s.Mod(s, blsOrder)
	var sk [32]byte
	s.FillBytes(sk[:])
	gpk, err := core.PubkeyOf(gsk)
	if err != nil {
		t.Fatal(err)
	}
	apk, err := core.PubkeyOf(a)
	if err != nil {
		t.Fatal(err)
	}
	return sk, []backend.Pubkey{gpk, apk}
}

// dvReq is the sealed import request of share 1 (secret sk) of the 2-of-3
// split with these commitments, under an order the approvers signed for
// its group key, commitments[0].
func (e *tgtEnv) dvReq(sk [32]byte, commitments []backend.Pubkey, index uint64) backend.SealedImportRequest {
	e.t.Helper()
	pk, err := core.PubkeyOf(sk)
	if err != nil {
		e.t.Fatal(err)
	}
	order := e.importOrder([]byte{1, 2}, commitments[0], func(b *importorder.Body) {
		b.T, b.N, b.ShareIndex = 2, 3, 1
		b.Validators[0].CommitmentsHash = importorder.CommitmentsHash(commitments)
	})
	req := backend.SealedImportRequest{Pubkey: commitments[0], SharePubkey: pk, Index: index, Order: order,
		T: 2, N: 3, ShareIndex: 1, Commitments: commitments}
	if req.Sealed, err = sealedimport.Seal(e.sealTo(), &req, &sk); err != nil {
		e.t.Fatal(err)
	}
	return req
}

// sendSealed sends req as IMPORT_SHARE_SEALED.
func (e *tgtEnv) sendSealed(req backend.SealedImportRequest) error {
	e.t.Helper()
	p, err := wireadmin.EncodeImportSealed(&req)
	if err != nil {
		e.t.Fatal(err)
	}
	_, err = e.srv.dispatch(ctx, wire.Frame{Type: wireadmin.TypeImportSealed, Payload: p})
	return err
}

// sendBatch sends reqs as one IMPORT_BATCH, under one order that names
// each request's split.
func (e *tgtEnv) sendBatch(reqs ...backend.SealedImportRequest) error {
	e.t.Helper()
	var entries []importorder.Entry
	for i := range reqs {
		entries = append(entries, importorder.Entry{Pubkey: reqs[i].Pubkey, CommitmentsHash: importorder.CommitmentsHash(reqs[i].Commitments)})
		reqs[i].Order = nil
	}
	order := e.importOrder([]byte{1, 2}, reqs[0].Pubkey, func(b *importorder.Body) {
		b.T, b.N, b.ShareIndex = 2, 3, 1
		b.Validators = entries
	})
	p, err := wireadmin.EncodeImportBatch(order, reqs)
	if err != nil {
		e.t.Fatal(err)
	}
	_, err = e.srv.dispatch(ctx, wire.Frame{Type: wireadmin.TypeImportBatch, Payload: p})
	return err
}

// neverBoth is the refusal of a validator key next to a share of it.
const neverBoth = "never holds a validator key and a share of it"

// wantNeverBoth fails the test unless err is that refusal and no key of
// pks is loaded.
func (e *tgtEnv) wantNeverBoth(what string, err error, pks ...backend.Pubkey) {
	e.t.Helper()
	if backend.StatusOf(err) != backend.StatusDuplicate || !strings.Contains(err.Error(), neverBoth) {
		e.t.Errorf("%s: %v, want a DUPLICATE refusal (%s)", what, err, neverBoth)
	}
	for _, pk := range pks {
		if hasKey(e.srv.Signer.Keys(), pk) {
			e.t.Errorf("%s: key %s loaded", what, pk.String()[:18])
		}
	}
}

// The one-share rule compares group keys, and the runner cannot tell a
// made-up group key (the approvers check it). It can see two cases in
// itself, which would let it hold a validator key next to a share of
// that validator: a key that is the group key of a share it holds, and a
// group key that is a key it holds. The sealed import and the batch
// import refuse both, also after a restart.
func TestDVShareValidatorKeyNextToShareRefused(t *testing.T) {
	for _, way := range []string{"sealed import", "batch import"} {
		for _, what := range []string{"the group key", "a share under the share's key"} {
			t.Run(way+" of "+what, func(t *testing.T) {
				e := newDVEnv(t)
				gsk, group := newKey(t)
				ssk, comm := dvSplitUnder(t, gsk)
				if err := e.sendSealed(e.dvReq(ssk, comm, 1)); err != nil {
					t.Fatal(err)
				}
				send := e.sendSealed
				if way == "batch import" {
					send = func(r backend.SealedImportRequest) error { return e.sendBatch(r) }
				}
				for _, when := range []string{"before a restart", "after a restart"} {
					if when == "after a restart" {
						e.restart()
					}
					var (
						req backend.SealedImportRequest
						pk  backend.Pubkey
					)
					if what == "the group key" {
						// The validator key itself, as share 1 of a made-up split.
						_, gc := dvSplitOf(t, gsk)
						req, pk = e.dvReq(gsk, gc, 2), group
					} else {
						// Share 1 of a made-up split whose group key is the held share's key.
						usk, uc := dvSplitUnder(t, ssk)
						req = e.dvReq(usk, uc, 3)
						pk, _ = core.PubkeyOf(usk)
					}
					e.wantNeverBoth(when, send(req), pk)
				}
			})
		}
	}
}

// The same two cases inside one batch: a share with its group key, and a
// share with a share whose group key is the first one's key.
func TestDVShareValidatorKeyNextToShareInOneBatch(t *testing.T) {
	for _, what := range []string{"a share and its group key", "a share and a share under its key"} {
		t.Run(what, func(t *testing.T) {
			e := newDVEnv(t)
			gsk, group := newKey(t)
			ssk, comm := dvSplitUnder(t, gsk)
			spk, _ := core.PubkeyOf(ssk)
			if what == "a share and its group key" {
				_, gc := dvSplitOf(t, gsk)
				e.wantNeverBoth(what, e.sendBatch(e.dvReq(ssk, comm, 1), e.dvReq(gsk, gc, 2)), spk, group)
				return
			}
			usk, uc := dvSplitUnder(t, ssk)
			upk, _ := core.PubkeyOf(usk)
			e.wantNeverBoth(what, e.sendBatch(e.dvReq(ssk, comm, 1), e.dvReq(usk, uc, 3)), spk, upk)
		})
	}
}

// A start with a share's record and its validator key's record stored
// (an older runner took both) loads one of them and names the other.
func TestDVShareValidatorKeyNextToShareAtStart(t *testing.T) {
	e := newDVEnv(t)
	gsk, group := newKey(t)
	ssk, comm := dvSplitUnder(t, gsk)
	spk, _ := core.PubkeyOf(ssk)
	_, gc := dvSplitOf(t, gsk)
	for _, r := range []shareRecord{
		{Pubkey: spk, Secret: ssk[:], Index: 1, GroupPubkey: &comm[0]},
		{Pubkey: group, Secret: gsk[:], Index: 2, GroupPubkey: &gc[0]},
	} {
		blob, err := e.srv.sealRecord(r)
		if err != nil {
			t.Fatal(err)
		}
		if err := e.srv.putShare(r.Pubkey, blob); err != nil {
			t.Fatal(err)
		}
	}
	e.looseLoad = true
	e.restart()
	keys := e.srv.Signer.Keys()
	if len(keys) != 1 || e.loadErr == nil || !strings.Contains(e.loadErr.Error(), neverBoth) {
		t.Fatalf("start with a share and its validator key stored: %d keys loaded, %v", len(keys), e.loadErr)
	}
}
