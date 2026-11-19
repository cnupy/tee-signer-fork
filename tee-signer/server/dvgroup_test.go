//go:build !debugimport

package server

import (
	"encoding/binary"
	"testing"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// A Charon split and its group's messages, for the dv_share tests of the
// dvt build (dvshare_test.go) and the single-mode tests of the default
// build below. The dvt build runs no single setup (CheckSigningMode), so
// the tests here skip there.

// dvShare is share index of a 3-of-4 split of a fresh group key, as a
// Charon cluster lock holds it: the group key, the share and its key, and
// the split's commitments.
type dvShare struct {
	groupSk, sk [32]byte
	group, pk   backend.Pubkey
	commitments []backend.Pubkey
	index       uint8
	otherSk     [32]byte // another share of the same split
	otherPk     backend.Pubkey
	otherIndex  uint8
}

func newDVShare(t *testing.T) *dvShare {
	t.Helper()
	gsk, gpk := newKey(t)
	shares, commitments, err := software.SplitWithCommitments(gsk, 3, 4)
	if err != nil {
		t.Fatal(err)
	}
	d := &dvShare{groupSk: gsk, group: gpk, commitments: commitments, index: 2, sk: shares[1].Secret,
		otherSk: shares[2].Secret, otherIndex: 3}
	d.pk, _ = core.PubkeyOf(d.sk)
	d.otherPk, _ = core.PubkeyOf(d.otherSk)
	return d
}

// proofBy is the selection proof sel that key sk, loaded alone for
// validator index 9 in a signer of the dev chain, makes.
func (e *tgtEnv) proofBy(sk [32]byte, pk backend.Pubkey, sel backend.Message) backend.Signature {
	e.t.Helper()
	m := software.NewMemHooks()
	m.Clock = func() (uint64, error) { return e.now(), nil }
	cfg := e.signer.Config()
	gcfg := cfg
	gcfg.DeviceMark = false // the memory hooks keep per-validator marks
	g, err := core.NewSigner(gcfg, 1, 1, m)
	if err != nil {
		e.t.Fatal(err)
	}
	defer g.Close()
	if _, err := g.AddValidator(pk, sk, 9, nil); err != nil {
		e.t.Fatal(err)
	}
	d, _ := cfg.MessageDomain(sel)
	proof, err := g.Sign(backend.SignRequest{Pubkey: pk, Message: sel, Domain: d})
	if err != nil {
		e.t.Fatal(err)
	}
	return proof
}

// groupAggregate is an AggregateAndProof (minimal preset: 4 committees
// per slot, one byte of committee_bits) for validator index 9 at the
// clock's epoch whose selection proof key sk made. The form is the one the
// epoch hashes with: Gloas from its fork on, else Electra.
func (e *tgtEnv) groupAggregate(sk [32]byte, pk backend.Pubkey) *backend.AggregateAndProof {
	e.t.Helper()
	cfg := e.signer.Config()
	epoch := e.signer.EpochAt(e.now())
	slot := epoch * cfg.SlotsPerEpoch
	proof := e.proofBy(sk, pk, &backend.SelectionProof{Slot: slot})
	form := backend.AggregateElectra
	if g := cfg.GloasForkEpoch; g != nil && epoch >= *g {
		form = backend.AggregateGloas
	}
	le := binary.LittleEndian
	b := le.AppendUint64(nil, 9)
	b = le.AppendUint32(b, 108) // offset of the Attestation
	b = append(b, proof[:]...)
	b = le.AppendUint32(b, 4+128+96+1) // offset of aggregation_bits in the Attestation
	data, err := backend.EncodeSSZ(&backend.AttestationData{Slot: slot, BeaconBlockRoot: backend.Root{0xbb},
		Source: backend.Checkpoint{Epoch: epoch - 1, Root: backend.Root{5}},
		Target: backend.Checkpoint{Epoch: epoch, Root: backend.Root{7}}})
	if err != nil {
		e.t.Fatal(err)
	}
	b = append(b, data...)
	b = append(b, make([]byte, 96)...) // aggregate signature
	b = append(b, 0x01)                // committee_bits
	b = append(b, 0x03)                // aggregation_bits: one bit set, delimiter
	return &backend.AggregateAndProof{Form: form, SSZ: b}
}

// groupContribution is a ContributionAndProof (minimal preset, the dev
// chain's) for validator index 9 whose selection proof the group key sk
// made, as a Charon cluster combines it.
func (e *tgtEnv) groupContribution(sk [32]byte, pk backend.Pubkey) *backend.ContributionAndProof {
	e.t.Helper()
	slot := e.signer.EpochAt(e.now()) * e.signer.Config().SlotsPerEpoch
	proof := e.proofBy(sk, pk, &backend.SyncSelectionProof{Slot: slot, SubcommitteeIndex: 1})
	le := binary.LittleEndian
	b := le.AppendUint64(nil, 9)
	b = le.AppendUint64(b, slot)
	b = append(b, make([]byte, 32)...)
	b = le.AppendUint64(b, 1)
	b = append(b, 0x01)                // aggregation_bits: 32 / 4 subnets = 8 bits
	b = append(b, make([]byte, 96)...) // contribution signature
	b = append(b, proof[:]...)
	return &backend.ContributionAndProof{SSZ: b}
}

// The problem dv_share solves: a single-mode runner holds the same Charon
// share as a whole key, and refuses the contribution with the group's
// proof.
func TestSingleModeRefusesGroupSelectionProof(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	d := newDVShare(t)
	if err := e.importSealed(d.pk, d.sk, 9, nil); err != nil {
		t.Fatal(err)
	}
	err := e.signMsg(d.pk, e.groupContribution(d.groupSk, d.group))
	if backend.StatusOf(err) != backend.StatusSelectionProof {
		t.Fatalf("single mode, the group's proof: %v, want SELECTION_PROOF", err)
	}
}

// A single-mode runner signs a registration for its own key only, not for
// the group key of a Charon share it holds as a whole key (a dv_share
// runner takes both, TestDVShareRegistrationPubkey).
func TestSingleModeRefusesGroupRegistration(t *testing.T) {
	single := newTgtEnv(t, "dev", nil)
	d := newDVShare(t)
	if err := single.importSealed(d.pk, d.sk, 9, nil); err != nil {
		t.Fatal(err)
	}
	if err := single.signMsg(d.pk, single.registration(d.group)); backend.StatusOf(err) != backend.StatusPolicyPubkey {
		t.Errorf("single mode, registration for the group key: %v, want POLICY_PUBKEY", err)
	}
}
