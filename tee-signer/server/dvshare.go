//go:build dvt

package server

import (
	"fmt"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// signing_mode = dv_share, in builds with the tag dvt only (nodvt.go is the
// default build's side): the runner holds one share of each distributed
// validator of a Charon cluster. The import is the threshold one: the
// request's pubkey is the validator (group) key, the approvers' order names
// the cluster's split, and checkSplit checks that share_pubkey is the
// split's value at the share index. The runner then files and serves the
// share under share_pubkey, the key the Charon validator client asks for,
// and keeps the group key with it for the selection proof check of
// aggregates and contributions (core AddValidatorGroup). Marks, floors and
// policy apply to the share key.

// Variant is the build variant HEALTH reports (variant).
const Variant = "dvt"

// CheckSigningMode refuses a signing mode this build does not run: every
// mode but the dvt modes (variant.go), so the DVT core never holds keys of
// a threshold or single setup. The runner calls it at start, before the
// platform; NewUpdates calls it again.
func CheckSigningMode(m setupwire.SigningMode) error {
	if !dvtMode(m) {
		return fmt.Errorf("signing_mode = %s: this image is a DVT build and runs only %s setups; a %s signer needs a default image", m, dvtModeNames(), m)
	}
	return nil
}

// dvState is the dv_share state of a Server.
type dvState struct {
	// groups maps the group key of each dv_share key this runner stores,
	// loads or is adding to that key: one share per distributed validator
	// (claimGroups). shares is the other direction, key to group key.
	// Under admitMu.
	groups map[backend.Pubkey]backend.Pubkey
	shares map[backend.Pubkey]backend.Pubkey
}

// shareRecord is the sealed form of a stored share, with group_pubkey
// (nodvt.go has the default build's, without it; the fields are otherwise
// the same, TestShareRecordFields). parseShareRecord reads it and refuses
// a field it does not have (keyorigin.go).
type shareRecord struct {
	Pubkey backend.Pubkey `json:"pubkey"`
	Secret []byte         `json:"secret"`
	Index  uint64         `json:"index"`
	// History: the import that stored the share carried attestation
	// maxima, which raised the mark log first. A restart exempts the key
	// from the source gate (state.Hooks.NoteHistory). The host can roll
	// the record back to one without it, which only gates the key again.
	History bool `json:"history,omitempty"`
	// SourceFloor: the import came without vote history, and the key signs
	// no vote with a source below this epoch, the restart floor epoch at the
	// import (state.Hooks.ImportFloor, SLBOUND-01). A restart sets it again.
	// The host stores the record; the mark log's share set vouches for it
	// (LoadListedShares), so an older record with a lower floor or none
	// loads every key with a fresh floor instead.
	SourceFloor uint64 `json:"source_floor,omitempty"`
	// Batch tags the records of one batch import (importbatch.go), so a
	// start can leave out the records of a batch that did not complete.
	Batch []byte `json:"batch,omitempty"`
	// GroupPubkey: under signing_mode = dv_share, the validator key of the
	// import order (the Charon group key), which the share's selection
	// proofs must verify under. Pubkey is then the share's own key. Set
	// only in dv_share mode; a default build or a runner built before it
	// refuses the record.
	GroupPubkey *backend.Pubkey `json:"group_pubkey,omitempty"`
}

// setGroupKey sets the record's group key (nil in the other modes).
func (r *shareRecord) setGroupKey(group *backend.Pubkey) { r.GroupPubkey = group }

// groupKey is the record's group key, nil outside dv_share mode.
func (r *shareRecord) groupKey() *backend.Pubkey { return r.GroupPubkey }

// dvShare reports whether the setup says signing_mode = dv_share.
func (s *Server) dvShare() bool {
	return s.Updates != nil && s.Updates.SetupWire().SigningMode == setupwire.SigningModeDVShare
}

// importKey is the key a checked sealed import files the share under, and
// its group key: share_pubkey and the request's validator key in dv_share
// mode, the validator key and nil otherwise.
func (s *Server) importKey(req *backend.SealedImportRequest) (backend.Pubkey, *backend.Pubkey) {
	if s.dvShare() {
		group := req.Pubkey
		return req.SharePubkey, &group
	}
	return req.Pubkey, nil
}

// checkGroupKey refuses a key pk without a group key in dv_share mode, and
// a key with one in the other modes (which this build refuses at start,
// CheckSigningMode; the case stays as a second check). A dv_share key without its group key
// would check selection proofs against itself, and the group key comes
// only from an approver-signed import (never from the plain debug import
// or a signing request).
func (s *Server) checkGroupKey(pk backend.Pubkey, group *backend.Pubkey) error {
	if s.Updates == nil {
		if group != nil {
			return backend.Refused(backend.StatusBadKey, "a group key needs a setup with signing_mode = dv_share")
		}
		return nil
	}
	switch dv := s.dvShare(); {
	case dv && group == nil:
		return backend.Refused(backend.StatusBadKey, "the setup says signing_mode = dv_share, and key %s has no group key: import it under an import order for its validator key", pk.String()[:18])
	case dv && *group == pk:
		return backend.Refused(backend.StatusBadKey, "key %s is its own group key: a dv_share key is a share, not the validator key", pk.String()[:18])
	case !dv && group != nil:
		return backend.Refused(backend.StatusBadKey, "key %s has a group key, and the setup says signing_mode = %s: group keys are for signing_mode = dv_share", pk.String()[:18], s.Updates.SetupWire().SigningMode)
	}
	return nil
}

// addValidator loads a key into the core, with its group key if it has one.
// It takes the secret by pointer so that it makes no copy of its own; the
// core binding clears the copy it gets.
func (s *Server) addValidator(pk backend.Pubkey, secret *[32]byte, index uint64, imp *backend.Watermark, group *backend.Pubkey) (backend.ValidatorKey, error) {
	if group != nil {
		return s.Signer.AddValidatorGroup(pk, *secret, index, imp, *group)
	}
	return s.Signer.AddValidator(pk, *secret, index, imp)
}

// claimGroups takes the group key groups[i] of each dv_share key pks[i]
// (nil for a key of another mode) for that key. It refuses a group key
// that another key of this runner stores, loads or is adding: a dv_share
// runner holds one share of each distributed validator, as a threshold
// runner holds one share of each validator, and with t shares it would
// hold the whole key. It also refuses a key that is the group key of such
// a key, and a group key that is such a key: the runner would hold a
// validator key next to a share of it. It cannot see two shares under two
// made-up group keys; the approvers check the group keys. It returns the
// group keys it took, for unclaimGroups when the import stores nothing.
func (s *Server) claimGroups(pks []backend.Pubkey, groups []*backend.Pubkey) ([]backend.Pubkey, error) {
	s.admitMu.Lock()
	defer s.admitMu.Unlock()
	claim, claimShares := map[backend.Pubkey]backend.Pubkey{}, map[backend.Pubkey]backend.Pubkey{}
	for i, g := range groups {
		if g == nil {
			continue
		}
		have, ok := s.groups[*g]
		if !ok {
			have, ok = claim[*g]
		}
		if ok && have != pks[i] {
			return nil, &backend.RefusedError{Code: backend.StatusDuplicate, Detail: fmt.Sprintf(
				"key %s is a share of validator %s, and this runner holds or is adding its share %s: a dv_share runner holds one share of each validator",
				pks[i].String()[:18], g.String()[:18], have.String()[:18])}
		}
		claim[*g], claimShares[pks[i]] = pks[i], *g
	}
	// After the loop, so that the order of a batch does not matter.
	for i, g := range groups {
		if g == nil {
			continue
		}
		share, ok := s.groups[pks[i]]
		if !ok {
			share, ok = claim[pks[i]]
		}
		if ok {
			return nil, &backend.RefusedError{Code: backend.StatusDuplicate, Detail: fmt.Sprintf(
				"key %s is the validator key of share %s, which this runner holds or is adding: a dv_share runner never holds a validator key and a share of it",
				pks[i].String()[:18], share.String()[:18])}
		}
		_, ok = s.shares[*g]
		if !ok {
			_, ok = claimShares[*g]
		}
		if ok {
			return nil, &backend.RefusedError{Code: backend.StatusDuplicate, Detail: fmt.Sprintf(
				"key %s is a share of validator %s, and this runner holds or is adding that validator key as a share: a dv_share runner never holds a validator key and a share of it",
				pks[i].String()[:18], g.String()[:18])}
		}
	}
	if s.groups == nil {
		s.groups = map[backend.Pubkey]backend.Pubkey{}
	}
	if s.shares == nil {
		s.shares = map[backend.Pubkey]backend.Pubkey{}
	}
	var took []backend.Pubkey
	for g, pk := range claim {
		if _, ok := s.groups[g]; !ok {
			s.groups[g], s.shares[pk] = pk, g
			took = append(took, g)
		}
	}
	return took, nil
}

// unclaimGroups gives back the group keys of an import that stored no
// record.
func (s *Server) unclaimGroups(took []backend.Pubkey) {
	s.admitMu.Lock()
	defer s.admitMu.Unlock()
	for _, g := range took {
		delete(s.shares, s.groups[g])
		delete(s.groups, g)
	}
}
