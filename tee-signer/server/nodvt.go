//go:build !dvt

package server

import (
	"fmt"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// The default build: no signing_mode = dv_share. dvshare.go, built with the
// tag dvt, holds the dv_share code; here every hook it fills is empty or
// refuses, and no key ever has a group key.

// Variant is the build variant HEALTH reports (variant).
const Variant = "default"

const noDVT = "this image has no DVT support (built without dvt)"

// CheckSigningMode refuses a signing mode this build cannot run: the dvt
// modes (variant.go). The runner calls it at start, before the platform;
// NewUpdates calls it again.
func CheckSigningMode(m setupwire.SigningMode) error {
	if dvtMode(m) {
		return fmt.Errorf("signing_mode = %s: %s; a %s signer needs a dvt image", m, noDVT, m)
	}
	return nil
}

// dvState holds no dv_share state in the default build.
type dvState struct{}

// shareRecord is the sealed form of a stored share, without group_pubkey
// (dvshare.go has the dvt build's, with it; the fields are otherwise the
// same, TestShareRecordFields). parseShareRecord reads it and refuses a
// field it does not have (keyorigin.go), group_pubkey too.
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
}

// setGroupKey panics on a group key: checkGroupKey refused it before any
// record is made.
func (r *shareRecord) setGroupKey(group *backend.Pubkey) {
	if group != nil {
		panic("server: a share record with a group key in a build without dvt")
	}
}

func (r *shareRecord) groupKey() *backend.Pubkey { return nil }

func (s *Server) importKey(req *backend.SealedImportRequest) (backend.Pubkey, *backend.Pubkey) {
	return req.Pubkey, nil
}

// checkGroupKey refuses any group key.
func (s *Server) checkGroupKey(pk backend.Pubkey, group *backend.Pubkey) error {
	if group != nil {
		return backend.Refused(backend.StatusBadKey, "key %s has a group key: %s", pk.String()[:18], noDVT)
	}
	return nil
}

func (s *Server) addValidator(pk backend.Pubkey, secret *[32]byte, index uint64, imp *backend.Watermark, group *backend.Pubkey) (backend.ValidatorKey, error) {
	if err := s.checkGroupKey(pk, group); err != nil {
		return backend.ValidatorKey{}, err
	}
	return s.Signer.AddValidator(pk, *secret, index, imp)
}

// claimGroups takes nothing; it refuses a group key as checkGroupKey does.
func (s *Server) claimGroups(pks []backend.Pubkey, groups []*backend.Pubkey) ([]backend.Pubkey, error) {
	for i, g := range groups {
		if err := s.checkGroupKey(pks[i], g); err != nil {
			return nil, err
		}
	}
	return nil, nil
}

func (s *Server) unclaimGroups([]backend.Pubkey) {}
