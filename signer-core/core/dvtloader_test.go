//go:build dvt

package core_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// AddValidatorGroup (dvt.go) repeats the steps of AddValidator (core.go)
// around another C call, and core.go keeps its reviewed shape, so the two
// cannot share one function. With the group key equal to the loaded key
// the group loader must act as the plain one: the same keys, errors,
// unready marks (SSI-HISTORY-02) and signatures for the same calls. A fix
// to one loader that the other lacks fails here.
func TestAddValidatorGroupMatchesAddValidator(t *testing.T) {
	var sk [4][32]byte
	var pk [4]backend.Pubkey
	for i := range sk {
		var err error
		if sk[i], err = software.NewSecret(); err != nil {
			t.Fatal(err)
		}
		pk[i], _ = core.PubkeyOf(sk[i])
	}
	history := backend.Watermark{HasAttestation: true, SourceEpoch: 15, TargetEpoch: 18}
	// Above history, so its import writes the device mark again.
	later := backend.Watermark{HasAttestation: true, SourceEpoch: 16, TargetEpoch: 19}
	type step struct {
		name       string
		pk         backend.Pubkey
		sk         [32]byte
		index      uint64
		history    *backend.Watermark
		failStores int // device mark writes that fail during the call
	}
	steps := []step{
		{"a key", pk[0], sk[0], 7, nil, 0},
		{"the same key again", pk[0], sk[0], 7, nil, 0},
		{"its secret under another pubkey", pk[1], sk[0], 8, nil, 0},
		{"a zero secret", pk[1], [32]byte{}, 8, nil, 0},
		{"a key with history", pk[1], sk[1], 8, &history, 0},
		{"a key whose history import fails", pk[2], sk[2], 9, &later, 1},
		{"a key past max_validators", pk[3], sk[3], 10, nil, 0},
	}
	run := func(group bool) []string {
		h := &failingDeviceHooks{deviceHooks: deviceHooks{MemHooks: software.NewMemHooks()}}
		h.Clock = clockAtEpoch(20)
		cfg := software.DevConfig(genesis, 12, 32)
		cfg.DeviceMark = true
		s, err := core.NewSigner(cfg, 3, 0, h)
		if err != nil {
			t.Fatal(err)
		}
		add := func(c step) (backend.ValidatorKey, error) {
			// At genesis, as addAtGenesis: the restart floor stays below
			// the epochs signed below.
			saved := h.Clock
			h.Clock = func() (uint64, error) { return genesis, nil }
			defer func() { h.Clock = saved }()
			if group {
				return s.AddValidatorGroup(c.pk, c.sk, c.index, c.history, c.pk)
			}
			return s.AddValidator(c.pk, c.sk, c.index, c.history)
		}
		short := func(k backend.ValidatorKey) string {
			return fmt.Sprintf("%s/%s/%d", k.Pubkey.String()[:10], k.SharePubkey.String()[:10], k.Index)
		}
		var out []string
		for _, c := range steps {
			h.mu.Lock()
			h.failStores = c.failStores
			h.mu.Unlock()
			k, err := add(c)
			var keys []string
			for _, l := range s.Keys() {
				keys = append(keys, short(l))
			}
			out = append(out, fmt.Sprintf("%s: key %s, error %v, keys %v", c.name, short(k), err, keys))
		}
		for i, p := range pk {
			sig, err := s.Sign(signReq(s, p, att(19, 20)))
			out = append(out, fmt.Sprintf("vote of key %d: signature %x, error %v", i, sig[:8], err))
		}
		s.Close()
		k, err := add(steps[0])
		out = append(out, fmt.Sprintf("after Close: key %s, error %v", short(k), err))
		return out
	}
	plain, grouped := run(false), run(true)
	if len(plain) != len(grouped) {
		t.Fatalf("%d results of AddValidator, %d of AddValidatorGroup", len(plain), len(grouped))
	}
	for i := range plain {
		if plain[i] != grouped[i] {
			t.Errorf("AddValidator and AddValidatorGroup differ:\n  AddValidator:      %s\n  AddValidatorGroup: %s", plain[i], grouped[i])
		}
	}
	// The script reaches every branch: a duplicate, the moved-share text, a
	// bad key, a failed import, a full signer and a closed one.
	for _, want := range []string{"DUPLICATE", "loaded under another pubkey", "BAD_KEY", "the import of this key's slashing history failed", "NOMEM", core.ErrClosed.Error()} {
		found := false
		for _, l := range plain {
			found = found || strings.Contains(l, want)
		}
		if !found {
			t.Errorf("no result says %q:\n%v", want, plain)
		}
	}
}
