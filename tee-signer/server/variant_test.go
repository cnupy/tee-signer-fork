//go:build !debugimport

package server

import (
	"bytes"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
)

// HEALTH names the build's variant: default without the build tag dvt,
// dvt with it. The field is new and optional, so the protocol level stays.
func TestHealthNamesTheVariant(t *testing.T) {
	// A setup of a mode the variant runs (CheckSigningMode).
	a := newShareTgtEnv(t, "dev", func(s *setupwire.Setup) {
		if wantVariant == "dvt" {
			s.SigningMode = setupwire.SigningModeDVShare
		}
	})
	h, err := a.srv.health()
	if err != nil {
		t.Fatal(err)
	}
	if h.Variant != wantVariant || h.Protocol != backend.ProtocolLevel || backend.ProtocolLevel != 2 {
		t.Fatalf("HEALTH: variant %q, protocol %d; want variant %q at protocol 2", h.Variant, h.Protocol, wantVariant)
	}
	b, err := wire.EncodeHealth(h)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(`"variant":"`+wantVariant+`"`)) {
		t.Fatalf("HEALTH JSON has no variant %q: %s", wantVariant, b)
	}
}

// Each variant runs its own signing modes only: the dvt build the modes
// of dvt code (dv_share), the default build every other mode. So the DVT
// core never holds a key of a threshold or single setup, and the default
// core never a dv_share key.
func TestCheckSigningModeByVariant(t *testing.T) {
	for _, c := range []struct {
		mode setupwire.SigningMode
		dvt  bool
	}{{setupwire.SigningModeThreshold, false}, {setupwire.SigningModeSingle, false}, {setupwire.SigningModeDVShare, true}} {
		err := CheckSigningMode(c.mode)
		if runs := c.dvt == (wantVariant == "dvt"); runs != (err == nil) {
			t.Errorf("%s variant, signing_mode = %s: got %v, want runs %v", wantVariant, c.mode, err, runs)
		}
	}
}
