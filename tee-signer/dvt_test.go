//go:build dvt

package main

import (
	"context"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// A runner built with the tag dvt starts from a dv_share setup.
func TestStartTakesDVShareWithDVT(t *testing.T) {
	s, err := setupwire.DecodeSetup(sampleSetupFile(t, "dev-threshold"))
	if err != nil {
		t.Fatal(err)
	}
	s.SigningMode = setupwire.SigningModeDVShare
	raw, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	var events []string
	if _, err := readSetup(context.Background(), &fakeChannel{raw: raw, events: &events}, "dev"); err != nil {
		t.Fatalf("dv_share setup: %v", err)
	}
}

// A runner built with the tag dvt refuses a threshold or single setup at
// its first step, before the platform starts: the DVT core holds no key of
// another mode.
func TestStartRefusesOtherModesWithDVT(t *testing.T) {
	for _, name := range []string{"dev-threshold", "dev-single"} {
		var events []string
		_, err := readSetup(context.Background(), &fakeChannel{raw: sampleSetupFile(t, name), events: &events}, "dev")
		if err == nil || !strings.Contains(err.Error(), "this image is a DVT build and runs only dv_share setups") {
			t.Errorf("%s: got %v", name, err)
		}
	}
}
