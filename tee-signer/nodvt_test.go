//go:build !dvt

package main

import (
	"context"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// dvShareSetup is the threshold dev sample setup with signing_mode =
// dv_share.
func dvShareSetup(t *testing.T) []byte {
	t.Helper()
	s, err := setupwire.DecodeSetup(sampleSetupFile(t, "dev-threshold"))
	if err != nil {
		t.Fatal(err)
	}
	s.SigningMode = setupwire.SigningModeDVShare
	raw, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// A runner built without the tag dvt refuses a dv_share setup at its
// first step, before the platform starts, and says why. Threshold and
// single setups still start.
func TestStartRefusesDVShareWithoutDVT(t *testing.T) {
	var events []string
	_, err := readSetup(context.Background(), &fakeChannel{raw: dvShareSetup(t), events: &events}, "dev")
	if err == nil || !strings.Contains(err.Error(), "this image has no DVT support (built without dvt)") {
		t.Fatalf("dv_share setup: got %v", err)
	}
	for _, name := range []string{"dev-threshold", "dev-single"} {
		if _, err := readSetup(context.Background(), &fakeChannel{raw: sampleSetupFile(t, name), events: &events}, "dev"); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
