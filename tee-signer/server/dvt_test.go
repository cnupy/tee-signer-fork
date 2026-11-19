//go:build dvt

package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/slashing-log"
)

// The variant HEALTH reports with the build tag dvt.
const wantVariant = "dvt"

// emptyUpdateLog is an UpdateLog with no state; NewUpdates reads only
// State.
type emptyUpdateLog struct{ UpdateLog }

func (emptyUpdateLog) State() markstore.ConfigState { return markstore.ConfigState{} }

// The config updates of a dvt build refuse a threshold or single setup,
// as readSetup does at start: a dvt image runs dv_share setups only.
func TestUpdatesRefuseOtherModesWithDVT(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "governance", "setupwire", "testdata", "setup-dev-threshold.bin"))
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []setupwire.SigningMode{setupwire.SigningModeThreshold, setupwire.SigningModeSingle} {
		s, err := setupwire.DecodeSetup(raw)
		if err != nil {
			t.Fatal(err)
		}
		s.SigningMode = m
		_, err = NewUpdates(UpdatesOptions{Setup: s, Log: emptyUpdateLog{}, Clock: &fakeClock{}, Logger: quiet})
		if err == nil || !strings.Contains(err.Error(), "this image is a DVT build and runs only dv_share setups") {
			t.Errorf("signing_mode = %s: got %v", m, err)
		}
	}
}
