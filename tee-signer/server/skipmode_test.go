package server

import (
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// skipUnlessVariantRuns skips a test whose setup says a signing mode this
// build refuses (CheckSigningMode): the threshold and single tests run in
// the default build only, the dv_share tests in the dvt build only.
func skipUnlessVariantRuns(t *testing.T, m setupwire.SigningMode) {
	t.Helper()
	if err := CheckSigningMode(m); err != nil {
		t.Skipf("%s build: %v", Variant, err)
	}
}

// dvtBuild reports whether this build runs dv_share setups: the dvt build.
func dvtBuild() bool { return CheckSigningMode(setupwire.SigningModeDVShare) == nil }
