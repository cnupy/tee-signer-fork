package server

import (
	"slices"
	"strings"

	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// dvtModes are the signing modes whose code only a dvt build holds. Each
// variant runs its own modes only (CheckSigningMode): a dvt build these,
// so the DVT core never holds a key of another mode, and the default build
// every other mode. A later dvt-only mode (ssv_share) joins this list.
var dvtModes = []setupwire.SigningMode{setupwire.SigningModeDVShare}

// dvtMode reports whether m is a mode of dvt builds only.
func dvtMode(m setupwire.SigningMode) bool { return slices.Contains(dvtModes, m) }

// dvtModeNames names the dvt modes for an error: "dv_share", or
// "dv_share or ssv_share".
func dvtModeNames() string {
	names := make([]string, len(dvtModes))
	for i, m := range dvtModes {
		names[i] = m.String()
	}
	return strings.Join(names, " or ")
}
