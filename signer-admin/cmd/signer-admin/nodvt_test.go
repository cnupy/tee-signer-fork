//go:build !dvt

package main

import (
	"strings"
	"testing"
)

// A default build has none of the dv exit commands: they come with the
// tag dvt only.
func TestDefaultBuildHasNoDVExitCommands(t *testing.T) {
	for _, c := range []string{"dv-indices", "dv-exit", "dv-exit-post"} {
		wantIn(t, failTool(t, c), `unknown subcommand "`+c+`"`)
	}
	if out := failTool(t); strings.Contains(out, "dv-exit") || strings.Contains(out, "dv-indices") {
		t.Fatalf("the default usage names a dv exit command:\n%s", out)
	}
}
