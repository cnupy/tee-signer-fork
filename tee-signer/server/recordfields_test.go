package server

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

// The share record of each build: the same fields, and group_pubkey in
// the dvt build only (nodvt.go, dvshare.go).
func TestShareRecordFields(t *testing.T) {
	want := []string{"pubkey", "secret", "index", "history", "source_floor", "batch"}
	if Variant == "dvt" {
		want = append(want, "group_pubkey")
	}
	if got := recordFields(); !slices.Equal(got, want) {
		t.Fatalf("shareRecord fields of the %s build: %v, want %v", Variant, got, want)
	}
}

// recordFields lists the JSON names of shareRecord's fields.
func recordFields() []string {
	var out []string
	rt := reflect.TypeOf(shareRecord{})
	for i := range rt.NumField() {
		out = append(out, strings.Split(rt.Field(i).Tag.Get("json"), ",")[0])
	}
	return out
}
