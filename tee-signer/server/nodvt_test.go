//go:build !dvt && !debugimport

package server

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// The variant HEALTH reports without the build tag dvt.
const wantVariant = "default"

// Without the build tag dvt the runner reads a share record with a group
// key as one of an unknown format, as runners before dv_share did, so such
// a record never loads.
func TestShareRecordWithGroupKeyRefused(t *testing.T) {
	var pk, group backend.Pubkey
	pk[0], group[0] = 0xa1, 0xb2
	plain, err := json.Marshal(shareRecord{Pubkey: pk, Secret: make([]byte, 32), Index: 7})
	if err != nil {
		t.Fatal(err)
	}
	gj, err := json.Marshal(group)
	if err != nil {
		t.Fatal(err)
	}
	withGroup := append(bytes.TrimSuffix(plain, []byte("}")), []byte(`,"group_pubkey":`+string(gj)+`}`)...)
	if _, err := parseShareRecord(plain); err != nil {
		t.Fatalf("record without a group key: %v", err)
	}
	if _, err := parseShareRecord(withGroup); err == nil || !strings.Contains(err.Error(), `unknown field "group_pubkey"`) {
		t.Fatalf("record with a group key: got %v, want an unknown field", err)
	}
}

// Without the build tag dvt no key loads with a group key, whatever the
// setup says.
func TestGroupKeyRefusedWithoutDVT(t *testing.T) {
	a := newTgtEnv(t, "dev", nil)
	var pk, group backend.Pubkey
	pk[0], group[0] = 0xa1, 0xb2
	err := a.srv.checkGroupKey(pk, &group)
	if err == nil || !strings.Contains(err.Error(), "this image has no DVT support (built without dvt)") {
		t.Fatalf("group key: got %v", err)
	}
	if err := a.srv.checkGroupKey(pk, nil); err != nil {
		t.Fatalf("no group key: %v", err)
	}
}
