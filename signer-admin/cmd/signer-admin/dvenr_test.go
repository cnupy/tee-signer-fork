//go:build dvt

package main

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

// The ENR of a real Charon operator (obol-sdk test/fixtures.ts, MIT):
// the key dv-exit-post reads from it is the one that signed the record.
const realENR = "enr:-HW4QLlrtMjFLGkFT1bwdGbvZQlH8hLi0M2g44JAxEYP3BZmYpcsy9Q56HPPD87fMucjvLv4-obEFacpsg0ehRilbHeAgmlkgnY0iXNlY3AyNTZrMaEDRaa5o2aSgqyFq_ERZcQTztrOij1mFtXX1bJuVI6ieak"

func TestENRKey(t *testing.T) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(realENR, "enr:"))
	if err != nil {
		t.Fatal(err)
	}
	// raw: f8 len, b8 40, 64 bytes of signature, then the content's items.
	if raw[0] != 0xf8 || raw[2] != 0xb8 || raw[3] != 64 {
		t.Fatalf("record header %x", raw[:4])
	}
	sig, rest := raw[4:68], raw[68:]
	h := sha3.NewLegacyKeccak256()
	h.Write(append(rlpHeader(0xc0, len(rest)), rest...))
	digest := h.Sum(nil)

	got, err := enrPubkey(realENR)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := secp256k1.ParsePubKey(got)
	if err != nil {
		t.Fatal(err)
	}
	var r, s secp256k1.ModNScalar
	r.SetByteSlice(sig[:32])
	s.SetByteSlice(sig[32:])
	if !ecdsa.NewSignature(&r, &s).Verify(digest, pub) {
		t.Fatal("the key read from the ENR did not sign it")
	}
	for _, bad := range []string{"", "enr:", "enr:-test", realENR[:40], "enx:" + realENR[4:]} {
		if _, err := enrPubkey(bad); err == nil {
			t.Fatalf("enrPubkey(%q) passed", bad)
		}
	}
}
