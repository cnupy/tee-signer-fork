//go:build !debugimport

package server

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/sealedimport"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
	"github.com/lidofinance/tee-signer/slashing-log"
)

func (e *tgtEnv) sendOperatorKey(der []byte) ([]byte, error) {
	e.t.Helper()
	sealed, err := sealedimport.SealBytes(e.sealTo(), wireadmin.OperatorKeyAAD, der)
	if err != nil {
		e.t.Fatal(err)
	}
	p, err := wireadmin.EncodeImportOperatorKey(sealed)
	if err != nil {
		e.t.Fatal(err)
	}
	return e.srv.dispatch(ctx, wire.Frame{Type: wireadmin.TypeImportOperatorKey, Payload: p})
}

func newOperatorKey(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k, x509.MarshalPKCS1PrivateKey(k)
}

// The SSV operator key of a dv_share runner: imported sealed once, its
// public key served, SHA-256 digests signed as ssv-signer signs them, the
// key kept across a restart, and a second key refused.
func TestOperatorKey(t *testing.T) {
	e := newDVEnv(t)
	k, der := newOperatorKey(t)

	_, err := e.srv.dispatch(ctx, wire.Frame{Type: wire.TypeOperatorIdentity})
	if backend.StatusOf(err) != backend.StatusUnknownValidator {
		t.Fatalf("OPERATOR_IDENTITY before an import: %v", err)
	}
	pub, err := e.sendOperatorKey(der)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if string(pub) != string(want) {
		t.Fatal("the import answers another public key")
	}

	check := func() {
		t.Helper()
		got, err := e.srv.dispatch(ctx, wire.Frame{Type: wire.TypeOperatorIdentity})
		if err != nil || string(got) != string(want) {
			t.Fatalf("OPERATOR_IDENTITY: %v", err)
		}
		msg := []byte("an SSV message")
		d := sha256.Sum256(msg)
		sig, err := e.srv.dispatch(ctx, wire.Frame{Type: wire.TypeOperatorSign, Payload: d[:]})
		if err != nil {
			t.Fatal(err)
		}
		if err := rsa.VerifyPKCS1v15(&k.PublicKey, crypto.SHA256, d[:], sig); err != nil {
			t.Fatalf("OPERATOR_SIGN: %v", err)
		}
		if _, err := e.srv.dispatch(ctx, wire.Frame{Type: wire.TypeOperatorSign, Payload: msg}); backend.StatusOf(err) != backend.StatusBadRequest {
			t.Fatalf("OPERATOR_SIGN of a payload that is not a digest: %v", err)
		}
	}
	check()

	_, other := newOperatorKey(t)
	if _, err := e.sendOperatorKey(other); backend.StatusOf(err) != backend.StatusDuplicate {
		t.Fatalf("a second operator key: %v", err)
	}

	e.restart()
	check()
	if _, err := e.sendOperatorKey(other); backend.StatusOf(err) != backend.StatusDuplicate {
		t.Fatalf("a second operator key after a restart: %v", err)
	}
}

// With a state copy, the operator key comes back as the shares do after
// a start that lost the local store, as every restart on Azure ACI.
func TestOperatorKeyStateCopy(t *testing.T) {
	e := newDVEnv(t)
	fl, err := markstore.NewFileLog(filepath.Join(e.dir, "copy"))
	if err != nil {
		t.Fatal(err)
	}
	e.copyLog = fl
	e.restart()
	k, der := newOperatorKey(t)
	if _, err := e.sendOperatorKey(der); err != nil {
		t.Fatal(err)
	}
	e.store = &shareStore{m: map[string][]byte{}}
	e.restart()
	want, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if got, err := e.srv.dispatch(ctx, wire.Frame{Type: wire.TypeOperatorIdentity}); err != nil || string(got) != string(want) {
		t.Fatalf("OPERATOR_IDENTITY after a start from the state copy: %v", err)
	}
}

// A stored operator key that no longer opens, as after a new sealing key
// on Nitro or GCP: the runner says so, and an import replaces it.
func TestOperatorKeyReplaceUnopened(t *testing.T) {
	e := newDVEnv(t)
	_, der := newOperatorKey(t)
	if _, err := e.sendOperatorKey(der); err != nil {
		t.Fatal(err)
	}
	e.store.mu.Lock()
	e.store.m[operatorKeyName] = []byte("sealed under another key")
	e.store.mu.Unlock()
	e.restart()
	if _, err := e.srv.dispatch(ctx, wire.Frame{Type: wire.TypeOperatorIdentity}); backend.StatusOf(err) != backend.StatusPlatform ||
		!strings.Contains(err.Error(), "import the key again") {
		t.Fatalf("OPERATOR_IDENTITY of a record that does not open: %v", err)
	}
	k, other := newOperatorKey(t)
	if _, err := e.sendOperatorKey(other); err != nil {
		t.Fatalf("an import over a record that does not open: %v", err)
	}
	want, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if got, err := e.srv.dispatch(ctx, wire.Frame{Type: wire.TypeOperatorIdentity}); err != nil || string(got) != string(want) {
		t.Fatalf("OPERATOR_IDENTITY after the new import: %v", err)
	}
}

// Only dv_share runners take an operator key, and only an RSA key of
// 2048 to 4096 bits.
func TestOperatorKeyRefused(t *testing.T) {
	_, der := newOperatorKey(t)
	e := newShareTgtEnv(t, "dev", nil)
	if _, err := e.sendOperatorKey(der); err == nil || !strings.Contains(err.Error(), "dv_share") {
		t.Fatalf("a threshold runner took an operator key: %v", err)
	}

	e = newDVEnv(t)
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.sendOperatorKey(x509.MarshalPKCS1PrivateKey(small)); backend.StatusOf(err) != backend.StatusBadKey {
		t.Fatalf("a 1024-bit key: %v", err)
	}
	if _, err := e.sendOperatorKey([]byte("not a key")); backend.StatusOf(err) != backend.StatusBadKey {
		t.Fatalf("garbage: %v", err)
	}
	// A share sealed for an import does not open as an operator key.
	var sk [32]byte
	sk[31] = 7
	sealed, err := sealedimport.SealAAD(e.sealTo(), []byte("another header"), &sk)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := wireadmin.EncodeImportOperatorKey(sealed)
	if _, err := e.srv.dispatch(ctx, wire.Frame{Type: wireadmin.TypeImportOperatorKey, Payload: p}); backend.StatusOf(err) != backend.StatusBadKey {
		t.Fatalf("a sealed share as an operator key: %v", err)
	}
}
