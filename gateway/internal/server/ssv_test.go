package server

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/gateway/internal/policy"
)

type fakeOperator struct{ key *rsa.PrivateKey }

func (o *fakeOperator) OperatorIdentity(context.Context) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(&o.key.PublicKey)
}

func (o *fakeOperator) OperatorSign(_ context.Context, d [32]byte) ([]byte, error) {
	return rsa.SignPKCS1v15(rand.Reader, o.key, crypto.SHA256, d[:])
}

func newSSVServer(t *testing.T) (*httptest.Server, *fakeSigner, *fakeOperator) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	op := &fakeOperator{key: k}
	srv, f := newTestServerWith(t, io.Discard, func(p *policy.Policy) { p.PassGroupKeyRegistrations() },
		func(s *Server) *Server { return s.WithSSV(op) })

	return srv, f, op
}

func request(t *testing.T, method, url, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)

	return resp.StatusCode, string(b)
}

// The ssv-signer API in the shapes ssv's client sends and reads
// (ssvsigner/client.go, types.go, web3signer/types.go).
func TestSSVAPI(t *testing.T) {
	srv, f, op := newSSVServer(t)

	code, body := request(t, http.MethodGet, srv.URL+"/v1/validators", "")
	if code != 200 || !strings.Contains(body, pubHex) {
		t.Fatalf("list: %d %s", code, body)
	}

	// A share the signers hold: "duplicate", which the node takes as added.
	code, body = request(t, http.MethodPost, srv.URL+"/v1/validators",
		`{"share_keys":[{"EncryptedPrivKey":"0x0102","PubKey":"`+pubHex+`"}]}`)
	var add struct {
		Data []struct{ Status, Message string }
	}
	if code != 200 || json.Unmarshal([]byte(body), &add) != nil || len(add.Data) != 1 || add.Data[0].Status != "duplicate" {
		t.Fatalf("add a held share: %d %s", code, body)
	}
	// One they do not hold: 503, never 422 (the node would skip it for good).
	other := "0x" + strings.Repeat("a1", 48)
	code, body = request(t, http.MethodPost, srv.URL+"/v1/validators",
		`{"share_keys":[{"EncryptedPrivKey":"0x0102","PubKey":"`+other+`"}]}`)
	if code != http.StatusServiceUnavailable || !strings.Contains(body, "signer-admin") {
		t.Fatalf("add a share not imported: %d %s", code, body)
	}

	code, body = request(t, http.MethodDelete, srv.URL+"/v1/validators", `{"pubkeys":["`+pubHex+`"]}`)
	if code != 200 || !strings.Contains(body, `"status":"deleted"`) {
		t.Fatalf("remove: %d %s", code, body)
	}

	// Sign answers JSON without an Accept header.
	code, body = request(t, http.MethodPost, srv.URL+"/v1/validators/sign/"+pubHex, attestationBody(100))
	if code != 200 || !strings.Contains(body, `"signature":"0xab`) || len(f.calls) != 1 {
		t.Fatalf("sign: %d %s", code, body)
	}
	// A registration of the group key passes the gateway; the signer
	// checks it.
	group := "0x" + strings.Repeat("b2", 48)
	code, body = request(t, http.MethodPost, srv.URL+"/v1/validators/sign/"+pubHex, registrationBody(allowedFeeRecipient, group))
	if code != 200 {
		t.Fatalf("registration of the group key: %d %s", code, body)
	}
	code, _ = request(t, http.MethodPost, srv.URL+"/v1/validators/sign/"+pubHex, registrationBody("0x"+strings.Repeat("22", 20), group))
	if code != http.StatusPreconditionFailed {
		t.Fatalf("a fee recipient off the allowlist: %d", code)
	}

	// Identity: base64 of a PEM block of type RSA PUBLIC KEY over PKIX, as
	// ssv's rsaencryption.PublicKeyToBase64PEM.
	code, body = request(t, http.MethodGet, srv.URL+"/v1/operator/identity", "")
	p, err := base64.StdEncoding.DecodeString(body)
	if code != 200 || err != nil {
		t.Fatalf("identity: %d %s", code, body)
	}
	blk, _ := pem.Decode(p)
	if blk == nil || blk.Type != "RSA PUBLIC KEY" {
		t.Fatalf("identity PEM: %q", p)
	}
	pub, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil || !pub.(*rsa.PublicKey).Equal(&op.key.PublicKey) {
		t.Fatalf("identity key: %v", err)
	}

	// Operator sign: RSA PKCS #1 v1.5 over SHA-256 of the body, raw bytes.
	msg := "an SSV message"
	code, body = request(t, http.MethodPost, srv.URL+"/v1/operator/sign", msg)
	d := sha256.Sum256([]byte(msg))
	if code != 200 || rsa.VerifyPKCS1v15(&op.key.PublicKey, crypto.SHA256, d[:], []byte(body)) != nil {
		t.Fatalf("operator sign: %d", code)
	}

	// Encrypt and decrypt are not served: 404, which the node reads as
	// unsupported.
	if code, _ = request(t, http.MethodPost, srv.URL+"/v1/operator/encrypt", "x"); code != http.StatusNotFound {
		t.Fatalf("encrypt: %d", code)
	}
}

// Without WithSSV the routes do not exist, and a registration of
// another key stays refused.
func TestSSVAPIOff(t *testing.T) {
	srv, _ := newTestServer(t)
	if code, _ := request(t, http.MethodGet, srv.URL+"/v1/operator/identity", ""); code != http.StatusNotFound {
		t.Fatalf("identity without ssv_api: %d", code)
	}
	code, _, _ := post(t, srv, pubHex, "", registrationBody(allowedFeeRecipient, "0x"+strings.Repeat("b2", 48)))
	if code != http.StatusPreconditionFailed {
		t.Fatalf("registration of another key without ssv_api: %d", code)
	}
}
