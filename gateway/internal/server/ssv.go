package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"strings"
)

// The ssv-signer API (ssvlabs/ssv ssvsigner/server.go) for an SSV node in
// remote signing mode. Shares enter the signers only under an
// approver-signed import order (signer-admin ssv-split), never from the
// node: an add answers "duplicate" for a share the signers hold and 503
// for one they do not, so the node retries until an admin imports it (never
// 422, which would make it drop the validator). A remove leaves the share
// in the signers. /v1/operator/encrypt and /decrypt are not served.

// Operator is the SSV operator key behind the gateway.
type Operator interface {
	// OperatorIdentity is the public key, PKIX DER.
	OperatorIdentity(ctx context.Context) ([]byte, error)
	// OperatorSign is the RSA PKCS #1 v1.5 signature over a SHA-256 digest.
	OperatorSign(ctx context.Context, digest [32]byte) ([]byte, error)
}

// WithSSV serves the ssv-signer API with the operator key of op.
func (s *Server) WithSSV(op Operator) *Server {
	s.ssv = op

	return s
}

func (s *Server) ssvRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/validators", s.publicKeys)
	mux.HandleFunc("POST /v1/validators", s.ssvAdd)
	mux.HandleFunc("DELETE /v1/validators", s.ssvRemove)
	mux.HandleFunc("POST /v1/validators/sign/{identifier}", func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("Accept", "application/json") // the node reads JSON
		s.sign(w, r)
	})
	mux.HandleFunc("GET /v1/operator/identity", s.ssvIdentity)
	mux.HandleFunc("POST /v1/operator/sign", s.ssvOperatorSign)
}

// keyStatus is one entry of the Web3Signer key manager answer that the
// SSV node reads for an add or a remove.
type keyStatus struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

// statuses is n entries of status.
func statuses(n int, status, message string) []keyStatus {
	out := make([]keyStatus, n)
	for i := range out {
		out[i] = keyStatus{Status: status, Message: message}
	}

	return out
}

func (s *Server) ssvAdd(w http.ResponseWriter, r *http.Request) {
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	var req struct {
		ShareKeys []struct {
			PubKey string `json:"PubKey"`
		} `json:"share_keys"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "failed to parse request: "+err.Error())
		return
	}
	var missing []string
	for _, sk := range req.ShareKeys {
		pk, ok := parsePubkey(sk.PubKey)
		if !ok {
			writeError(w, http.StatusBadRequest, "bad share public key "+sk.PubKey)
			return
		}
		if !s.signer.HasKey(r.Context(), pk) {
			missing = append(missing, sk.PubKey)
		}
	}
	if len(missing) > 0 {
		s.log.Warn("the node adds shares the signers do not hold; import them (signer-admin ssv-split)", "shares", strings.Join(missing, ","))
		writeError(w, http.StatusServiceUnavailable, "share not in the TEE signer yet, import it with signer-admin: "+strings.Join(missing, ", "))
		return
	}
	s.log.Info("shares held", "count", len(req.ShareKeys))
	writeJSON(w, http.StatusOK, map[string][]keyStatus{"data": statuses(len(req.ShareKeys), "duplicate", "the TEE signer holds this share")})
}

func (s *Server) ssvRemove(w http.ResponseWriter, r *http.Request) {
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	var req struct {
		Pubkeys []string `json:"pubkeys"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "failed to parse request: "+err.Error())
		return
	}
	s.log.Warn("the node removed shares; they stay in the signers until an admin removes them", "shares", strings.Join(req.Pubkeys, ","))
	writeJSON(w, http.StatusOK, map[string][]keyStatus{"data": statuses(len(req.Pubkeys), "deleted", "the TEE signer keeps the share until an admin removes it")})
}

func (s *Server) ssvIdentity(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), s.signTimeout)
	defer cancel()
	der, err := s.ssv.OperatorIdentity(ctx)
	if err != nil {
		s.log.Error("operator identity failed", "err", err.Error())
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	// As ssv's rsaencryption.PublicKeyToBase64PEM: PKIX under PEM type "RSA PUBLIC KEY".
	w.Header().Set("Content-Type", contentTypeText)
	_, _ = io.WriteString(w, base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: der})))
}

func (s *Server) ssvOperatorSign(w http.ResponseWriter, r *http.Request) {
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	if len(body) == 0 {
		writeError(w, http.StatusBadRequest, "request payload is empty")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.signTimeout)
	defer cancel()
	sig, err := s.ssv.OperatorSign(ctx, sha256.Sum256(body))
	if err != nil {
		s.log.Error("operator sign failed", "err", err.Error())
		writeError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	w.Header().Set("Content-Type", contentTypeOctets)
	_, _ = w.Write(sig)
}
