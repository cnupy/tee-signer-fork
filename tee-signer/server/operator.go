package server

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/signer-protocol"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
)

// The SSV operator key. An SSV operator signs its consensus messages with
// an RSA key, and the network encrypts each validator share to it on
// chain. A host that holds the key can decrypt every share the operator
// was ever given, so a dv_share runner that serves an SSV node keeps the
// key too: the admin imports it once, sealed to the runner's attested
// import key (IMPORT_OPERATOR_KEY_SEALED), the runner stores it sealed
// under the platform's sealing key and gives out only its public key
// (OPERATOR_IDENTITY) and signatures over SHA-256 digests
// (OPERATOR_SIGN), never a decryption. It refuses a second key while the
// stored one opens. The key lives under operator/, which the state copy holds with
// the shares (statestore.Prefixes), so it outlives a restart on Azure ACI.

const (
	operatorKeyName = "operator/rsa"
	minOperatorBits = 2048
	maxOperatorBits = 4096
)

// operatorAAD binds the stored key to the setup and the mark log, as
// shareAAD binds a share.
func (s *Server) operatorAAD() []byte {
	return setupwire.CtxOperatorKey.Message(s.SetupHash[:], s.LogID[:])
}

// checkOperatorMode refuses the operator key messages off signing_mode =
// dv_share.
func (s *Server) checkOperatorMode() error {
	if !s.dvShare() {
		return backend.Refused(backend.StatusUnsupported, "the SSV operator key needs a setup with signing_mode = dv_share")
	}
	return nil
}

// operator returns the operator key, loading it from the store at first
// use.
func (s *Server) operator() (*rsa.PrivateKey, error) {
	if err := s.checkOperatorMode(); err != nil {
		return nil, err
	}
	s.operatorMu.Lock()
	defer s.operatorMu.Unlock()
	if s.operatorKey != nil {
		return s.operatorKey, nil
	}
	if s.SealingKeyUnproven {
		return nil, backend.Refused(backend.StatusPlatform,
			"operator key: the sealing key came from the store and the stored shares were not checked at this start (the image check held them); restart once it passes")
	}
	blob, err := s.Platform.Store.Get(operatorKeyName)
	if errors.Is(err, platform.ErrNotFound) {
		return nil, backend.Refused(backend.StatusUnknownValidator, "no SSV operator key: import one (signer-admin ssv-operator-key)")
	}
	if err != nil {
		return nil, backend.Refused(backend.StatusStorage, "operator key: %v", err)
	}
	der, err := s.Platform.Sealer.Unseal(blob, s.operatorAAD())
	if err != nil {
		return nil, backend.Refused(backend.StatusPlatform, "operator key: the stored record does not open: %v; import the key again (signer-admin ssv-operator-key)", err)
	}
	defer clear(der)
	k, err := parseOperatorKey(der)
	if err != nil {
		return nil, backend.Refused(backend.StatusBadKey, "stored operator key: %v", err)
	}
	s.operatorKey = k
	return k, nil
}

// parseOperatorKey reads a PKCS #1 DER RSA key of minOperatorBits to
// maxOperatorBits.
func parseOperatorKey(der []byte) (*rsa.PrivateKey, error) {
	k, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		return nil, errors.New("not a PKCS #1 DER RSA private key")
	}
	if b := k.N.BitLen(); b < minOperatorBits || b > maxOperatorBits {
		return nil, fmt.Errorf("RSA key of %d bits, want %d to %d", b, minOperatorBits, maxOperatorBits)
	}
	if err := k.Validate(); err != nil {
		return nil, fmt.Errorf("RSA key: %w", err)
	}
	return k, nil
}

// importOperatorKey serves IMPORT_OPERATOR_KEY_SEALED.
func (s *Server) importOperatorKey(p []byte) ([]byte, error) {
	if err := s.checkOperatorMode(); err != nil {
		return nil, err
	}
	if s.ImportKey == nil {
		return nil, backend.Refused(backend.StatusUnsupported, "sealed import is disabled (-sealed-import=false)")
	}
	if err := s.checkLogID(); err != nil {
		return nil, backend.Refused(backend.StatusNotReady, "%v", err)
	}
	if s.SealingKeyUnproven {
		return nil, backend.Refused(backend.StatusPlatform,
			"seal operator key: the sealing key came from the store and the stored shares were not checked at this start (the image check held them); restart once it passes")
	}
	sealed, err := wireadmin.DecodeImportOperatorKey(p)
	if err != nil {
		return nil, backend.Refused(backend.StatusBadRequest, "%v", err)
	}
	der, err := s.ImportKey.OpenBytes(sealed, wireadmin.OperatorKeyAAD)
	if err != nil {
		return nil, backend.Refused(backend.StatusBadKey, "%v", err)
	}
	defer clear(der)
	k, err := parseOperatorKey(der)
	if err != nil {
		return nil, backend.Refused(backend.StatusBadKey, "%v", err)
	}
	s.operatorMu.Lock()
	defer s.operatorMu.Unlock()
	// A stored key that no longer opens may be replaced: on Nitro and GCP a
	// start with no share stored makes a new sealing key.
	dup := backend.Refused(backend.StatusDuplicate, "this runner holds an SSV operator key already; a new key needs a new runner state")
	switch old, err := s.Platform.Store.Get(operatorKeyName); {
	case s.operatorKey != nil:
		return nil, dup
	case err == nil:
		if k, err := s.Platform.Sealer.Unseal(old, s.operatorAAD()); err == nil {
			clear(k)
			return nil, dup
		}
		s.Log.Warn("replacing a stored operator key that does not open")
	case !errors.Is(err, platform.ErrNotFound):
		return nil, backend.Refused(backend.StatusStorage, "operator key: %v", err)
	}
	blob, err := s.Platform.Sealer.Seal(der, s.operatorAAD())
	if err != nil {
		return nil, backend.Refused(backend.StatusPlatform, "seal operator key: %v", err)
	}
	if err := s.Platform.Store.Put(operatorKeyName, blob); err != nil {
		return nil, backend.Refused(backend.StatusStorage, "store operator key: %v", err)
	}
	s.operatorKey = k
	pub, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		return nil, err
	}
	s.Log.Info("imported operator key", "bits", k.N.BitLen())
	return pub, nil
}

// operatorIdentity serves OPERATOR_IDENTITY: the public key, PKIX DER.
func (s *Server) operatorIdentity() ([]byte, error) {
	k, err := s.operator()
	if err != nil {
		return nil, err
	}
	return x509.MarshalPKIXPublicKey(&k.PublicKey)
}

// operatorSign serves OPERATOR_SIGN: p is a SHA-256 digest. The padding
// fixes all but those 32 bytes, so the answers are signatures and never a
// decryption of a share ciphertext.
func (s *Server) operatorSign(p []byte) ([]byte, error) {
	if len(p) != 32 {
		return nil, backend.Refused(backend.StatusBadRequest, "OPERATOR_SIGN takes a 32-byte SHA-256 digest, got %d bytes", len(p))
	}
	k, err := s.operator()
	if err != nil {
		return nil, err
	}
	return rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, p)
}
