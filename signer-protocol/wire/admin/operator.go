package admin

import (
	"errors"
	"fmt"
)

// OperatorKeyVersion is the version byte of IMPORT_OPERATOR_KEY_SEALED.
const OperatorKeyVersion = 1

// MaxOperatorKey bounds the sealed operator key: a PKCS #1 DER RSA key
// of up to 4096 bits, the HPKE encapsulation and the tag.
const MaxOperatorKey = 8192

// OperatorKeyAAD is the associated data of a sealed operator key, the
// context signer-operator-key-import-v1 (setupwire.CtxOperatorKeyImport).
// It differs from every share header, so a sealed share never opens as an
// operator key, nor the other way round.
var OperatorKeyAAD = []byte("signer-operator-key-import-v1")

// EncodeImportOperatorKey is the IMPORT_OPERATOR_KEY_SEALED payload:
// version:u8 sealed (sealedimport.SealBytes under OperatorKeyAAD).
func EncodeImportOperatorKey(sealed []byte) ([]byte, error) {
	if len(sealed) == 0 || len(sealed) > MaxOperatorKey {
		return nil, fmt.Errorf("wire: sealed operator key of %d bytes, want 1 to %d", len(sealed), MaxOperatorKey)
	}
	return append([]byte{OperatorKeyVersion}, sealed...), nil
}

// DecodeImportOperatorKey returns the sealed key of the payload.
func DecodeImportOperatorKey(p []byte) ([]byte, error) {
	switch {
	case len(p) < 2:
		return nil, errors.New("wire: short IMPORT_OPERATOR_KEY_SEALED")
	case p[0] != OperatorKeyVersion:
		return nil, fmt.Errorf("wire: IMPORT_OPERATOR_KEY_SEALED version %d, want %d", p[0], OperatorKeyVersion)
	case len(p)-1 > MaxOperatorKey:
		return nil, fmt.Errorf("wire: sealed operator key of %d bytes, at most %d", len(p)-1, MaxOperatorKey)
	}
	return p[1:], nil
}
