package remote

import (
	"context"

	"github.com/lidofinance/tee-signer/signer-protocol/wire"
)

// OperatorIdentity returns the SSV operator's RSA public key (PKIX DER)
// that a dv_share runner holds (OPERATOR_IDENTITY).
func (c *Client) OperatorIdentity(ctx context.Context) ([]byte, error) {
	return c.roundTrip(ctx, wire.TypeOperatorIdentity, nil)
}

// OperatorSign signs digest, the SHA-256 of an SSV message, with the
// operator key (OPERATOR_SIGN): RSA PKCS #1 v1.5 over SHA-256, the
// signature ssv-signer's /v1/operator/sign returns for that message.
func (c *Client) OperatorSign(ctx context.Context, digest [32]byte) ([]byte, error) {
	return c.roundTrip(ctx, wire.TypeOperatorSign, digest[:])
}
