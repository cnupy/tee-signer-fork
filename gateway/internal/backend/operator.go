package backend

import (
	"context"
	"errors"
	"fmt"
)

// operatorRunner is a runner that serves the SSV operator key of a
// dv_share signer (runnerclient.Client and node do).
type operatorRunner interface {
	OperatorIdentity(ctx context.Context) ([]byte, error)
	OperatorSign(ctx context.Context, digest [32]byte) ([]byte, error)
}

var errNoOperator = errors.New("signer client has no operator key calls")

// OperatorIdentity is the SSV operator key (PKIX DER) of the first signer
// that answers, in config order: an SSV node has one operator key, so its
// gateway has one signer that holds it.
func (s *Signers) OperatorIdentity(ctx context.Context) ([]byte, error) {
	return s.firstOperator(ctx, func(ctx context.Context, o operatorRunner) ([]byte, error) {
		return o.OperatorIdentity(ctx)
	})
}

// OperatorSign signs digest, a SHA-256, with the operator key of the first
// signer that answers, in config order.
func (s *Signers) OperatorSign(ctx context.Context, digest [32]byte) ([]byte, error) {
	return s.firstOperator(ctx, func(ctx context.Context, o operatorRunner) ([]byte, error) {
		return o.OperatorSign(ctx, digest)
	})
}

// firstOperator makes call on each signer in config order and returns the
// first answer, or every signer's error.
func (s *Signers) firstOperator(ctx context.Context, call func(context.Context, operatorRunner) ([]byte, error)) ([]byte, error) {
	var errs []error
	for i, n := range s.nodes {
		o, ok := n.(operatorRunner)
		if !ok {
			errs = append(errs, fmt.Errorf("%s: %w", s.names[i], errNoOperator))

			continue
		}
		cctx, cancel := context.WithTimeout(ctx, s.timeout)
		out, err := call(cctx, o)
		cancel()
		if err == nil {
			return out, nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", s.names[i], capDetail(err)))
	}

	return nil, errors.Join(errs...)
}
