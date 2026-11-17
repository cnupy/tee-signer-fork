package backend

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// operatorFake is a fakeRunner that holds an operator key, or fails.
type operatorFake struct {
	fakeRunner
	pub []byte
	err error
}

func (f *operatorFake) OperatorIdentity(context.Context) ([]byte, error) { return f.pub, f.err }

func (f *operatorFake) OperatorSign(_ context.Context, d [32]byte) ([]byte, error) {
	return append(append([]byte(nil), f.pub...), d[:]...), f.err
}

// The operator calls go to the signers in config order and take the first
// answer; a signer without the calls, or one that fails, is skipped and
// named in the error when none answers.
func TestOperatorCalls(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	down := &operatorFake{err: errors.New("down")}
	s := newSigners([]string{"s1", "s2", "s3"}, []runner{&fakeRunner{}, down, &operatorFake{pub: []byte{7}}}, 0, time.Second, log)
	if pub, err := s.OperatorIdentity(context.Background()); err != nil || string(pub) != "\x07" {
		t.Fatalf("identity: %x, %v", pub, err)
	}
	if sig, err := s.OperatorSign(context.Background(), [32]byte{9}); err != nil || len(sig) != 33 || sig[1] != 9 {
		t.Fatalf("sign: %x, %v", sig, err)
	}
	s = newSigners([]string{"s1", "s2"}, []runner{&fakeRunner{}, down}, 0, time.Second, log)
	_, err := s.OperatorIdentity(context.Background())
	if err == nil || !strings.Contains(err.Error(), "s1: "+errNoOperator.Error()) || !strings.Contains(err.Error(), "s2: down") {
		t.Fatalf("no signer answers: %v", err)
	}
}
