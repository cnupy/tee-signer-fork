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

// A signer that answers and holds no key: a load error by default, an
// empty key list with AllowNoKeys (an SSV operator before its first
// validator). A signer that never answered is an error either way.
func TestNoKeys(t *testing.T) {
	for _, allow := range []bool{false, true} {
		f := &fakeRunner{mode: "dv_share"}
		s := newSigners([]string{"s1"}, []runner{f}, 0, 2*time.Second, slog.New(slog.NewTextHandler(io.Discard, nil)))
		s.allowNoKeys = allow
		n, err := s.Refresh(context.Background())
		switch {
		case !allow && (err == nil || !strings.Contains(err.Error(), "no key")):
			t.Fatalf("no keys, not allowed: %d, %v", n, err)
		case allow && (err != nil || n != 0):
			t.Fatalf("no keys, allowed: %d, %v", n, err)
		}
		// A signer that never answered: an error, keys or not. (One that
		// answered once keeps its last answer through failures.)
		down := &fakeRunner{mode: "dv_share", err: errors.New("down")}
		s = newSigners([]string{"s1"}, []runner{down}, 0, 2*time.Second, slog.New(slog.NewTextHandler(io.Discard, nil)))
		s.allowNoKeys = allow
		if _, err := s.Refresh(context.Background()); err == nil || !strings.Contains(err.Error(), "no signer answered") {
			t.Fatalf("allow=%v: a signer that never answered: %v", allow, err)
		}
	}
}
