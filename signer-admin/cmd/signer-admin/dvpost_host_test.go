//go:build dvt

package main

import (
	"context"
	"errors"
	"net"
	"net/url"
	"os"
	"strings"
	"testing"
)

// fakeLookup makes the API host lookup of dv-exit-post answer from hosts
// (a name to its addresses); a name it lacks does not resolve. It counts
// the lookups of each name.
func fakeLookup(t *testing.T, hosts map[string][]string) map[string]int {
	t.Helper()
	old := apiLookup
	t.Cleanup(func() { apiLookup = old })
	n := map[string]int{}
	apiLookup = func(_ context.Context, host string) ([]net.IPAddr, error) {
		n[host]++
		addrs, ok := hosts[host]
		if !ok {
			return nil, errors.New("no such host " + host)
		}
		var ips []net.IPAddr
		for _, a := range addrs {
			ips = append(ips, net.IPAddr{IP: net.ParseIP(a)})
		}
		return ips, nil
	}
	return n
}

// -api: https to any host; http only to a host whose every address is a
// loopback one, by resolution, not by the name localhost.
func TestCheckAPIURLLoopback(t *testing.T) {
	fakeLookup(t, map[string][]string{
		"localhost":  {"127.0.0.1", "::1"},
		"obol.test":  {"127.0.0.1"},
		"evil.test":  {"203.0.113.7"},
		"mixed.test": {"127.0.0.1", "203.0.113.7"},
	})
	for _, c := range []struct {
		url string
		ok  bool
	}{
		{"https://api.obol.tech/v1", true},
		{"http://localhost:3000/v1", true},
		{"http://obol.test:3000", true},
		{"http://127.0.0.2", true},
		{"http://[::1]:8080", true},
		{"http://evil.test", false},
		{"http://mixed.test", false},
		{"http://nx.test", false},
		{"http://10.0.0.1", false},
		{"ftp://localhost", false},
	} {
		if err := checkAPIURL(c.url); (err == nil) != c.ok {
			t.Errorf("checkAPIURL(%q): %v, want ok %v", c.url, err, c.ok)
		}
	}
	// A hosts file that points localhost elsewhere.
	fakeLookup(t, map[string][]string{"localhost": {"203.0.113.7"}})
	if err := checkAPIURL("http://localhost:3000"); err == nil || !strings.Contains(err.Error(), "203.0.113.7 is not a loopback address") {
		t.Fatalf("localhost to 203.0.113.7: %v", err)
	}
}

// Over http dv-exit-post connects to the loopback address it checked, and
// checks again at connect time: a name that resolves to loopback at the
// check and elsewhere at the connection is refused before any request.
func TestDVExitPostLoopbackDial(t *testing.T) {
	p := newDVPost(t)
	key := p.keyFile(t, 1, 0o600)
	u, err := url.Parse(p.api.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	api := "http://obol.test:" + u.Port()
	fakeLookup(t, map[string][]string{"obol.test": {"127.0.0.1"}})
	wantIn(t, mustTool(t, "dv-exit-post", "-lock", p.lock, "-enr-key", key, "-api", api, "-yes", p.partials), "201 Created")
	if p.api.requests != 1 {
		t.Fatalf("%d requests", p.api.requests)
	}

	// The scheme in capitals is http too.
	for _, api := range []string{api, "HTTP://localhost:" + u.Port()} {
		n := fakeLookup(t, map[string][]string{"obol.test": {"127.0.0.1"}, "localhost": {"127.0.0.1"}})
		old := apiLookup
		apiLookup = func(ctx context.Context, host string) ([]net.IPAddr, error) {
			if n[host] > 0 {
				return []net.IPAddr{{IP: net.ParseIP("203.0.113.7")}}, nil
			}
			return old(ctx, host)
		}
		wantIn(t, failTool(t, "dv-exit-post", "-lock", p.lock, "-enr-key", key, "-api", api, "-yes", p.partials), "203.0.113.7 is not a loopback address")
		if p.api.requests != 1 {
			t.Fatalf("%s: a request reached the API after the name moved off loopback", api)
		}
	}
}

// The ENR key file must belong to the user who runs dv-exit-post, as well
// as have mode 0600. The refusal says to run the tool as the key's owner:
// a chown could stop Charon from reading its key.
func TestDVExitPostKeyOwner(t *testing.T) {
	p := newDVPost(t)
	key := p.keyFile(t, 1, 0o600)
	old := currentUID
	t.Cleanup(func() { currentUID = old })
	me := os.Getuid()
	currentUID = func() int { return me + 1 }
	res := failTool(t, "dv-exit-post", "-lock", p.lock, "-enr-key", key, "-api", p.api.srv.URL, "-yes", p.partials)
	wantIn(t, res, key+": owned by uid "+uitoa(uint64(me))+", not by this user (uid "+uitoa(uint64(me+1))+"); run dv-exit-post as that user")
	if strings.Contains(res, "chown") {
		t.Fatalf("the refusal tells the operator to chown Charon's key: %s", res)
	}
	if p.api.requests != 0 {
		t.Fatal("a request reached the API")
	}
}
