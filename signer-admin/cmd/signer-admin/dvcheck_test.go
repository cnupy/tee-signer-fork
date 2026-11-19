package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	cloud "github.com/lidofinance/tee-signer/signer-protocol"
)

// testSplit is the split file dv-split makes from c, for share index 2.
func testSplit(c *charonCluster) *splitFile {
	sf := &splitFile{T: uint8(c.t), N: uint8(c.n), Shares: map[string]uint8{"d1": 2}}
	for v, g := range c.groups {
		sf.Validators = append(sf.Validators, splitValidator{Pubkey: g, Commitments: c.commitments[v]})
	}
	return sf
}

// The split file of an order must come from the lock: each validator one
// of the lock's, with its commitments, and the same t and n. The share at
// the index is then the lock's public share there.
func TestCheckLockSplit(t *testing.T) {
	dir := t.TempDir()
	c := newCharonCluster(t, 2, 3, 4)
	lock := c.lock(t, filepath.Join(dir, "lock.json"), nil)
	shares, err := checkLockSplit(testSplit(c), lock, 2)
	if err != nil {
		t.Fatal(err)
	}
	for v, g := range c.groups {
		if shares[g] != c.sharePub(t, v, 1) {
			t.Errorf("validator %d: share key %s, want the lock's public share 2", v, shares[g])
		}
	}

	other := newCharonCluster(t, 1, 3, 4)
	foreign := testSplit(c)
	foreign.Validators = append(foreign.Validators, testSplit(other).Validators...)
	otherT := newCharonCluster(t, 2, 2, 4)
	for _, x := range []struct {
		name string
		sf   *splitFile
		lock string
		want string
	}{
		{"validator not in the lock", foreign, lock, "is not in"},
		{"commitments of another split", func() *splitFile {
			sf := testSplit(c)
			sf.Validators[1].Commitments = slicesWith(sf.Validators[1].Commitments, 1, other.commitments[0][1])
			return sf
		}(), lock, "commitments are not those"},
		{"another t", testSplit(c), otherT.lock(t, filepath.Join(dir, "lock-t2.json"), nil), "2 of 4 cluster"},
	} {
		if _, err := checkLockSplit(x.sf, x.lock, 2); err == nil || !strings.Contains(err.Error(), x.want) {
			t.Errorf("%s: %v, want %q", x.name, err, x.want)
		}
	}
}

func slicesWith(s []cloud.Pubkey, i int, v cloud.Pubkey) []cloud.Pubkey {
	out := append([]cloud.Pubkey(nil), s...)
	out[i] = v
	return out
}

// fakeBeacon is a beacon node of the chain whose genesis_validators_root
// is gvr. It answers the validators endpoint from known, key to status;
// unknown keys are left out, as a beacon node does. It records each id
// parameter.
func fakeBeacon(t *testing.T, gvr [32]byte, known map[cloud.Pubkey]string, ids *[]string) *httptest.Server {
	t.Helper()
	return fakeBeaconSync(t, gvr, "false", known, ids)
}

// fakeBeaconSync is fakeBeacon whose node/syncing answer says
// is_syncing = syncing ("bad": an answer that does not parse).
func fakeBeaconSync(t *testing.T, gvr [32]byte, syncing string, known map[cloud.Pubkey]string, ids *[]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/eth/v1/beacon/genesis" {
			fmt.Fprintf(w, `{"data":{"genesis_time":"1606824023","genesis_validators_root":"0x%x","genesis_fork_version":"0x00000000"}}`, gvr)
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/eth/v1/node/syncing" {
			if syncing == "bad" {
				fmt.Fprint(w, `{"data":`)
				return
			}
			fmt.Fprintf(w, `{"data":{"head_slot":"100","sync_distance":"0","is_syncing":%s,"is_optimistic":false,"el_offline":false}}`, syncing)
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/eth/v1/config/spec" {
			fmt.Fprint(w, `{"data":{"CONFIG_NAME":"mainnet","SECONDS_PER_SLOT":"12","SLOTS_PER_EPOCH":"32"}}`)
			return
		}
		if r.Method != http.MethodGet || r.URL.Path != "/eth/v1/beacon/states/head/validators" {
			http.NotFound(w, r)
			return
		}
		id := r.URL.Query().Get("id")
		*ids = append(*ids, id)
		type val struct {
			Status    string `json:"status"`
			Validator struct {
				Pubkey string `json:"pubkey"`
			} `json:"validator"`
		}
		resp := struct {
			Data []val `json:"data"`
		}{Data: []val{}}
		for _, k := range strings.Split(id, ",") {
			for pk, st := range known {
				if pk.String() == k {
					v := val{Status: st}
					v.Validator.Pubkey = k
					resp.Data = append(resp.Data, v)
				}
			}
		}
		json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// testGVR is the chain of the fake beacon node in the tests.
var testGVR = [32]byte{0x4b, 0x36, 0x3d}

// -beacon refuses a share key that is a validator, warns on a group key
// that is unknown, not active or slashed, and sends public keys only, at
// most beaconBatch per request.
func TestCheckBeacon(t *testing.T) {
	c := newCharonCluster(t, 20, 3, 4)
	shares := map[cloud.Pubkey]cloud.Pubkey{}
	for v, g := range c.groups {
		shares[g] = c.sharePub(t, v, 1)
	}
	known := map[cloud.Pubkey]string{c.groups[1]: "pending_queued", c.groups[3]: "active_slashed", c.groups[4]: "exited_slashed"}
	for _, v := range []int{0, 2} {
		known[c.groups[v]] = "active_ongoing"
	}
	for v := 5; v < 20; v++ {
		known[c.groups[v]] = "active_ongoing"
	}
	ctx := context.Background()

	var ids []string
	srv := fakeBeacon(t, testGVR, known, &ids)
	var out bytes.Buffer
	if confirmed, err := checkBeacon(ctx, srv.URL, testGVR, shares, &out); err != nil || !confirmed {
		t.Fatalf("confirmed %v, %v", confirmed, err)
	}
	wantIn(t, out.String(), "WARNING validator "+c.groups[1].String()+": status pending_queued",
		"WARNING validator "+c.groups[3].String()+": slashed (active_slashed)",
		"WARNING validator "+c.groups[4].String()+": slashed (exited_slashed)", "17 of 20 group keys active")
	if strings.Contains(out.String(), "WARNING validator "+c.groups[0].String()) {
		t.Errorf("warned about an active validator:\n%s", out.String())
	}
	asked := 0
	for _, id := range ids {
		ks := strings.Split(id, ",")
		if len(ks) > beaconBatch || beaconBatch > 16 {
			t.Errorf("one request asked for %d keys, batch %d", len(ks), beaconBatch)
		}
		for _, k := range ks {
			if !strings.HasPrefix(k, "0x") || len(k) != 98 {
				t.Errorf("id %q is not a public key", k)
			}
			asked++
		}
	}
	if asked != 40 {
		t.Errorf("asked for %d keys, want 40", asked)
	}

	srv = fakeBeacon(t, testGVR, map[cloud.Pubkey]string{c.groups[0]: "active_ongoing", c.sharePub(t, 2, 1): "active_ongoing"}, &ids)
	_, err := checkBeacon(ctx, srv.URL, testGVR, shares, &out)
	if err == nil || !strings.Contains(err.Error(), "share "+c.sharePub(t, 2, 1).String()) || !strings.Contains(err.Error(), "is itself a validator") {
		t.Fatalf("share key that is a validator: %v", err)
	}

	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	defer down.Close()
	if _, err := checkBeacon(ctx, down.URL, testGVR, shares, &out); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("beacon node down: %v", err)
	}
}

// A node of another chain knows none of the keys: -beacon stops before any
// lookup, and so does a node that is still syncing or whose sync state does
// not read. A synced node that knows no group key gets a warning (a new
// cluster), and a share key it knows as a validator is still refused. A
// setup without a genesis_validators_root cannot be compared.
func TestCheckBeaconWrongNode(t *testing.T) {
	c := newCharonCluster(t, 2, 3, 4)
	shares := map[cloud.Pubkey]cloud.Pubkey{}
	for v, g := range c.groups {
		shares[g] = c.sharePub(t, v, 1)
	}
	ctx := context.Background()
	var ids []string
	other := [32]byte{0xd8, 0xea}
	srv := fakeBeacon(t, other, map[cloud.Pubkey]string{}, &ids)
	var out bytes.Buffer
	_, err := checkBeacon(ctx, srv.URL, testGVR, shares, &out)
	if err == nil || !strings.Contains(err.Error(), "0x"+hex.EncodeToString(other[:])) || !strings.Contains(err.Error(), "another chain") || len(ids) != 0 {
		t.Fatalf("node of another chain: %v, %d lookups", err, len(ids))
	}

	for _, syncing := range []string{"true", "bad"} {
		ids = nil
		srv = fakeBeaconSync(t, testGVR, syncing, map[cloud.Pubkey]string{}, &ids)
		_, err = checkBeacon(ctx, srv.URL, testGVR, shares, &out)
		if err == nil || !strings.Contains(err.Error(), "the beacon node is not synced; drop -beacon to skip") || len(ids) != 0 {
			t.Fatalf("is_syncing %s: %v, %d lookups", syncing, err, len(ids))
		}
	}

	srv = fakeBeacon(t, testGVR, map[cloud.Pubkey]string{}, &ids)
	out.Reset()
	if confirmed, err := checkBeacon(ctx, srv.URL, testGVR, shares, &out); err != nil || confirmed {
		t.Fatalf("synced node that knows no group key: confirmed %v, %v", confirmed, err)
	}
	wantIn(t, out.String(), "WARNING no group key is deposited yet (new cluster?)")

	srv = fakeBeacon(t, testGVR, map[cloud.Pubkey]string{c.sharePub(t, 1, 1): "active_ongoing"}, &ids)
	_, err = checkBeacon(ctx, srv.URL, testGVR, shares, &out)
	if err == nil || !strings.Contains(err.Error(), "is itself a validator") {
		t.Fatalf("share key that is a validator, no group key known: %v", err)
	}

	if _, err := checkBeacon(ctx, srv.URL, [32]byte{}, shares, &out); err == nil || !strings.Contains(err.Error(), "no genesis_validators_root") {
		t.Fatalf("setup without a root: %v", err)
	}
}

// fakePrompt makes confirmShares read answer from a terminal (or from a
// stdin that is not one) and returns what it prints.
func fakePrompt(t *testing.T, terminal bool, answer string) *bytes.Buffer {
	t.Helper()
	in, out, term := confirmIn, confirmOut, confirmTerminal
	t.Cleanup(func() { confirmIn, confirmOut, confirmTerminal = in, out, term })
	var b bytes.Buffer
	confirmIn, confirmOut, confirmTerminal = strings.NewReader(answer), &b, func() bool { return terminal }
	return &b
}

// Without a chain check the admin confirms the keys are shares: only y or
// yes goes on; anything else, EOF and a stdin that is not a terminal stop.
func TestConfirmShares(t *testing.T) {
	for _, c := range []struct {
		terminal bool
		answer   string
		ok       bool
		want     string
	}{
		{true, "y\n", true, ""},
		{true, "yes\n", true, ""},
		{true, "n\n", false, "not confirmed"},
		{true, "Y\n", false, "not confirmed"},
		{true, "yess\n", false, "not confirmed"},
		{true, "", false, "not confirmed"},
		{false, "y\n", false, "stdin is not a terminal"},
	} {
		asked := fakePrompt(t, c.terminal, c.answer)
		err := confirmShares(3)
		if c.ok != (err == nil) || err != nil && !strings.Contains(err.Error(), c.want) {
			t.Errorf("terminal %v, answer %q: %v", c.terminal, c.answer, err)
		}
		if prompted := strings.Contains(asked.String(), "No chain check for these 3 keys. Confirm they are shares from a Charon cluster, not whole validator keys [y/N] "); prompted != c.terminal {
			t.Errorf("terminal %v: prompt %q", c.terminal, asked.String())
		}
	}
}

// TestCheckBeaconPartlyKnown: a node that knows only some of the group keys
// does not confirm the order, so the admin is still asked about the rest.
func TestCheckBeaconPartlyKnown(t *testing.T) {
	c := newCharonCluster(t, 3, 3, 4)
	shares := map[cloud.Pubkey]cloud.Pubkey{}
	known := map[cloud.Pubkey]string{}
	for v, g := range c.groups {
		shares[g] = c.sharePub(t, v, 1)
		if v != 0 {
			known[g] = "active_ongoing"
		}
	}
	var ids []string
	srv := fakeBeacon(t, testGVR, known, &ids)
	var out bytes.Buffer
	if confirmed, err := checkBeacon(context.Background(), srv.URL, testGVR, shares, &out); err != nil || confirmed {
		t.Fatalf("one group key unknown: confirmed %v, %v", confirmed, err)
	}
}
