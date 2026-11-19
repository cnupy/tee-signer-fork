package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/lidofinance/tee-signer/signer-core/threshold"
	cloud "github.com/lidofinance/tee-signer/signer-protocol"
)

// ---- import-draft checks for a dv_share signer ----
//
// They help the admin catch a wrong file before the approvers sign; the
// approvers still check each group key (README, "Charon shares"). The
// runner checks only that the share is the commitments' value at the
// order's index.

// checkLockSplit checks the split file of an order for share index idx
// against the Charon cluster lock it came from: the same t and n, every
// validator one of the lock's with the commitments dv-split makes from it,
// so the share at idx is the lock's public share at idx. It returns each
// validator's share key at idx, by group key.
func checkLockSplit(split *splitFile, lockPath string, idx uint8) (map[cloud.Pubkey]cloud.Pubkey, error) {
	ls, err := dvSplit(lockPath)
	if err != nil {
		return nil, err
	}
	if ls.T != split.T || ls.N != split.N {
		return nil, fmt.Errorf("%s is a %d of %d cluster, the split file says %d of %d", lockPath, ls.T, ls.N, split.T, split.N)
	}
	shares := make(map[cloud.Pubkey]cloud.Pubkey, len(split.Validators))
	for _, v := range split.Validators {
		comm, ok := ls.commitmentsOf(v.Pubkey)
		if !ok {
			return nil, fmt.Errorf("validator %s is not in %s", v.Pubkey, lockPath)
		}
		if !slices.Equal(comm, v.Commitments) {
			return nil, fmt.Errorf("validator %s: the split file's commitments are not those of %s", v.Pubkey, lockPath)
		}
		p, err := threshold.FeldmanEval(comm, uint64(idx))
		if err != nil {
			return nil, fmt.Errorf("validator %s: %w", v.Pubkey, err)
		}
		shares[v.Pubkey] = p
	}
	return shares, nil
}

// beaconTimeout bounds each beacon node request.
const beaconTimeout = 10 * time.Second

// beaconBatch is how many keys one request asks for: 16 keys make a query
// of about 1.6 kB, under the URL limits of common proxies.
const beaconBatch = 16

// beaconGenesis asks the beacon node at base for its chain's
// genesis_validators_root (GET /eth/v1/beacon/genesis).
func beaconGenesis(ctx context.Context, base string) ([32]byte, error) {
	var root [32]byte
	cl := &http.Client{Timeout: beaconTimeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/eth/v1/beacon/genesis", nil)
	if err != nil {
		return root, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := cl.Do(req)
	if err != nil {
		return root, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return root, fmt.Errorf("beacon node genesis: %s", resp.Status)
	}
	var r struct {
		Data struct {
			Root string `json:"genesis_validators_root"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&r); err != nil {
		return root, fmt.Errorf("beacon node genesis: %w", err)
	}
	b, err := hex.DecodeString(strings.TrimPrefix(r.Data.Root, "0x"))
	if err != nil || len(b) != 32 {
		return root, fmt.Errorf("beacon node genesis: genesis_validators_root %q", r.Data.Root)
	}
	copy(root[:], b)
	return root, nil
}

// beaconValidators asks the beacon node at base for the validators with the
// given public keys (GET /eth/v1/beacon/states/head/validators?id=...) and
// returns the status of each one it knows. The request carries public keys
// only.
func beaconValidators(ctx context.Context, base string, keys []cloud.Pubkey) (map[cloud.Pubkey]string, error) {
	cl := &http.Client{Timeout: beaconTimeout}
	got := map[cloud.Pubkey]string{}
	for len(keys) > 0 {
		n := min(len(keys), beaconBatch)
		ids := make([]string, n)
		for i, k := range keys[:n] {
			ids[i] = k.String()
		}
		keys = keys[n:]
		u := strings.TrimRight(base, "/") + "/eth/v1/beacon/states/head/validators?id=" + url.QueryEscape(strings.Join(ids, ","))
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		resp, err := cl.Do(req)
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusNotFound {
			continue // none of these keys is a validator
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("beacon node: %s", resp.Status)
		}
		var r struct {
			Data []struct {
				Status    string `json:"status"`
				Validator struct {
					Pubkey cloud.Pubkey `json:"pubkey"`
				} `json:"validator"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &r); err != nil {
			return nil, fmt.Errorf("beacon node: %w", err)
		}
		for _, d := range r.Data {
			got[d.Validator.Pubkey] = d.Status
		}
	}
	return got, nil
}

// beaconSynced reports whether the beacon node at base says it is synced
// (GET /eth/v1/node/syncing, is_syncing false). An answer that does not
// read is an error.
func beaconSynced(ctx context.Context, base string) (bool, error) {
	cl := &http.Client{Timeout: beaconTimeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/eth/v1/node/syncing", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := cl.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("beacon node syncing: %s", resp.Status)
	}
	var r struct {
		Data *struct {
			IsSyncing *bool `json:"is_syncing"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&r); err != nil {
		return false, fmt.Errorf("beacon node syncing: %w", err)
	}
	if r.Data == nil || r.Data.IsSyncing == nil {
		return false, errors.New("beacon node syncing: no is_syncing in the answer")
	}
	return !*r.Data.IsSyncing, nil
}

// checkBeacon looks up each share key and group key on the beacon node at
// base. The node must serve the setup's chain (gvr, its
// genesis_validators_root) and be synced. A share key that is a validator
// is refused: a whole validator key would go in as a share. A group key
// that is not an active validator gets a warning only, and so does a node
// that knows none of them (a new cluster may not be deposited yet). It
// reports whether the node knows a group key, so the chain backs the keys.
func checkBeacon(ctx context.Context, base string, gvr [32]byte, shares map[cloud.Pubkey]cloud.Pubkey, out io.Writer) (bool, error) {
	if gvr == ([32]byte{}) {
		return false, errors.New("-beacon: the setup's chain has no genesis_validators_root to compare the beacon node with; drop -beacon to skip the check")
	}
	got, err := beaconGenesis(ctx, base)
	if err != nil {
		return false, fmt.Errorf("-beacon: %w", err)
	}
	if got != gvr {
		return false, fmt.Errorf("-beacon: the beacon node serves another chain: genesis_validators_root 0x%x, the setup's chain has 0x%x (refusing)", got, gvr)
	}
	if synced, err := beaconSynced(ctx, base); err != nil || !synced {
		if err != nil {
			return false, fmt.Errorf("-beacon: the beacon node is not synced; drop -beacon to skip (%v)", err)
		}
		return false, errors.New("-beacon: the beacon node is not synced; drop -beacon to skip")
	}
	var keys []cloud.Pubkey
	for g, s := range shares {
		keys = append(keys, g, s)
	}
	slices.SortFunc(keys, func(a, b cloud.Pubkey) int { return strings.Compare(a.String(), b.String()) })
	known, err := beaconValidators(ctx, base, keys)
	if err != nil {
		return false, fmt.Errorf("-beacon: %w", err)
	}
	var bad []string
	for g, s := range shares {
		if st, ok := known[s]; ok {
			bad = append(bad, fmt.Sprintf("share %s of %s is itself a validator (%s)", s, g, st))
		}
	}
	if len(bad) > 0 {
		slices.Sort(bad)
		return false, fmt.Errorf("-beacon: %s: a whole validator key would go in as a share (refusing)", strings.Join(bad, "; "))
	}
	found := 0
	for g := range shares {
		if _, ok := known[g]; ok {
			found++
		}
	}
	if found == 0 {
		fprintf(out, "WARNING no group key is deposited yet (new cluster?): the beacon node, synced and on the setup's chain, knows none of the %d\n", len(shares))
	}
	warned := 0
	for _, g := range keys {
		if _, isGroup := shares[g]; !isGroup {
			continue
		}
		switch st, ok := known[g]; {
		case !ok:
			fprintf(out, "WARNING validator %s: not found on the beacon node\n", g)
			warned++
		case strings.HasSuffix(st, "_slashed"):
			fprintf(out, "WARNING validator %s: slashed (%s) on the beacon node\n", g, st)
			warned++
		case !strings.HasPrefix(st, "active_"):
			fprintf(out, "WARNING validator %s: status %s on the beacon node, not active\n", g, st)
			warned++
		}
	}
	fprintf(out, "beacon check: %d share keys are no validator; %d of %d group keys active\n", len(shares), len(shares)-warned, len(shares))
	// Confirmed only when the node knows every group key: one known key
	// says nothing about the others.
	return found == len(shares), nil
}

// The question of confirmShares reads confirmIn and prints to confirmOut,
// and is asked only when confirmTerminal says stdin is a terminal.
var (
	confirmIn       io.Reader = os.Stdin
	confirmOut      io.Writer = os.Stderr
	confirmTerminal           = func() bool {
		fi, err := os.Stdin.Stat()
		return err == nil && fi.Mode()&os.ModeCharDevice != 0
	}
)

// confirmShares asks the admin once to confirm that n keys no chain check
// backed are Charon shares, not whole validator keys. Only "y" or "yes"
// goes on; any other answer, EOF, or a stdin that is not a terminal stops.
func confirmShares(n int) error {
	if !confirmTerminal() {
		return fmt.Errorf("no chain check for these %d keys, and stdin is not a terminal to confirm them: "+
			"use -beacon with a node that knows the group keys, or -yes to confirm they are shares from a Charon cluster", n)
	}
	fmt.Fprintf(confirmOut, "No chain check for these %d keys. Confirm they are shares from a Charon cluster, not whole validator keys [y/N] ", n)
	line, err := bufio.NewReader(confirmIn).ReadString('\n')
	if a := strings.TrimSpace(line); (a == "y" || a == "yes") && (err == nil || err == io.EOF) {
		return nil
	}
	return errors.New("not confirmed that the keys are shares from a Charon cluster: no order written")
}
