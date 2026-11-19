package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
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

// beaconGet reads the JSON answer of GET base+path into v, at most limit
// bytes. what names the request in errors.
func beaconGet(ctx context.Context, base, path, what string, limit int64, v any) error {
	cl := &http.Client{Timeout: beaconTimeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("beacon node %s: %s", what, resp.Status)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, limit)).Decode(v); err != nil {
		return fmt.Errorf("beacon node %s: %w", what, err)
	}
	return nil
}

// beaconGenesis asks the beacon node at base for its chain's
// genesis_validators_root and genesis fork version
// (GET /eth/v1/beacon/genesis).
func beaconGenesis(ctx context.Context, base string) (cloud.Root, cloud.Version, error) {
	var r struct {
		Data struct {
			Root *cloud.Root    `json:"genesis_validators_root"`
			Fork *cloud.Version `json:"genesis_fork_version"`
		} `json:"data"`
	}
	if err := beaconGet(ctx, base, "/eth/v1/beacon/genesis", "genesis", 1<<16, &r); err != nil {
		return cloud.Root{}, cloud.Version{}, err
	}
	if r.Data.Root == nil || r.Data.Fork == nil {
		return cloud.Root{}, cloud.Version{}, errors.New("beacon node genesis: no genesis_validators_root or genesis_fork_version in the answer")
	}
	return *r.Data.Root, *r.Data.Fork, nil
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

// beaconSyncing reads the beacon node's sync state at base
// (GET /eth/v1/node/syncing): whether it says it is synced (is_syncing
// false) and its head slot. An answer that does not read is an error.
func beaconSyncing(ctx context.Context, base string) (synced bool, headSlot uint64, err error) {
	var r struct {
		Data *struct {
			IsSyncing *bool  `json:"is_syncing"`
			HeadSlot  string `json:"head_slot"`
		} `json:"data"`
	}
	if err := beaconGet(ctx, base, "/eth/v1/node/syncing", "syncing", 1<<16, &r); err != nil {
		return false, 0, err
	}
	if r.Data == nil || r.Data.IsSyncing == nil {
		return false, 0, errors.New("beacon node syncing: no is_syncing in the answer")
	}
	if r.Data.HeadSlot != "" {
		if headSlot, err = strconv.ParseUint(r.Data.HeadSlot, 10, 64); err != nil {
			return false, 0, fmt.Errorf("beacon node syncing: head_slot %q", r.Data.HeadSlot)
		}
	}
	return !*r.Data.IsSyncing, headSlot, nil
}

// beaconSynced reports whether the beacon node at base says it is synced
// (beaconSyncing).
func beaconSynced(ctx context.Context, base string) (bool, error) {
	synced, _, err := beaconSyncing(ctx, base)
	return synced, err
}

// chainView is what the chain says about the keys of an order: the status
// of each key it knows as a validator. It comes from a beacon node
// (-beacon) or from a chain-export file (-chain-file). A key not in status
// is no validator.
type chainView struct {
	flag   string // the flag that gave it, for messages
	where  string // "on the beacon node", "in the chain file"
	status map[cloud.Pubkey]string
}

// orderKeys lists the group keys and share keys of shares, sorted.
func orderKeys(shares map[cloud.Pubkey]cloud.Pubkey) []cloud.Pubkey {
	var keys []cloud.Pubkey
	for g, s := range shares {
		keys = append(keys, g, s)
	}
	slices.SortFunc(keys, func(a, b cloud.Pubkey) int { return strings.Compare(a.String(), b.String()) })
	return keys
}

// beaconView looks up keys on the beacon node at base. The node must serve
// the setup's chain (gvr, its genesis_validators_root) and be synced.
func beaconView(ctx context.Context, base string, gvr [32]byte, keys []cloud.Pubkey) (*chainView, error) {
	if gvr == ([32]byte{}) {
		return nil, errors.New("-beacon: the setup's chain has no genesis_validators_root to compare the beacon node with; drop -beacon to skip the check")
	}
	got, _, err := beaconGenesis(ctx, base)
	if err != nil {
		return nil, fmt.Errorf("-beacon: %w", err)
	}
	if got != gvr {
		return nil, fmt.Errorf("-beacon: the beacon node serves another chain: genesis_validators_root %s, the setup's chain has %s (refusing)", got, cloud.Root(gvr))
	}
	if synced, err := beaconSynced(ctx, base); err != nil || !synced {
		if err != nil {
			return nil, fmt.Errorf("-beacon: the beacon node is not synced; drop -beacon to skip (%v)", err)
		}
		return nil, errors.New("-beacon: the beacon node is not synced; drop -beacon to skip")
	}
	known, err := beaconValidators(ctx, base, keys)
	if err != nil {
		return nil, fmt.Errorf("-beacon: %w", err)
	}
	return &chainView{flag: "-beacon", where: "on the beacon node", status: known}, nil
}

// check refuses a share key the chain knows as a validator: a whole
// validator key would go in as a share. A group key that is not an active
// validator gets a warning only, and so does a chain that knows none of
// them (a new cluster may not be deposited yet). It returns how many group
// keys the chain knows.
func (v *chainView) check(shares map[cloud.Pubkey]cloud.Pubkey, out io.Writer) (int, error) {
	var bad []string
	for g, s := range shares {
		if st, ok := v.status[s]; ok {
			bad = append(bad, fmt.Sprintf("share %s of %s is itself a validator (%s)", s, g, st))
		}
	}
	if len(bad) > 0 {
		slices.Sort(bad)
		return 0, fmt.Errorf("%s: %s: a whole validator key would go in as a share (refusing)", v.flag, strings.Join(bad, "; "))
	}
	found := 0
	for g := range shares {
		if _, ok := v.status[g]; ok {
			found++
		}
	}
	if found == 0 {
		fprintf(out, "WARNING no group key is deposited yet (new cluster?): the chain, %s, knows none of the %d\n", v.where, len(shares))
	}
	warned := 0
	for _, g := range orderKeys(shares) {
		if _, isGroup := shares[g]; !isGroup {
			continue
		}
		switch st, ok := v.status[g]; {
		case !ok:
			fprintf(out, "WARNING validator %s: not found %s\n", g, v.where)
			warned++
		case strings.HasSuffix(st, "_slashed"):
			fprintf(out, "WARNING validator %s: slashed (%s) %s\n", g, st, v.where)
			warned++
		case !strings.HasPrefix(st, "active_"):
			fprintf(out, "WARNING validator %s: status %s %s, not active\n", g, st, v.where)
			warned++
		}
	}
	fprintf(out, "chain check (%s): %d share keys are no validator; %d of %d group keys active\n", v.flag, len(shares), len(shares)-warned, len(shares))
	return found, nil
}

// checkBeacon is check on the beacon node at base (beaconView). It reports
// whether the node knows every group key, so the chain backs the keys:
// one known key says nothing about the others.
func checkBeacon(ctx context.Context, base string, gvr [32]byte, shares map[cloud.Pubkey]cloud.Pubkey, out io.Writer) (bool, error) {
	v, err := beaconView(ctx, base, gvr, orderKeys(shares))
	if err != nil {
		return false, err
	}
	found, err := v.check(shares, out)
	return err == nil && found == len(shares), err
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
			"use -beacon or -chain-file with chain data that knows the group keys, or -yes to confirm they are shares from a Charon cluster", n)
	}
	fmt.Fprintf(confirmOut, "No chain check for these %d keys. Confirm they are shares from a Charon cluster, not whole validator keys [y/N] ", n)
	line, err := bufio.NewReader(confirmIn).ReadString('\n')
	if a := strings.TrimSpace(line); (a == "y" || a == "yes") && (err == nil || err == io.EOF) {
		return nil
	}
	return errors.New("not confirmed that the keys are shares from a Charon cluster: no order written")
}
