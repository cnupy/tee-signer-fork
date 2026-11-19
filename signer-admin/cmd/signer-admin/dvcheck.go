package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/lidofinance/tee-signer/governance/setupwire"
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

// nodeGenesis is a beacon node's answer to GET /eth/v1/beacon/genesis.
type nodeGenesis struct {
	Root cloud.Root
	Fork cloud.Version
	Time uint64 // genesis_time, in Unix seconds
}

// beaconGenesis asks the beacon node at base for its chain's
// genesis_validators_root, genesis fork version and genesis time.
func beaconGenesis(ctx context.Context, base string) (*nodeGenesis, error) {
	var r struct {
		Data struct {
			Time string         `json:"genesis_time"`
			Root *cloud.Root    `json:"genesis_validators_root"`
			Fork *cloud.Version `json:"genesis_fork_version"`
		} `json:"data"`
	}
	if err := beaconGet(ctx, base, "/eth/v1/beacon/genesis", "genesis", 1<<16, &r); err != nil {
		return nil, err
	}
	if r.Data.Root == nil || r.Data.Fork == nil || r.Data.Time == "" {
		return nil, errors.New("beacon node genesis: no genesis_time, genesis_validators_root or genesis_fork_version in the answer")
	}
	t, err := strconv.ParseUint(r.Data.Time, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("beacon node genesis: genesis_time %q", r.Data.Time)
	}
	return &nodeGenesis{Root: *r.Data.Root, Fork: *r.Data.Fork, Time: t}, nil
}

// beaconSpec reads SECONDS_PER_SLOT and SLOTS_PER_EPOCH from the beacon
// node at base (GET /eth/v1/config/spec). Neither may be 0.
func beaconSpec(ctx context.Context, base string) (secondsPerSlot, slotsPerEpoch uint64, err error) {
	var spec struct {
		Data struct {
			SecondsPerSlot string `json:"SECONDS_PER_SLOT"`
			SlotsPerEpoch  string `json:"SLOTS_PER_EPOCH"`
		} `json:"data"`
	}
	if err := beaconGet(ctx, base, "/eth/v1/config/spec", "spec", 1<<20, &spec); err != nil {
		return 0, 0, err
	}
	if secondsPerSlot, err = strconv.ParseUint(spec.Data.SecondsPerSlot, 10, 64); err != nil || secondsPerSlot == 0 {
		return 0, 0, fmt.Errorf("beacon node spec: SECONDS_PER_SLOT %q", spec.Data.SecondsPerSlot)
	}
	if slotsPerEpoch, err = strconv.ParseUint(spec.Data.SlotsPerEpoch, 10, 64); err != nil || slotsPerEpoch == 0 {
		return 0, 0, fmt.Errorf("beacon node spec: SLOTS_PER_EPOCH %q", spec.Data.SlotsPerEpoch)
	}
	return secondsPerSlot, slotsPerEpoch, nil
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
		// Only a 200 answers: it leaves out the keys the node does not know.
		// A 404 here is "state not found", not "no such validator".
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("beacon node: the validators endpoint answered %s, not 200 OK", resp.Status)
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
			if !beaconStatuses[d.Status] {
				return nil, fmt.Errorf("beacon node: validator %s has status %q, not a validator status of the beacon API", d.Validator.Pubkey, d.Status)
			}
			got[d.Validator.Pubkey] = d.Status
		}
	}
	return got, nil
}

// beaconStatuses are the validator statuses of the beacon API
// (/eth/v1/beacon/states/{state_id}/validators). The chain check refuses
// any other text, from a node or in a chain file.
var beaconStatuses = map[string]bool{
	"pending_initialized": true, "pending_queued": true,
	"active_ongoing": true, "active_exiting": true, "active_slashed": true,
	"exited_unslashed": true, "exited_slashed": true,
	"withdrawal_possible": true, "withdrawal_done": true,
}

// statusGone reports whether a validator of status st is slashed or has
// exited: no cluster would import its key. active_exiting is not gone:
// it still attests until its exit epoch.
func statusGone(st string) bool {
	switch st {
	case "active_slashed", "exited_unslashed", "exited_slashed", "withdrawal_possible", "withdrawal_done":
		return true
	}
	return false
}

// nodeSync is a beacon node's answer to GET /eth/v1/node/syncing. A field
// the node leaves out is nil or empty.
type nodeSync struct {
	IsSyncing    *bool  `json:"is_syncing"`
	IsOptimistic *bool  `json:"is_optimistic"`
	ELOffline    *bool  `json:"el_offline"`
	HeadSlot     string `json:"head_slot"`
}

// beaconSyncing reads the beacon node's sync state at base. An answer that
// does not read, or has no is_syncing, is an error.
func beaconSyncing(ctx context.Context, base string) (*nodeSync, error) {
	var r struct {
		Data *nodeSync `json:"data"`
	}
	if err := beaconGet(ctx, base, "/eth/v1/node/syncing", "syncing", 1<<16, &r); err != nil {
		return nil, err
	}
	if r.Data == nil || r.Data.IsSyncing == nil {
		return nil, errors.New("beacon node syncing: no is_syncing in the answer")
	}
	return r.Data, nil
}

// beaconSynced reports whether the beacon node at base says it is synced:
// is_syncing false (beaconSyncing).
func beaconSynced(ctx context.Context, base string) (bool, error) {
	s, err := beaconSyncing(ctx, base)
	if err != nil {
		return false, err
	}
	return !*s.IsSyncing, nil
}

// chainHeadMaxLag is how far the start of a beacon node's head slot may
// be behind this machine's clock for the chain check. A synced node's
// head is the current slot, or a few slots back after missed blocks. 15
// minutes (75 slots of 12 s, over two epochs) lets through a run of
// missed blocks and a small difference between the node's clock and this
// machine's. A node further behind has lost its peers or its execution
// client while it may still say is_syncing false, and does not know the
// validators deposited since its head.
const chainHeadMaxLag = 15 * time.Minute

// chainHead is the head of a beacon node that passed beaconHead.
type chainHead struct {
	Slot  uint64
	Epoch uint64
	Time  time.Time // the start of the head slot, in UTC
}

// beaconHead reads the head of the beacon node at base, whose genesis is
// g, and checks that the node is current at time at: is_syncing,
// is_optimistic and el_offline false, and the head slot, timed from
// genesis_time and SECONDS_PER_SLOT, starting at most chainHeadMaxLag
// before at and at most chainClockSkew after it. Each refusal of the
// node's state starts with "the beacon node is not synced".
func beaconHead(ctx context.Context, base string, g *nodeGenesis, at time.Time) (*chainHead, error) {
	s, err := beaconSyncing(ctx, base)
	if err != nil {
		return nil, fmt.Errorf("the beacon node is not synced: %w", err)
	}
	const notSynced = "the beacon node is not synced: "
	switch {
	case *s.IsSyncing:
		return nil, errors.New(notSynced + "is_syncing true")
	case s.IsOptimistic == nil:
		return nil, errors.New(notSynced + "no is_optimistic in its syncing answer")
	case *s.IsOptimistic:
		return nil, errors.New(notSynced + "is_optimistic true, its execution client has not verified the head")
	case s.ELOffline == nil:
		return nil, errors.New(notSynced + "no el_offline in its syncing answer")
	case *s.ELOffline:
		return nil, errors.New(notSynced + "el_offline true, its execution client is offline")
	case s.HeadSlot == "":
		return nil, errors.New(notSynced + "no head_slot in its syncing answer")
	}
	slot, err := strconv.ParseUint(s.HeadSlot, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("beacon node syncing: head_slot %q", s.HeadSlot)
	}
	sps, spe, err := beaconSpec(ctx, base)
	if err != nil {
		return nil, err
	}
	if g.Time > math.MaxInt64 || slot > (math.MaxInt64-g.Time)/sps {
		return nil, fmt.Errorf("beacon node: head slot %d at genesis_time %d is out of range", slot, g.Time)
	}
	h := &chainHead{Slot: slot, Epoch: slot / spe, Time: time.Unix(int64(g.Time+slot*sps), 0).UTC()}
	switch lag := at.Sub(h.Time); {
	case lag > chainHeadMaxLag:
		return nil, fmt.Errorf(notSynced+"its head, slot %d, started at %s, %s behind this machine's clock (%s), more than %s",
			slot, h.Time.Format(time.RFC3339), lag.Truncate(time.Second), at.UTC().Format(time.RFC3339), chainHeadMaxLag)
	case -lag > chainClockSkew:
		return nil, fmt.Errorf("the beacon node's head, slot %d, starts at %s, ahead of this machine's clock (%s) by more than %s: check both clocks",
			slot, h.Time.Format(time.RFC3339), at.UTC().Format(time.RFC3339), chainClockSkew)
	}
	return h, nil
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

// beaconHint ends a -beacon error that a node, not the keys, caused. On a
// prod chain the check cannot be skipped, so it does not say to drop
// -beacon.
func beaconHint(prod bool) string {
	if prod {
		return "the chain check is required on this chain: use a synced node of the chain, or -chain-file FILE (signer-admin chain-export)"
	}
	return "drop -beacon to skip the check"
}

// beaconView looks up keys on the beacon node at base. The node must serve
// the setup's chain ch (both genesis values) and be current (beaconHead).
func beaconView(ctx context.Context, base string, ch *setupwire.Chain, keys []cloud.Pubkey) (*chainView, error) {
	hint := beaconHint(ch.Prod())
	if ch.GenesisValidatorsRoot == (cloud.Root{}) {
		return nil, fmt.Errorf("-beacon: the setup's chain has no genesis_validators_root to compare the beacon node with; %s", hint)
	}
	g, err := beaconGenesis(ctx, base)
	if err != nil {
		return nil, fmt.Errorf("-beacon: %w", err)
	}
	if g.Root != ch.GenesisValidatorsRoot || g.Fork != ch.GenesisForkVersion {
		return nil, fmt.Errorf("-beacon: the beacon node serves another chain: genesis_validators_root %s, genesis_fork_version 0x%x; the setup's chain has %s, 0x%x (refusing)",
			g.Root, g.Fork, ch.GenesisValidatorsRoot, ch.GenesisForkVersion)
	}
	if _, err := beaconHead(ctx, base, g, now()); err != nil {
		return nil, fmt.Errorf("-beacon: %v; %s", err, hint)
	}
	known, err := beaconValidators(ctx, base, keys)
	if err != nil {
		return nil, fmt.Errorf("-beacon: %w", err)
	}
	return &chainView{flag: "-beacon", where: "on the beacon node", status: known}, nil
}

// check refuses a share key the chain knows as a validator: a whole
// validator key would go in as a share. On a prod chain it also refuses a
// group key that is slashed or exited (statusGone). Elsewhere such a key,
// and any group key that is not an active validator, gets a warning only,
// and so does a chain that knows none of them (a new cluster may not be
// deposited yet). It returns how many group keys the chain knows.
func (v *chainView) check(shares map[cloud.Pubkey]cloud.Pubkey, prod bool, out io.Writer) (int, error) {
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
	if prod {
		for g := range shares {
			if st := v.status[g]; statusGone(st) {
				bad = append(bad, fmt.Sprintf("validator %s is %s %s", g, st, v.where))
			}
		}
		if len(bad) > 0 {
			slices.Sort(bad)
			return 0, fmt.Errorf("%s: %s: on a prod chain a group key that is slashed or exited is not imported (refusing)", v.flag, strings.Join(bad, "; "))
		}
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

// checkBeacon is check on the beacon node at base for chain ch
// (beaconView). It reports whether the node knows every group key, so the
// chain backs the keys: one known key says nothing about the others.
func checkBeacon(ctx context.Context, base string, ch *setupwire.Chain, shares map[cloud.Pubkey]cloud.Pubkey, out io.Writer) (bool, error) {
	v, err := beaconView(ctx, base, ch, orderKeys(shares))
	if err != nil {
		return false, err
	}
	found, err := v.check(shares, ch.Prod(), out)
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
