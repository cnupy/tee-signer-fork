package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-core/threshold"
	cloud "github.com/lidofinance/tee-signer/signer-protocol"
)

// ---- chain-export: a beacon node's answer for the keys of a Charon lock ----
//
// On a prod chain import-draft for a dv_share signer needs the chain
// check: every group key of the order is a validator, and no share key
// is. -beacon asks a node at draft time. For a drafting machine without
// network, chain-export asks the node on a machine that has one and writes
// the answer to a file that import-draft -chain-file reads. The file
// carries public keys and their status only. The check trusts the node or
// the file; the approvers' own check of each group key stays.

// chainFileFormat names the format of a chain file. Format 1 had no
// head_time; import-draft refuses it.
const chainFileFormat = "signer-admin chain-export 2"

// chainFileMaxAge is the age past which import-draft refuses a chain file,
// counted from the node's head time (and from the export time). A key
// that became a validator after the head is not in the file, so the file
// must be recent; a day leaves time to carry it to an offline machine and
// draft there, the same working day. Export again for a later draft.
const chainFileMaxAge = 24 * time.Hour

// chainClockSkew is how far a chain file's times, or a beacon node's
// head, may be ahead of this machine's clock: two machines' clocks differ
// a little.
const chainClockSkew = 5 * time.Minute

// chainNotFound is the status of a key the beacon node does not know.
const chainNotFound = "not_found"

// chainFile is the file of chain-export.
type chainFile struct {
	Format                string        `json:"format"`
	GenesisValidatorsRoot cloud.Root    `json:"genesis_validators_root"`
	GenesisForkVersion    cloud.Version `json:"genesis_fork_version"`
	// HeadSlot and Epoch are the node's head when it answered.
	HeadSlot uint64 `json:"head_slot"`
	Epoch    uint64 `json:"epoch"`
	// HeadTime is the start of the head slot, from the node's genesis_time
	// and SECONDS_PER_SLOT, in UTC: the time of the chain state the file
	// shows.
	HeadTime time.Time `json:"head_time"`
	// Time is this machine's clock at the export, in UTC.
	Time time.Time `json:"time"`
	// Validators lists each key of the lock, every group key followed by
	// its public shares 1 to n, with the node's status for it or
	// chainNotFound.
	Validators []chainKey `json:"validators"`
}

type chainKey struct {
	Pubkey cloud.Pubkey `json:"pubkey"`
	Status string       `json:"status"`
}

func cmdChainExport(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("chain-export", flag.ContinueOnError)
	beacon := fs.String("beacon", "", "a beacon node API URL of the cluster's chain, synced")
	lockPath := fs.String("lock", "", "the Charon cluster-lock.json: each group key and public share is looked up")
	outPath := fs.String("out", "chain.json", "the chain file to write, for import-draft -chain-file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *beacon == "" || *lockPath == "" {
		return errors.New("usage: signer-admin chain-export -beacon URL -lock cluster-lock.json [-out chain.json]")
	}
	ls, err := dvSplit(*lockPath)
	if err != nil {
		return err
	}
	var keys []cloud.Pubkey
	for _, v := range ls.Validators {
		keys = append(keys, v.Pubkey)
		for i := range uint64(ls.N) {
			s, err := threshold.FeldmanEval(v.Commitments, i+1)
			if err != nil {
				return fmt.Errorf("validator %s: %w", v.Pubkey, err)
			}
			keys = append(keys, s)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), beaconTimeout*time.Duration(4+len(keys)/beaconBatch))
	defer cancel()
	g, err := beaconGenesis(ctx, *beacon)
	if err != nil {
		return err
	}
	at := now()
	head, err := beaconHead(ctx, *beacon, g, at)
	if err != nil {
		return err
	}
	known, err := beaconValidators(ctx, *beacon, keys)
	if err != nil {
		return err
	}
	f := chainFile{Format: chainFileFormat, GenesisValidatorsRoot: g.Root, GenesisForkVersion: g.Fork,
		HeadSlot: head.Slot, Epoch: head.Epoch, HeadTime: head.Time, Time: at.UTC().Truncate(time.Second)}
	found := 0
	for _, k := range keys {
		st, ok := known[k]
		if !ok {
			st = chainNotFound
		} else {
			found++
		}
		f.Validators = append(f.Validators, chainKey{Pubkey: k, Status: st})
	}
	js, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(*outPath, append(js, '\n'), 0o644); err != nil {
		return err
	}
	fprintf(out, "chain-export %s: %d keys (%d validators, %d public shares each), %d of them validators on chain; genesis_validators_root %s, genesis_fork_version 0x%x, head slot %d (epoch %d) at %s, exported %s\nwrote %s\n",
		*lockPath, len(keys), len(ls.Validators), ls.N, found, g.Root, g.Fork, f.HeadSlot, f.Epoch, f.HeadTime.Format(time.RFC3339), f.Time.Format(time.RFC3339), *outPath)
	return nil
}

// checkDVChain is the chain check of import-draft for the dv_share signer
// name on chain ch, whose order binds each group key of shares to the
// share key there. The chain data comes from the beacon node at beacon or
// from the chain file at chainFile (one of them, or none). A share key the
// chain knows as a validator is refused on every chain.
//
// On a prod chain (setupwire.ProdChain: mainnet, or genesis values no row
// of the chain table matches) the check is required and every group key
// must be a validator on chain, not slashed or exited; -yes does not
// replace it. On a non-prod
// chain it is optional: without it, or when a group key is not on chain,
// the admin confirms once (or with -yes) that the keys are Charon shares.
func checkDVChain(name string, ch *setupwire.Chain, shares map[cloud.Pubkey]cloud.Pubkey, beacon, chainFile string, yes bool, out io.Writer) error {
	prod := ch.Prod()
	if beacon != "" && chainFile != "" {
		return errors.New("-beacon and -chain-file: give one of -beacon and -chain-file")
	}
	if prod && yes {
		return fmt.Errorf("%s: -yes: on a prod chain the chain check cannot be skipped; use -beacon URL or -chain-file FILE (signer-admin chain-export)", name)
	}
	var view *chainView
	var err error
	switch {
	case beacon != "":
		view, err = beaconView(context.Background(), beacon, ch, orderKeys(shares))
	case chainFile != "":
		view, err = readChainFile(chainFile, ch, orderKeys(shares), now())
	case prod:
		return fmt.Errorf("%s: a dv_share signer on a prod chain: the chain check is required, -beacon URL or -chain-file FILE (signer-admin chain-export)", name)
	default:
		fprintf(out, "beacon check skipped (no -beacon or -chain-file): share keys not looked up as validators, group keys not checked for active\n")
	}
	if err != nil {
		return err
	}
	found := 0
	if view != nil {
		if found, err = view.check(shares, prod, out); err != nil {
			return err
		}
	}
	if found == len(shares) {
		return nil
	}
	if prod {
		return fmt.Errorf("%s: on a prod chain every group key must be a validator on chain: %d of %d group keys are not found %s (refusing; deposit first, or check the lock)",
			name, len(shares)-found, len(shares), view.where)
	}
	// Without the chain behind them the admin vouches for the keys.
	if !yes {
		return confirmShares(len(shares))
	}
	return nil
}

// readChainFile reads a chain file for an order on chain ch whose keys
// are keys, at time at. The file must be of ch (both genesis values), list
// every key, and be recent: its head time and export time at most
// chainFileMaxAge before at and at most chainClockSkew after it, and the
// head at most chainHeadMaxLag behind the export, as chain-export checks.
func readChainFile(path string, ch *setupwire.Chain, keys []cloud.Pubkey, at time.Time) (*chainView, error) {
	var f chainFile
	if err := readStrictJSON(path, &f); err != nil {
		return nil, fmt.Errorf("-chain-file: %w", err)
	}
	if f.Format != chainFileFormat {
		return nil, fmt.Errorf("-chain-file %s: format %q, want %q: export it again with this signer-admin chain-export", path, f.Format, chainFileFormat)
	}
	if ch.GenesisValidatorsRoot == (cloud.Root{}) {
		return nil, fmt.Errorf("-chain-file %s: the setup's chain has no genesis_validators_root to compare the file with", path)
	}
	if f.GenesisValidatorsRoot != ch.GenesisValidatorsRoot || f.GenesisForkVersion != ch.GenesisForkVersion {
		return nil, fmt.Errorf("-chain-file %s: the file is for another chain: genesis_validators_root %s, genesis_fork_version 0x%x; the setup's chain has %s, 0x%x (refusing)",
			path, f.GenesisValidatorsRoot, f.GenesisForkVersion, ch.GenesisValidatorsRoot, ch.GenesisForkVersion)
	}
	rfc := func(t time.Time) string { return t.UTC().Format(time.RFC3339) }
	switch {
	case f.Time.IsZero():
		return nil, fmt.Errorf("-chain-file %s: no time", path)
	case f.Time.After(at.Add(chainClockSkew)):
		return nil, fmt.Errorf("-chain-file %s: exported at %s, after this machine's clock (%s)", path, rfc(f.Time), rfc(at))
	case at.Sub(f.Time) > chainFileMaxAge:
		return nil, fmt.Errorf("-chain-file %s: exported at %s, %s old, more than %s: export it again", path, rfc(f.Time),
			at.Sub(f.Time).Truncate(time.Minute), chainFileMaxAge)
	case f.HeadTime.IsZero():
		return nil, fmt.Errorf("-chain-file %s: no head_time", path)
	case f.HeadTime.After(at.Add(chainClockSkew)):
		return nil, fmt.Errorf("-chain-file %s: head_time %s is after this machine's clock (%s)", path, rfc(f.HeadTime), rfc(at))
	case at.Sub(f.HeadTime) > chainFileMaxAge:
		return nil, fmt.Errorf("-chain-file %s: the chain state is from %s (head slot %d), %s old, more than %s: export it again from a synced node",
			path, rfc(f.HeadTime), f.HeadSlot, at.Sub(f.HeadTime).Truncate(time.Minute), chainFileMaxAge)
	case f.HeadTime.After(f.Time.Add(chainClockSkew)) || f.Time.Sub(f.HeadTime) > chainHeadMaxLag:
		return nil, fmt.Errorf("-chain-file %s: head_time %s and export time %s: chain-export takes a head at most %s behind its clock and %s ahead (refusing)",
			path, rfc(f.HeadTime), rfc(f.Time), chainHeadMaxLag, chainClockSkew)
	}
	listed := make(map[cloud.Pubkey]string, len(f.Validators))
	for _, v := range f.Validators {
		if v.Status != chainNotFound && !beaconStatuses[v.Status] {
			return nil, fmt.Errorf("-chain-file %s: key %s has status %q, not a validator status of the beacon API or %s", path, v.Pubkey, v.Status, chainNotFound)
		}
		if _, dup := listed[v.Pubkey]; dup {
			return nil, fmt.Errorf("-chain-file %s: key %s is listed twice", path, v.Pubkey)
		}
		listed[v.Pubkey] = v.Status
	}
	view := &chainView{flag: "-chain-file", where: "in the chain file", status: map[cloud.Pubkey]string{}}
	for _, k := range keys {
		st, ok := listed[k]
		if !ok {
			return nil, fmt.Errorf("-chain-file %s: the file does not list %s, a key of the order: export it from the same lock", path, k)
		}
		if st != chainNotFound {
			view.status[k] = st
		}
	}
	return view, nil
}
