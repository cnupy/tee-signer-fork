//go:build dvt

package main

// ---- Exit route of dv_share signers (build tag dvt) ----
//
// A distributed validator of an Obol Charon cluster exits with t partial
// exits, each signed with one operator's share. The Obol API collects them
// (POST /exp/partial_exits/{lock_hash}, each operator's request signed with
// its Charon ENR key), and `charon exit fetch` on each operator's Charon
// host combines t of them into the full exits that the validator ejector
// reads. An operator whose share sits in a dv_share signer makes its
// partials offline with its admin certificate:
//
//	dv-indices    online, no certificate: the validator index of each
//	              validator of the lock, from a beacon node, into a file
//	dv-exit       with the admin certificate: the signer's partial exit of
//	              each validator of a batch, signed with its share, into
//	              a file in the Obol API's form
//	dv-exit-post  on the Charon host: the file to the Obol API, signed
//	              with the ENR key (dvpost.go)

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/threshold"
	cloud "github.com/lidofinance/tee-signer/signer-protocol"
)

const (
	dvIndicesUsage  = "usage: signer-admin dv-indices -lock cluster-lock.json -beacon URL [-out indices.json]"
	dvExitUsage     = "usage: signer-admin dv-exit -cluster cluster.json -signer NAME -split split.json -lock cluster-lock.json -indices FILE|-beacon URL -pubkeys FILE|-all [-epoch E] [-yes] -out FILE|-check"
	dvExitPostUsage = "usage: signer-admin dv-exit-post -lock cluster-lock.json -enr-key FILE [-api URL] [-domain D | -fork-version V -genesis-root R] [-check|-yes] PARTIALS..."
)

func init() {
	dvtCommands = map[string]func([]string, io.Writer) error{
		"dv-indices": cmdDVIndices, "dv-exit": cmdDVExit, "dv-exit-post": cmdDVExitPost,
	}
	dvtUsage = "\n  " + strings.TrimPrefix(dvIndicesUsage, "usage: ") +
		"\n  " + strings.TrimPrefix(dvExitUsage, "usage: ") +
		"\n  " + strings.TrimPrefix(dvExitPostUsage, "usage: ")
}

// dvExitEpochs is the default exit epoch of each public network: the one
// Obol's Lido node setup gives lido-dv-exit there
// (lido-charon-distributed-validator-node, LIDODVEXIT_EXIT_EPOCH in
// .env.sample.mainnet and .env.sample.hoodi; docs.obol.org, "Exit a DV").
// Every operator of a cluster must use the same epoch: the Obol API keeps
// the first epoch it gets for a validator. Any epoch at or after Capella
// signs in the same domain (EIP-7044).
var dvExitEpochs = map[string]uint64{"mainnet": 194048, "hoodi": 256}

// exitsForGood ends the batch that dv-exit and dv-exit-post print.
const exitsForGood = "A partial exit stays valid at every later epoch, and the Obol API keeps what it gets: this cannot be taken back.\n"

// confirmExits asks q on a terminal (confirmIn, confirmOut,
// confirmTerminal of dvcheck.go) and goes on only on the answer yes. Any
// other answer, EOF, or a stdin that is not a terminal stops; done says
// what did not happen ("signed", "posted").
func confirmExits(q, done string) error {
	if !confirmTerminal() {
		return errors.New("stdin is not a terminal to confirm the batch: -yes confirms it, -check only checks it")
	}
	fmt.Fprint(confirmOut, q)
	line, err := bufio.NewReader(confirmIn).ReadString('\n')
	if strings.TrimSpace(line) == "yes" && (err == nil || err == io.EOF) {
		return nil
	}
	return errors.New("not confirmed: nothing " + done)
}

// dvLock is the part of a Charon cluster-lock.json that the exit route
// reads.
type dvLock struct {
	Definition struct {
		ForkVersion string `json:"fork_version"`
		Operators   []struct {
			ENR string `json:"enr"`
		} `json:"operators"`
	} `json:"cluster_definition"`
	Validators []struct {
		Group  cloud.Pubkey   `json:"distributed_public_key"`
		Shares []cloud.Pubkey `json:"public_shares"`
	} `json:"distributed_validators"`
	LockHash string `json:"lock_hash"`
}

// readDVLock reads the lock at path. Its lock_hash must be 32 bytes of
// hex; the tools write it as 0x and lower case hex, as Charon names it in
// the Obol API's paths. The lock's signatures and hash are not checked.
// Charon's lock_hash is the SSZ hash tree root of the whole lock, its
// definition included, in a container layout that changes with the
// lock's version field; recomputing it here would mean carrying every
// version's layout. The Obol API knows a cluster by this hash and checks
// each partial against that cluster's public shares, and dv-exit-post
// runs on the Charon host with the lock Charon runs with.
func readDVLock(path string) (*dvLock, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var l dvLock
	if err := json.Unmarshal(raw, &l); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	b, err := hex.DecodeString(strings.TrimPrefix(l.LockHash, "0x"))
	if err != nil || len(b) != 32 {
		return nil, fmt.Errorf("%s: lock_hash %q is not 32 bytes of hex", path, l.LockHash)
	}
	l.LockHash = hexOf(b)
	return &l, nil
}

// indexFile is the index file of dv-indices and dv-exit -indices: the
// body of the beacon API's GET /eth/v1/beacon/states/head/validators, of
// which only these fields are read. A saved answer of that endpoint is an
// index file.
type indexFile struct {
	Data []indexEntry `json:"data"`
}

type indexEntry struct {
	Index     string `json:"index"`
	Status    string `json:"status"`
	Validator struct {
		Pubkey cloud.Pubkey `json:"pubkey"`
	} `json:"validator"`
}

// indices maps each validator of f to its index.
func (f *indexFile) indices() (map[cloud.Pubkey]uint64, error) {
	m := map[cloud.Pubkey]uint64{}
	for _, e := range f.Data {
		i, err := strconv.ParseUint(e.Index, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("validator %s: index %q", e.Validator.Pubkey, e.Index)
		}
		if j, ok := m[e.Validator.Pubkey]; ok && j != i {
			return nil, fmt.Errorf("validator %s has two indices, %d and %d", e.Validator.Pubkey, j, i)
		}
		m[e.Validator.Pubkey] = i
	}
	return m, nil
}

// beaconChain asks the beacon node at base for its genesis fork version
// and genesis_validators_root (GET /eth/v1/beacon/genesis), and that it is
// synced.
func beaconChain(ctx context.Context, base string) (cloud.Version, cloud.Root, error) {
	var fork cloud.Version
	var gvr cloud.Root
	cl := &http.Client{Timeout: beaconTimeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/eth/v1/beacon/genesis", nil)
	if err != nil {
		return fork, gvr, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := cl.Do(req)
	if err != nil {
		return fork, gvr, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fork, gvr, fmt.Errorf("beacon node genesis: %s", resp.Status)
	}
	var r struct {
		Data struct {
			Root cloud.Root    `json:"genesis_validators_root"`
			Fork cloud.Version `json:"genesis_fork_version"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&r); err != nil {
		return fork, gvr, fmt.Errorf("beacon node genesis: %w", err)
	}
	synced, err := beaconSynced(ctx, base)
	if err != nil {
		return fork, gvr, err
	}
	if !synced {
		return fork, gvr, errors.New("the beacon node is syncing")
	}
	return r.Data.Fork, r.Data.Root, nil
}

// beaconIndices asks the beacon node at base for the validators with these
// keys (GET /eth/v1/beacon/states/head/validators?id=...), beaconBatch keys
// per request, and returns the ones it knows in the index file's form.
func beaconIndices(ctx context.Context, base string, keys []cloud.Pubkey) (*indexFile, error) {
	cl := &http.Client{Timeout: beaconTimeout}
	f := &indexFile{Data: []indexEntry{}}
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
		var r indexFile
		if err := json.Unmarshal(body, &r); err != nil {
			return nil, fmt.Errorf("beacon node: %w", err)
		}
		f.Data = append(f.Data, r.Data...)
	}
	return f, nil
}

func cmdDVIndices(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("dv-indices", flag.ContinueOnError)
	lockPath := fs.String("lock", "", "the Charon cluster-lock.json")
	beacon := fs.String("beacon", "", "a beacon node API of the lock's chain")
	outPath := fs.String("out", "indices.json", "the index file to write, for dv-exit -indices")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *lockPath == "" || *beacon == "" {
		return errors.New(dvIndicesUsage)
	}
	l, err := readDVLock(*lockPath)
	if err != nil {
		return err
	}
	var want cloud.Version
	if err := want.UnmarshalText([]byte(l.Definition.ForkVersion)); err != nil {
		return fmt.Errorf("%s: fork_version %q: %w", *lockPath, l.Definition.ForkVersion, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*beaconTimeout)
	defer cancel()
	fork, _, err := beaconChain(ctx, *beacon)
	if err != nil {
		return fmt.Errorf("-beacon: %w", err)
	}
	if fork != want {
		return fmt.Errorf("-beacon: the node's genesis fork version is %s, the lock's fork_version %s: another chain", hexOf(fork[:]), hexOf(want[:]))
	}
	keys := make([]cloud.Pubkey, len(l.Validators))
	for i, v := range l.Validators {
		keys[i] = v.Group
	}
	ctx, cancel = context.WithTimeout(context.Background(), beaconTimeout*time.Duration(1+len(keys)/beaconBatch))
	defer cancel()
	f, err := beaconIndices(ctx, *beacon, keys)
	if err != nil {
		return fmt.Errorf("-beacon: %w", err)
	}
	got, err := f.indices()
	if err != nil {
		return fmt.Errorf("-beacon: %w", err)
	}
	// Only the lock's validators, in the lock's order.
	kept := &indexFile{Data: []indexEntry{}}
	var missing []string
	for _, k := range keys {
		i, ok := got[k]
		if !ok {
			missing = append(missing, k.String())
			continue
		}
		e := indexEntry{Index: strconv.FormatUint(i, 10)}
		for _, d := range f.Data {
			if d.Validator.Pubkey == k {
				e.Status = d.Status
			}
		}
		e.Validator.Pubkey = k
		kept.Data = append(kept.Data, e)
	}
	if len(kept.Data) == 0 {
		return fmt.Errorf("no validator of %s has an index yet (not deposited, or not seen by the beacon node); nothing written", *lockPath)
	}
	raw, err := json.MarshalIndent(kept, "", "  ")
	if err != nil {
		return err
	}
	if err := writeAtomic(*outPath, append(raw, '\n'), 0o644); err != nil {
		return err
	}
	fprintf(out, "%d of %d validators of %s have an index\n", len(kept.Data), len(keys), *lockPath)
	for _, k := range missing {
		fprintf(out, "no index yet: %s\n", k)
	}
	fprintf(out, "wrote %s\n", *outPath)
	return nil
}

// dvPartialFile is the file of dv-exit: one signer's partial exits in the
// Obol API's form (partial_exits, share_idx), with the lock hash and the
// chain values of the signing domain, which dv-exit-post checks. It holds
// nothing secret.
type dvPartialFile struct {
	LockHash                 string            `json:"lock_hash"`
	ShareIdx                 uint64            `json:"share_idx"`
	Signer                   string            `json:"signer"`
	VoluntaryExitForkVersion cloud.Version     `json:"voluntary_exit_fork_version"`
	GenesisValidatorsRoot    cloud.Root        `json:"genesis_validators_root"`
	PartialExits             []obolPartialExit `json:"partial_exits"`
}

// obolPartialExit is one item of the Obol API's partial_exits: the group
// key and the exit with the share's partial signature.
type obolPartialExit struct {
	PublicKey         cloud.Pubkey `json:"public_key"`
	SignedExitMessage exitJSON     `json:"signed_exit_message"`
}

// message is the exit e names.
func (e *obolPartialExit) message() (*cloud.VoluntaryExit, error) {
	epoch, err := strconv.ParseUint(e.SignedExitMessage.Message.Epoch, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("partial exit of %s: epoch %q", e.PublicKey, e.SignedExitMessage.Message.Epoch)
	}
	index, err := strconv.ParseUint(e.SignedExitMessage.Message.ValidatorIndex, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("partial exit of %s: validator_index %q", e.PublicKey, e.SignedExitMessage.Message.ValidatorIndex)
	}
	return &cloud.VoluntaryExit{Epoch: epoch, ValidatorIndex: index}, nil
}

// readKeyList reads a file of one 0x key per line; empty lines and lines
// that start with # are left out.
func readKeyList(path string) ([]cloud.Pubkey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var keys []cloud.Pubkey
	seen := map[cloud.Pubkey]bool{}
	for n, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var pk cloud.Pubkey
		if err := pk.UnmarshalText([]byte(line)); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, n+1, err)
		}
		if seen[pk] {
			return nil, fmt.Errorf("%s:%d: %s is named twice", path, n+1, pk)
		}
		seen[pk] = true
		keys = append(keys, pk)
	}
	return keys, nil
}

// wrongKind is the refusal of a batch key that is no validator of the
// split: when it is a share key of one, it names the share index and the
// group key.
func wrongKind(split *splitFile, lockPath string, pk cloud.Pubkey) error {
	for _, v := range split.Validators {
		for i := uint64(1); i <= uint64(split.N); i++ {
			if s, err := threshold.FeldmanEval(v.Commitments, i); err == nil && s == pk {
				return fmt.Errorf("%s is share %d of validator %s: name each validator by its group key (distributed_public_key)", pk, i, v.Pubkey)
			}
		}
	}
	return fmt.Errorf("%s is not a validator of %s", pk, lockPath)
}

func cmdDVExit(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("dv-exit", flag.ContinueOnError)
	clusterPath := fs.String("cluster", "", "cluster.json: the cloud.json and the setup of each signer")
	name := fs.String("signer", "", "the dv_share signer of cluster.json that signs, with this admin certificate")
	timeout := fs.Duration("timeout", 30*time.Second, "time allowed for each request to the signer")
	splitPath := fs.String("split", "", "the split file of dv-split, for the signer's share index")
	lockPath := fs.String("lock", "", "the Charon cluster-lock.json of the split")
	indicesPath := fs.String("indices", "", "the index file of dv-indices, or a saved answer of the beacon API's validators endpoint")
	beacon := fs.String("beacon", "", "a beacon node API of the signer's chain, instead of -indices")
	pubkeysPath := fs.String("pubkeys", "", "the validators of the batch, one group key per line")
	all := fs.Bool("all", false, "the batch is every validator of the lock, instead of -pubkeys")
	epochArg := fs.String("epoch", "", "the exit epoch, the same for every operator of the cluster (default: 194048 on mainnet, 256 on hoodi)")
	outPath := fs.String("out", "", "the file to write, for dv-exit-post")
	yes := fs.Bool("yes", false, "sign the batch without the question, for scripts")
	check := fs.Bool("check", false, "run every check and print the batch; sign and write nothing")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *clusterPath == "" || *name == "" || *splitPath == "" || *lockPath == "" || *outPath == "" && !*check ||
		(*indicesPath == "") == (*beacon == "") {
		return errors.New(dvExitUsage)
	}
	// A partial exit stays valid for good: the batch is named, never
	// implied.
	switch {
	case *pubkeysPath != "" && *all:
		return errors.New("-pubkeys and -all: give one of them")
	case *pubkeysPath == "" && !*all:
		return fmt.Errorf("name the batch: -pubkeys FILE, or -all for every validator of %s", *lockPath)
	}

	// The signer's share index, and its share key of each validator.
	split, err := readSplit(*splitPath)
	if err != nil {
		return err
	}
	idx, ok := split.Shares[*name]
	if !ok {
		return fmt.Errorf("%s has no share index in %s", *name, *splitPath)
	}
	shares, err := checkLockSplit(split, *lockPath, idx)
	if err != nil {
		return err
	}
	lock, err := readDVLock(*lockPath)
	if err != nil {
		return err
	}
	var batch []cloud.Pubkey
	if *pubkeysPath != "" {
		if batch, err = readKeyList(*pubkeysPath); err != nil {
			return err
		}
		if len(batch) == 0 {
			return fmt.Errorf("%s names no validator", *pubkeysPath)
		}
	} else {
		for _, v := range split.Validators {
			batch = append(batch, v.Pubkey)
		}
	}
	for _, pk := range batch {
		if _, ok := shares[pk]; !ok {
			return wrongKind(split, *lockPath, pk)
		}
	}

	c, err := loadCluster(*clusterPath, []string{*name})
	if err != nil {
		return err
	}
	m := c.members[0]
	if mode := m.setup.SigningMode; mode != setupwire.SigningModeDVShare {
		return fmt.Errorf("the setup of %s says signing_mode = %s; dv-exit needs signing_mode = dv_share", m.name, mode)
	}
	ch := m.setup.Chain
	var epoch uint64
	note := ""
	if *epochArg != "" {
		if epoch, err = strconv.ParseUint(*epochArg, 10, 64); err != nil {
			return fmt.Errorf("-epoch: %w", err)
		}
	} else {
		net, exact := setupwire.PublicNetwork(ch.GenesisForkVersion, ch.GenesisValidatorsRoot)
		e, ok := dvExitEpochs[net]
		if !exact || !ok {
			return errors.New("no default exit epoch for this chain; give -epoch (every operator of the cluster must use the same one)")
		}
		epoch, note = e, " (the default on "+net+")"
	}

	// The index of each validator of the batch, all of them before any
	// signature.
	var index map[cloud.Pubkey]uint64
	from := *indicesPath
	if *indicesPath != "" {
		var f indexFile
		raw, err := os.ReadFile(*indicesPath)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(raw, &f); err != nil {
			return fmt.Errorf("%s: %w", *indicesPath, err)
		}
		if index, err = f.indices(); err != nil {
			return fmt.Errorf("%s: %w", *indicesPath, err)
		}
	} else {
		from = "the beacon node " + *beacon
		ctx, cancel := context.WithTimeout(context.Background(), beaconTimeout*time.Duration(2+len(batch)/beaconBatch))
		defer cancel()
		_, gvr, err := beaconChain(ctx, *beacon)
		if err != nil {
			return fmt.Errorf("-beacon: %w", err)
		}
		if gvr != ch.GenesisValidatorsRoot {
			return fmt.Errorf("-beacon: the node's genesis_validators_root is %s, the setup's %s: another chain", gvr, ch.GenesisValidatorsRoot)
		}
		f, err := beaconIndices(ctx, *beacon, batch)
		if err != nil {
			return fmt.Errorf("-beacon: %w", err)
		}
		if index, err = f.indices(); err != nil {
			return fmt.Errorf("-beacon: %w", err)
		}
	}
	for _, pk := range batch {
		if _, ok := index[pk]; !ok {
			return fmt.Errorf("validator %s has no index in %s (not deposited yet?); leave it out with -pubkeys", pk, from)
		}
	}
	sort.SliceStable(batch, func(i, j int) bool { return index[batch[i]] < index[batch[j]] })

	cl, err := connectAdmin(m, *timeout)
	if err != nil {
		return fmt.Errorf("%s: %w", m.name, err)
	}
	defer cl.Close()
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	keys, err := cl.PublicKeys(ctx)
	cancel()
	if err != nil {
		return fmt.Errorf("%s: public keys: %w", m.name, err)
	}
	// A dv_share signer lists each share under the share's own key.
	listed := map[cloud.Pubkey]cloud.ValidatorKey{}
	for _, k := range keys {
		listed[k.Pubkey] = k
	}
	for _, g := range batch {
		sk := shares[g]
		if k, ok := listed[sk]; ok && k.SharePubkey == sk {
			continue
		}
		if _, ok := listed[g]; ok {
			return fmt.Errorf("%s lists validator %s under its group key, not under share %d %s: it is no dv_share signer", m.name, g, idx, sk)
		}
		return fmt.Errorf("%s does not hold share %d %s of validator %s", m.name, idx, sk, g)
	}

	// Every check passed: the batch, then -check, -yes or the question.
	net, exact := setupwire.PublicNetwork(ch.GenesisForkVersion, ch.GenesisValidatorsRoot)
	if !exact {
		net = "no public network"
	}
	fprintf(out, "dv-exit batch: %d partial exits, signer %s (share_idx %d), epoch %d%s, lock_hash %s\n",
		len(batch), m.name, idx, epoch, note, lock.LockHash)
	fprintf(out, "chain: %s, genesis_validators_root %s, voluntary_exit_fork_version %s\n",
		net, ch.GenesisValidatorsRoot, hexOf(ch.VoluntaryExitForkVersion[:]))
	for _, g := range batch {
		fprintf(out, "  validator index %d %s\n", index[g], g)
	}
	fprintf(out, "%s", exitsForGood)
	if *check {
		fprintf(out, "-check: every check passed; nothing signed, nothing written\n")
		return nil
	}
	if !*yes {
		if err := confirmExits(fmt.Sprintf("Type yes to sign these %d partial exits: ", len(batch)), "signed"); err != nil {
			return err
		}
		// The answer may come after the runner closed the idle connection
		// the checks ran on. Close it: the first SIGN dials a new one, with
		// the TLS key and attestation checks of the first.
		cl.Close()
	}

	file := dvPartialFile{LockHash: lock.LockHash, ShareIdx: uint64(idx), Signer: m.name,
		VoluntaryExitForkVersion: ch.VoluntaryExitForkVersion, GenesisValidatorsRoot: ch.GenesisValidatorsRoot,
		PartialExits: []obolPartialExit{}}
	failed := false
	for _, g := range batch {
		sk, msg := shares[g], &cloud.VoluntaryExit{Epoch: epoch, ValidatorIndex: index[g]}
		domain, root, err := exitRoot(msg, ch.VoluntaryExitForkVersion, ch.GenesisValidatorsRoot)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), *timeout)
		sig, err := cl.Sign(ctx, cloud.SignRequest{Pubkey: sk, Message: msg, Domain: domain})
		cancel()
		if err == nil && !core.Verify(sk, root, sig) {
			err = errors.New("the partial signature does not verify under the share key")
		}
		if err != nil {
			fprintf(out, "%s: validator %s (index %d): %v\n", m.name, g, msg.ValidatorIndex, err)
			failed = true
			continue
		}
		e := obolPartialExit{PublicKey: g}
		e.SignedExitMessage.Message.Epoch = strconv.FormatUint(epoch, 10)
		e.SignedExitMessage.Message.ValidatorIndex = strconv.FormatUint(msg.ValidatorIndex, 10)
		e.SignedExitMessage.Signature = hexOf(sig[:])
		file.PartialExits = append(file.PartialExits, e)
	}
	if len(file.PartialExits) == 0 {
		return errors.New("no partial exit verifies; nothing written")
	}
	raw, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	if err := writeAtomic(*outPath, append(raw, '\n'), 0o644); err != nil {
		return err
	}
	fprintf(out, "%d partial exits of %s (share_idx %d), epoch %d%s, lock_hash %s; each verifies under its share key\nwrote %s\n",
		len(file.PartialExits), m.name, idx, epoch, note, lock.LockHash, *outPath)
	if failed {
		return errReported
	}
	return nil
}
