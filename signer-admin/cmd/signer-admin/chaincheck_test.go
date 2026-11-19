package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/governance/runnerchain"
	cloud "github.com/lidofinance/tee-signer/signer-protocol"
)

// newDVFakeMainnet is newDVFakeBare on mainnet, a prod chain: three fake
// runners whose setups say signing_mode = dv_share, with mainnet's exact
// chain values, and the lock and split of a 3-of-4 Charon cluster.
func newDVFakeMainnet(t *testing.T) *dvFake {
	t.Helper()
	fc := newFakeClusterEdit(t, runnerchain.Mainnet, 0, "", func(s string) string {
		return onMainnet(t, strings.Replace(s, "signing_mode = threshold", "signing_mode = dv_share", 1))
	})
	c := newCharonCluster(t, 3, 3, 4)
	f := &dvFake{fc: fc, c: c, forkVersion: mainnetFork}
	f.lock = dvLockFile(t, c, fc.path("cluster-lock.json"), mainnetFork, f.lockHash, nil)
	f.split = fc.path("split.json")
	mustTool(t, "dv-split", "-lock", f.lock, "-signers", "s1=1,s2=2,s3=3", "-out", f.split)
	return f
}

// chainMaxAgeForTest is the age past which import-draft refuses a chain
// file (chainFileMaxAge).
const chainMaxAgeForTest = 24 * time.Hour

// testChainFile is the chain file of chain-export, as the tests read it.
type testChainFile struct {
	Format                string `json:"format"`
	GenesisValidatorsRoot string `json:"genesis_validators_root"`
	GenesisForkVersion    string `json:"genesis_fork_version"`
	HeadSlot              uint64 `json:"head_slot"`
	Epoch                 uint64 `json:"epoch"`
	HeadTime              string `json:"head_time"`
	Time                  string `json:"time"`
	Validators            []struct {
		Pubkey string `json:"pubkey"`
		Status string `json:"status"`
	} `json:"validators"`
}

func readTestChainFile(t *testing.T, path string) *testChainFile {
	t.Helper()
	var f testChainFile
	if err := json.Unmarshal(mustRead(t, path), &f); err != nil {
		t.Fatal(err)
	}
	return &f
}

// editChainFile rewrites the chain file at path with change applied to its
// JSON object and returns the path of the copy.
func editChainFile(t *testing.T, path, name string, change func(m map[string]any)) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(mustRead(t, path), &m); err != nil {
		t.Fatal(err)
	}
	change(m)
	return writeJSONFile(t, strings.TrimSuffix(path, ".json")+"-"+name+".json", m)
}

func mustHexRoot(t *testing.T, s string) (r [32]byte) {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil || len(b) != 32 {
		t.Fatalf("root %q", s)
	}
	copy(r[:], b)
	return r
}

// chain-export writes, for every group key and public share of the lock,
// what a synced beacon node of the chain says about it, with the chain's
// genesis values, the head slot and epoch, and the time. A node that is
// syncing writes nothing.
func TestChainExport(t *testing.T) {
	dir := t.TempDir()
	c := newCharonCluster(t, 2, 3, 4)
	lock := c.lock(t, dir+"/lock.json", nil)
	root := mustHexRoot(t, mainnetRoot)
	known := map[cloud.Pubkey]string{c.groups[0]: "active_ongoing", c.sharePub(t, 1, 2): "pending_queued"}
	var ids []string
	at := time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)
	defer func(f func() time.Time) { now = f }(now)
	now = func() time.Time { return at }
	beacon := fakeBeacon(t, root, known, &ids)

	out := dir + "/chain.json"
	res := mustTool(t, "chain-export", "-beacon", beacon.URL, "-lock", lock, "-out", out)
	wantIn(t, res, "10 keys", "wrote "+out)
	f := readTestChainFile(t, out)
	slot := fakeHeadSlot(at, 0)
	headTime := time.Unix(int64(fakeGenesisTime+slot*fakeSlotSeconds), 0).UTC().Format(time.RFC3339)
	if f.Format != "signer-admin chain-export 2" || f.GenesisValidatorsRoot != mainnetRoot || f.GenesisForkVersion != "0x00000000" ||
		f.HeadSlot != slot || f.Epoch != slot/32 || f.HeadTime != headTime || f.Time != "2026-11-19T10:00:00Z" {
		t.Fatalf("chain file header %+v, want head slot %d at %s", f, slot, headTime)
	}
	want := map[string]string{}
	for v, g := range c.groups {
		want[g.String()] = "not_found"
		for i := range 4 {
			want[c.sharePub(t, v, i).String()] = "not_found"
		}
	}
	want[c.groups[0].String()] = "active_ongoing"
	want[c.sharePub(t, 1, 2).String()] = "pending_queued"
	if len(f.Validators) != len(want) {
		t.Fatalf("%d keys in the file, want %d", len(f.Validators), len(want))
	}
	for _, v := range f.Validators {
		if want[v.Pubkey] != v.Status {
			t.Errorf("key %s: status %q, want %q", v.Pubkey, v.Status, want[v.Pubkey])
		}
	}

	syncing := fakeBeaconSync(t, root, "true", known, &ids)
	os.Remove(out)
	wantIn(t, failTool(t, "chain-export", "-beacon", syncing.URL, "-lock", lock, "-out", out), "not synced")
	if _, err := os.Stat(out); err == nil {
		t.Fatal("a syncing node's answer was written")
	}
	wantIn(t, failTool(t, "chain-export", "-lock", lock, "-out", out), "usage: signer-admin chain-export")
}

// On a prod chain import-draft for a dv_share signer needs the chain
// check: from a beacon node (-beacon) or a chain-export file
// (-chain-file). It refuses without one, also with -yes, refuses a share
// key that is a validator, and refuses when a group key is not on chain.
// The file must list every key of the order, be of the setup's chain and
// be at most chainFileMaxAge old.
func TestDVShareProdChainCheck(t *testing.T) {
	f := newDVFakeMainnet(t)
	root := mustHexRoot(t, mainnetRoot)
	c := f.c
	body := f.fc.path("import.bin")
	draft := []string{"import-draft", "-cluster", f.fc.cluster, "-signer", "s2", "-split", f.split, "-lock", f.lock, "-out", body}
	fakePrompt(t, true, "y\n")

	wantIn(t, failTool(t, draft...), "prod chain", "-beacon", "-chain-file")
	wantIn(t, failTool(t, append(draft, "-yes")...), "prod chain")
	if _, err := os.Stat(body); err == nil {
		t.Fatal("an order was written without the chain check")
	}

	var ids []string
	allGroups := map[cloud.Pubkey]string{}
	for _, g := range c.groups {
		allGroups[g] = "active_ongoing"
	}
	// Online: a node that knows every group key passes; one that misses a
	// group key, or knows a share key, is refused.
	wantIn(t, mustTool(t, append(draft, "-beacon", fakeBeacon(t, root, allGroups, &ids).URL)...), "import order for s2")
	oneMissing := map[cloud.Pubkey]string{c.groups[0]: "active_ongoing", c.groups[1]: "active_ongoing"}
	wantIn(t, failTool(t, append(draft, "-beacon", fakeBeacon(t, root, oneMissing, &ids).URL)...),
		"prod chain", "1 of 3 group keys")
	shareKnown := map[cloud.Pubkey]string{c.sharePub(t, 1, 1): "active_ongoing"}
	for g, s := range allGroups {
		shareKnown[g] = s
	}
	wantIn(t, failTool(t, append(draft, "-beacon", fakeBeacon(t, root, shareKnown, &ids).URL)...), "is itself a validator")
	hoodi := mustHexRoot(t, dvChains["hoodi"][1])
	wantIn(t, failTool(t, append(draft, "-beacon", fakeBeacon(t, hoodi, allGroups, &ids).URL)...), "another chain")

	// Offline: the file of chain-export.
	at := time.Now().UTC().Truncate(time.Second)
	chain := f.fc.path("chain.json")
	mustTool(t, "chain-export", "-beacon", fakeBeacon(t, root, allGroups, &ids).URL, "-lock", f.lock, "-out", chain)
	asked := fakePrompt(t, true, "")
	wantIn(t, mustTool(t, append(draft, "-chain-file", chain)...), "import order for s2", "3 of 3 group keys")
	if asked.Len() != 0 {
		t.Fatalf("asked with the chain file: %q", asked.String())
	}
	wantIn(t, failTool(t, append(draft, "-chain-file", chain, "-beacon", fakeBeacon(t, root, allGroups, &ids).URL)...), "one of -beacon and -chain-file")

	stale := at.Add(-chainMaxAgeForTest - time.Minute).Format(time.RFC3339)
	future := at.Add(time.Hour).Format(time.RFC3339)
	shareKey := c.sharePub(t, 2, 1).String()
	for _, x := range []struct {
		name   string
		change func(m map[string]any)
		want   string
	}{
		{"another root", func(m map[string]any) { m["genesis_validators_root"] = dvChains["hoodi"][1] }, "another chain"},
		{"another fork version", func(m map[string]any) { m["genesis_fork_version"] = "0x10000910" }, "another chain"},
		{"stale", func(m map[string]any) { m["time"] = stale }, "old"},
		{"future", func(m map[string]any) { m["time"] = future }, "after this machine's clock"},
		{"no time", func(m map[string]any) { delete(m, "time") }, "time"},
		{"a share key missing", func(m map[string]any) {
			var keep []any
			for _, v := range m["validators"].([]any) {
				if v.(map[string]any)["pubkey"] != shareKey {
					keep = append(keep, v)
				}
			}
			m["validators"] = keep
		}, "does not list " + shareKey},
		{"a group key missing", func(m map[string]any) {
			var keep []any
			for _, v := range m["validators"].([]any) {
				if v.(map[string]any)["pubkey"] != c.groups[1].String() {
					keep = append(keep, v)
				}
			}
			m["validators"] = keep
		}, "does not list " + c.groups[1].String()},
		{"a share key on chain", func(m map[string]any) {
			for _, v := range m["validators"].([]any) {
				if e := v.(map[string]any); e["pubkey"] == shareKey {
					e["status"] = "active_ongoing"
				}
			}
		}, "is itself a validator"},
		{"a group key not on chain", func(m map[string]any) {
			for _, v := range m["validators"].([]any) {
				if e := v.(map[string]any); e["pubkey"] == c.groups[2].String() {
					e["status"] = "not_found"
				}
			}
		}, "1 of 3 group keys"},
		{"format 1", func(m map[string]any) { m["format"] = "signer-admin chain-export 1"; delete(m, "head_time") }, "format"},
		{"another format", func(m map[string]any) { m["format"] = "signer-admin chain-export 3" }, "format"},
	} {
		p := editChainFile(t, chain, strings.ReplaceAll(x.name, " ", "-"), x.change)
		wantIn(t, failTool(t, append(draft, "-chain-file", p)...), x.want)
	}
}

// A non-prod chain keeps the chain check optional: no -beacon and no
// -chain-file asks once (or takes -yes), and a chain file of the chain
// passes without a question.
func TestDVShareNonProdChainCheck(t *testing.T) {
	f := newDVFakeBare(t, "hoodi")
	root := mustHexRoot(t, dvChains["hoodi"][1])
	body := f.fc.path("import.bin")
	draft := []string{"import-draft", "-cluster", f.fc.cluster, "-signer", "s2", "-split", f.split, "-lock", f.lock, "-out", body}
	fakePrompt(t, false, "")
	wantIn(t, mustTool(t, append(draft, "-yes")...), "beacon check skipped", "import order for s2")
	var ids []string
	allGroups := map[cloud.Pubkey]string{}
	for _, g := range f.c.groups {
		allGroups[g] = "active_ongoing"
	}
	chain := f.fc.path("chain.json")
	mustTool(t, "chain-export", "-beacon", fakeBeacon(t, root, allGroups, &ids).URL, "-lock", f.lock, "-out", chain)
	// The fake node says fork version 0x00000000; Hoodi's is 0x10000910.
	hoodiChain := editChainFile(t, chain, "hoodi", func(m map[string]any) { m["genesis_fork_version"] = dvChains["hoodi"][0] })
	asked := fakePrompt(t, true, "")
	wantIn(t, mustTool(t, append(draft, "-chain-file", hoodiChain)...), "import order for s2")
	if asked.Len() != 0 {
		t.Fatalf("asked with the chain file: %q", asked.String())
	}
}

// stalledNodes are beacon nodes that say is_syncing false but whose chain
// state is not current, each with the text of its refusal.
func stalledNodes(gvr [32]byte, known map[cloud.Pubkey]string, ids *[]string) []struct {
	name string
	node fakeNode
	want string
} {
	return []struct {
		name string
		node fakeNode
		want string
	}{
		{"head 16 minutes behind", fakeNode{gvr: gvr, headLag: 16 * time.Minute, known: known, ids: ids}, "behind this machine's clock"},
		{"head a day behind", fakeNode{gvr: gvr, headLag: 24 * time.Hour, known: known, ids: ids}, "behind this machine's clock"},
		{"head ahead", fakeNode{gvr: gvr, headLag: -10 * time.Minute, known: known, ids: ids}, "ahead of this machine's clock"},
		{"optimistic", fakeNode{gvr: gvr, optimistic: true, known: known, ids: ids}, "is_optimistic true"},
		{"execution client offline", fakeNode{gvr: gvr, elOffline: true, known: known, ids: ids}, "el_offline true"},
	}
}

// A node that says it is synced but whose head is more than
// chainHeadMaxLag behind the clock (or ahead of it), or that is
// optimistic or has lost its execution client, is refused at chain-export
// and at -beacon before any key is looked up. A head a few minutes
// behind passes.
func TestChainCheckStalledNode(t *testing.T) {
	f := newDVFakeMainnet(t)
	root := mustHexRoot(t, mainnetRoot)
	allGroups := map[cloud.Pubkey]string{}
	for _, g := range f.c.groups {
		allGroups[g] = "active_ongoing"
	}
	body := f.fc.path("import.bin")
	draft := []string{"import-draft", "-cluster", f.fc.cluster, "-signer", "s2", "-split", f.split, "-lock", f.lock, "-out", body}
	chain := f.fc.path("chain.json")
	var ids []string
	for _, x := range stalledNodes(root, allGroups, &ids) {
		ids = nil
		srv := fakeBeaconNode(t, x.node)
		wantIn(t, failTool(t, "chain-export", "-beacon", srv.URL, "-lock", f.lock, "-out", chain), x.want)
		if _, err := os.Stat(chain); err == nil {
			t.Fatalf("%s: chain-export wrote a file", x.name)
		}
		wantIn(t, failTool(t, append(draft, "-beacon", srv.URL)...), x.want)
		if _, err := os.Stat(body); err == nil {
			t.Fatalf("%s: import-draft wrote an order", x.name)
		}
		if len(ids) != 0 {
			t.Fatalf("%s: %d key lookups on a stalled node", x.name, len(ids))
		}
	}
	lagging := fakeBeaconNode(t, fakeNode{gvr: root, headLag: 10 * time.Minute, known: allGroups, ids: &ids})
	wantIn(t, mustTool(t, append(draft, "-beacon", lagging.URL)...), "import order for s2")
	mustTool(t, "chain-export", "-beacon", lagging.URL, "-lock", f.lock, "-out", chain)
}

// import-draft ages a chain file from the node's head time, not only from
// the export time: a file exported now from a node whose head is old is
// stale. It refuses a head time older than chainFileMaxAge, ahead of the
// clock, missing, or further behind the export time than chain-export
// allows.
func TestChainFileHeadTime(t *testing.T) {
	f := newDVFakeMainnet(t)
	root := mustHexRoot(t, mainnetRoot)
	allGroups := map[cloud.Pubkey]string{}
	for _, g := range f.c.groups {
		allGroups[g] = "active_ongoing"
	}
	body := f.fc.path("import.bin")
	draft := []string{"import-draft", "-cluster", f.fc.cluster, "-signer", "s2", "-split", f.split, "-lock", f.lock, "-out", body}
	fakePrompt(t, true, "")
	var ids []string
	chain := f.fc.path("chain.json")
	mustTool(t, "chain-export", "-beacon", fakeBeacon(t, root, allGroups, &ids).URL, "-lock", f.lock, "-out", chain)
	wantIn(t, mustTool(t, append(draft, "-chain-file", chain)...), "import order for s2")

	at := time.Now().UTC().Truncate(time.Second)
	for _, x := range []struct {
		name   string
		change func(m map[string]any)
		want   string
	}{
		{"head older than a day", func(m map[string]any) {
			m["head_time"] = at.Add(-chainMaxAgeForTest - time.Minute).Format(time.RFC3339)
		}, "chain state"},
		{"head ahead of the clock", func(m map[string]any) { m["head_time"] = at.Add(time.Hour).Format(time.RFC3339) }, "is after this machine's clock"},
		{"no head time", func(m map[string]any) { delete(m, "head_time") }, "no head_time"},
		{"head far behind the export", func(m map[string]any) {
			m["head_time"] = at.Add(-time.Hour).Format(time.RFC3339)
		}, "behind"},
	} {
		p := editChainFile(t, chain, strings.ReplaceAll(x.name, " ", "-"), x.change)
		wantIn(t, failTool(t, append(draft, "-chain-file", p)...), x.want)
	}
}

func mustHexFork(t *testing.T, s string) (v [4]byte) {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil || len(b) != 4 {
		t.Fatalf("fork version %q", s)
	}
	copy(v[:], b)
	return v
}

// On a prod chain the chain check refuses a group key that is slashed or
// exited (a cluster key no one would import), from a beacon node and from
// a chain file; active_exiting passes, and a pending key with a warning. On
// every chain it refuses a status the beacon API does not define.
func TestDVShareProdChainStatuses(t *testing.T) {
	f := newDVFakeMainnet(t)
	root := mustHexRoot(t, mainnetRoot)
	c := f.c
	body := f.fc.path("import.bin")
	draft := []string{"import-draft", "-cluster", f.fc.cluster, "-signer", "s2", "-split", f.split, "-lock", f.lock, "-out", body}
	fakePrompt(t, true, "")
	var ids []string
	withGroup1 := func(st string) map[cloud.Pubkey]string {
		m := map[cloud.Pubkey]string{}
		for _, g := range c.groups {
			m[g] = "active_ongoing"
		}
		m[c.groups[1]] = st
		return m
	}
	chain := f.fc.path("chain.json")
	t.Run("slashed or exited", func(t *testing.T) {
		for _, st := range []string{"active_slashed", "exited_unslashed", "exited_slashed", "withdrawal_possible", "withdrawal_done"} {
			wantIn(t, failTool(t, append(draft, "-beacon", fakeBeacon(t, root, withGroup1(st), &ids).URL)...),
				"slashed or exited", c.groups[1].String(), st)
			mustTool(t, "chain-export", "-beacon", fakeBeacon(t, root, withGroup1(st), &ids).URL, "-lock", f.lock, "-out", chain)
			wantIn(t, failTool(t, append(draft, "-chain-file", chain)...), "slashed or exited", c.groups[1].String(), st)
		}
		wantIn(t, mustTool(t, append(draft, "-beacon", fakeBeacon(t, root, withGroup1("active_exiting"), &ids).URL)...), "import order for s2")
		for _, st := range []string{"pending_initialized", "pending_queued"} {
			wantIn(t, mustTool(t, append(draft, "-beacon", fakeBeacon(t, root, withGroup1(st), &ids).URL)...),
				"WARNING validator "+c.groups[1].String()+": status "+st, "import order for s2")
		}
	})

	t.Run("status the beacon API does not define", func(t *testing.T) {
		wantIn(t, failTool(t, append(draft, "-beacon", fakeBeacon(t, root, withGroup1("active"), &ids).URL)...), `status "active"`, "beacon API")
		mustTool(t, "chain-export", "-beacon", fakeBeacon(t, root, withGroup1("active_ongoing"), &ids).URL, "-lock", f.lock, "-out", chain)
		shareKey := c.sharePub(t, 0, 1).String()
		for _, x := range []struct{ key, status string }{{c.groups[1].String(), "active"}, {shareKey, "unknown"}, {shareKey, "Active_ongoing"}} {
			p := editChainFile(t, chain, "status-"+x.status, func(m map[string]any) {
				for _, v := range m["validators"].([]any) {
					if e := v.(map[string]any); e["pubkey"] == x.key {
						e["status"] = x.status
					}
				}
			})
			wantIn(t, failTool(t, append(draft, "-chain-file", p)...), `status "`+x.status+`"`, "beacon API")
		}
	})
}

// -beacon compares both genesis values with the setup's chain, as the
// chain file does. On a prod chain its errors say that the check is
// required; elsewhere they say that dropping -beacon skips it.
func TestDVShareBeaconForkAndHints(t *testing.T) {
	f := newDVFakeMainnet(t)
	root := mustHexRoot(t, mainnetRoot)
	allGroups := map[cloud.Pubkey]string{}
	for _, g := range f.c.groups {
		allGroups[g] = "active_ongoing"
	}
	body := f.fc.path("import.bin")
	draft := []string{"import-draft", "-cluster", f.fc.cluster, "-signer", "s2", "-split", f.split, "-lock", f.lock, "-out", body}
	fakePrompt(t, true, "")
	var ids []string
	t.Run("fork version", func(t *testing.T) {
		ids = nil
		otherFork := fakeBeaconNode(t, fakeNode{gvr: root, fork: mustHexFork(t, hoodiFork), known: allGroups, ids: &ids})
		wantIn(t, failTool(t, append(draft, "-beacon", otherFork.URL)...), "another chain", "genesis_fork_version 0x10000910")
		if len(ids) != 0 {
			t.Fatalf("%d key lookups on a node of another fork version", len(ids))
		}
	})

	t.Run("prod chain errors", func(t *testing.T) {
		for _, x := range stalledNodes(root, allGroups, &ids) {
			out := failTool(t, append(draft, "-beacon", fakeBeaconNode(t, x.node).URL)...)
			wantIn(t, out, x.want, "the chain check is required on this chain")
			if strings.Contains(out, "drop -beacon") {
				t.Fatalf("%s: a prod chain error says to drop -beacon:\n%s", x.name, out)
			}
		}
	})

	t.Run("non-prod chain errors", func(t *testing.T) {
		h := newDVFakeBare(t, "hoodi")
		hoodi := fakeNode{gvr: mustHexRoot(t, hoodiRoot), fork: mustHexFork(t, hoodiFork), headLag: time.Hour, ids: &ids}
		hdraft := []string{"import-draft", "-cluster", h.fc.cluster, "-signer", "s2", "-split", h.split, "-lock", h.lock, "-out", h.fc.path("import.bin")}
		out := failTool(t, append(hdraft, "-beacon", fakeBeaconNode(t, hoodi).URL)...)
		wantIn(t, out, "behind this machine's clock", "drop -beacon to skip")
	})
}
