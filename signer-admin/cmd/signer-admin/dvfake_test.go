package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/runnerchain"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	cloud "github.com/lidofinance/tee-signer/signer-protocol"
)

// dvChains are the chains of the dv_share fake clusters: genesis fork
// version, genesis validators root and voluntary exit fork version.
// ci-test is setupText's chain; hoodi has Hoodi's values
// (governance/chains/hoodi.json).
var dvChains = map[string][3]string{
	"ci-test": {"0x00000001", "0x4b36000000000000000000000000000000000000000000000000000000000000", "0x04000010"},
	"hoodi":   {"0x10000910", "0x212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f", "0x40000910"},
}

// dvFake is three fake runners s1, s2 and s3 whose setups say
// signing_mode = dv_share. Runner si holds share i of each of three
// validators of a Charon cluster (3 of 4) under the share's own key, with
// validator index 100 + v, as a dv_share runner lists it. lock is the
// cluster lock and split the dv-split file of s1=1, s2=2, s3=3.
type dvFake struct {
	fc          *fakeCluster
	c           *charonCluster
	cfg         core.Config
	lock, split string
	lockHash    [32]byte
	forkVersion string // the chain's genesis fork version, the lock's definition.fork_version
	index       map[cloud.Pubkey]uint64
}

func newDVFake(t *testing.T, chain string) *dvFake {
	t.Helper()
	f := newDVFakeBare(t, chain)
	for i, name := range names {
		s, err := core.NewSigner(f.cfg, 16, 0, software.NewMemHooks())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Close)
		for v := range f.c.groups {
			k, err := s.AddValidator(f.c.sharePub(t, v, i), f.c.secrets[v][i], uint64(100+v), nil)
			if err != nil {
				t.Fatal(err)
			}
			f.fc.runners[name].SetSigner(k, s.Sign)
		}
	}
	return f
}

// newDVFakeBare is newDVFake with runners that hold no key.
func newDVFakeBare(t *testing.T, chain string) *dvFake {
	t.Helper()
	ch := dvChains[chain]
	fc := newFakeClusterEdit(t, runnerchain.Mainnet, 0, "", func(s string) string {
		for _, r := range [][2]string{
			{"signing_mode = threshold", "signing_mode = dv_share"},
			{"genesis_fork_version = " + dvChains["ci-test"][0], "genesis_fork_version = " + ch[0]},
			{"genesis_validators_root = " + dvChains["ci-test"][1], "genesis_validators_root = " + ch[1]},
			{"voluntary_exit_fork_version = " + dvChains["ci-test"][2], "voluntary_exit_fork_version = " + ch[2]},
		} {
			s = strings.Replace(s, r[0], r[1], 1)
		}
		return s
	})
	c := newCharonCluster(t, 3, 3, 4)
	f := &dvFake{fc: fc, c: c, forkVersion: ch[0], index: map[cloud.Pubkey]uint64{}}
	if _, err := rand.Read(f.lockHash[:]); err != nil {
		t.Fatal(err)
	}
	f.lock = dvLockFile(t, c, fc.path("cluster-lock.json"), ch[0], f.lockHash, nil)
	f.split = fc.path("split.json")
	mustTool(t, "dv-split", "-lock", f.lock, "-signers", "s1=1,s2=2,s3=3", "-out", f.split)

	f.cfg = software.DevConfig(uint64(genesisTime()), secondsPerSlot, slotsPerEpoch)
	copy(f.cfg.GenesisValidatorsRoot[:], mustHex(t, ch[1]))
	copy(f.cfg.VoluntaryExitForkVersion[:], mustHex(t, ch[2]))
	for v, g := range c.groups {
		f.index[g] = uint64(100 + v)
	}
	return f
}

// exitRoot is the signing root of the exit (epoch, index) on f's chain:
// the voluntary exit fork version's domain (EIP-7044).
func (f *dvFake) exitRoot(epoch, index uint64) cloud.Root {
	domain := cloud.ComputeDomain(cloud.DomainVoluntaryExit, f.cfg.VoluntaryExitForkVersion, f.cfg.GenesisValidatorsRoot)
	obj, _ := cloud.HashTreeRoot(&cloud.VoluntaryExit{Epoch: epoch, ValidatorIndex: index})
	return cloud.SigningRoot(obj, domain)
}

// checkExitFile checks that the beacon API body at path is the exit of
// validator v at epoch and verifies under its group key.
func (f *dvFake) checkExitFile(t *testing.T, path string, v int, epoch uint64) {
	t.Helper()
	var body exitJSON
	if err := json.Unmarshal(mustRead(t, path), &body); err != nil {
		t.Fatal(err)
	}
	var sig cloud.Signature
	if err := sig.UnmarshalText([]byte(body.Signature)); err != nil {
		t.Fatal(err)
	}
	idx := f.index[f.c.groups[v]]
	if body.Message.Epoch != uitoa(epoch) || body.Message.ValidatorIndex != uitoa(idx) {
		t.Fatalf("exit body %+v, want epoch %d index %d", body, epoch, idx)
	}
	if !core.Verify(f.c.groups[v], f.exitRoot(epoch, idx), sig) {
		t.Fatal("the exit does not verify under the group key")
	}
}

// dvLockFile writes the lock of c to path with the fields the exit route
// reads: lock_hash, the definition's fork_version and, where enrs has
// one, each operator's enr.
func dvLockFile(t *testing.T, c *charonCluster, path, forkVersion string, lockHash [32]byte, enrs []string) string {
	t.Helper()
	c.lock(t, path, nil)
	var m map[string]any
	if err := json.Unmarshal(mustRead(t, path), &m); err != nil {
		t.Fatal(err)
	}
	m["lock_hash"] = "0x" + hex.EncodeToString(lockHash[:])
	def := m["cluster_definition"].(map[string]any)
	def["fork_version"] = forkVersion
	for i, op := range def["operators"].([]any) {
		if i < len(enrs) {
			op.(map[string]any)["enr"] = enrs[i]
		}
	}
	return writeJSONFile(t, path, m)
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func uitoa(u uint64) string { return strconv.FormatUint(u, 10) }
