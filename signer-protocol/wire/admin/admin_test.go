package admin

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/lidofinance/tee-signer/devkit/fuzzcheck"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
)

// testState is a setup state with every field set.
func testState() backend.SetupState {
	return backend.SetupState{
		SetupHash:       backend.Root{0x5e},
		Locked:          backend.ConfigGroup{Version: 4, Hash: backend.Root{1}, Pending: backend.PendingUpdate{Version: 6, Hash: backend.Root{2}, EffectiveAt: 1_800_000_000}},
		Open:            backend.ConfigGroup{Version: 1, Hash: backend.Root{3}},
		ApproverSetHash: backend.Root{4},
		Order:           backend.Order{Kind: 1, Hash: backend.Root{5}, ActAt: 1_900_000_000},
		KeyReleaseHash:  backend.Root{6},
		KeyOrigin:       backend.KeyOrigin{Imported: 8},
	}
}

func seedState() backend.SetupState { return testState() }

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

func TestImport(t *testing.T) {
	imp := backend.ImportShareRequest{Pubkey: backend.Pubkey{9}, Secret: [32]byte{8}, Index: 7,
		Interchange: &backend.Watermark{HasAttestation: true, SourceEpoch: 5, TargetEpoch: 6}}
	got, err := DecodeImport(EncodeImport(imp))
	if err != nil || !reflect.DeepEqual(got, imp) {
		t.Fatalf("%+v %v", got, err)
	}
	imp.Interchange = nil
	if got, _ := DecodeImport(EncodeImport(imp)); got.Interchange != nil {
		t.Fatal("empty interchange should decode as nil")
	}

}

func TestSealedImport(t *testing.T) {
	req := backend.SealedImportRequest{Pubkey: backend.Pubkey{1}, SharePubkey: backend.Pubkey{2}, Index: 3,
		Interchange: &backend.Watermark{HasBlock: true, BlockSlot: 99}, Sealed: []byte("enc-and-ciphertext")}
	p, err := EncodeImportSealed(&req)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p[:SealedHeaderLen], SealedHeader(&req)) {
		t.Fatal("header prefix")
	}
	got, err := DecodeImportSealed(p)
	if err != nil || !reflect.DeepEqual(got, req) {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := DecodeImportSealed(p[:len(p)-1]); err == nil {
		t.Fatal("truncated sealed share accepted")
	}
	if _, err := DecodeImportSealed(append(p, 0)); err == nil {
		t.Fatal("trailing byte accepted")
	}

}

func TestConfigUpdate(t *testing.T) {
	if MaxConfigUpdate != setupwire.MaxUpdate {
		t.Fatalf("MaxConfigUpdate %d, setupwire.MaxUpdate %d", MaxConfigUpdate, setupwire.MaxUpdate)
	}
	if TypeConfigUpdate.String() != "CONFIG_UPDATE" || (TypeConfigUpdate|wire.ResponseFlag).String() != "CONFIG_UPDATE_RESPONSE" {
		t.Fatalf("names %v %v", TypeConfigUpdate, TypeConfigUpdate|wire.ResponseFlag)
	}
	update := bytes.Repeat([]byte{'U'}, 300)
	p, err := EncodeConfigUpdate(update)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DecodeConfigUpdate(p); err != nil || !bytes.Equal(got, update) {
		t.Fatalf("%x %v", got, err)
	}
	for _, n := range []int{0, MaxConfigUpdate + 1} {
		if _, err := EncodeConfigUpdate(make([]byte, n)); err == nil {
			t.Errorf("encoded an update of %d bytes", n)
		}
		if _, err := DecodeConfigUpdate(make([]byte, n)); err == nil {
			t.Errorf("decoded an update of %d bytes", n)
		}
	}

	st := testState()
	for _, outcome := range []uint8{ConfigAccepted, ConfigKnown} {
		b := EncodeConfigUpdateResponse(outcome, &st)
		if len(b) != 2+backend.SetupStateLen {
			t.Fatalf("answer of %d bytes", len(b))
		}
		got, s, err := DecodeConfigUpdateResponse(b)
		if err != nil || got != outcome || *s != st {
			t.Fatalf("outcome %d state %+v %v", got, s, err)
		}
	}
	good := EncodeConfigUpdateResponse(ConfigAccepted, &st)
	for name, b := range map[string][]byte{
		"empty":         nil,
		"version 2":     append([]byte{2}, good[1:]...),
		"outcome 0":     append([]byte{good[0], 0}, good[2:]...),
		"outcome 3":     append([]byte{good[0], 3}, good[2:]...),
		"short":         good[:len(good)-1],
		"trailing byte": append(append([]byte{}, good...), 0),
		"bad state":     append(append([]byte{}, good[:2]...), make([]byte, backend.SetupStateLen)...),
	} {
		if name == "bad state" {
			// Locked: active version 2, pending version 1.
			b[2+32+7], b[2+32+8+32+7] = 2, 1
		}
		if _, _, err := DecodeConfigUpdateResponse(b); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
}

// IMPORT_SHARE and IMPORT_SHARE_SEALED: with flags 0 the decoder drops the
// three maxima, whatever they hold, so only a value round trip holds there.
func interchangeCanonical(flags byte, maxima []byte) bool {
	return flags != 0 || bytes.Equal(maxima, make([]byte, 24))
}

func FuzzDecodeImport(f *testing.F) {
	imp := backend.ImportShareRequest{Pubkey: backend.Pubkey{9}, Secret: [32]byte{8}, Index: 7,
		Interchange: &backend.Watermark{HasAttestation: true, SourceEpoch: 5, TargetEpoch: 6}}
	f.Add(EncodeImport(imp))
	imp.Interchange = nil
	f.Add(EncodeImport(imp))
	f.Fuzz(func(t *testing.T, b []byte) {
		fuzzcheck.Watch(t)
		req, err := DecodeImport(b)
		if err != nil {
			return
		}
		again := EncodeImport(req)
		if interchangeCanonical(b[88], b[89:]) && !bytes.Equal(again, b) {
			t.Fatalf("IMPORT_SHARE does not encode back:\n%x\n%x", again, b)
		}
		if req2, err := DecodeImport(again); err != nil || !reflect.DeepEqual(req2, req) {
			t.Fatalf("IMPORT_SHARE value round trip: %+v %v", req2, err)
		}
	})
}

func FuzzDecodeImportSealed(f *testing.F) {
	req := backend.SealedImportRequest{Pubkey: backend.Pubkey{1}, SharePubkey: backend.Pubkey{2}, Index: 3,
		Interchange: &backend.Watermark{HasBlock: true, BlockSlot: 99}, Sealed: []byte("enc-and-ciphertext")}
	f.Add(must(EncodeImportSealed(&req)))
	req.Interchange, req.Sealed = nil, nil
	f.Add(must(EncodeImportSealed(&req)))
	f.Fuzz(func(t *testing.T, b []byte) {
		fuzzcheck.Watch(t)
		req, err := DecodeImportSealed(b)
		if err != nil {
			return
		}
		again, err := EncodeImportSealed(&req)
		if err != nil {
			t.Fatalf("decoded sealed import does not encode: %v", err)
		}
		if interchangeCanonical(b[104], b[105:SealedHeaderLen]) && !bytes.Equal(again, b) {
			t.Fatalf("IMPORT_SHARE_SEALED does not encode back:\n%x\n%x", again, b)
		}
		if req2, err := DecodeImportSealed(again); err != nil || !reflect.DeepEqual(req2, req) {
			t.Fatalf("IMPORT_SHARE_SEALED value round trip: %+v %v", req2, err)
		}
	})
}

func FuzzDecodeConfigUpdateResponse(f *testing.F) {
	st := seedState()
	f.Add(EncodeConfigUpdateResponse(ConfigAccepted, &st))
	f.Add(EncodeConfigUpdateResponse(ConfigKnown, &backend.SetupState{}))
	f.Fuzz(func(t *testing.T, b []byte) {
		fuzzcheck.Watch(t)
		outcome, s, err := DecodeConfigUpdateResponse(b)
		if err != nil {
			return
		}
		if again := EncodeConfigUpdateResponse(outcome, s); !bytes.Equal(again, b) {
			t.Fatalf("CONFIG_UPDATE answer does not encode back:\n%x\n%x", again, b)
		}
	})
}

// batchSeed is an IMPORT_SHARES_SEALED request of two shares, one with a
// split and interchange maxima, under an order.
func batchSeed() ([]byte, []backend.SealedImportRequest) {
	order := []byte("signed import order")
	reqs := []backend.SealedImportRequest{
		{Pubkey: backend.Pubkey{1}, SharePubkey: backend.Pubkey{2}, Index: 3, Sealed: []byte("sealed one"), T: 2, N: 3, ShareIndex: 1,
			Commitments: []backend.Pubkey{{7}, {8}}, Interchange: &backend.Watermark{HasAttestation: true, SourceEpoch: 5, TargetEpoch: 6}},
		{Pubkey: backend.Pubkey{4}, SharePubkey: backend.Pubkey{5}, Index: 6, Sealed: []byte("sealed two")},
	}
	for i := range reqs {
		reqs[i].Order = order
	}
	return order, reqs
}

// IMPORT_SHARES_SEALED round trips, BatchLen and BatchShareLen size it, and
// a bad version, a split without an order and trailing bytes are refused.
func TestImportBatch(t *testing.T) {
	order, reqs := batchSeed()
	p, err := EncodeImportBatch(order, reqs)
	if err != nil {
		t.Fatal(err)
	}
	if n := BatchLen(order) + BatchShareLen(&reqs[0]) + BatchShareLen(&reqs[1]); n != len(p) {
		t.Fatalf("BatchLen and BatchShareLen give %d, the payload has %d bytes", n, len(p))
	}
	got, err := DecodeImportBatch(p)
	if err != nil || !reflect.DeepEqual(got, reqs) {
		t.Fatalf("%+v %v", got, err)
	}
	if got, err := DecodeImportBatch(must(EncodeImportBatch(nil, nil))); err != nil || len(got) != 0 {
		t.Fatalf("empty batch: %+v %v", got, err)
	}
	if _, err := EncodeImportBatch(nil, reqs); err == nil {
		t.Fatal("a split without an order encoded")
	}
	bad := map[string][]byte{"version 1": append([]byte{1}, p[1:]...), "trailing": append(append([]byte(nil), p...), 0), "cut": p[:len(p)-1]}
	for name, b := range bad {
		if _, err := DecodeImportBatch(b); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
}

func FuzzDecodeImportBatch(f *testing.F) {
	order, reqs := batchSeed()
	f.Add(must(EncodeImportBatch(order, reqs)))
	f.Add(must(EncodeImportBatch(nil, reqs[1:])))
	f.Fuzz(func(t *testing.T, b []byte) {
		fuzzcheck.Watch(t)
		reqs, err := DecodeImportBatch(b)
		if err != nil {
			return
		}
		var order []byte
		if len(reqs) > 0 {
			order = reqs[0].Order
		}
		again, err := EncodeImportBatch(order, reqs)
		if err != nil {
			t.Fatalf("decoded batch does not encode: %v", err)
		}
		if reqs2, err := DecodeImportBatch(again); err != nil || !reflect.DeepEqual(reqs2, reqs) {
			t.Fatalf("IMPORT_SHARES_SEALED value round trip: %+v %v", reqs2, err)
		}
	})
}

// The share index is a u64 in both imports: an SSV share's index is its
// operator ID, often above 255.
func TestImportShareIndexU64(t *testing.T) {
	order := []byte("order")
	share := func(idx uint64) backend.SealedImportRequest {
		return backend.SealedImportRequest{Pubkey: backend.Pubkey{0xa1}, SharePubkey: backend.Pubkey{0xb1}, Index: 7,
			Sealed: []byte{1, 2, 3}, T: 3, N: 4, ShareIndex: idx,
			Commitments: []backend.Pubkey{{0xa1}, {0xc1}, {0xc2}}}
	}
	for _, idx := range []uint64{2, 255, 1043, 1 << 40} {
		reqs := []backend.SealedImportRequest{share(idx), share(idx)}
		p, err := EncodeImportBatch(order, reqs)
		if err != nil {
			t.Fatal(err)
		}
		if size := BatchLen(order) + BatchShareLen(&reqs[0]) + BatchShareLen(&reqs[1]); len(p) != size {
			t.Fatalf("index %d: %d bytes, BatchLen and BatchShareLen give %d", idx, len(p), size)
		}
		got, err := DecodeImportBatch(p)
		if err != nil || len(got) != 2 {
			t.Fatalf("index %d: %v", idx, err)
		}
		for i := range got {
			if got[i].ShareIndex != idx || got[i].T != 3 || got[i].N != 4 || len(got[i].Commitments) != 3 ||
				got[i].Commitments[2] != (backend.Pubkey{0xc2}) || string(got[i].Order) != "order" || got[i].Index != 7 {
				t.Fatalf("index %d: share %d decoded as %+v", idx, i, got[i])
			}
		}
		for n := 1; n < len(p); n += 7 {
			if _, err := DecodeImportBatch(p[:n]); err == nil {
				t.Fatalf("index %d: %d of %d bytes decoded", idx, n, len(p))
			}
		}
		r := share(idx)
		r.Order = order
		sp, err := EncodeImportSealed(&r)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := DecodeImportSealed(sp); err != nil || got.ShareIndex != idx || len(got.Commitments) != 3 {
			t.Fatalf("IMPORT_SHARE_SEALED index %d: %v", idx, err)
		}
	}
}

// IMPORT_OPERATOR_KEY_SEALED: version, then the sealed key; nothing else
// decodes.
func TestImportOperatorKey(t *testing.T) {
	sealed := bytes.Repeat([]byte{7}, 300)
	p, err := EncodeImportOperatorKey(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DecodeImportOperatorKey(p); err != nil || !bytes.Equal(got, sealed) {
		t.Fatalf("round trip: %v", err)
	}
	for name, b := range map[string][]byte{
		"empty":        nil,
		"version 2":    append([]byte{2}, sealed...),
		"no key":       {OperatorKeyVersion},
		"over the cap": append([]byte{OperatorKeyVersion}, make([]byte, MaxOperatorKey+1)...),
	} {
		if _, err := DecodeImportOperatorKey(b); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
	if _, err := EncodeImportOperatorKey(make([]byte, MaxOperatorKey+1)); err == nil {
		t.Error("a sealed key over the cap encoded")
	}
}
