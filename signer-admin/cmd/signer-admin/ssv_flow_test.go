package main

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"path/filepath"
	"slices"
	"testing"

	cloud "github.com/lidofinance/tee-signer/signer-protocol"
)

// The SSV track with a dev runner, at operator IDs as on a live network
// (above n and above 255): ssv-split for operator 1043, the approvers'
// order, import, ssv-operator-key. The signing client gets the operator's
// public key and signatures, and the runner lists the shares under their
// own keys.
func TestSSVDevRunner(t *testing.T) {
	r := startDVRunner(t)
	c := newSSVCluster(t, 2, 1041, 1042, 1043, 1044)
	ks := c.keyshares(t, filepath.Join(r.dir, "keyshares.json"), nil)
	opKey := c.opKeyFile(t, filepath.Join(r.dir, "op1043.key"), 2)
	splitPath, sharesPath := filepath.Join(r.dir, "split.json"), filepath.Join(r.dir, "ssv-shares.txt")
	noSecretChecks(t, r.dir)
	mustTool(t, "ssv-split", "-keyshares", ks, "-operator-id", "1043", "-operator-key", opKey, "-signer", "d1", "-out", splitPath, "-shares", sharesPath)
	wantIn(t, r.approveAndImport(t, splitPath, sharesPath), "imported 2 shares")

	pubDER, err := x509.MarshalPKIXPublicKey(&c.ops[2].PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	wantIn(t, mustTool(t, "ssv-operator-key", "-cluster", r.cluster, "-signer", "d1", "-operator-key", opKey),
		"d1 holds the SSV operator key (2048 bits)", operatorPublicText(pubDER))
	wantIn(t, failTool(t, "ssv-operator-key", "-cluster", r.cluster, "-signer", "d1", "-operator-key", c.opKeyFile(t, filepath.Join(r.dir, "op1044.key"), 3)),
		"holds an SSV operator key already")

	lane, ctx := r.lane(t), context.Background()
	if got, err := lane.OperatorIdentity(ctx); err != nil || string(got) != string(pubDER) {
		t.Fatalf("OPERATOR_IDENTITY: %v", err)
	}
	d := sha256.Sum256([]byte("a QBFT message"))
	if sig, err := lane.OperatorSign(ctx, d); err != nil || rsa.VerifyPKCS1v15(&c.ops[2].PublicKey, crypto.SHA256, d[:], sig) != nil {
		t.Fatalf("OPERATOR_SIGN: %v", err)
	}
	held, err := lane.PublicKeys(ctx)
	if err != nil || len(held) != 2 {
		t.Fatalf("PUBLIC_KEYS: %v, %v", held, err)
	}
	for v := range c.groups {
		sp := c.sharePub(t, v, 2)
		if !slices.ContainsFunc(held, func(k cloud.ValidatorKey) bool { return k.Pubkey == sp && k.SharePubkey == sp }) {
			t.Fatalf("validator %d: share %s is not listed under its own key", v, sp)
		}
	}
}
