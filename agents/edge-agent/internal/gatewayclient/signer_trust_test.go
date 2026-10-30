package gatewayclient

import (
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/edgesignertrust"
)

func signerTrustKey(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte(label))
	return ed25519.NewKeyFromSeed(seed[:])
}

func signerTrustPEM(t *testing.T, key crypto.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

type signerTrustFixture struct {
	t       *testing.T
	trust   *TrustStore
	control ed25519.PrivateKey
	root    ed25519.PrivateKey
	now     time.Time
}

func newSignerTrustFixture(t *testing.T) *signerTrustFixture {
	control := signerTrustKey("control publisher")
	trust, err := NewTrustStore(map[string]crypto.PublicKey{
		"edge-publish":    control.Public(),
		"release-old":     signerTrustKey("release old").Public(),
		"release-renamed": signerTrustKey("release renamed").Public(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return &signerTrustFixture{t: t, trust: trust, control: control, root: signerTrustKey("root"),
		now: time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)}
}

func (fixture *signerTrustFixture) document(revision uint64, trusted map[string]ed25519.PrivateKey,
	revoked ...edgesignertrust.RevokedKey) []byte {
	fixture.t.Helper()
	document := edgesignertrust.Document{Schema: edgesignertrust.DocumentSchema, Revision: revision,
		IssuedAt: "2026-10-17T08:00:00Z", TrustedKeys: []edgesignertrust.TrustedKey{}, RevokedKeys: revoked}
	for keyID, key := range trusted {
		document.TrustedKeys = append(document.TrustedKeys, edgesignertrust.TrustedKey{KeyID: keyID,
			PublicKeyPEM: signerTrustPEM(fixture.t, key.Public())})
	}
	document, err := edgesignertrust.Normalize(document)
	if err != nil {
		fixture.t.Fatal(err)
	}
	encoded, err := edgesignertrust.Sign(document, "offline-root", 1, fixture.root)
	if err != nil {
		fixture.t.Fatal(err)
	}
	return encoded
}

func (fixture *signerTrustFixture) bundle(nodeID, keyID string, key ed25519.PrivateKey, document []byte) []byte {
	fixture.t.Helper()
	bundle, err := edgesignertrust.NewBundle(nodeID, document, keyID, fixture.now)
	if err != nil {
		fixture.t.Fatal(err)
	}
	payload, err := edgesignertrust.BundleSigningPayload(bundle)
	if err != nil {
		fixture.t.Fatal(err)
	}
	wire, err := edgesignertrust.SealBundle(bundle, ed25519.Sign(key, payload))
	if err != nil {
		fixture.t.Fatal(err)
	}
	return wire
}

func revokedKey(keyID string) edgesignertrust.RevokedKey {
	return edgesignertrust.RevokedKey{KeyID: keyID, RevokedAt: "2026-10-17T07:00:00Z", Reason: "signer_compromise"}
}

func TestSignerTrustOverlayRevokesAndAddsKeys(t *testing.T) {
	fixture := newSignerTrustFixture(t)
	dir := filepath.Join(t.TempDir(), "signer-trust")
	runtime, err := NewSignerTrustRuntime(dir, "node-1", fixture.trust, func() time.Time { return fixture.now })
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := fixture.trust.key("release-old"); !ok {
		t.Fatal("base key missing before any document")
	}
	renamedPrint, _ := edgesignertrust.PublicKeySHA256(signerTrustKey("release renamed").Public())
	newKey := signerTrustKey("release new")
	first := fixture.document(1, map[string]ed25519.PrivateKey{"release-new": newKey}, revokedKey("release-old"),
		edgesignertrust.RevokedKey{KeyID: "release-previous-name", PublicKeySHA256: renamedPrint,
			RevokedAt: "2026-10-17T07:00:00Z", Reason: "signer_compromise"})
	receipt := runtime.Apply(fixture.bundle("node-1", "edge-publish", fixture.control, first))
	if receipt.Result != edgesignertrust.ResultApplied || receipt.Revision != 1 || fixture.trust.SignerTrustRevision() != 1 {
		t.Fatalf("receipt = %#v", receipt)
	}
	if _, ok := fixture.trust.key("release-old"); ok {
		t.Fatal("revoked key still trusted")
	}
	if _, ok := fixture.trust.key("release-renamed"); ok {
		t.Fatal("key revoked by fingerprint still trusted under another ID")
	}
	if key, ok := fixture.trust.Ed25519Key("release-new"); !ok || !key.Equal(newKey.Public()) {
		t.Fatal("trusted key from the document missing")
	}
	subset := fixture.trust.Ed25519Subset()
	if _, ok := subset["release-old"]; ok || subset["release-new"] == nil || subset["edge-publish"] == nil {
		t.Fatalf("Ed25519Subset = %v", subset)
	}
	if !fixture.trust.Revoked("anything", signerTrustKey("release renamed").Public()) || fixture.trust.Revoked("edge-publish", nil) {
		t.Fatal("Revoked is wrong")
	}

	// Restart: a fresh store from artifacts.json plus the persisted state.
	restarted := newSignerTrustFixture(t)
	restoredRuntime, err := NewSignerTrustRuntime(dir, "node-1", restarted.trust, func() time.Time { return fixture.now })
	if err != nil {
		t.Fatal(err)
	}
	if err := restoredRuntime.Restore(); err != nil {
		t.Fatal(err)
	}
	if _, ok := restarted.trust.key("release-old"); ok || restarted.trust.SignerTrustRevision() != 1 {
		t.Fatal("revocation not restored after restart")
	}
	info, err := os.Stat(filepath.Join(dir, signerTrustStateFile))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode = %v, %v", info, err)
	}
}

func TestSignerTrustRuntimeRejections(t *testing.T) {
	fixture := newSignerTrustFixture(t)
	dir := filepath.Join(t.TempDir(), "signer-trust")
	runtime, _ := NewSignerTrustRuntime(dir, "node-1", fixture.trust, func() time.Time { return fixture.now })
	second := fixture.document(2, nil, revokedKey("release-old"))
	if receipt := runtime.Apply(fixture.bundle("node-1", "edge-publish", fixture.control, second)); receipt.Result != edgesignertrust.ResultApplied {
		t.Fatalf("second = %#v", receipt)
	}
	for name, test := range map[string]struct {
		wire   []byte
		reason string
	}{
		"replay is idempotent": {fixture.bundle("node-1", "edge-publish", fixture.control, second), ""},
		"stale":                {fixture.bundle("node-1", "edge-publish", fixture.control, fixture.document(1, nil, revokedKey("release-old"))), edgesignertrust.ReasonStale},
		"same revision, other content": {fixture.bundle("node-1", "edge-publish", fixture.control,
			fixture.document(2, nil, revokedKey("release-old"), revokedKey("release-x"))), edgesignertrust.ReasonConflict},
		"drops a revocation": {fixture.bundle("node-1", "edge-publish", fixture.control, fixture.document(3, nil)), edgesignertrust.ReasonConflict},
		"forged control key": {fixture.bundle("node-1", "edge-publish", signerTrustKey("attacker"), second), edgesignertrust.ReasonUntrusted},
		"signed by a revoked key": {fixture.bundle("node-1", "release-old", signerTrustKey("release old"),
			fixture.document(3, nil, revokedKey("release-old"))), edgesignertrust.ReasonUntrusted},
		"other node": {fixture.bundle("node-2", "edge-publish", fixture.control, second), edgesignertrust.ReasonInvalid},
		"garbage":    {[]byte(`{"schema":"x"}`), edgesignertrust.ReasonInvalid},
	} {
		t.Run(name, func(t *testing.T) {
			receipt := runtime.Apply(test.wire)
			if test.reason == "" && receipt.Result != edgesignertrust.ResultApplied ||
				test.reason != "" && (receipt.Result != edgesignertrust.ResultRejected || receipt.Reason != test.reason) {
				t.Fatalf("receipt = %#v", receipt)
			}
			if receipt.Revision != 2 || !edgesignertrust.ValidReceipt(receipt) {
				t.Fatalf("enforced revision/receipt = %#v", receipt)
			}
		})
	}
	if _, ok := fixture.trust.key("release-old"); ok {
		t.Fatal("a rejected bundle lifted the revocation")
	}
}

func TestSignerTrustRestoreQuarantinesCorruptState(t *testing.T) {
	fixture := newSignerTrustFixture(t)
	dir := filepath.Join(t.TempDir(), "signer-trust")
	runtime, _ := NewSignerTrustRuntime(dir, "node-1", fixture.trust, func() time.Time { return fixture.now })
	if err := os.WriteFile(filepath.Join(dir, signerTrustStateFile), []byte(`{"schema":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Restore(); err == nil || !strings.Contains(err.Error(), "moved to") {
		t.Fatalf("restore error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, signerTrustStateFile)); !os.IsNotExist(err) {
		t.Fatal("corrupt state left in place")
	}
	if fixture.trust.SignerTrustRevision() != 0 {
		t.Fatal("corrupt state applied")
	}
	if receipt := runtime.Apply(fixture.bundle("node-1", "edge-publish", fixture.control,
		fixture.document(1, nil, revokedKey("release-old")))); receipt.Result != edgesignertrust.ResultApplied {
		t.Fatalf("redelivery after quarantine = %#v", receipt)
	}
}
