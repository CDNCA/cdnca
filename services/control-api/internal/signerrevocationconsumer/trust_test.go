package signerrevocationconsumer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/signercheckpoint"
)

func TestDeploymentTrustFreezesSortsAndClonesTrustMaterial(t *testing.T) {
	pins := []entitlementguard.VerificationKey{
		{KeyID: "pin-z", PublicKey: trustTestPublicKey(3)},
		{KeyID: "pin-a", PublicKey: trustTestPublicKey(1)},
		{KeyID: "pin-m", PublicKey: trustTestPublicKey(2)},
	}
	expectedA := append(ed25519.PublicKey(nil), pins[1].PublicKey...)
	expectedM := append(ed25519.PublicKey(nil), pins[2].PublicKey...)
	expectedZ := append(ed25519.PublicKey(nil), pins[0].PublicKey...)
	store, err := entitlementguard.NewTrustStore(pins)
	if err != nil {
		t.Fatal(err)
	}
	offlineRoot := trustTestPublicKey(9)
	expectedRoot := append(ed25519.PublicKey(nil), offlineRoot...)
	trust, err := NewDeploymentTrust(store, Config{OfflineRootKeyID: "offline-root",
		OfflineRootGeneration: 7, OfflineRootPublicKey: offlineRoot})
	if err != nil {
		t.Fatalf("NewDeploymentTrust() error = %v", err)
	}
	for index := range pins {
		clear(pins[index].PublicKey)
	}
	clear(offlineRoot)

	first, err := trust.KeysetPins(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 3 || first[0].KeyID != "pin-a" || first[1].KeyID != "pin-m" || first[2].KeyID != "pin-z" ||
		!bytes.Equal(first[0].PublicKey, expectedA) || !bytes.Equal(first[1].PublicKey, expectedM) ||
		!bytes.Equal(first[2].PublicKey, expectedZ) {
		t.Fatalf("KeysetPins() = %#v", first)
	}
	first[0].KeyID = "changed"
	clear(first[1].PublicKey)
	second, err := trust.KeysetPins(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if second[0].KeyID != "pin-a" || !bytes.Equal(second[1].PublicKey, expectedM) {
		t.Fatalf("KeysetPins() exposed mutable storage: %#v", second)
	}

	ref := signercheckpoint.AuthorityRef{Kind: signercheckpoint.AuthorityOfflineRoot, KeyID: "offline-root", Generation: 7}
	root, err := trust.OfflineRoot(context.Background(), ref)
	if err != nil || !bytes.Equal(root, expectedRoot) {
		t.Fatalf("OfflineRoot() = %x, %v", root, err)
	}
	clear(root)
	root, err = trust.OfflineRoot(context.Background(), ref)
	if err != nil || !bytes.Equal(root, expectedRoot) {
		t.Fatalf("OfflineRoot() exposed mutable storage: %x, %v", root, err)
	}
}

func TestDeploymentTrustKeepsOfflineRootSeparateFromPins(t *testing.T) {
	sharedID := "shared-key-id"
	pin := trustTestPublicKey(1)
	root := trustTestPublicKey(2)
	store, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{KeyID: sharedID, PublicKey: pin}})
	if err != nil {
		t.Fatal(err)
	}
	trust, err := NewDeploymentTrust(store, Config{OfflineRootKeyID: sharedID,
		OfflineRootGeneration: 2, OfflineRootPublicKey: root})
	if err != nil {
		t.Fatal(err)
	}
	pins, err := trust.KeysetPins(context.Background())
	if err != nil || len(pins) != 1 || !bytes.Equal(pins[0].PublicKey, pin) || bytes.Equal(pins[0].PublicKey, root) {
		t.Fatalf("KeysetPins() mixed offline root into pins: %#v, %v", pins, err)
	}
	gotRoot, err := trust.OfflineRoot(context.Background(), signercheckpoint.AuthorityRef{
		Kind: signercheckpoint.AuthorityOfflineRoot, KeyID: sharedID, Generation: 2,
	})
	if err != nil || !bytes.Equal(gotRoot, root) {
		t.Fatalf("OfflineRoot() = %x, %v", gotRoot, err)
	}
}

func TestDeploymentTrustRejectsInvalidConstructionAndReferences(t *testing.T) {
	root := trustTestPublicKey(4)
	store, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{
		KeyID: "pin-a", PublicKey: trustTestPublicKey(1),
	}})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		store  *entitlementguard.TrustStore
		config Config
	}{
		{name: "nil store", config: Config{OfflineRootKeyID: "offline-root", OfflineRootGeneration: 1, OfflineRootPublicKey: root}},
		{name: "invalid ID", store: store, config: Config{OfflineRootKeyID: "root key", OfflineRootGeneration: 1, OfflineRootPublicKey: root}},
		{name: "zero generation", store: store, config: Config{OfflineRootKeyID: "offline-root", OfflineRootPublicKey: root}},
		{name: "short key", store: store, config: Config{OfflineRootKeyID: "offline-root", OfflineRootGeneration: 1, OfflineRootPublicKey: root[:31]}},
		{name: "identity key", store: store, config: Config{OfflineRootKeyID: "offline-root", OfflineRootGeneration: 1,
			OfflineRootPublicKey: append(ed25519.PublicKey{1}, make([]byte, ed25519.PublicKeySize-1)...)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewDeploymentTrust(test.store, test.config); !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("NewDeploymentTrust() error = %v", err)
			}
		})
	}

	trust, err := NewDeploymentTrust(store, Config{OfflineRootKeyID: "offline-root",
		OfflineRootGeneration: 7, OfflineRootPublicKey: root})
	if err != nil {
		t.Fatal(err)
	}
	refs := []signercheckpoint.AuthorityRef{
		{Kind: signercheckpoint.AuthorityLineage, KeyID: "offline-root", Generation: 7},
		{Kind: signercheckpoint.AuthorityOfflineRoot, KeyID: "other-root", Generation: 7},
		{Kind: signercheckpoint.AuthorityOfflineRoot, KeyID: "offline-root", Generation: 6},
	}
	for _, ref := range refs {
		if _, err := trust.OfflineRoot(context.Background(), ref); !errors.Is(err, signercheckpoint.ErrAuthorityUntrusted) {
			t.Fatalf("OfflineRoot(%#v) error = %v", ref, err)
		}
	}
}

func TestDeploymentTrustHonorsContextCancellation(t *testing.T) {
	store, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{
		KeyID: "pin-a", PublicKey: trustTestPublicKey(1),
	}})
	if err != nil {
		t.Fatal(err)
	}
	trust, err := NewDeploymentTrust(store, Config{OfflineRootKeyID: "offline-root",
		OfflineRootGeneration: 7, OfflineRootPublicKey: trustTestPublicKey(2)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := trust.KeysetPins(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("KeysetPins() error = %v", err)
	}
	if _, err := trust.OfflineRoot(ctx, signercheckpoint.AuthorityRef{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("OfflineRoot() error = %v", err)
	}
}

func trustTestPublicKey(seed byte) ed25519.PublicKey {
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	return append(ed25519.PublicKey(nil), privateKey.Public().(ed25519.PublicKey)...)
}
