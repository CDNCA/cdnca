package errorpage

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type site13Trust struct {
	key ed25519.PublicKey
}

func (trust site13Trust) ResolveProductionBundleKey(_ context.Context, keyID string) (ed25519.PublicKey, error) {
	if keyID != "error-page-signing-v1" {
		return nil, errors.New("unknown signing key")
	}
	return append(ed25519.PublicKey(nil), trust.key...), nil
}

func TestSITE13SignedBundleInstallsAtomicallyAndReturnsBoundReceipt(t *testing.T) {
	publisher, runtime := testPublisher(t)
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x51}, ed25519.SeedSize))
	installer, err := NewProductionBundleInstaller(publisher, site13Trust{key: private.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	binding := site13Binding()
	bundle := site13SignedBundle(t, private, binding, "production page\n")
	receipt, err := installer.Install(t.Context(), bundle, binding)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.State != ActivationStateActivated || receipt.ReasonCode != "" || receipt.Binding != binding ||
		receipt.BundleSHA256 != bundle.SHA256 || receipt.ActiveDigest == "" || receipt.RunningConfigUnchanged || runtime.activations != 1 {
		t.Fatalf("receipt=%+v runtime=%+v", receipt, runtime)
	}
	assertPointers(t, publisher, binding.Revision, receipt.ActiveDigest)
}

func TestSITE13SignedBundleRejectsTamperAndCrossBindingBeforeActivation(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x61}, ed25519.SeedSize))
	base := site13Binding()
	for name, mutate := range map[string]func(*ProductionBundleBinding, *SignedProductionBundle){
		"unsigned":    func(_ *ProductionBundleBinding, bundle *SignedProductionBundle) { bundle.Signature = nil },
		"wire tamper": func(_ *ProductionBundleBinding, bundle *SignedProductionBundle) { bundle.WireBytes[0] ^= 1 },
		"tenant": func(binding *ProductionBundleBinding, _ *SignedProductionBundle) {
			binding.TenantID = "01990000-0000-7000-8000-000000000099"
		},
		"site": func(binding *ProductionBundleBinding, _ *SignedProductionBundle) {
			binding.SiteID = "01990000-0000-7000-8000-000000000098"
		},
		"category": func(binding *ProductionBundleBinding, _ *SignedProductionBundle) {
			binding.Category = CategoryOriginResponse
		},
		"revision": func(binding *ProductionBundleBinding, _ *SignedProductionBundle) { binding.Revision++ },
		"asset digest": func(binding *ProductionBundleBinding, _ *SignedProductionBundle) {
			binding.AssetSHA256 = strings.Repeat("0", 64)
		},
	} {
		t.Run(name, func(t *testing.T) {
			publisher, runtime := testPublisher(t)
			installer, err := NewProductionBundleInstaller(publisher, site13Trust{key: private.Public().(ed25519.PublicKey)})
			if err != nil {
				t.Fatal(err)
			}
			expected := base
			bundle := site13SignedBundle(t, private, base, "production page\n")
			mutate(&expected, &bundle)
			receipt, err := installer.Install(t.Context(), bundle, expected)
			if err == nil || receipt.State != ActivationStateFailed || !receipt.RunningConfigUnchanged || receipt.ReasonCode == "" || runtime.activations != 0 {
				t.Fatalf("receipt=%+v err=%v runtime=%+v", receipt, err, runtime)
			}
			if _, found, err := publisher.Current(); err != nil || found {
				t.Fatalf("invalid bundle changed current: found=%t err=%v", found, err)
			}
		})
	}
}

func TestSITE13SignedBundleMapsPartialFailureAndKeepsLKG(t *testing.T) {
	publisher, runtime := testPublisher(t)
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x71}, ed25519.SeedSize))
	installer, err := NewProductionBundleInstaller(publisher, site13Trust{key: private.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	first := site13Binding()
	first.Revision = 1
	baseline, err := installer.Install(t.Context(), site13SignedBundle(t, private, first, "production page\n"), first)
	if err != nil {
		t.Fatal(err)
	}
	runtime.precheckFail = true
	next := first
	next.Revision = 2
	receipt, err := installer.Install(t.Context(), site13SignedBundle(t, private, next, "production page\n"), next)
	if !errors.Is(err, ErrPrecheck) || receipt.ReasonCode != ActivationReasonPrecheckFailed || !receipt.RunningConfigUnchanged {
		t.Fatalf("receipt=%+v err=%v", receipt, err)
	}
	assertPointers(t, publisher, 1, baseline.ActiveDigest)
}

func TestSITE13RestartReconcilesSafeStagingOrphan(t *testing.T) {
	publisher, _ := testPublisher(t)
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x21}, ed25519.SeedSize))
	installer, err := NewProductionBundleInstaller(publisher, site13Trust{key: private.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	binding := site13Binding()
	if _, err := installer.Install(t.Context(), site13SignedBundle(t, private, binding, "production page\n"), binding); err != nil {
		t.Fatal(err)
	}
	orphan := filepath.Join(publisher.stateRoot, "staging", strings.Repeat("a", 64)+"-0123456789abcdef")
	if err := os.Mkdir(orphan, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(orphan, "manifest.json"), []byte("{}"), 0o400); err != nil {
		t.Fatal(err)
	}
	receipt, err := installer.Reconcile(t.Context())
	if err != nil || receipt.RemovedOrphans != 1 || receipt.CurrentRevision != binding.Revision || receipt.LKGRevision != binding.Revision {
		t.Fatalf("receipt=%+v err=%v", receipt, err)
	}
	if _, err := os.Lstat(orphan); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("orphan remains: %v", err)
	}
}

func site13Binding() ProductionBundleBinding {
	bodyDigest := sha256.Sum256([]byte("production page\n"))
	return ProductionBundleBinding{
		TenantID: "01990000-0000-7000-8000-000000000001", SiteID: "01990000-0000-7000-8000-000000000002",
		Category: CategoryEdgeRoute, Revision: 7, AssetSHA256: hex.EncodeToString(bodyDigest[:]),
	}
}

func site13SignedBundle(t *testing.T, private ed25519.PrivateKey, binding ProductionBundleBinding, body string) SignedProductionBundle {
	t.Helper()
	digest := sha256.Sum256([]byte(body))
	binding.AssetSHA256 = hex.EncodeToString(digest[:])
	document := ProductionBundleDocument{
		Schema: ProductionBundleSchema, Binding: binding, RuleID: "01990000-0000-7000-8000-000000000003",
		Match:    StatusMatch{Codes: []int{404}},
		Resource: ProductionBundleResource{MIMEType: "text/plain", Size: int64(len(body)), SHA256: binding.AssetSHA256, Body: []byte(body)},
	}
	wire, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	wireDigest := sha256.Sum256(wire)
	return SignedProductionBundle{WireBytes: wire, SHA256: hex.EncodeToString(wireDigest[:]), Signature: ed25519.Sign(private, wire), SigningKeyID: "error-page-signing-v1"}
}
