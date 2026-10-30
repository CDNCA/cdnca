package signerrevocation

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementsync"
)

func gateSnapshot(revision uint64, revocations ...Revocation) Snapshot {
	return Snapshot{Revision: revision, Keyset: &entitlementsync.VerifiedKeyset{Chain: []string{"lineage-1", "lineage-2"}},
		Revocations: revocations}
}

func TestGateFailsOpenWithoutVerifiedState(t *testing.T) {
	var logs bytes.Buffer
	gate := NewGate(&Runtime{}, func() time.Time { return time.Now() }, slog.New(slog.NewTextHandler(&logs, nil)))
	if err := gate.CheckSigner(entitlementguard.SignerArtifactLease, "lineage-1"); err != nil {
		t.Fatalf("no LKG must allow, got %v", err)
	}
	var nilGate *Gate
	if err := nilGate.CheckSigner(entitlementguard.SignerArtifactLease, "lineage-1"); err != nil {
		t.Fatalf("nil gate must allow, got %v", err)
	}
	if stats := gate.Stats(); stats.Denied != 0 || stats.StateUnavailable != 1 {
		t.Fatalf("stats = %#v", stats)
	}
}

func TestGateDeniesKnownRevocationFromEffectiveTimeOnly(t *testing.T) {
	effective := time.Date(2026, 10, 16, 8, 0, 0, 0, time.UTC)
	now := effective.Add(-time.Second)
	runtime, err := NewRuntime(gateSnapshot(3, Revocation{Sequence: 1, RevokedKeyID: "lineage-1",
		RevokedKeyGeneration: 1, ArtifactClasses: []ArtifactClass{ArtifactLease, ArtifactPolicy},
		EffectiveNotBefore: effective}))
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	gate := NewGate(runtime, func() time.Time { return now }, slog.New(slog.NewJSONHandler(&logs, nil)))

	if err := gate.CheckSigner(entitlementguard.SignerArtifactLease, "lineage-1"); err != nil {
		t.Fatalf("before effective_not_before must allow, got %v", err)
	}
	now = effective
	err = gate.CheckSigner(entitlementguard.SignerArtifactLease, "lineage-1")
	var revoked *entitlementguard.SignerRevokedError
	if !errors.Is(err, entitlementguard.ErrSignerRevoked) || !errors.As(err, &revoked) ||
		revoked.KeyID != "lineage-1" || revoked.Class != entitlementguard.SignerArtifactLease {
		t.Fatalf("at effective_not_before = %v", err)
	}
	if err := gate.CheckSigner(entitlementguard.SignerArtifactPolicy, "lineage-1"); !errors.Is(err, entitlementguard.ErrSignerRevoked) {
		t.Fatalf("policy class = %v", err)
	}
	if err := gate.CheckSigner(entitlementguard.SignerArtifactRelease, "lineage-1"); err != nil {
		t.Fatalf("release class not listed must allow, got %v", err)
	}
	if err := gate.CheckSigner(entitlementguard.SignerArtifactLease, "lineage-2"); err != nil {
		t.Fatalf("other key must allow, got %v", err)
	}
	if stats := gate.Stats(); stats.Denied != 2 {
		t.Fatalf("denied counter = %#v", stats)
	}
	text := logs.String()
	for _, want := range []string{`"event":"signer_revocation.denied"`, `"reason":"signer_revoked"`,
		`"key_id":"lineage-1"`, `"revocation_sequence":1`, `"checkpoint_revision":3`} {
		if !strings.Contains(text, want) {
			t.Fatalf("denial log missing %s: %s", want, text)
		}
	}
}

func TestGateUsesLatestReplacedSnapshot(t *testing.T) {
	runtime, err := NewRuntime(gateSnapshot(1))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC)
	gate := NewGate(runtime, func() time.Time { return now }, slog.New(slog.DiscardHandler))
	if err := gate.CheckSigner(entitlementguard.SignerArtifactRelease, "lineage-1"); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Replace(gateSnapshot(2, Revocation{Sequence: 1, RevokedKeyID: "lineage-1",
		RevokedKeyGeneration: 1, ArtifactClasses: []ArtifactClass{ArtifactRelease},
		EffectiveNotBefore: now.Add(-time.Hour)})); err != nil {
		t.Fatal(err)
	}
	if err := gate.CheckSigner(entitlementguard.SignerArtifactRelease, "lineage-1"); !errors.Is(err, entitlementguard.ErrSignerRevoked) {
		t.Fatalf("after Replace = %v", err)
	}
}
