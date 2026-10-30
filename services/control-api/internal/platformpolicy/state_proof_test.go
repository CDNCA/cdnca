package platformpolicy

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestStateEnforcesEntitlementAndFailStale(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	clock := now
	state := NewState(func() time.Time { return clock })

	if decision := state.ReleaseChannel("stable", false); decision.Allowed || decision.Reason != DecisionEntitlementDenied {
		t.Fatalf("release without entitlement = %#v", decision)
	}
	if decision := state.PluginMarket(true); decision.Allowed || decision.Reason != DecisionPluginMarketDenied {
		t.Fatalf("default plugin market = %#v", decision)
	}
	policy := Policy{
		Schema: PolicySchema, MinimumControlVersion: "1.4.0",
		BlockedControlVersions: []string{}, AllowedReleaseChannels: []string{"stable"},
		PluginMarket: PluginMarket{Enabled: true, TrustedCatalogIDs: []string{"cdnca-official"}},
	}
	if err := state.Replace(Snapshot{Policy: policy, Source: ScopeInstallation,
		TargetRevisionID: uuid.NewString(), ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	policy.AllowedReleaseChannels[0] = "tampered"
	if decision := state.ReleaseChannel("stable", true); !decision.Allowed || decision.Source != ScopeInstallation {
		t.Fatalf("release decision = %#v", decision)
	}
	if decision := state.TrustedCatalog("cdnca-official", true); !decision.Allowed {
		t.Fatalf("catalog decision = %#v", decision)
	}
	if decision := state.TrustedCatalog("untrusted", true); decision.Allowed || decision.Reason != DecisionCatalogDenied {
		t.Fatalf("untrusted catalog decision = %#v", decision)
	}

	clock = now.Add(time.Hour)
	for name, decision := range map[string]Decision{
		"release": state.ReleaseChannel("stable", true),
		"market":  state.PluginMarket(true),
		"catalog": state.TrustedCatalog("cdnca-official", true),
	} {
		if decision.Allowed || !decision.Stale || decision.Reason != DecisionPolicyStale {
			t.Errorf("%s stale decision = %#v", name, decision)
		}
	}
	if snapshot, stale := state.Snapshot(); !stale || snapshot.TargetRevisionID == "" {
		t.Fatalf("stale snapshot was discarded: (%#v, %t)", snapshot, stale)
	}
}

func TestPrepareResolveAndAcknowledgementProofs(t *testing.T) {
	requestedAt := time.Date(2026, 7, 22, 12, 1, 0, 987, time.UTC)
	observedAt := requestedAt.Add(-time.Second)
	installationID := uuid.New()
	publicKey, privateKey := testPolicyKey()
	targetID := uuid.NewString()
	digest := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	cursor, etag := "cursor", "etag"
	resolve, err := PrepareResolve(ResolveInput{
		InstallationID: installationID, ControlVersion: "1.4.0", ControlProtocolVersion: 1,
		KnownGlobalRevision: 2, KnownInstallationRevision: 3,
		ActiveTargetRevisionID: &targetID, ActivePolicySHA256: &digest, Cursor: &cursor, KnownETag: &etag,
	}, "resolve-request", requestedAt, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := base64.RawURLEncoding.DecodeString(resolve.Proof)
	if err != nil || !ed25519.Verify(publicKey, ResolveProofMessage(resolve), proof) {
		t.Fatal("resolve proof did not verify")
	}
	if resolve.RequestedAt != requestedAt.Unix() {
		t.Fatalf("resolve requested_at = %d", resolve.RequestedAt)
	}
	errorCode := "invalid_signature"
	acknowledgement, err := PrepareAcknowledgement(AckInput{
		InstallationID: installationID, TargetRevisionID: targetID, ScopeKind: ScopeInstallation,
		ScopeRevision: 4, CanonicalPolicySHA256: digest, Status: AckRejected,
		ErrorCode: &errorCode, ObservedAt: observedAt,
	}, "ack-request", requestedAt, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	proof, err = base64.RawURLEncoding.DecodeString(acknowledgement.Proof)
	if err != nil || !ed25519.Verify(publicKey, AckProofMessage(acknowledgement), proof) {
		t.Fatal("acknowledgement proof did not verify")
	}

	if _, err := PrepareResolve(ResolveInput{
		InstallationID: installationID, ControlVersion: "1.4.0", ControlProtocolVersion: 1,
		ActiveTargetRevisionID: &targetID,
	}, "resolve-request", requestedAt, privateKey); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("PrepareResolve(unpaired active fields) error = %v", err)
	}
	if _, err := PrepareAcknowledgement(AckInput{
		InstallationID: installationID, TargetRevisionID: targetID, ScopeKind: ScopeInstallation,
		ScopeRevision: 4, CanonicalPolicySHA256: digest, Status: AckRejected, ObservedAt: observedAt,
	}, "ack-request", requestedAt, privateKey); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("PrepareAcknowledgement(rejected without code) error = %v", err)
	}
}
