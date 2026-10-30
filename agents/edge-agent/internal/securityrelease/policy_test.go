package securityrelease

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

const testDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestSecurityHotfixSignedManifestAndRolloutDecisions(t *testing.T) {
	now := time.Date(2026, 8, 8, 8, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := validManifest(now)
	encoded := signAndMarshal(t, &manifest, privateKey)
	verified, err := Verify(encoded, map[string]ed25519.PublicKey{"security-2026": publicKey}, now)
	if err != nil {
		t.Fatal(err)
	}

	selected := Decide(verified, NodeFacts{
		NodeID: "00000000-0000-4000-8000-000000000001", AgentVersion: "1.8.0", RuntimeVersion: "1.27.1.2",
	})
	if selected.Action != ActionDeploy || selected.Reason != ReasonCanaryEligible {
		t.Fatalf("selected canary decision = %+v", selected)
	}
	unselected := Decide(verified, NodeFacts{
		NodeID: "00000000-0000-4000-8000-000000000003", AgentVersion: "1.8.0", RuntimeVersion: "1.27.1.2",
	})
	if unselected.Action != ActionHold || unselected.Reason != ReasonCanaryNotSelected {
		t.Fatalf("unselected canary decision = %+v", unselected)
	}

	manifest.Rollout.Phase = PhaseExpansion
	manifest.Rollout.ExpansionPercentage = 100
	manifest.Rollout.CanaryEvidenceSHA256 = testDigest
	verified, err = Verify(signAndMarshal(t, &manifest, privateKey), map[string]ed25519.PublicKey{"security-2026": publicKey}, now)
	if err != nil {
		t.Fatal(err)
	}
	expanded := Decide(verified, NodeFacts{
		NodeID: "00000000-0000-4000-8000-000000000003", AgentVersion: "1.8.0", RuntimeVersion: "1.27.1.2",
	})
	if expanded.Action != ActionDeploy || expanded.Reason != ReasonExpansionEligible {
		t.Fatalf("expansion decision = %+v", expanded)
	}

	manifest.Rollout.Phase = PhasePaused
	verified, err = Verify(signAndMarshal(t, &manifest, privateKey), map[string]ed25519.PublicKey{"security-2026": publicKey}, now)
	if err != nil {
		t.Fatal(err)
	}
	paused := Decide(verified, NodeFacts{
		NodeID: "00000000-0000-4000-8000-000000000003", AgentVersion: "1.8.0", RuntimeVersion: "1.27.1.2",
	})
	if paused.Action != ActionHold || paused.Reason != ReasonPaused {
		t.Fatalf("paused decision = %+v", paused)
	}

	manifest.Rollout.Phase = PhaseRollback
	manifest.Rollout.ExpansionPercentage = 0
	manifest.Rollout.LastKnownGoodVersion = "1.27.1.2"
	manifest.Rollout.LastKnownGoodImageDigest = "sha256:" + testDigest
	verified, err = Verify(signAndMarshal(t, &manifest, privateKey), map[string]ed25519.PublicKey{"security-2026": publicKey}, now)
	if err != nil {
		t.Fatal(err)
	}
	rollback := Decide(verified, NodeFacts{
		NodeID: "00000000-0000-4000-8000-000000000003", AgentVersion: "1.8.0", RuntimeVersion: "1.31.3.1",
	})
	if rollback.Action != ActionRollback || rollback.Reason != ReasonRollbackRequired {
		t.Fatalf("rollback decision = %+v", rollback)
	}
}

func TestSecurityHotfixRejectsInvalidOrIncompleteReleaseEvidence(t *testing.T) {
	now := time.Date(2026, 8, 8, 8, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*Manifest)
		reason ReasonCode
	}{
		{name: "wrong channel", mutate: func(value *Manifest) { value.Channel = "stable" }, reason: ReasonInvalidManifest},
		{name: "expired", mutate: func(value *Manifest) { value.ExpiresAt = now }, reason: ReasonEvidenceExpired},
		{name: "open advisory", mutate: func(value *Manifest) { value.Advisories[0].Status = AdvisoryOpen }, reason: ReasonAdvisoryOpen},
		{name: "missing protocol", mutate: func(value *Manifest) { value.ProtocolRegressions = value.ProtocolRegressions[1:] }, reason: ReasonProtocolEvidenceMissing},
		{name: "failed protocol", mutate: func(value *Manifest) { value.ProtocolRegressions[0].Status = RegressionFailed }, reason: ReasonProtocolEvidenceMissing},
		{name: "three canaries", mutate: func(value *Manifest) {
			value.Rollout.CanaryNodeIDs = append(value.Rollout.CanaryNodeIDs, "00000000-0000-4000-8000-000000000003")
		}, reason: ReasonInvalidRollout},
		{name: "unordered canaries", mutate: func(value *Manifest) {
			value.Rollout.CanaryNodeIDs[0], value.Rollout.CanaryNodeIDs[1] = value.Rollout.CanaryNodeIDs[1], value.Rollout.CanaryNodeIDs[0]
		}, reason: ReasonInvalidRollout},
		{name: "manual rollback", mutate: func(value *Manifest) { value.Rollout.AutomaticRollback = false }, reason: ReasonInvalidRollout},
		{name: "expansion without canary proof", mutate: func(value *Manifest) {
			value.Rollout.Phase = PhaseExpansion
			value.Rollout.ExpansionPercentage = 25
		}, reason: ReasonInvalidRollout},
		{name: "unbound SBOM", mutate: func(value *Manifest) { value.Evidence.SBOMSHA256 = "" }, reason: ReasonInvalidEvidence},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := validManifest(now)
			test.mutate(&manifest)
			_, err := Verify(signAndMarshal(t, &manifest, privateKey), map[string]ed25519.PublicKey{"security-2026": publicKey}, now)
			if Reason(err) != test.reason {
				t.Fatalf("Verify() error = %v, reason = %q, want %q", err, Reason(err), test.reason)
			}
		})
	}

	manifest := validManifest(now)
	encoded := signAndMarshal(t, &manifest, privateKey)
	encoded = []byte(strings.Replace(string(encoded), `"target_runtime_version":"1.31.3.1"`, `"target_runtime_version":"1.31.3.2"`, 1))
	if _, err := Verify(encoded, map[string]ed25519.PublicKey{"security-2026": publicKey}, now); Reason(err) != ReasonInvalidSignature {
		t.Fatalf("tampered signature reason = %q, error = %v", Reason(err), err)
	}
	canonical := signAndMarshal(t, &manifest, privateKey)
	noncanonical := append([]byte(" "), canonical...)
	if _, err := Verify(noncanonical, map[string]ed25519.PublicKey{"security-2026": publicKey}, now); Reason(err) != ReasonInvalidManifest {
		t.Fatalf("noncanonical reason = %q, error = %v", Reason(err), err)
	}
}

func TestSecurityHotfixCompatibilityAndIdempotentReasons(t *testing.T) {
	now := time.Date(2026, 8, 8, 8, 0, 0, 0, time.UTC)
	manifest := validManifest(now)
	tests := []struct {
		name   string
		facts  NodeFacts
		action Action
		reason ReasonCode
	}{
		{name: "agent too old", facts: NodeFacts{NodeID: manifest.Rollout.CanaryNodeIDs[0], AgentVersion: "1.6.9", RuntimeVersion: "1.27.1.2"}, action: ActionHold, reason: ReasonAgentIncompatible},
		{name: "runtime mismatch", facts: NodeFacts{NodeID: manifest.Rollout.CanaryNodeIDs[0], AgentVersion: "1.8.0", RuntimeVersion: "1.25.3.2"}, action: ActionHold, reason: ReasonRuntimeMismatch},
		{name: "already active", facts: NodeFacts{NodeID: manifest.Rollout.CanaryNodeIDs[0], AgentVersion: "1.8.0", RuntimeVersion: "1.31.3.1"}, action: ActionHold, reason: ReasonAlreadyActive},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision := Decide(manifest, test.facts)
			if decision.Action != test.action || decision.Reason != test.reason {
				t.Fatalf("Decide() = %+v", decision)
			}
		})
	}
}

func validManifest(now time.Time) Manifest {
	protocols := make([]ProtocolRegression, 0, len(requiredProtocolRegressions))
	for _, name := range requiredProtocolRegressions {
		protocols = append(protocols, ProtocolRegression{Name: name, Status: RegressionPassed, EvidenceSHA256: testDigest})
	}
	return Manifest{
		Schema: Schema, ReleaseID: "00000000-0000-4000-8000-000000000010", ReleaseSequence: 10,
		Channel: ChannelSecurityHotfix, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
		CurrentRuntimeVersion: "1.27.1.2", TargetRuntimeVersion: "1.31.3.1",
		Compatibility: Compatibility{MinAgentVersion: "1.7.0", MaxAgentVersion: "1.9.0"},
		Evidence: Evidence{
			SourceSHA256: testDigest, BaseImageDigest: "sha256:" + testDigest,
			RuntimeImageDigest: "sha256:" + testDigest, PatchManifestSHA256: testDigest,
			SBOMSHA256: testDigest, ProvenanceSHA256: testDigest,
			AdvisorySnapshotSHA256: testDigest, SignatureBundleSHA256: testDigest,
		},
		Advisories: []Advisory{{
			ID: "CVE-2026-42533", Status: AdvisoryPatched,
			UpstreamURL: "https://nginx.org/en/security_advisories.html", FixedVersion: "1.31.3",
			PatchReference: strings.Repeat("a", 40), RegressionTest: "rewrite-boundary", EvidenceSHA256: testDigest,
		}},
		ProtocolRegressions: protocols,
		Rollout: RolloutPolicy{
			Phase: PhaseCanary,
			CanaryNodeIDs: []string{
				"00000000-0000-4000-8000-000000000001",
				"00000000-0000-4000-8000-000000000002",
			},
			AutomaticRollback: true,
		},
	}
}

func signAndMarshal(t *testing.T, manifest *Manifest, privateKey ed25519.PrivateKey) []byte {
	t.Helper()
	if err := Sign(manifest, "security-2026", privateKey); err != nil {
		t.Fatal(err)
	}
	encoded, err := Marshal(*manifest)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
