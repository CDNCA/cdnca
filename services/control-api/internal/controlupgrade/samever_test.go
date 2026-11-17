package controlupgrade

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

type rereleaseReaderFunc func(context.Context, string, string, int, uint64) (MaintenanceCandidate, error)

func (f rereleaseReaderFunc) ReadCandidate(ctx context.Context, component, version string, protocol int,
	sequence uint64) (MaintenanceCandidate, error) {
	return f(ctx, component, version, protocol, sequence)
}

func rereleaseCapabilityFact(t *testing.T, nodeID string, sequence uint64, sameVersion bool) rolloutNodeCapabilityFact {
	t.Helper()
	features := []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE, ApiVersion: 1}}
	if sameVersion {
		features = append(features, &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_SAME_VERSION_UPGRADE, ApiVersion: 1})
	}
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(&agentv1.AgentCapabilities{
		AgentVersion: "1.4.0", BuildId: "build-1", OperatingSystem: "linux", Architecture: "amd64",
		Features: features, InstalledReleaseSequence: sequence})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	return rolloutNodeCapabilityFact{NodeID: nodeID, PresenceVersion: "1.4.0", ProtocolVersion: 2,
		CapabilityBytes: encoded, CapabilitySHA256: digest[:]}
}

// The cohort carries the highest installed release_sequence only when every
// node declares SAME_VERSION_UPGRADE with one.
func TestRolloutCohortInstalledReleaseSequence(t *testing.T) {
	for _, test := range []struct {
		name  string
		facts []rolloutNodeCapabilityFact
		want  uint64
	}{
		{"all capable", []rolloutNodeCapabilityFact{rereleaseCapabilityFact(t, planID(1), 7, true),
			rereleaseCapabilityFact(t, planID(2), 9, true)}, 9},
		{"one without capability", []rolloutNodeCapabilityFact{rereleaseCapabilityFact(t, planID(1), 7, true),
			rereleaseCapabilityFact(t, planID(2), 9, false)}, 0},
		{"one without sequence", []rolloutNodeCapabilityFact{rereleaseCapabilityFact(t, planID(1), 7, true),
			rereleaseCapabilityFact(t, planID(2), 0, true)}, 0},
		{"older agent", []rolloutNodeCapabilityFact{rereleaseCapabilityFact(t, planID(1), 0, false)}, 0},
	} {
		cohort, err := rolloutCohortFromFacts(test.facts)
		if err != nil || cohort.CurrentReleaseSequence != test.want {
			t.Errorf("%s: cohort sequence = %d (%v), want %d", test.name, cohort.CurrentReleaseSequence, err, test.want)
		}
	}
}

// A same-version candidate is shown as available only for a re-release above
// the installed release_sequence the console asked with.
func TestMaintenanceCandidateRerelease(t *testing.T) {
	now := time.Unix(1800000000, 0).UTC()
	expires := now.Add(time.Minute)
	grant := entitlementguard.VersionGrant{Channel: "stable", MinVersion: "2.0.0", MaxVersion: "3.0.0"}
	authorization := MaintenanceAuthorization{State: "valid", Reason: "eligible", Channel: "stable"}
	for _, test := range []struct {
		name            string
		installed       uint64
		target          uint64
		state, reason   string
		wantState       string
		wantSequenceSet bool
	}{
		{"higher", 7, 9, "available", "rerelease_available", "available", true},
		{"equal", 9, 9, "available", "rerelease_available", "unavailable", false},
		{"lower", 9, 7, "available", "rerelease_available", "unavailable", false},
		{"not asked", 0, 9, "available", "rerelease_available", "unavailable", false},
		{"up to date", 9, 9, "up_to_date", "same_version", "up_to_date", true},
	} {
		var asked uint64
		reader := rereleaseReaderFunc(func(_ context.Context, _, _ string, _ int, sequence uint64) (MaintenanceCandidate, error) {
			asked = sequence
			version, target := "2.4.1", test.target
			return MaintenanceCandidate{State: test.state, Reason: test.reason, Version: &version, ExpiresAt: &expires,
				Channel: "stable", ReleaseSequence: &target}, nil
		})
		got := maintenanceReadCandidate(t.Context(), reader, "edge-agent", "2.4.1", 1, test.installed, authorization, grant,
			func() time.Time { return now })
		if asked != test.installed || got.State != test.wantState || (got.ReleaseSequence != nil) != test.wantSequenceSet {
			t.Errorf("%s: asked %d, got %+v", test.name, asked, got)
		}
		status := maintenanceNodeEligibility(MaintenanceNodeStatus{Candidate: got,
			Runtime: MaintenanceRuntimeState{Ready: true, Reason: "ready"}})
		if status.Eligible != (test.wantState == "available") {
			t.Errorf("%s: eligible = %v", test.name, status.Eligible)
		}
	}
}

func rereleasePlanInput(t *testing.T) RolloutPlanInput {
	t.Helper()
	input := validRolloutPlanInput()
	input.TargetVersion = input.CurrentVersion
	input.CurrentReleaseSequence = input.ReleaseSequence - 1
	input.RollbackGrantDigest, input.RollbackReleaseSequence = "", 0
	input.RollbackArtifactID, input.RollbackSHA256Digest, input.RollbackArtifactSizeBytes = "", "", 0
	input.Safety.RollbackAvailable = false
	return input
}

// A re-release plan starts without the rollback blocker, is schema v3, and
// never begins a control-issued rollback.
func TestRereleaseRolloutPlan(t *testing.T) {
	plan, err := NewRolloutPlan(rereleasePlanInput(t))
	if err != nil {
		t.Fatalf("re-release plan: %v", err)
	}
	if plan.SchemaVersion != RolloutPlanSchemaVersion || len(plan.Blockers) != 0 || !validRolloutPlan(plan) {
		t.Fatalf("re-release plan schema=%d blockers=%v valid=%v", plan.SchemaVersion, plan.Blockers, validRolloutPlan(plan))
	}
	started := mustPlanCommand(t, plan, planCommand(PlanStart, plan.Revision, "start_requested")).Plan
	failure := currentPlanHealth(started, started.Batches[0].NodeIDs[0], false)
	failure.Code = "health_probe_failed"
	failed := mustPlanHealth(t, started, failure).Plan
	if failed.State != PlanPaused || len(failed.RollbackBatches) != 0 {
		t.Fatalf("re-release failure state=%s rollback batches=%d", failed.State, len(failed.RollbackBatches))
	}
	if _, err := ApplyPlanCommand(failed, planCommand(PlanRollback, failed.Revision, "operator_requested")); !errors.Is(err, ErrPlanBlocked) {
		t.Fatalf("manual re-release rollback error = %v", err)
	}
	for name, mutate := range map[string]func(*RolloutPlanInput){
		"equal sequence":     func(input *RolloutPlanInput) { input.CurrentReleaseSequence = input.ReleaseSequence },
		"version change":     func(input *RolloutPlanInput) { input.TargetVersion = validRolloutPlanInput().TargetVersion },
		"rollback available": func(input *RolloutPlanInput) { input.Safety.RollbackAvailable = true },
		"same version no sequence": func(input *RolloutPlanInput) {
			input.CurrentReleaseSequence = 0
		},
	} {
		input := rereleasePlanInput(t)
		mutate(&input)
		if _, err := NewRolloutPlan(input); !errors.Is(err, ErrInvalidPlan) {
			t.Errorf("%s: error = %v, want invalid plan", name, err)
		}
	}
	// Plans of other kinds keep their snapshot bytes (field omitted).
	encoded, err := json.Marshal(mustRolloutPlan(t))
	if err != nil || bytes.Contains(encoded, []byte("CurrentReleaseSequence")) {
		t.Fatalf("ordinary plan snapshot mentions CurrentReleaseSequence (%v)", err)
	}
}

// A re-release node reports the build it replaced as last known good
// (updater healthGate); the plan has no rollback digest, so healthy only needs a
// last known good other than the target. Before the fix every healthy was refused.
func TestRereleaseHealthyAcceptsReplacedBuild(t *testing.T) {
	plan, err := NewRolloutPlan(rereleasePlanInput(t))
	if err != nil {
		t.Fatal(err)
	}
	started := mustPlanCommand(t, plan, planCommand(PlanStart, plan.Revision, "start_requested")).Plan
	node := started.Batches[0].NodeIDs[0]
	withLastKnownGood := func(digest string) PlanHealthEvent {
		health := currentPlanHealth(started, node, true)
		health.ActiveEvidence.LastKnownGoodArtifactSHA256 = digest
		health.ActiveEvidence.EvidenceSHA256 =
			activeProbeEvidenceDigest(health.InstallerTransactionID, *health.ActiveEvidence)
		return health
	}
	replaced := planDigest(0x5a)
	healthy := mustPlanHealth(t, started, withLastKnownGood(replaced)).Plan
	if healthy.NodeStates[node] != NodeHealthy || !validRolloutPlan(healthy) {
		t.Fatalf("re-release healthy node=%s valid=%v", healthy.NodeStates[node], validRolloutPlan(healthy))
	}
	targetHex, _ := base64.RawURLEncoding.DecodeString(started.SHA256Digest)
	for name, health := range map[string]PlanHealthEvent{
		"last known good is the target":     withLastKnownGood(started.SHA256Digest),
		"last known good is the target hex": withLastKnownGood(hex.EncodeToString(targetHex)),
		"last known good empty":             withLastKnownGood(""),
	} {
		if _, err := ApplyPlanHealth(started, health); !errors.Is(err, ErrInvalidPlanEvent) {
			t.Errorf("%s: error = %v, want invalid event", name, err)
		}
	}
	wrongActive := withLastKnownGood(replaced)
	wrongActive.ActiveEvidence.ActiveArtifactSHA256 = replaced
	wrongActive.ActiveEvidence.LastKnownGoodArtifactSHA256 = planDigest(0x5b)
	wrongActive.ActiveEvidence.EvidenceSHA256 =
		activeProbeEvidenceDigest(wrongActive.InstallerTransactionID, *wrongActive.ActiveEvidence)
	if _, err := ApplyPlanHealth(started, wrongActive); !errors.Is(err, ErrInvalidPlanEvent) {
		t.Fatalf("re-release healthy on another build error = %v", err)
	}
	// Cross-version plans still require last known good == rollback artifact.
	cross := mustRolloutPlan(t)
	crossStarted := mustPlanCommand(t, cross, planCommand(PlanStart, cross.Revision, "start_requested")).Plan
	crossHealth := currentPlanHealth(crossStarted, crossStarted.Batches[0].NodeIDs[0], true)
	crossHealth.ActiveEvidence.LastKnownGoodArtifactSHA256 = replaced
	crossHealth.ActiveEvidence.EvidenceSHA256 =
		activeProbeEvidenceDigest(crossHealth.InstallerTransactionID, *crossHealth.ActiveEvidence)
	if _, err := ApplyPlanHealth(crossStarted, crossHealth); !errors.Is(err, ErrInvalidPlanEvent) {
		t.Fatalf("cross-version healthy with another last known good error = %v", err)
	}
}

// The parent grant request names the installed sequence under proof v3.
func TestLicenseClientParentGrantReleaseSequenceProofV3(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x73}, ed25519.SeedSize))
	installationID := uuid.MustParse("00000000-0000-4000-8000-000000000073")
	transport := roundTripUpgradeFunc(func(request *http.Request) (*http.Response, error) {
		var body struct {
			Component              string `json:"component"`
			CurrentVersion         string `json:"current_version"`
			ProtocolVersion        int    `json:"protocol_version"`
			Proof                  string `json:"proof"`
			CurrentReleaseSequence uint64 `json:"current_release_sequence"`
		}
		decoder := json.NewDecoder(request.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&body); err != nil || body.CurrentReleaseSequence != 41 {
			t.Fatalf("body = %#v, %v", body, err)
		}
		proof, _ := base64.RawURLEncoding.DecodeString(body.Proof)
		message := upgradeLengthPrefixedDigest("cdnca-upgrade-grant-request-proof/v3", request.Header.Get("Idempotency-Key"),
			installationID.String(), body.Component, body.CurrentVersion, strconv.Itoa(body.ProtocolVersion), "41")
		if !ed25519.Verify(privateKey.Public().(ed25519.PublicKey), message, proof) {
			t.Fatal("v3 proof does not bind current_release_sequence")
		}
		return licenseResponse(http.StatusConflict, `{"code":"upgrade_target_blocked","reason_code":"same_version","request_id":"r"}`+"\n"), nil
	})
	client, err := NewLicenseClient("https://license.example.test", transport, installationID, privateKey, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.IssueParentGrant(context.Background(), ParentGrantRequest{IdempotencyKey: "parent-v3",
		CurrentVersion: "1.0.35", ProtocolVersion: 1, CurrentReleaseSequence: 41})
	var blocked *UpgradeTargetBlockedError
	if !errors.As(err, &blocked) || blocked.Reason != "same_version" {
		t.Fatalf("blocked error = %v", err)
	}
	if _, err := client.IssueParentGrant(context.Background(), ParentGrantRequest{IdempotencyKey: "parent-v3",
		CurrentVersion: "1.0.35", ProtocolVersion: 1, CurrentReleaseSequence: 41,
		RequestedArtifactID: "00000000-0000-4000-8000-0000000000a1"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("sequence with requested artifact = %v", err)
	}
}
