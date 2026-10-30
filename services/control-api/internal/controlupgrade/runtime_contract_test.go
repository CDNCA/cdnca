package controlupgrade

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/google/uuid"
)

func TestCreateRolloutRequestValidationAndDigestContract(t *testing.T) {
	actor := Actor{UserID: uuid.MustParse(planID(901)), ScopeID: uuid.MustParse(planID(902)), ScopeKind: "platform"}
	installationID := uuid.MustParse(planID(903))
	request := CreateRolloutRequest{
		CreateRolloutBody: CreateRolloutBody{Schema: "cdnca.control-upgrade-rollout.create/v1",
			NodeIDs:       []string{planID(1), planID(2), planID(3)},
			CanaryNodeIDs: []string{planID(1)}, BatchSize: 2, AutomaticRollback: true},
		IdempotencyKey: "create.rollout.1", RequestID: "create-rollout-1",
	}
	if err := validateCreateRolloutRequest(request); err != nil {
		t.Fatalf("valid create request error = %v", err)
	}
	body := CreateRolloutBody{Schema: request.Schema, NodeIDs: request.NodeIDs,
		CanaryNodeIDs: request.CanaryNodeIDs, BatchSize: request.BatchSize,
		AutomaticRollback: request.AutomaticRollback}
	wantDocument, err := json.Marshal(struct {
		Domain         string            `json:"domain"`
		Operation      string            `json:"operation"`
		ActorScopeID   string            `json:"actor_scope_id"`
		ActorUserID    string            `json:"actor_user_id"`
		InstallationID string            `json:"installation_id"`
		PlanID         string            `json:"plan_id"`
		Body           CreateRolloutBody `json:"body"`
	}{"cdnca.control-upgrade-rollout.request/v1", "create", actor.ScopeID.String(), actor.UserID.String(),
		installationID.String(), "", body})
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(wantDocument)
	got, encoded, err := rolloutRequestDigest(actor, installationID, "create", "", body)
	if err != nil || got != want || !reflect.DeepEqual(encoded, wantDocument) {
		t.Fatalf("rolloutRequestDigest() = (%x,%q,%v), want (%x,%q)", got, encoded, err, want, wantDocument)
	}

	for _, test := range []struct {
		name   string
		mutate func(*CreateRolloutRequest)
	}{
		{"schema", func(value *CreateRolloutRequest) { value.Schema += "x" }},
		{"empty nodes", func(value *CreateRolloutRequest) { value.NodeIDs = nil }},
		{"unsorted nodes", func(value *CreateRolloutRequest) {
			value.NodeIDs[0], value.NodeIDs[1] = value.NodeIDs[1], value.NodeIDs[0]
		}},
		{"duplicate nodes", func(value *CreateRolloutRequest) { value.NodeIDs[1] = value.NodeIDs[0] }},
		{"empty canary", func(value *CreateRolloutRequest) { value.CanaryNodeIDs = nil }},
		{"more than two canaries", func(value *CreateRolloutRequest) {
			value.CanaryNodeIDs = append([]string(nil), value.NodeIDs...)
		}},
		{"foreign canary", func(value *CreateRolloutRequest) { value.CanaryNodeIDs = []string{planID(9)} }},
		{"batch zero", func(value *CreateRolloutRequest) { value.BatchSize = 0 }},
		{"batch too large", func(value *CreateRolloutRequest) { value.BatchSize = 101 }},
		{"automatic rollback false", func(value *CreateRolloutRequest) { value.AutomaticRollback = false }},
		{"idempotency whitespace", func(value *CreateRolloutRequest) { value.IdempotencyKey = " bad" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := request
			candidate.NodeIDs = append([]string(nil), request.NodeIDs...)
			candidate.CanaryNodeIDs = append([]string(nil), request.CanaryNodeIDs...)
			test.mutate(&candidate)
			if !errors.Is(validateCreateRolloutRequest(candidate), ErrInvalidInput) {
				t.Fatalf("invalid create request accepted: %#v", candidate)
			}
		})
	}
}

func TestRolloutPlanSchemaV2BindsParentGrantProfilesAndArtifactSizes(t *testing.T) {
	now := time.Date(2026, 8, 5, 0, 0, 0, 0, time.UTC)
	input := rolloutPlanV2Input(t, now)
	plan, err := NewRolloutPlan(input)
	if err != nil {
		t.Fatalf("NewRolloutPlan() error = %v", err)
	}
	if plan.SchemaVersion != 2 || plan.ParentGrantID != input.ParentGrantID ||
		plan.ParentGrantExpiresAt != input.ParentGrantExpiresAt || plan.ArtifactSizeBytes != input.ArtifactSizeBytes ||
		!reflect.DeepEqual(plan.ForwardProfile, input.ForwardProfile) ||
		!reflect.DeepEqual(plan.RollbackProfile, input.RollbackProfile) {
		t.Fatalf("schema v2 plan lost immutable grant/profile facts: %#v", plan)
	}
	for name, mutate := range map[string]func(*RolloutPlan){
		"parent id":       func(value *RolloutPlan) { value.ParentGrantID = uuid.Nil.String() },
		"parent expiry":   func(value *RolloutPlan) { value.ParentGrantExpiresAt = 0 },
		"bundle id":       func(value *RolloutPlan) { value.ArtifactBundleID = uuid.Nil.String() },
		"bundle digest":   func(value *RolloutPlan) { value.ArtifactBundleSHA256 = "not-a-digest" },
		"bundle deadline": func(value *RolloutPlan) { value.CommandIssuanceNotAfter = 0 },
		"artifact size":   func(value *RolloutPlan) { value.ArtifactSizeBytes = 0 },
		"forward profile": func(value *RolloutPlan) { value.ForwardProfile.Platform = "" },
		"rollback profile": func(value *RolloutPlan) {
			value.RollbackProfile.Rollout.Percentage = 0
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := cloneRolloutPlan(plan)
			mutate(&candidate)
			if validRolloutPlan(candidate) {
				t.Fatalf("mutated schema v2 plan accepted: %#v", candidate)
			}
		})
	}
}

func TestRolloutPlanSchemaV3PreservesDistinctArtifactAndExecutionSequences(t *testing.T) {
	now := time.Date(2026, 8, 5, 0, 0, 0, 0, time.UTC)
	input := rolloutPlanV2Input(t, now)
	input.ReleaseSequence = 12
	input.RollbackReleaseSequence = 4
	for groupIndex := range input.Groups {
		for targetIndex := range input.Groups[groupIndex].Targets {
			input.Groups[groupIndex].Targets[targetIndex].ProtocolVersion = 3
		}
	}
	plan, err := NewRolloutPlan(input)
	if err != nil {
		t.Fatalf("NewRolloutPlan() error = %v", err)
	}
	if plan.SchemaVersion != 3 || plan.ReleaseSequence != input.ReleaseSequence ||
		plan.RollbackReleaseSequence != input.RollbackReleaseSequence {
		t.Fatalf("schema v3 lost dual sequence facts: %#v", plan)
	}
	// Real nodes negotiate gateway session protocol major 1; that must not block a v3 plan.
	sessionV1 := input
	sessionV1.Groups = make([]PlanGroup, len(input.Groups))
	for groupIndex, group := range input.Groups {
		sessionV1.Groups[groupIndex] = group
		sessionV1.Groups[groupIndex].Targets = append([]PlanTarget(nil), group.Targets...)
		for targetIndex := range sessionV1.Groups[groupIndex].Targets {
			sessionV1.Groups[groupIndex].Targets[targetIndex].ProtocolVersion = 1
		}
	}
	sessionPlan, err := NewRolloutPlan(sessionV1)
	if err != nil || sessionPlan.SchemaVersion != 3 || !validRolloutPlan(sessionPlan) {
		t.Fatalf("schema v3 rejected session-protocol-1 nodes: schema=%d err=%v", sessionPlan.SchemaVersion, err)
	}
}

func rolloutPlanV2Input(t *testing.T, now time.Time) RolloutPlanInput {
	t.Helper()
	forward := CommandProfile{
		Platform: "linux", Architecture: "amd64",
		Compatibility: entitlement.UpgradeExecutionCompatibility{MinAgentVersion: "1.0.0", MaxAgentVersion: "2.0.0"},
		Health: entitlement.UpgradeExecutionHealthPolicy{Command: []string{"{artifact}", "--version"},
			ActivationTimeoutNanoseconds: int64(30 * time.Second), ObservationWindowNanoseconds: int64(time.Minute),
			IntervalNanoseconds: int64(time.Second), ProbeTimeoutNanoseconds: int64(500 * time.Millisecond),
			RequiredConsecutiveSuccesses: 3},
		Rollout:  entitlement.UpgradeExecutionRolloutPolicy{Percentage: 100},
		Rollback: entitlement.UpgradeExecutionRollbackPolicy{Automatic: true},
	}
	rollback := forward
	return RolloutPlanInput{
		ID: planID(50), ParentGrantID: planID(51), GrantDigest: planDigest(0x51),
		ParentGrantExpiresAt: now.Add(15 * time.Minute).Unix(), ReleaseSequence: 7,
		ArtifactBundleID: planID(54), ArtifactBundleSHA256: planDigest(0x55),
		CommandIssuanceNotAfter: now.Add(6 * time.Hour).Unix(),
		Component:               "edge-agent", ArtifactID: planID(52), SHA256Digest: planDigest(0x52), ArtifactSizeBytes: 4096,
		RollbackGrantDigest: planDigest(0x51), RollbackReleaseSequence: 7,
		RollbackArtifactID: planID(53), RollbackSHA256Digest: planDigest(0x54), RollbackArtifactSizeBytes: 2048,
		CurrentVersion: "1.0.0", TargetVersion: "2.0.0", AutomaticRollback: true,
		ForwardProfile: forward, RollbackProfile: rollback,
		Safety: PlanSafety{MinAgentVersion: "1.0.0", MaxAgentVersion: "2.0.0", ProtocolMin: 1,
			ProtocolMax: 3, RollbackAvailable: true},
		Groups: []PlanGroup{{ID: "canary", Canary: true, BatchSize: 1,
			Targets: []PlanTarget{{NodeID: planID(1), AgentVersion: "1.0.0", ProtocolVersion: 2}}},
			{ID: "wave", BatchSize: 1, Targets: []PlanTarget{{NodeID: planID(2), AgentVersion: "1.0.0", ProtocolVersion: 2}}}},
	}
}

func TestStableCommandMessageIDBindsExactWire(t *testing.T) {
	payload := []byte(`{"schema":"cdnca.edge.upgrade.command/v1"}`)
	digest := sha256.Sum256(payload)
	want := "control-upgrade-v1-" + hex.EncodeToString(digest[:])
	if got := commandMessageID(payload); got != want {
		t.Fatalf("commandMessageID() = %q, want %q", got, want)
	}
	if commandMessageID(append(payload, ' ')) == want {
		t.Fatal("different command wire reused the same NATS Msg-Id")
	}
}

func TestPostgresBigintRevisionBoundary(t *testing.T) {
	plan := mustRolloutPlan(t)
	command := planCommand(PlanStart, plan.Revision, "start_requested")
	command.ExpectedRevision = maxRolloutRevision + 1
	if _, err := ApplyPlanCommand(plan, command); !errors.Is(err, ErrInvalidPlanCommand) {
		t.Fatalf("oversized command revision error = %v", err)
	}

	actor := Actor{UserID: uuid.MustParse(planID(901)), ScopeID: uuid.MustParse(planID(902)), ScopeKind: "platform"}
	action := RolloutActionRequest{RolloutActionBody: RolloutActionBody{
		ExpectedRevision: maxRolloutRevision + 1, Reason: "start_requested"},
		PlanID: plan.ID, Operation: string(PlanStart), IdempotencyKey: "revision.boundary", RequestID: "revision-boundary"}
	if err := validateRolloutActionRequest(actor, action); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("oversized action revision error = %v", err)
	}

	identity := RolloutIdentity{ActorScopeID: planID(903), ActorUserID: planID(904), InstallationID: planID(905)}
	receipt := RolloutStatusReceipt{StatusID: planID(906), StatusRevision: 1, CommandID: planID(907),
		PlanID: plan.ID, PlanRevision: maxRolloutRevision + 1, InstallationID: identity.InstallationID,
		NodeID: planID(908), CommandSHA256: hex.EncodeToString(make([]byte, sha256.Size)),
		StatusBytes: []byte(`{}`), StatusSHA256: hex.EncodeToString(make([]byte, sha256.Size)),
		State: "accepted", ObservedAt: time.Now()}
	if validRolloutStatus(identity, receipt) {
		t.Fatal("oversized status plan revision accepted")
	}
}

func planID(value int) string {
	return nodeID(value)
}
