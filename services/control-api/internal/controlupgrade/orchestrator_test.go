package controlupgrade

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/google/uuid"
)

func TestRolloutProfilesUseProductionEdgeAgentContract(t *testing.T) {
	policy := RolloutProfilePolicy{ActivationTimeout: 5 * time.Minute, ObservationWindow: 2 * time.Minute,
		HealthInterval: 10 * time.Second, ProbeTimeout: 3 * time.Second, RequiredConsecutiveSuccesses: 3}
	cohort := RolloutTargetCohort{Platform: "linux", Architecture: "amd64", CurrentVersion: "1.2.3",
		ProtocolVersion: 2}
	profiles := rolloutProfiles(cohort, "2.0.0", policy)
	wantHealth := entitlement.UpgradeExecutionHealthPolicy{Command: []string{"{artifact}", "--version"},
		ActivationTimeoutNanoseconds: int64(policy.ActivationTimeout),
		ObservationWindowNanoseconds: int64(policy.ObservationWindow),
		IntervalNanoseconds:          int64(policy.HealthInterval), ProbeTimeoutNanoseconds: int64(policy.ProbeTimeout),
		RequiredConsecutiveSuccesses: policy.RequiredConsecutiveSuccesses}
	for name, profile := range map[string]CommandProfile{"forward": profiles.forward, "rollback": profiles.rollback} {
		if profile.Platform != cohort.Platform || profile.Architecture != cohort.Architecture ||
			!reflect.DeepEqual(profile.Health, wantHealth) || profile.Rollout.Percentage != 100 ||
			!profile.Rollback.Automatic || !validCommandProfile(profile) {
			t.Fatalf("%s profile = %#v", name, profile)
		}
	}
	if profiles.forward.Compatibility.MinAgentVersion != cohort.CurrentVersion ||
		profiles.forward.Compatibility.MaxAgentVersion != cohort.CurrentVersion ||
		profiles.rollback.Compatibility.MinAgentVersion != "2.0.0" ||
		profiles.rollback.Compatibility.MaxAgentVersion != "2.0.0" {
		t.Fatalf("compatibility = %#v / %#v", profiles.forward.Compatibility, profiles.rollback.Compatibility)
	}
	bad := profiles.forward
	bad.Health.Command = []string{"{artifact}", "health"}
	if validCommandProfile(bad) {
		t.Fatal("accepted the nonexistent production edge-agent health subcommand")
	}
}

func TestNewRolloutPlanFromV3ArtifactsPreservesPhysicalSequences(t *testing.T) {
	now := time.Date(2026, 8, 6, 0, 0, 0, 0, time.UTC)
	parent := entitlement.UpgradeGrant{GrantID: planID(700), ExpiresAt: now.Add(time.Hour).Unix()}
	forward := entitlement.ArtifactManifestV2{Schema: entitlement.ArtifactManifestV3Schema,
		ArtifactID: planID(701), ArtifactSizeBytes: 4096,
		SHA256Digest: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), ProtocolMin: 3, ProtocolMax: 3,
		ReleaseSequence: 12}
	rollback := entitlement.ArtifactManifestV2{Schema: entitlement.ArtifactManifestV3Schema,
		ArtifactID: planID(702), ArtifactSizeBytes: 2048,
		SHA256Digest: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), ProtocolMin: 3, ProtocolMax: 3,
		ReleaseSequence: 4}
	bundle := entitlement.UpgradePlanArtifactBundle{Schema: entitlement.UpgradePlanArtifactBundleV2Schema,
		BundleID: planID(703), Component: "edge-agent",
		CurrentVersion: "1.0.0", Version: "2.0.0", ProtocolVersion: 3,
		CommandIssuanceNotAfter: now.Add(30 * time.Minute).Unix(),
		Forward:                 entitlement.UpgradePlanArtifact{Manifest: forward}, Rollback: entitlement.UpgradePlanArtifact{Manifest: rollback}}
	binding := PlanGrantBinding{ParentGrantSHA256: planDigest(0x31), ArtifactBundleSHA256: planDigest(0x32)}
	cohort := RolloutTargetCohort{Platform: "linux", Architecture: "amd64", CurrentVersion: "1.0.0",
		ProtocolVersion: 3, Targets: []PlanTarget{{NodeID: planID(704), AgentVersion: "1.0.0", ProtocolVersion: 3}}}
	request := CreateRolloutRequest{CreateRolloutBody: CreateRolloutBody{CanaryNodeIDs: []string{planID(704)}, BatchSize: 1}}
	profiles := rolloutProfiles(cohort, bundle.Version, RolloutProfilePolicy{ActivationTimeout: time.Minute,
		ObservationWindow: time.Minute, HealthInterval: time.Second, ProbeTimeout: time.Second,
		RequiredConsecutiveSuccesses: 1})
	plan, err := newRolloutPlanFromArtifacts(planID(705), parent, bundle, binding, cohort, request, profiles)
	if err != nil {
		t.Fatalf("newRolloutPlanFromArtifacts() error = %v", err)
	}
	if plan.SchemaVersion != 3 || plan.ReleaseSequence != forward.ReleaseSequence ||
		plan.RollbackReleaseSequence != rollback.ReleaseSequence {
		t.Fatalf("rollout plan lost physical sequences: %#v", plan)
	}
}

func TestCreateRolloutSeparatesUnavailableRuntimeFromInvalidRequest(t *testing.T) {
	service := &Service{store: &Store{}}
	if _, err := service.CreateRollout(context.Background(), Actor{}, CreateRolloutRequest{}); !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("disabled runtime error = %v", err)
	}
	service.rollout = validTestRolloutRuntime(t)
	if _, err := service.CreateRollout(context.Background(), Actor{}, CreateRolloutRequest{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid request error = %v", err)
	}
}

func TestCreateRolloutCompletedReplaySkipsMutableCohortAndLicense(t *testing.T) {
	actor, request := testCreateRolloutInput()
	licenseCalls := 0
	service := testCreateRolloutService(t, func(*http.Request) (*http.Response, error) {
		licenseCalls++
		return nil, errors.New("unexpected license call")
	})
	want := RolloutWriteResult{Detail: RolloutDetail{RolloutSummary: RolloutSummary{ID: nodeID(801)}}, Replayed: true}
	prepareCalls := 0
	service.rollout.createPreparation = rolloutCreatePreparationStub{
		prepare: func(context.Context, Actor, RolloutIdentity, CreateRolloutRequest,
			[32]byte) (CreateRolloutIntent, RolloutWriteResult, error) {
			prepareCalls++
			return CreateRolloutIntent{}, want, nil
		},
		load: func(context.Context, Actor, []string) (RolloutTargetCohort, error) {
			t.Fatal("completed replay loaded the mutable target cohort")
			return RolloutTargetCohort{}, nil
		},
	}

	got, err := service.CreateRollout(t.Context(), actor, request)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("completed replay = (%#v, %v), want %#v", got, err, want)
	}
	if prepareCalls != 1 || licenseCalls != 0 {
		t.Fatalf("completed replay calls = prepare %d, license %d", prepareCalls, licenseCalls)
	}
}

func TestCreateRolloutPrepareDenialPrecedesReplayAndCohort(t *testing.T) {
	actor, request := testCreateRolloutInput()
	licenseCalls := 0
	service := testCreateRolloutService(t, func(*http.Request) (*http.Response, error) {
		licenseCalls++
		return nil, errors.New("unexpected license call")
	})
	prepareCalls := 0
	service.rollout.createPreparation = rolloutCreatePreparationStub{
		prepare: func(context.Context, Actor, RolloutIdentity, CreateRolloutRequest,
			[32]byte) (CreateRolloutIntent, RolloutWriteResult, error) {
			prepareCalls++
			return CreateRolloutIntent{}, RolloutWriteResult{Replayed: true}, ErrPermissionDenied
		},
		load: func(context.Context, Actor, []string) (RolloutTargetCohort, error) {
			t.Fatal("permission-denied prepare loaded the target cohort")
			return RolloutTargetCohort{}, nil
		},
	}

	if _, err := service.CreateRollout(t.Context(), actor, request); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("permission-denied prepare error = %v", err)
	}
	if prepareCalls != 1 || licenseCalls != 0 {
		t.Fatalf("permission-denied calls = prepare %d, license %d", prepareCalls, licenseCalls)
	}
}

func TestCreateRolloutNoncompletedIntentsStillLoadCohort(t *testing.T) {
	actor, request := testCreateRolloutInput()
	for _, test := range []struct {
		name        string
		state       string
		wantLicense int
		wantError   error
	}{
		{name: "fresh", state: createIntentReserved, wantLicense: 1, wantError: ErrLicenseOutcomeUnknown},
		{name: "reserved", state: createIntentReserved, wantLicense: 1, wantError: ErrLicenseOutcomeUnknown},
		{name: "acquired", state: createIntentAcquired, wantError: ErrGrantInvalid},
	} {
		t.Run(test.name, func(t *testing.T) {
			licenseCalls := 0
			service := testCreateRolloutService(t, func(*http.Request) (*http.Response, error) {
				licenseCalls++
				return nil, errors.New("license unavailable")
			})
			loadCalls := 0
			service.rollout.createPreparation = rolloutCreatePreparationStub{
				prepare: func(context.Context, Actor, RolloutIdentity, CreateRolloutRequest,
					[32]byte) (CreateRolloutIntent, RolloutWriteResult, error) {
					return CreateRolloutIntent{ID: nodeID(811), PlanID: nodeID(812), State: test.state},
						RolloutWriteResult{}, nil
				},
				load: func(context.Context, Actor, []string) (RolloutTargetCohort, error) {
					loadCalls++
					return RolloutTargetCohort{Platform: "linux", Architecture: "amd64",
						CurrentVersion: "1.2.3", ProtocolVersion: 2,
						Targets: []PlanTarget{{NodeID: request.NodeIDs[0]}}}, nil
				},
			}

			if _, err := service.CreateRollout(t.Context(), actor, request); !errors.Is(err, test.wantError) {
				t.Fatalf("%s error = %v, want %v", test.name, err, test.wantError)
			}
			if loadCalls != 1 || licenseCalls != test.wantLicense {
				t.Fatalf("%s calls = cohort %d, license %d", test.name, loadCalls, licenseCalls)
			}
		})
	}
}

func TestBuildRolloutStatusMutationCarriesNextBatchAndAutomaticRollbackEvents(t *testing.T) {
	identity := RolloutIdentity{ActorScopeID: nodeID(701), ActorUserID: nodeID(702), InstallationID: nodeID(703)}
	t.Run("next batch", func(t *testing.T) {
		plan := mustRolloutPlan(t)
		plan = mustPlanCommand(t, plan, planCommand(PlanStart, plan.Revision, "start_requested")).Plan
		health := currentPlanHealth(plan, nodeID(1), true)
		mutation, err := buildRolloutStatusMutation(LockedRolloutPlan{Identity: identity, Plan: plan}, health, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		dispatches := rolloutDispatchIntents(identity, plan, mutation.Plan)
		if len(mutation.Events) != 1 || mutation.Events[0].Causation.ID != health.ID || len(dispatches) != 2 ||
			mutation.Plan.State != PlanRunning || mutation.Plan.ActiveBatch != 1 {
			t.Fatalf("next batch mutation = events=%#v dispatches=%#v plan=%#v", mutation.Events, dispatches, mutation.Plan)
		}
	})
	t.Run("automatic rollback", func(t *testing.T) {
		plan := mustRolloutPlan(t)
		plan = mustPlanCommand(t, plan, planCommand(PlanStart, plan.Revision, "start_requested")).Plan
		health := currentPlanHealth(plan, nodeID(1), false)
		health.Code = "health_probe_failed"
		mutation, err := buildRolloutStatusMutation(LockedRolloutPlan{Identity: identity, Plan: plan}, health, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		var rollback PlanCommand
		if len(mutation.Events) != 2 || json.Unmarshal(mutation.Events[1].CausationBytes, &rollback) != nil ||
			rollback.Action != PlanRollback || mutation.Plan.State != PlanRollingBack ||
			len(rolloutDispatchIntents(identity, plan, mutation.Plan)) != 1 {
			t.Fatalf("automatic rollback mutation = events=%#v plan=%#v", mutation.Events, mutation.Plan)
		}
	})
}

func TestRolloutHealthFromStatusNormalizesFailureReason(t *testing.T) {
	receipt := RolloutStatusReceipt{StatusID: nodeID(710), PlanID: nodeID(711), NodeID: nodeID(712),
		State: "failed"}
	health, err := rolloutHealthFromStatus(RolloutNodeCommand{PlanRevision: 9}, receipt,
		rolloutStatusPayload{ErrorCode: "ROLLBACK.VERSION-FAILED"})
	if err != nil || health.ID != receipt.StatusID || health.Code != "rollback_version_failed" ||
		health.Success || health.DispatchRevision != 9 {
		t.Fatalf("normalized health = (%#v,%v)", health, err)
	}
}

func TestNewRolloutRuntimeRejectsUnsafeProfileAndSignerConfiguration(t *testing.T) {
	valid := testRolloutRuntimeConfig()
	if _, err := NewRolloutRuntime(valid); err != nil {
		t.Fatalf("valid runtime config error = %v", err)
	}
	for name, mutate := range map[string]func(*RolloutRuntimeConfig){
		"issuance too long":          func(value *RolloutRuntimeConfig) { value.CommandIssuanceTTL = 7*24*time.Hour + time.Second },
		"execution exceeds issuance": func(value *RolloutRuntimeConfig) { value.ExecutionTTL = value.CommandIssuanceTTL + time.Second },
		"probe exceeds activation": func(value *RolloutRuntimeConfig) {
			value.Profiles.ProbeTimeout = value.Profiles.ActivationTimeout + time.Second
		},
		"interval exceeds observation": func(value *RolloutRuntimeConfig) {
			value.Profiles.HealthInterval = value.Profiles.ObservationWindow + time.Second
		},
		"successes zero":    func(value *RolloutRuntimeConfig) { value.Profiles.RequiredConsecutiveSuccesses = 0 },
		"same signer ids":   func(value *RolloutRuntimeConfig) { value.EdgeSigner = value.ControlSigner },
		"no artifact cache": func(value *RolloutRuntimeConfig) { value.Artifacts = nil },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if _, err := NewRolloutRuntime(candidate); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("unsafe runtime config error = %v", err)
			}
		})
	}
}

func validTestRolloutRuntime(t *testing.T) *RolloutRuntime {
	t.Helper()
	runtime, err := NewRolloutRuntime(testRolloutRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	return runtime
}

func testRolloutRuntimeConfig() RolloutRuntimeConfig {
	return RolloutRuntimeConfig{License: &LicenseClient{}, LicenseKeys: entitlement.NewKeyRing(),
		Artifacts: &ArtifactCache{root: "/nonexistent/cdnca-upgrade-artifacts",
			baseURL: "https://cdnca.com/downloads/edge-agent/upgrades/sha256", client: http.DefaultClient},
		CommandGrantKeys: entitlement.NewKeyRing(), ControlSigner: rolloutTestSigner{id: "control-upgrade-signing"},
		EdgeSigner:         rolloutTestSigner{id: "edge-upgrade-signing"},
		InstallationID:     uuid.MustParse("00000000-0000-4000-8000-000000000004"),
		CommandIssuanceTTL: 6 * time.Hour, ExecutionTTL: 10 * time.Minute,
		Profiles: RolloutProfilePolicy{ActivationTimeout: 5 * time.Minute, ObservationWindow: 2 * time.Minute,
			HealthInterval: 10 * time.Second, ProbeTimeout: 3 * time.Second, RequiredConsecutiveSuccesses: 3},
		Clock: func() time.Time { return time.Unix(1_800_000_000, 0).UTC() }}
}

type rolloutCreatePreparationStub struct {
	prepare func(context.Context, Actor, RolloutIdentity, CreateRolloutRequest,
		[32]byte) (CreateRolloutIntent, RolloutWriteResult, error)
	load func(context.Context, Actor, []string) (RolloutTargetCohort, error)
}

func (stub rolloutCreatePreparationStub) PrepareCreateRollout(ctx context.Context, actor Actor,
	identity RolloutIdentity, request CreateRolloutRequest,
	digest [32]byte) (CreateRolloutIntent, RolloutWriteResult, error) {
	return stub.prepare(ctx, actor, identity, request, digest)
}

func (stub rolloutCreatePreparationStub) LoadRolloutTargetCohort(ctx context.Context, actor Actor,
	nodeIDs []string) (RolloutTargetCohort, error) {
	return stub.load(ctx, actor, nodeIDs)
}

func testCreateRolloutInput() (Actor, CreateRolloutRequest) {
	actor := Actor{ScopeID: uuid.MustParse(nodeID(821)), UserID: uuid.MustParse(nodeID(822)), ScopeKind: "platform"}
	request := CreateRolloutRequest{CreateRolloutBody: CreateRolloutBody{
		Schema: "cdnca.control-upgrade-rollout.create/v1", NodeIDs: []string{nodeID(823)},
		CanaryNodeIDs: []string{nodeID(823)}, BatchSize: 1, AutomaticRollback: true},
		IdempotencyKey: "create-replay", RequestID: "create-replay-request"}
	return actor, request
}

func testCreateRolloutService(t *testing.T,
	do func(*http.Request) (*http.Response, error)) *Service {
	t.Helper()
	runtime := validTestRolloutRuntime(t)
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	license, err := NewLicenseClient("https://license.example.test", roundTripUpgradeFunc(do),
		runtime.config.InstallationID, privateKey, runtime.config.Clock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(license.Close)
	runtime.config.License = license
	return &Service{store: &Store{}, rollout: runtime}
}

type rolloutTestSigner struct{ id string }

func (signer rolloutTestSigner) KeyID() string { return signer.id }
func (rolloutTestSigner) Sign(context.Context, []byte) ([]byte, error) {
	return make([]byte, ed25519.SignatureSize), nil
}
