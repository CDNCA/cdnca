package updater

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
)

const (
	fixtureExecutionSchema    = "cdnca.upgrade.execution/v1"
	fixtureExecutionAudience  = "cdnca-edge-upgrade"
	fixtureExecutionPurpose   = "cdnca-edge-upgrade-execution"
	fixtureExecutionAction    = "execute"
	fixtureControlDomain      = "cdnca-upgrade-execution-control-signature/v1"
	fixtureCommitmentDomain   = "cdnca-upgrade-execution-edge-consumption-commitment/v1"
	fixtureControlDomainV2    = "cdnca-upgrade-execution-control-signature/v2"
	fixtureCommitmentDomainV2 = "cdnca-upgrade-execution-edge-consumption-commitment/v2"
	fixtureEdgeDomainV2       = "cdnca-upgrade-execution-edge-signature/v2"
	fixtureControlDomainV3    = "cdnca-upgrade-execution-control-signature/v3"
	fixtureCommitmentDomainV3 = "cdnca-upgrade-execution-edge-consumption-commitment/v3"
	fixtureEdgeDomainV3       = "cdnca-upgrade-execution-edge-signature/v3"
)

func TestVerifyAndConsumeUpgradeExecutionReturnsExecutablePlan(t *testing.T) {
	fixture := newExecutionFixture(t)
	wireDigest := sha256.Sum256(fixture.encoded)
	if got := hex.EncodeToString(wireDigest[:]); got != "a62308a0314e79384870a1d4729818fcd2fb488b1671c764a7f10ee15fe0166f" {
		t.Fatalf("canonical envelope sha256 = %s", got)
	}
	replay := &executionReplayFixture{consume: true}
	plan, err := VerifyAndConsumeUpgradeExecution(context.Background(), fixture.encoded,
		fixture.options(), replay)
	if err != nil {
		t.Fatalf("VerifyAndConsumeUpgradeExecution() error = %v", err)
	}
	if replay.calls != 1 || replay.claim.CommandID != fixture.execution.CommandID ||
		replay.claim.Nonce != fixture.execution.Nonce || replay.claim.GrantDigest != fixture.execution.GrantDigest {
		t.Fatalf("replay = (%d, %#v)", replay.calls, replay.claim)
	}
	artifactDigest, _ := base64.RawURLEncoding.DecodeString(fixture.execution.SHA256Digest)
	if plan.PlanID != fixture.execution.CommandID || plan.Revision != fixture.execution.ReleaseSequence ||
		plan.ReleaseSequence != fixture.execution.ReleaseSequence || plan.CurrentVersion != fixture.execution.CurrentVersion ||
		plan.TargetVersion != fixture.execution.TargetVersion || plan.Artifact.SHA256 != hex.EncodeToString(artifactDigest) ||
		plan.Artifact.Size != fixture.execution.ArtifactSizeBytes || plan.Artifact.URL != fixture.execution.DownloadURL ||
		plan.Signature.KeyID != fixture.envelope.EdgeKeyID {
		t.Fatalf("Plan = %#v", plan)
	}
	if err := validatePlan(plan, Config{
		Platform: fixture.execution.Platform, Architecture: fixture.execution.Architecture,
		AgentVersion: fixture.execution.CurrentVersion, NodeID: fixture.execution.NodeID,
		Keys:             map[string]ed25519.PublicKey{fixture.envelope.EdgeKeyID: fixture.edgePublic},
		MaxArtifactBytes: fixture.execution.ArtifactSizeBytes,
	}, fixture.now.Add(2*time.Minute), false); err != nil {
		t.Fatalf("converted plan is not executable: %v", err)
	}
	decodedEnvelope, err := decodeUpgradeExecution(fixture.encoded)
	if err != nil {
		t.Fatalf("decodeUpgradeExecution() error = %v", err)
	}
	edgeSigningBytes, err := upgradeExecutionSigningBytes(decodedEnvelope)
	if err != nil {
		t.Fatalf("upgradeExecutionSigningBytes() error = %v", err)
	}
	planSigningBytes, err := SigningBytes(plan)
	if err != nil || !bytes.Equal(edgeSigningBytes, planSigningBytes) {
		t.Fatalf("edge signing bytes differ from updater SigningBytes: %v", err)
	}
}

// The control plane signs executions on another host; a node clock trailing it
// by up to upgradeExecutionClockSkew must still accept them.
func TestVerifyUpgradeExecutionToleratesBoundedControlClockLead(t *testing.T) {
	fixture := newExecutionFixture(t)
	notBefore := time.Unix(fixture.execution.NotBefore, 0)
	for _, lead := range []time.Duration{500 * time.Millisecond, time.Second, upgradeExecutionClockSkew} {
		options := fixture.options()
		options.Now = notBefore.Add(-lead)
		if _, _, err := verifyUpgradeExecution(fixture.encoded, options); err != nil {
			t.Fatalf("lead %s: verifyUpgradeExecution() error = %v", lead, err)
		}
	}
}

func TestVerifyAndConsumeUpgradeExecutionDefersPlanConversionUntilAfterReplay(t *testing.T) {
	fixture := newExecutionFixture(t)
	for _, test := range []struct {
		name    string
		options UpgradeExecutionConsumerOptions
		replay  *executionReplayFixture
		want    error
	}{
		{name: "bad target", options: func() UpgradeExecutionConsumerOptions {
			value := fixture.options()
			value.ExpectedTargetVersion = "2.0.1"
			return value
		}(), replay: &executionReplayFixture{consume: true}, want: ErrUpgradeExecutionTargetMismatch},
		{name: "not yet valid", options: func() UpgradeExecutionConsumerOptions {
			value := fixture.options()
			value.Now = time.Unix(fixture.execution.NotBefore, 0).Add(-upgradeExecutionClockSkew - time.Second)
			return value
		}(), replay: &executionReplayFixture{consume: true}, want: ErrUpgradeExecutionNotYetValid},
		{name: "expired", options: func() UpgradeExecutionConsumerOptions {
			value := fixture.options()
			value.Now = time.Unix(fixture.execution.ExpiresAt, 0)
			return value
		}(), replay: &executionReplayFixture{consume: true}, want: ErrUpgradeExecutionExpired},
		{name: "replay denied", options: fixture.options(), replay: &executionReplayFixture{consume: false},
			want: ErrUpgradeExecutionReplay},
	} {
		t.Run(test.name, func(t *testing.T) {
			builderCalls := 0
			builder := func(envelope upgradeExecutionEnvelope) (Plan, error) {
				builderCalls++
				return upgradeExecutionPlan(envelope)
			}
			if _, err := verifyAndConsumeUpgradeExecution(context.Background(), fixture.encoded,
				test.options, test.replay, builder); !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if builderCalls != 0 {
				t.Fatalf("plan builder calls = %d, want 0", builderCalls)
			}
		})
	}
}

func TestVerifyAndConsumeUpgradeExecutionFailsClosedBeforeReplay(t *testing.T) {
	fixture := newExecutionFixture(t)
	base := fixture.options()

	for _, mismatch := range []struct {
		name string
		set  func(*UpgradeExecutionConsumerOptions)
	}{
		{name: "installation", set: func(value *UpgradeExecutionConsumerOptions) {
			value.ExpectedInstallationID = "00000000-0000-4000-8000-000000000099"
		}},
		{name: "node", set: func(value *UpgradeExecutionConsumerOptions) {
			value.ExpectedNodeID = "00000000-0000-4000-8000-000000000099"
		}},
		{name: "command", set: func(value *UpgradeExecutionConsumerOptions) {
			value.ExpectedCommandID = "00000000-0000-4000-8000-000000000099"
		}},
		{name: "nonce", set: func(value *UpgradeExecutionConsumerOptions) {
			value.ExpectedNonce = "00000000-0000-4000-8000-000000000099"
		}},
		{name: "current", set: func(value *UpgradeExecutionConsumerOptions) { value.ExpectedCurrentVersion = "1.0.1" }},
		{name: "target", set: func(value *UpgradeExecutionConsumerOptions) { value.ExpectedTargetVersion = "2.0.1" }},
		{name: "platform", set: func(value *UpgradeExecutionConsumerOptions) { value.ExpectedPlatform = "darwin" }},
		{name: "architecture", set: func(value *UpgradeExecutionConsumerOptions) { value.ExpectedArchitecture = "arm64" }},
	} {
		t.Run(mismatch.name, func(t *testing.T) {
			options := base
			mismatch.set(&options)
			replay := &executionReplayFixture{consume: true}
			if _, err := VerifyAndConsumeUpgradeExecution(context.Background(), fixture.encoded, options, replay); !errors.Is(err, ErrUpgradeExecutionTargetMismatch) {
				t.Fatalf("error = %v", err)
			}
			if replay.calls != 0 {
				t.Fatalf("replay calls = %d, want 0", replay.calls)
			}
		})
	}

	for _, test := range []struct {
		name    string
		options UpgradeExecutionConsumerOptions
		want    error
	}{
		{name: "not yet valid", options: func() UpgradeExecutionConsumerOptions {
			value := base
			value.Now = time.Unix(fixture.execution.NotBefore, 0).Add(-upgradeExecutionClockSkew - time.Second)
			return value
		}(), want: ErrUpgradeExecutionNotYetValid},
		{name: "expired", options: func() UpgradeExecutionConsumerOptions {
			value := base
			value.Now = time.Unix(fixture.execution.ExpiresAt, 0)
			return value
		}(), want: ErrUpgradeExecutionExpired},
		{name: "artifact too large", options: func() UpgradeExecutionConsumerOptions {
			value := base
			value.MaxArtifactBytes = fixture.execution.ArtifactSizeBytes - 1
			return value
		}(), want: ErrArtifactTooLarge},
	} {
		t.Run(test.name, func(t *testing.T) {
			replay := &executionReplayFixture{consume: true}
			if _, err := VerifyAndConsumeUpgradeExecution(context.Background(), fixture.encoded, test.options, replay); !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if replay.calls != 0 {
				t.Fatalf("replay calls = %d, want 0", replay.calls)
			}
		})
	}
}

func TestVerifyAndConsumeUpgradeExecutionRejectsMalformedOrUntrustedWire(t *testing.T) {
	fixture := newExecutionFixture(t)
	var object map[string]any
	_ = json.Unmarshal(fixture.encoded, &object)
	object["unknown"] = true
	unknown, _ := json.Marshal(object)
	object["execution"] = nil
	nullExecution, _ := json.Marshal(object)
	duplicate := bytes.Replace(fixture.encoded, []byte(`{"control_algorithm":`),
		[]byte(`{"control_algorithm":"Ed25519","control_algorithm":`), 1)

	for name, candidate := range map[string][]byte{
		"empty":              nil,
		"leading whitespace": append([]byte(" "), fixture.encoded...),
		"trailing value":     append(append([]byte(nil), fixture.encoded...), []byte("{}")...),
		"unknown field":      unknown,
		"null execution":     nullExecution,
		"duplicate field":    duplicate,
	} {
		t.Run(name, func(t *testing.T) {
			replay := &executionReplayFixture{consume: true}
			if _, err := VerifyAndConsumeUpgradeExecution(context.Background(), candidate, fixture.options(), replay); !errors.Is(err, ErrInvalidUpgradeExecutionEnvelope) {
				t.Fatalf("error = %v", err)
			}
			if replay.calls != 0 {
				t.Fatalf("replay calls = %d, want 0", replay.calls)
			}
		})
	}

	tampered := fixture.envelope
	tampered.Execution.CurrentVersion = "1.0.1"
	tamperedWire, _ := json.Marshal(tampered)
	replay := &executionReplayFixture{consume: true}
	if _, err := VerifyAndConsumeUpgradeExecution(context.Background(), tamperedWire, fixture.options(), replay); !errors.Is(err, ErrInvalidUpgradeExecutionControlSignature) {
		t.Fatalf("control tamper error = %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*fixtureEnvelope)
	}{
		{name: "unknown schema", mutate: func(value *fixtureEnvelope) { value.Execution.Schema = "cdnca.upgrade.execution/v2" }},
		{name: "unknown action", mutate: func(value *fixtureEnvelope) { value.Execution.Action = "download" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := fixture.envelope
			test.mutate(&candidate)
			encoded, _ := json.Marshal(candidate)
			if _, err := VerifyAndConsumeUpgradeExecution(context.Background(), encoded, fixture.options(), replay); !errors.Is(err, ErrInvalidUpgradeExecutionEnvelope) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	edgeSwap := fixture.envelope
	edgeSwap.EdgeSignature = fixture.envelope.ControlSignature
	edgeSwapWire, _ := json.Marshal(edgeSwap)
	if _, err := VerifyAndConsumeUpgradeExecution(context.Background(), edgeSwapWire, fixture.options(), replay); !errors.Is(err, ErrInvalidUpgradeExecutionEdgeSignature) {
		t.Fatalf("edge domain swap error = %v", err)
	}

	wrongControl := fixture.options()
	wrongControl.ControlKeys = nil
	if _, err := VerifyAndConsumeUpgradeExecution(context.Background(), fixture.encoded, wrongControl, replay); !errors.Is(err, ErrUnknownUpgradeExecutionControlKey) {
		t.Fatalf("unknown control key error = %v", err)
	}
	wrongEdge := fixture.options()
	wrongEdge.EdgeKeys = nil
	if _, err := VerifyAndConsumeUpgradeExecution(context.Background(), fixture.encoded, wrongEdge, replay); !errors.Is(err, ErrUnknownUpgradeExecutionEdgeKey) {
		t.Fatalf("unknown edge key error = %v", err)
	}
}

func TestVerifyAndConsumeUpgradeExecutionRequiresAtomicReplayClaim(t *testing.T) {
	fixture := newExecutionFixture(t)
	if _, err := VerifyAndConsumeUpgradeExecution(context.Background(), fixture.encoded, fixture.options(), nil); !errors.Is(err, ErrUpgradeExecutionReplay) {
		t.Fatalf("nil replay error = %v", err)
	}
	replay := &executionReplayFixture{consume: false}
	if _, err := VerifyAndConsumeUpgradeExecution(context.Background(), fixture.encoded, fixture.options(), replay); !errors.Is(err, ErrUpgradeExecutionReplay) {
		t.Fatalf("duplicate replay error = %v", err)
	}
	if replay.calls != 1 {
		t.Fatalf("replay calls = %d, want 1", replay.calls)
	}
}

func TestVerifyAndConsumeUpgradeExecutionV2BindsRolloutAndDurableProvenance(t *testing.T) {
	fixture := newExecutionV2Fixture(t)
	replay := &executionReplayFixture{consume: true}
	plan, err := VerifyAndConsumeUpgradeExecution(context.Background(), fixture.encoded, fixture.options(), replay)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Domain != fixtureEdgeDomainV2 || plan.SchemaVersion != planSchemaVersionV2 ||
		plan.PlanID != fixture.execution.PlanID || plan.Revision != fixture.execution.PlanRevision ||
		plan.BatchID != fixture.execution.BatchID || plan.ArtifactBundleID != fixture.execution.ArtifactBundleID ||
		plan.ArtifactBundleSHA256 != fixture.execution.ArtifactBundleSHA256 ||
		plan.CommandIssuanceNotAfter != fixture.execution.CommandIssuanceNotAfter ||
		replay.claim.PlanID != fixture.execution.PlanID || replay.claim.PlanRevision != fixture.execution.PlanRevision ||
		replay.claim.BatchID != fixture.execution.BatchID ||
		replay.claim.ArtifactBundleID != fixture.execution.ArtifactBundleID ||
		replay.claim.ArtifactBundleSHA256 != fixture.execution.ArtifactBundleSHA256 ||
		replay.claim.CommandIssuanceNotAfter != fixture.execution.CommandIssuanceNotAfter {
		t.Fatalf("plan=%#v claim=%#v", plan, replay.claim)
	}
	decoded, err := decodeUpgradeExecution(fixture.encoded)
	if err != nil {
		t.Fatal(err)
	}
	want, err := upgradeExecutionSigningBytes(decoded)
	if err != nil {
		t.Fatal(err)
	}
	got, err := SigningBytes(plan)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("v2 signing bytes differ: %v", err)
	}

	for _, mismatch := range []struct {
		name string
		set  func(*UpgradeExecutionConsumerOptions)
	}{
		{name: "plan", set: func(options *UpgradeExecutionConsumerOptions) {
			options.ExpectedPlanID = "00000000-0000-4000-8000-000000000099"
		}},
		{name: "revision", set: func(options *UpgradeExecutionConsumerOptions) { options.ExpectedPlanRevision++ }},
		{name: "batch", set: func(options *UpgradeExecutionConsumerOptions) {
			options.ExpectedBatchID = "00000000-0000-4000-8000-000000000098"
		}},
	} {
		t.Run(mismatch.name, func(t *testing.T) {
			options := fixture.options()
			mismatch.set(&options)
			candidate := &executionReplayFixture{consume: true}
			if _, err := VerifyAndConsumeUpgradeExecution(context.Background(), fixture.encoded, options, candidate); !errors.Is(err, ErrUpgradeExecutionTargetMismatch) {
				t.Fatalf("error = %v", err)
			}
			if candidate.calls != 0 {
				t.Fatalf("replay calls = %d, want 0", candidate.calls)
			}
		})
	}
}

func TestUpgradeExecutionV2RejectsInvalidProvenanceAndHealthProfile(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*fixtureExecution)
	}{
		{name: "bundle id", mutate: func(execution *fixtureExecution) { execution.ArtifactBundleID = "bundle" }},
		{name: "bundle digest", mutate: func(execution *fixtureExecution) { execution.ArtifactBundleSHA256 = "bad" }},
		{name: "issuance deadline", mutate: func(execution *fixtureExecution) {
			execution.CommandIssuanceNotAfter = execution.ExpiresAt - 1
		}},
		{name: "arbitrary health argv", mutate: func(execution *fixtureExecution) {
			execution.Health.Command = []string{"{artifact}", "health"}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newExecutionV2Fixture(t)
			test.mutate(&fixture.execution)
			resignExecutionFixture(t, &fixture)
			replay := &executionReplayFixture{consume: true}
			if _, err := VerifyAndConsumeUpgradeExecution(context.Background(), fixture.encoded, fixture.options(), replay); !errors.Is(err, ErrInvalidUpgradeExecutionEnvelope) {
				t.Fatalf("error = %v", err)
			}
			if replay.calls != 0 {
				t.Fatalf("replay calls = %d, want 0", replay.calls)
			}
		})
	}
}

func TestVerifyAndConsumeUpgradeExecutionV3BindsDualSequenceAndRejectsLegacyDowngrade(t *testing.T) {
	fixture := newExecutionV3Fixture(t)
	replay := &executionReplayFixture{consume: true}
	plan, err := VerifyAndConsumeUpgradeExecution(context.Background(), fixture.encoded, fixture.options(), replay)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Domain != fixtureEdgeDomainV3 || plan.SchemaVersion != planSchemaVersionV3 ||
		plan.ExecutionSequence != fixture.execution.ExecutionSequence ||
		plan.ReleaseSequence != fixture.execution.ReleaseSequence ||
		replay.claim.ExecutionSequence != fixture.execution.ExecutionSequence ||
		replay.claim.ReleaseSequence != fixture.execution.ReleaseSequence ||
		replay.claim.Component != fixture.execution.Component {
		t.Fatalf("plan=%#v claim=%#v", plan, replay.claim)
	}
	decoded, err := decodeUpgradeExecution(fixture.encoded)
	if err != nil {
		t.Fatal(err)
	}
	want, err := upgradeExecutionSigningBytes(decoded)
	if err != nil {
		t.Fatal(err)
	}
	got, err := SigningBytes(plan)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("v3 signing bytes differ: %v", err)
	}

	downgraded := fixture
	downgraded.execution.Schema = upgradeExecutionV2Schema
	resignExecutionFixture(t, &downgraded)
	if _, err := VerifyAndConsumeUpgradeExecution(context.Background(), downgraded.encoded,
		downgraded.options(), &executionReplayFixture{consume: true}); !errors.Is(err, ErrInvalidUpgradeExecutionEnvelope) {
		t.Fatalf("v2 accepted v3 execution sequence: %v", err)
	}
}

type executionFixture struct {
	now           time.Time
	execution     fixtureExecution
	envelope      fixtureEnvelope
	encoded       []byte
	controlPublic ed25519.PublicKey
	edgePublic    ed25519.PublicKey
}

func newExecutionFixture(t *testing.T) executionFixture {
	t.Helper()
	now := time.Unix(1_800_000_000, 0).UTC()
	controlPrivate := executionFixtureKey(0x81)
	edgePrivate := executionFixtureKey(0x82)
	execution := fixtureExecution{
		Schema: fixtureExecutionSchema, Audience: fixtureExecutionAudience,
		Purpose: fixtureExecutionPurpose, Action: fixtureExecutionAction,
		GrantDigestAlgorithm: "sha256", GrantDigest: fixtureDigest(0x31),
		GrantExpiresAt: now.Add(15 * time.Minute).Unix(),
		InstallationID: "00000000-0000-4000-8000-000000000004",
		NodeID:         "00000000-0000-4000-8000-000000000021",
		CommandID:      "00000000-0000-4000-8000-000000000022",
		Nonce:          "00000000-0000-4000-8000-000000000023", ReleaseSequence: 7,
		Component: "edge-agent", Operation: "upgrade", CurrentVersion: "1.0.0", TargetVersion: "2.0.0",
		ArtifactID: "00000000-0000-4000-8000-000000000010", DigestAlgorithm: "sha256",
		SHA256Digest: fixtureDigest(0x42), DownloadURL: "https://cdn.example/releases/edge-agent-2.0.0",
		ArtifactSizeBytes: 1024, Platform: "linux", Architecture: "amd64",
		Compatibility: fixtureCompatibility{MinAgentVersion: "1.0.0", MaxAgentVersion: "2.0.0"},
		Health: fixtureHealthPolicy{
			Command: []string{"{artifact}", "health"}, ActivationTimeoutNanoseconds: int64(30 * time.Second),
			ObservationWindowNanoseconds: int64(time.Minute), IntervalNanoseconds: int64(time.Second),
			ProbeTimeoutNanoseconds: int64(500 * time.Millisecond), RequiredConsecutiveSuccesses: 3,
		},
		Rollout: fixtureRolloutPolicy{Percentage: 100}, Rollback: fixtureRollbackPolicy{Automatic: true},
		IssuedAt: now.Unix(), NotBefore: now.Add(time.Minute).Unix(), ExpiresAt: now.Add(10 * time.Minute).Unix(),
	}
	envelope := fixtureEnvelope{
		ControlAlgorithm: "Ed25519", ControlKeyID: "control-execution-1", Execution: execution,
		EdgeAlgorithm: "Ed25519", EdgeKeyID: "edge-consumption-1",
	}
	controlPayload, _ := json.Marshal(fixtureControlDocument{
		Domain: fixtureControlDomain, Algorithm: envelope.ControlAlgorithm,
		KeyID: envelope.ControlKeyID, Execution: execution,
	})
	envelope.ControlSignature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(controlPrivate, controlPayload))
	plan := fixturePlan(envelope)
	if err := Sign(&plan, envelope.EdgeKeyID, edgePrivate); err != nil {
		t.Fatal(err)
	}
	edgeSignature, _ := base64.RawStdEncoding.DecodeString(plan.Signature.Value)
	envelope.EdgeSignature = base64.RawURLEncoding.EncodeToString(edgeSignature)
	encoded, _ := json.Marshal(envelope)
	return executionFixture{
		now: now, execution: execution, envelope: envelope, encoded: encoded,
		controlPublic: controlPrivate.Public().(ed25519.PublicKey), edgePublic: edgePrivate.Public().(ed25519.PublicKey),
	}
}

func newExecutionV2Fixture(t *testing.T) executionFixture {
	t.Helper()
	fixture := newExecutionFixture(t)
	fixture.execution.Schema = upgradeExecutionV2Schema
	fixture.execution.PlanID = "00000000-0000-4000-8000-000000000024"
	fixture.execution.PlanRevision = 3
	fixture.execution.BatchID = "00000000-0000-4000-8000-000000000025"
	fixture.execution.ArtifactBundleID = "00000000-0000-4000-8000-000000000026"
	fixture.execution.ArtifactBundleSHA256 = fixtureDigest(0x52)
	fixture.execution.CommandIssuanceNotAfter = fixture.execution.ExpiresAt
	fixture.execution.Health.Command = []string{"{artifact}", "--version"}
	resignExecutionFixture(t, &fixture)
	return fixture
}

func newRollbackExecutionFixture(t *testing.T) executionFixture {
	t.Helper()
	fixture := newExecutionV2Fixture(t)
	fixture.execution.ReleaseSequence++
	fixture.execution.Operation = string(ActionRollback)
	fixture.execution.CurrentVersion = "2.0.0"
	fixture.execution.TargetVersion = "1.0.0"
	resignExecutionFixture(t, &fixture)
	return fixture
}

func newExecutionV3Fixture(t *testing.T) executionFixture {
	t.Helper()
	fixture := newExecutionV2Fixture(t)
	fixture.execution.Schema = upgradeExecutionV3Schema
	fixture.execution.ExecutionSequence = 11
	resignExecutionFixture(t, &fixture)
	return fixture
}

func resignExecutionFixture(t *testing.T, fixture *executionFixture) {
	t.Helper()
	fixture.envelope.Execution = fixture.execution
	controlPrivate := executionFixtureKey(0x81)
	controlDomain := fixtureControlDomain
	if fixture.execution.Schema == upgradeExecutionV2Schema {
		controlDomain = fixtureControlDomainV2
	} else if fixture.execution.Schema == upgradeExecutionV3Schema {
		controlDomain = fixtureControlDomainV3
	}
	controlPayload, err := json.Marshal(fixtureControlDocument{
		Domain: controlDomain, Algorithm: fixture.envelope.ControlAlgorithm,
		KeyID: fixture.envelope.ControlKeyID, Execution: fixture.execution,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.envelope.ControlSignature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(controlPrivate, controlPayload))
	plan := fixturePlan(fixture.envelope)
	if err := Sign(&plan, fixture.envelope.EdgeKeyID, executionFixtureKey(0x82)); err != nil {
		t.Fatal(err)
	}
	edgeSignature, err := base64.RawStdEncoding.DecodeString(plan.Signature.Value)
	if err != nil {
		t.Fatal(err)
	}
	fixture.envelope.EdgeSignature = base64.RawURLEncoding.EncodeToString(edgeSignature)
	fixture.encoded, err = json.Marshal(fixture.envelope)
	if err != nil {
		t.Fatal(err)
	}
}

func (fixture executionFixture) options() UpgradeExecutionConsumerOptions {
	options := UpgradeExecutionConsumerOptions{
		Now:                    fixture.now.Add(2 * time.Minute),
		ExpectedInstallationID: fixture.execution.InstallationID, ExpectedNodeID: fixture.execution.NodeID,
		ExpectedCommandID: fixture.execution.CommandID, ExpectedNonce: fixture.execution.Nonce,
		ExpectedCurrentVersion: fixture.execution.CurrentVersion, ExpectedTargetVersion: fixture.execution.TargetVersion,
		ExpectedPlatform: fixture.execution.Platform, ExpectedArchitecture: fixture.execution.Architecture,
		MaxArtifactBytes: fixture.execution.ArtifactSizeBytes,
		ControlKeys:      map[string]ed25519.PublicKey{fixture.envelope.ControlKeyID: fixture.controlPublic},
		EdgeKeys:         map[string]ed25519.PublicKey{fixture.envelope.EdgeKeyID: fixture.edgePublic},
	}
	if fixture.execution.Schema == upgradeExecutionV2Schema || fixture.execution.Schema == upgradeExecutionV3Schema {
		options.ExpectedPlanID = fixture.execution.PlanID
		options.ExpectedPlanRevision = fixture.execution.PlanRevision
		options.ExpectedBatchID = fixture.execution.BatchID
		options.RequireV2 = true
	}
	return options
}

func fixturePlan(envelope fixtureEnvelope) Plan {
	artifactDigest, _ := base64.RawURLEncoding.DecodeString(envelope.Execution.SHA256Digest)
	commitmentDomain := fixtureCommitmentDomain
	if envelope.Execution.Schema == upgradeExecutionV2Schema {
		commitmentDomain = fixtureCommitmentDomainV2
	} else if envelope.Execution.Schema == upgradeExecutionV3Schema {
		commitmentDomain = fixtureCommitmentDomainV3
	}
	commitment, _ := json.Marshal(fixtureCommitmentDocument{
		Domain: commitmentDomain, Algorithm: envelope.ControlAlgorithm,
		KeyID: envelope.ControlKeyID, Execution: envelope.Execution, Signature: envelope.ControlSignature,
	})
	digest := sha256.Sum256(commitment)
	plan := Plan{
		SchemaVersion: 1, PlanID: envelope.Execution.CommandID,
		Revision: envelope.Execution.ReleaseSequence, ReleaseSequence: envelope.Execution.ReleaseSequence,
		IssuedAt: time.Unix(envelope.Execution.IssuedAt, 0).UTC(), ExpiresAt: time.Unix(envelope.Execution.ExpiresAt, 0).UTC(),
		Action: Action(envelope.Execution.Operation), CurrentVersion: envelope.Execution.CurrentVersion,
		TargetVersion: envelope.Execution.TargetVersion, Platform: envelope.Execution.Platform,
		Architecture: envelope.Execution.Architecture,
		Artifact:     Artifact{URL: envelope.Execution.DownloadURL, SHA256: hex.EncodeToString(artifactDigest), Size: envelope.Execution.ArtifactSizeBytes},
		Compatibility: Compatibility{MinAgentVersion: envelope.Execution.Compatibility.MinAgentVersion,
			MaxAgentVersion: envelope.Execution.Compatibility.MaxAgentVersion},
		Health: HealthPolicy{
			Command:                      envelope.Execution.Health.Command,
			ActivationTimeout:            time.Duration(envelope.Execution.Health.ActivationTimeoutNanoseconds),
			ObservationWindow:            time.Duration(envelope.Execution.Health.ObservationWindowNanoseconds),
			Interval:                     time.Duration(envelope.Execution.Health.IntervalNanoseconds),
			ProbeTimeout:                 time.Duration(envelope.Execution.Health.ProbeTimeoutNanoseconds),
			RequiredConsecutiveSuccesses: envelope.Execution.Health.RequiredConsecutiveSuccesses,
		},
		Rollout: RolloutPolicy{Percentage: envelope.Execution.Rollout.Percentage,
			CohortSalt: "exec-v1." + base64.RawURLEncoding.EncodeToString(digest[:])},
		Rollback: RollbackPolicy{Automatic: envelope.Execution.Rollback.Automatic},
	}
	if envelope.Execution.Schema == upgradeExecutionV2Schema || envelope.Execution.Schema == upgradeExecutionV3Schema {
		plan.Domain = fixtureEdgeDomainV2
		plan.SchemaVersion = planSchemaVersionV2
		plan.PlanID = envelope.Execution.PlanID
		plan.Revision = envelope.Execution.PlanRevision
		plan.BatchID = envelope.Execution.BatchID
		plan.ArtifactBundleID = envelope.Execution.ArtifactBundleID
		plan.ArtifactBundleSHA256 = envelope.Execution.ArtifactBundleSHA256
		plan.CommandIssuanceNotAfter = envelope.Execution.CommandIssuanceNotAfter
		if envelope.Execution.Schema == upgradeExecutionV3Schema {
			plan.Domain = fixtureEdgeDomainV3
			plan.SchemaVersion = planSchemaVersionV3
			plan.ExecutionSequence = envelope.Execution.ExecutionSequence
		}
	}
	return plan
}

type executionReplayFixture struct {
	consume bool
	calls   int
	claim   UpgradeExecutionReplayClaim
}

func (store *executionReplayFixture) ConsumeUpgradeExecution(_ context.Context,
	claim UpgradeExecutionReplayClaim) (bool, error) {
	store.calls++
	store.claim = claim
	return store.consume, nil
}

func executionFixtureKey(fill byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{fill}, ed25519.SeedSize))
}

func fixtureDigest(fill byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{fill}, sha256.Size))
}

type fixtureEnvelope struct {
	ControlAlgorithm string           `json:"control_algorithm"`
	ControlKeyID     string           `json:"control_key_id"`
	Execution        fixtureExecution `json:"execution"`
	ControlSignature string           `json:"control_signature"`
	EdgeAlgorithm    string           `json:"edge_algorithm"`
	EdgeKeyID        string           `json:"edge_key_id"`
	EdgeSignature    string           `json:"edge_signature"`
}

type fixtureExecution struct {
	Schema                  string                             `json:"schema"`
	Audience                string                             `json:"audience"`
	Purpose                 string                             `json:"purpose"`
	Action                  string                             `json:"action"`
	GrantDigestAlgorithm    string                             `json:"grant_digest_algorithm"`
	GrantDigest             string                             `json:"grant_digest"`
	GrantExpiresAt          int64                              `json:"grant_expires_at"`
	InstallationID          string                             `json:"installation_id"`
	NodeID                  string                             `json:"node_id"`
	CommandID               string                             `json:"command_id"`
	Nonce                   string                             `json:"nonce"`
	PlanID                  string                             `json:"plan_id,omitempty"`
	PlanRevision            uint64                             `json:"plan_revision,omitempty"`
	BatchID                 string                             `json:"batch_id,omitempty"`
	ArtifactBundleID        string                             `json:"artifact_bundle_id,omitempty"`
	ArtifactBundleSHA256    string                             `json:"artifact_bundle_sha256,omitempty"`
	CommandIssuanceNotAfter int64                              `json:"command_issuance_not_after,omitempty"`
	ExecutionSequence       uint64                             `json:"execution_sequence,omitempty"`
	ReleaseSequence         uint64                             `json:"release_sequence"`
	Component               string                             `json:"component"`
	Operation               string                             `json:"operation"`
	CurrentVersion          string                             `json:"current_version"`
	TargetVersion           string                             `json:"target_version"`
	ArtifactID              string                             `json:"artifact_id"`
	DigestAlgorithm         string                             `json:"digest_algorithm"`
	SHA256Digest            string                             `json:"sha256_digest"`
	DownloadURL             string                             `json:"download_url"`
	ArtifactSizeBytes       int64                              `json:"artifact_size_bytes"`
	Platform                string                             `json:"platform"`
	Architecture            string                             `json:"architecture"`
	Compatibility           fixtureCompatibility               `json:"compatibility"`
	Health                  fixtureHealthPolicy                `json:"health"`
	Rollout                 fixtureRolloutPolicy               `json:"rollout"`
	Rollback                fixtureRollbackPolicy              `json:"rollback"`
	IssuedAt                int64                              `json:"issued_at"`
	NotBefore               int64                              `json:"not_before"`
	ExpiresAt               int64                              `json:"expires_at"`
	DownloadPolicy          *entitlement.UpgradeDownloadPolicy `json:"download_policy,omitempty"`
}

type fixtureCompatibility struct {
	MinAgentVersion string `json:"min_agent_version"`
	MaxAgentVersion string `json:"max_agent_version"`
}

type fixtureHealthPolicy struct {
	Command                      []string `json:"command"`
	ActivationTimeoutNanoseconds int64    `json:"activation_timeout_nanoseconds"`
	ObservationWindowNanoseconds int64    `json:"observation_window_nanoseconds"`
	IntervalNanoseconds          int64    `json:"interval_nanoseconds"`
	ProbeTimeoutNanoseconds      int64    `json:"probe_timeout_nanoseconds"`
	RequiredConsecutiveSuccesses int      `json:"required_consecutive_successes"`
}

type fixtureRolloutPolicy struct {
	Percentage uint8 `json:"percentage"`
}

type fixtureRollbackPolicy struct {
	Automatic bool `json:"automatic"`
}

type fixtureControlDocument struct {
	Domain    string           `json:"domain"`
	Algorithm string           `json:"algorithm"`
	KeyID     string           `json:"key_id"`
	Execution fixtureExecution `json:"execution"`
}

type fixtureCommitmentDocument struct {
	Domain    string           `json:"domain"`
	Algorithm string           `json:"algorithm"`
	KeyID     string           `json:"key_id"`
	Execution fixtureExecution `json:"execution"`
	Signature string           `json:"signature"`
}
