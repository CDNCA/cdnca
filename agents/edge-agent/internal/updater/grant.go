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
	"io"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
)

const (
	upgradeExecutionSchema   = "cdnca.upgrade.execution/v1"
	upgradeExecutionV2Schema = "cdnca.upgrade.execution/v2"
	upgradeExecutionV3Schema = "cdnca.upgrade.execution/v3"
	upgradeExecutionAudience = "cdnca-edge-upgrade"
	upgradeExecutionPurpose  = "cdnca-edge-upgrade-execution"
	upgradeExecutionAction   = "execute"

	upgradeExecutionControlDomain      = "cdnca-upgrade-execution-control-signature/v1"
	upgradeExecutionCommitmentDomain   = "cdnca-upgrade-execution-edge-consumption-commitment/v1"
	upgradeExecutionControlDomainV2    = "cdnca-upgrade-execution-control-signature/v2"
	upgradeExecutionCommitmentDomainV2 = "cdnca-upgrade-execution-edge-consumption-commitment/v2"
	upgradeExecutionEdgeDomainV2       = "cdnca-upgrade-execution-edge-signature/v2"
	upgradeExecutionControlDomainV3    = "cdnca-upgrade-execution-control-signature/v3"
	upgradeExecutionCommitmentDomainV3 = "cdnca-upgrade-execution-edge-consumption-commitment/v3"
	upgradeExecutionEdgeDomainV3       = "cdnca-upgrade-execution-edge-signature/v3"
	maxUpgradeExecutionBytes           = 128 * 1024
	maxUpgradeExecutionWindow          = int64((15 * time.Minute) / time.Second)
	maxUpgradeExecutionTimestamp       = int64(253402300799)
	maxUpgradePlanRevision             = uint64(1<<63 - 1)
	// Matches libs/entitlement.VerifierClockSkew: the control plane signs on
	// another host, so only the not_before bound tolerates a leading signer.
	upgradeExecutionClockSkew = 30 * time.Second
)

var (
	ErrInvalidUpgradeExecutionEnvelope         = errors.New("invalid signed upgrade execution envelope")
	ErrUnknownUpgradeExecutionControlKey       = errors.New("unknown upgrade execution control key")
	ErrUnknownUpgradeExecutionEdgeKey          = errors.New("unknown upgrade execution edge key")
	ErrInvalidUpgradeExecutionControlSignature = errors.New("invalid upgrade execution control signature")
	ErrInvalidUpgradeExecutionEdgeSignature    = errors.New("invalid upgrade execution edge signature")
	ErrUpgradeExecutionTargetMismatch          = errors.New("upgrade execution target mismatch")
	ErrUpgradeExecutionNotYetValid             = errors.New("upgrade execution is not yet valid")
	ErrUpgradeExecutionExpired                 = errors.New("upgrade execution is expired")
	ErrUpgradeExecutionReplay                  = errors.New("upgrade execution replay rejected")
)

var (
	upgradeExecutionUUIDPattern       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	upgradeExecutionControlKeyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	upgradeExecutionCodePattern       = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,95}$`)
)

type UpgradeExecutionConsumerOptions struct {
	Now                    time.Time
	ExpectedInstallationID string
	ExpectedNodeID         string
	ExpectedCommandID      string
	ExpectedNonce          string
	ExpectedCurrentVersion string
	ExpectedTargetVersion  string
	ExpectedPlanID         string
	ExpectedPlanRevision   uint64
	ExpectedBatchID        string
	ExpectedPlatform       string
	ExpectedArchitecture   string
	MaxArtifactBytes       int64
	ControlKeys            map[string]ed25519.PublicKey
	EdgeKeys               map[string]ed25519.PublicKey
	RequireV2              bool
}

type UpgradeExecutionReplayClaim struct {
	Schema                  string
	InstallationID          string
	NodeID                  string
	CommandID               string
	Nonce                   string
	GrantDigest             string
	PlanID                  string
	PlanRevision            uint64
	BatchID                 string
	ArtifactBundleID        string
	ArtifactBundleSHA256    string
	CommandIssuanceNotAfter int64
	ExecutionSequence       uint64
	ReleaseSequence         uint64
	Component               string
	ExpiresAt               time.Time
}

// ConsumeUpgradeExecution must atomically persist a first-seen claim until ExpiresAt.
type UpgradeExecutionReplayStore interface {
	ConsumeUpgradeExecution(context.Context, UpgradeExecutionReplayClaim) (bool, error)
}

type upgradeExecutionEnvelope struct {
	ControlAlgorithm string               `json:"control_algorithm"`
	ControlKeyID     string               `json:"control_key_id"`
	Execution        upgradeExecutionWire `json:"execution"`
	ControlSignature string               `json:"control_signature"`
	EdgeAlgorithm    string               `json:"edge_algorithm"`
	EdgeKeyID        string               `json:"edge_key_id"`
	EdgeSignature    string               `json:"edge_signature"`
}

type upgradeExecutionWire struct {
	Schema                  string                        `json:"schema"`
	Audience                string                        `json:"audience"`
	Purpose                 string                        `json:"purpose"`
	Action                  string                        `json:"action"`
	GrantDigestAlgorithm    string                        `json:"grant_digest_algorithm"`
	GrantDigest             string                        `json:"grant_digest"`
	GrantExpiresAt          int64                         `json:"grant_expires_at"`
	InstallationID          string                        `json:"installation_id"`
	NodeID                  string                        `json:"node_id"`
	CommandID               string                        `json:"command_id"`
	Nonce                   string                        `json:"nonce"`
	PlanID                  string                        `json:"plan_id,omitempty"`
	PlanRevision            uint64                        `json:"plan_revision,omitempty"`
	BatchID                 string                        `json:"batch_id,omitempty"`
	ArtifactBundleID        string                        `json:"artifact_bundle_id,omitempty"`
	ArtifactBundleSHA256    string                        `json:"artifact_bundle_sha256,omitempty"`
	CommandIssuanceNotAfter int64                         `json:"command_issuance_not_after,omitempty"`
	ExecutionSequence       uint64                        `json:"execution_sequence,omitempty"`
	ReleaseSequence         uint64                        `json:"release_sequence"`
	Component               string                        `json:"component"`
	Operation               string                        `json:"operation"`
	CurrentVersion          string                        `json:"current_version"`
	TargetVersion           string                        `json:"target_version"`
	ArtifactID              string                        `json:"artifact_id"`
	DigestAlgorithm         string                        `json:"digest_algorithm"`
	SHA256Digest            string                        `json:"sha256_digest"`
	DownloadURL             string                        `json:"download_url"`
	ArtifactSizeBytes       int64                         `json:"artifact_size_bytes"`
	Platform                string                        `json:"platform"`
	Architecture            string                        `json:"architecture"`
	Compatibility           upgradeExecutionCompatibility `json:"compatibility"`
	Health                  upgradeExecutionHealth        `json:"health"`
	Rollout                 upgradeExecutionRollout       `json:"rollout"`
	Rollback                upgradeExecutionRollback      `json:"rollback"`
	IssuedAt                int64                         `json:"issued_at"`
	NotBefore               int64                         `json:"not_before"`
	ExpiresAt               int64                         `json:"expires_at"`
	// DownloadPolicy is the control plane's current download endpoint
	// (libs/entitlement UpgradeDownloadPolicy, control-signed; fix-btenv3).
	DownloadPolicy *entitlement.UpgradeDownloadPolicy `json:"download_policy,omitempty"`
}

type upgradeExecutionCompatibility struct {
	MinAgentVersion string `json:"min_agent_version"`
	MaxAgentVersion string `json:"max_agent_version"`
}

type upgradeExecutionHealth struct {
	Command                      []string `json:"command"`
	ActivationTimeoutNanoseconds int64    `json:"activation_timeout_nanoseconds"`
	ObservationWindowNanoseconds int64    `json:"observation_window_nanoseconds"`
	IntervalNanoseconds          int64    `json:"interval_nanoseconds"`
	ProbeTimeoutNanoseconds      int64    `json:"probe_timeout_nanoseconds"`
	RequiredConsecutiveSuccesses int      `json:"required_consecutive_successes"`
}

type upgradeExecutionRollout struct {
	Percentage uint8 `json:"percentage"`
}

type upgradeExecutionRollback struct {
	Automatic bool `json:"automatic"`
}

type upgradeExecutionControlDocument struct {
	Domain    string               `json:"domain"`
	Algorithm string               `json:"algorithm"`
	KeyID     string               `json:"key_id"`
	Execution upgradeExecutionWire `json:"execution"`
}

type upgradeExecutionCommitmentDocument struct {
	Domain    string               `json:"domain"`
	Algorithm string               `json:"algorithm"`
	KeyID     string               `json:"key_id"`
	Execution upgradeExecutionWire `json:"execution"`
	Signature string               `json:"signature"`
}

type upgradeExecutionPlanBuilder func(upgradeExecutionEnvelope) (Plan, error)

func VerifyAndConsumeUpgradeExecution(ctx context.Context, encoded []byte,
	options UpgradeExecutionConsumerOptions, replay UpgradeExecutionReplayStore) (Plan, error) {
	return verifyAndConsumeUpgradeExecution(ctx, encoded, options, replay, upgradeExecutionPlan)
}

func verifyAndConsumeUpgradeExecution(ctx context.Context, encoded []byte,
	options UpgradeExecutionConsumerOptions, replay UpgradeExecutionReplayStore,
	buildPlan upgradeExecutionPlanBuilder) (Plan, error) {
	if buildPlan == nil {
		return Plan{}, ErrInvalidUpgradeExecutionEnvelope
	}
	envelope, edgeSignature, err := verifyUpgradeExecution(encoded, options)
	if err != nil {
		return Plan{}, err
	}
	execution := envelope.Execution
	if replay == nil {
		return Plan{}, ErrUpgradeExecutionReplay
	}
	consumed, err := replay.ConsumeUpgradeExecution(ctx, upgradeExecutionReplayClaim(execution))
	if err != nil {
		return Plan{}, err
	}
	if !consumed {
		return Plan{}, ErrUpgradeExecutionReplay
	}
	plan, err := buildPlan(envelope)
	if err != nil {
		return Plan{}, err
	}
	plan.Signature.Value = base64.RawStdEncoding.EncodeToString(edgeSignature)
	return plan, nil
}

func verifyUpgradeExecution(encoded []byte, options UpgradeExecutionConsumerOptions) (upgradeExecutionEnvelope, []byte, error) {
	envelope, err := decodeUpgradeExecution(encoded)
	if err != nil {
		return upgradeExecutionEnvelope{}, nil, err
	}
	controlKey, ok := options.ControlKeys[envelope.ControlKeyID]
	if !ok {
		return upgradeExecutionEnvelope{}, nil, ErrUnknownUpgradeExecutionControlKey
	}
	controlDomain := upgradeExecutionControlDomain
	if envelope.Execution.Schema == upgradeExecutionV2Schema {
		controlDomain = upgradeExecutionControlDomainV2
	} else if envelope.Execution.Schema == upgradeExecutionV3Schema {
		controlDomain = upgradeExecutionControlDomainV3
	}
	controlPayload, err := json.Marshal(upgradeExecutionControlDocument{
		Domain: controlDomain, Algorithm: envelope.ControlAlgorithm,
		KeyID: envelope.ControlKeyID, Execution: envelope.Execution,
	})
	controlSignature, _ := base64.RawURLEncoding.DecodeString(envelope.ControlSignature)
	if err != nil || len(controlKey) != ed25519.PublicKeySize ||
		!ed25519.Verify(controlKey, controlPayload, controlSignature) {
		return upgradeExecutionEnvelope{}, nil, ErrInvalidUpgradeExecutionControlSignature
	}
	edgeKey, ok := options.EdgeKeys[envelope.EdgeKeyID]
	if !ok {
		return upgradeExecutionEnvelope{}, nil, ErrUnknownUpgradeExecutionEdgeKey
	}
	edgePayload, err := upgradeExecutionSigningBytes(envelope)
	edgeSignature, _ := base64.RawURLEncoding.DecodeString(envelope.EdgeSignature)
	if err != nil || len(edgeKey) != ed25519.PublicKeySize ||
		!ed25519.Verify(edgeKey, edgePayload, edgeSignature) {
		return upgradeExecutionEnvelope{}, nil, ErrInvalidUpgradeExecutionEdgeSignature
	}
	execution := envelope.Execution
	if options.RequireV2 && execution.Schema != upgradeExecutionV2Schema && execution.Schema != upgradeExecutionV3Schema {
		return upgradeExecutionEnvelope{}, nil, ErrInvalidUpgradeExecutionEnvelope
	}
	if options.ExpectedInstallationID == "" || execution.InstallationID != options.ExpectedInstallationID ||
		options.ExpectedNodeID == "" || execution.NodeID != options.ExpectedNodeID ||
		options.ExpectedCommandID == "" || execution.CommandID != options.ExpectedCommandID ||
		options.ExpectedNonce == "" || execution.Nonce != options.ExpectedNonce ||
		options.ExpectedCurrentVersion == "" || execution.CurrentVersion != options.ExpectedCurrentVersion ||
		options.ExpectedTargetVersion == "" || execution.TargetVersion != options.ExpectedTargetVersion ||
		options.ExpectedPlatform == "" || execution.Platform != options.ExpectedPlatform ||
		options.ExpectedArchitecture == "" || execution.Architecture != options.ExpectedArchitecture {
		return upgradeExecutionEnvelope{}, nil, ErrUpgradeExecutionTargetMismatch
	}
	if (execution.Schema == upgradeExecutionV2Schema || execution.Schema == upgradeExecutionV3Schema) &&
		(options.ExpectedPlanID == "" || execution.PlanID != options.ExpectedPlanID ||
			options.ExpectedPlanRevision == 0 || execution.PlanRevision != options.ExpectedPlanRevision ||
			options.ExpectedBatchID == "" || execution.BatchID != options.ExpectedBatchID) {
		return upgradeExecutionEnvelope{}, nil, ErrUpgradeExecutionTargetMismatch
	}
	now := options.Now.UTC()
	if options.Now.IsZero() || now.Add(upgradeExecutionClockSkew).Unix() < execution.NotBefore {
		return upgradeExecutionEnvelope{}, nil, ErrUpgradeExecutionNotYetValid
	}
	if now.Unix() >= execution.ExpiresAt {
		return upgradeExecutionEnvelope{}, nil, ErrUpgradeExecutionExpired
	}
	if options.MaxArtifactBytes <= 0 || execution.ArtifactSizeBytes > options.MaxArtifactBytes {
		return upgradeExecutionEnvelope{}, nil, ErrArtifactTooLarge
	}
	return envelope, edgeSignature, nil
}

func upgradeExecutionReplayClaim(execution upgradeExecutionWire) UpgradeExecutionReplayClaim {
	return UpgradeExecutionReplayClaim{
		Schema: execution.Schema, InstallationID: execution.InstallationID, NodeID: execution.NodeID,
		CommandID: execution.CommandID, Nonce: execution.Nonce, GrantDigest: execution.GrantDigest,
		PlanID: execution.PlanID, PlanRevision: execution.PlanRevision, BatchID: execution.BatchID,
		ArtifactBundleID: execution.ArtifactBundleID, ArtifactBundleSHA256: execution.ArtifactBundleSHA256,
		CommandIssuanceNotAfter: execution.CommandIssuanceNotAfter,
		ExecutionSequence:       execution.ExecutionSequence,
		ReleaseSequence:         execution.ReleaseSequence,
		Component:               execution.Component,
		ExpiresAt:               time.Unix(execution.ExpiresAt, 0).UTC(),
	}
}

func decodeUpgradeExecution(encoded []byte) (upgradeExecutionEnvelope, error) {
	if len(encoded) == 0 || len(encoded) > maxUpgradeExecutionBytes {
		return upgradeExecutionEnvelope{}, ErrInvalidUpgradeExecutionEnvelope
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var envelope upgradeExecutionEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return upgradeExecutionEnvelope{}, ErrInvalidUpgradeExecutionEnvelope
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return upgradeExecutionEnvelope{}, ErrInvalidUpgradeExecutionEnvelope
	}
	canonical, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(canonical, encoded) || validateUpgradeExecutionEnvelope(envelope) != nil {
		return upgradeExecutionEnvelope{}, ErrInvalidUpgradeExecutionEnvelope
	}
	return envelope, nil
}

func validateUpgradeExecutionEnvelope(envelope upgradeExecutionEnvelope) error {
	if envelope.ControlAlgorithm != "Ed25519" ||
		!upgradeExecutionControlKeyPattern.MatchString(envelope.ControlKeyID) ||
		envelope.EdgeAlgorithm != "Ed25519" || !safeIDPattern.MatchString(envelope.EdgeKeyID) ||
		validateUpgradeExecution(envelope.Execution) != nil {
		return ErrInvalidUpgradeExecutionEnvelope
	}
	controlSignature, controlErr := base64.RawURLEncoding.DecodeString(envelope.ControlSignature)
	edgeSignature, edgeErr := base64.RawURLEncoding.DecodeString(envelope.EdgeSignature)
	if controlErr != nil || len(controlSignature) != ed25519.SignatureSize ||
		edgeErr != nil || len(edgeSignature) != ed25519.SignatureSize {
		return ErrInvalidUpgradeExecutionEnvelope
	}
	return nil
}

func validateUpgradeExecution(execution upgradeExecutionWire) error {
	grantDigest, grantErr := base64.RawURLEncoding.DecodeString(execution.GrantDigest)
	artifactDigest, artifactErr := base64.RawURLEncoding.DecodeString(execution.SHA256Digest)
	current, currentErr := parseVersion(execution.CurrentVersion)
	target, targetErr := parseVersion(execution.TargetVersion)
	if (execution.Schema != upgradeExecutionSchema && execution.Schema != upgradeExecutionV2Schema &&
		execution.Schema != upgradeExecutionV3Schema) ||
		execution.Audience != upgradeExecutionAudience ||
		execution.Purpose != upgradeExecutionPurpose || execution.Action != upgradeExecutionAction ||
		execution.GrantDigestAlgorithm != "sha256" || grantErr != nil || len(grantDigest) != sha256.Size ||
		execution.DigestAlgorithm != "sha256" || artifactErr != nil || len(artifactDigest) != sha256.Size ||
		!validUpgradeExecutionUUID(execution.InstallationID) || !validUpgradeExecutionUUID(execution.NodeID) ||
		!validUpgradeExecutionUUID(execution.CommandID) || !validUpgradeExecutionUUID(execution.Nonce) ||
		!validUpgradeExecutionUUID(execution.ArtifactID) || execution.ReleaseSequence == 0 ||
		!upgradeExecutionCodePattern.MatchString(execution.Component) || currentErr != nil || targetErr != nil ||
		!validUpgradeExecutionURL(execution.DownloadURL) || execution.ArtifactSizeBytes <= 0 ||
		!upgradeExecutionCodePattern.MatchString(execution.Platform) ||
		!upgradeExecutionCodePattern.MatchString(execution.Architecture) ||
		execution.IssuedAt <= 0 || execution.NotBefore < execution.IssuedAt || execution.ExpiresAt <= execution.NotBefore ||
		execution.GrantExpiresAt < execution.ExpiresAt || execution.GrantExpiresAt > maxUpgradeExecutionTimestamp ||
		execution.ExpiresAt-execution.IssuedAt > maxUpgradeExecutionWindow {
		return ErrInvalidUpgradeExecutionEnvelope
	}
	v2 := execution.Schema == upgradeExecutionV2Schema
	v3 := execution.Schema == upgradeExecutionV3Schema
	durable := v2 || v3
	if !durable && (execution.PlanID != "" || execution.PlanRevision != 0 || execution.BatchID != "" ||
		execution.ArtifactBundleID != "" || execution.ArtifactBundleSHA256 != "" ||
		execution.CommandIssuanceNotAfter != 0 || execution.ExecutionSequence != 0) {
		return ErrInvalidUpgradeExecutionEnvelope
	}
	bundleDigest, bundleErr := base64.RawURLEncoding.DecodeString(execution.ArtifactBundleSHA256)
	if durable && (!validUpgradeExecutionUUID(execution.PlanID) || execution.PlanRevision == 0 ||
		execution.PlanRevision > maxUpgradePlanRevision || !validUpgradeExecutionUUID(execution.BatchID) ||
		!validUpgradeExecutionUUID(execution.ArtifactBundleID) || bundleErr != nil || len(bundleDigest) != sha256.Size ||
		execution.CommandIssuanceNotAfter <= execution.IssuedAt ||
		execution.ExpiresAt > execution.CommandIssuanceNotAfter) {
		return ErrInvalidUpgradeExecutionEnvelope
	}
	if v2 && execution.ExecutionSequence != 0 || v3 && execution.ExecutionSequence == 0 {
		return ErrInvalidUpgradeExecutionEnvelope
	}
	comparison := compareVersion(target, current)
	if (execution.Operation == string(ActionUpgrade) && comparison <= 0) ||
		(execution.Operation == string(ActionRollback) && comparison >= 0) ||
		(execution.Operation != string(ActionUpgrade) && execution.Operation != string(ActionRollback)) {
		return ErrInvalidUpgradeExecutionEnvelope
	}
	minimum, minErr := parseVersion(execution.Compatibility.MinAgentVersion)
	maximum, maxErr := parseVersion(execution.Compatibility.MaxAgentVersion)
	if minErr != nil || maxErr != nil || compareVersion(minimum, maximum) > 0 {
		return ErrInvalidUpgradeExecutionEnvelope
	}
	health := execution.Health
	if len(health.Command) == 0 || len(health.Command) > 32 || health.Command[0] != "{artifact}" ||
		health.ActivationTimeoutNanoseconds <= 0 || health.ObservationWindowNanoseconds <= 0 ||
		health.IntervalNanoseconds <= 0 || health.ProbeTimeoutNanoseconds <= 0 ||
		health.RequiredConsecutiveSuccesses <= 0 || health.IntervalNanoseconds > health.ActivationTimeoutNanoseconds ||
		health.ProbeTimeoutNanoseconds > health.ActivationTimeoutNanoseconds ||
		execution.Rollout.Percentage == 0 || execution.Rollout.Percentage > 100 || !execution.Rollback.Automatic {
		return ErrInvalidUpgradeExecutionEnvelope
	}
	if durable && (len(health.Command) != 2 || health.Command[1] != "--version") {
		return ErrInvalidUpgradeExecutionEnvelope
	}
	for _, argument := range health.Command {
		if argument == "" || len(argument) > 4096 || strings.ContainsRune(argument, 0) {
			return ErrInvalidUpgradeExecutionEnvelope
		}
	}
	if execution.DownloadPolicy != nil && execution.DownloadPolicy.Validate(execution.DownloadURL) != nil {
		return ErrInvalidUpgradeExecutionEnvelope
	}
	return nil
}

func upgradeExecutionSigningBytes(envelope upgradeExecutionEnvelope) ([]byte, error) {
	document, err := upgradeExecutionSignablePlan(envelope)
	if err != nil {
		return nil, err
	}
	return json.Marshal(document)
}

func upgradeExecutionSignablePlan(envelope upgradeExecutionEnvelope) (signablePlan, error) {
	execution := envelope.Execution
	artifactDigest, err := base64.RawURLEncoding.DecodeString(execution.SHA256Digest)
	if err != nil || len(artifactDigest) != sha256.Size {
		return signablePlan{}, ErrInvalidUpgradeExecutionEnvelope
	}
	commitmentDomain := upgradeExecutionCommitmentDomain
	if execution.Schema == upgradeExecutionV2Schema {
		commitmentDomain = upgradeExecutionCommitmentDomainV2
	} else if execution.Schema == upgradeExecutionV3Schema {
		commitmentDomain = upgradeExecutionCommitmentDomainV3
	}
	commitment, err := json.Marshal(upgradeExecutionCommitmentDocument{
		Domain: commitmentDomain, Algorithm: envelope.ControlAlgorithm,
		KeyID: envelope.ControlKeyID, Execution: execution, Signature: envelope.ControlSignature,
	})
	if err != nil {
		return signablePlan{}, ErrInvalidUpgradeExecutionEnvelope
	}
	digest := sha256.Sum256(commitment)
	document := signablePlan{
		SchemaVersion: planSchemaVersion, PlanID: execution.CommandID,
		Revision: execution.ReleaseSequence, ReleaseSequence: execution.ReleaseSequence,
		IssuedAt: time.Unix(execution.IssuedAt, 0).UTC(), ExpiresAt: time.Unix(execution.ExpiresAt, 0).UTC(),
		Action: Action(execution.Operation), CurrentVersion: execution.CurrentVersion,
		TargetVersion: execution.TargetVersion, Platform: execution.Platform, Architecture: execution.Architecture,
		Artifact: Artifact{URL: execution.DownloadURL, SHA256: hex.EncodeToString(artifactDigest), Size: execution.ArtifactSizeBytes},
		Compatibility: Compatibility{MinAgentVersion: execution.Compatibility.MinAgentVersion,
			MaxAgentVersion: execution.Compatibility.MaxAgentVersion},
		Health: HealthPolicy{
			Command:                      append([]string(nil), execution.Health.Command...),
			ActivationTimeout:            time.Duration(execution.Health.ActivationTimeoutNanoseconds),
			ObservationWindow:            time.Duration(execution.Health.ObservationWindowNanoseconds),
			Interval:                     time.Duration(execution.Health.IntervalNanoseconds),
			ProbeTimeout:                 time.Duration(execution.Health.ProbeTimeoutNanoseconds),
			RequiredConsecutiveSuccesses: execution.Health.RequiredConsecutiveSuccesses,
		},
		Rollout: RolloutPolicy{Percentage: execution.Rollout.Percentage,
			CohortSalt: "exec-v1." + base64.RawURLEncoding.EncodeToString(digest[:])},
		Rollback: RollbackPolicy{Automatic: execution.Rollback.Automatic},
		KeyID:    envelope.EdgeKeyID,
	}
	if execution.Schema == upgradeExecutionV2Schema || execution.Schema == upgradeExecutionV3Schema {
		document.Domain = upgradeExecutionEdgeDomainV2
		document.SchemaVersion = planSchemaVersionV2
		document.PlanID = execution.PlanID
		document.Revision = execution.PlanRevision
		document.BatchID = execution.BatchID
		document.ArtifactBundleID = execution.ArtifactBundleID
		document.ArtifactBundleSHA256 = execution.ArtifactBundleSHA256
		document.CommandIssuanceNotAfter = execution.CommandIssuanceNotAfter
		if execution.Schema == upgradeExecutionV3Schema {
			document.Domain = upgradeExecutionEdgeDomainV3
			document.SchemaVersion = planSchemaVersionV3
			document.ExecutionSequence = execution.ExecutionSequence
		}
	}
	return document, nil
}

func upgradeExecutionPlan(envelope upgradeExecutionEnvelope) (Plan, error) {
	document, err := upgradeExecutionSignablePlan(envelope)
	if err != nil {
		return Plan{}, err
	}
	return Plan{
		Domain: document.Domain, SchemaVersion: document.SchemaVersion, PlanID: document.PlanID,
		Revision: document.Revision, BatchID: document.BatchID, ArtifactBundleID: document.ArtifactBundleID,
		ArtifactBundleSHA256:    document.ArtifactBundleSHA256,
		CommandIssuanceNotAfter: document.CommandIssuanceNotAfter,
		ExecutionSequence:       document.ExecutionSequence, ReleaseSequence: document.ReleaseSequence,
		IssuedAt: document.IssuedAt, ExpiresAt: document.ExpiresAt, Action: document.Action,
		CurrentVersion: document.CurrentVersion, TargetVersion: document.TargetVersion,
		Platform: document.Platform, Architecture: document.Architecture, Artifact: document.Artifact,
		Compatibility: document.Compatibility, Health: document.Health, Rollout: document.Rollout,
		Rollback: document.Rollback, Signature: Signature{KeyID: document.KeyID},
	}, nil
}

func validUpgradeExecutionUUID(value string) bool {
	return value != "00000000-0000-0000-0000-000000000000" && upgradeExecutionUUIDPattern.MatchString(value)
}

func validUpgradeExecutionURL(value string) bool {
	if len(value) < 9 || len(value) > 4096 || strings.TrimSpace(value) != value {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.Host == strings.ToLower(parsed.Host) &&
		parsed.User == nil && parsed.Fragment == "" && parsed.Opaque == "" && parsed.String() == value
}
