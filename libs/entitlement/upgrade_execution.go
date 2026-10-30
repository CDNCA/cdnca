package entitlement

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
	"regexp"
	"time"

	"golang.org/x/mod/semver"
)

const (
	UpgradeExecutionSchema   = "cdnca.upgrade.execution/v1"
	UpgradeExecutionV2Schema = "cdnca.upgrade.execution/v2"
	UpgradeExecutionV3Schema = "cdnca.upgrade.execution/v3"
	UpgradeExecutionAudience = "cdnca-edge-upgrade"
	UpgradeExecutionPurpose  = "cdnca-edge-upgrade-execution"
	UpgradeExecutionAction   = "execute"

	upgradeExecutionControlSignatureDomain   = "cdnca-upgrade-execution-control-signature/v1"
	upgradeExecutionCommitmentDomain         = "cdnca-upgrade-execution-edge-consumption-commitment/v1"
	upgradeExecutionControlSignatureDomainV2 = "cdnca-upgrade-execution-control-signature/v2"
	upgradeExecutionCommitmentDomainV2       = "cdnca-upgrade-execution-edge-consumption-commitment/v2"
	upgradeExecutionEdgeSignatureDomainV2    = "cdnca-upgrade-execution-edge-signature/v2"
	upgradeExecutionControlSignatureDomainV3 = "cdnca-upgrade-execution-control-signature/v3"
	upgradeExecutionCommitmentDomainV3       = "cdnca-upgrade-execution-edge-consumption-commitment/v3"
	upgradeExecutionEdgeSignatureDomainV3    = "cdnca-upgrade-execution-edge-signature/v3"
	maxEncodedUpgradeExecutionBytes          = 128 * 1024
	maxUpgradeExecutionLifetimeSeconds       = int64((15 * time.Minute) / time.Second)
	executionPlanSchemaVersion               = 1
)

var (
	ErrInvalidUpgradeExecution                 = errors.New("invalid upgrade execution")
	ErrInvalidUpgradeExecutionEnvelope         = errors.New("invalid signed upgrade execution envelope")
	ErrUnknownUpgradeExecutionControlKey       = errors.New("unknown upgrade execution control key")
	ErrUnknownUpgradeExecutionEdgeKey          = errors.New("unknown upgrade execution edge key")
	ErrInvalidUpgradeExecutionControlSignature = errors.New("invalid upgrade execution control signature")
	ErrInvalidUpgradeExecutionEdgeSignature    = errors.New("invalid upgrade execution edge signature")
	ErrUpgradeExecutionTargetMismatch          = errors.New("upgrade execution target mismatch")
	ErrUpgradeExecutionNotYetValid             = errors.New("upgrade execution is not yet valid")
	ErrUpgradeExecutionExpired                 = errors.New("upgrade execution is expired")
)

var upgradeExecutionPlanIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type UpgradeExecution struct {
	Schema                  string                         `json:"schema"`
	Audience                string                         `json:"audience"`
	Purpose                 string                         `json:"purpose"`
	Action                  string                         `json:"action"`
	GrantDigestAlgorithm    string                         `json:"grant_digest_algorithm"`
	GrantDigest             string                         `json:"grant_digest"`
	GrantExpiresAt          int64                          `json:"grant_expires_at"`
	InstallationID          string                         `json:"installation_id"`
	NodeID                  string                         `json:"node_id"`
	CommandID               string                         `json:"command_id"`
	Nonce                   string                         `json:"nonce"`
	PlanID                  string                         `json:"plan_id,omitempty"`
	PlanRevision            uint64                         `json:"plan_revision,omitempty"`
	BatchID                 string                         `json:"batch_id,omitempty"`
	ArtifactBundleID        string                         `json:"artifact_bundle_id,omitempty"`
	ArtifactBundleSHA256    string                         `json:"artifact_bundle_sha256,omitempty"`
	CommandIssuanceNotAfter int64                          `json:"command_issuance_not_after,omitempty"`
	ExecutionSequence       uint64                         `json:"execution_sequence,omitempty"`
	ReleaseSequence         uint64                         `json:"release_sequence"`
	Component               string                         `json:"component"`
	Operation               string                         `json:"operation"`
	CurrentVersion          string                         `json:"current_version"`
	TargetVersion           string                         `json:"target_version"`
	ArtifactID              string                         `json:"artifact_id"`
	DigestAlgorithm         string                         `json:"digest_algorithm"`
	SHA256Digest            string                         `json:"sha256_digest"`
	DownloadURL             string                         `json:"download_url"`
	ArtifactSizeBytes       int64                          `json:"artifact_size_bytes"`
	Platform                string                         `json:"platform"`
	Architecture            string                         `json:"architecture"`
	Compatibility           UpgradeExecutionCompatibility  `json:"compatibility"`
	Health                  UpgradeExecutionHealthPolicy   `json:"health"`
	Rollout                 UpgradeExecutionRolloutPolicy  `json:"rollout"`
	Rollback                UpgradeExecutionRollbackPolicy `json:"rollback"`
	IssuedAt                int64                          `json:"issued_at"`
	NotBefore               int64                          `json:"not_before"`
	ExpiresAt               int64                          `json:"expires_at"`
	// DownloadPolicy (optional, control-signed) is the control plane's current
	// download endpoint for download_url; nodes adopt it (fix-btenv3).
	DownloadPolicy *UpgradeDownloadPolicy `json:"download_policy,omitempty"`
}

type UpgradeExecutionCompatibility struct {
	MinAgentVersion string `json:"min_agent_version"`
	MaxAgentVersion string `json:"max_agent_version"`
}

type UpgradeExecutionHealthPolicy struct {
	Command                      []string `json:"command"`
	ActivationTimeoutNanoseconds int64    `json:"activation_timeout_nanoseconds"`
	ObservationWindowNanoseconds int64    `json:"observation_window_nanoseconds"`
	IntervalNanoseconds          int64    `json:"interval_nanoseconds"`
	ProbeTimeoutNanoseconds      int64    `json:"probe_timeout_nanoseconds"`
	RequiredConsecutiveSuccesses int      `json:"required_consecutive_successes"`
}

type UpgradeExecutionRolloutPolicy struct {
	Percentage uint8 `json:"percentage"`
}

type UpgradeExecutionRollbackPolicy struct {
	Automatic bool `json:"automatic"`
}

type SignedUpgradeExecution struct {
	ControlAlgorithm string           `json:"control_algorithm"`
	ControlKeyID     string           `json:"control_key_id"`
	Execution        UpgradeExecution `json:"execution"`
	ControlSignature string           `json:"control_signature"`
	EdgeAlgorithm    string           `json:"edge_algorithm"`
	EdgeKeyID        string           `json:"edge_key_id"`
	EdgeSignature    string           `json:"edge_signature"`
}

type UpgradeExecutionVerifyOptions struct {
	Now                    time.Time
	ExpectedAudience       string
	ExpectedInstallationID string
	ExpectedNodeID         string
	ExpectedCommandID      string
	ExpectedNonce          string
	ExpectedCurrentVersion string
	ExpectedTargetVersion  string
	ExpectedPlanID         string
	ExpectedPlanRevision   uint64
	ExpectedBatchID        string
}

type upgradeExecutionControlDocument struct {
	Domain    string           `json:"domain"`
	Algorithm string           `json:"algorithm"`
	KeyID     string           `json:"key_id"`
	Execution UpgradeExecution `json:"execution"`
}

type upgradeExecutionCommitmentDocument struct {
	Domain    string           `json:"domain"`
	Algorithm string           `json:"algorithm"`
	KeyID     string           `json:"key_id"`
	Execution UpgradeExecution `json:"execution"`
	Signature string           `json:"signature"`
}

type upgradeExecutionPlanArtifact struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type upgradeExecutionPlanCompatibility struct {
	MinAgentVersion string `json:"min_agent_version"`
	MaxAgentVersion string `json:"max_agent_version"`
}

type upgradeExecutionPlanHealth struct {
	Command                      []string      `json:"command,omitempty"`
	ActivationTimeout            time.Duration `json:"activation_timeout"`
	ObservationWindow            time.Duration `json:"observation_window"`
	Interval                     time.Duration `json:"interval"`
	ProbeTimeout                 time.Duration `json:"probe_timeout"`
	RequiredConsecutiveSuccesses int           `json:"required_consecutive_successes"`
}

type upgradeExecutionPlanRollout struct {
	Percentage uint8  `json:"percentage"`
	CohortSalt string `json:"cohort_salt"`
}

type upgradeExecutionPlanRollback struct {
	Automatic bool `json:"automatic"`
}

type upgradeExecutionPlanSigningDocument struct {
	Domain                  string                            `json:"domain,omitempty"`
	SchemaVersion           int                               `json:"schema_version"`
	PlanID                  string                            `json:"plan_id"`
	Revision                uint64                            `json:"revision"`
	BatchID                 string                            `json:"batch_id,omitempty"`
	ArtifactBundleID        string                            `json:"artifact_bundle_id,omitempty"`
	ArtifactBundleSHA256    string                            `json:"artifact_bundle_sha256,omitempty"`
	CommandIssuanceNotAfter int64                             `json:"command_issuance_not_after,omitempty"`
	ExecutionSequence       uint64                            `json:"execution_sequence,omitempty"`
	ReleaseSequence         uint64                            `json:"release_sequence"`
	IssuedAt                time.Time                         `json:"issued_at"`
	ExpiresAt               time.Time                         `json:"expires_at"`
	Action                  string                            `json:"action"`
	CurrentVersion          string                            `json:"current_version"`
	TargetVersion           string                            `json:"target_version"`
	Platform                string                            `json:"platform"`
	Architecture            string                            `json:"architecture"`
	Artifact                upgradeExecutionPlanArtifact      `json:"artifact"`
	Compatibility           upgradeExecutionPlanCompatibility `json:"compatibility"`
	Health                  upgradeExecutionPlanHealth        `json:"health"`
	Rollout                 upgradeExecutionPlanRollout       `json:"rollout"`
	Rollback                upgradeExecutionPlanRollback      `json:"rollback"`
	KeyID                   string                            `json:"key_id"`
}

func (execution UpgradeExecution) Validate() error {
	grantDigest, grantDigestErr := base64.RawURLEncoding.DecodeString(execution.GrantDigest)
	artifactDigest, artifactDigestErr := base64.RawURLEncoding.DecodeString(execution.SHA256Digest)
	if (execution.Schema != UpgradeExecutionSchema && execution.Schema != UpgradeExecutionV2Schema &&
		execution.Schema != UpgradeExecutionV3Schema) ||
		execution.Audience != UpgradeExecutionAudience ||
		execution.Purpose != UpgradeExecutionPurpose || execution.Action != UpgradeExecutionAction ||
		execution.GrantDigestAlgorithm != "sha256" || grantDigestErr != nil || len(grantDigest) != sha256.Size ||
		execution.DigestAlgorithm != "sha256" || artifactDigestErr != nil || len(artifactDigest) != sha256.Size ||
		!validCanonicalUUID(execution.InstallationID) || !validCanonicalUUID(execution.NodeID) ||
		!validCanonicalUUID(execution.CommandID) || !validCanonicalUUID(execution.Nonce) ||
		!validCanonicalUUID(execution.ArtifactID) || execution.ReleaseSequence == 0 ||
		!upgradeGrantCodePattern.MatchString(execution.Component) || !validCanonicalSemver(execution.CurrentVersion) ||
		!validCanonicalSemver(execution.TargetVersion) || execution.Operation != upgradeOperation(execution.CurrentVersion, execution.TargetVersion) ||
		(execution.Operation != UpgradeOperation && execution.Operation != RollbackOperation) ||
		!validUpgradeDownloadURL(execution.DownloadURL) || execution.ArtifactSizeBytes <= 0 ||
		!upgradeGrantCodePattern.MatchString(execution.Platform) || !upgradeGrantCodePattern.MatchString(execution.Architecture) ||
		execution.IssuedAt <= 0 || execution.NotBefore < execution.IssuedAt || execution.ExpiresAt <= execution.NotBefore ||
		execution.GrantExpiresAt < execution.ExpiresAt || execution.GrantExpiresAt > maxUnixTimestamp ||
		execution.ExpiresAt-execution.IssuedAt > maxUpgradeExecutionLifetimeSeconds {
		return ErrInvalidUpgradeExecution
	}
	provenance := execution.Schema == UpgradeExecutionV2Schema || execution.Schema == UpgradeExecutionV3Schema
	v3 := execution.Schema == UpgradeExecutionV3Schema
	if (!v3 && execution.ExecutionSequence != 0) || (v3 && execution.ExecutionSequence == 0) {
		return ErrInvalidUpgradeExecution
	}
	if !provenance && (execution.PlanID != "" || execution.PlanRevision != 0 || execution.BatchID != "" ||
		execution.ArtifactBundleID != "" || execution.ArtifactBundleSHA256 != "" ||
		execution.CommandIssuanceNotAfter != 0) {
		return ErrInvalidUpgradeExecution
	}
	bundleDigest, bundleErr := base64.RawURLEncoding.DecodeString(execution.ArtifactBundleSHA256)
	if provenance && (!validCanonicalUUID(execution.PlanID) || execution.PlanRevision == 0 ||
		execution.PlanRevision > MaxUpgradePlanRevision ||
		!validCanonicalUUID(execution.BatchID) || !validCanonicalUUID(execution.ArtifactBundleID) ||
		bundleErr != nil || len(bundleDigest) != sha256.Size ||
		execution.CommandIssuanceNotAfter <= execution.IssuedAt ||
		execution.ExpiresAt > execution.CommandIssuanceNotAfter) {
		return ErrInvalidUpgradeExecution
	}
	if !validCanonicalSemver(execution.Compatibility.MinAgentVersion) ||
		!validCanonicalSemver(execution.Compatibility.MaxAgentVersion) ||
		semver.Compare("v"+execution.Compatibility.MinAgentVersion, "v"+execution.Compatibility.MaxAgentVersion) > 0 {
		return ErrInvalidUpgradeExecution
	}
	health := execution.Health
	if len(health.Command) == 0 || len(health.Command) > 32 || health.Command[0] != "{artifact}" ||
		health.ActivationTimeoutNanoseconds <= 0 || health.ObservationWindowNanoseconds <= 0 ||
		health.IntervalNanoseconds <= 0 || health.ProbeTimeoutNanoseconds <= 0 ||
		health.RequiredConsecutiveSuccesses <= 0 || health.IntervalNanoseconds > health.ActivationTimeoutNanoseconds ||
		health.ProbeTimeoutNanoseconds > health.ActivationTimeoutNanoseconds ||
		execution.Rollout.Percentage == 0 || execution.Rollout.Percentage > 100 || !execution.Rollback.Automatic {
		return ErrInvalidUpgradeExecution
	}
	for _, argument := range health.Command {
		if argument == "" || len(argument) > 4096 || bytes.IndexByte([]byte(argument), 0) >= 0 {
			return ErrInvalidUpgradeExecution
		}
	}
	if execution.DownloadPolicy != nil && execution.DownloadPolicy.Validate(execution.DownloadURL) != nil {
		return ErrInvalidUpgradeExecution
	}
	return nil
}

func SignUpgradeExecution(ctx context.Context, execution UpgradeExecution,
	controlSigner, edgeSigner Signer) (SignedUpgradeExecution, error) {
	if execution.Validate() != nil || controlSigner == nil || edgeSigner == nil ||
		ValidateKeyID(controlSigner.KeyID()) != nil || !upgradeExecutionPlanIDPattern.MatchString(edgeSigner.KeyID()) {
		return SignedUpgradeExecution{}, ErrInvalidUpgradeExecution
	}
	signed := SignedUpgradeExecution{
		ControlAlgorithm: Algorithm, ControlKeyID: controlSigner.KeyID(), Execution: execution,
		EdgeAlgorithm: Algorithm, EdgeKeyID: edgeSigner.KeyID(),
	}
	controlPayload, err := signed.controlSigningBytes()
	if err != nil {
		return SignedUpgradeExecution{}, err
	}
	controlSignature, err := controlSigner.Sign(ctx, controlPayload)
	if err != nil {
		return SignedUpgradeExecution{}, err
	}
	if len(controlSignature) != ed25519.SignatureSize {
		return SignedUpgradeExecution{}, ErrInvalidUpgradeExecutionControlSignature
	}
	signed.ControlSignature = base64.RawURLEncoding.EncodeToString(controlSignature)
	edgePayload, err := signed.edgeSigningBytes()
	if err != nil {
		return SignedUpgradeExecution{}, err
	}
	edgeSignature, err := edgeSigner.Sign(ctx, edgePayload)
	if err != nil {
		return SignedUpgradeExecution{}, err
	}
	if len(edgeSignature) != ed25519.SignatureSize {
		return SignedUpgradeExecution{}, ErrInvalidUpgradeExecutionEdgeSignature
	}
	signed.EdgeSignature = base64.RawURLEncoding.EncodeToString(edgeSignature)
	return signed, nil
}

func (signed SignedUpgradeExecution) Encode() ([]byte, error) {
	if err := signed.validateEnvelope(); err != nil {
		return nil, err
	}
	return json.Marshal(signed)
}

func DecodeUpgradeExecution(encoded []byte) (SignedUpgradeExecution, error) {
	if len(encoded) == 0 || len(encoded) > maxEncodedUpgradeExecutionBytes {
		return SignedUpgradeExecution{}, ErrInvalidUpgradeExecutionEnvelope
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var signed SignedUpgradeExecution
	if err := decoder.Decode(&signed); err != nil {
		return SignedUpgradeExecution{}, ErrInvalidUpgradeExecutionEnvelope
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return SignedUpgradeExecution{}, ErrInvalidUpgradeExecutionEnvelope
	}
	canonical, err := json.Marshal(signed)
	if err != nil || !bytes.Equal(canonical, encoded) || signed.validateEnvelope() != nil {
		return SignedUpgradeExecution{}, ErrInvalidUpgradeExecutionEnvelope
	}
	return signed, nil
}

func VerifyUpgradeExecution(signed SignedUpgradeExecution, controlKeys, edgeKeys *KeyRing,
	options UpgradeExecutionVerifyOptions) (UpgradeExecution, error) {
	if err := signed.validateEnvelope(); err != nil {
		return UpgradeExecution{}, err
	}
	if controlKeys == nil {
		return UpgradeExecution{}, ErrUnknownUpgradeExecutionControlKey
	}
	controlKey, ok := controlKeys.keys[signed.ControlKeyID]
	if !ok {
		return UpgradeExecution{}, ErrUnknownUpgradeExecutionControlKey
	}
	controlPayload, err := signed.controlSigningBytes()
	controlSignature, _ := base64.RawURLEncoding.DecodeString(signed.ControlSignature)
	if err != nil || !ed25519.Verify(controlKey, controlPayload, controlSignature) {
		return UpgradeExecution{}, ErrInvalidUpgradeExecutionControlSignature
	}
	if edgeKeys == nil {
		return UpgradeExecution{}, ErrUnknownUpgradeExecutionEdgeKey
	}
	edgeKey, ok := edgeKeys.keys[signed.EdgeKeyID]
	if !ok {
		return UpgradeExecution{}, ErrUnknownUpgradeExecutionEdgeKey
	}
	edgePayload, err := signed.edgeSigningBytes()
	edgeSignature, _ := base64.RawURLEncoding.DecodeString(signed.EdgeSignature)
	if err != nil || !ed25519.Verify(edgeKey, edgePayload, edgeSignature) {
		return UpgradeExecution{}, ErrInvalidUpgradeExecutionEdgeSignature
	}
	execution := signed.Execution
	if options.ExpectedAudience == "" || execution.Audience != options.ExpectedAudience ||
		options.ExpectedInstallationID == "" || execution.InstallationID != options.ExpectedInstallationID ||
		options.ExpectedNodeID == "" || execution.NodeID != options.ExpectedNodeID ||
		options.ExpectedCommandID == "" || execution.CommandID != options.ExpectedCommandID ||
		options.ExpectedNonce == "" || execution.Nonce != options.ExpectedNonce ||
		options.ExpectedCurrentVersion == "" || execution.CurrentVersion != options.ExpectedCurrentVersion ||
		options.ExpectedTargetVersion == "" || execution.TargetVersion != options.ExpectedTargetVersion {
		return UpgradeExecution{}, ErrUpgradeExecutionTargetMismatch
	}
	if (execution.Schema == UpgradeExecutionV2Schema || execution.Schema == UpgradeExecutionV3Schema) &&
		(options.ExpectedPlanID == "" || execution.PlanID != options.ExpectedPlanID ||
			options.ExpectedPlanRevision == 0 || execution.PlanRevision != options.ExpectedPlanRevision ||
			options.ExpectedBatchID == "" || execution.BatchID != options.ExpectedBatchID) {
		return UpgradeExecution{}, ErrUpgradeExecutionTargetMismatch
	}
	if options.Now.IsZero() || notYetValid(options.Now.UTC().Unix(), execution.NotBefore) {
		return UpgradeExecution{}, ErrUpgradeExecutionNotYetValid
	}
	if options.Now.UTC().Unix() >= execution.ExpiresAt {
		return UpgradeExecution{}, ErrUpgradeExecutionExpired
	}
	return execution, nil
}

func CanonicalUpgradeGrantDigest(encoded []byte) (string, error) {
	if _, err := DecodeUpgradeGrant(encoded); err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

func CanonicalUpgradeCommandGrantDigest(encoded []byte) (string, error) {
	if _, err := DecodeUpgradeCommandGrant(encoded); err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

func IssueCommandExecution(ctx context.Context, encodedCommandGrant []byte, commandGrantKeys *KeyRing,
	options UpgradeCommandGrantVerifyOptions, controlSigner, edgeSigner Signer) ([]byte, error) {
	return IssueCommandExecutionWithDownloadURL(ctx, encodedCommandGrant, commandGrantKeys, options,
		controlSigner, edgeSigner, "")
}

// IssueCommandExecutionWithDownloadURL signs the execution with downloadURL
// (when non-empty) in place of the license-signed manifest URL, so nodes fetch
// the artifact from the control plane cache. Every other field, including the
// signed SHA-256 digest and size the node verifies, still comes from the grant.
func IssueCommandExecutionWithDownloadURL(ctx context.Context, encodedCommandGrant []byte, commandGrantKeys *KeyRing,
	options UpgradeCommandGrantVerifyOptions, controlSigner, edgeSigner Signer, downloadURL string) ([]byte, error) {
	return IssueCommandExecutionWithDownloadPolicy(ctx, encodedCommandGrant, commandGrantKeys, options,
		controlSigner, edgeSigner, downloadURL, nil)
}

// IssueCommandExecutionWithDownloadPolicy also signs the control plane's
// current download policy for downloadURL (nil: none), see UpgradeDownloadPolicy.
func IssueCommandExecutionWithDownloadPolicy(ctx context.Context, encodedCommandGrant []byte, commandGrantKeys *KeyRing,
	options UpgradeCommandGrantVerifyOptions, controlSigner, edgeSigner Signer, downloadURL string,
	policy *UpgradeDownloadPolicy) ([]byte, error) {
	if downloadURL != "" && !validUpgradeDownloadURL(downloadURL) {
		return nil, ErrInvalidUpgradeExecution
	}
	signedGrant, err := DecodeUpgradeCommandGrant(encodedCommandGrant)
	if err != nil {
		return nil, err
	}
	grant, err := commandGrantKeys.VerifyUpgradeCommandGrant(signedGrant, options)
	if err != nil {
		return nil, err
	}
	grantDigest, err := CanonicalUpgradeCommandGrantDigest(encodedCommandGrant)
	if err != nil {
		return nil, err
	}
	execution := UpgradeExecution{Schema: UpgradeExecutionSchema, Audience: UpgradeExecutionAudience,
		Purpose: UpgradeExecutionPurpose, Action: UpgradeExecutionAction, GrantDigestAlgorithm: "sha256",
		GrantDigest: grantDigest, GrantExpiresAt: grant.ExpiresAt, InstallationID: grant.InstallationID,
		NodeID: grant.NodeID, CommandID: grant.CommandID, Nonce: grant.Nonce,
		ExecutionSequence: grant.ExecutionSequence, ReleaseSequence: grant.ChannelRevision,
		Component: grant.Component, Operation: grant.Operation, CurrentVersion: grant.CurrentVersion,
		TargetVersion: grant.Version, ArtifactID: grant.ArtifactID, DigestAlgorithm: grant.DigestAlgorithm,
		SHA256Digest: grant.SHA256Digest, DownloadURL: grant.DownloadURL, ArtifactSizeBytes: grant.ArtifactSizeBytes,
		Platform: grant.Platform, Architecture: grant.Architecture, Compatibility: grant.Compatibility,
		Health: grant.Health, Rollout: grant.Rollout, Rollback: grant.Rollback,
		IssuedAt: grant.IssuedAt, NotBefore: grant.NotBefore, ExpiresAt: grant.ExpiresAt}
	if grant.Schema == UpgradeCommandGrantV2Schema || grant.Schema == UpgradeCommandGrantV3Schema {
		execution.Schema = UpgradeExecutionV2Schema
		execution.PlanID = grant.PlanID
		execution.PlanRevision = grant.PlanRevision
		execution.BatchID = grant.BatchID
		execution.ArtifactBundleID = grant.ArtifactBundleID
		execution.ArtifactBundleSHA256 = grant.ArtifactBundleSHA256
		execution.CommandIssuanceNotAfter = grant.CommandIssuanceNotAfter
	}
	if grant.Schema == UpgradeCommandGrantV3Schema {
		execution.Schema = UpgradeExecutionV3Schema
		execution.ReleaseSequence = grant.ReleaseSequence
	}
	if downloadURL != "" {
		execution.DownloadURL = downloadURL
	}
	if policy != nil {
		copied := *policy
		copied.Addresses = append([]string(nil), policy.Addresses...)
		execution.DownloadPolicy = &copied
	}
	signed, err := SignUpgradeExecution(ctx, execution, controlSigner, edgeSigner)
	if err != nil {
		return nil, err
	}
	return signed.Encode()
}

func (signed SignedUpgradeExecution) validateEnvelope() error {
	if signed.ControlAlgorithm != Algorithm || ValidateKeyID(signed.ControlKeyID) != nil ||
		signed.EdgeAlgorithm != Algorithm || !upgradeExecutionPlanIDPattern.MatchString(signed.EdgeKeyID) ||
		signed.Execution.Validate() != nil {
		return ErrInvalidUpgradeExecutionEnvelope
	}
	controlSignature, controlErr := base64.RawURLEncoding.DecodeString(signed.ControlSignature)
	edgeSignature, edgeErr := base64.RawURLEncoding.DecodeString(signed.EdgeSignature)
	if controlErr != nil || len(controlSignature) != ed25519.SignatureSize ||
		edgeErr != nil || len(edgeSignature) != ed25519.SignatureSize {
		return ErrInvalidUpgradeExecutionEnvelope
	}
	return nil
}

func (signed SignedUpgradeExecution) controlSigningBytes() ([]byte, error) {
	domain := upgradeExecutionControlSignatureDomain
	if signed.Execution.Schema == UpgradeExecutionV2Schema {
		domain = upgradeExecutionControlSignatureDomainV2
	} else if signed.Execution.Schema == UpgradeExecutionV3Schema {
		domain = upgradeExecutionControlSignatureDomainV3
	}
	return json.Marshal(upgradeExecutionControlDocument{
		Domain: domain, Algorithm: signed.ControlAlgorithm,
		KeyID: signed.ControlKeyID, Execution: signed.Execution,
	})
}

func (signed SignedUpgradeExecution) edgeSigningBytes() ([]byte, error) {
	document, err := signed.planSigningDocument()
	if err != nil {
		return nil, err
	}
	return json.Marshal(document)
}

func (signed SignedUpgradeExecution) planSigningDocument() (upgradeExecutionPlanSigningDocument, error) {
	execution := signed.Execution
	artifactDigest, err := base64.RawURLEncoding.DecodeString(execution.SHA256Digest)
	if err != nil || len(artifactDigest) != sha256.Size {
		return upgradeExecutionPlanSigningDocument{}, ErrInvalidUpgradeExecution
	}
	commitmentDomain := upgradeExecutionCommitmentDomain
	if execution.Schema == UpgradeExecutionV2Schema {
		commitmentDomain = upgradeExecutionCommitmentDomainV2
	} else if execution.Schema == UpgradeExecutionV3Schema {
		commitmentDomain = upgradeExecutionCommitmentDomainV3
	}
	commitment, err := json.Marshal(upgradeExecutionCommitmentDocument{
		Domain: commitmentDomain, Algorithm: signed.ControlAlgorithm,
		KeyID: signed.ControlKeyID, Execution: execution, Signature: signed.ControlSignature,
	})
	if err != nil {
		return upgradeExecutionPlanSigningDocument{}, err
	}
	digest := sha256.Sum256(commitment)
	document := upgradeExecutionPlanSigningDocument{
		SchemaVersion: executionPlanSchemaVersion, PlanID: execution.CommandID,
		Revision: execution.ReleaseSequence, ReleaseSequence: execution.ReleaseSequence,
		IssuedAt: time.Unix(execution.IssuedAt, 0).UTC(), ExpiresAt: time.Unix(execution.ExpiresAt, 0).UTC(),
		Action: execution.Operation, CurrentVersion: execution.CurrentVersion, TargetVersion: execution.TargetVersion,
		Platform: execution.Platform, Architecture: execution.Architecture,
		Artifact: upgradeExecutionPlanArtifact{URL: execution.DownloadURL,
			SHA256: hex.EncodeToString(artifactDigest), Size: execution.ArtifactSizeBytes},
		Compatibility: upgradeExecutionPlanCompatibility{
			MinAgentVersion: execution.Compatibility.MinAgentVersion,
			MaxAgentVersion: execution.Compatibility.MaxAgentVersion,
		},
		Health: upgradeExecutionPlanHealth{
			Command:                      execution.Health.Command,
			ActivationTimeout:            time.Duration(execution.Health.ActivationTimeoutNanoseconds),
			ObservationWindow:            time.Duration(execution.Health.ObservationWindowNanoseconds),
			Interval:                     time.Duration(execution.Health.IntervalNanoseconds),
			ProbeTimeout:                 time.Duration(execution.Health.ProbeTimeoutNanoseconds),
			RequiredConsecutiveSuccesses: execution.Health.RequiredConsecutiveSuccesses,
		},
		Rollout: upgradeExecutionPlanRollout{Percentage: execution.Rollout.Percentage,
			CohortSalt: "exec-v1." + base64.RawURLEncoding.EncodeToString(digest[:])},
		Rollback: upgradeExecutionPlanRollback{Automatic: execution.Rollback.Automatic},
		KeyID:    signed.EdgeKeyID,
	}
	if execution.Schema == UpgradeExecutionV2Schema || execution.Schema == UpgradeExecutionV3Schema {
		document.Domain = upgradeExecutionEdgeSignatureDomainV2
		document.SchemaVersion = 2
		document.PlanID = execution.PlanID
		document.Revision = execution.PlanRevision
		document.BatchID = execution.BatchID
		document.ArtifactBundleID = execution.ArtifactBundleID
		document.ArtifactBundleSHA256 = execution.ArtifactBundleSHA256
		document.CommandIssuanceNotAfter = execution.CommandIssuanceNotAfter
	}
	if execution.Schema == UpgradeExecutionV3Schema {
		document.Domain = upgradeExecutionEdgeSignatureDomainV3
		document.SchemaVersion = 3
		document.ExecutionSequence = execution.ExecutionSequence
	}
	return document, nil
}
