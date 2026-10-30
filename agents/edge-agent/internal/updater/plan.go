package updater

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	planSchemaVersion   = 1
	planSchemaVersionV2 = 2
	planSchemaVersionV3 = 3
)

var safeIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type signablePlan struct {
	Domain                  string         `json:"domain,omitempty"`
	SchemaVersion           int            `json:"schema_version"`
	PlanID                  string         `json:"plan_id"`
	Revision                uint64         `json:"revision"`
	BatchID                 string         `json:"batch_id,omitempty"`
	ArtifactBundleID        string         `json:"artifact_bundle_id,omitempty"`
	ArtifactBundleSHA256    string         `json:"artifact_bundle_sha256,omitempty"`
	CommandIssuanceNotAfter int64          `json:"command_issuance_not_after,omitempty"`
	ExecutionSequence       uint64         `json:"execution_sequence,omitempty"`
	ReleaseSequence         uint64         `json:"release_sequence"`
	IssuedAt                time.Time      `json:"issued_at"`
	ExpiresAt               time.Time      `json:"expires_at"`
	Action                  Action         `json:"action"`
	CurrentVersion          string         `json:"current_version"`
	TargetVersion           string         `json:"target_version"`
	Platform                string         `json:"platform"`
	Architecture            string         `json:"architecture"`
	Artifact                Artifact       `json:"artifact"`
	Compatibility           Compatibility  `json:"compatibility"`
	Health                  HealthPolicy   `json:"health"`
	Rollout                 RolloutPolicy  `json:"rollout"`
	Rollback                RollbackPolicy `json:"rollback"`
	KeyID                   string         `json:"key_id"`
}

func SigningBytes(plan Plan) ([]byte, error) {
	value := signablePlan{
		Domain: plan.Domain, SchemaVersion: plan.SchemaVersion, PlanID: plan.PlanID, Revision: plan.Revision,
		BatchID: plan.BatchID, ArtifactBundleID: plan.ArtifactBundleID,
		ArtifactBundleSHA256: plan.ArtifactBundleSHA256, CommandIssuanceNotAfter: plan.CommandIssuanceNotAfter,
		ExecutionSequence: plan.ExecutionSequence, ReleaseSequence: plan.ReleaseSequence,
		IssuedAt: plan.IssuedAt, ExpiresAt: plan.ExpiresAt, Action: plan.Action,
		CurrentVersion: plan.CurrentVersion, TargetVersion: plan.TargetVersion,
		Platform: plan.Platform, Architecture: plan.Architecture, Artifact: plan.Artifact,
		Compatibility: plan.Compatibility, Health: plan.Health, Rollout: plan.Rollout, Rollback: plan.Rollback,
		KeyID: plan.Signature.KeyID,
	}
	return json.Marshal(value)
}

func Sign(plan *Plan, keyID string, privateKey ed25519.PrivateKey) error {
	if plan == nil || len(privateKey) != ed25519.PrivateKeySize || !safeIDPattern.MatchString(keyID) {
		return fmt.Errorf("%w: signing input", ErrInvalidPlan)
	}
	plan.Signature = Signature{KeyID: keyID}
	payload, err := SigningBytes(*plan)
	if err != nil {
		return fmt.Errorf("%w: encode signing payload", ErrInvalidPlan)
	}
	plan.Signature.Value = base64.RawStdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	return nil
}

func planDigest(plan Plan) (string, error) {
	payload, err := SigningBytes(plan)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append(payload, []byte(plan.Signature.Value)...))
	return hex.EncodeToString(digest[:]), nil
}

func validatePlan(plan Plan, config Config, now time.Time, allowExpired bool) error {
	if (plan.SchemaVersion != planSchemaVersion && plan.SchemaVersion != planSchemaVersionV2 &&
		plan.SchemaVersion != planSchemaVersionV3) ||
		!safeIDPattern.MatchString(plan.PlanID) || plan.Revision == 0 || plan.ReleaseSequence == 0 ||
		!safeIDPattern.MatchString(plan.Signature.KeyID) {
		return fmt.Errorf("%w: schema, plan ID, revision, or key ID", ErrInvalidPlan)
	}
	if plan.SchemaVersion == planSchemaVersion && (plan.Domain != "" || plan.BatchID != "" || plan.ArtifactBundleID != "" ||
		plan.ArtifactBundleSHA256 != "" || plan.CommandIssuanceNotAfter != 0 || plan.ExecutionSequence != 0) {
		return fmt.Errorf("%w: v1 plan contains v2 provenance", ErrInvalidPlan)
	}
	bundleDigest, bundleErr := base64.RawURLEncoding.DecodeString(plan.ArtifactBundleSHA256)
	if plan.SchemaVersion == planSchemaVersionV2 && (plan.Domain != upgradeExecutionEdgeDomainV2 ||
		!validUpgradeExecutionUUID(plan.PlanID) || plan.Revision > maxUpgradePlanRevision ||
		!validUpgradeExecutionUUID(plan.BatchID) || !validUpgradeExecutionUUID(plan.ArtifactBundleID) ||
		bundleErr != nil || len(bundleDigest) != sha256.Size ||
		plan.ExecutionSequence != 0 ||
		plan.CommandIssuanceNotAfter <= plan.IssuedAt.Unix() || plan.ExpiresAt.Unix() > plan.CommandIssuanceNotAfter) {
		return fmt.Errorf("%w: invalid v2 provenance", ErrInvalidPlan)
	}
	if plan.SchemaVersion == planSchemaVersionV3 && (plan.Domain != upgradeExecutionEdgeDomainV3 ||
		!validUpgradeExecutionUUID(plan.PlanID) || plan.Revision > maxUpgradePlanRevision ||
		!validUpgradeExecutionUUID(plan.BatchID) || !validUpgradeExecutionUUID(plan.ArtifactBundleID) ||
		bundleErr != nil || len(bundleDigest) != sha256.Size || plan.ExecutionSequence == 0 ||
		plan.CommandIssuanceNotAfter <= plan.IssuedAt.Unix() || plan.ExpiresAt.Unix() > plan.CommandIssuanceNotAfter) {
		return fmt.Errorf("%w: invalid v3 provenance", ErrInvalidPlan)
	}
	if plan.IssuedAt.IsZero() || plan.ExpiresAt.IsZero() || !plan.IssuedAt.Equal(plan.IssuedAt.UTC()) ||
		!plan.ExpiresAt.Equal(plan.ExpiresAt.UTC()) || !plan.ExpiresAt.After(plan.IssuedAt) || plan.IssuedAt.After(now.Add(5*time.Minute)) {
		return fmt.Errorf("%w: validity interval", ErrInvalidPlan)
	}
	if !allowExpired && !now.Before(plan.ExpiresAt) {
		return ErrExpired
	}
	key, exists := config.Keys[plan.Signature.KeyID]
	if !exists {
		return ErrUnknownKey
	}
	signature, err := base64.RawStdEncoding.DecodeString(plan.Signature.Value)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return ErrInvalidSignature
	}
	payload, err := SigningBytes(plan)
	if err != nil || !ed25519.Verify(key, payload, signature) {
		return ErrInvalidSignature
	}
	if plan.Platform != config.Platform || plan.Architecture != config.Architecture {
		return fmt.Errorf("%w: platform or architecture", ErrIncompatible)
	}
	if !safeIDPattern.MatchString(config.NodeID) || plan.Rollout.Percentage == 0 || plan.Rollout.Percentage > 100 ||
		!safeIDPattern.MatchString(plan.Rollout.CohortSalt) {
		return fmt.Errorf("%w: rollout policy", ErrInvalidPlan)
	}
	cohort := sha256.Sum256([]byte(plan.Rollout.CohortSalt + "\x00" + config.NodeID))
	bucket := (uint16(cohort[0])<<8 | uint16(cohort[1])) % 10000
	if bucket >= uint16(plan.Rollout.Percentage)*100 {
		return ErrRolloutIneligible
	}
	current, err := parseVersion(plan.CurrentVersion)
	if err != nil {
		return fmt.Errorf("%w: current version", ErrInvalidPlan)
	}
	target, err := parseVersion(plan.TargetVersion)
	if err != nil {
		return fmt.Errorf("%w: target version", ErrInvalidPlan)
	}
	comparison := compareVersion(target, current)
	switch plan.Action {
	case ActionUpgrade:
		if comparison <= 0 {
			return ErrDowngrade
		}
	case ActionRollback:
		if comparison >= 0 {
			return fmt.Errorf("%w: rollback target must be older", ErrInvalidPlan)
		}
	default:
		return fmt.Errorf("%w: action", ErrInvalidPlan)
	}
	minimum, err := parseVersion(plan.Compatibility.MinAgentVersion)
	if err != nil {
		return fmt.Errorf("%w: minimum compatible version", ErrInvalidPlan)
	}
	maximum, err := parseVersion(plan.Compatibility.MaxAgentVersion)
	if err != nil || compareVersion(minimum, maximum) > 0 {
		return fmt.Errorf("%w: maximum compatible version", ErrInvalidPlan)
	}
	agent, err := parseVersion(config.AgentVersion)
	if err != nil {
		return fmt.Errorf("%w: configured agent version", ErrIncompatible)
	}
	if compareVersion(agent, minimum) < 0 || compareVersion(agent, maximum) > 0 {
		return fmt.Errorf("%w: agent version range", ErrIncompatible)
	}
	decodedDigest, err := hex.DecodeString(plan.Artifact.SHA256)
	if err != nil || len(decodedDigest) != sha256.Size || strings.ToLower(plan.Artifact.SHA256) != plan.Artifact.SHA256 {
		return fmt.Errorf("%w: artifact digest", ErrInvalidPlan)
	}
	if plan.Artifact.Size <= 0 || plan.Artifact.Size > config.MaxArtifactBytes {
		return ErrArtifactTooLarge
	}
	artifactURL, err := url.Parse(plan.Artifact.URL)
	if err != nil || artifactURL.Scheme != "https" || artifactURL.Host == "" || artifactURL.User != nil || artifactURL.Fragment != "" {
		return ErrDownloadPolicy
	}
	if plan.Health.ActivationTimeout <= 0 || plan.Health.ObservationWindow <= 0 || plan.Health.Interval <= 0 ||
		plan.Health.ProbeTimeout <= 0 || plan.Health.RequiredConsecutiveSuccesses <= 0 ||
		plan.Health.Interval > plan.Health.ActivationTimeout || plan.Health.ProbeTimeout > plan.Health.ActivationTimeout {
		return fmt.Errorf("%w: health policy", ErrInvalidPlan)
	}
	if !plan.Rollback.Automatic {
		return fmt.Errorf("%w: automatic rollback is required", ErrInvalidPlan)
	}
	if config.Probe == nil {
		if len(plan.Health.Command) == 0 || plan.Health.Command[0] != "{artifact}" {
			return fmt.Errorf("%w: health command must execute the signed artifact directly", ErrInvalidPlan)
		}
	}
	if (plan.SchemaVersion == planSchemaVersionV2 || plan.SchemaVersion == planSchemaVersionV3) &&
		(len(plan.Health.Command) != 2 || plan.Health.Command[0] != "{artifact}" || plan.Health.Command[1] != "--version") {
		return fmt.Errorf("%w: v2 health profile", ErrInvalidPlan)
	}
	for _, argument := range plan.Health.Command {
		if argument == "" || strings.ContainsRune(argument, '\x00') {
			return fmt.Errorf("%w: health command", ErrInvalidPlan)
		}
	}
	return nil
}

type semanticVersion struct {
	major uint64
	minor uint64
	patch uint64
	pre   string
}

func parseVersion(value string) (semanticVersion, error) {
	if value == "" || strings.TrimSpace(value) != value || strings.Contains(value, "+") {
		return semanticVersion{}, fmt.Errorf("invalid version")
	}
	core, pre, found := strings.Cut(value, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 || (found && !validPrerelease(pre)) {
		return semanticVersion{}, fmt.Errorf("invalid version")
	}
	numbers := make([]uint64, 3)
	for index, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return semanticVersion{}, fmt.Errorf("invalid version")
		}
		parsed, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return semanticVersion{}, fmt.Errorf("invalid version")
		}
		numbers[index] = parsed
	}
	return semanticVersion{major: numbers[0], minor: numbers[1], patch: numbers[2], pre: pre}, nil
}

func validPrerelease(value string) bool {
	if value == "" {
		return false
	}
	for _, identifier := range strings.Split(value, ".") {
		if identifier == "" || (len(identifier) > 1 && identifier[0] == '0' && numericIdentifier(identifier)) {
			return false
		}
		for _, character := range identifier {
			if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
				(character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func numericIdentifier(value string) bool {
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return value != ""
}

// VersionBefore reports whether version precedes reference (semantic
// versions as plans carry them).
func VersionBefore(version, reference string) (bool, error) {
	left, err := parseVersion(version)
	if err != nil {
		return false, err
	}
	right, err := parseVersion(reference)
	if err != nil {
		return false, err
	}
	return compareVersion(left, right) < 0, nil
}

func compareVersion(left, right semanticVersion) int {
	for _, pair := range [][2]uint64{{left.major, right.major}, {left.minor, right.minor}, {left.patch, right.patch}} {
		if pair[0] < pair[1] {
			return -1
		}
		if pair[0] > pair[1] {
			return 1
		}
	}
	if left.pre == right.pre {
		return 0
	}
	if left.pre == "" {
		return 1
	}
	if right.pre == "" {
		return -1
	}
	leftIdentifiers := strings.Split(left.pre, ".")
	rightIdentifiers := strings.Split(right.pre, ".")
	for index := 0; index < len(leftIdentifiers) && index < len(rightIdentifiers); index++ {
		leftID, rightID := leftIdentifiers[index], rightIdentifiers[index]
		if leftID == rightID {
			continue
		}
		leftNumeric, rightNumeric := numericIdentifier(leftID), numericIdentifier(rightID)
		switch {
		case leftNumeric && rightNumeric:
			if len(leftID) < len(rightID) || (len(leftID) == len(rightID) && leftID < rightID) {
				return -1
			}
			return 1
		case leftNumeric:
			return -1
		case rightNumeric:
			return 1
		default:
			return strings.Compare(leftID, rightID)
		}
	}
	if len(leftIdentifiers) < len(rightIdentifiers) {
		return -1
	}
	return 1
}
