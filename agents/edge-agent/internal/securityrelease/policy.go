package securityrelease

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	Schema                 = "cdnca.edge.security-hotfix/v1"
	ChannelSecurityHotfix  = "security-hotfix"
	maxManifestBytes       = 128 * 1024
	maxManifestLifetime    = 24 * time.Hour
	allowedFutureClockSkew = 5 * time.Minute
	maximumCanaryNodeCount = 2
	minimumCanaryNodeCount = 1
)

var requiredProtocolRegressions = [...]string{
	"cache-refresh", "http1", "http2", "http3", "range206", "rewrite", "websocket",
}

type ReasonCode string

const (
	ReasonInvalidManifest         ReasonCode = "security_hotfix_invalid_manifest"
	ReasonInvalidSignature        ReasonCode = "security_hotfix_invalid_signature"
	ReasonEvidenceExpired         ReasonCode = "security_hotfix_evidence_expired"
	ReasonInvalidEvidence         ReasonCode = "security_hotfix_invalid_evidence"
	ReasonAdvisoryOpen            ReasonCode = "security_hotfix_advisory_open"
	ReasonProtocolEvidenceMissing ReasonCode = "security_hotfix_protocol_evidence_missing"
	ReasonInvalidRollout          ReasonCode = "security_hotfix_invalid_rollout"
	ReasonCanaryEligible          ReasonCode = "security_hotfix_canary_eligible"
	ReasonCanaryNotSelected       ReasonCode = "security_hotfix_canary_not_selected"
	ReasonExpansionEligible       ReasonCode = "security_hotfix_expansion_eligible"
	ReasonExpansionNotSelected    ReasonCode = "security_hotfix_expansion_not_selected"
	ReasonPaused                  ReasonCode = "security_hotfix_paused"
	ReasonRollbackRequired        ReasonCode = "security_hotfix_rollback_required"
	ReasonAgentIncompatible       ReasonCode = "security_hotfix_agent_incompatible"
	ReasonRuntimeMismatch         ReasonCode = "security_hotfix_runtime_mismatch"
	ReasonAlreadyActive           ReasonCode = "security_hotfix_already_active"
)

type validationError struct {
	reason ReasonCode
	detail string
}

func (err *validationError) Error() string {
	return fmt.Sprintf("%s: %s", err.reason, err.detail)
}

func invalid(reason ReasonCode, detail string) error {
	return &validationError{reason: reason, detail: detail}
}

func Reason(err error) ReasonCode {
	var target *validationError
	if errors.As(err, &target) {
		return target.reason
	}
	return ""
}

type Phase string

const (
	PhaseCanary    Phase = "canary"
	PhaseExpansion Phase = "expansion"
	PhasePaused    Phase = "paused"
	PhaseRollback  Phase = "rollback"
)

type AdvisoryStatus string

const (
	AdvisoryOpen        AdvisoryStatus = "open"
	AdvisoryPatched     AdvisoryStatus = "patched"
	AdvisoryNotAffected AdvisoryStatus = "not_affected"
)

type RegressionStatus string

const (
	RegressionPassed RegressionStatus = "passed"
	RegressionFailed RegressionStatus = "failed"
)

type Compatibility struct {
	MinAgentVersion string `json:"min_agent_version"`
	MaxAgentVersion string `json:"max_agent_version"`
}

type Evidence struct {
	SourceSHA256           string `json:"source_sha256"`
	BaseImageDigest        string `json:"base_image_digest"`
	RuntimeImageDigest     string `json:"runtime_image_digest"`
	PatchManifestSHA256    string `json:"patch_manifest_sha256"`
	SBOMSHA256             string `json:"sbom_sha256"`
	ProvenanceSHA256       string `json:"provenance_sha256"`
	AdvisorySnapshotSHA256 string `json:"advisory_snapshot_sha256"`
	SignatureBundleSHA256  string `json:"signature_bundle_sha256"`
}

type Advisory struct {
	ID             string         `json:"id"`
	Status         AdvisoryStatus `json:"status"`
	UpstreamURL    string         `json:"upstream_url"`
	FixedVersion   string         `json:"fixed_version"`
	PatchReference string         `json:"patch_reference"`
	RegressionTest string         `json:"regression_test"`
	EvidenceSHA256 string         `json:"evidence_sha256"`
}

type ProtocolRegression struct {
	Name           string           `json:"name"`
	Status         RegressionStatus `json:"status"`
	EvidenceSHA256 string           `json:"evidence_sha256"`
}

type RolloutPolicy struct {
	Phase                    Phase    `json:"phase"`
	CanaryNodeIDs            []string `json:"canary_node_ids"`
	ExpansionPercentage      uint8    `json:"expansion_percentage"`
	CanaryEvidenceSHA256     string   `json:"canary_evidence_sha256,omitempty"`
	AutomaticRollback        bool     `json:"automatic_rollback"`
	LastKnownGoodVersion     string   `json:"last_known_good_version,omitempty"`
	LastKnownGoodImageDigest string   `json:"last_known_good_image_digest,omitempty"`
}

type Manifest struct {
	Schema                string               `json:"schema"`
	ReleaseID             string               `json:"release_id"`
	ReleaseSequence       uint64               `json:"release_sequence"`
	Channel               string               `json:"channel"`
	IssuedAt              time.Time            `json:"issued_at"`
	ExpiresAt             time.Time            `json:"expires_at"`
	CurrentRuntimeVersion string               `json:"current_runtime_version"`
	TargetRuntimeVersion  string               `json:"target_runtime_version"`
	Compatibility         Compatibility        `json:"compatibility"`
	Evidence              Evidence             `json:"evidence"`
	Advisories            []Advisory           `json:"advisories"`
	ProtocolRegressions   []ProtocolRegression `json:"protocol_regressions"`
	Rollout               RolloutPolicy        `json:"rollout"`
	KeyID                 string               `json:"key_id"`
	Signature             string               `json:"signature"`
}

func Marshal(manifest Manifest) ([]byte, error) {
	return json.Marshal(manifest)
}

func Sign(manifest *Manifest, keyID string, privateKey ed25519.PrivateKey) error {
	if manifest == nil || !safeToken(keyID) || len(privateKey) != ed25519.PrivateKeySize {
		return invalid(ReasonInvalidManifest, "invalid signing input")
	}
	manifest.KeyID = keyID
	manifest.Signature = ""
	payload, err := signingBytes(*manifest)
	if err != nil {
		return invalid(ReasonInvalidManifest, "cannot encode signing payload")
	}
	manifest.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	return nil
}

func Verify(encoded []byte, keys map[string]ed25519.PublicKey, now time.Time) (Manifest, error) {
	if len(encoded) == 0 || len(encoded) > maxManifestBytes {
		return Manifest{}, invalid(ReasonInvalidManifest, "manifest size is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil || requireEOF(decoder) != nil {
		return Manifest{}, invalid(ReasonInvalidManifest, "manifest JSON is invalid")
	}
	canonical, err := Marshal(manifest)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return Manifest{}, invalid(ReasonInvalidManifest, "manifest is not canonical JSON")
	}
	key, ok := keys[manifest.KeyID]
	signature, signatureErr := base64.RawURLEncoding.DecodeString(manifest.Signature)
	payload, payloadErr := signingBytes(manifest)
	if !ok || len(key) != ed25519.PublicKeySize || signatureErr != nil || len(signature) != ed25519.SignatureSize ||
		payloadErr != nil || !ed25519.Verify(key, payload, signature) {
		return Manifest{}, invalid(ReasonInvalidSignature, "signature verification failed")
	}
	if err := validateManifest(manifest, now.UTC()); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func signingBytes(manifest Manifest) ([]byte, error) {
	manifest.Signature = ""
	return json.Marshal(manifest)
}

func requireEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	return nil
}

func validateManifest(manifest Manifest, now time.Time) error {
	if manifest.Schema != Schema || !canonicalUUID(manifest.ReleaseID) || manifest.ReleaseSequence == 0 ||
		manifest.Channel != ChannelSecurityHotfix || !safeToken(manifest.KeyID) {
		return invalid(ReasonInvalidManifest, "identity or channel is invalid")
	}
	if manifest.IssuedAt.IsZero() || manifest.ExpiresAt.IsZero() || !manifest.IssuedAt.Equal(manifest.IssuedAt.UTC()) ||
		!manifest.ExpiresAt.Equal(manifest.ExpiresAt.UTC()) || !manifest.ExpiresAt.After(manifest.IssuedAt) ||
		manifest.IssuedAt.After(now.Add(allowedFutureClockSkew)) || manifest.ExpiresAt.Sub(manifest.IssuedAt) > maxManifestLifetime {
		return invalid(ReasonInvalidManifest, "validity window is invalid")
	}
	if !now.Before(manifest.ExpiresAt) {
		return invalid(ReasonEvidenceExpired, "manifest evidence expired")
	}
	current, currentOK := numericVersion(manifest.CurrentRuntimeVersion, 4)
	target, targetOK := numericVersion(manifest.TargetRuntimeVersion, 4)
	minimum, minimumOK := numericVersion(manifest.Compatibility.MinAgentVersion, 3)
	maximum, maximumOK := numericVersion(manifest.Compatibility.MaxAgentVersion, 3)
	if !currentOK || !targetOK || compareVersion(target, current) <= 0 || !minimumOK || !maximumOK || compareVersion(minimum, maximum) > 0 {
		return invalid(ReasonInvalidManifest, "runtime or compatibility version is invalid")
	}
	if !validEvidence(manifest.Evidence) {
		return invalid(ReasonInvalidEvidence, "supply-chain evidence is incomplete")
	}
	if err := validateAdvisories(manifest.Advisories); err != nil {
		return err
	}
	if !validProtocolRegressions(manifest.ProtocolRegressions) {
		return invalid(ReasonProtocolEvidenceMissing, "required protocol regression evidence is incomplete")
	}
	return validateRollout(manifest.Rollout)
}

func validEvidence(evidence Evidence) bool {
	return validDigest(evidence.SourceSHA256) && validImageDigest(evidence.BaseImageDigest) &&
		validImageDigest(evidence.RuntimeImageDigest) && validDigest(evidence.PatchManifestSHA256) &&
		validDigest(evidence.SBOMSHA256) && validDigest(evidence.ProvenanceSHA256) &&
		validDigest(evidence.AdvisorySnapshotSHA256) && validDigest(evidence.SignatureBundleSHA256)
}

func validateAdvisories(advisories []Advisory) error {
	if len(advisories) == 0 {
		return invalid(ReasonInvalidEvidence, "advisory mapping is empty")
	}
	previous := ""
	for _, advisory := range advisories {
		if advisory.ID <= previous || !safeAdvisoryID(advisory.ID) || !validHTTPSURL(advisory.UpstreamURL) ||
			advisory.FixedVersion == "" || len(advisory.FixedVersion) > 128 || !safeToken(advisory.RegressionTest) ||
			!validDigest(advisory.EvidenceSHA256) {
			return invalid(ReasonInvalidEvidence, "advisory mapping is invalid")
		}
		previous = advisory.ID
		switch advisory.Status {
		case AdvisoryOpen:
			return invalid(ReasonAdvisoryOpen, "unresolved upstream advisory")
		case AdvisoryPatched:
			if !validPatchReference(advisory.PatchReference) {
				return invalid(ReasonInvalidEvidence, "patched advisory lacks an immutable patch reference")
			}
		case AdvisoryNotAffected:
			if advisory.PatchReference != "not-applicable" {
				return invalid(ReasonInvalidEvidence, "not-affected advisory has a patch reference")
			}
		default:
			return invalid(ReasonInvalidEvidence, "unknown advisory status")
		}
	}
	return nil
}

func validProtocolRegressions(regressions []ProtocolRegression) bool {
	if len(regressions) != len(requiredProtocolRegressions) {
		return false
	}
	for index, regression := range regressions {
		if regression.Name != requiredProtocolRegressions[index] || regression.Status != RegressionPassed ||
			!validDigest(regression.EvidenceSHA256) {
			return false
		}
	}
	return true
}

func validateRollout(rollout RolloutPolicy) error {
	if len(rollout.CanaryNodeIDs) < minimumCanaryNodeCount || len(rollout.CanaryNodeIDs) > maximumCanaryNodeCount ||
		!sort.StringsAreSorted(rollout.CanaryNodeIDs) || !rollout.AutomaticRollback {
		return invalid(ReasonInvalidRollout, "canary or rollback policy is invalid")
	}
	for index, nodeID := range rollout.CanaryNodeIDs {
		if !canonicalUUID(nodeID) || index > 0 && rollout.CanaryNodeIDs[index-1] == nodeID {
			return invalid(ReasonInvalidRollout, "canary node identity is invalid")
		}
	}
	switch rollout.Phase {
	case PhaseCanary:
		if rollout.ExpansionPercentage != 0 || rollout.CanaryEvidenceSHA256 != "" ||
			rollout.LastKnownGoodVersion != "" || rollout.LastKnownGoodImageDigest != "" {
			return invalid(ReasonInvalidRollout, "canary phase contains later-phase evidence")
		}
	case PhaseExpansion, PhasePaused:
		if rollout.ExpansionPercentage == 0 || rollout.ExpansionPercentage > 100 || !validDigest(rollout.CanaryEvidenceSHA256) ||
			rollout.LastKnownGoodVersion != "" || rollout.LastKnownGoodImageDigest != "" {
			return invalid(ReasonInvalidRollout, "expansion or pause evidence is invalid")
		}
	case PhaseRollback:
		_, validLastKnownGood := numericVersion(rollout.LastKnownGoodVersion, 4)
		if rollout.ExpansionPercentage != 0 || !validDigest(rollout.CanaryEvidenceSHA256) ||
			!validLastKnownGood || !validImageDigest(rollout.LastKnownGoodImageDigest) {
			return invalid(ReasonInvalidRollout, "rollback target is invalid")
		}
	default:
		return invalid(ReasonInvalidRollout, "rollout phase is invalid")
	}
	return nil
}

type Action string

const (
	ActionDeploy   Action = "deploy"
	ActionHold     Action = "hold"
	ActionRollback Action = "rollback"
)

type NodeFacts struct {
	NodeID         string
	AgentVersion   string
	RuntimeVersion string
}

type Decision struct {
	Action Action
	Reason ReasonCode
}

func Decide(manifest Manifest, facts NodeFacts) Decision {
	if manifest.Rollout.Phase == PhasePaused {
		return Decision{Action: ActionHold, Reason: ReasonPaused}
	}
	if manifest.Rollout.Phase == PhaseRollback {
		if facts.RuntimeVersion == manifest.Rollout.LastKnownGoodVersion {
			return Decision{Action: ActionHold, Reason: ReasonAlreadyActive}
		}
		if facts.RuntimeVersion == manifest.TargetRuntimeVersion {
			return Decision{Action: ActionRollback, Reason: ReasonRollbackRequired}
		}
		return Decision{Action: ActionHold, Reason: ReasonRuntimeMismatch}
	}
	agent, agentOK := numericVersion(facts.AgentVersion, 3)
	minimum, minimumOK := numericVersion(manifest.Compatibility.MinAgentVersion, 3)
	maximum, maximumOK := numericVersion(manifest.Compatibility.MaxAgentVersion, 3)
	if !agentOK || !minimumOK || !maximumOK || compareVersion(agent, minimum) < 0 || compareVersion(agent, maximum) > 0 {
		return Decision{Action: ActionHold, Reason: ReasonAgentIncompatible}
	}
	if facts.RuntimeVersion == manifest.TargetRuntimeVersion {
		return Decision{Action: ActionHold, Reason: ReasonAlreadyActive}
	}
	if facts.RuntimeVersion != manifest.CurrentRuntimeVersion || !canonicalUUID(facts.NodeID) {
		return Decision{Action: ActionHold, Reason: ReasonRuntimeMismatch}
	}
	if manifest.Rollout.Phase == PhaseCanary {
		for _, nodeID := range manifest.Rollout.CanaryNodeIDs {
			if nodeID == facts.NodeID {
				return Decision{Action: ActionDeploy, Reason: ReasonCanaryEligible}
			}
		}
		return Decision{Action: ActionHold, Reason: ReasonCanaryNotSelected}
	}
	digest := sha256.Sum256([]byte(manifest.ReleaseID + "\x00" + facts.NodeID))
	bucket := (uint16(digest[0])<<8 | uint16(digest[1])) % 10000
	if bucket < uint16(manifest.Rollout.ExpansionPercentage)*100 {
		return Decision{Action: ActionDeploy, Reason: ReasonExpansionEligible}
	}
	return Decision{Action: ActionHold, Reason: ReasonExpansionNotSelected}
}

var (
	uuidPattern       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	tokenPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	advisoryIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	commitPattern     = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

func canonicalUUID(value string) bool  { return uuidPattern.MatchString(value) }
func safeToken(value string) bool      { return tokenPattern.MatchString(value) }
func safeAdvisoryID(value string) bool { return advisoryIDPattern.MatchString(value) }

func validDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}

func validImageDigest(value string) bool {
	return strings.HasPrefix(value, "sha256:") && validDigest(strings.TrimPrefix(value, "sha256:"))
}

func validPatchReference(value string) bool {
	return commitPattern.MatchString(value) || validHTTPSURL(value)
}

func validHTTPSURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.Fragment == ""
}

func numericVersion(value string, parts int) ([]uint64, bool) {
	values := strings.Split(value, ".")
	if len(values) != parts {
		return nil, false
	}
	result := make([]uint64, parts)
	for index, part := range values {
		if part == "" || len(part) > 1 && part[0] == '0' {
			return nil, false
		}
		parsed, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return nil, false
		}
		result[index] = parsed
	}
	return result, true
}

func compareVersion(left, right []uint64) int {
	for index := range left {
		if left[index] < right[index] {
			return -1
		}
		if left[index] > right[index] {
			return 1
		}
	}
	return 0
}
