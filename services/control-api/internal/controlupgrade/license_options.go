package controlupgrade

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
)

const (
	upgradeOptionsRequestSchema = "cdnca.upgrade.options.request/v1"
	upgradeOptionsSchema        = "cdnca.upgrade.options/v1"
	upgradeOptionsProofDomain   = "cdnca-upgrade-options-request-proof/v1"
)

var (
	upgradeTargetReasonPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	artifactDigestPattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// CurrentSchemaReasonArtifactUnverified: the master listed options without a
// runner-verified digest of its installed release, so License cannot identify the
// build and current_schema_head stays null.
const CurrentSchemaReasonArtifactUnverified = "current_artifact_unverified"

// UpgradeTargetBlockedError is the license schema gate's readable refusal.
type UpgradeTargetBlockedError struct{ Reason string }

func (err *UpgradeTargetBlockedError) Error() string { return "upgrade target blocked: " + err.Reason }
func (err *UpgradeTargetBlockedError) Unwrap() error { return ErrResourceUnavailable }

// LicenseRefusalError is any other License business refusal (403/409/422) with
// a stable code, e.g. upgrade_plan_artifact_bundle_unavailable or
// installation_banned. The code is passed through so the page can say why;
// errors.Is still sees the old mapLicenseStatus sentinel.
type LicenseRefusalError struct {
	Status int
	Code   string
}

func (err *LicenseRefusalError) Error() string { return "license refused: " + err.Code }
func (err *LicenseRefusalError) Unwrap() error { return mapLicenseStatus(err.Status) }

// LicenseStatusRefusalError is a codeless License refusal (400/401/403/422):
// it keeps the HTTP status so a create preparation can say License refused,
// while errors.Is still sees the mapLicenseStatus sentinel (ErrGrantInvalid).
type LicenseStatusRefusalError struct{ Status int }

func (err *LicenseStatusRefusalError) Error() string {
	return fmt.Sprintf("license refused with HTTP %d: %v", err.Status, mapLicenseStatus(err.Status))
}
func (err *LicenseStatusRefusalError) Unwrap() error { return mapLicenseStatus(err.Status) }

// licenseIssueError maps a non-200 License answer of an issue call. 5xx,
// timeouts and codeless bodies keep mapLicenseStatus (the caller answers 503);
// a codeless refusal carries its status (LicenseStatusRefusalError).
func licenseIssueError(status int, body []byte) error {
	if reason := upgradeTargetBlockedReason(status, body); reason != "" {
		return &UpgradeTargetBlockedError{Reason: reason}
	}
	if status == http.StatusForbidden || status == http.StatusConflict || status == http.StatusUnprocessableEntity {
		var wire struct {
			Code string `json:"code"`
		}
		if json.Unmarshal(body, &wire) == nil && upgradeTargetReasonPattern.MatchString(wire.Code) {
			return &LicenseRefusalError{Status: status, Code: wire.Code}
		}
	}
	switch status {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusUnprocessableEntity:
		return &LicenseStatusRefusalError{Status: status}
	}
	return mapLicenseStatus(status)
}

func upgradeTargetBlockedReason(status int, body []byte) string {
	if status != http.StatusConflict {
		return ""
	}
	var wire struct {
		Code   string `json:"code"`
		Reason string `json:"reason_code"`
	}
	if json.Unmarshal(body, &wire) != nil || wire.Code != "upgrade_target_blocked" ||
		!upgradeTargetReasonPattern.MatchString(wire.Reason) {
		return ""
	}
	return wire.Reason
}

// UpgradeOptionsRequest.CurrentArtifactSHA256 is the runner-verified lowercase hex
// SHA-256 of the installed signed release ("" = not verified). License takes the
// schema head of that exact build; builds of one SemVer differ (1.0.35: 692 / 697).
type UpgradeOptionsRequest struct {
	IdempotencyKey        string
	Component             string
	CurrentVersion        string
	ProtocolVersion       int
	CurrentArtifactSHA256 string
}

type UpgradeOption struct {
	ArtifactID        string `json:"artifact_id"`
	Version           string `json:"version"`
	ReleaseNotes      string `json:"release_notes"`
	PublishedAt       int64  `json:"published_at"`
	Operation         string `json:"operation"`
	ControlSchemaHead *int   `json:"control_schema_head"`
	ChannelTarget     bool   `json:"channel_target"`
	Pinned            bool   `json:"pinned"`
	Selectable        bool   `json:"selectable"`
	Reason            string `json:"reason"`
}

// UpgradeOptions.CurrentSchemaHead is the installed build's schema head, null when
// unconfirmed; CurrentSchemaHeadReason then says why.
type UpgradeOptions struct {
	Schema                  string          `json:"schema"`
	InstallationID          string          `json:"installation_id"`
	Component               string          `json:"component"`
	CurrentVersion          string          `json:"current_version"`
	CurrentSchemaHead       *int            `json:"current_schema_head"`
	CurrentSchemaHeadReason string          `json:"current_schema_head_reason,omitempty"`
	TargetMode              string          `json:"target_mode"`
	Items                   []UpgradeOption `json:"items"`
}

func (client *LicenseClient) ListUpgradeOptions(ctx context.Context, input UpgradeOptionsRequest) (UpgradeOptions, error) {
	if client == nil || !writeMetadataPattern.MatchString(input.IdempotencyKey) || !codePattern.MatchString(input.Component) ||
		!validCanonicalVersion(input.CurrentVersion) || input.ProtocolVersion <= 0 ||
		(input.CurrentArtifactSHA256 != "" && !artifactDigestPattern.MatchString(input.CurrentArtifactSHA256)) {
		return UpgradeOptions{}, ErrInvalidInput
	}
	body, err := json.Marshal(struct {
		Schema                string `json:"schema"`
		Component             string `json:"component"`
		CurrentVersion        string `json:"current_version"`
		ProtocolVersion       int    `json:"protocol_version"`
		CurrentArtifactSHA256 string `json:"current_artifact_sha256,omitempty"`
	}{upgradeOptionsRequestSchema, input.Component, input.CurrentVersion, input.ProtocolVersion, input.CurrentArtifactSHA256})
	if err != nil {
		return UpgradeOptions{}, ErrInvalidInput
	}
	path := "/activation/v1/installations/" + client.installationID.String() + "/upgrade-options:list"
	requestedAt := client.now().UTC().Unix()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return UpgradeOptions{}, ErrInvalidInput
	}
	proof := ed25519.Sign(client.privateKey, upgradeLengthPrefixedDigest(upgradeOptionsProofDomain, http.MethodPost, path,
		input.IdempotencyKey, client.installationID.String(), strconv.FormatInt(requestedAt, 10),
		base64.RawURLEncoding.EncodeToString(sha256Bytes(body))))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", input.IdempotencyKey)
	request.Header.Set("X-CDNCA-Installation-ID", client.installationID.String())
	request.Header.Set("X-CDNCA-Requested-At", strconv.FormatInt(requestedAt, 10))
	request.Header.Set("X-CDNCA-Proof", base64.RawURLEncoding.EncodeToString(proof))
	response, err := client.http.Do(request)
	if err != nil {
		return UpgradeOptions{}, fmt.Errorf("%w: %v", ErrLicenseUnavailable, err)
	}
	defer response.Body.Close()
	encoded, readErr := io.ReadAll(io.LimitReader(response.Body, licenseResponseLimit+1))
	if readErr != nil || len(encoded) > licenseResponseLimit {
		return UpgradeOptions{}, ErrLicenseUnavailable
	}
	if response.StatusCode != http.StatusOK {
		return UpgradeOptions{}, mapLicenseStatus(response.StatusCode)
	}
	var options UpgradeOptions
	if decodeCanonicalLicenseJSON(encoded, &options) != nil || options.Schema != upgradeOptionsSchema ||
		options.InstallationID != client.installationID.String() || options.Component != input.Component ||
		options.CurrentVersion != input.CurrentVersion || len(options.Items) > 200 {
		return UpgradeOptions{}, ErrLicenseUnavailable
	}
	if input.CurrentArtifactSHA256 == "" {
		// Without the installed build's identity no head License names is this database's.
		options.CurrentSchemaHead, options.CurrentSchemaHeadReason = nil, CurrentSchemaReasonArtifactUnverified
	} else if (options.CurrentSchemaHead != nil) == (options.CurrentSchemaHeadReason != "") ||
		(options.CurrentSchemaHead != nil && *options.CurrentSchemaHead < 1) ||
		(options.CurrentSchemaHeadReason != "" && !upgradeTargetReasonPattern.MatchString(options.CurrentSchemaHeadReason)) {
		return UpgradeOptions{}, ErrLicenseUnavailable
	}
	for _, item := range options.Items {
		if !validCanonicalPlanUUID(item.ArtifactID) || !validCanonicalVersion(item.Version) ||
			(item.Selectable && item.Reason != "") || (!item.Selectable && !upgradeTargetReasonPattern.MatchString(item.Reason)) {
			return UpgradeOptions{}, ErrLicenseUnavailable
		}
	}
	return options, nil
}
