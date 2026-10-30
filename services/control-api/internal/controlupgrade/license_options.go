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

var upgradeTargetReasonPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

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

// licenseIssueError maps a non-200 License answer of an issue call. 5xx,
// timeouts and codeless bodies keep mapLicenseStatus (the caller answers 503).
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

type UpgradeOptionsRequest struct {
	IdempotencyKey  string
	Component       string
	CurrentVersion  string
	ProtocolVersion int
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

type UpgradeOptions struct {
	Schema            string          `json:"schema"`
	InstallationID    string          `json:"installation_id"`
	Component         string          `json:"component"`
	CurrentVersion    string          `json:"current_version"`
	CurrentSchemaHead *int            `json:"current_schema_head"`
	TargetMode        string          `json:"target_mode"`
	Items             []UpgradeOption `json:"items"`
}

func (client *LicenseClient) ListUpgradeOptions(ctx context.Context, input UpgradeOptionsRequest) (UpgradeOptions, error) {
	if client == nil || !writeMetadataPattern.MatchString(input.IdempotencyKey) || !codePattern.MatchString(input.Component) ||
		!validCanonicalVersion(input.CurrentVersion) || input.ProtocolVersion <= 0 {
		return UpgradeOptions{}, ErrInvalidInput
	}
	body, err := json.Marshal(struct {
		Schema          string `json:"schema"`
		Component       string `json:"component"`
		CurrentVersion  string `json:"current_version"`
		ProtocolVersion int    `json:"protocol_version"`
	}{upgradeOptionsRequestSchema, input.Component, input.CurrentVersion, input.ProtocolVersion})
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
	for _, item := range options.Items {
		if !validCanonicalPlanUUID(item.ArtifactID) || !validCanonicalVersion(item.Version) ||
			(item.Selectable && item.Reason != "") || (!item.Selectable && !upgradeTargetReasonPattern.MatchString(item.Reason)) {
			return UpgradeOptions{}, ErrLicenseUnavailable
		}
	}
	return options, nil
}
