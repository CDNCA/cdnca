package controlupgrade

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/google/uuid"
)

const (
	upgradeCommandGrantRequestSchema       = "cdnca.upgrade.command-grant.request/v1"
	upgradePlanArtifactBundleRequestSchema = "cdnca.upgrade.plan-artifact-bundle.request/v1"
	licenseResponseLimit                   = 1 << 20
)

type licenseHTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

type LicenseClient struct {
	baseURL        string
	http           licenseHTTPClient
	installationID uuid.UUID
	privateKey     ed25519.PrivateKey
	now            func() time.Time
}

type ParentGrantRequest struct {
	IdempotencyKey  string
	RequestID       string
	Component       string
	CurrentVersion  string
	ProtocolVersion int
	// RequestedArtifactID is the version the customer chose ("" = pin or channel latest).
	RequestedArtifactID string
}

type ParentGrantResult struct {
	ID      uuid.UUID
	Encoded []byte
	Signed  entitlement.SignedUpgradeGrant
}

type CommandGrantRequest struct {
	IdempotencyKey  string
	RequestID       string
	PlanID          string
	PlanRevision    uint64
	BatchID         string
	CommandID       string
	NodeID          string
	Operation       string
	ArtifactBundle  []byte
	ForwardProfile  CommandProfile
	RollbackProfile CommandProfile
}

type IssueUpgradeCommandGrantHTTPBody struct {
	Schema                    string         `json:"schema"`
	PlanID                    string         `json:"plan_id"`
	PlanRevision              uint64         `json:"plan_revision"`
	BatchID                   string         `json:"batch_id"`
	CommandID                 string         `json:"command_id"`
	NodeID                    string         `json:"node_id"`
	Operation                 string         `json:"operation"`
	UpgradePlanArtifactBundle string         `json:"upgrade_plan_artifact_bundle"`
	ForwardProfile            CommandProfile `json:"forward_profile"`
	RollbackProfile           CommandProfile `json:"rollback_profile"`
}

type CommandGrantResult struct {
	ID        uuid.UUID
	Encoded   []byte
	Digest    [sha256.Size]byte
	ExpiresAt int64
}

type PlanArtifactBundleRequest struct {
	IdempotencyKey          string
	RequestID               string
	PlanID                  string
	InitialPlanRevision     uint64
	ParentUpgradeGrant      []byte
	CommandIssuanceNotAfter int64
}

type IssueUpgradePlanArtifactBundleHTTPBody struct {
	Schema                  string `json:"schema"`
	PlanID                  string `json:"plan_id"`
	InitialPlanRevision     uint64 `json:"initial_plan_revision"`
	ParentUpgradeGrant      string `json:"parent_upgrade_grant"`
	CommandIssuanceNotAfter int64  `json:"command_issuance_not_after"`
}

type PlanArtifactBundleResult struct {
	ID                      uuid.UUID
	Encoded                 []byte
	Digest                  [sha256.Size]byte
	CommandIssuanceNotAfter int64
}

type parentGrantReceiptHTTPBody struct {
	Schema           string  `json:"schema"`
	RequestID        string  `json:"request_id"`
	InstallationID   string  `json:"installation_id"`
	RequestedAt      int64   `json:"requested_at"`
	GrantID          string  `json:"grant_id"`
	Status           string  `json:"status"`
	InstalledVersion string  `json:"installed_version"`
	ErrorCode        *string `json:"error_code"`
	ObservedAt       int64   `json:"observed_at"`
	Proof            string  `json:"proof"`
}

type parentGrantReceiptHTTPResponse struct {
	Schema         string `json:"schema"`
	RequestID      string `json:"request_id"`
	ReceiptID      string `json:"receipt_id"`
	AcceptedStatus string `json:"accepted_status"`
	ReceivedAt     int64  `json:"received_at"`
}

func (client *LicenseClient) Close() {
	if client == nil {
		return
	}
	clear(client.privateKey)
	client.privateKey = nil
}

func NewLicenseClient(baseURL string, client licenseHTTPClient, installationID uuid.UUID,
	privateKey ed25519.PrivateKey, now func() time.Time) (*LicenseClient, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" ||
		strings.TrimSuffix(baseURL, "/") != baseURL || client == nil || installationID == uuid.Nil ||
		len(privateKey) != ed25519.PrivateKeySize {
		return nil, ErrInvalidInput
	}
	if now == nil {
		now = time.Now
	}
	return &LicenseClient{baseURL: baseURL, http: client, installationID: installationID,
		privateKey: append(ed25519.PrivateKey(nil), privateKey...), now: now}, nil
}

func (client *LicenseClient) IssueCommandGrant(ctx context.Context, input CommandGrantRequest) (CommandGrantResult, error) {
	if client == nil || !writeMetadataPattern.MatchString(input.IdempotencyKey) ||
		!validCanonicalPlanUUID(input.PlanID) || input.PlanRevision == 0 ||
		input.PlanRevision > maxRolloutRevision || !validCanonicalPlanUUID(input.BatchID) ||
		!validCanonicalPlanUUID(input.CommandID) || !validCanonicalPlanUUID(input.NodeID) ||
		(input.Operation != "forward" && input.Operation != "rollback") || len(input.ArtifactBundle) == 0 ||
		!validCommandProfile(input.ForwardProfile) || !validCommandProfile(input.RollbackProfile) {
		return CommandGrantResult{}, ErrInvalidInput
	}
	body := IssueUpgradeCommandGrantHTTPBody{Schema: upgradeCommandGrantRequestSchema,
		PlanID: input.PlanID, PlanRevision: input.PlanRevision, BatchID: input.BatchID,
		CommandID: input.CommandID, NodeID: input.NodeID, Operation: input.Operation,
		UpgradePlanArtifactBundle: base64.RawURLEncoding.EncodeToString(input.ArtifactBundle),
		ForwardProfile:            cloneCommandProfile(input.ForwardProfile),
		RollbackProfile:           cloneCommandProfile(input.RollbackProfile)}
	encoded, err := json.Marshal(body)
	if err != nil {
		return CommandGrantResult{}, ErrInvalidInput
	}
	path := "/activation/v1/installations/" + client.installationID.String() + "/upgrade-command-grants:issue"
	request, requestedAt, err := client.newSignedUpgradeRequest(ctx, path,
		"cdnca-upgrade-command-grant-request-proof/v1", input.IdempotencyKey, input.RequestID, encoded)
	if err != nil {
		return CommandGrantResult{}, err
	}

	response, err := client.http.Do(request)
	if err != nil {
		return CommandGrantResult{}, fmt.Errorf("%w: %v", ErrLicenseOutcomeUnknown, err)
	}
	defer response.Body.Close()
	responseBytes, readErr := io.ReadAll(io.LimitReader(response.Body, licenseResponseLimit+1))
	if readErr != nil || len(responseBytes) > licenseResponseLimit {
		return CommandGrantResult{}, ErrLicenseOutcomeUnknown
	}
	if response.StatusCode != http.StatusOK {
		return CommandGrantResult{}, mapLicenseStatus(response.StatusCode)
	}
	var wire struct {
		ID           string `json:"id"`
		EncodedGrant string `json:"encoded_grant"`
		GrantSHA256  string `json:"grant_sha256"`
		ExpiresAt    int64  `json:"expires_at"`
	}
	if err := decodeCanonicalLicenseJSON(responseBytes, &wire); err != nil {
		return CommandGrantResult{}, ErrLicenseOutcomeUnknown
	}
	id, idErr := uuid.Parse(wire.ID)
	encodedGrant, grantErr := base64.RawURLEncoding.DecodeString(wire.EncodedGrant)
	digestBytes, digestErr := base64.RawURLEncoding.DecodeString(wire.GrantSHA256)
	digest := sha256.Sum256(encodedGrant)
	if idErr != nil || id == uuid.Nil || id.String() != wire.ID || grantErr != nil || len(encodedGrant) == 0 ||
		base64.RawURLEncoding.EncodeToString(encodedGrant) != wire.EncodedGrant || digestErr != nil ||
		len(digestBytes) != sha256.Size || !bytes.Equal(digestBytes, digest[:]) || wire.ExpiresAt <= requestedAt {
		return CommandGrantResult{}, ErrLicenseOutcomeUnknown
	}
	return CommandGrantResult{ID: id, Encoded: encodedGrant, Digest: digest, ExpiresAt: wire.ExpiresAt}, nil
}

func (client *LicenseClient) IssuePlanArtifactBundle(ctx context.Context,
	input PlanArtifactBundleRequest) (PlanArtifactBundleResult, error) {
	if client == nil || !writeMetadataPattern.MatchString(input.IdempotencyKey) ||
		!validCanonicalPlanUUID(input.PlanID) || input.InitialPlanRevision != 1 ||
		len(input.ParentUpgradeGrant) == 0 || input.CommandIssuanceNotAfter <= client.now().UTC().Unix() {
		return PlanArtifactBundleResult{}, ErrInvalidInput
	}
	body := IssueUpgradePlanArtifactBundleHTTPBody{Schema: upgradePlanArtifactBundleRequestSchema,
		PlanID: input.PlanID, InitialPlanRevision: input.InitialPlanRevision,
		ParentUpgradeGrant:      base64.RawURLEncoding.EncodeToString(input.ParentUpgradeGrant),
		CommandIssuanceNotAfter: input.CommandIssuanceNotAfter}
	encoded, err := json.Marshal(body)
	if err != nil {
		return PlanArtifactBundleResult{}, ErrInvalidInput
	}
	path := "/activation/v1/installations/" + client.installationID.String() +
		"/upgrade-plan-artifact-bundles:issue"
	request, requestedAt, err := client.newSignedUpgradeRequest(ctx, path,
		"cdnca-upgrade-plan-artifact-bundle-request-proof/v1", input.IdempotencyKey, input.RequestID, encoded)
	if err != nil {
		return PlanArtifactBundleResult{}, err
	}
	response, err := client.http.Do(request)
	if err != nil {
		return PlanArtifactBundleResult{}, fmt.Errorf("%w: %v", ErrLicenseOutcomeUnknown, err)
	}
	defer response.Body.Close()
	responseBytes, readErr := io.ReadAll(io.LimitReader(response.Body, licenseResponseLimit+1))
	if readErr != nil || len(responseBytes) > licenseResponseLimit {
		return PlanArtifactBundleResult{}, ErrLicenseOutcomeUnknown
	}
	if response.StatusCode != http.StatusOK {
		return PlanArtifactBundleResult{}, licenseIssueError(response.StatusCode, responseBytes)
	}
	var wire struct {
		ID                      string `json:"id"`
		EncodedBundle           string `json:"encoded_bundle"`
		BundleSHA256            string `json:"bundle_sha256"`
		CommandIssuanceNotAfter int64  `json:"command_issuance_not_after"`
	}
	if decodeCanonicalLicenseJSON(responseBytes, &wire) != nil {
		return PlanArtifactBundleResult{}, ErrLicenseOutcomeUnknown
	}
	id, idErr := uuid.Parse(wire.ID)
	bundleBytes, bundleErr := base64.RawURLEncoding.DecodeString(wire.EncodedBundle)
	digestBytes, digestErr := base64.RawURLEncoding.DecodeString(wire.BundleSHA256)
	digest := sha256.Sum256(bundleBytes)
	if idErr != nil || id == uuid.Nil || id.String() != wire.ID || bundleErr != nil || len(bundleBytes) == 0 ||
		base64.RawURLEncoding.EncodeToString(bundleBytes) != wire.EncodedBundle || digestErr != nil ||
		len(digestBytes) != sha256.Size || !bytes.Equal(digestBytes, digest[:]) ||
		wire.CommandIssuanceNotAfter != input.CommandIssuanceNotAfter ||
		wire.CommandIssuanceNotAfter <= requestedAt {
		return PlanArtifactBundleResult{}, ErrLicenseOutcomeUnknown
	}
	return PlanArtifactBundleResult{ID: id, Encoded: bundleBytes, Digest: digest,
		CommandIssuanceNotAfter: wire.CommandIssuanceNotAfter}, nil
}

func (client *LicenseClient) newSignedUpgradeRequest(ctx context.Context, path, proofDomain,
	idempotencyKey, requestID string, body []byte) (*http.Request, int64, error) {
	if client == nil || !writeMetadataPattern.MatchString(idempotencyKey) ||
		(proofDomain != "cdnca-upgrade-command-grant-request-proof/v1" &&
			proofDomain != "cdnca-upgrade-plan-artifact-bundle-request-proof/v1") {
		return nil, 0, ErrInvalidInput
	}
	if requestID == "" {
		requestID = idempotencyKey
	}
	if !writeMetadataPattern.MatchString(requestID) {
		return nil, 0, ErrInvalidInput
	}
	requestedAt := client.now().UTC().Unix()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, 0, ErrInvalidInput
	}
	proof := ed25519.Sign(client.privateKey, upgradeLengthPrefixedDigest(proofDomain, http.MethodPost, path,
		idempotencyKey, client.installationID.String(), strconv.FormatInt(requestedAt, 10),
		base64.RawURLEncoding.EncodeToString(sha256Bytes(body))))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", idempotencyKey)
	request.Header.Set("X-Request-ID", requestID)
	request.Header.Set("X-CDNCA-Installation-ID", client.installationID.String())
	request.Header.Set("X-CDNCA-Requested-At", strconv.FormatInt(requestedAt, 10))
	request.Header.Set("X-CDNCA-Proof", base64.RawURLEncoding.EncodeToString(proof))
	return request, requestedAt, nil
}

func (client *LicenseClient) IssueParentGrant(ctx context.Context, input ParentGrantRequest) (ParentGrantResult, error) {
	if input.Component == "" {
		input.Component = "edge-agent"
	}
	if client == nil || !writeMetadataPattern.MatchString(input.IdempotencyKey) ||
		!codePattern.MatchString(input.Component) || !validCanonicalVersion(input.CurrentVersion) ||
		input.ProtocolVersion <= 0 || (input.RequestedArtifactID != "" && !validCanonicalPlanUUID(input.RequestedArtifactID)) {
		return ParentGrantResult{}, ErrInvalidInput
	}
	requestID := input.RequestID
	if requestID == "" {
		requestID = input.IdempotencyKey
	}
	// License verifies this proof over the Idempotency-Key; X-Request-ID only traces.
	// v2 also binds the requested artifact so it cannot be swapped in transit.
	fields := []string{"cdnca-upgrade-grant-request-proof/v1", input.IdempotencyKey, client.installationID.String(),
		input.Component, input.CurrentVersion, strconv.Itoa(input.ProtocolVersion)}
	if input.RequestedArtifactID != "" {
		fields[0] = "cdnca-upgrade-grant-request-proof/v2"
		fields = append(fields, input.RequestedArtifactID)
	}
	proof := ed25519.Sign(client.privateKey, upgradeLengthPrefixedDigest(fields...))
	body := struct {
		Component           string `json:"component"`
		CurrentVersion      string `json:"current_version"`
		ProtocolVersion     int    `json:"protocol_version"`
		Proof               string `json:"proof"`
		RequestedArtifactID string `json:"requested_artifact_id,omitempty"`
	}{input.Component, input.CurrentVersion, input.ProtocolVersion,
		base64.RawURLEncoding.EncodeToString(proof), input.RequestedArtifactID}
	encoded, _ := json.Marshal(body)
	path := "/activation/v1/installations/" + client.installationID.String() + "/upgrade-grants:issue"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.baseURL+path, bytes.NewReader(encoded))
	if err != nil {
		return ParentGrantResult{}, ErrInvalidInput
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", input.IdempotencyKey)
	request.Header.Set("X-Request-ID", requestID)
	response, err := client.http.Do(request)
	if err != nil {
		return ParentGrantResult{}, fmt.Errorf("%w: %v", ErrLicenseOutcomeUnknown, err)
	}
	defer response.Body.Close()
	responseBytes, readErr := io.ReadAll(io.LimitReader(response.Body, licenseResponseLimit+1))
	if readErr != nil || len(responseBytes) > licenseResponseLimit {
		return ParentGrantResult{}, ErrLicenseOutcomeUnknown
	}
	if response.StatusCode != http.StatusOK {
		return ParentGrantResult{}, licenseIssueError(response.StatusCode, responseBytes)
	}
	var wire struct {
		ID          uuid.UUID                      `json:"id"`
		SignedGrant entitlement.SignedUpgradeGrant `json:"signed_grant"`
	}
	if err := decodeCanonicalLicenseJSON(responseBytes, &wire); err != nil || wire.ID == uuid.Nil {
		return ParentGrantResult{}, ErrLicenseOutcomeUnknown
	}
	grantWire, err := wire.SignedGrant.Encode()
	if err != nil {
		return ParentGrantResult{}, ErrLicenseOutcomeUnknown
	}
	return ParentGrantResult{ID: wire.ID, Encoded: grantWire, Signed: wire.SignedGrant}, nil
}

func (client *LicenseClient) RecordParentGrantReceipt(ctx context.Context,
	receipt ParentGrantReceipt) (ParentGrantReceiptResponse, error) {
	if client == nil || ctx == nil || ctx.Err() != nil ||
		receipt.InstallationID != client.installationID.String() || !validParentGrantReceiptFields(receipt) {
		return ParentGrantReceiptResponse{}, ErrInvalidInput
	}
	digest, err := parentGrantReceiptLogicalDigest(receipt)
	if err != nil || receipt.LogicalDigest != digest {
		return ParentGrantReceiptResponse{}, ErrInvalidInput
	}
	requestedAt := client.now().UTC().Unix()
	errorCode := (*string)(nil)
	if receipt.ErrorCode != "" {
		errorCode = &receipt.ErrorCode
	}
	proof := ed25519.Sign(client.privateKey, upgradeLengthPrefixedDigest(
		"cdnca-upgrade-grant-receipt-proof/v1", parentGrantReceiptRequestSchema, receipt.ID,
		receipt.InstallationID, strconv.FormatInt(requestedAt, 10), receipt.GrantID, receipt.Status,
		receipt.InstalledVersion, receipt.ErrorCode, strconv.FormatInt(receipt.ObservedAt.UTC().Unix(), 10)))
	body := parentGrantReceiptHTTPBody{Schema: parentGrantReceiptRequestSchema, RequestID: receipt.ID,
		InstallationID: receipt.InstallationID, RequestedAt: requestedAt, GrantID: receipt.GrantID,
		Status: receipt.Status, InstalledVersion: receipt.InstalledVersion, ErrorCode: errorCode,
		ObservedAt: receipt.ObservedAt.UTC().Unix(), Proof: base64.RawURLEncoding.EncodeToString(proof)}
	encoded, err := json.Marshal(body)
	if err != nil {
		return ParentGrantReceiptResponse{}, ErrInvalidInput
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		client.baseURL+"/installation/v1/upgrade-grant-receipts", bytes.NewReader(encoded))
	if err != nil {
		return ParentGrantReceiptResponse{}, ErrInvalidInput
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.http.Do(request)
	if err != nil {
		return ParentGrantReceiptResponse{}, fmt.Errorf("%w: %v", ErrLicenseReceiptRetryable, err)
	}
	defer response.Body.Close()
	responseBytes, readErr := io.ReadAll(io.LimitReader(response.Body, licenseResponseLimit+1))
	if readErr != nil || len(responseBytes) > licenseResponseLimit {
		return ParentGrantReceiptResponse{}, ErrLicenseReceiptRetryable
	}
	if response.StatusCode != http.StatusOK {
		return ParentGrantReceiptResponse{}, mapParentGrantReceiptHTTPStatus(response.StatusCode)
	}
	var wire parentGrantReceiptHTTPResponse
	if err := decodeCanonicalLicenseJSONLine(responseBytes, &wire); err != nil {
		return ParentGrantReceiptResponse{}, ErrLicenseReceiptRetryable
	}
	receiptID, receiptErr := uuid.Parse(wire.ReceiptID)
	if wire.Schema != parentGrantReceiptResponseSchema || wire.RequestID != receipt.ID ||
		receiptErr != nil || receiptID == uuid.Nil || receiptID.String() != wire.ReceiptID ||
		wire.AcceptedStatus != receipt.Status || wire.ReceivedAt <= 0 {
		return ParentGrantReceiptResponse{}, ErrLicenseReceiptRetryable
	}
	return ParentGrantReceiptResponse{Schema: wire.Schema, RequestID: wire.RequestID,
		ReceiptID: wire.ReceiptID, AcceptedStatus: wire.AcceptedStatus,
		ReceivedAt: time.Unix(wire.ReceivedAt, 0).UTC()}, nil
}

func mapParentGrantReceiptHTTPStatus(status int) error {
	switch status {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound,
		http.StatusConflict, http.StatusUnprocessableEntity:
		return ErrLicenseReceiptPermanent
	default:
		return ErrLicenseReceiptRetryable
	}
}

func decodeCanonicalLicenseJSONLine(encoded []byte, target any) error {
	if len(encoded) < 2 || encoded[len(encoded)-1] != '\n' {
		return errors.New("canonical License response must end in one newline")
	}
	content := encoded[:len(encoded)-1]
	if len(content) == 0 || content[len(content)-1] == '\n' || content[len(content)-1] == '\r' {
		return errors.New("canonical License response has invalid line ending")
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing License response")
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(canonical, content) {
		return errors.New("noncanonical License response")
	}
	return nil
}

func mapLicenseStatus(status int) error {
	switch status {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusUnprocessableEntity:
		return ErrGrantInvalid
	case http.StatusConflict:
		return ErrResourceUnavailable
	case http.StatusRequestTimeout, http.StatusGatewayTimeout:
		return ErrLicenseOutcomeUnknown
	case http.StatusBadGateway, http.StatusServiceUnavailable:
		return ErrLicenseUnavailable
	default:
		return ErrLicenseUnavailable
	}
}

func decodeCanonicalLicenseJSON(encoded []byte, target any) error {
	canonicalInput := encoded
	if len(canonicalInput) > 0 && canonicalInput[len(canonicalInput)-1] == '\n' {
		canonicalInput = canonicalInput[:len(canonicalInput)-1]
	}
	decoder := json.NewDecoder(bytes.NewReader(canonicalInput))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing license response")
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(canonical, canonicalInput) {
		return errors.New("noncanonical license response")
	}
	return nil
}

func upgradeLengthPrefixedDigest(values ...string) []byte {
	hash := sha256.New()
	var size [4]byte
	for _, value := range values {
		binary.BigEndian.PutUint32(size[:], uint32(len(value)))
		_, _ = hash.Write(size[:])
		_, _ = hash.Write([]byte(value))
	}
	return hash.Sum(nil)
}

func sha256Bytes(value []byte) []byte {
	digest := sha256.Sum256(value)
	return digest[:]
}
