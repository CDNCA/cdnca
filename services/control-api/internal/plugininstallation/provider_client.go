package plugininstallation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/mod/semver"
)

const (
	activationRequestSchema = "cdnca.plugin-installation-activation-request/v1"
	activationBatchSchema   = "cdnca.plugin-installation-activation-batch/v1"
	activationFactSchema    = "cdnca.plugin-installation-activation-fact/v1"

	activationRequestDomain       = "cdnca-plugin-installation-activation-request/v1"
	activationBatchDomain         = "cdnca-plugin-installation-activation-batch/v1"
	activationFactDomain          = "cdnca-plugin-installation-activation-fact/v1"
	activationIdempotencyDomain   = "cdnca-plugin-installation-activation-idempotency/v1"
	candidateSyncRequestSchema    = "cdnca.plugin-installation-candidate-sync-request/v1"
	candidateSyncBatchSchema      = "cdnca.plugin-installation-candidate-sync-batch/v1"
	lifecycleReceiptRequestSchema = "cdnca.plugin-installation-lifecycle-receipt-request/v1"
	lifecycleReceiptSchema        = "cdnca.plugin-installation-lifecycle-receipt/v1"
	candidateSyncRequestDomain    = "cdnca-plugin-installation-candidate-sync-request/v1"
	candidateSyncBatchDomain      = "cdnca-plugin-installation-candidate-sync-batch/v1"
	lifecycleReceiptRequestDomain = "cdnca-plugin-installation-lifecycle-receipt-request/v1"
	lifecycleReceiptDomain        = "cdnca-plugin-installation-lifecycle-receipt/v1"
	// License migration 076: market authorizations confirmed by this controller's administrator.
	pendingSyncRequestSchema       = "cdnca.plugin-installation-pending-sync-request/v1"
	controllerConfirmRequestSchema = "cdnca.plugin-installation-controller-confirm-request/v1"
	controllerConfirmResultSchema  = "cdnca.plugin-installation-controller-confirm/v1"
	controllerConfirmRequestDomain = "cdnca-plugin-installation-controller-confirm-request/v1"

	ActivationInstall = "install"
	ActivationUpgrade = "upgrade"
)

var ErrActivationInvalid = errors.New("plugin installation activation response invalid")

type activationHTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

type ActivationTrust interface {
	VerifyDetached(keyID string, payload, signature []byte, signedAt, now time.Time) error
}

type ActivationClientConfig struct {
	BaseURL        string
	HTTP           activationHTTPClient
	InstallationID uuid.UUID
	PrivateKey     ed25519.PrivateKey
	Trust          ActivationTrust
	Now            func() time.Time
}

type ActivationClient struct {
	endpoint       string
	http           activationHTTPClient
	installationID uuid.UUID
	privateKey     ed25519.PrivateKey
	trust          ActivationTrust
	now            func() time.Time
}

type ActivationResolveRequest struct {
	RequestID              string
	IdempotencyKey         string
	VerificationID         uuid.UUID
	Action                 string
	KnownLifecycleRevision uint64
	RequestedScopes        []string
}

type ActivationResult struct {
	Candidate          Candidate
	LifecycleStatus    string
	LifecycleRevision  uint64
	IdentityGeneration uint64
	NewScopes          []string
	verified           bool
}

func NewActivationClient(config ActivationClientConfig) (*ActivationClient, error) {
	base, err := url.Parse(config.BaseURL)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil ||
		base.RawQuery != "" || base.Fragment != "" || (base.Path != "" && base.Path != "/") ||
		config.HTTP == nil || config.InstallationID == uuid.Nil || len(config.PrivateKey) != ed25519.PrivateKeySize ||
		config.Trust == nil || config.Now == nil {
		return nil, ErrInvalidInput
	}
	return &ActivationClient{
		endpoint:       strings.TrimSuffix(config.BaseURL, "/") + "/installation/v1/plugin-installation-activation-facts:resolve",
		http:           config.HTTP,
		installationID: config.InstallationID,
		privateKey:     append(ed25519.PrivateKey(nil), config.PrivateKey...),
		trust:          config.Trust,
		now:            config.Now,
	}, nil
}

func (client *ActivationClient) Resolve(ctx context.Context, input ActivationResolveRequest) (ActivationResult, error) {
	if ctx == nil || client == nil || client.http == nil || client.trust == nil || client.now == nil ||
		!validRequestID(input.RequestID) || !idempotencyPattern.MatchString(input.IdempotencyKey) ||
		input.VerificationID == uuid.Nil || (input.Action != ActivationInstall && input.Action != ActivationUpgrade) ||
		!validScopes(input.RequestedScopes) || len(input.RequestedScopes) == 0 {
		return ActivationResult{}, ErrInvalidInput
	}
	now := client.now().UTC().Truncate(time.Second)
	if now.IsZero() {
		return ActivationResult{}, ErrInvalidInput
	}
	payload := activationRequestPayload{Schema: activationRequestSchema, RequestID: input.RequestID,
		IdempotencyKey: input.IdempotencyKey, InstallationID: client.installationID,
		VerificationID: input.VerificationID, Action: input.Action,
		KnownLifecycleRevision: input.KnownLifecycleRevision,
		RequestedScopes:        append([]string{}, input.RequestedScopes...), RequestedAt: now}
	canonical, err := json.Marshal(payload)
	if err != nil {
		return ActivationResult{}, ErrInvalidInput
	}
	proof := ed25519.Sign(client.privateKey, framed(activationRequestDomain, canonical))
	wire := activationRequestWire{activationRequestPayload: payload,
		Proof: base64.RawURLEncoding.EncodeToString(proof)}
	body, err := json.Marshal(wire)
	if err != nil {
		return ActivationResult{}, ErrInvalidInput
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.endpoint, bytes.NewReader(body))
	if err != nil {
		return ActivationResult{}, ErrInvalidInput
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := client.http.Do(request)
	if err != nil {
		return ActivationResult{}, ErrFactUnavailable
	}
	if response == nil || response.Body == nil {
		return ActivationResult{}, ErrFactUnavailable
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
	if err != nil || len(responseBody) > 1<<20 {
		return ActivationResult{}, ErrActivationInvalid
	}
	if response.StatusCode != http.StatusOK {
		return ActivationResult{}, activationHTTPError(response.StatusCode, responseBody)
	}
	if len(responseBody) < 2 || responseBody[len(responseBody)-1] != '\n' ||
		responseBody[len(responseBody)-2] == '\n' {
		return ActivationResult{}, ErrActivationInvalid
	}
	responseBody = responseBody[:len(responseBody)-1]
	var signed activationBatchWire
	if err := strictJSON(responseBody, &signed); err != nil {
		return ActivationResult{}, ErrActivationInvalid
	}
	canonicalResponse, err := json.Marshal(signed)
	if err != nil || !bytes.Equal(canonicalResponse, responseBody) {
		return ActivationResult{}, ErrActivationInvalid
	}
	// The license service binds its answer to the framed canonical request plus proof (the same idempotency digest
	// as candidate sync and lifecycle receipts), not to the transport bytes.
	digest := sha256.Sum256(framed(activationIdempotencyDomain, append(canonical, proof...)))
	return client.verifyResponse(digest, payload, signed, now)
}

func (client *ActivationClient) Discover(ctx context.Context, input CandidateDiscoveryRequest) (Page, error) {
	return client.sync(ctx, candidateSyncRequestSchema, input)
}

// DiscoverPending lists the market authorizations of this installation waiting for the controller
// administrator's confirmation (license migration 076). Items carry AuthorizationStatus pending_confirmation.
func (client *ActivationClient) DiscoverPending(ctx context.Context, input CandidateDiscoveryRequest) (Page, error) {
	return client.sync(ctx, pendingSyncRequestSchema, input)
}

func (client *ActivationClient) sync(ctx context.Context, schema string, input CandidateDiscoveryRequest) (Page, error) {
	if ctx == nil || client == nil || client.http == nil || client.trust == nil || client.now == nil ||
		!validRequestID(input.RequestID) || input.TenantID == uuid.Nil || input.Limit < 1 || input.Limit > 100 {
		return Page{}, ErrInvalidInput
	}
	cursor := uuid.Nil
	if input.Cursor != "" {
		if !strings.HasPrefix(input.Cursor, "license:") {
			return Page{}, ErrInvalidInput
		}
		parsed, err := uuid.Parse(strings.TrimPrefix(input.Cursor, "license:"))
		if err != nil || parsed == uuid.Nil || parsed.String() != strings.TrimPrefix(input.Cursor, "license:") {
			return Page{}, ErrInvalidInput
		}
		cursor = parsed
	}
	now := client.now().UTC().Truncate(time.Second)
	var wireCursor *uuid.UUID
	if cursor != uuid.Nil {
		wireCursor = &cursor
	}
	payload := candidateSyncRequestPayload{Schema: schema, RequestID: input.RequestID,
		InstallationID: client.installationID, Limit: input.Limit, Cursor: wireCursor, RequestedAt: now}
	canonical, err := json.Marshal(payload)
	if err != nil {
		return Page{}, ErrInvalidInput
	}
	proof := ed25519.Sign(client.privateKey, framed(candidateSyncRequestDomain, canonical))
	wire := candidateSyncRequestWire{candidateSyncRequestPayload: payload,
		Proof: base64.RawURLEncoding.EncodeToString(proof)}
	body, err := json.Marshal(wire)
	if err != nil {
		return Page{}, ErrInvalidInput
	}
	responseBody, err := client.post(ctx, body)
	if err != nil {
		return Page{}, err
	}
	var batch candidateSyncBatchWire
	if strictJSON(responseBody, &batch) != nil {
		return Page{}, ErrActivationInvalid
	}
	reencoded, err := json.Marshal(batch)
	if err != nil || !bytes.Equal(reencoded, responseBody) {
		return Page{}, ErrActivationInvalid
	}
	digest := sha256.Sum256(framed("cdnca-plugin-installation-candidate-sync-idempotency/v1",
		append(canonical, proof...)))
	if batch.Schema != candidateSyncBatchSchema || batch.RequestID != input.RequestID ||
		batch.RequestDigest != hex.EncodeToString(digest[:]) || batch.CustomerID == uuid.Nil ||
		batch.InstallationID != client.installationID || len(batch.Candidates) > input.Limit ||
		!canonicalSecond(batch.IssuedAt) || batch.IssuedAt.After(now) ||
		!batch.ExpiresAt.Equal(batch.IssuedAt.Add(time.Minute)) || !now.Before(batch.ExpiresAt) ||
		batch.Algorithm != "Ed25519" || batch.KeyID == "" || len(batch.KeyID) > 128 {
		return Page{}, ErrActivationInvalid
	}
	unsigned := batch
	unsigned.Signature = ""
	unsignedPayload, err := json.Marshal(unsigned)
	signature, decodeErr := decodeSignature(batch.Signature)
	if err != nil || decodeErr != nil || client.trust.VerifyDetached(batch.KeyID,
		framed(candidateSyncBatchDomain, unsignedPayload), signature, batch.IssuedAt, now) != nil {
		return Page{}, ErrActivationInvalid
	}
	page := Page{Items: make([]InstallationView, 0, len(batch.Candidates))}
	for _, candidate := range batch.Candidates {
		// The regular sync never carries pending rows; the pending sync carries nothing else.
		if (candidate.Status == StatusPendingConfirmation) != (schema == pendingSyncRequestSchema) {
			return Page{}, ErrActivationInvalid
		}
		view, err := candidate.toView(input.TenantID, batch.InstallationID, input.Status, input.PluginID)
		if err != nil {
			return Page{}, err
		}
		if view.Installation.AuthorizationID != uuid.Nil {
			page.Items = append(page.Items, view)
		}
	}
	if batch.NextCursor != nil {
		if *batch.NextCursor == uuid.Nil || len(batch.Candidates) == 0 ||
			*batch.NextCursor != batch.Candidates[len(batch.Candidates)-1].AuthorizationID {
			return Page{}, ErrActivationInvalid
		}
		page.NextCursor = "license:" + batch.NextCursor.String()
	}
	return page, nil
}

// PendingConfirmRequest is the controller administrator's confirmation of a pending market authorization.
type PendingConfirmRequest struct {
	RequestID                     string
	IdempotencyKey                string
	AuthorizationID               uuid.UUID
	VerificationID                uuid.UUID
	ExpectedRevision              uint64
	ApprovedScopes                []string
	SensitivePermissionsConfirmed bool
	NewPermissionsConfirmed       bool
	UserID                        uuid.UUID
	Username                      string
}

// PendingConfirmResult is the license authorization after the confirmation (status authorized).
type PendingConfirmResult struct {
	AuthorizationID uuid.UUID
	Revision        uint64
}

// ConfirmPending asks the license service to confirm a pending market authorization on behalf of the
// controller administrator. The install itself then goes through the signed activation resolve.
func (client *ActivationClient) ConfirmPending(ctx context.Context, input PendingConfirmRequest) (PendingConfirmResult, error) {
	if ctx == nil || client == nil || client.http == nil || client.now == nil || !validRequestID(input.RequestID) ||
		!idempotencyPattern.MatchString(input.IdempotencyKey) || len(input.IdempotencyKey) > 100 ||
		input.AuthorizationID == uuid.Nil || input.VerificationID == uuid.Nil || input.ExpectedRevision == 0 ||
		!validScopes(input.ApprovedScopes) || input.UserID == uuid.Nil || !validRequestID(input.Username) {
		return PendingConfirmResult{}, ErrInvalidInput
	}
	scopes := append([]string{}, input.ApprovedScopes...)
	payload := controllerConfirmRequestPayload{Schema: controllerConfirmRequestSchema, RequestID: input.RequestID,
		IdempotencyKey: input.IdempotencyKey, InstallationID: client.installationID,
		AuthorizationID: input.AuthorizationID, VerificationID: input.VerificationID,
		ExpectedRevision: input.ExpectedRevision, ApprovedScopes: scopes,
		SensitivePermissionsConfirmed: input.SensitivePermissionsConfirmed,
		NewPermissionsConfirmed:       input.NewPermissionsConfirmed, ControllerUserID: input.UserID,
		ControllerUsername: input.Username, RequestedAt: client.now().UTC().Truncate(time.Second)}
	canonical, err := json.Marshal(payload)
	if err != nil {
		return PendingConfirmResult{}, ErrInvalidInput
	}
	proof := ed25519.Sign(client.privateKey, framed(controllerConfirmRequestDomain, canonical))
	body, err := json.Marshal(controllerConfirmRequestWire{controllerConfirmRequestPayload: payload,
		Proof: base64.RawURLEncoding.EncodeToString(proof)})
	if err != nil {
		return PendingConfirmResult{}, ErrInvalidInput
	}
	responseBody, err := client.post(ctx, body)
	if err != nil {
		return PendingConfirmResult{}, err
	}
	var result controllerConfirmResultWire
	if strictJSON(responseBody, &result) != nil || result.Schema != controllerConfirmResultSchema ||
		result.RequestID != input.RequestID || result.InstallationID != client.installationID ||
		result.AuthorizationID != input.AuthorizationID || result.VerificationID != input.VerificationID ||
		result.Status != "authorized" || result.Revision != input.ExpectedRevision+1 ||
		result.ControllerUserID != input.UserID || result.ControllerUsername != input.Username {
		return PendingConfirmResult{}, ErrActivationInvalid
	}
	return PendingConfirmResult{AuthorizationID: result.AuthorizationID, Revision: result.Revision}, nil
}

func (client *ActivationClient) ReportLifecycle(ctx context.Context,
	input LifecycleReportRequest) (LifecycleReportResult, error) {
	receipt := input.Receipt
	if ctx == nil || client == nil || receipt.ID == uuid.Nil || receipt.AuthorizationID == uuid.Nil ||
		receipt.Snapshot.InstallationID != client.installationID || receipt.Snapshot.VerificationID == uuid.Nil ||
		!validRequestID(receipt.RequestID) || !idempotencyPattern.MatchString(receipt.IdempotencyKey) {
		return LifecycleReportResult{}, ErrInvalidInput
	}
	action := lifecycleReportAction(receipt.Result)
	if action == "" {
		return LifecycleReportResult{}, ErrInvalidInput
	}
	if !validLifecycleReportRevision(action, receipt.FromRevision, receipt.ToRevision) {
		return LifecycleReportResult{}, ErrInvalidInput
	}
	payload := lifecycleReportRequestPayload{Schema: lifecycleReceiptRequestSchema, RequestID: receipt.RequestID,
		IdempotencyKey: receipt.IdempotencyKey, InstallationID: client.installationID,
		AuthorizationID: receipt.AuthorizationID, VerificationID: receipt.Snapshot.VerificationID,
		Action: action, ControlFromRevision: receipt.FromRevision, ControlToRevision: receipt.ToRevision,
		Status: receipt.Snapshot.Status, Reason: receipt.Reason, StableReasonCode: receipt.StableReasonCode,
		OccurredAt: receipt.OccurredAt.UTC().Truncate(time.Second)}
	canonical, err := json.Marshal(payload)
	if err != nil {
		return LifecycleReportResult{}, ErrInvalidInput
	}
	proof := ed25519.Sign(client.privateKey, framed(lifecycleReceiptRequestDomain, canonical))
	body, err := json.Marshal(lifecycleReportRequestWire{lifecycleReportRequestPayload: payload,
		Proof: base64.RawURLEncoding.EncodeToString(proof)})
	if err != nil {
		return LifecycleReportResult{}, ErrInvalidInput
	}
	responseBody, err := client.post(ctx, body)
	if err != nil {
		return LifecycleReportResult{}, err
	}
	var response lifecycleReportResponseWire
	if strictJSON(responseBody, &response) != nil {
		return LifecycleReportResult{}, ErrActivationInvalid
	}
	reencoded, err := json.Marshal(response)
	if err != nil || !bytes.Equal(reencoded, responseBody) {
		return LifecycleReportResult{}, ErrActivationInvalid
	}
	digest := sha256.Sum256(framed("cdnca-plugin-installation-lifecycle-idempotency/v1", append(canonical, proof...)))
	now := client.now().UTC().Truncate(time.Second)
	if response.Schema != lifecycleReceiptSchema || response.RequestID != receipt.RequestID ||
		response.RequestDigest != hex.EncodeToString(digest[:]) || response.InstallationID != client.installationID ||
		response.AuthorizationID != receipt.AuthorizationID || response.VerificationID != receipt.Snapshot.VerificationID ||
		response.Action != action || response.LifecycleRevision == 0 || response.Status != receipt.Snapshot.Status ||
		response.Algorithm != "Ed25519" || response.KeyID == "" || !canonicalSecond(response.IssuedAt) ||
		response.IssuedAt.After(now) {
		return LifecycleReportResult{}, ErrActivationInvalid
	}
	unsigned := response
	unsigned.Signature = ""
	unsignedPayload, err := json.Marshal(unsigned)
	signature, decodeErr := decodeSignature(response.Signature)
	if err != nil || decodeErr != nil || client.trust.VerifyDetached(response.KeyID,
		framed(lifecycleReceiptDomain, unsignedPayload), signature, response.IssuedAt, now) != nil {
		return LifecycleReportResult{}, ErrActivationInvalid
	}
	return LifecycleReportResult{AuthorizationID: response.AuthorizationID,
		LifecycleRevision: response.LifecycleRevision, Status: response.Status}, nil
}

func (client *ActivationClient) post(ctx context.Context, body []byte) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, ErrInvalidInput
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := client.http.Do(request)
	if err != nil || response == nil || response.Body == nil {
		return nil, ErrFactUnavailable
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
	if err != nil || len(responseBody) > 1<<20 {
		return nil, ErrActivationInvalid
	}
	if response.StatusCode != http.StatusOK {
		return nil, activationHTTPError(response.StatusCode, responseBody)
	}
	if len(responseBody) < 2 || responseBody[len(responseBody)-1] != '\n' || responseBody[len(responseBody)-2] == '\n' {
		return nil, ErrActivationInvalid
	}
	return responseBody[:len(responseBody)-1], nil
}

func lifecycleReportAction(result string) string {
	switch result {
	case ReceiptInstalled:
		return "installed"
	case ReceiptUpgradeApplied, ReceiptUpgradeFailedLKGPreserved:
		return result
	case ReceiptDisabled:
		return ActionDisable
	case ReceiptUninstalled:
		return ActionUninstall
	case ReceiptResumed:
		// The license lifecycle action for a controller resume (license accepts only its own pause).
		return "enable"
	default:
		return ""
	}
}

func (client *ActivationClient) verifyResponse(digest [sha256.Size]byte, request activationRequestPayload,
	signed activationBatchWire, now time.Time) (ActivationResult, error) {
	if signed.Schema != activationBatchSchema || signed.RequestID != request.RequestID ||
		signed.RequestDigest != hex.EncodeToString(digest[:]) || signed.CustomerID == uuid.Nil ||
		signed.InstallationID != request.InstallationID || signed.AuthorizationID == uuid.Nil ||
		signed.VerificationID != request.VerificationID || signed.PluginID == "" ||
		signed.Action != request.Action || !slices.Equal(signed.RequestedScopes, request.RequestedScopes) ||
		signed.SourceReceiptID == uuid.Nil || signed.Decision != "allow" || signed.StableReasonCode == "" ||
		signed.Algorithm != "Ed25519" || signed.KeyID == "" || len(signed.KeyID) > 128 ||
		!canonicalSecond(signed.IssuedAt) || signed.IssuedAt.After(now) ||
		!signed.ExpiresAt.Equal(signed.IssuedAt.Add(time.Minute)) || !now.Before(signed.ExpiresAt) ||
		signed.LifecycleRevision == 0 || !validScopes(signed.ApprovedScopes) ||
		!validScopes(signed.ManifestScopes) || !validScopes(signed.RequestedScopes) || !validScopes(signed.SensitiveScopes) ||
		!validScopes(signed.NewScopes) || !subset(signed.RequestedScopes, signed.ApprovedScopes) ||
		!subset(signed.ApprovedScopes, signed.ManifestScopes) || !subset(signed.SensitiveScopes, signed.ManifestScopes) ||
		!subset(signed.NewScopes, signed.ManifestScopes) ||
		len(signed.Facts) != len(signed.RequestedScopes) {
		return ActivationResult{}, ErrActivationInvalid
	}
	unsignedFacts := make([]activationFactUnsigned, len(signed.Facts))
	for index, fact := range signed.Facts {
		if fact.Schema != activationFactSchema || fact.Scope != signed.RequestedScopes[index] ||
			fact.Decision != "allow" || fact.StableReasonCode == "" {
			return ActivationResult{}, ErrActivationInvalid
		}
		unsignedFacts[index] = activationFactUnsigned{Schema: fact.Schema, Scope: fact.Scope,
			Decision: fact.Decision, StableReasonCode: fact.StableReasonCode}
	}
	batchPayload, err := json.Marshal(activationBatchPayload{activationShared: signed.activationShared, Facts: unsignedFacts})
	batchSignature, decodeErr := decodeSignature(signed.Signature)
	if err != nil || decodeErr != nil || client.trust.VerifyDetached(signed.KeyID,
		framed(activationBatchDomain, batchPayload), batchSignature, signed.IssuedAt, now) != nil {
		return ActivationResult{}, ErrActivationInvalid
	}
	for _, fact := range signed.Facts {
		factPayload, err := json.Marshal(activationFactPayload{activationShared: signed.activationShared,
			FactSchema: fact.Schema, Scope: fact.Scope, FactDecision: fact.Decision,
			FactStableReasonCode: fact.StableReasonCode})
		factSignature, decodeErr := decodeSignature(fact.Signature)
		if err != nil || decodeErr != nil || client.trust.VerifyDetached(signed.KeyID,
			framed(activationFactDomain, factPayload), factSignature, signed.IssuedAt, now) != nil {
			return ActivationResult{}, ErrActivationInvalid
		}
	}
	candidate := Candidate{TenantID: signed.CustomerID, InstallationID: signed.InstallationID,
		AuthorizationID: signed.AuthorizationID, VerificationID: signed.VerificationID,
		PluginID: signed.PluginID, Version: signed.PluginVersion, ResourceScope: signed.ResourceScope,
		EntrypointType:            signed.EntrypointType,
		ManifestSHA256:            signed.ManifestSHA256,
		ConfigurationSchemaSHA256: signed.ConfigurationSchemaSHA256,
		ManifestScopes:            append([]string{}, signed.ManifestScopes...),
		ApprovedScopes:            append([]string{}, signed.RequestedScopes...),
		SensitiveScopes:           append([]string{}, signed.SensitiveScopes...)}
	if !validCandidate(candidate) {
		return ActivationResult{}, ErrActivationInvalid
	}
	return ActivationResult{Candidate: candidate, LifecycleStatus: signed.LifecycleStatus,
		LifecycleRevision: signed.LifecycleRevision, IdentityGeneration: signed.IdentityGeneration,
		NewScopes: append([]string{}, signed.NewScopes...), verified: true}, nil
}

func (result ActivationResult) Verifier() CandidateVerifier {
	return activationResultVerifier{candidate: result.Candidate, verified: result.verified}
}

type activationResultVerifier struct {
	candidate Candidate
	verified  bool
}

func (verifier activationResultVerifier) VerifyCandidate(_ context.Context, candidate Candidate,
	_ []SignedRuntimeFact) error {
	if !verifier.verified || !sameCandidate(verifier.candidate, candidate) {
		return ErrFactDenied
	}
	return nil
}

func sameCandidate(left, right Candidate) bool {
	return left.TenantID == right.TenantID && left.ResourceScope == right.ResourceScope &&
		left.EntrypointType == right.EntrypointType &&
		left.InstallationID == right.InstallationID &&
		left.AuthorizationID == right.AuthorizationID && left.VerificationID == right.VerificationID &&
		left.PluginID == right.PluginID && left.Version == right.Version &&
		left.ManifestSHA256 == right.ManifestSHA256 &&
		left.ConfigurationSchemaSHA256 == right.ConfigurationSchemaSHA256 &&
		slices.Equal(left.ManifestScopes, right.ManifestScopes) &&
		slices.Equal(left.ApprovedScopes, right.ApprovedScopes) &&
		slices.Equal(left.SensitiveScopes, right.SensitiveScopes)
}

func activationHTTPError(status int, body []byte) error {
	var response struct {
		Code      string `json:"code"`
		RequestID string `json:"request_id"`
	}
	if strictJSON(body, &response) != nil || !validRequestID(response.RequestID) {
		return ErrActivationInvalid
	}
	switch response.Code {
	case "scope_approval_required":
		return ErrConsentRequired
	case "controller_confirmation_unavailable":
		return ErrFactDenied
	case "lifecycle_stale":
		return ErrRevisionConflict
	case "platform_paused":
		return ErrPlatformPaused
	case "idempotency_conflict":
		return ErrIdempotencyConflict
	case "activation_denied":
		return ErrFactDenied
	case "signer_unavailable", "internal_error":
		return ErrFactUnavailable
	case "invalid_request", "unauthenticated", "forbidden", "not_found":
		return ErrFactDenied
	default:
		if status >= http.StatusInternalServerError {
			return ErrFactUnavailable
		}
		return ErrActivationInvalid
	}
}

type activationRequestPayload struct {
	Schema                 string    `json:"schema"`
	RequestID              string    `json:"request_id"`
	IdempotencyKey         string    `json:"idempotency_key"`
	InstallationID         uuid.UUID `json:"installation_id"`
	VerificationID         uuid.UUID `json:"verification_id"`
	Action                 string    `json:"action"`
	KnownLifecycleRevision uint64    `json:"known_lifecycle_revision"`
	RequestedScopes        []string  `json:"requested_scopes"`
	RequestedAt            time.Time `json:"requested_at"`
}

type activationRequestWire struct {
	activationRequestPayload
	Proof string `json:"proof"`
}

type activationShared struct {
	Schema                    string    `json:"schema"`
	RequestID                 string    `json:"request_id"`
	RequestDigest             string    `json:"request_digest"`
	CustomerID                uuid.UUID `json:"customer_id"`
	InstallationID            uuid.UUID `json:"installation_id"`
	AuthorizationID           uuid.UUID `json:"authorization_id"`
	VerificationID            uuid.UUID `json:"verification_id"`
	PluginID                  string    `json:"plugin_id"`
	PluginVersion             string    `json:"plugin_version"`
	ResourceScope             string    `json:"resource_scope"`
	EntrypointType            string    `json:"entrypoint_type"`
	ManifestSHA256            string    `json:"manifest_sha256"`
	ConfigurationSchemaSHA256 string    `json:"configuration_schema_sha256"`
	ManifestScopes            []string  `json:"manifest_scopes"`
	Action                    string    `json:"action"`
	ApprovedScopes            []string  `json:"approved_scopes"`
	RequestedScopes           []string  `json:"requested_scopes"`
	SensitiveScopes           []string  `json:"sensitive_scopes"`
	NewScopes                 []string  `json:"new_scopes"`
	LifecycleStatus           string    `json:"lifecycle_status"`
	LifecycleRevision         uint64    `json:"lifecycle_revision"`
	IdentityGeneration        uint64    `json:"identity_generation"`
	SourceReceiptID           uuid.UUID `json:"source_receipt_id"`
	Decision                  string    `json:"decision"`
	StableReasonCode          string    `json:"stable_reason_code"`
	IssuedAt                  time.Time `json:"issued_at"`
	ExpiresAt                 time.Time `json:"expires_at"`
	Algorithm                 string    `json:"algorithm"`
	KeyID                     string    `json:"key_id"`
}

type activationFact struct {
	Schema           string `json:"schema"`
	Scope            string `json:"scope"`
	Decision         string `json:"decision"`
	StableReasonCode string `json:"stable_reason_code"`
	Signature        string `json:"signature"`
}

type activationFactUnsigned struct {
	Schema           string `json:"schema"`
	Scope            string `json:"scope"`
	Decision         string `json:"decision"`
	StableReasonCode string `json:"stable_reason_code"`
}

type activationBatchPayload struct {
	activationShared
	Facts []activationFactUnsigned `json:"facts"`
}

type activationFactPayload struct {
	activationShared
	FactSchema           string `json:"fact_schema"`
	Scope                string `json:"scope"`
	FactDecision         string `json:"fact_decision"`
	FactStableReasonCode string `json:"fact_stable_reason_code"`
}

type activationBatchWire struct {
	activationShared
	Signature string           `json:"signature"`
	Facts     []activationFact `json:"facts"`
}

type candidateSyncRequestPayload struct {
	Schema         string     `json:"schema"`
	RequestID      string     `json:"request_id"`
	InstallationID uuid.UUID  `json:"installation_id"`
	Limit          int        `json:"limit"`
	Cursor         *uuid.UUID `json:"cursor,omitempty"`
	RequestedAt    time.Time  `json:"requested_at"`
}

type controllerConfirmRequestPayload struct {
	Schema                        string    `json:"schema"`
	RequestID                     string    `json:"request_id"`
	IdempotencyKey                string    `json:"idempotency_key"`
	InstallationID                uuid.UUID `json:"installation_id"`
	AuthorizationID               uuid.UUID `json:"authorization_id"`
	VerificationID                uuid.UUID `json:"verification_id"`
	ExpectedRevision              uint64    `json:"expected_revision"`
	ApprovedScopes                []string  `json:"approved_scopes"`
	SensitivePermissionsConfirmed bool      `json:"sensitive_permissions_confirmed"`
	NewPermissionsConfirmed       bool      `json:"new_permissions_confirmed"`
	ControllerUserID              uuid.UUID `json:"controller_user_id"`
	ControllerUsername            string    `json:"controller_username"`
	RequestedAt                   time.Time `json:"requested_at"`
}

type controllerConfirmRequestWire struct {
	controllerConfirmRequestPayload
	Proof string `json:"proof"`
}

type controllerConfirmResultWire struct {
	Schema             string    `json:"schema"`
	RequestID          string    `json:"request_id"`
	InstallationID     uuid.UUID `json:"installation_id"`
	AuthorizationID    uuid.UUID `json:"authorization_id"`
	VerificationID     uuid.UUID `json:"verification_id"`
	Status             string    `json:"status"`
	Revision           uint64    `json:"revision"`
	ControllerUserID   uuid.UUID `json:"controller_user_id"`
	ControllerUsername string    `json:"controller_username"`
	ConfirmedAt        time.Time `json:"confirmed_at"`
}

type candidateSyncRequestWire struct {
	candidateSyncRequestPayload
	Proof string `json:"proof"`
}

type candidateSyncCandidateWire struct {
	AuthorizationID           uuid.UUID `json:"authorization_id"`
	VerificationID            uuid.UUID `json:"verification_id"`
	PluginID                  string    `json:"plugin_id"`
	PluginVersion             string    `json:"plugin_version"`
	ResourceScope             string    `json:"resource_scope"`
	EntrypointType            string    `json:"entrypoint_type"`
	ManifestSHA256            string    `json:"manifest_sha256"`
	ConfigurationSchemaSHA256 string    `json:"configuration_schema_sha256"`
	ManifestScopes            []string  `json:"manifest_scopes"`
	ApprovedScopes            []string  `json:"approved_scopes"`
	SensitiveScopes           []string  `json:"sensitive_scopes"`
	NewScopes                 []string  `json:"new_scopes"`
	Status                    string    `json:"status"`
	Revision                  uint64    `json:"revision"`
	IdentityGeneration        uint64    `json:"identity_generation"`
	LKGVerificationID         uuid.UUID `json:"lkg_verification_id,omitempty"`
	LKGVersion                string    `json:"lkg_version,omitempty"`
	UpdatedAt                 time.Time `json:"updated_at"`
	PausedBy                  string    `json:"paused_by,omitempty"`
	PausedReason              string    `json:"paused_reason,omitempty"`
}

type candidateSyncBatchWire struct {
	Schema         string                       `json:"schema"`
	RequestID      string                       `json:"request_id"`
	RequestDigest  string                       `json:"request_digest"`
	CustomerID     uuid.UUID                    `json:"customer_id"`
	InstallationID uuid.UUID                    `json:"installation_id"`
	Candidates     []candidateSyncCandidateWire `json:"candidates"`
	NextCursor     *uuid.UUID                   `json:"next_cursor,omitempty"`
	IssuedAt       time.Time                    `json:"issued_at"`
	ExpiresAt      time.Time                    `json:"expires_at"`
	Algorithm      string                       `json:"algorithm"`
	KeyID          string                       `json:"key_id"`
	Signature      string                       `json:"signature"`
}

func (candidate candidateSyncCandidateWire) toView(tenantID, installationID uuid.UUID,
	statusFilter, pluginFilter string) (InstallationView, error) {
	if !candidate.valid() {
		return InstallationView{}, ErrActivationInvalid
	}
	status := candidate.Status
	if status == "authorized" {
		status = StatusPendingConfirmation
	}
	value := Installation{Schema: Schema, TenantID: tenantID, InstallationID: installationID,
		AuthorizationID: candidate.AuthorizationID, VerificationID: candidate.VerificationID,
		PluginID: candidate.PluginID, Version: candidate.PluginVersion, ResourceScope: candidate.ResourceScope,
		EntrypointType:            candidate.EntrypointType,
		ManifestSHA256:            candidate.ManifestSHA256,
		ConfigurationSchemaSHA256: candidate.ConfigurationSchemaSHA256,
		ManifestScopes:            append([]string{}, candidate.ManifestScopes...),
		ApprovedScopes:            append([]string{}, candidate.ApprovedScopes...),
		SensitiveScopes:           append([]string{}, candidate.SensitiveScopes...), Status: status,
		Revision: candidate.Revision, IdentityGeneration: candidate.IdentityGeneration,
		LKGVerificationID: candidate.LKGVerificationID, LKGVersion: candidate.LKGVersion,
		UpdatedAt: candidate.UpdatedAt}
	if !validCandidate(candidateFromInstallation(value)) {
		return InstallationView{}, ErrActivationInvalid
	}
	if statusFilter != "" && statusFilter != status || pluginFilter != "" && candidate.PluginID != pluginFilter {
		return InstallationView{}, nil
	}
	return InstallationView{Installation: value, NewScopes: append([]string{}, candidate.NewScopes...),
		AuthorizationStatus: candidate.Status, PausedBy: candidate.PausedBy, PausedReason: candidate.PausedReason}, nil
}

func (candidate candidateSyncCandidateWire) valid() bool {
	if candidate.AuthorizationID == uuid.Nil || candidate.VerificationID == uuid.Nil ||
		candidate.Revision == 0 || !canonicalSecond(candidate.UpdatedAt) ||
		!digestPattern.MatchString(candidate.ManifestSHA256) ||
		!digestPattern.MatchString(candidate.ConfigurationSchemaSHA256) ||
		!validScopes(candidate.ManifestScopes) || !validScopes(candidate.ApprovedScopes) ||
		!validScopes(candidate.SensitiveScopes) || !validScopes(candidate.NewScopes) ||
		!subset(candidate.ApprovedScopes, candidate.ManifestScopes) ||
		!subset(candidate.SensitiveScopes, candidate.ManifestScopes) ||
		!subset(candidate.NewScopes, candidate.ManifestScopes) {
		return false
	}
	// Only a disabled authorization names who paused it; an owner-less disabled row is a platform pause.
	if candidate.Status != StatusDisabled && (candidate.PausedBy != "" || candidate.PausedReason != "") ||
		candidate.PausedBy == "" && candidate.PausedReason != "" ||
		candidate.PausedBy != "" && candidate.PausedBy != PausedByInstallation && candidate.PausedBy != PausedByOperator &&
			candidate.PausedBy != PausedByService ||
		candidate.PausedReason != "" && !validReason(candidate.PausedReason) {
		return false
	}
	switch candidate.Status {
	case "authorized", StatusPendingConfirmation:
		return candidate.IdentityGeneration == 0 && candidate.LKGVerificationID == uuid.Nil && candidate.LKGVersion == ""
	case StatusEnabled, StatusDisabled:
		return candidate.IdentityGeneration > 0 && candidate.LKGVerificationID != uuid.Nil &&
			versionPattern.MatchString(candidate.LKGVersion) && semver.IsValid("v"+candidate.LKGVersion)
	default:
		return false
	}
}

func validLifecycleReportRevision(action string, from, to uint64) bool {
	if action == "installed" {
		return from == 0 && to == 1
	}
	return from > 0 && to == from+1
}

type lifecycleReportRequestPayload struct {
	Schema              string    `json:"schema"`
	RequestID           string    `json:"request_id"`
	IdempotencyKey      string    `json:"idempotency_key"`
	InstallationID      uuid.UUID `json:"installation_id"`
	AuthorizationID     uuid.UUID `json:"authorization_id"`
	VerificationID      uuid.UUID `json:"verification_id"`
	Action              string    `json:"action"`
	ControlFromRevision uint64    `json:"control_from_revision"`
	ControlToRevision   uint64    `json:"control_to_revision"`
	Status              string    `json:"status"`
	Reason              string    `json:"reason,omitempty"`
	StableReasonCode    string    `json:"stable_reason_code,omitempty"`
	OccurredAt          time.Time `json:"occurred_at"`
}

type lifecycleReportRequestWire struct {
	lifecycleReportRequestPayload
	Proof string `json:"proof"`
}

type lifecycleReportResponseWire struct {
	Schema             string    `json:"schema"`
	RequestID          string    `json:"request_id"`
	RequestDigest      string    `json:"request_digest"`
	InstallationID     uuid.UUID `json:"installation_id"`
	AuthorizationID    uuid.UUID `json:"authorization_id"`
	VerificationID     uuid.UUID `json:"verification_id"`
	Action             string    `json:"action"`
	Status             string    `json:"status"`
	LifecycleRevision  uint64    `json:"lifecycle_revision"`
	IdentityGeneration uint64    `json:"identity_generation"`
	IssuedAt           time.Time `json:"issued_at"`
	Algorithm          string    `json:"algorithm"`
	KeyID              string    `json:"key_id"`
	Signature          string    `json:"signature"`
}

func framed(domain string, payload []byte) []byte {
	result := make([]byte, 0, 8+len(domain)+len(payload))
	for _, field := range [][]byte{[]byte(domain), payload} {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		result = append(result, length[:]...)
		result = append(result, field...)
	}
	return result
}

func decodeSignature(value string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != ed25519.SignatureSize {
		return nil, ErrActivationInvalid
	}
	return decoded, nil
}

func canonicalSecond(value time.Time) bool {
	return !value.IsZero() && value.Equal(value.UTC().Truncate(time.Second))
}

func strictJSON(raw []byte, destination any) error {
	if !json.Valid(raw) || duplicateJSONKey(raw) {
		return ErrInvalidInput
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return ErrInvalidInput
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalidInput
	}
	return nil
}

func duplicateJSONKey(raw []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var walk func() bool
	walk = func() bool {
		token, err := decoder.Token()
		if err != nil {
			return true
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return false
		}
		switch delimiter {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				key, err := decoder.Token()
				name, ok := key.(string)
				if err != nil || !ok {
					return true
				}
				if _, exists := seen[name]; exists {
					return true
				}
				seen[name] = struct{}{}
				if walk() {
					return true
				}
			}
		case '[':
			for decoder.More() {
				if walk() {
					return true
				}
			}
		default:
			return true
		}
		_, err = decoder.Token()
		return err != nil
	}
	return walk()
}

var _ PendingConfirmer = (*ActivationClient)(nil)
