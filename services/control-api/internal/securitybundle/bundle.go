package securitybundle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

const (
	SchemaVersion  = "cdnca.security-policy.bundle/v1"
	maxBundleSize  = 1 << 20
	maxTargetNodes = 10_000
	maxUnixTime    = int64(253402300799)
)

var (
	ErrInvalidInput        = errors.New("invalid security bundle input")
	ErrIdempotencyConflict = errors.New("security bundle idempotency conflict")
	ErrSigningFailed       = errors.New("security bundle signing failed")
	ErrInvalidBundle       = errors.New("invalid security bundle")
	ErrUnknownKey          = errors.New("unknown security bundle signing key")
	ErrInvalidSignature    = errors.New("invalid security bundle signature")
	ErrNotYetValid         = errors.New("security bundle is not yet valid")
	ErrExpired             = errors.New("security bundle is expired")
	ErrBindingMismatch     = errors.New("security bundle binding mismatch")
)

type Signer interface {
	entitlement.Signer
	PublicKey() ed25519.PublicKey
}

type Config struct {
	Clock    func() time.Time
	Validity time.Duration
}

type PublishRequest struct {
	TenantScopeID         uuid.UUID
	SiteID                uuid.UUID
	Policy                securitypolicy.Policy
	TargetNodeIDs         []uuid.UUID
	ExpectedActiveVersion int64
	RolloutID             uuid.UUID
	IdempotencyKey        string
}

type Payload struct {
	SchemaVersion         string                         `json:"schema_version"`
	BundleID              uuid.UUID                      `json:"bundle_id"`
	TenantScopeID         uuid.UUID                      `json:"tenant_scope_id"`
	SiteID                uuid.UUID                      `json:"site_id"`
	PolicyID              uuid.UUID                      `json:"policy_id"`
	PolicyVersion         int64                          `json:"policy_version"`
	RuntimeSnapshotSHA256 string                         `json:"runtime_snapshot_sha256"`
	RuntimeSnapshot       securitypolicy.RuntimeSnapshot `json:"runtime_snapshot"`
	TargetNodeIDs         []uuid.UUID                    `json:"target_node_ids"`
	ExpectedActiveVersion int64                          `json:"expected_active_version"`
	RolloutID             uuid.UUID                      `json:"rollout_id"`
	IdempotencyKey        string                         `json:"idempotency_key"`
	IssuedAt              int64                          `json:"issued_at"`
	ExpiresAt             int64                          `json:"expires_at"`
}

type SignedBundle struct {
	Algorithm     string  `json:"algorithm"`
	KeyID         string  `json:"key_id"`
	PayloadSHA256 string  `json:"payload_sha256"`
	Payload       Payload `json:"payload"`
	Signature     string  `json:"signature"`
}

type PublicationPlan struct {
	IdempotencyKey         string
	RequestSHA256          [32]byte
	BundleID               uuid.UUID
	CanonicalPayload       []byte
	CanonicalPayloadSHA256 [32]byte
	RuntimeSnapshotSHA256  [32]byte
	Bundle                 SignedBundle
	BundleJSON             []byte
}

type PlanResult struct {
	Plan     PublicationPlan
	Replayed bool
}

type VerifyOptions struct {
	Now                   time.Time
	TenantScopeID         uuid.UUID
	SiteID                uuid.UUID
	PolicyID              uuid.UUID
	PolicyVersion         int64
	TargetNodeIDs         []uuid.UUID
	ExpectedActiveVersion int64
	RolloutID             uuid.UUID
	IdempotencyKey        string
}

type Publisher struct {
	signer   Signer
	clock    func() time.Time
	validity time.Duration
}

type signingDocument struct {
	Algorithm     string  `json:"algorithm"`
	KeyID         string  `json:"key_id"`
	PayloadSHA256 string  `json:"payload_sha256"`
	Payload       Payload `json:"payload"`
}

type requestDocument struct {
	TenantScopeID         uuid.UUID   `json:"tenant_scope_id"`
	SiteID                uuid.UUID   `json:"site_id"`
	PolicyID              uuid.UUID   `json:"policy_id"`
	PolicyVersion         int64       `json:"policy_version"`
	RuntimeSnapshotSHA256 string      `json:"runtime_snapshot_sha256"`
	TargetNodeIDs         []uuid.UUID `json:"target_node_ids"`
	ExpectedActiveVersion int64       `json:"expected_active_version"`
	RolloutID             uuid.UUID   `json:"rollout_id"`
}

func NewPublisher(signer Signer, config Config) (*Publisher, error) {
	if signer == nil || config.Clock == nil || config.Validity < time.Second ||
		config.Validity > 24*time.Hour || config.Validity%time.Second != 0 ||
		entitlement.ValidateKeyID(signer.KeyID()) != nil || len(signer.PublicKey()) != ed25519.PublicKeySize {
		return nil, ErrInvalidInput
	}
	return &Publisher{signer: signer, clock: config.Clock, validity: config.Validity}, nil
}

// Plan is side-effect free. A persistence adapter passes the plan previously
// loaded under the same idempotency key while holding its transaction lock.
func (publisher *Publisher) Plan(ctx context.Context, request PublishRequest, existing *PublicationPlan) (PlanResult, error) {
	if publisher == nil || publisher.signer == nil {
		return PlanResult{}, ErrInvalidInput
	}
	snapshot, targets, requestDigest, err := normalizeRequest(request)
	if err != nil {
		return PlanResult{}, err
	}
	if existing != nil {
		if existing.IdempotencyKey != request.IdempotencyKey || existing.RequestSHA256 != requestDigest {
			return PlanResult{}, ErrIdempotencyConflict
		}
		return PlanResult{Plan: clonePlan(*existing), Replayed: true}, nil
	}

	now := publisher.clock().UTC().Truncate(time.Second)
	if now.Unix() <= 0 || now.Unix() > maxUnixTime-int64(publisher.validity/time.Second) {
		return PlanResult{}, ErrInvalidInput
	}
	bundleID := deterministicBundleID(request.TenantScopeID, request.SiteID, request.IdempotencyKey)
	payload := Payload{
		SchemaVersion: SchemaVersion, BundleID: bundleID,
		TenantScopeID: request.TenantScopeID, SiteID: request.SiteID,
		PolicyID: request.Policy.ID, PolicyVersion: request.Policy.Revision,
		RuntimeSnapshotSHA256: hex.EncodeToString(snapshot.SHA256[:]), RuntimeSnapshot: snapshot.Snapshot,
		TargetNodeIDs: targets, ExpectedActiveVersion: request.ExpectedActiveVersion,
		RolloutID: request.RolloutID, IdempotencyKey: request.IdempotencyKey,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(publisher.validity).Unix(),
	}
	keyID := publisher.signer.KeyID()
	publicKey := slices.Clone(publisher.signer.PublicKey())
	if entitlement.ValidateKeyID(keyID) != nil || len(publicKey) != ed25519.PublicKeySize {
		return PlanResult{}, ErrSigningFailed
	}
	canonicalPayload, err := json.Marshal(payload)
	if err != nil {
		return PlanResult{}, fmt.Errorf("%w: marshal payload", ErrInvalidInput)
	}
	payloadDigest := sha256.Sum256(canonicalPayload)
	payloadDigestText := hex.EncodeToString(payloadDigest[:])
	signingBytes, err := json.Marshal(signingDocument{
		Algorithm: entitlement.Algorithm, KeyID: keyID, PayloadSHA256: payloadDigestText, Payload: payload,
	})
	if err != nil {
		return PlanResult{}, fmt.Errorf("%w: marshal signing document", ErrInvalidInput)
	}
	signature, err := publisher.signer.Sign(ctx, slices.Clone(signingBytes))
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, signingBytes, signature) {
		return PlanResult{}, ErrSigningFailed
	}
	bundle := SignedBundle{
		Algorithm: entitlement.Algorithm, KeyID: keyID, PayloadSHA256: payloadDigestText, Payload: payload,
		Signature: base64.RawURLEncoding.EncodeToString(signature),
	}
	bundleJSON, err := json.Marshal(bundle)
	if err != nil {
		return PlanResult{}, fmt.Errorf("%w: marshal bundle", ErrInvalidInput)
	}
	return PlanResult{Plan: PublicationPlan{
		IdempotencyKey: request.IdempotencyKey, RequestSHA256: requestDigest, BundleID: bundleID,
		CanonicalPayload: canonicalPayload, CanonicalPayloadSHA256: payloadDigest,
		RuntimeSnapshotSHA256: snapshot.SHA256, Bundle: bundle, BundleJSON: bundleJSON,
	}}, nil
}

func Verify(encoded []byte, keys map[string]ed25519.PublicKey, options VerifyOptions) (SignedBundle, error) {
	bundle, err := decode(encoded)
	if err != nil {
		return SignedBundle{}, err
	}
	if bundle.Algorithm != entitlement.Algorithm || entitlement.ValidateKeyID(bundle.KeyID) != nil {
		return SignedBundle{}, ErrInvalidBundle
	}
	publicKey, exists := keys[bundle.KeyID]
	if !exists {
		return SignedBundle{}, ErrUnknownKey
	}
	publicKey = slices.Clone(publicKey)
	if len(publicKey) != ed25519.PublicKeySize {
		return SignedBundle{}, ErrInvalidBundle
	}
	signature, err := base64.RawURLEncoding.DecodeString(bundle.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return SignedBundle{}, ErrInvalidBundle
	}
	canonicalPayload, err := json.Marshal(bundle.Payload)
	if err != nil {
		return SignedBundle{}, ErrInvalidBundle
	}
	payloadDigest := sha256.Sum256(canonicalPayload)
	if bundle.PayloadSHA256 != hex.EncodeToString(payloadDigest[:]) {
		return SignedBundle{}, ErrInvalidBundle
	}
	signingBytes, err := json.Marshal(signingDocument{
		Algorithm: bundle.Algorithm, KeyID: bundle.KeyID, PayloadSHA256: bundle.PayloadSHA256, Payload: bundle.Payload,
	})
	if err != nil || !ed25519.Verify(publicKey, signingBytes, signature) {
		return SignedBundle{}, ErrInvalidSignature
	}
	if err := validatePayload(bundle.Payload); err != nil {
		return SignedBundle{}, err
	}
	if options.Now.IsZero() {
		return SignedBundle{}, ErrInvalidInput
	}
	now := options.Now.UTC().Unix()
	if now < bundle.Payload.IssuedAt {
		return SignedBundle{}, ErrNotYetValid
	}
	if now >= bundle.Payload.ExpiresAt {
		return SignedBundle{}, ErrExpired
	}
	targets, err := normalizeTargets(options.TargetNodeIDs)
	if err != nil || options.TenantScopeID == uuid.Nil || options.SiteID == uuid.Nil || options.PolicyID == uuid.Nil ||
		options.PolicyVersion < 1 || options.ExpectedActiveVersion < 0 || options.RolloutID == uuid.Nil ||
		!validIdempotencyKey(options.IdempotencyKey) {
		return SignedBundle{}, ErrInvalidInput
	}
	payload := bundle.Payload
	if payload.TenantScopeID != options.TenantScopeID || payload.SiteID != options.SiteID ||
		payload.PolicyID != options.PolicyID || payload.PolicyVersion != options.PolicyVersion ||
		payload.ExpectedActiveVersion != options.ExpectedActiveVersion || payload.RolloutID != options.RolloutID ||
		payload.IdempotencyKey != options.IdempotencyKey || !slices.Equal(payload.TargetNodeIDs, targets) {
		return SignedBundle{}, ErrBindingMismatch
	}
	return bundle, nil
}

func normalizeRequest(request PublishRequest) (securitypolicy.CompiledRuntimeSnapshot, []uuid.UUID, [32]byte, error) {
	if request.TenantScopeID == uuid.Nil || request.SiteID == uuid.Nil || request.Policy.ScopeID != request.TenantScopeID ||
		request.ExpectedActiveVersion < 0 || request.RolloutID == uuid.Nil || !validIdempotencyKey(request.IdempotencyKey) {
		return securitypolicy.CompiledRuntimeSnapshot{}, nil, [32]byte{}, ErrInvalidInput
	}
	snapshot, err := securitypolicy.CompileRuntimeSnapshot(request.Policy, request.SiteID)
	if err != nil {
		return securitypolicy.CompiledRuntimeSnapshot{}, nil, [32]byte{}, ErrInvalidInput
	}
	targets, err := normalizeTargets(request.TargetNodeIDs)
	if err != nil {
		return securitypolicy.CompiledRuntimeSnapshot{}, nil, [32]byte{}, err
	}
	document := requestDocument{
		TenantScopeID: request.TenantScopeID, SiteID: request.SiteID,
		PolicyID: request.Policy.ID, PolicyVersion: request.Policy.Revision,
		RuntimeSnapshotSHA256: hex.EncodeToString(snapshot.SHA256[:]), TargetNodeIDs: targets,
		ExpectedActiveVersion: request.ExpectedActiveVersion, RolloutID: request.RolloutID,
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return securitypolicy.CompiledRuntimeSnapshot{}, nil, [32]byte{}, ErrInvalidInput
	}
	return snapshot, targets, sha256.Sum256(encoded), nil
}

func validatePayload(payload Payload) error {
	if payload.SchemaVersion != SchemaVersion || payload.BundleID == uuid.Nil || payload.TenantScopeID == uuid.Nil ||
		payload.SiteID == uuid.Nil || payload.PolicyID == uuid.Nil || payload.PolicyVersion < 1 ||
		payload.ExpectedActiveVersion < 0 || payload.RolloutID == uuid.Nil || !validIdempotencyKey(payload.IdempotencyKey) ||
		payload.IssuedAt <= 0 || payload.ExpiresAt > maxUnixTime || payload.ExpiresAt <= payload.IssuedAt ||
		payload.ExpiresAt-payload.IssuedAt > int64((24*time.Hour)/time.Second) {
		return ErrInvalidBundle
	}
	if payload.BundleID != deterministicBundleID(payload.TenantScopeID, payload.SiteID, payload.IdempotencyKey) {
		return ErrInvalidBundle
	}
	if err := securitypolicy.ValidateRuntimeSnapshot(payload.RuntimeSnapshot); err != nil ||
		payload.RuntimeSnapshot.TenantScopeID != payload.TenantScopeID || payload.RuntimeSnapshot.SiteID != payload.SiteID ||
		payload.RuntimeSnapshot.PolicyID != payload.PolicyID || payload.RuntimeSnapshot.PolicyVersion != payload.PolicyVersion {
		return ErrInvalidBundle
	}
	snapshot, err := json.Marshal(payload.RuntimeSnapshot)
	if err != nil {
		return ErrInvalidBundle
	}
	digest := sha256.Sum256(snapshot)
	if payload.RuntimeSnapshotSHA256 != hex.EncodeToString(digest[:]) {
		return ErrInvalidBundle
	}
	targets, err := normalizeTargets(payload.TargetNodeIDs)
	if err != nil || !slices.Equal(targets, payload.TargetNodeIDs) {
		return ErrInvalidBundle
	}
	return nil
}

func decode(encoded []byte) (SignedBundle, error) {
	if len(encoded) == 0 || len(encoded) > maxBundleSize {
		return SignedBundle{}, ErrInvalidBundle
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var bundle SignedBundle
	if err := decoder.Decode(&bundle); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return SignedBundle{}, ErrInvalidBundle
	}
	canonical, err := json.Marshal(bundle)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return SignedBundle{}, ErrInvalidBundle
	}
	return bundle, nil
}

func normalizeTargets(values []uuid.UUID) ([]uuid.UUID, error) {
	if len(values) == 0 || len(values) > maxTargetNodes {
		return nil, ErrInvalidInput
	}
	targets := slices.Clone(values)
	for _, id := range targets {
		if id == uuid.Nil {
			return nil, ErrInvalidInput
		}
	}
	sort.Slice(targets, func(left, right int) bool {
		return bytes.Compare(targets[left][:], targets[right][:]) < 0
	})
	return slices.Compact(targets), nil
}

func validIdempotencyKey(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character < 'A' || character > 'Z') && (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') && character != '.' && character != '_' && character != '-' {
			return false
		}
	}
	return true
}

func deterministicBundleID(tenantScopeID, siteID uuid.UUID, idempotencyKey string) uuid.UUID {
	return uuid.NewSHA1(tenantScopeID, []byte(siteID.String()+"\x00"+idempotencyKey))
}

func clonePlan(plan PublicationPlan) PublicationPlan {
	plan.CanonicalPayload = slices.Clone(plan.CanonicalPayload)
	plan.BundleJSON = slices.Clone(plan.BundleJSON)
	plan.Bundle.Payload.TargetNodeIDs = slices.Clone(plan.Bundle.Payload.TargetNodeIDs)
	return plan
}
