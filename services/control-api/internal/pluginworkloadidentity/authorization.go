package pluginworkloadidentity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/pluginruntimeauth"
	"github.com/cdnca/cdnca/services/control-api/internal/pluginruntimeprovider"
	"github.com/google/uuid"
)

const (
	workloadActionDomain = "cdnca-plugin-workload-action/v1"
	maximumIdentityBytes = 64 << 10
)

var (
	ErrInvalidConfiguration = errors.New("invalid plugin workload identity configuration")
	ErrInvalidInput         = errors.New("invalid plugin workload identity input")
	ErrDenied               = errors.New("plugin workload identity denied")
	ErrRateLimited          = errors.New("plugin workload identity rate limited")
	ErrUnavailable          = errors.New("plugin workload identity unavailable")

	pluginSlugPattern  = regexp.MustCompile(`^[a-z0-9]+(?:[.-][a-z0-9]+)+$`)
	permissionPattern  = regexp.MustCompile(`^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){1,7}$`)
	eventPattern       = regexp.MustCompile(`^io\.cdnca\.[a-z][a-z0-9_]*\.v[1-9][0-9]*\.[a-z][a-z0-9_]*$`)
	hexDigestPattern   = regexp.MustCompile(`^[a-f0-9]{64}$`)
	errSerializeSealed = errors.New("plugin workload authorization serialization forbidden")
)

type Provider interface {
	Resolve(context.Context, pluginruntimeprovider.Request) (pluginruntimeprovider.Facts, error)
}

type Verifier interface {
	Authorize([]byte, []byte, pluginruntimeauth.ExpectedAction) (pluginruntimeauth.Authorization, error)
}

type Config struct {
	Provider Provider
	Verifier Verifier
	Now      func() time.Time
}

type Request struct {
	TenantID            uuid.UUID
	InstallationID      uuid.UUID
	InvocationID        uuid.UUID
	PluginID            string
	CapabilityKind      string
	CapabilityCode      string
	Action              string
	ServiceIdentityJSON []byte
	ManifestSHA256      string
	VerificationID      uuid.UUID
	AttestationID       uuid.UUID
	AttestationRevision uint64
	ApprovalRevision    uint64
	RequestedAt         time.Time
}

// Authorization is a sealed result of signed workload identity and fresh capability checks.
type Authorization struct {
	requestID           string
	tenantID            uuid.UUID
	installationID      uuid.UUID
	invocationID        uuid.UUID
	pluginID            string
	pluginVersion       string
	capabilityKind      string
	capabilityCode      string
	action              string
	identitySHA256      [sha256.Size]byte
	manifestSHA256      string
	verificationID      uuid.UUID
	attestationID       uuid.UUID
	attestationRevision uint64
	approvalRevision    uint64
	authorizationID     uuid.UUID
	tokenID             uuid.UUID
	identityGeneration  uint64
	approvalReceiptID   uuid.UUID
	evaluatedAt         time.Time
	expiresAt           time.Time
}

type Authorizer struct {
	provider Provider
	verifier Verifier
	now      func() time.Time
}

func NewAuthorizer(config Config) (*Authorizer, error) {
	if nilDependency(config.Provider) || nilDependency(config.Verifier) || config.Now == nil || config.Now().IsZero() {
		return nil, ErrInvalidConfiguration
	}
	return &Authorizer{provider: config.Provider, verifier: config.Verifier, now: config.Now}, nil
}

func (authorizer *Authorizer) Authorize(ctx context.Context, request Request) (Authorization, error) {
	if authorizer == nil || ctx == nil || nilDependency(authorizer.provider) || nilDependency(authorizer.verifier) ||
		authorizer.now == nil {
		return Authorization{}, ErrInvalidInput
	}
	now := authorizer.now().UTC()
	if now.IsZero() || !validRequest(request, now) {
		return Authorization{}, ErrInvalidInput
	}
	requestID := workloadRequestID(request)
	providerRequest := pluginruntimeprovider.Request{
		RequestID: requestID, InstallationID: request.InstallationID,
		ServiceIdentityJSON: append([]byte(nil), request.ServiceIdentityJSON...),
		ManifestSHA256:      request.ManifestSHA256, VerificationID: request.VerificationID,
		AttestationID: request.AttestationID, AttestationRevision: request.AttestationRevision,
		KnownApprovalRevision: request.ApprovalRevision, CapabilityKind: request.CapabilityKind,
		CapabilityCode: request.CapabilityCode, Action: request.Action, RequestedAt: request.RequestedAt,
	}
	defer clear(providerRequest.ServiceIdentityJSON)
	facts, err := authorizer.provider.Resolve(ctx, providerRequest)
	defer clear(facts.IdentityJSON)
	defer clear(facts.DecisionJSON)
	if err != nil {
		return Authorization{}, mapDependencyError(err)
	}
	if !bytes.Equal(facts.IdentityJSON, request.ServiceIdentityJSON) || len(facts.DecisionJSON) == 0 {
		return Authorization{}, ErrDenied
	}
	expected := pluginruntimeauth.ExpectedAction{
		InstallationID: request.InstallationID, RequestID: requestID,
		CapabilityKind: request.CapabilityKind, CapabilityCode: request.CapabilityCode, Action: request.Action,
	}
	verified, err := authorizer.verifier.Authorize(facts.IdentityJSON, facts.DecisionJSON, expected)
	if err != nil {
		return Authorization{}, mapDependencyError(err)
	}
	if !authorizationMatchesRequest(verified, request, requestID, now) {
		return Authorization{}, ErrDenied
	}
	sealed := Authorization{
		requestID: requestID, tenantID: request.TenantID, installationID: request.InstallationID,
		invocationID: request.InvocationID, pluginID: request.PluginID, pluginVersion: verified.PluginVersion,
		capabilityKind: request.CapabilityKind, capabilityCode: request.CapabilityCode, action: request.Action,
		identitySHA256: sha256.Sum256(request.ServiceIdentityJSON), manifestSHA256: request.ManifestSHA256,
		verificationID: request.VerificationID, attestationID: request.AttestationID,
		attestationRevision: request.AttestationRevision, approvalRevision: request.ApprovalRevision,
		authorizationID: verified.AuthorizationID, tokenID: verified.TokenID,
		identityGeneration: verified.IdentityGeneration, approvalReceiptID: verified.ApprovalReceiptID,
		evaluatedAt: verified.EvaluatedAt, expiresAt: verified.ExpiresAt,
	}
	if !sealed.ValidFor(request, now) {
		return Authorization{}, ErrDenied
	}
	return sealed, nil
}

func (authorization Authorization) ValidFor(request Request, now time.Time) bool {
	if now.IsZero() || !validRequest(request, now.UTC()) || authorization.requestID == "" ||
		authorization.authorizationID == uuid.Nil || authorization.tokenID == uuid.Nil ||
		authorization.identityGeneration == 0 || authorization.approvalReceiptID == uuid.Nil ||
		!now.Before(authorization.expiresAt) {
		return false
	}
	return authorization.requestID == workloadRequestID(request) && authorization.tenantID == request.TenantID &&
		authorization.installationID == request.InstallationID && authorization.invocationID == request.InvocationID &&
		authorization.pluginID == request.PluginID && authorization.capabilityKind == request.CapabilityKind &&
		authorization.capabilityCode == request.CapabilityCode && authorization.action == request.Action &&
		authorization.identitySHA256 == sha256.Sum256(request.ServiceIdentityJSON) &&
		authorization.manifestSHA256 == request.ManifestSHA256 && authorization.verificationID == request.VerificationID &&
		authorization.attestationID == request.AttestationID &&
		authorization.attestationRevision == request.AttestationRevision &&
		authorization.approvalRevision == request.ApprovalRevision
}

func (authorization Authorization) RequestID() string         { return authorization.requestID }
func (authorization Authorization) TenantID() uuid.UUID       { return authorization.tenantID }
func (authorization Authorization) InstallationID() uuid.UUID { return authorization.installationID }
func (authorization Authorization) InvocationID() uuid.UUID   { return authorization.invocationID }
func (authorization Authorization) PluginID() string          { return authorization.pluginID }
func (authorization Authorization) CapabilityKind() string    { return authorization.capabilityKind }
func (authorization Authorization) CapabilityCode() string    { return authorization.capabilityCode }
func (authorization Authorization) Action() string            { return authorization.action }
func (authorization Authorization) ExpiresAt() time.Time      { return authorization.expiresAt }

func (Authorization) String() string   { return "pluginworkloadidentity.Authorization{sealed}" }
func (Authorization) GoString() string { return "pluginworkloadidentity.Authorization{sealed}" }

func (Authorization) MarshalJSON() ([]byte, error) { return nil, errSerializeSealed }

func authorizationMatchesRequest(authorization pluginruntimeauth.Authorization, request Request,
	requestID string, now time.Time) bool {
	// The tenant is bound through workloadRequestID; the license customer is bound to the installation.
	return authorization.RequestID == requestID && authorization.CustomerID != uuid.Nil &&
		authorization.Action == request.Action && authorization.InstallationID == request.InstallationID &&
		authorization.AuthorizationID != uuid.Nil && authorization.TokenID != uuid.Nil &&
		authorization.IdentityGeneration > 0 && authorization.PluginID == request.PluginID &&
		authorization.PluginVersion != "" && authorization.ManifestSHA256 == request.ManifestSHA256 &&
		authorization.VerificationID == request.VerificationID && authorization.AttestationID == request.AttestationID &&
		authorization.AttestationRevision == request.AttestationRevision &&
		authorization.ApprovalReceiptID != uuid.Nil && authorization.ApprovalRevision == request.ApprovalRevision &&
		authorization.CapabilityKind == request.CapabilityKind && authorization.CapabilityCode == request.CapabilityCode &&
		authorization.EvaluatedAt.Equal(authorization.EvaluatedAt.UTC().Truncate(time.Second)) &&
		authorization.ExpiresAt.Equal(authorization.ExpiresAt.UTC().Truncate(time.Second)) &&
		!authorization.EvaluatedAt.After(now) && now.Before(authorization.ExpiresAt) &&
		!authorization.ExpiresAt.After(authorization.EvaluatedAt.Add(time.Minute))
}

func validRequest(request Request, now time.Time) bool {
	return request.TenantID != uuid.Nil && request.InstallationID != uuid.Nil &&
		request.InvocationID != uuid.Nil && request.InvocationID.Version() == 7 && request.InvocationID.Variant() == uuid.RFC4122 &&
		len(request.PluginID) >= 3 && len(request.PluginID) <= 128 && pluginSlugPattern.MatchString(request.PluginID) &&
		validCapability(request.CapabilityKind, request.CapabilityCode) && len(request.Action) <= 128 &&
		permissionPattern.MatchString(request.Action) && len(request.ServiceIdentityJSON) > 0 &&
		len(request.ServiceIdentityJSON) <= maximumIdentityBytes && hexDigestPattern.MatchString(request.ManifestSHA256) &&
		request.VerificationID != uuid.Nil && request.AttestationID != uuid.Nil && request.AttestationRevision > 0 &&
		request.ApprovalRevision > 0 && request.RequestedAt.Location() == time.UTC &&
		request.RequestedAt.Equal(request.RequestedAt.Truncate(time.Second)) &&
		!request.RequestedAt.Before(now.Add(-5*time.Minute)) && !request.RequestedAt.After(now.Add(time.Minute))
}

func validCapability(kind, code string) bool {
	if len(code) == 0 || len(code) > 160 {
		return false
	}
	if kind == "event" {
		return eventPattern.MatchString(code)
	}
	return (kind == "scope" || kind == "webhook") && permissionPattern.MatchString(code)
}

func workloadRequestID(request Request) string {
	digest := sha256.New()
	for _, field := range []string{
		workloadActionDomain,
		request.TenantID.String(),
		request.InstallationID.String(),
		request.InvocationID.String(),
		request.PluginID,
		request.CapabilityKind,
		request.CapabilityCode,
		request.Action,
		request.RequestedAt.UTC().Format(time.RFC3339),
	} {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(field)))
		_, _ = digest.Write(size[:])
		_, _ = digest.Write([]byte(field))
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func mapDependencyError(err error) error {
	if errors.Is(err, pluginruntimeprovider.ErrRateLimited) || errors.Is(err, pluginruntimeauth.ErrRateLimited) {
		return ErrRateLimited
	}
	if errors.Is(err, pluginruntimeprovider.ErrUnavailable) || errors.Is(err, pluginruntimeauth.ErrTrustUnavailable) {
		return ErrUnavailable
	}
	return ErrDenied
}

func nilDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

var _ json.Marshaler = Authorization{}
