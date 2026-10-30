package authprincipal

import (
	"context"
	"errors"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type CredentialKind string

const (
	CredentialKindSession CredentialKind = "session"
	CredentialKindAPIKey  CredentialKind = "api_key"

	ScopeKindPlatform = "platform"
	ScopeKindTenant   = "tenant"

	IdentityDomainCustomerControl = "customer_control"
	scopeLockPrefixV1             = "iam-authz:v1:"
)

var (
	ErrInvalidPrincipal = errors.New("invalid authenticated principal")
	ErrPermissionDenied = errors.New("transactional authorization permission denied")
	ErrUnavailable      = errors.New("transactional authorization unavailable")
	permissionPattern   = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
)

// SubjectV1 identifies the user and control-plane scope carried by a verified
// principal. It does not contain role or permission snapshots.
type SubjectV1 struct {
	userID         uuid.UUID
	scopeID        uuid.UUID
	tenantID       uuid.UUID
	hasTenant      bool
	scopeKind      string
	identityDomain string
}

func NewSubjectV1(
	userID uuid.UUID,
	scopeID uuid.UUID,
	tenantID *uuid.UUID,
	scopeKind string,
	identityDomain string,
) (SubjectV1, error) {
	subject := SubjectV1{
		userID: userID, scopeID: scopeID, scopeKind: scopeKind, identityDomain: identityDomain,
	}
	if tenantID != nil {
		subject.tenantID = *tenantID
		subject.hasTenant = true
	}
	if !subject.IsValid() {
		return SubjectV1{}, ErrInvalidPrincipal
	}
	return subject, nil
}

func (subject SubjectV1) UserID() uuid.UUID           { return subject.userID }
func (subject SubjectV1) ScopeID() uuid.UUID          { return subject.scopeID }
func (subject SubjectV1) ScopeKind() string           { return subject.scopeKind }
func (subject SubjectV1) IdentityDomain() string      { return subject.identityDomain }
func (subject SubjectV1) TenantID() (uuid.UUID, bool) { return subject.tenantID, subject.hasTenant }

func (subject SubjectV1) IsValid() bool {
	if subject.userID == uuid.Nil || subject.scopeID == uuid.Nil ||
		subject.identityDomain != IdentityDomainCustomerControl {
		return false
	}
	switch subject.scopeKind {
	case ScopeKindPlatform:
		return !subject.hasTenant && subject.tenantID == uuid.Nil
	case ScopeKindTenant:
		return subject.hasTenant && subject.tenantID != uuid.Nil
	default:
		return false
	}
}

// CredentialReferenceV1 is an opaque reference produced only after a verifier
// in this package authenticates a session or API key.
type CredentialReferenceV1 struct {
	kind       CredentialKind
	id         uuid.UUID
	generation int64
	issuedAt   time.Time
	notAfter   time.Time
}

func newSession(id uuid.UUID, issuedAt, notAfter time.Time) (CredentialReferenceV1, error) {
	reference := CredentialReferenceV1{
		kind: CredentialKindSession, id: id, issuedAt: issuedAt.UTC(), notAfter: notAfter.UTC(),
	}
	if !reference.IsValid() {
		return CredentialReferenceV1{}, ErrInvalidPrincipal
	}
	return reference, nil
}

func newAPIKey(id uuid.UUID, generation int64, issuedAt, notAfter time.Time) (CredentialReferenceV1, error) {
	reference := CredentialReferenceV1{
		kind: CredentialKindAPIKey, id: id, generation: generation,
		issuedAt: issuedAt.UTC(), notAfter: canonicalOptionalTime(notAfter),
	}
	if !reference.IsValid() {
		return CredentialReferenceV1{}, ErrInvalidPrincipal
	}
	return reference, nil
}

func (reference CredentialReferenceV1) Kind() CredentialKind { return reference.kind }
func (reference CredentialReferenceV1) ID() uuid.UUID        { return reference.id }
func (reference CredentialReferenceV1) Generation() int64    { return reference.generation }
func (reference CredentialReferenceV1) IssuedAt() time.Time  { return reference.issuedAt }
func (reference CredentialReferenceV1) NotAfter() time.Time  { return reference.notAfter }

func (reference CredentialReferenceV1) IsValid() bool {
	if reference.id == uuid.Nil || reference.issuedAt.IsZero() {
		return false
	}
	switch reference.kind {
	case CredentialKindSession:
		return reference.generation == 0 && !reference.notAfter.IsZero() &&
			reference.notAfter.After(reference.issuedAt)
	case CredentialKindAPIKey:
		return reference.generation >= 1 &&
			(reference.notAfter.IsZero() || reference.notAfter.After(reference.issuedAt))
	default:
		return false
	}
}

func (reference CredentialReferenceV1) String() string {
	kind := reference.kind
	if kind != CredentialKindSession && kind != CredentialKindAPIKey {
		kind = "invalid"
	}
	return "authprincipal.CredentialReferenceV1{kind:" + string(kind) + ",credential:redacted}"
}

func (reference CredentialReferenceV1) GoString() string { return reference.String() }

// AuthenticatedPrincipalV1 is an opaque result produced only by a session or
// API-key verifier in this package. Callers cannot construct a valid value.
type AuthenticatedPrincipalV1 struct {
	subject    SubjectV1
	credential CredentialReferenceV1
}

func newAuthenticatedPrincipalV1(
	subject SubjectV1,
	credential CredentialReferenceV1,
) (AuthenticatedPrincipalV1, error) {
	principal := AuthenticatedPrincipalV1{subject: subject, credential: credential}
	if !principal.IsValid() {
		return AuthenticatedPrincipalV1{}, ErrInvalidPrincipal
	}
	return principal, nil
}

func (principal AuthenticatedPrincipalV1) Subject() SubjectV1 { return principal.subject }
func (principal AuthenticatedPrincipalV1) Credential() CredentialReferenceV1 {
	return principal.credential
}

func (principal AuthenticatedPrincipalV1) IsValid() bool {
	return principal.subject.IsValid() && principal.credential.IsValid()
}

func (principal AuthenticatedPrincipalV1) String() string {
	return "authprincipal.AuthenticatedPrincipalV1{credential:redacted}"
}

func (principal AuthenticatedPrincipalV1) GoString() string { return principal.String() }

// AuthorizedScopeV1 is an opaque authorization result. A valid value can only
// be returned by a TransactionalAuthorizerV1 implementation in this package.
type AuthorizedScopeV1 struct {
	userID               uuid.UUID
	scopeID              uuid.UUID
	tenantID             uuid.UUID
	credentialKind       CredentialKind
	credentialID         uuid.UUID
	credentialGeneration int64
}

func newAuthorizedScopeV1(principal AuthenticatedPrincipalV1, tenantID uuid.UUID) (AuthorizedScopeV1, error) {
	if !principal.IsValid() || tenantID == uuid.Nil {
		return AuthorizedScopeV1{}, ErrInvalidPrincipal
	}
	subject := principal.Subject()
	if subject.ScopeKind() == ScopeKindTenant {
		subjectTenantID, ok := subject.TenantID()
		if !ok || subjectTenantID != tenantID {
			return AuthorizedScopeV1{}, ErrInvalidPrincipal
		}
	}
	credential := principal.Credential()
	result := AuthorizedScopeV1{
		userID: subject.UserID(), scopeID: subject.ScopeID(), tenantID: tenantID,
		credentialKind: credential.Kind(), credentialID: credential.ID(),
		credentialGeneration: credential.Generation(),
	}
	if !result.IsValid() {
		return AuthorizedScopeV1{}, ErrInvalidPrincipal
	}
	return result, nil
}

func (scope AuthorizedScopeV1) UserID() uuid.UUID              { return scope.userID }
func (scope AuthorizedScopeV1) ScopeID() uuid.UUID             { return scope.scopeID }
func (scope AuthorizedScopeV1) TenantID() uuid.UUID            { return scope.tenantID }
func (scope AuthorizedScopeV1) CredentialKind() CredentialKind { return scope.credentialKind }
func (scope AuthorizedScopeV1) CredentialID() uuid.UUID        { return scope.credentialID }
func (scope AuthorizedScopeV1) CredentialGeneration() int64    { return scope.credentialGeneration }

func (scope AuthorizedScopeV1) IsValid() bool {
	if scope.userID == uuid.Nil || scope.scopeID == uuid.Nil || scope.tenantID == uuid.Nil || scope.credentialID == uuid.Nil {
		return false
	}
	return scope.credentialKind == CredentialKindSession && scope.credentialGeneration == 0 ||
		scope.credentialKind == CredentialKindAPIKey && scope.credentialGeneration >= 1
}

func (scope AuthorizedScopeV1) String() string {
	return "authprincipal.AuthorizedScopeV1{credential:redacted}"
}

func (scope AuthorizedScopeV1) GoString() string { return scope.String() }

func ValidPermission(permission string) bool {
	return permissionPattern.MatchString(permission)
}

func ScopeLockNameV1(scopeID uuid.UUID) (string, error) {
	if scopeID == uuid.Nil {
		return "", ErrInvalidPrincipal
	}
	return scopeLockPrefixV1 + scopeID.String(), nil
}

// TransactionalAuthorizerV1 must acquire the shared iam-authz:v1 scope lock
// in its first SQL statement, then recheck the server-authenticated credential,
// active account, membership, and current RBAC facts in tx. Authorization must
// happen before idempotency or business access, must reject non-canonical
// permissions, and must not trust client-supplied credential IDs or cached grants.
// Only implementations in this package can construct a valid AuthorizedScopeV1.
type TransactionalAuthorizerV1 interface {
	AuthorizeTx(
		context.Context,
		pgx.Tx,
		AuthenticatedPrincipalV1,
		uuid.UUID,
		string,
	) (AuthorizedScopeV1, error)
}

func canonicalOptionalTime(value time.Time) time.Time {
	if value.IsZero() {
		return time.Time{}
	}
	return value.UTC()
}
