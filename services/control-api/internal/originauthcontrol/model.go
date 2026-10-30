package originauthcontrol

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	PermissionRead   = "origin_auth.read"
	PermissionManage = "origin_auth.manage"

	ProviderS3  = "s3"
	ProviderOSS = "oss"
	ProviderCOS = "cos"

	AlgorithmS3  = "aws4-hmac-sha256"
	AlgorithmOSS = "oss4-hmac-sha256"
	AlgorithmCOS = "cos-hmac-sha1"

	StatusPending  = "pending"
	StatusVerified = "verified"
	StatusDisabled = "disabled"
	StatusDeleted  = "deleted"

	publicationSchema = "cdnca.control.originauth-publication/v1"
)

var (
	ErrUnauthenticated        = errors.New("origin authentication required")
	ErrInvalidInput           = errors.New("invalid origin authentication input")
	ErrValidation             = errors.New("origin authentication validation failed")
	ErrPermissionDenied       = errors.New("origin authentication permission denied")
	ErrNotFound               = errors.New("origin authentication resource not found")
	ErrConflict               = errors.New("origin authentication resource conflict")
	ErrSiteLocked             = errors.New("site is locked by a platform administrator")
	ErrRevisionConflict       = errors.New("origin authentication revision conflict")
	ErrIdempotencyConflict    = errors.New("origin authentication idempotency conflict")
	ErrCredentialUnverified   = errors.New("origin authentication credential is not verified")
	ErrVerificationRejected   = errors.New("origin authentication credential verification rejected")
	ErrVerifierUnavailable    = errors.New("origin authentication credential verifier unavailable")
	ErrEncryptionUnavailable  = errors.New("origin authentication encryption unavailable")
	ErrEntitlementDenied      = errors.New("origin authentication entitlement denied")
	ErrEntitlementUnavailable = errors.New("origin authentication entitlement unavailable")
	ErrUnavailable            = errors.New("origin authentication storage unavailable")
)

type Actor struct {
	UserID      uuid.UUID
	ScopeID     uuid.UUID
	ScopeKind   string
	Permissions []string
	sessionID   uuid.UUID
	tenantID    *uuid.UUID
	rawSession  string
}

type WriteMetadata struct {
	IdempotencyKey string
	RequestID      string
	TraceID        string
}

type CredentialSecret struct {
	AccessKeyID     string    `json:"access_key_id"`
	SecretAccessKey string    `json:"secret_access_key"`
	SessionToken    string    `json:"session_token,omitempty"`
	NotBefore       time.Time `json:"not_before"`
	ExpiresAt       time.Time `json:"expires_at"`
}

type Credential struct {
	ID          uuid.UUID  `json:"id"`
	TenantScope uuid.UUID  `json:"tenant_scope_id"`
	Provider    string     `json:"provider"`
	Name        string     `json:"name"`
	Status      string     `json:"status"`
	Revision    int64      `json:"revision"`
	RevisionRef uuid.UUID  `json:"revision_ref"`
	NotBefore   time.Time  `json:"not_before"`
	ExpiresAt   time.Time  `json:"expires_at"`
	VerifiedAt  *time.Time `json:"verified_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

type CreateCredentialRequest struct {
	TargetScopeID uuid.UUID
	Provider      string
	Name          string
	Secret        CredentialSecret
	WriteMetadata
}

type ReplaceCredentialRequest struct {
	TargetScopeID    uuid.UUID
	CredentialID     uuid.UUID
	ExpectedRevision int64
	Secret           CredentialSecret
	WriteMetadata
}

type CredentialMutationRequest struct {
	TargetScopeID    uuid.UUID
	CredentialID     uuid.UUID
	ExpectedRevision int64
	WriteMetadata
}

type CredentialListFilter struct {
	TargetScopeID uuid.UUID
	Provider      string
	Status        string
	Limit         int
	Cursor        string
}

type CredentialList struct {
	Items      []Credential `json:"items"`
	NextCursor string       `json:"next_cursor,omitempty"`
}

type CredentialWriteResult struct {
	Credential Credential
	Replayed   bool
}

type CredentialReference struct {
	CredentialID uuid.UUID `json:"credential_id"`
	Revision     int64     `json:"revision"`
}

type RuleConfig struct {
	Provider              string               `json:"provider"`
	Algorithm             string               `json:"algorithm"`
	Endpoint              string               `json:"endpoint"`
	Bucket                string               `json:"bucket"`
	PathPrefix            string               `json:"path_prefix"`
	Region                string               `json:"region"`
	Service               string               `json:"service"`
	SignatureTTLSeconds   int                  `json:"signature_ttl_seconds"`
	EgressPolicyReference string               `json:"egress_policy_reference,omitempty"`
	CurrentCredential     CredentialReference  `json:"current_credential"`
	PreviousCredential    *CredentialReference `json:"previous_credential,omitempty"`
	ActivateCurrentAt     *time.Time           `json:"activate_current_at,omitempty"`
}

type Rule struct {
	ID             uuid.UUID `json:"id"`
	TenantScopeID  uuid.UUID `json:"tenant_scope_id"`
	SiteID         uuid.UUID `json:"site_id"`
	SourcePosition int       `json:"source_position"`
	RuleConfig
	Enabled   bool      `json:"enabled"`
	Deleted   bool      `json:"deleted"`
	Revision  int64     `json:"revision"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type CreateRuleRequest struct {
	TargetScopeID  uuid.UUID
	SiteID         uuid.UUID
	SourcePosition int
	Config         RuleConfig
	Enabled        bool
	WriteMetadata
}

type UpdateRuleRequest struct {
	TargetScopeID    uuid.UUID
	RuleID           uuid.UUID
	ExpectedRevision int64
	Config           RuleConfig
	WriteMetadata
}

type RuleMutationRequest struct {
	TargetScopeID    uuid.UUID
	RuleID           uuid.UUID
	ExpectedRevision int64
	WriteMetadata
}

type RotateRuleRequest struct {
	TargetScopeID     uuid.UUID
	RuleID            uuid.UUID
	ExpectedRevision  int64
	CurrentCredential CredentialReference
	ActivateCurrentAt time.Time
	WriteMetadata
}

type RuleListFilter struct {
	TargetScopeID uuid.UUID
	SiteID        uuid.UUID
	Enabled       *bool
	Limit         int
	Cursor        string
}

type RuleList struct {
	Items      []Rule `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
}

type RuleWriteResult struct {
	Rule     Rule
	Replayed bool
}

type PublicationRule struct {
	RuleID                        uuid.UUID  `json:"rule_id"`
	SiteID                        uuid.UUID  `json:"site_id"`
	SourcePosition                int        `json:"source_position"`
	Provider                      string     `json:"provider"`
	Algorithm                     string     `json:"algorithm"`
	Endpoint                      string     `json:"endpoint"`
	Bucket                        string     `json:"bucket"`
	PathPrefix                    string     `json:"path_prefix"`
	Region                        string     `json:"region"`
	Service                       string     `json:"service"`
	SignatureTTLSeconds           int        `json:"signature_ttl_seconds"`
	CurrentCredentialRevisionRef  uuid.UUID  `json:"current_credential_revision_ref"`
	PreviousCredentialRevisionRef *uuid.UUID `json:"previous_credential_revision_ref,omitempty"`
	ActivateCurrentAtUnix         int64      `json:"activate_current_at_unix"`
}

type PublicationSnapshot struct {
	SchemaVersion       string            `json:"schema_version"`
	TenantScopeID       uuid.UUID         `json:"tenant_scope_id"`
	PublicationRevision int64             `json:"publication_revision"`
	Rules               []PublicationRule `json:"rules"`
}

type Publication struct {
	ID            uuid.UUID           `json:"id"`
	TenantScopeID uuid.UUID           `json:"tenant_scope_id"`
	Revision      int64               `json:"revision"`
	SnapshotHash  string              `json:"snapshot_hash"`
	PreviousHash  string              `json:"previous_hash,omitempty"`
	Snapshot      PublicationSnapshot `json:"snapshot"`
	CreatedAt     time.Time           `json:"created_at"`
}

type CreatePublicationRequest struct {
	TargetScopeID    uuid.UUID
	ExpectedRevision int64
	WriteMetadata
}

type PublicationWriteResult struct {
	Publication Publication
	Replayed    bool
}

type VerificationRequest struct {
	Provider   string
	Credential CredentialSecret
}

type CredentialVerifier interface {
	Verify(context.Context, VerificationRequest) error
}

type CredentialVerifierFunc func(context.Context, VerificationRequest) error

func (function CredentialVerifierFunc) Verify(ctx context.Context, request VerificationRequest) error {
	return function(ctx, request)
}

type EntitlementCheck struct {
	AuditScopeID uuid.UUID
	ActorUserID  uuid.UUID
	ResourceID   uuid.UUID
	RequestID    string
	Operation    string
}

type EntitlementGate interface {
	Check(context.Context, pgx.Tx, EntitlementCheck) error
}
