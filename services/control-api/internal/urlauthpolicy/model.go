package urlauthpolicy

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	AlgorithmHMACSHA256 = "hmac-sha256"
	SchemaVersion       = "cdnca.edge.urlauth/v1"
	LegacyTypeA         = "cdnfly_type_a_md5"
	LegacyTypeB         = "cdnfly_type_b_md5"
	PermissionRead      = "url_auth_policies.read"
	PermissionManage    = "url_auth_policies.manage"
	CredentialSession   = "session"
	CredentialAPIKey    = "api_key"
)

var (
	ErrInvalidInput          = errors.New("invalid URL auth policy input")
	ErrPermissionDenied      = errors.New("URL auth policy permission denied")
	ErrNotFound              = errors.New("URL auth policy not found")
	ErrConflict              = errors.New("URL auth policy conflict")
	ErrRevisionConflict      = errors.New("URL auth policy revision conflict")
	ErrIdempotencyConflict   = errors.New("URL auth policy idempotency conflict")
	ErrKeyNotRevocable       = errors.New("URL auth policy key is not revocable")
	ErrEncryptionUnavailable = errors.New("URL auth policy encryption unavailable")
	ErrUnauthenticated       = errors.New("URL auth policy authentication required")
	ErrUnavailable           = errors.New("URL auth policy dependency unavailable")
)

type Actor struct {
	UserID         uuid.UUID
	ScopeID        uuid.UUID
	ScopeKind      string
	credentialKind string
	credentialID   uuid.UUID
	rawCredential  string
	tenantID       *uuid.UUID
}

func (Actor) String() string   { return "urlauthpolicy.Actor{credential:redacted}" }
func (Actor) GoString() string { return "urlauthpolicy.Actor{credential:redacted}" }
func (Actor) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("urlauthpolicy.Actor{credential:redacted}"))
}

func (actor Actor) WithCredential(kind string, credentialID uuid.UUID, raw string, tenantID *uuid.UUID) Actor {
	actor.credentialKind, actor.credentialID, actor.rawCredential = kind, credentialID, raw
	if tenantID != nil {
		value := *tenantID
		actor.tenantID = &value
	}
	return actor
}

// TxAuthorizer rechecks the authenticated credential and current RBAC facts in
// the caller-owned business transaction.
type TxAuthorizer interface {
	Authorize(context.Context, pgx.Tx, Actor, uuid.UUID, string) (uuid.UUID, error)
}

type OwnerReference struct {
	ID          uuid.UUID `json:"id"`
	DisplayName string    `json:"display_name"`
}

type SiteReference struct {
	ID     uuid.UUID `json:"id"`
	Domain string    `json:"domain"`
}

type KeyMetadata struct {
	KeyID     string     `json:"key_id"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

type Policy struct {
	ID                      uuid.UUID       `json:"id"`
	ScopeID                 uuid.UUID       `json:"scope_id"`
	Owner                   *OwnerReference `json:"owner,omitempty"`
	Site                    SiteReference   `json:"site"`
	Name                    string          `json:"name"`
	Enabled                 bool            `json:"enabled"`
	Algorithm               string          `json:"algorithm"`
	MigrationMarker         *string         `json:"migration_marker,omitempty"`
	SignatureParameter      string          `json:"signature_parameter"`
	ExpirationParameter     string          `json:"expiration_parameter"`
	KeyIDParameter          string          `json:"key_id_parameter"`
	BindClientIP            bool            `json:"bind_client_ip"`
	MaxClockSkewSeconds     uint32          `json:"max_clock_skew_seconds"`
	MaxValiditySeconds      uint32          `json:"max_validity_seconds"`
	MaxSignatureUses        uint32          `json:"max_signature_uses"`
	ExcludedQueryParameters []string        `json:"excluded_query_parameters"`
	TrustedProxyCIDRs       []string        `json:"trusted_proxy_cidrs"`
	CurrentKey              KeyMetadata     `json:"current_key"`
	PreviousKey             *KeyMetadata    `json:"previous_key,omitempty"`
	Revision                int64           `json:"version"`
	CreatedAt               time.Time       `json:"created_at"`
	UpdatedAt               time.Time       `json:"updated_at"`
	tenantID                uuid.UUID
	ownerID                 uuid.UUID
}

type PolicyFields struct {
	SiteID                  uuid.UUID `json:"site_id"`
	Name                    string    `json:"name"`
	Enabled                 bool      `json:"enabled"`
	Algorithm               string    `json:"algorithm"`
	SignatureParameter      string    `json:"signature_parameter"`
	ExpirationParameter     string    `json:"expiration_parameter"`
	KeyIDParameter          string    `json:"key_id_parameter"`
	BindClientIP            bool      `json:"bind_client_ip"`
	MaxClockSkewSeconds     uint32    `json:"max_clock_skew_seconds"`
	MaxValiditySeconds      uint32    `json:"max_validity_seconds"`
	MaxSignatureUses        uint32    `json:"max_signature_uses"`
	ExcludedQueryParameters []string  `json:"excluded_query_parameters"`
	TrustedProxyCIDRs       []string  `json:"trusted_proxy_cidrs"`
}

type CreateRequest struct {
	TargetScopeID  uuid.UUID
	OwnerUserID    uuid.UUID
	Fields         PolicyFields
	IdempotencyKey string
	RequestID      string
}

type UpdateRequest struct {
	ID               uuid.UUID
	ExpectedRevision int64
	Fields           PolicyFields
	IdempotencyKey   string
	RequestID        string
}

type StateRequest struct {
	ID               uuid.UUID
	ExpectedRevision int64
	Enabled          bool
	IdempotencyKey   string
	RequestID        string
}

type RotateRequest struct {
	ID               uuid.UUID
	ExpectedRevision int64
	IdempotencyKey   string
	RequestID        string
}

type RevokeRequest struct {
	ID               uuid.UUID
	KeyID            string
	ExpectedRevision int64
	IdempotencyKey   string
	RequestID        string
}

type ListFilter struct {
	Page   int
	Limit  int
	Status string
	Name   string
	SiteID uuid.UUID
}

type ListResult struct {
	Items []Policy `json:"items"`
	Total int64    `json:"total"`
	Page  int      `json:"page"`
	Limit int      `json:"limit"`
}

type SecretWriteResult struct {
	Policy   Policy `json:"policy"`
	Secret   string `json:"secret,omitempty"`
	Replayed bool   `json:"replayed"`
}

type WriteResult struct {
	Policy   Policy `json:"policy"`
	Replayed bool   `json:"replayed"`
}

type SnapshotResult struct {
	PolicyID uuid.UUID  `json:"policy_id"`
	Revision int64      `json:"version"`
	SHA256   string     `json:"sha256"`
	Document EdgePolicy `json:"document"`
}

type EdgePolicy struct {
	SchemaVersion           string   `json:"schema_version"`
	PolicyVersion           uint64   `json:"policy_version"`
	TenantID                string   `json:"tenant_id"`
	SiteID                  string   `json:"site_id"`
	Algorithm               string   `json:"algorithm"`
	SignatureParameter      string   `json:"signature_parameter"`
	ExpirationParameter     string   `json:"expiration_parameter"`
	KeyIDParameter          string   `json:"key_id_parameter"`
	BindClientIP            bool     `json:"bind_client_ip"`
	MaxClockSkewSeconds     uint32   `json:"max_clock_skew_seconds"`
	MaxValiditySeconds      uint32   `json:"max_validity_seconds"`
	MaxSignatureUses        uint32   `json:"max_signature_uses"`
	ExcludedQueryParameters []string `json:"excluded_query_parameters"`
	TrustedProxies          []string `json:"trusted_proxies"`
	CurrentKey              EdgeKey  `json:"current_key"`
	PreviousKey             *EdgeKey `json:"previous_key,omitempty"`
}

type EdgeKey struct {
	KeyID   string `json:"key_id"`
	KeyFile string `json:"key_file"`
}
