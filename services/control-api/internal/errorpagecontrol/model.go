package errorpagecontrol

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	SchemaV1                     = "cdnca.error-pages/v1"
	MaxEdgeResourceBytes         = int64(1 << 20)
	MaxEdgePolicyBytes           = int64(8 << 20)
	MaxEdgeRulesPerScope         = 128
	MaxPublicationSites          = 256
	MaxPageSize                  = 100
	StatusInitiated              = "initiated"
	StatusStaged                 = "staged"
	StatusScanFailed             = "scan_failed"
	StatusFinalizing             = "finalizing"
	StatusReady                  = "ready"
	StatusRejected               = "rejected"
	StatusDeletePending          = "delete_pending"
	StatusDeleted                = "deleted"
	StatusOrphaned               = "orphaned"
	CategoryOriginResponse       = "origin_response"
	CategoryEdgeRoute            = "edge_route"
	CategoryEdgeConnect          = "edge_connect"
	CategoryNoHost               = "no_host"
	CategoryUnknownSite          = "unknown_site"
	ScopeGlobal                  = "global"
	ScopeSite                    = "site"
	MatchExact                   = "exact"
	MatchRange                   = "range"
	permissionRead               = "error_pages.read"
	permissionManage             = "error_pages.manage"
	operationAssetInitiate       = "error_page.asset.initiate"
	operationAssetUpload         = "error_page.asset.upload"
	operationAssetFinalize       = "error_page.asset.finalize"
	operationAssetReconcile      = "error_page.asset.reconcile_finalize"
	operationAssetDelete         = "error_page.asset.delete"
	operationRuleCreate          = "error_page.rule.create"
	operationRuleUpdate          = "error_page.rule.update"
	operationRuleEnable          = "error_page.rule.enable"
	operationRuleDisable         = "error_page.rule.disable"
	operationRuleDelete          = "error_page.rule.delete"
	CredentialKindSession        = "session"
	CredentialKindAPIKey         = "api_key"
	entitlementPrincipalUser     = "user"
	entitlementPrincipalSystem   = "system"
	errorPageReconcilerPrincipal = "error-page-reconciler"
	defaultReconcilePageSize     = 100
)

var (
	ErrInvalidInput        = errors.New("invalid error page control input")
	ErrInvalidCredential   = errors.New("invalid error page control credential")
	ErrUnauthenticated     = errors.New("error page control authentication required")
	ErrInvalidStore        = errors.New("invalid error page control dependencies")
	ErrPermissionDenied    = errors.New("error page control permission denied")
	ErrNotFound            = errors.New("error page control resource not found")
	ErrConflict            = errors.New("error page control conflict")
	ErrRevisionConflict    = errors.New("error page control revision conflict")
	ErrIdempotencyConflict = errors.New("error page control idempotency conflict")
	ErrQuotaExceeded       = errors.New("error page control quota exceeded")
	ErrEntitlementDenied   = errors.New("error page control entitlement denied")
	ErrUnsafeContent       = errors.New("unsafe error page content")
	ErrScanRejected        = errors.New("error page content rejected by scanner")
	ErrUnavailable         = errors.New("error page control dependency unavailable")
	ErrObjectNotFound      = errors.New("error page object not found")
)

type CredentialReference struct {
	Kind string
	ID   uuid.UUID
}

type Actor struct {
	UserID     uuid.UUID
	ScopeID    uuid.UUID
	ScopeKind  string
	Credential CredentialReference

	rawSession string
	tenantID   *uuid.UUID
}

const redactedActor = "errorpagecontrol.Actor{credential:redacted}"

func (Actor) Format(state fmt.State, _ rune) { _, _ = state.Write([]byte(redactedActor)) }
func (Actor) String() string                 { return redactedActor }
func (Actor) GoString() string               { return redactedActor }
func (Actor) MarshalJSON() ([]byte, error) {
	return []byte(`"errorpagecontrol.Actor{credential:redacted}"`), nil
}

type WriteMetadata struct {
	IdempotencyKey string
	RequestID      string
	TraceID        string
}

type Asset struct {
	ID       uuid.UUID  `json:"id"`
	ScopeID  uuid.UUID  `json:"scope_id"`
	TenantID *uuid.UUID `json:"tenant_id,omitempty"`
	// Name is the display name given at upload (migration 509); "" for an
	// asset uploaded before it.
	Name       string     `json:"name"`
	MIMEType   string     `json:"mime_type"`
	SizeBytes  int64      `json:"size_bytes"`
	SHA256     string     `json:"sha256"`
	Status     string     `json:"status"`
	ScanStatus string     `json:"scan_status"`
	Revision   int64      `json:"revision"`
	CreatedBy  uuid.UUID  `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	DeletedAt  *time.Time `json:"deleted_at,omitempty"`

	stagingObjectKey string
	storageObjectKey string
	objectState      string
}

type AssetQuota struct {
	MaxAssetBytes int64
	MaxAssets     int64
	MaxTotalBytes int64
}

type AssetTarget struct {
	ScopeID uuid.UUID
}

type InitiateAssetRequest struct {
	Target AssetTarget
	// Name is the asset's display name (optional, ValidAssetName).
	Name   string
	MIME   string
	Size   int64
	SHA256 string
	WriteMetadata
}

type UploadAssetRequest struct {
	AssetID       uuid.UUID
	MIMEType      string
	ContentLength int64
	Body          io.Reader
	WriteMetadata
}

type FinalizeAssetRequest struct {
	AssetID uuid.UUID
	WriteMetadata
}

type DeleteAssetRequest struct {
	AssetID          uuid.UUID
	ExpectedRevision int64
	WriteMetadata
}

type AssetPageRequest struct {
	TargetScopeID uuid.UUID
	Limit         int
	Cursor        string
	Status        string
}

type AssetPage struct {
	Items      []Asset `json:"items"`
	NextCursor string  `json:"next_cursor,omitempty"`
}

type RuleTarget struct {
	Kind    string     `json:"kind"`
	ScopeID uuid.UUID  `json:"scope_id"`
	SiteID  *uuid.UUID `json:"site_id,omitempty"`
}

type StatusSelector struct {
	Kind string `json:"kind"`
	From int    `json:"from"`
	To   int    `json:"to"`
}

type RuleFields struct {
	Category string         `json:"category"`
	Match    StatusSelector `json:"match"`
	AssetID  uuid.UUID      `json:"asset_id"`
	Enabled  bool           `json:"enabled"`
}

type Rule struct {
	ID        uuid.UUID  `json:"id"`
	Target    RuleTarget `json:"target"`
	TenantID  *uuid.UUID `json:"tenant_id,omitempty"`
	Fields    RuleFields `json:"fields"`
	Priority  int        `json:"priority"`
	Revision  int64      `json:"revision"`
	Deleted   bool       `json:"deleted"`
	CreatedBy uuid.UUID  `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

type CreateRuleRequest struct {
	Target RuleTarget
	Fields RuleFields
	WriteMetadata
}

type UpdateRuleRequest struct {
	RuleID           uuid.UUID
	ExpectedRevision int64
	Fields           RuleFields
	WriteMetadata
}

type ChangeRuleStateRequest struct {
	RuleID           uuid.UUID
	ExpectedRevision int64
	WriteMetadata
}

type RulePageRequest struct {
	TargetScopeID uuid.UUID
	SiteID        *uuid.UUID
	Limit         int
	Cursor        string
	Enabled       *bool
}

type RulePage struct {
	Items      []Rule `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
}

type WriteResult[T any] struct {
	Value    T    `json:"value"`
	Replayed bool `json:"replayed"`
}

type Snapshot struct {
	Schema   string         `json:"schema"`
	Version  string         `json:"version"`
	Revision int64          `json:"revision"`
	Global   SnapshotScope  `json:"global"`
	Sites    []SnapshotSite `json:"sites"`
	// ThemePackageSHA256 pins the theme active when this revision was made
	// (ADR 0007 §7.3): its default pages fill the global categories no
	// platform rule covers. Empty before any theme activation.
	ThemePackageSHA256 string `json:"theme_package_sha256,omitempty"`
	// Slots are the platform's bound error page slots that replace a theme
	// default page (errpage-content); omitted when none is bound, so earlier
	// revisions keep their canonical bytes.
	Slots []SnapshotSlot `json:"slots,omitempty"`
}

// SnapshotSlot is a platform slot binding pinned in a publication revision:
// the theme default page (category, status) it replaces.
//
// errpage-3: a slot the node answers itself (slotOwnPages) and a region /
// node override (Region / NodeID, at most one) are pinned the same way; they
// reach the node as node pages (ProductionSnapshotDocument.Slots), not as a
// replaced theme rule.
type SnapshotSlot struct {
	Key      string           `json:"key"`
	Category string           `json:"category"`
	Status   int              `json:"status"`
	Resource SnapshotResource `json:"resource"`
	Region   string           `json:"region,omitempty"`
	NodeID   string           `json:"node_id,omitempty"`
}

type PublicationSnapshot struct {
	Policy    Snapshot  `json:"policy"`
	SHA256    string    `json:"snapshot_sha256"`
	CreatedAt time.Time `json:"created_at"`
}

type SnapshotScope struct {
	Rules []SnapshotRule `json:"rules"`
}

type SnapshotSite struct {
	SiteKey string         `json:"site_key"`
	Rules   []SnapshotRule `json:"rules"`
}

type SnapshotRule struct {
	ID       string           `json:"id"`
	Category string           `json:"category"`
	Match    SnapshotMatch    `json:"match"`
	Resource SnapshotResource `json:"resource"`
}

type SnapshotMatch struct {
	Codes  []int           `json:"codes,omitempty"`
	Ranges []SnapshotRange `json:"ranges,omitempty"`
}

type SnapshotRange struct {
	From int `json:"from"`
	To   int `json:"to"`
}

type SnapshotResource struct {
	MIMEType string `json:"mime_type"`
	Size     int64  `json:"size_bytes"`
	SHA256   string `json:"sha256"`
	File     string `json:"file"`
}

type ObjectInfo struct {
	Size           int64
	SHA256         string
	MIMEType       string
	ImmutableToken string
}

type ObjectRef struct {
	TenantID   *uuid.UUID
	ScopeID    uuid.UUID
	LogicalKey string
}

type ObjectStoreCapabilities struct {
	ImmutableStaging      bool
	ConditionalFinalize   bool
	TrustedMetadata       bool
	ImmutableReads        bool
	PreservesStagingAlias bool
}

func (capabilities ObjectStoreCapabilities) runtimeReady() bool {
	return capabilities.ImmutableStaging && capabilities.ConditionalFinalize &&
		capabilities.TrustedMetadata && capabilities.ImmutableReads &&
		capabilities.PreservesStagingAlias
}

type ContentStore interface {
	Capabilities() ObjectStoreCapabilities
	PutStaging(context.Context, ObjectRef, []byte, string) (ObjectInfo, error)
	Open(context.Context, ObjectRef, string) (io.ReadCloser, error)
	Finalize(context.Context, ObjectRef, ObjectRef, ObjectInfo) (ObjectInfo, error)
	Stat(context.Context, ObjectRef) (ObjectInfo, error)
	Delete(context.Context, ObjectRef) error
}

type ScanInput struct {
	AssetID        uuid.UUID
	MIMEType       string
	Size           int64
	SHA256         string
	ImmutableToken string
	Body           io.Reader
}

type Scanner interface {
	Name() string
	Scan(context.Context, ScanInput) error
}

type EntitlementCheck struct {
	Operation     string
	ScopeID       uuid.UUID
	ResourceID    uuid.UUID
	ActorUserID   uuid.UUID
	PrincipalKind string
	PrincipalID   string
	RequestID     string
	Expands       bool
	Publishes     bool
}

type EntitlementLimits struct {
	FeatureEnabled      bool
	AssetQuota          AssetQuota
	MaxRulesPerScope    int
	MaxPublicationSites int
	MaxPublicationBytes int64
}

type LimitProvider interface {
	Limits(context.Context, pgx.Tx, EntitlementCheck) (EntitlementLimits, error)
}

type TxAuthorizer interface {
	Authorize(context.Context, pgx.Tx, Actor, string) error
}

type AuditAppender interface {
	Append(context.Context, pgx.Tx, audit.Event) error
}

type Clock func() time.Time
