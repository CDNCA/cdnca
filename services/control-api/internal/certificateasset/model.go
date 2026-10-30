package certificateasset

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	SourceUploaded = "uploaded"
	SourceACME     = "acme"

	StatusDefault           = "default"
	StatusPendingActivation = "pending_activation"
	StatusActive            = "active"
	StatusSuperseded        = "superseded"
	StatusRevoked           = "revoked"
	StatusExpired           = "expired"

	ScopeTenant   = "tenant"
	ScopePlatform = "platform"

	MaxCertificatePEMBytes = 256 * 1024
	MaxPrivateKeyPEMBytes  = 64 * 1024
	MaxCertificateChain    = 16
	MaxCertificateSANs     = 100
	MinimumRSAKeyBits      = 2048
	DefaultRenewBefore     = 30 * 24 * time.Hour
)

var (
	ErrInvalidInput           = errors.New("invalid certificate asset input")
	ErrInvalidCertificatePEM  = errors.New("invalid certificate PEM")
	ErrInvalidPrivateKeyPEM   = errors.New("invalid certificate private key PEM")
	ErrKeyMismatch            = errors.New("certificate private key mismatch")
	ErrCertificateExpired     = errors.New("certificate is expired")
	ErrCertificateNotYetValid = errors.New("certificate is not yet valid")
	ErrWeakPublicKey          = errors.New("certificate public key is too weak")
	ErrWeakSignature          = errors.New("certificate signature algorithm is too weak")
	ErrCertificateAuthority   = errors.New("certificate leaf must not be a certificate authority")
	ErrServerAuthRequired     = errors.New("certificate leaf does not permit server authentication")
	ErrInvalidSAN             = errors.New("certificate contains an invalid subject alternative name")
	ErrChainOrder             = errors.New("certificate chain is out of order")
	ErrChainIncomplete        = errors.New("certificate chain is incomplete")
	ErrEnvelopeUnavailable    = errors.New("certificate private key envelope unavailable")
	ErrPermissionDenied       = errors.New("certificate asset permission denied")
	ErrNotFound               = errors.New("certificate asset not found")
	ErrRevisionConflict       = errors.New("certificate asset revision conflict")
	ErrIdempotencyConflict    = errors.New("certificate asset idempotency conflict")
	ErrInvalidTransition      = errors.New("invalid certificate asset transition")
	ErrDomainNotCovered       = errors.New("certificate does not cover site domain")
	ErrReferenced             = errors.New("certificate asset is still referenced")
	ErrDeleted                = errors.New("certificate asset is deleted")
	ErrAutoRenewUnsupported   = errors.New("uploaded certificate cannot auto-renew")
	ErrAssetDisabled          = errors.New("certificate asset is disabled")
	ErrDownloadUnavailable    = errors.New("certificate has no downloadable version")
	ErrACMEOrderMismatch      = errors.New("certificate does not match ACME order")
	ErrInvalidStore           = errors.New("invalid certificate asset store")
)

type Clock func() time.Time

type AuditAppender interface {
	Append(context.Context, pgx.Tx, audit.Event) error
}

// PrivateKeyEnveloper is the only boundary that accepts plaintext or provider-
// wrapped private-key material. Every operation is bound to canonical row AAD.
type PrivateKeyEnveloper interface {
	Seal(context.Context, PrivateKeySealRequest) (PrivateKeyEnvelope, error)
	SealOpaque(context.Context, OpaquePrivateKeySealRequest) (PrivateKeyEnvelope, error)
	Unseal(context.Context, PrivateKeyUnsealRequest) ([]byte, error)
	Rewrap(context.Context, PrivateKeyRewrapRequest) (PrivateKeyEnvelope, error)
}

type PrivateKeyEnvelope struct {
	KeyID      string
	Ciphertext []byte
	Nonce      []byte
	Metadata   json.RawMessage
}

type PrivateKeyEnvelopeContext struct {
	TenantScopeID                uuid.UUID
	AssetID                      uuid.UUID
	VersionID                    uuid.UUID
	Version                      int64
	CertificateFingerprintSHA256 [32]byte
	CertificatePublicKeySHA256   [32]byte
	PrivateKeyReference          string
}

func (value PrivateKeyEnvelopeContext) CanonicalAAD() ([]byte, error) {
	if value.TenantScopeID == uuid.Nil || value.AssetID == uuid.Nil || value.VersionID == uuid.Nil ||
		value.Version < 1 || !validOpaqueName(value.PrivateKeyReference, 256) {
		return nil, ErrInvalidInput
	}
	return json.Marshal(struct {
		Schema                       string    `json:"schema"`
		TenantScopeID                uuid.UUID `json:"tenant_scope_id"`
		AssetID                      uuid.UUID `json:"asset_id"`
		VersionID                    uuid.UUID `json:"version_id"`
		Version                      int64     `json:"version"`
		CertificateFingerprintSHA256 string    `json:"certificate_fingerprint_sha256"`
		CertificatePublicKeySHA256   string    `json:"certificate_public_key_sha256"`
		PrivateKeyReference          string    `json:"private_key_reference"`
	}{
		Schema: "cdnca.certificate-private-key-envelope.v1", TenantScopeID: value.TenantScopeID,
		AssetID: value.AssetID, VersionID: value.VersionID, Version: value.Version,
		CertificateFingerprintSHA256: hex.EncodeToString(value.CertificateFingerprintSHA256[:]),
		CertificatePublicKeySHA256:   hex.EncodeToString(value.CertificatePublicKeySHA256[:]),
		PrivateKeyReference:          value.PrivateKeyReference,
	})
}

func (value PrivateKeyEnvelopeContext) AADDigest() ([32]byte, error) {
	aad, err := value.CanonicalAAD()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(aad), nil
}

type PrivateKeySealRequest struct {
	Context        PrivateKeyEnvelopeContext
	PlaintextPKCS8 []byte
}

type OpaquePrivateKey struct {
	KeyReference       string
	PublicKeySPKIDER   []byte
	WrappedKeyMaterial []byte
	Metadata           json.RawMessage
}

type OpaquePrivateKeySealRequest struct {
	Context            PrivateKeyEnvelopeContext
	WrappedKeyMaterial []byte
	Metadata           json.RawMessage
}

type PrivateKeyUnsealRequest struct {
	Context  PrivateKeyEnvelopeContext
	Envelope PrivateKeyEnvelope
}

type PrivateKeyRewrapRequest struct {
	Context     PrivateKeyEnvelopeContext
	Envelope    PrivateKeyEnvelope
	TargetKeyID string
}

type Actor struct {
	UserID    uuid.UUID
	ScopeID   uuid.UUID
	ScopeKind string
	SessionID uuid.UUID
}

type Asset struct {
	ID                 uuid.UUID    `json:"id"`
	DisplayID          string       `json:"display_id"`
	TenantScopeID      uuid.UUID    `json:"tenant_scope_id"`
	Tenant             *AssetTenant `json:"tenant"`
	Owner              *AssetOwner  `json:"owner"`
	OwnerStatus        string       `json:"owner_status"`
	Name               string       `json:"name"`
	Remark             string       `json:"remark"`
	Source             string       `json:"source"`
	AutoRenew          bool         `json:"auto_renew"` // migration 537: asset-level renewal intent
	Disabled           bool         `json:"disabled"`   // migration 552: disabled certificates cannot be bound or renewed
	Revision           int64        `json:"revision"`
	CreatedBy          uuid.UUID    `json:"created_by"`
	CreatedByDisplayID string       `json:"created_by_display_id"`
	UpdatedBy          uuid.UUID    `json:"updated_by"`
	UpdatedByDisplayID string       `json:"updated_by_display_id"`
	CreatedAt          time.Time    `json:"created_at"`
	UpdatedAt          time.Time    `json:"updated_at"`
	DeletedAt          *time.Time   `json:"deleted_at,omitempty"`
}

type AssetOwner struct {
	ID          uuid.UUID `json:"id"`
	DisplayID   string    `json:"display_id"`
	Username    string    `json:"username"`
	DisplayName string    `json:"display_name"`
}

type AssetTenant struct {
	ID        uuid.UUID `json:"id"`
	DisplayID string    `json:"display_id"`
	Name      string    `json:"name"`
}

type Version struct {
	ID                 uuid.UUID  `json:"id"`
	AssetID            uuid.UUID  `json:"asset_id"`
	TenantScopeID      uuid.UUID  `json:"tenant_scope_id"`
	Version            int64      `json:"version"`
	Status             string     `json:"status"`
	FingerprintSHA256  string     `json:"fingerprint_sha256"`
	CertificatePEM     []byte     `json:"certificate_pem"`
	SANs               []string   `json:"sans"`
	Subject            string     `json:"subject"`
	SerialNumber       string     `json:"serial_number"`
	PublicKeyAlgorithm string     `json:"public_key_algorithm"`
	PublicKeyBits      int        `json:"public_key_bits"`
	SignatureAlgorithm string     `json:"signature_algorithm"`
	NotBefore          time.Time  `json:"not_before"`
	NotAfter           time.Time  `json:"not_after"`
	ACMEOrderID        *uuid.UUID `json:"acme_order_id,omitempty"`
	RenewalDueAt       *time.Time `json:"renewal_due_at,omitempty"`
	RenewalDue         bool       `json:"renewal_due"`
	ImportedBy         uuid.UUID  `json:"imported_by"`
	ImportedAt         time.Time  `json:"imported_at"`
}

type ImportResult struct {
	Asset    Asset   `json:"asset"`
	Version  Version `json:"version"`
	Replayed bool    `json:"-"`
}

type ImportRequest struct {
	TenantScopeID    uuid.UUID
	OwnerUserID      *uuid.UUID
	AssetID          *uuid.UUID
	ExpectedRevision int64
	Name             string
	// Remark is the new asset's remark (CERT-04); not used for a new version.
	Remark           string
	Source           string
	ACMEOrderID      *uuid.UUID
	CertificatePEM   []byte
	PrivateKeyPEM    []byte
	OpaquePrivateKey *OpaquePrivateKey
	IdempotencyKey   string
	RequestID        string
}

type ACMEImportRequest struct {
	Actor  Actor
	Import ImportRequest
}

type RewrapRequest struct {
	TenantScopeID            uuid.UUID
	AssetID                  uuid.UUID
	VersionID                uuid.UUID
	ExpectedEnvelopeSequence int64
	TargetKeyID              string
	IdempotencyKey           string
	RequestID                string
}

type EnvelopeRevision struct {
	TenantScopeID uuid.UUID `json:"tenant_scope_id"`
	AssetID       uuid.UUID `json:"asset_id"`
	VersionID     uuid.UUID `json:"version_id"`
	Sequence      int64     `json:"sequence"`
	AADDigest     string    `json:"aad_sha256"`
	ChangedAt     time.Time `json:"changed_at"`
}

type ActivateRequest struct {
	TenantScopeID    uuid.UUID
	AssetID          uuid.UUID
	VersionID        uuid.UUID
	ExpectedRevision int64
	IdempotencyKey   string
	RequestID        string
}

// SetAutoRenewRequest turns an ACME certificate's automatic renewal on or off
// (fix-autorenew, migration 537).
type SetAutoRenewRequest struct {
	TenantScopeID    uuid.UUID
	AssetID          uuid.UUID
	Enabled          bool
	ExpectedRevision int64
	IdempotencyKey   string
	RequestID        string
}

// SetDisabledRequest disables or re-enables a certificate (fix-certops,
// migration 552). A certificate still bound to a site cannot be disabled.
type SetDisabledRequest struct {
	TenantScopeID    uuid.UUID
	AssetID          uuid.UUID
	Disabled         bool
	ExpectedRevision int64
	IdempotencyKey   string
	RequestID        string
}

// DownloadRequest exports the current version's chain and private key
// (fix-certops 下载证书); audited as certificate.asset.download.
type DownloadRequest struct {
	TenantScopeID uuid.UUID
	AssetID       uuid.UUID
	RequestID     string
	// OpaqueResolver unwraps ACME-issued keys (the publication resolver).
	OpaqueResolver OpaquePublicationResolver
}

// Download is the exported material. PrivateKeyPEM is PKCS#8 PEM; callers
// zero it after writing.
type Download struct {
	AssetID        uuid.UUID
	Name           string
	SANs           []string
	CertificatePEM []byte
	PrivateKeyPEM  []byte
}

type DeleteRequest struct {
	TenantScopeID    uuid.UUID
	AssetID          uuid.UUID
	ExpectedRevision int64
	IdempotencyKey   string
	RequestID        string
}

type ListRequest struct {
	TenantScopeID  uuid.UUID
	IncludeDeleted bool
	Page           int
	Limit          int
	Search         string
	// Status: one of ListStatuses (证书状态胶囊), "" for all.
	Status string
	// Filters are the advanced search (CERT-05); they narrow the items,
	// total and counts alike.
	Filters ListFilters
}

// ListFilters are the certificate list's advanced search. Empty fields do
// not filter.
type ListFilters struct {
	Domain        string     // a SAN of any version contains it
	Domains       []string   // the latest version's SANs contain every one (exact)
	User          string     // owner display ID, username, email or phone contains it
	CertificateID string     // display ID contains it
	Name          string     // name contains it
	Remark        string     // remark contains it
	Source        string     // uploaded / acme
	DNSProviderID *uuid.UUID // the issuing order's DNS provider
	Expiry        string     // ListExpiries
	AutoRenew     *bool      // an auto-renewing order issued the asset
	Issue         string     // ListIssueStates
	Sync          string     // ListSyncStates
}

// ListExpiries: within30/within90 are versions in force (active or default,
// not yet expired) whose not_after is at most 30/90 days away; expired is a
// passed not_after.
var ListExpiries = []string{"within30", "within90", "expired"}

// ListIssueStates: issued is an asset issued by an order; failed is an asset
// whose issuing order or one of its renewal orders failed. Failed requests
// that never produced an asset are in 申请记录.
var ListIssueStates = []string{"issued", "failed"}

// ListSyncStates are the publication of the asset's current site bindings:
// failed when one permanently failed, complete when every one succeeded,
// pending otherwise. An asset bound to no site matches none.
var ListSyncStates = []string{"complete", "pending", "failed"}

// ListStatuses are the list's status filters. normal/expiring/expired come
// from the latest version (expiring: active within 30 days; expired:
// not_after passed); auto_renew/manual_renew from whether an auto-renewing
// order issued the asset.
var ListStatuses = []string{"normal", "expiring", "expired", "auto_renew", "manual_renew"}

// ListCounts are the assets per status under the list's search (not its
// status filter).
type ListCounts struct {
	All         int64 `json:"all"`
	Normal      int64 `json:"normal"`
	Expiring    int64 `json:"expiring"`
	Expired     int64 `json:"expired"`
	AutoRenew   int64 `json:"auto_renew"`
	ManualRenew int64 `json:"manual_renew"`
}

type ListResult struct {
	Items  []Asset    `json:"items"`
	Total  int64      `json:"total"`
	Counts ListCounts `json:"counts"`
}

type BindRequest struct {
	TenantScopeID    uuid.UUID
	SiteID           uuid.UUID
	AssetID          uuid.UUID
	VersionID        uuid.UUID
	ExpectedRevision int64
	Default          bool
	IdempotencyKey   string
	RequestID        string
}

type UnbindRequest struct {
	TenantScopeID    uuid.UUID
	SiteID           uuid.UUID
	ExpectedRevision int64
	IdempotencyKey   string
	RequestID        string
}

type Binding struct {
	TenantScopeID uuid.UUID `json:"tenant_scope_id"`
	SiteID        uuid.UUID `json:"site_id"`
	AssetID       uuid.UUID `json:"asset_id"`
	VersionID     uuid.UUID `json:"version_id"`
	Revision      int64     `json:"revision"`
	Default       bool      `json:"default"`
	Bound         bool      `json:"bound"`
	ChangedBy     uuid.UUID `json:"changed_by"`
	ChangedAt     time.Time `json:"changed_at"`
}

type preparedCertificate struct {
	Fingerprint         [32]byte
	PublicKeySHA256     [32]byte
	CanonicalPEM        []byte
	SANs                []string
	Subject             string
	SerialNumber        string
	PublicKeyAlgorithm  string
	PublicKeyBits       int
	SignatureAlgorithm  string
	NotBefore           time.Time
	NotAfter            time.Time
	PrivateKeyReference string
	CanonicalPrivateKey []byte
	OpaquePrivateKey    *OpaquePrivateKey
}
