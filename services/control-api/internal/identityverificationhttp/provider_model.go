package identityverificationhttp

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identityverification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	ProviderSessionCreating   = "creating"
	ProviderSessionPending    = "pending"
	ProviderSessionProcessing = "processing"
	ProviderSessionSucceeded  = "succeeded"
	ProviderSessionFailed     = "failed"
	ProviderSessionCanceled   = "canceled"
	ProviderSessionExpired    = "expired"
	ProviderSessionUnknown    = "unknown"

	ProviderUploadIssued       = "issued"
	ProviderUploadFinalized    = "finalized"
	ProviderUploadErasePending = "erase_pending"
	ProviderUploadErased       = "erased"

	maximumProviderMaterialBytes int64 = 20 << 20
)

var (
	ErrProviderInvalid             = errors.New("identity verification provider input is invalid")
	ErrProviderUnavailable         = errors.New("identity verification provider is unavailable")
	ErrProviderConflict            = errors.New("identity verification provider state conflicts")
	ErrProviderCallbackAuth        = errors.New("identity verification provider callback authentication failed")
	ErrProviderCallbackReplay      = errors.New("identity verification provider callback replay conflicts")
	ErrProviderObjectUnavailable   = errors.New("identity verification private object store is unavailable")
	ErrProviderObjectMismatch      = errors.New("identity verification private object facts mismatch")
	ErrProviderMaterialsIncomplete = errors.New("identity verification provider materials are incomplete")
)

type StartProviderSessionRequest struct {
	Kind           string
	Provider       string
	IdempotencyKey string
	RequestID      string
}

type ProviderSessionView struct {
	ID            uuid.UUID `json:"id"`
	Kind          string    `json:"kind"`
	Provider      string    `json:"provider"`
	State         string    `json:"state"`
	Revision      int64     `json:"revision"`
	EvidenceToken string    `json:"evidence_token,omitempty"`
	ExpiresAt     time.Time `json:"expires_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	Replayed      bool      `json:"replayed"`
}

type CreateProviderUploadRequest struct {
	SessionID      uuid.UUID
	MaterialKind   string
	ContentType    string
	SizeBytes      int64
	SHA256         [sha256.Size]byte
	IdempotencyKey string
	RequestID      string
}

type ProviderUploadView struct {
	ID              uuid.UUID         `json:"id"`
	SessionID       uuid.UUID         `json:"session_id"`
	MaterialKind    string            `json:"material_kind"`
	State           string            `json:"state"`
	Revision        int64             `json:"revision"`
	UploadURL       string            `json:"upload_url,omitempty"`
	RequiredHeaders map[string]string `json:"required_headers,omitempty"`
	ExpiresAt       time.Time         `json:"expires_at"`
	Replayed        bool              `json:"replayed"`
}

type FinalizeProviderUploadRequest struct {
	SessionID        uuid.UUID
	UploadID         uuid.UUID
	ExpectedRevision int64
	IdempotencyKey   string
	RequestID        string
}

type ProviderSessionCreate struct {
	LocalSessionID    uuid.UUID
	TenantScopeID     uuid.UUID
	ActorUserID       uuid.UUID
	Kind              string
	ProviderRequestID string
	ExpiresAt         time.Time
}

type ProviderSessionCreated struct {
	ExternalSessionID string
	State             string
	ResponseSHA256    [sha256.Size]byte
	SignatureSHA256   [sha256.Size]byte
	VerificationKeyID string
}

type ProviderCallbackEnvelope struct {
	Provider string
	Header   http.Header
	Body     []byte
}

type VerifiedProviderCallback struct {
	Provider               string
	EventID                string
	Nonce                  string
	SessionID              uuid.UUID
	ExternalSessionID      string
	State                  string
	FailureCode            string
	OccurredAt             time.Time
	ReceivedAt             time.Time
	PayloadSHA256          [sha256.Size]byte
	SignatureSHA256        [sha256.Size]byte
	VerificationKeyID      string
	SubjectFingerprint     [sha256.Size]byte
	OrganizationName       string
	LegalPersonFingerprint [sha256.Size]byte
	AgentFingerprint       [sha256.Size]byte
	AgentRelationship      string
}

type ProviderCallbackResult struct {
	SessionID uuid.UUID `json:"session_id"`
	State     string    `json:"state"`
	Revision  int64     `json:"revision"`
	Applied   bool      `json:"applied"`
	Replayed  bool      `json:"replayed"`
}

type PrivateObjectPresignRequest struct {
	ObjectKey       string
	SHA256          [sha256.Size]byte
	SizeBytes       int64
	ContentType     string
	EncryptionKeyID string
	ExpiresAt       time.Time
}

type PrivateObjectPresignResult struct {
	URL             string
	RequiredHeaders map[string]string
}

type PrivateObjectReference struct {
	ObjectKey       string
	ObjectVersion   string
	SHA256          [sha256.Size]byte
	SizeBytes       int64
	ContentType     string
	EncryptionKeyID string
}

type PrivateObjectDeleteReceipt struct {
	ReceiptSHA256 [sha256.Size]byte
}

type PrivateObjectStore interface {
	Configured() bool
	PresignPut(context.Context, PrivateObjectPresignRequest) (PrivateObjectPresignResult, error)
	Stat(context.Context, string) (PrivateObjectReference, error)
	Delete(context.Context, PrivateObjectReference) (PrivateObjectDeleteReceipt, error)
}

type KYCProvider interface {
	Configured() bool
	Name() string
	CreateSession(context.Context, ProviderSessionCreate) (ProviderSessionCreated, error)
	VerifyCallback(context.Context, ProviderCallbackEnvelope) (VerifiedProviderCallback, error)
	Close()
}

type providerWriteAuthorizer interface {
	AuthorizeProviderWrite(context.Context, pgx.Tx, identityverification.Actor) error
}

type ProviderWorkflowConfig struct {
	Clock              identityverification.Clock
	NewID              identityverification.IDGenerator
	TokenKey           []byte
	ResolverName       string
	EncryptionKeyID    string
	SessionTTL         time.Duration
	UploadTTL          time.Duration
	RetentionPeriod    time.Duration
	CallbackMaxAge     time.Duration
	CallbackFutureSkew time.Duration
	EraseLeaseDuration time.Duration
	EraseRetryDelay    time.Duration
}
