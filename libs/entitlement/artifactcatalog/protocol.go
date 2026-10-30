package artifactcatalog

import (
	"regexp"
	"strconv"

	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
)

// Installation-facing protocol. Both requests are authenticated with the
// installation's Ed25519 identity key: the proof signs a length-prefixed
// SHA-256 digest of every field (same construction as the platform policy
// channel). Resolve returns the signed catalog (or not_modified); fetch
// returns exactly the bytes of one entry the installation is currently
// served, as application/octet-stream.
const (
	ResolvePath           = "/installation/v1/artifact-catalog:resolve"
	FetchPath             = "/installation/v1/artifacts:fetch"
	ResolveRequestSchema  = "cdnca.artifact-catalog.resolve-request/v1"
	ResolveResponseSchema = "cdnca.artifact-catalog.resolve-response/v1"
	FetchRequestSchema    = "cdnca.artifact-catalog.fetch-request/v1"
	ResolveProofDomain    = "cdnca-artifact-catalog-resolve-proof/v1"
	FetchProofDomain      = "cdnca-artifact-catalog-fetch-proof/v1"
	FetchMediaType        = "application/octet-stream"
	MaxRequestBytes       = 4 << 10
)

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// ResolveRequest: Known* describe the delivery the control plane applied
// (all zero before the first one).
type ResolveRequest struct {
	Schema             string `json:"schema"`
	RequestID          string `json:"request_id"`
	InstallationID     string `json:"installation_id"`
	RequestedAt        int64  `json:"requested_at"`
	ControlVersion     string `json:"control_version"`
	KnownDeliveryID    string `json:"known_delivery_id"`
	KnownScopeRevision uint64 `json:"known_scope_revision"`
	KnownCatalogSHA256 string `json:"known_catalog_sha256"`
	Proof              string `json:"proof"`
}

// ResolveResponse: exactly one of NotModified / Delivery.
type ResolveResponse struct {
	Schema         string  `json:"schema"`
	RequestID      string  `json:"request_id"`
	InstallationID string  `json:"installation_id"`
	ResolvedAt     int64   `json:"resolved_at"`
	NotModified    bool    `json:"not_modified"`
	Delivery       *Signed `json:"delivery"`
}

// FetchRequest names one entry by id, revision and sha256.
type FetchRequest struct {
	Schema         string `json:"schema"`
	RequestID      string `json:"request_id"`
	InstallationID string `json:"installation_id"`
	RequestedAt    int64  `json:"requested_at"`
	ArtifactID     string `json:"artifact_id"`
	Revision       uint64 `json:"revision"`
	SHA256         string `json:"sha256"`
	Proof          string `json:"proof"`
}

func ResolveProofMessage(request ResolveRequest) []byte {
	return rulecatalog.DigestFields(ResolveProofDomain, request.Schema, request.RequestID, request.InstallationID,
		strconv.FormatInt(request.RequestedAt, 10), request.ControlVersion, request.KnownDeliveryID,
		strconv.FormatUint(request.KnownScopeRevision, 10), request.KnownCatalogSHA256)
}

func FetchProofMessage(request FetchRequest) []byte {
	return rulecatalog.DigestFields(FetchProofDomain, request.Schema, request.RequestID, request.InstallationID,
		strconv.FormatInt(request.RequestedAt, 10), request.ArtifactID, strconv.FormatUint(request.Revision, 10), request.SHA256)
}

// ValidRequestID bounds request ids on both sides of the channel.
func ValidRequestID(value string) bool { return requestIDPattern.MatchString(value) }

// Installation encryption key (ADR 0007 §6.1, PA-14): the X25519 key the
// license service wraps encrypted packs' content keys to. It is generated
// separately from the Ed25519 identity key (never converted from it) and
// registered with a proof of the identity key: at activation (optional
// activation field) or later with this request (rotation, reinstall, a
// control plane activated before PA-14). Registering the same key again
// changes nothing.
const (
	RegisterEncryptionKeyPath   = "/installation/v1/encryption-key:register"
	RegisterEncryptionKeySchema = "cdnca.installation-encryption-key.register-request/v1"
	RegisterEncryptionKeyDomain = "cdnca-installation-encryption-key-proof/v1"
	EncryptionKeySize           = 32
)

// RegisterEncryptionKeyRequest: PublicKey is the raw X25519 public key,
// base64url without padding.
type RegisterEncryptionKeyRequest struct {
	Schema         string `json:"schema"`
	RequestID      string `json:"request_id"`
	InstallationID string `json:"installation_id"`
	RequestedAt    int64  `json:"requested_at"`
	PublicKey      string `json:"public_key"`
	Proof          string `json:"proof"`
}

// RegisterEncryptionKeyResponse names the registered key.
type RegisterEncryptionKeyResponse struct {
	InstallationID string `json:"installation_id"`
	KeyID          string `json:"key_id"`
	Changed        bool   `json:"changed"`
}

func RegisterEncryptionKeyProofMessage(request RegisterEncryptionKeyRequest) []byte {
	return rulecatalog.DigestFields(RegisterEncryptionKeyDomain, request.Schema, request.RequestID, request.InstallationID,
		strconv.FormatInt(request.RequestedAt, 10), request.PublicKey)
}
