package certstore

import (
	"context"
	"crypto/sha256"
	"errors"
	"io/fs"
	"time"
)

const (
	SchemaVersion           = "cdnca.edge.certificates/v1"
	ActivationSchemaVersion = "cdnca.edge.certificate-activation/v1"

	// A command carries only the sites it changes; the node keeps any number
	// of sites (sites/ index). The only per-command bound is its size.
	MaxBundleBytes      = 4 << 20
	MaxDomainsPerSite   = 100
	MaxCertificateBytes = 128 << 10
	MaxPrivateKeyBytes  = 32 << 10
	MaxVersionIDBytes   = 64
	MaxSiteIDBytes      = 64
	MaxDomainBytes      = 253
)

var (
	ErrInvalidBundle          = errors.New("invalid certificate bundle")
	ErrUnsafeState            = errors.New("unsafe certificate state")
	ErrConflict               = errors.New("certificate version conflict")
	ErrPrecheck               = errors.New("OpenResty certificate precheck failed")
	ErrActivation             = errors.New("OpenResty certificate activation failed")
	ErrHealth                 = errors.New("OpenResty certificate health check failed")
	ErrRollback               = errors.New("certificate rollback failed")
	ErrStaleActivation        = errors.New("stale certificate activation")
	ErrCertificateUnavailable = errors.New("certificate version unavailable")
	// ErrCertificateNotValidNow joins ErrCertificateUnavailable when the
	// site's binding exists but is outside its validity window (expired or
	// not yet valid): only that site's HTTPS is unavailable.
	ErrCertificateNotValidNow = errors.New("certificate version is outside its validity window")
)

type Bundle struct {
	SchemaVersion string    `json:"schema_version"`
	VersionID     string    `json:"version_id"`
	Bindings      []Binding `json:"bindings"`
}

type Binding struct {
	SiteID              string   `json:"site_id"`
	Domains             []string `json:"domains"`
	CertificateChainPEM string   `json:"certificate_chain_pem"`
	PrivateKeyPEM       string   `json:"private_key_pem"`
}

type RuntimeConfig struct {
	StateRoot     string
	ListenAddress string
	ListenPort    uint16
}

type Artifact struct {
	VersionID     string
	Digest        string
	Manifest      Manifest
	Activation    *ActivationMetadata
	Files         []ArtifactFile
	HealthTargets []HealthTarget
}

type ArtifactFile struct {
	Path    string
	Content []byte
	Mode    fs.FileMode
	Private bool
}

type Manifest struct {
	SchemaVersion string              `json:"schema_version"`
	VersionID     string              `json:"version_id"`
	Digest        string              `json:"digest"`
	Activation    *ActivationMetadata `json:"activation,omitempty"`
	Bindings      []ManifestBinding   `json:"bindings"`
}

type ActivationMetadata struct {
	SchemaVersion   string                `json:"schema_version"`
	ConfigVersionID string                `json:"config_version_id"`
	RecipientKeyID  string                `json:"recipient_key_id"`
	CommandEventID  string                `json:"command_event_id"`
	DeploymentID    string                `json:"deployment_id"`
	Attempt         uint32                `json:"attempt"`
	ArtifactID      string                `json:"artifact_id"`
	Certificates    []CertificateRevision `json:"certificates"`
	RemovedSites    []RemovedSite         `json:"removed_sites,omitempty"`
}

type CertificateRevision struct {
	TenantID             string `json:"tenant_id"`
	TenantScopeID        string `json:"tenant_scope_id,omitempty"`
	SiteID               string `json:"site_id"`
	CertificateID        string `json:"certificate_id"`
	CertificateVersionID string `json:"certificate_version_id,omitempty"`
	Version              uint64 `json:"version"`
	BindingRevision      uint64 `json:"binding_revision,omitempty"`
}

// RemovedSite names a site whose certificate binding was removed at
// BindingRevision (the control plane's per-site binding fact sequence).
type RemovedSite struct {
	TenantID        string `json:"tenant_id"`
	TenantScopeID   string `json:"tenant_scope_id"`
	SiteID          string `json:"site_id"`
	BindingRevision uint64 `json:"binding_revision"`
}

type CertificateVersionReferences struct {
	Current  []string `json:"current"`
	Previous []string `json:"previous"`
}

type CertificateResolveRequest struct {
	TenantScopeID        string
	SiteID               string
	CertificateID        string
	CertificateVersionID string
	Domain               string
}

type ResolvedCertificateVersion struct {
	TenantID             string
	TenantScopeID        string
	SiteID               string
	CertificateID        string
	CertificateVersionID string
	Version              uint64
	Domains              []string
	CertificatePath      string
	PrivateKeyPath       string
	LeafSHA256           [sha256.Size]byte
	// Digests of the files at CertificatePath and PrivateKeyPath, recorded
	// when the version was validated, so a copy can be checked without
	// parsing it again.
	CertificateSHA256 [sha256.Size]byte
	PrivateKeySHA256  [sha256.Size]byte
	NotBefore         time.Time
	NotAfter          time.Time
}

type ManifestBinding struct {
	SiteID          string   `json:"site_id"`
	Domains         []string `json:"domains"`
	CertificateFile string   `json:"certificate_file"`
	PrivateKeyFile  string   `json:"private_key_file"`
	LeafSHA256      string   `json:"leaf_sha256"`
}

type HealthTarget struct {
	ServerName string
	LeafSHA256 [sha256.Size]byte
}

type Runtime interface {
	Precheck(context.Context, string) error
	Activate(context.Context, string) error
	Healthy(context.Context, []HealthTarget) error
	Stop(context.Context, string) error
}

type Result struct {
	VersionID               string    `json:"version_id"`
	Digest                  string    `json:"digest"`
	ActiveVersionID         string    `json:"active_version_id,omitempty"`
	ActiveDigest            string    `json:"active_digest,omitempty"`
	Changed                 bool      `json:"changed"`
	RunningVersionUnchanged bool      `json:"running_version_unchanged"`
	ErrorCode               string    `json:"error_code,omitempty"`
	AppliedAt               time.Time `json:"applied_at,omitempty"`
}

type Status struct {
	SchemaVersion string               `json:"schema_version"`
	Active        bool                 `json:"active"`
	VersionID     string               `json:"version_id,omitempty"`
	Digest        string               `json:"digest,omitempty"`
	Activation    *ActivationMetadata  `json:"activation,omitempty"`
	HealthTargets []StatusHealthTarget `json:"health_targets,omitempty"`
	AppliedAt     time.Time            `json:"applied_at,omitempty"`
}

type StatusHealthTarget struct {
	ServerName string `json:"server_name"`
	LeafSHA256 string `json:"leaf_sha256"`
}
