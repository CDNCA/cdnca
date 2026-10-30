// Package artifactsync is the control-plane consumer of the license
// service's signed artifact catalog (cdnca.artifact-catalog/v1,
// docs/adr/0007-plugin-platform-architecture.md §4.1, §5.4). It replaces the
// security rule catalog consumer and the IP intelligence library sync.
//
//   - The catalog is synchronized in full: every delivered entry is
//     "available" (artifact_catalog_entries); entries no longer delivered are
//     kept as withdrawn.
//   - Bytes are fetched only for resident entries, entries an administrator
//     asked to download, and newer revisions of what is already downloaded.
//     They are checked against the signed entry (and, per kind, decoded)
//     before they are stored (artifact_objects, by sha256, immutable).
//   - LKG: the downloaded revision of an artifact only moves forward; any
//     failed check keeps the previous download (local_artifacts).
//   - Every read recomputes the installation's lease features: an entry that
//     requires a feature the local lease does not grant is not returned, not
//     downloaded and not materialized, even if the license service listed it.
//   - Downloading never enables anything for nodes: the node artifact set
//     (PA-01) decides what goes to nodes; artifact_enablement_overrides is
//     reserved for the enable state (PA-11).
//
// The ruleset / crs_profile artifacts are materialized into
// security_system_rules, the table the management UI and the site
// publisher read; a change of the CRS rule package digest requests the
// republication of the scopes whose release loads a changed rule file.
package artifactsync

import (
	"context"
	"errors"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/libs/entitlement/artifactcatalog"
	"github.com/cdnca/cdnca/services/control-api/internal/rulepackcontrol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	// ErrStaleApply: the catalog head moved while a delivery was applied.
	ErrStaleApply = errors.New("artifact catalog head moved during apply")
	// ErrNotFound: no such catalog entry, local artifact or object.
	ErrNotFound = errors.New("artifact not found")
	// ErrNotEntitled: the local lease does not grant the entry's feature.
	ErrNotEntitled = errors.New("artifact requires a lease feature this installation does not have")
	// ErrUnsupported: this release cannot download or use the entry
	// (unknown kind, encrypted, or withdrawn).
	ErrUnsupported  = errors.New("artifact cannot be downloaded by this release")
	ErrInvalidInput = errors.New("invalid artifact sync input")
)

// LocalArtifact is one artifact this control plane downloaded and may use
// now: its catalog entry is active and the local lease grants its feature.
// Version / Revision / SHA256 / Size / RequiresCapability describe the
// downloaded bytes (the catalog may already list a newer revision that has
// not been downloaded yet). SHA256 is lowercase hex.
type LocalArtifact struct {
	ArtifactID         string
	Kind               string
	Version            string
	Revision           uint64
	SHA256             string
	Size               int64
	MediaType          string
	RequiresCapability *artifactcatalog.Capability
	AppliedAt          time.Time
}

// FeatureReader returns the feature codes of the installation's valid
// lease now (entitlementguard.Guard.ReadValidFeatures). Nil grants nothing:
// only free entries are usable.
type FeatureReader interface {
	ReadValidFeatures(ctx context.Context, tx pgx.Tx) (map[string]bool, error)
}

// CRSRepublisher requests, in the materialization transaction, the
// republication of the scopes whose release loads a CRS rule file whose
// text changed between the previous and the next materialized CRS rule
// package (digests: lowercase hex, "" when absent; bodies: the
// security_system_rules body, nil when absent). sourceID is the catalog
// delivery that brought the next package. edgeautopublish.RuleCatalogPublisher.
//
// RepublishCRSProfilePackChangeTx requests the republication of the scopes
// whose release selects a CRS profile pack by one of previousSHA256 (a newer
// downloaded revision, or the pack is no longer usable): system-layer
// security packs auto-enable their new versions (ADR 0007 §5.4).
type CRSRepublisher interface {
	RepublishCRSPackageChangeTx(ctx context.Context, tx pgx.Tx, sourceID uuid.UUID,
		previousSHA256, nextSHA256 string, previous, next []byte) ([]uuid.UUID, error)
	RepublishCRSProfilePackChangeTx(ctx context.Context, tx pgx.Tx, sourceID uuid.UUID, previousSHA256 []string) ([]uuid.UUID, error)
}

// TrustedCrawlerRepublisher (optional on a CRSRepublisher) republishes the
// scopes with CC policies when a new trusted crawler dataset
// (dataset/trusted-crawlers) is downloaded or the dataset goes away: the
// official ranges are part of the compiled CC policies.
type TrustedCrawlerRepublisher interface {
	RepublishTrustedCrawlersChangeTx(ctx context.Context, tx pgx.Tx, sourceID uuid.UUID) ([]uuid.UUID, error)
}

// DefaultOnPackRepublisher (optional on a CRSRepublisher) republishes the
// scopes whose rule pack mounts the control plane recomputed for a
// default-on official pack.
type DefaultOnPackRepublisher interface {
	RepublishDefaultOnPackMountsTx(ctx context.Context, tx pgx.Tx, sourceID uuid.UUID, scopes []rulepackcontrol.DefaultOnScope) error
}

// DownloadRequest is an administrator asking for an entry's bytes
// ("下载", ADR 0007 §5.4). Authorization is the caller's job.
type DownloadRequest struct {
	ArtifactID  string
	ActorUserID uuid.UUID
	ScopeID     uuid.UUID
	SourceIP    string
	RequestID   string
}

// Rejection and attempt codes (artifact_catalog_state / local_artifacts
// last_error_code).
const (
	CodeResolveFailed      = "resolve_failed"
	CodeNotYetValid        = "not_yet_valid"
	CodeUnknownKey         = "unknown_signing_key"
	CodeInvalidSignature   = "invalid_signature"
	CodeDigestMismatch     = "catalog_digest_mismatch"
	CodeTargetMismatch     = "target_mismatch"
	CodeExpired            = "expired"
	CodeRevisionOutOfOrder = "revision_out_of_order"
	CodeSupersedes         = "supersedes_mismatch"
	CodeInvalidEnvelope    = "invalid_envelope"
	CodeApplyFailed        = "atomic_apply_failed"
	CodeEntryOutOfOrder    = "entry_revision_out_of_order"
	CodeDownloadFailed     = "download_failed"
	CodeContentMismatch    = "content_mismatch"
)

// RejectionCode maps a catalog verification failure to its code.
func RejectionCode(err error) string {
	switch {
	case errors.Is(err, artifactcatalog.ErrDigestMismatch):
		return CodeDigestMismatch
	case errors.Is(err, artifactcatalog.ErrInvalidSignature):
		if errors.Is(err, entitlement.ErrUnknownKey) {
			return CodeUnknownKey
		}
		return CodeInvalidSignature
	case errors.Is(err, artifactcatalog.ErrTargetMismatch):
		return CodeTargetMismatch
	case errors.Is(err, artifactcatalog.ErrExpired):
		return CodeExpired
	case errors.Is(err, artifactcatalog.ErrNotYetValid):
		return CodeNotYetValid
	case errors.Is(err, artifactcatalog.ErrRevisionOutOfOrder):
		return CodeRevisionOutOfOrder
	case errors.Is(err, artifactcatalog.ErrSupersedesMismatch):
		return CodeSupersedes
	default:
		return CodeInvalidEnvelope
	}
}
