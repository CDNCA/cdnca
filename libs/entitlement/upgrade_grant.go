package entitlement

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"regexp"
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

const (
	ArtifactManifestSchema   = "cdnca.release.artifact/v1"
	ArtifactManifestV2Schema = "cdnca.release.artifact/v2"
	ArtifactManifestV3Schema = "cdnca.release.artifact/v3"
	ArtifactManifestAudience = "cdnca-control-plane-release"
	ArtifactManifestPurpose  = "cdnca-release-artifact"
	UpgradeGrantSchema       = "cdnca.upgrade.grant/v1"
	UpgradeGrantAudience     = "cdnca-control-plane-upgrade"
	UpgradeGrantPurpose      = "cdnca-control-plane-upgrade-grant"
	UpgradeOperation         = "upgrade"
	RollbackOperation        = "rollback"
	ReinstallOperation       = "reinstall"
	MaxUpgradeArtifactBytes  = int64(285229182)
	MaxUpgradePlanRevision   = uint64(1<<63 - 1)

	UpgradeCommandGrantSchema         = "cdnca.upgrade.command-grant/v1"
	UpgradeCommandGrantV2Schema       = "cdnca.upgrade.command-grant/v2"
	UpgradeCommandGrantV3Schema       = "cdnca.upgrade.command-grant/v3"
	UpgradeCommandGrantAudience       = "cdnca-control-plane-upgrade-command"
	UpgradeCommandGrantPurpose        = "cdnca-upgrade-command-grant"
	UpgradePlanArtifactBundleSchema   = "cdnca.upgrade.plan-artifact-bundle/v1"
	UpgradePlanArtifactBundleV2Schema = "cdnca.upgrade.plan-artifact-bundle/v2"
	UpgradePlanArtifactBundleAudience = "cdnca-control-plane-upgrade-plan"
	UpgradePlanArtifactBundlePurpose  = "cdnca-upgrade-plan-artifact-bundle"

	artifactManifestSignatureDomain              = "cdnca-release-artifact-signature/v1"
	artifactManifestV2SignatureDomain            = "cdnca-release-artifact-signature/v2"
	artifactManifestV3SignatureDomain            = "cdnca-release-artifact-signature/v3"
	upgradeGrantSignatureDomain                  = "cdnca-upgrade-grant-signature/v1"
	upgradeCommandGrantSignatureDomain           = "cdnca-upgrade-command-grant-signature/v1"
	upgradeCommandGrantV2SignatureDomain         = "cdnca-upgrade-command-grant-signature/v2"
	upgradeCommandGrantV3SignatureDomain         = "cdnca-upgrade-command-grant-signature/v3"
	upgradePlanArtifactBundleSignatureDomain     = "cdnca-upgrade-plan-artifact-bundle-signature/v1"
	upgradePlanArtifactBundleV2SignatureDomain   = "cdnca-upgrade-plan-artifact-bundle-signature/v2"
	maxEncodedUpgradeGrantBytes                  = 128 * 1024
	maxEncodedUpgradeCommandGrantBytes           = 128 * 1024
	maxEncodedUpgradePlanArtifactBundleBytes     = 256 * 1024
	maxUpgradeGrantLifetimeSeconds               = int64((15 * time.Minute) / time.Second)
	maxUpgradePlanCommandIssuanceLifetimeSeconds = int64((7 * 24 * time.Hour) / time.Second)
)

var (
	ErrInvalidArtifactManifest                   = errors.New("invalid release artifact manifest")
	ErrInvalidArtifactManifestSignature          = errors.New("invalid release artifact manifest signature")
	ErrInvalidUpgradeGrant                       = errors.New("invalid upgrade grant")
	ErrInvalidUpgradeGrantEnvelope               = errors.New("invalid signed upgrade grant envelope")
	ErrUnknownUpgradeGrantKey                    = errors.New("unknown upgrade grant signing key")
	ErrInvalidUpgradeGrantSignature              = errors.New("invalid upgrade grant signature")
	ErrUpgradeGrantAudienceMismatch              = errors.New("upgrade grant audience mismatch")
	ErrUpgradeGrantInstallationMismatch          = errors.New("upgrade grant installation mismatch")
	ErrUpgradeGrantNotYetValid                   = errors.New("upgrade grant is not yet valid")
	ErrUpgradeGrantExpired                       = errors.New("upgrade grant is expired")
	ErrInvalidUpgradeCommandGrant                = errors.New("invalid upgrade command grant")
	ErrInvalidUpgradeCommandGrantEnvelope        = errors.New("invalid signed upgrade command grant envelope")
	ErrUnknownUpgradeCommandGrantKey             = errors.New("unknown upgrade command grant signing key")
	ErrInvalidUpgradeCommandGrantSignature       = errors.New("invalid upgrade command grant signature")
	ErrUpgradeCommandGrantTargetMismatch         = errors.New("upgrade command grant target mismatch")
	ErrUpgradeCommandGrantNotYetValid            = errors.New("upgrade command grant is not yet valid")
	ErrUpgradeCommandGrantExpired                = errors.New("upgrade command grant is expired")
	ErrInvalidUpgradePlanArtifactBundle          = errors.New("invalid upgrade plan artifact bundle")
	ErrInvalidUpgradePlanArtifactBundleEnvelope  = errors.New("invalid signed upgrade plan artifact bundle envelope")
	ErrUnknownUpgradePlanArtifactBundleKey       = errors.New("unknown upgrade plan artifact bundle signing key")
	ErrInvalidUpgradePlanArtifactBundleSignature = errors.New("invalid upgrade plan artifact bundle signature")
	ErrUpgradePlanArtifactBundleTargetMismatch   = errors.New("upgrade plan artifact bundle target mismatch")
	ErrUpgradePlanArtifactBundleNotYetValid      = errors.New("upgrade plan artifact bundle is not yet valid")
	ErrUpgradePlanArtifactBundleExpired          = errors.New("upgrade plan artifact bundle is expired")
)

var (
	upgradeGrantCodePattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,95}$`)
)

type ArtifactManifest struct {
	Schema          string `json:"schema"`
	Audience        string `json:"audience"`
	Purpose         string `json:"purpose"`
	ArtifactID      string `json:"artifact_id"`
	Component       string `json:"component"`
	Version         string `json:"version"`
	ProtocolMin     int    `json:"protocol_min"`
	ProtocolMax     int    `json:"protocol_max"`
	DigestAlgorithm string `json:"digest_algorithm"`
	SHA256Digest    string `json:"sha256_digest"`
	DownloadURL     string `json:"download_url"`
}

type ArtifactManifestV2 struct {
	Schema            string `json:"schema"`
	Audience          string `json:"audience"`
	Purpose           string `json:"purpose"`
	ArtifactID        string `json:"artifact_id"`
	Component         string `json:"component"`
	Version           string `json:"version"`
	ProtocolMin       int    `json:"protocol_min"`
	ProtocolMax       int    `json:"protocol_max"`
	ArtifactSizeBytes int64  `json:"artifact_size_bytes"`
	ReleaseSequence   uint64 `json:"release_sequence,omitempty"`
	DigestAlgorithm   string `json:"digest_algorithm"`
	SHA256Digest      string `json:"sha256_digest"`
	DownloadURL       string `json:"download_url"`
}

type UpgradeGrant struct {
	Schema                     string `json:"schema"`
	Audience                   string `json:"audience"`
	Purpose                    string `json:"purpose"`
	GrantID                    string `json:"grant_id"`
	Nonce                      string `json:"nonce"`
	CustomerID                 string `json:"customer_id"`
	InstallationID             string `json:"installation_id"`
	LicenseID                  string `json:"license_id"`
	Channel                    string `json:"channel"`
	ChannelRevision            uint64 `json:"channel_revision"`
	Component                  string `json:"component"`
	Operation                  string `json:"operation"`
	CurrentVersion             string `json:"current_version"`
	Version                    string `json:"version"`
	ProtocolVersion            int    `json:"protocol_version"`
	ArtifactID                 string `json:"artifact_id"`
	ArtifactProtocolMin        int    `json:"artifact_protocol_min"`
	ArtifactProtocolMax        int    `json:"artifact_protocol_max"`
	DownloadURL                string `json:"download_url"`
	DigestAlgorithm            string `json:"digest_algorithm"`
	SHA256Digest               string `json:"sha256_digest"`
	ArtifactSignatureAlgorithm string `json:"artifact_signature_algorithm"`
	ArtifactSignatureKeyID     string `json:"artifact_signature_key_id"`
	ArtifactManifestSignature  string `json:"artifact_manifest_signature"`
	IssuedAt                   int64  `json:"issued_at"`
	ExpiresAt                  int64  `json:"expires_at"`
}

type SignedUpgradeGrant struct {
	Algorithm string       `json:"algorithm"`
	KeyID     string       `json:"key_id"`
	Grant     UpgradeGrant `json:"grant"`
	Signature string       `json:"signature"`
}

type UpgradePlanArtifact struct {
	Manifest           ArtifactManifestV2 `json:"manifest"`
	SignatureAlgorithm string             `json:"signature_algorithm"`
	SignatureKeyID     string             `json:"signature_key_id"`
	ManifestSignature  string             `json:"manifest_signature"`
}

type UpgradePlanArtifactBundle struct {
	Schema                  string              `json:"schema"`
	Audience                string              `json:"audience"`
	Purpose                 string              `json:"purpose"`
	BundleID                string              `json:"bundle_id"`
	PlanID                  string              `json:"plan_id"`
	InitialPlanRevision     uint64              `json:"initial_plan_revision"`
	ParentGrantID           string              `json:"parent_grant_id"`
	ParentGrantSHA256       string              `json:"parent_grant_sha256"`
	ParentGrantIssuedAt     int64               `json:"parent_grant_issued_at"`
	ParentGrantExpiresAt    int64               `json:"parent_grant_expires_at"`
	CustomerID              string              `json:"customer_id"`
	InstallationID          string              `json:"installation_id"`
	LicenseID               string              `json:"license_id"`
	Channel                 string              `json:"channel"`
	ChannelRevision         uint64              `json:"channel_revision"`
	Component               string              `json:"component"`
	CurrentVersion          string              `json:"current_version"`
	Version                 string              `json:"version"`
	ProtocolVersion         int                 `json:"protocol_version"`
	Forward                 UpgradePlanArtifact `json:"forward"`
	Rollback                UpgradePlanArtifact `json:"rollback"`
	IssuedAt                int64               `json:"issued_at"`
	CommandIssuanceNotAfter int64               `json:"command_issuance_not_after"`
}

type SignedUpgradePlanArtifactBundle struct {
	Algorithm string                    `json:"algorithm"`
	KeyID     string                    `json:"key_id"`
	Bundle    UpgradePlanArtifactBundle `json:"bundle"`
	Signature string                    `json:"signature"`
}

type UpgradePlanArtifactBundleVerifyOptions struct {
	Now                         time.Time
	ExpectedAudience            string
	ExpectedInstallationID      string
	ExpectedPlanID              string
	ExpectedInitialPlanRevision uint64
}

type UpgradeCommandGrant struct {
	Schema                     string                         `json:"schema"`
	Audience                   string                         `json:"audience"`
	Purpose                    string                         `json:"purpose"`
	CommandID                  string                         `json:"command_id"`
	Nonce                      string                         `json:"nonce"`
	ParentGrantID              string                         `json:"parent_grant_id"`
	ParentGrantSHA256          string                         `json:"parent_grant_sha256"`
	ParentGrantIssuedAt        int64                          `json:"parent_grant_issued_at"`
	ParentGrantExpiresAt       int64                          `json:"parent_grant_expires_at"`
	PlanID                     string                         `json:"plan_id,omitempty"`
	PlanRevision               uint64                         `json:"plan_revision,omitempty"`
	BatchID                    string                         `json:"batch_id,omitempty"`
	ArtifactBundleID           string                         `json:"artifact_bundle_id,omitempty"`
	ArtifactBundleSHA256       string                         `json:"artifact_bundle_sha256,omitempty"`
	CommandIssuanceNotAfter    int64                          `json:"command_issuance_not_after,omitempty"`
	CustomerID                 string                         `json:"customer_id"`
	InstallationID             string                         `json:"installation_id"`
	LicenseID                  string                         `json:"license_id"`
	Channel                    string                         `json:"channel"`
	ChannelRevision            uint64                         `json:"channel_revision"`
	ExecutionSequence          uint64                         `json:"execution_sequence,omitempty"`
	ReleaseSequence            uint64                         `json:"release_sequence,omitempty"`
	Component                  string                         `json:"component"`
	Operation                  string                         `json:"operation"`
	CurrentVersion             string                         `json:"current_version"`
	Version                    string                         `json:"version"`
	ProtocolVersion            int                            `json:"protocol_version"`
	ArtifactID                 string                         `json:"artifact_id"`
	ArtifactProtocolMin        int                            `json:"artifact_protocol_min"`
	ArtifactProtocolMax        int                            `json:"artifact_protocol_max"`
	ArtifactSizeBytes          int64                          `json:"artifact_size_bytes"`
	DownloadURL                string                         `json:"download_url"`
	DigestAlgorithm            string                         `json:"digest_algorithm"`
	SHA256Digest               string                         `json:"sha256_digest"`
	ArtifactSignatureAlgorithm string                         `json:"artifact_signature_algorithm"`
	ArtifactSignatureKeyID     string                         `json:"artifact_signature_key_id"`
	ArtifactManifestSignature  string                         `json:"artifact_manifest_signature"`
	NodeID                     string                         `json:"node_id"`
	Platform                   string                         `json:"platform"`
	Architecture               string                         `json:"architecture"`
	Compatibility              UpgradeExecutionCompatibility  `json:"compatibility"`
	Health                     UpgradeExecutionHealthPolicy   `json:"health"`
	Rollout                    UpgradeExecutionRolloutPolicy  `json:"rollout"`
	Rollback                   UpgradeExecutionRollbackPolicy `json:"rollback"`
	IssuedAt                   int64                          `json:"issued_at"`
	NotBefore                  int64                          `json:"not_before"`
	ExpiresAt                  int64                          `json:"expires_at"`
}

type SignedUpgradeCommandGrant struct {
	Algorithm string              `json:"algorithm"`
	KeyID     string              `json:"key_id"`
	Grant     UpgradeCommandGrant `json:"grant"`
	Signature string              `json:"signature"`
}

type UpgradeCommandGrantVerifyOptions struct {
	Now                    time.Time
	ExpectedAudience       string
	ExpectedInstallationID string
	ExpectedNodeID         string
	ExpectedCommandID      string
	ExpectedPlanID         string
	ExpectedPlanRevision   uint64
	ExpectedBatchID        string
}

type UpgradeGrantVerifyOptions struct {
	Now                    time.Time
	ExpectedAudience       string
	ExpectedInstallationID string
}

type artifactManifestSigningDocument struct {
	Domain   string           `json:"domain"`
	Manifest ArtifactManifest `json:"manifest"`
}

type artifactManifestV2SigningDocument struct {
	Domain   string             `json:"domain"`
	Manifest ArtifactManifestV2 `json:"manifest"`
}

type upgradeGrantSigningDocument struct {
	Domain    string       `json:"domain"`
	Algorithm string       `json:"algorithm"`
	KeyID     string       `json:"key_id"`
	Grant     UpgradeGrant `json:"grant"`
}

type upgradeCommandGrantSigningDocument struct {
	Domain    string              `json:"domain"`
	Algorithm string              `json:"algorithm"`
	KeyID     string              `json:"key_id"`
	Grant     UpgradeCommandGrant `json:"grant"`
}

type upgradePlanArtifactBundleSigningDocument struct {
	Domain    string                    `json:"domain"`
	Algorithm string                    `json:"algorithm"`
	KeyID     string                    `json:"key_id"`
	Bundle    UpgradePlanArtifactBundle `json:"bundle"`
}

func (artifact UpgradePlanArtifact) validate() error {
	signature, err := base64.RawURLEncoding.DecodeString(artifact.ManifestSignature)
	if artifact.Manifest.Validate() != nil || artifact.SignatureAlgorithm != Algorithm ||
		ValidateKeyID(artifact.SignatureKeyID) != nil || err != nil || len(signature) != ed25519.SignatureSize {
		return ErrInvalidUpgradePlanArtifactBundle
	}
	return nil
}

func (bundle UpgradePlanArtifactBundle) Validate() error {
	parentDigest, digestErr := base64.RawURLEncoding.DecodeString(bundle.ParentGrantSHA256)
	v2 := bundle.Schema == UpgradePlanArtifactBundleV2Schema
	if (bundle.Schema != UpgradePlanArtifactBundleSchema && !v2) || bundle.Audience != UpgradePlanArtifactBundleAudience ||
		bundle.Purpose != UpgradePlanArtifactBundlePurpose || !validCanonicalUUID(bundle.BundleID) ||
		!validCanonicalUUID(bundle.PlanID) || bundle.InitialPlanRevision != 1 || !validCanonicalUUID(bundle.ParentGrantID) ||
		digestErr != nil || len(parentDigest) != 32 || bundle.ParentGrantIssuedAt <= 0 ||
		bundle.ParentGrantExpiresAt <= bundle.ParentGrantIssuedAt || !validCanonicalUUID(bundle.CustomerID) ||
		!validCanonicalUUID(bundle.InstallationID) || !validCanonicalUUID(bundle.LicenseID) ||
		!upgradeGrantCodePattern.MatchString(bundle.Channel) || bundle.ChannelRevision == 0 ||
		!upgradeGrantCodePattern.MatchString(bundle.Component) || !validCanonicalSemver(bundle.CurrentVersion) ||
		!validCanonicalSemver(bundle.Version) || bundle.ProtocolVersion < 1 || bundle.IssuedAt < bundle.ParentGrantIssuedAt ||
		bundle.IssuedAt >= bundle.ParentGrantExpiresAt || bundle.CommandIssuanceNotAfter <= bundle.IssuedAt ||
		bundle.CommandIssuanceNotAfter-bundle.IssuedAt > maxUpgradePlanCommandIssuanceLifetimeSeconds ||
		bundle.Forward.validate() != nil || bundle.Rollback.validate() != nil {
		return ErrInvalidUpgradePlanArtifactBundle
	}
	if (!v2 && (bundle.Forward.Manifest.Schema != ArtifactManifestV2Schema ||
		bundle.Rollback.Manifest.Schema != ArtifactManifestV2Schema)) ||
		(v2 && (bundle.Forward.Manifest.Schema != ArtifactManifestV3Schema ||
			bundle.Rollback.Manifest.Schema != ArtifactManifestV3Schema ||
			bundle.Forward.Manifest.ReleaseSequence <= bundle.Rollback.Manifest.ReleaseSequence)) {
		return ErrInvalidUpgradePlanArtifactBundle
	}
	if bundle.Forward.Manifest.Component != bundle.Component || bundle.Forward.Manifest.Version != bundle.Version ||
		bundle.Rollback.Manifest.Component != bundle.Component || bundle.Rollback.Manifest.Version != bundle.CurrentVersion ||
		bundle.ProtocolVersion < bundle.Forward.Manifest.ProtocolMin ||
		bundle.ProtocolVersion > bundle.Forward.Manifest.ProtocolMax ||
		bundle.ProtocolVersion < bundle.Rollback.Manifest.ProtocolMin ||
		bundle.ProtocolVersion > bundle.Rollback.Manifest.ProtocolMax {
		return ErrInvalidUpgradePlanArtifactBundle
	}
	return nil
}

func (manifest ArtifactManifest) Validate() error {
	digest, err := base64.RawURLEncoding.DecodeString(manifest.SHA256Digest)
	if manifest.Schema != ArtifactManifestSchema || manifest.Audience != ArtifactManifestAudience ||
		manifest.Purpose != ArtifactManifestPurpose || !validCanonicalUUID(manifest.ArtifactID) ||
		!upgradeGrantCodePattern.MatchString(manifest.Component) || !validCanonicalSemver(manifest.Version) ||
		manifest.ProtocolMin < 1 || manifest.ProtocolMax < manifest.ProtocolMin ||
		manifest.DigestAlgorithm != "sha256" || err != nil || len(digest) != 32 ||
		!validUpgradeDownloadURL(manifest.DownloadURL) {
		return ErrInvalidArtifactManifest
	}
	return nil
}

func (manifest ArtifactManifestV2) Validate() error {
	digest, err := base64.RawURLEncoding.DecodeString(manifest.SHA256Digest)
	v3 := manifest.Schema == ArtifactManifestV3Schema
	if (manifest.Schema != ArtifactManifestV2Schema && !v3) || manifest.Audience != ArtifactManifestAudience ||
		manifest.Purpose != ArtifactManifestPurpose || !validCanonicalUUID(manifest.ArtifactID) ||
		!upgradeGrantCodePattern.MatchString(manifest.Component) || !validCanonicalSemver(manifest.Version) ||
		manifest.ProtocolMin < 1 || manifest.ProtocolMax < manifest.ProtocolMin ||
		manifest.ArtifactSizeBytes < 1 || manifest.ArtifactSizeBytes > MaxUpgradeArtifactBytes ||
		manifest.DigestAlgorithm != "sha256" || err != nil || len(digest) != 32 ||
		!validUpgradeDownloadURL(manifest.DownloadURL) {
		return ErrInvalidArtifactManifest
	}
	if (v3 && manifest.ReleaseSequence == 0) || (!v3 && manifest.ReleaseSequence != 0) {
		return ErrInvalidArtifactManifest
	}
	return nil
}

func (grant UpgradeCommandGrant) Validate() error {
	parentDigest, parentErr := base64.RawURLEncoding.DecodeString(grant.ParentGrantSHA256)
	artifactSignature, signatureErr := base64.RawURLEncoding.DecodeString(grant.ArtifactManifestSignature)
	if (grant.Schema != UpgradeCommandGrantSchema && grant.Schema != UpgradeCommandGrantV2Schema &&
		grant.Schema != UpgradeCommandGrantV3Schema) ||
		grant.Audience != UpgradeCommandGrantAudience ||
		grant.Purpose != UpgradeCommandGrantPurpose || !validCanonicalUUID(grant.CommandID) ||
		!validCanonicalUUID(grant.Nonce) || !validCanonicalUUID(grant.ParentGrantID) ||
		parentErr != nil || len(parentDigest) != 32 || grant.ParentGrantIssuedAt <= 0 ||
		grant.ParentGrantExpiresAt <= grant.ParentGrantIssuedAt || !validCanonicalUUID(grant.CustomerID) ||
		!validCanonicalUUID(grant.InstallationID) || !validCanonicalUUID(grant.LicenseID) ||
		!validCanonicalUUID(grant.NodeID) || !upgradeGrantCodePattern.MatchString(grant.Channel) ||
		grant.ChannelRevision == 0 || !upgradeGrantCodePattern.MatchString(grant.Component) ||
		!validCanonicalSemver(grant.CurrentVersion) || !validCanonicalSemver(grant.Version) ||
		grant.Operation != upgradeOperation(grant.CurrentVersion, grant.Version) ||
		(grant.Operation != UpgradeOperation && grant.Operation != RollbackOperation) ||
		grant.ProtocolVersion < 1 || !validCanonicalUUID(grant.ArtifactID) ||
		grant.ArtifactProtocolMin < 1 || grant.ArtifactProtocolMax < grant.ArtifactProtocolMin ||
		grant.ProtocolVersion < grant.ArtifactProtocolMin || grant.ProtocolVersion > grant.ArtifactProtocolMax ||
		grant.ArtifactSizeBytes < 1 || grant.ArtifactSizeBytes > MaxUpgradeArtifactBytes ||
		grant.ArtifactSignatureAlgorithm != Algorithm || ValidateKeyID(grant.ArtifactSignatureKeyID) != nil ||
		signatureErr != nil || len(artifactSignature) != ed25519.SignatureSize ||
		grant.IssuedAt < grant.ParentGrantIssuedAt || grant.NotBefore < grant.IssuedAt ||
		grant.ExpiresAt <= grant.NotBefore || grant.ExpiresAt-grant.IssuedAt > maxUpgradeGrantLifetimeSeconds {
		return ErrInvalidUpgradeCommandGrant
	}
	provenance := grant.Schema == UpgradeCommandGrantV2Schema || grant.Schema == UpgradeCommandGrantV3Schema
	v3 := grant.Schema == UpgradeCommandGrantV3Schema
	if !provenance && (grant.PlanID != "" || grant.PlanRevision != 0 || grant.BatchID != "" ||
		grant.ArtifactBundleID != "" || grant.ArtifactBundleSHA256 != "" || grant.CommandIssuanceNotAfter != 0 ||
		grant.IssuedAt >= grant.ParentGrantExpiresAt || grant.ExpiresAt > grant.ParentGrantExpiresAt) {
		return ErrInvalidUpgradeCommandGrant
	}
	if (v3 && (grant.ExecutionSequence == 0 || grant.ReleaseSequence == 0)) ||
		(!v3 && (grant.ExecutionSequence != 0 || grant.ReleaseSequence != 0)) {
		return ErrInvalidUpgradeCommandGrant
	}
	bundleDigest, bundleErr := base64.RawURLEncoding.DecodeString(grant.ArtifactBundleSHA256)
	if provenance && (!validCanonicalUUID(grant.PlanID) || grant.PlanRevision == 0 ||
		grant.PlanRevision > MaxUpgradePlanRevision || !validCanonicalUUID(grant.BatchID) ||
		!validCanonicalUUID(grant.ArtifactBundleID) || bundleErr != nil || len(bundleDigest) != 32 ||
		grant.CommandIssuanceNotAfter <= grant.ParentGrantIssuedAt || grant.IssuedAt >= grant.CommandIssuanceNotAfter ||
		grant.ExpiresAt > grant.CommandIssuanceNotAfter) {
		return ErrInvalidUpgradeCommandGrant
	}
	if err := artifactManifestV2FromCommandGrant(grant).Validate(); err != nil {
		return ErrInvalidUpgradeCommandGrant
	}
	executionSchema, grantDigest, grantExpiresAt := UpgradeExecutionSchema, grant.ParentGrantSHA256, grant.ParentGrantExpiresAt
	if provenance {
		executionSchema, grantDigest, grantExpiresAt = UpgradeExecutionV2Schema, grant.ArtifactBundleSHA256, grant.ExpiresAt
	}
	if v3 {
		executionSchema = UpgradeExecutionV3Schema
	}
	execution := UpgradeExecution{Schema: executionSchema, Audience: UpgradeExecutionAudience,
		Purpose: UpgradeExecutionPurpose, Action: UpgradeExecutionAction, GrantDigestAlgorithm: "sha256",
		GrantDigest: grantDigest, GrantExpiresAt: grantExpiresAt,
		InstallationID: grant.InstallationID, NodeID: grant.NodeID, CommandID: grant.CommandID, Nonce: grant.Nonce,
		PlanID: grant.PlanID, PlanRevision: grant.PlanRevision, BatchID: grant.BatchID,
		ArtifactBundleID: grant.ArtifactBundleID, ArtifactBundleSHA256: grant.ArtifactBundleSHA256,
		CommandIssuanceNotAfter: grant.CommandIssuanceNotAfter,
		ExecutionSequence:       grant.ExecutionSequence, ReleaseSequence: grant.ChannelRevision,
		Component: grant.Component, Operation: grant.Operation,
		CurrentVersion: grant.CurrentVersion, TargetVersion: grant.Version, ArtifactID: grant.ArtifactID,
		DigestAlgorithm: grant.DigestAlgorithm, SHA256Digest: grant.SHA256Digest, DownloadURL: grant.DownloadURL,
		ArtifactSizeBytes: grant.ArtifactSizeBytes, Platform: grant.Platform, Architecture: grant.Architecture,
		Compatibility: grant.Compatibility, Health: grant.Health, Rollout: grant.Rollout, Rollback: grant.Rollback,
		IssuedAt: grant.IssuedAt, NotBefore: grant.NotBefore, ExpiresAt: grant.ExpiresAt}
	if v3 {
		execution.ReleaseSequence = grant.ReleaseSequence
	}
	if execution.Validate() != nil {
		return ErrInvalidUpgradeCommandGrant
	}
	return nil
}

func (grant UpgradeGrant) Validate() error {
	digest, digestErr := base64.RawURLEncoding.DecodeString(grant.SHA256Digest)
	artifactSignature, signatureErr := base64.RawURLEncoding.DecodeString(grant.ArtifactManifestSignature)
	if grant.Schema != UpgradeGrantSchema || grant.Audience != UpgradeGrantAudience || grant.Purpose != UpgradeGrantPurpose ||
		!validCanonicalUUID(grant.GrantID) || !validCanonicalUUID(grant.Nonce) ||
		!validCanonicalUUID(grant.CustomerID) || !validCanonicalUUID(grant.InstallationID) ||
		!validCanonicalUUID(grant.LicenseID) || !validCanonicalUUID(grant.ArtifactID) ||
		!upgradeGrantCodePattern.MatchString(grant.Channel) || !upgradeGrantCodePattern.MatchString(grant.Component) ||
		grant.ChannelRevision == 0 || !validCanonicalSemver(grant.CurrentVersion) || !validCanonicalSemver(grant.Version) ||
		grant.Operation != upgradeOperation(grant.CurrentVersion, grant.Version) || grant.ProtocolVersion < 1 ||
		grant.ArtifactProtocolMin < 1 || grant.ArtifactProtocolMax < grant.ArtifactProtocolMin ||
		grant.ProtocolVersion < grant.ArtifactProtocolMin || grant.ProtocolVersion > grant.ArtifactProtocolMax ||
		grant.DigestAlgorithm != "sha256" || digestErr != nil || len(digest) != 32 ||
		!validUpgradeDownloadURL(grant.DownloadURL) || grant.ArtifactSignatureAlgorithm != Algorithm ||
		ValidateKeyID(grant.ArtifactSignatureKeyID) != nil || signatureErr != nil ||
		len(artifactSignature) != ed25519.SignatureSize || grant.IssuedAt <= 0 || grant.ExpiresAt <= grant.IssuedAt ||
		grant.ExpiresAt-grant.IssuedAt > maxUpgradeGrantLifetimeSeconds {
		return ErrInvalidUpgradeGrant
	}
	if err := artifactManifestFromGrant(grant).Validate(); err != nil {
		return ErrInvalidUpgradeGrant
	}
	return nil
}

func SignArtifactManifest(ctx context.Context, manifest ArtifactManifest, signer Signer) ([]byte, error) {
	if signer == nil || ValidateKeyID(signer.KeyID()) != nil || manifest.Validate() != nil {
		return nil, ErrInvalidArtifactManifest
	}
	payload, err := artifactManifestSigningBytes(manifest)
	if err != nil {
		return nil, err
	}
	signature, err := signer.Sign(ctx, payload)
	if err != nil {
		return nil, err
	}
	if len(signature) != ed25519.SignatureSize {
		return nil, ErrInvalidArtifactManifestSignature
	}
	return append([]byte(nil), signature...), nil
}

func VerifyArtifactManifestSignature(manifest ArtifactManifest, publicKey ed25519.PublicKey, signature []byte) error {
	if manifest.Validate() != nil {
		return ErrInvalidArtifactManifest
	}
	if ValidateEd25519PublicKey(publicKey) != nil || len(signature) != ed25519.SignatureSize {
		return ErrInvalidArtifactManifestSignature
	}
	payload, err := artifactManifestSigningBytes(manifest)
	if err != nil || !ed25519.Verify(publicKey, payload, signature) {
		return ErrInvalidArtifactManifestSignature
	}
	return nil
}

func SignArtifactManifestV2(ctx context.Context, manifest ArtifactManifestV2, signer Signer) ([]byte, error) {
	if signer == nil || ValidateKeyID(signer.KeyID()) != nil || manifest.Schema != ArtifactManifestV2Schema || manifest.Validate() != nil {
		return nil, ErrInvalidArtifactManifest
	}
	payload, err := json.Marshal(artifactManifestV2SigningDocument{
		Domain: artifactManifestV2SignatureDomain, Manifest: manifest,
	})
	if err != nil {
		return nil, err
	}
	signature, err := signer.Sign(ctx, payload)
	if err != nil {
		return nil, err
	}
	if len(signature) != ed25519.SignatureSize {
		return nil, ErrInvalidArtifactManifestSignature
	}
	return append([]byte(nil), signature...), nil
}

func VerifyArtifactManifestV2Signature(manifest ArtifactManifestV2, publicKey ed25519.PublicKey, signature []byte) error {
	if manifest.Schema != ArtifactManifestV2Schema || manifest.Validate() != nil {
		return ErrInvalidArtifactManifest
	}
	if ValidateEd25519PublicKey(publicKey) != nil || len(signature) != ed25519.SignatureSize {
		return ErrInvalidArtifactManifestSignature
	}
	payload, err := json.Marshal(artifactManifestV2SigningDocument{
		Domain: artifactManifestV2SignatureDomain, Manifest: manifest,
	})
	if err != nil || !ed25519.Verify(publicKey, payload, signature) {
		return ErrInvalidArtifactManifestSignature
	}
	return nil
}

func SignArtifactManifestV3(ctx context.Context, manifest ArtifactManifestV2, signer Signer) ([]byte, error) {
	if signer == nil || ValidateKeyID(signer.KeyID()) != nil || manifest.Schema != ArtifactManifestV3Schema || manifest.Validate() != nil {
		return nil, ErrInvalidArtifactManifest
	}
	payload, err := json.Marshal(artifactManifestV2SigningDocument{
		Domain: artifactManifestV3SignatureDomain, Manifest: manifest,
	})
	if err != nil {
		return nil, err
	}
	signature, err := signer.Sign(ctx, payload)
	if err != nil {
		return nil, err
	}
	if len(signature) != ed25519.SignatureSize {
		return nil, ErrInvalidArtifactManifestSignature
	}
	return append([]byte(nil), signature...), nil
}

func VerifyArtifactManifestV3Signature(manifest ArtifactManifestV2, publicKey ed25519.PublicKey, signature []byte) error {
	if manifest.Schema != ArtifactManifestV3Schema || manifest.Validate() != nil {
		return ErrInvalidArtifactManifest
	}
	if ValidateEd25519PublicKey(publicKey) != nil || len(signature) != ed25519.SignatureSize {
		return ErrInvalidArtifactManifestSignature
	}
	payload, err := json.Marshal(artifactManifestV2SigningDocument{
		Domain: artifactManifestV3SignatureDomain, Manifest: manifest,
	})
	if err != nil || !ed25519.Verify(publicKey, payload, signature) {
		return ErrInvalidArtifactManifestSignature
	}
	return nil
}

func SignUpgradeGrant(ctx context.Context, grant UpgradeGrant, signer Signer) (SignedUpgradeGrant, error) {
	if signer == nil || ValidateKeyID(signer.KeyID()) != nil || grant.Validate() != nil {
		return SignedUpgradeGrant{}, ErrInvalidUpgradeGrant
	}
	signed := SignedUpgradeGrant{Algorithm: Algorithm, KeyID: signer.KeyID(), Grant: grant}
	payload, err := signed.signingBytes()
	if err != nil {
		return SignedUpgradeGrant{}, err
	}
	signature, err := signer.Sign(ctx, payload)
	if err != nil {
		return SignedUpgradeGrant{}, err
	}
	if len(signature) != ed25519.SignatureSize {
		return SignedUpgradeGrant{}, ErrInvalidUpgradeGrantSignature
	}
	signed.Signature = base64.RawURLEncoding.EncodeToString(signature)
	return signed, nil
}

func SignUpgradePlanArtifactBundle(ctx context.Context, bundle UpgradePlanArtifactBundle,
	signer Signer) (SignedUpgradePlanArtifactBundle, error) {
	if signer == nil || ValidateKeyID(signer.KeyID()) != nil || bundle.Validate() != nil {
		return SignedUpgradePlanArtifactBundle{}, ErrInvalidUpgradePlanArtifactBundle
	}
	signed := SignedUpgradePlanArtifactBundle{Algorithm: Algorithm, KeyID: signer.KeyID(), Bundle: bundle}
	payload, err := signed.signingBytes()
	if err != nil {
		return SignedUpgradePlanArtifactBundle{}, err
	}
	signature, err := signer.Sign(ctx, payload)
	if err != nil {
		return SignedUpgradePlanArtifactBundle{}, err
	}
	if len(signature) != ed25519.SignatureSize {
		return SignedUpgradePlanArtifactBundle{}, ErrInvalidUpgradePlanArtifactBundleSignature
	}
	signed.Signature = base64.RawURLEncoding.EncodeToString(signature)
	return signed, nil
}

func SignUpgradeCommandGrant(ctx context.Context, grant UpgradeCommandGrant, signer Signer) (SignedUpgradeCommandGrant, error) {
	if signer == nil || ValidateKeyID(signer.KeyID()) != nil || grant.Validate() != nil {
		return SignedUpgradeCommandGrant{}, ErrInvalidUpgradeCommandGrant
	}
	signed := SignedUpgradeCommandGrant{Algorithm: Algorithm, KeyID: signer.KeyID(), Grant: grant}
	payload, err := signed.signingBytes()
	if err != nil {
		return SignedUpgradeCommandGrant{}, err
	}
	signature, err := signer.Sign(ctx, payload)
	if err != nil {
		return SignedUpgradeCommandGrant{}, err
	}
	if len(signature) != ed25519.SignatureSize {
		return SignedUpgradeCommandGrant{}, ErrInvalidUpgradeCommandGrantSignature
	}
	signed.Signature = base64.RawURLEncoding.EncodeToString(signature)
	return signed, nil
}

func (signed SignedUpgradeGrant) Encode() ([]byte, error) {
	if err := signed.validateEnvelope(); err != nil {
		return nil, err
	}
	return json.Marshal(signed)
}

func DecodeUpgradeGrant(encoded []byte) (SignedUpgradeGrant, error) {
	if len(encoded) == 0 || len(encoded) > maxEncodedUpgradeGrantBytes {
		return SignedUpgradeGrant{}, ErrInvalidUpgradeGrantEnvelope
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var signed SignedUpgradeGrant
	if err := decoder.Decode(&signed); err != nil {
		return SignedUpgradeGrant{}, ErrInvalidUpgradeGrantEnvelope
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return SignedUpgradeGrant{}, ErrInvalidUpgradeGrantEnvelope
	}
	canonical, err := json.Marshal(signed)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return SignedUpgradeGrant{}, ErrInvalidUpgradeGrantEnvelope
	}
	if err := signed.validateEnvelope(); err != nil {
		return SignedUpgradeGrant{}, err
	}
	return signed, nil
}

func (signed SignedUpgradePlanArtifactBundle) Encode() ([]byte, error) {
	if err := signed.validateEnvelope(); err != nil {
		return nil, err
	}
	return json.Marshal(signed)
}

func DecodeUpgradePlanArtifactBundle(encoded []byte) (SignedUpgradePlanArtifactBundle, error) {
	if len(encoded) == 0 || len(encoded) > maxEncodedUpgradePlanArtifactBundleBytes || validateUniqueJSON(encoded) != nil {
		return SignedUpgradePlanArtifactBundle{}, ErrInvalidUpgradePlanArtifactBundleEnvelope
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var signed SignedUpgradePlanArtifactBundle
	if err := decoder.Decode(&signed); err != nil {
		return SignedUpgradePlanArtifactBundle{}, ErrInvalidUpgradePlanArtifactBundleEnvelope
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return SignedUpgradePlanArtifactBundle{}, ErrInvalidUpgradePlanArtifactBundleEnvelope
	}
	canonical, err := json.Marshal(signed)
	if err != nil || !bytes.Equal(canonical, encoded) || signed.validateEnvelope() != nil {
		return SignedUpgradePlanArtifactBundle{}, ErrInvalidUpgradePlanArtifactBundleEnvelope
	}
	return signed, nil
}

func (signed SignedUpgradeCommandGrant) Encode() ([]byte, error) {
	if err := signed.validateEnvelope(); err != nil {
		return nil, err
	}
	return json.Marshal(signed)
}

func DecodeUpgradeCommandGrant(encoded []byte) (SignedUpgradeCommandGrant, error) {
	if len(encoded) == 0 || len(encoded) > maxEncodedUpgradeCommandGrantBytes || validateUniqueJSON(encoded) != nil {
		return SignedUpgradeCommandGrant{}, ErrInvalidUpgradeCommandGrantEnvelope
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var signed SignedUpgradeCommandGrant
	if err := decoder.Decode(&signed); err != nil {
		return SignedUpgradeCommandGrant{}, ErrInvalidUpgradeCommandGrantEnvelope
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return SignedUpgradeCommandGrant{}, ErrInvalidUpgradeCommandGrantEnvelope
	}
	canonical, err := json.Marshal(signed)
	if err != nil || !bytes.Equal(canonical, encoded) || signed.validateEnvelope() != nil {
		return SignedUpgradeCommandGrant{}, ErrInvalidUpgradeCommandGrantEnvelope
	}
	return signed, nil
}

func (ring *KeyRing) VerifyUpgradeGrant(signed SignedUpgradeGrant, options UpgradeGrantVerifyOptions) error {
	if err := signed.validateEnvelope(); err != nil {
		return err
	}
	if options.ExpectedAudience == "" || signed.Grant.Audience != options.ExpectedAudience {
		return ErrUpgradeGrantAudienceMismatch
	}
	if options.ExpectedInstallationID == "" || signed.Grant.InstallationID != options.ExpectedInstallationID {
		return ErrUpgradeGrantInstallationMismatch
	}
	now := options.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if notYetValid(now.Unix(), signed.Grant.IssuedAt) {
		return ErrUpgradeGrantNotYetValid
	}
	if now.Unix() >= signed.Grant.ExpiresAt {
		return ErrUpgradeGrantExpired
	}
	if ring == nil {
		return ErrUnknownUpgradeGrantKey
	}
	outerKey, exists := ring.keys[signed.KeyID]
	if !exists {
		return ErrUnknownUpgradeGrantKey
	}
	payload, err := signed.signingBytes()
	if err != nil {
		return err
	}
	outerSignature, _ := base64.RawURLEncoding.DecodeString(signed.Signature)
	if !ed25519.Verify(outerKey, payload, outerSignature) {
		return ErrInvalidUpgradeGrantSignature
	}
	artifactKey, exists := ring.keys[signed.Grant.ArtifactSignatureKeyID]
	if !exists {
		return ErrUnknownUpgradeGrantKey
	}
	artifactSignature, _ := base64.RawURLEncoding.DecodeString(signed.Grant.ArtifactManifestSignature)
	return VerifyArtifactManifestSignature(artifactManifestFromGrant(signed.Grant), artifactKey, artifactSignature)
}

func (ring *KeyRing) VerifyUpgradePlanArtifactBundle(signed SignedUpgradePlanArtifactBundle,
	options UpgradePlanArtifactBundleVerifyOptions) (UpgradePlanArtifactBundle, error) {
	if err := signed.validateEnvelope(); err != nil {
		return UpgradePlanArtifactBundle{}, err
	}
	bundle := signed.Bundle
	if options.ExpectedAudience == "" || bundle.Audience != options.ExpectedAudience ||
		options.ExpectedInstallationID == "" || bundle.InstallationID != options.ExpectedInstallationID ||
		options.ExpectedPlanID == "" || bundle.PlanID != options.ExpectedPlanID ||
		options.ExpectedInitialPlanRevision != 1 || bundle.InitialPlanRevision != options.ExpectedInitialPlanRevision {
		return UpgradePlanArtifactBundle{}, ErrUpgradePlanArtifactBundleTargetMismatch
	}
	now := options.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if notYetValid(now.Unix(), bundle.IssuedAt) {
		return UpgradePlanArtifactBundle{}, ErrUpgradePlanArtifactBundleNotYetValid
	}
	if now.Unix() >= bundle.CommandIssuanceNotAfter {
		return UpgradePlanArtifactBundle{}, ErrUpgradePlanArtifactBundleExpired
	}
	if ring == nil {
		return UpgradePlanArtifactBundle{}, ErrUnknownUpgradePlanArtifactBundleKey
	}
	outerKey, exists := ring.keys[signed.KeyID]
	if !exists {
		return UpgradePlanArtifactBundle{}, ErrUnknownUpgradePlanArtifactBundleKey
	}
	payload, err := signed.signingBytes()
	signature, _ := base64.RawURLEncoding.DecodeString(signed.Signature)
	if err != nil || !ed25519.Verify(outerKey, payload, signature) {
		return UpgradePlanArtifactBundle{}, ErrInvalidUpgradePlanArtifactBundleSignature
	}
	for _, artifact := range []UpgradePlanArtifact{bundle.Forward, bundle.Rollback} {
		key, exists := ring.keys[artifact.SignatureKeyID]
		if !exists {
			return UpgradePlanArtifactBundle{}, ErrUnknownUpgradePlanArtifactBundleKey
		}
		artifactSignature, _ := base64.RawURLEncoding.DecodeString(artifact.ManifestSignature)
		verify := VerifyArtifactManifestV2Signature
		if bundle.Schema == UpgradePlanArtifactBundleV2Schema {
			verify = VerifyArtifactManifestV3Signature
		}
		if verify(artifact.Manifest, key, artifactSignature) != nil {
			return UpgradePlanArtifactBundle{}, ErrInvalidArtifactManifestSignature
		}
	}
	return bundle, nil
}

func (ring *KeyRing) VerifyUpgradeCommandGrant(signed SignedUpgradeCommandGrant,
	options UpgradeCommandGrantVerifyOptions) (UpgradeCommandGrant, error) {
	if err := signed.validateEnvelope(); err != nil {
		return UpgradeCommandGrant{}, err
	}
	grant := signed.Grant
	if options.ExpectedAudience == "" || grant.Audience != options.ExpectedAudience ||
		options.ExpectedInstallationID == "" || grant.InstallationID != options.ExpectedInstallationID ||
		options.ExpectedNodeID == "" || grant.NodeID != options.ExpectedNodeID ||
		options.ExpectedCommandID == "" || grant.CommandID != options.ExpectedCommandID {
		return UpgradeCommandGrant{}, ErrUpgradeCommandGrantTargetMismatch
	}
	if (grant.Schema == UpgradeCommandGrantV2Schema || grant.Schema == UpgradeCommandGrantV3Schema) &&
		(options.ExpectedPlanID == "" || grant.PlanID != options.ExpectedPlanID ||
			options.ExpectedPlanRevision == 0 || grant.PlanRevision != options.ExpectedPlanRevision ||
			options.ExpectedBatchID == "" || grant.BatchID != options.ExpectedBatchID) {
		return UpgradeCommandGrant{}, ErrUpgradeCommandGrantTargetMismatch
	}
	now := options.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if notYetValid(now.Unix(), grant.NotBefore) {
		return UpgradeCommandGrant{}, ErrUpgradeCommandGrantNotYetValid
	}
	if now.Unix() >= grant.ExpiresAt {
		return UpgradeCommandGrant{}, ErrUpgradeCommandGrantExpired
	}
	if ring == nil {
		return UpgradeCommandGrant{}, ErrUnknownUpgradeCommandGrantKey
	}
	outerKey, exists := ring.keys[signed.KeyID]
	if !exists {
		return UpgradeCommandGrant{}, ErrUnknownUpgradeCommandGrantKey
	}
	payload, err := signed.signingBytes()
	signature, _ := base64.RawURLEncoding.DecodeString(signed.Signature)
	if err != nil || !ed25519.Verify(outerKey, payload, signature) {
		return UpgradeCommandGrant{}, ErrInvalidUpgradeCommandGrantSignature
	}
	artifactKey, exists := ring.keys[grant.ArtifactSignatureKeyID]
	if !exists {
		return UpgradeCommandGrant{}, ErrUnknownUpgradeCommandGrantKey
	}
	artifactSignature, _ := base64.RawURLEncoding.DecodeString(grant.ArtifactManifestSignature)
	verify := VerifyArtifactManifestV2Signature
	if grant.Schema == UpgradeCommandGrantV3Schema {
		verify = VerifyArtifactManifestV3Signature
	}
	if verify(artifactManifestV2FromCommandGrant(grant), artifactKey, artifactSignature) != nil {
		return UpgradeCommandGrant{}, ErrInvalidArtifactManifestSignature
	}
	return grant, nil
}

func (signed SignedUpgradeGrant) validateEnvelope() error {
	if signed.Algorithm != Algorithm || ValidateKeyID(signed.KeyID) != nil || signed.Grant.Validate() != nil {
		return ErrInvalidUpgradeGrantEnvelope
	}
	signature, err := base64.RawURLEncoding.DecodeString(signed.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return ErrInvalidUpgradeGrantEnvelope
	}
	return nil
}

func (signed SignedUpgradeGrant) signingBytes() ([]byte, error) {
	return json.Marshal(upgradeGrantSigningDocument{Domain: upgradeGrantSignatureDomain,
		Algorithm: signed.Algorithm, KeyID: signed.KeyID, Grant: signed.Grant})
}

func (signed SignedUpgradePlanArtifactBundle) validateEnvelope() error {
	if signed.Algorithm != Algorithm || ValidateKeyID(signed.KeyID) != nil || signed.Bundle.Validate() != nil {
		return ErrInvalidUpgradePlanArtifactBundleEnvelope
	}
	signature, err := base64.RawURLEncoding.DecodeString(signed.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return ErrInvalidUpgradePlanArtifactBundleEnvelope
	}
	return nil
}

func (signed SignedUpgradePlanArtifactBundle) signingBytes() ([]byte, error) {
	domain := upgradePlanArtifactBundleSignatureDomain
	if signed.Bundle.Schema == UpgradePlanArtifactBundleV2Schema {
		domain = upgradePlanArtifactBundleV2SignatureDomain
	}
	return json.Marshal(upgradePlanArtifactBundleSigningDocument{Domain: domain,
		Algorithm: signed.Algorithm, KeyID: signed.KeyID, Bundle: signed.Bundle})
}

func (signed SignedUpgradeCommandGrant) validateEnvelope() error {
	if signed.Algorithm != Algorithm || ValidateKeyID(signed.KeyID) != nil || signed.Grant.Validate() != nil {
		return ErrInvalidUpgradeCommandGrantEnvelope
	}
	signature, err := base64.RawURLEncoding.DecodeString(signed.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return ErrInvalidUpgradeCommandGrantEnvelope
	}
	return nil
}

func (signed SignedUpgradeCommandGrant) signingBytes() ([]byte, error) {
	domain := upgradeCommandGrantSignatureDomain
	if signed.Grant.Schema == UpgradeCommandGrantV2Schema {
		domain = upgradeCommandGrantV2SignatureDomain
	} else if signed.Grant.Schema == UpgradeCommandGrantV3Schema {
		domain = upgradeCommandGrantV3SignatureDomain
	}
	return json.Marshal(upgradeCommandGrantSigningDocument{Domain: domain,
		Algorithm: signed.Algorithm, KeyID: signed.KeyID, Grant: signed.Grant})
}

func artifactManifestSigningBytes(manifest ArtifactManifest) ([]byte, error) {
	return json.Marshal(artifactManifestSigningDocument{Domain: artifactManifestSignatureDomain, Manifest: manifest})
}

func artifactManifestFromGrant(grant UpgradeGrant) ArtifactManifest {
	return ArtifactManifest{Schema: ArtifactManifestSchema, Audience: ArtifactManifestAudience,
		Purpose: ArtifactManifestPurpose, ArtifactID: grant.ArtifactID, Component: grant.Component,
		Version: grant.Version, ProtocolMin: grant.ArtifactProtocolMin, ProtocolMax: grant.ArtifactProtocolMax,
		DigestAlgorithm: grant.DigestAlgorithm, SHA256Digest: grant.SHA256Digest, DownloadURL: grant.DownloadURL}
}

func artifactManifestV2FromCommandGrant(grant UpgradeCommandGrant) ArtifactManifestV2 {
	schema := ArtifactManifestV2Schema
	if grant.Schema == UpgradeCommandGrantV3Schema {
		schema = ArtifactManifestV3Schema
	}
	return ArtifactManifestV2{Schema: schema, Audience: ArtifactManifestAudience,
		Purpose: ArtifactManifestPurpose, ArtifactID: grant.ArtifactID, Component: grant.Component,
		Version: grant.Version, ProtocolMin: grant.ArtifactProtocolMin, ProtocolMax: grant.ArtifactProtocolMax,
		ArtifactSizeBytes: grant.ArtifactSizeBytes, ReleaseSequence: grant.ReleaseSequence,
		DigestAlgorithm: grant.DigestAlgorithm,
		SHA256Digest:    grant.SHA256Digest, DownloadURL: grant.DownloadURL}
}

func upgradeOperation(currentVersion, targetVersion string) string {
	switch semver.Compare("v"+targetVersion, "v"+currentVersion) {
	case -1:
		return RollbackOperation
	case 0:
		return ReinstallOperation
	default:
		return UpgradeOperation
	}
}

func validCanonicalSemver(value string) bool {
	if value == "" || strings.Contains(value, "+") {
		return false
	}
	prefixed := "v" + value
	return semver.IsValid(prefixed) && semver.Canonical(prefixed) == prefixed
}

func validUpgradeDownloadURL(value string) bool {
	if len(value) < 9 || len(value) > 4096 || strings.TrimSpace(value) != value {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.Host == strings.ToLower(parsed.Host) &&
		parsed.User == nil && parsed.Fragment == "" && parsed.Opaque == "" && parsed.String() == value
}
