package edgepublish

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/sitecapture"
	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type snapshotCapturePolicy struct {
	Revision       int64                      `json:"revision"`
	EvidenceDigest string                     `json:"evidence_digest"`
	Document       sitecapture.PolicyDocument `json:"document"`
}

type siteCapturePolicyFact struct {
	revision       int64
	evidenceDigest string
	document       sitecapture.PolicyDocument
}

func loadSiteCapturePolicyFacts(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) (map[uuid.UUID]*siteCapturePolicyFact, error) {
	rows, err := tx.Query(ctx, `
		SELECT head.site_id,revision.revision,revision.document_bytes,revision.document_sha256
		FROM site_capture_policy_heads AS head
		JOIN site_capture_policy_revisions AS revision
		  ON revision.scope_id=head.scope_id AND revision.site_id=head.site_id
		 AND revision.revision=head.current_revision
		WHERE head.scope_id=$1
		ORDER BY head.site_id
		FOR SHARE OF head,revision`, scopeID)
	if err != nil {
		return nil, fmt.Errorf("%w: read active site capture policies", ErrPersistence)
	}
	defer rows.Close()
	result := make(map[uuid.UUID]*siteCapturePolicyFact)
	for rows.Next() {
		var siteID uuid.UUID
		var revision int64
		var document, digest []byte
		if err := rows.Scan(&siteID, &revision, &document, &digest); err != nil {
			return nil, fmt.Errorf("%w: scan active site capture policy", ErrPersistence)
		}
		fact, err := decodeSiteCapturePolicyFact(siteID, revision, document, digest)
		if err != nil {
			return nil, fmt.Errorf("%w: decode active site capture policy", ErrPersistence)
		}
		if _, duplicate := result[siteID]; duplicate {
			return nil, fmt.Errorf("%w: duplicate active site capture policy", ErrPersistence)
		}
		result[siteID] = fact
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("%w: iterate active site capture policies", ErrPersistence)
	}
	return result, nil
}

func decodeSiteCapturePolicyFact(siteID uuid.UUID, revision int64, raw, digest []byte) (*siteCapturePolicyFact, error) {
	computed := sha256.Sum256(raw)
	if siteID == uuid.Nil || revision < 1 || len(raw) == 0 || len(digest) != sha256.Size || !bytes.Equal(computed[:], digest) {
		return nil, ErrInvalidInput
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document sitecapture.PolicyDocument
	if err := decoder.Decode(&document); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, ErrInvalidInput
	}
	canonical, err := json.Marshal(document)
	if err != nil || !bytes.Equal(canonical, raw) {
		return nil, ErrInvalidInput
	}
	return &siteCapturePolicyFact{
		revision: revision, evidenceDigest: hex.EncodeToString(digest), document: document,
	}, nil
}

func (fact *siteCapturePolicyFact) edgePolicy() edgeconfig.TelemetryCapturePolicy {
	if fact == nil {
		return edgeconfig.TelemetryCapturePolicy{}
	}
	return edgeconfig.TelemetryCapturePolicy{
		SchemaVersion: 1, Revision: uint64(fact.revision), EvidenceDigest: fact.evidenceDigest,
		Enabled: fact.document.Enabled, Methods: cloneCaptureValues(fact.document.Methods),
		URIPrefixes:                cloneCaptureValues(fact.document.URIPrefixes),
		RequestHeaderAllowlist:     cloneCaptureValues(fact.document.RequestHeaderAllowlist),
		ResponseHeaderAllowlist:    cloneCaptureValues(fact.document.ResponseHeaderAllowlist),
		RequestBodyFieldAllowlist:  cloneCaptureValues(fact.document.RequestBodyFieldAllowlist),
		ResponseBodyFieldAllowlist: cloneCaptureValues(fact.document.ResponseBodyFieldAllowlist),
		MaxValueBytes:              fact.document.MaxValueBytes, MaxBodyBytes: fact.document.MaxBodyBytes,
		MaxEventBytes: fact.document.MaxEventBytes,
	}
}

func buildSiteRuntimeV2TelemetryManifest(
	scopeID, tenantID, installationID, configID uuid.UUID,
	sourceRevision int64,
	document siteRuntimeV2Document,
	packageSubscriptions map[uuid.UUID]uuid.UUID,
	capturePolicies map[uuid.UUID]*siteCapturePolicyFact,
	accessLogFields edgeconfig.AccessLogFields,
	stateRoot string,
) ([]byte, error) {
	if scopeID == uuid.Nil || tenantID == uuid.Nil || installationID == uuid.Nil || configID == uuid.Nil || sourceRevision < 1 ||
		document.ConfigurationScopeID != scopeID.String() || document.ConfigVersionID != configID.String() ||
		document.SourceRevision != sourceRevision {
		return nil, ErrInvalidInput
	}
	type entry struct {
		site   edgeconfig.TelemetrySiteIdentity
		policy edgeconfig.TelemetrySiteCapturePolicy
	}
	entries := make([]entry, 0)
	for _, site := range document.Sites {
		siteID, err := uuid.Parse(site.ID)
		// A site's telemetry is keyed on its first (primary) domain; see
		// siteRuntimeV2Domains.
		if err != nil || siteID.String() != site.ID || len(site.Domains) == 0 {
			return nil, ErrInvalidInput
		}
		policy := withPlatformCaptureHeaders(capturePolicies[siteID].edgePolicy(), accessLogFields)
		for _, listener := range site.Listeners {
			if listener.Port < 1 || listener.Port > 65535 {
				return nil, ErrInvalidInput
			}
			port := uint16(listener.Port)
			directory := filepath.Join(stateRoot, "shared", "telemetry", configID.String(), site.ID, strconv.Itoa(int(port)))
			identity := edgeconfig.TelemetrySiteIdentity{
				SiteID: site.ID, Domain: site.Domains[0], ListenPort: port,
				NamespaceID:   edgeconfig.CacheSiteNamespaceID(tenantID.String(), site.ID),
				AccessLogPath: filepath.Join(directory, "access.jsonl"), SecurityLogPath: filepath.Join(directory, "security.jsonl"),
			}
			if subscriptionID := packageSubscriptions[siteID]; subscriptionID != uuid.Nil {
				identity.PackageSubscriptionID = subscriptionID.String()
			}
			entries = append(entries, entry{site: identity, policy: edgeconfig.TelemetrySiteCapturePolicy{
				SiteID: site.ID, Domain: site.Domains[0], ListenPort: port,
				Revision: policy.Revision, EvidenceDigest: policy.EvidenceDigest, Enabled: policy.Enabled,
				Methods: cloneCaptureValues(policy.Methods), URIPrefixes: cloneCaptureValues(policy.URIPrefixes),
				RequestHeaderAllowlist:     cloneCaptureValues(policy.RequestHeaderAllowlist),
				ResponseHeaderAllowlist:    cloneCaptureValues(policy.ResponseHeaderAllowlist),
				RequestBodyFieldAllowlist:  cloneCaptureValues(policy.RequestBodyFieldAllowlist),
				ResponseBodyFieldAllowlist: cloneCaptureValues(policy.ResponseBodyFieldAllowlist),
				MaxValueBytes:              policy.MaxValueBytes, MaxBodyBytes: policy.MaxBodyBytes, MaxEventBytes: policy.MaxEventBytes,
			}})
		}
	}
	if len(entries) == 0 {
		return nil, ErrInvalidInput
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].site.ListenPort != entries[j].site.ListenPort {
			return entries[i].site.ListenPort < entries[j].site.ListenPort
		}
		return entries[i].site.Domain < entries[j].site.Domain
	})
	manifest := edgeconfig.TelemetryIdentityManifest{
		SchemaVersion: 1, ConfigVersionID: configID.String(), ConfigRevision: uint64(sourceRevision), TenantID: tenantID.String(),
		InstallationID:     installationID.String(),
		Sites:              make([]edgeconfig.TelemetrySiteIdentity, len(entries)),
		CapturePolicy:      edgeconfig.TelemetryCapturePolicyManifest{SchemaVersion: 1, Sites: make([]edgeconfig.TelemetrySiteCapturePolicy, len(entries))},
		SourceCapabilities: edgeconfig.TelemetrySourceCapabilities{SchemaVersion: 1},
	}
	for index, item := range entries {
		manifest.Sites[index], manifest.CapturePolicy.Sites[index] = item.site, item.policy
	}
	content, err := json.Marshal(manifest)
	if err != nil {
		return nil, ErrInvalidInput
	}
	content = append(content, '\n')
	parsed, err := edgeconfig.ParseTelemetryIdentityManifest(content)
	if err != nil || edgeconfig.ValidateTelemetryIdentityPaths(parsed, stateRoot) != nil {
		return nil, ErrInvalidInput
	}
	return content, nil
}

func cloneCaptureValues(values []string) []string { return append([]string{}, values...) }

// withPlatformCaptureHeaders adds the request and response headers the
// platform records for every site (system configuration access_log_fields)
// to a site's capture allowlists. A site without an enabled capture policy
// captures them on every request (no method or URI prefix limit); a site's
// own policy keeps its limits, revision and evidence digest.
func withPlatformCaptureHeaders(policy edgeconfig.TelemetryCapturePolicy, fields edgeconfig.AccessLogFields) edgeconfig.TelemetryCapturePolicy {
	request, response := fields.Headers()
	if len(request) == 0 && len(response) == 0 {
		return policy
	}
	if !policy.Enabled {
		policy.SchemaVersion, policy.Enabled = 1, true
		policy.Methods, policy.URIPrefixes = []string{}, []string{}
		policy.RequestHeaderAllowlist, policy.ResponseHeaderAllowlist = []string{}, []string{}
		policy.RequestBodyFieldAllowlist, policy.ResponseBodyFieldAllowlist = []string{}, []string{}
	}
	policy.RequestHeaderAllowlist = edgeconfig.MergeCaptureHeaders(policy.RequestHeaderAllowlist, request)
	policy.ResponseHeaderAllowlist = edgeconfig.MergeCaptureHeaders(policy.ResponseHeaderAllowlist, response)
	return policy
}

// loadAccessLogFields is the access_log_fields a publication applies: the
// system configuration being published, else the active one, else the
// default.
func loadAccessLogFields(ctx context.Context, tx pgx.Tx, source *SystemConfigurationSource) (edgeconfig.AccessLogFields, error) {
	if source != nil {
		return edgeconfig.EffectiveAccessLogFields(source.AccessLogFields), nil
	}
	active, found, err := systemconfig.LoadActiveEdgeNginx(ctx, tx)
	if err != nil {
		return edgeconfig.AccessLogFields{}, fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	if !found {
		return edgeconfig.EffectiveAccessLogFields(nil), nil
	}
	return active.AccessLogFields, nil
}
