package edgepublish

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"

	"github.com/cdnca/cdnca/services/control-api/internal/httppolicycontrol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const siteRuntimeV2HTTPPolicyArtifactPath = "http-policy.v1.json"

type siteRuntimeV2HTTPPolicyBinding struct {
	PolicyID       string `json:"policy_id"`
	PolicyRevision int64  `json:"policy_revision"`
	ArtifactSHA256 string `json:"artifact_sha256"`
}

type httpPolicyRevisionDocument struct {
	SchemaVersion   string    `json:"schema_version"`
	PolicyID        uuid.UUID `json:"policy_id"`
	TenantScopeID   uuid.UUID `json:"tenant_scope_id"`
	SiteID          uuid.UUID `json:"site_id"`
	SiteOwnerUserID uuid.UUID `json:"site_owner_user_id"`
	Revision        int64     `json:"revision"`
	httppolicycontrol.Config
	Enabled bool `json:"enabled"`
	Deleted bool `json:"deleted"`
}

type httpPolicyFact struct {
	tenantScopeID  uuid.UUID
	policyID       uuid.UUID
	siteID         uuid.UUID
	sourceRevision int64
	revision       int64
	document       httpPolicyRevisionDocument
}

func lockHTTPPolicyPublicationFacts(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) error {
	if scopeID == uuid.Nil {
		return ErrInvalidInput
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(
		hashtextextended('http-policy-publication:' || $1::text, 0))`, scopeID); err != nil {
		return fmt.Errorf("%w: lock HTTP policy publication facts", ErrPersistence)
	}
	return nil
}

// loadHTTPPolicyFactsAt reads the facts for a release at sourceRevision while
// the scope is locked at lockedRevision: equal for a publication (which has
// advanced the scope), the active revision for a security activation
// candidate (promotion advances it later).
func loadHTTPPolicyFactsAt(
	ctx context.Context,
	tx pgx.Tx,
	scopeID uuid.UUID,
	lockedRevision, sourceRevision int64,
	sites []siteRuntimeV2Site,
) (uint64, []httpPolicyFact, error) {
	if scopeID == uuid.Nil || sourceRevision < 1 || sourceRevision > maxSiteRuntimeV2SafeInteger || len(sites) > maxSiteRuntimeV2Sites ||
		lockedRevision < 1 || lockedRevision > sourceRevision {
		return 0, nil, ErrInvalidInput
	}
	if len(sites) == 0 {
		return 0, nil, nil
	}
	for index, site := range sites {
		value, err := uuid.Parse(site.ID)
		if err != nil || value == uuid.Nil || value.String() != site.ID || site.Revision < 1 ||
			site.Revision > maxSiteRuntimeV2SafeInteger {
			return 0, nil, ErrInvalidInput
		}
		if index > 0 && sites[index-1].ID >= site.ID {
			return 0, nil, ErrInvalidInput
		}
	}

	var lockedSourceRevision int64
	if err := tx.QueryRow(ctx, `SELECT source_revision FROM edge_configuration_scopes
		WHERE scope_id=$1 FOR SHARE`, scopeID).Scan(&lockedSourceRevision); errors.Is(err, pgx.ErrNoRows) {
		return 0, nil, ErrInvalidInput
	} else if err != nil {
		return 0, nil, fmt.Errorf("%w: read HTTP policy edge source revision", ErrPersistence)
	} else if lockedSourceRevision != lockedRevision {
		return 0, nil, ErrRevisionConflict
	}

	var publicationRevision int64
	err := tx.QueryRow(ctx, `SELECT revision FROM http_policy_publication_heads
		WHERE tenant_scope_id=$1 FOR SHARE`, scopeID).Scan(&publicationRevision)
	if errors.Is(err, pgx.ErrNoRows) {
		var policies int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM http_policies WHERE tenant_scope_id=$1`, scopeID).Scan(&policies); err != nil {
			return 0, nil, fmt.Errorf("%w: verify absent HTTP policy publication head", ErrPersistence)
		}
		if policies != 0 {
			return 0, nil, fmt.Errorf("%w: HTTP policies exist without a publication head", ErrPersistence)
		}
		return 0, nil, nil
	}
	if err != nil || publicationRevision < 1 || publicationRevision > httppolicycontrol.MaxPolicyVersion {
		return 0, nil, fmt.Errorf("%w: read HTTP policy publication head", ErrPersistence)
	}

	var expected int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM http_policies
		WHERE tenant_scope_id=$1 AND current_enabled=true AND current_deleted=false
		  AND deleted_at IS NULL`, scopeID).Scan(&expected); err != nil {
		return 0, nil, fmt.Errorf("%w: count enabled HTTP policy facts", ErrPersistence)
	}
	if expected > len(sites) || expected > httppolicycontrol.MaxSites {
		return 0, nil, fmt.Errorf("%w: enabled HTTP policy site is absent from the source revision", ErrPersistence)
	}
	rows, err := tx.Query(ctx, `SELECT policy.id,policy.tenant_scope_id,policy.site_id,
		policy.current_revision,policy.current_document,revision.document
		FROM http_policies policy
		JOIN http_policy_revisions revision
		  ON revision.policy_id=policy.id AND revision.tenant_scope_id=policy.tenant_scope_id
		 AND revision.site_id=policy.site_id AND revision.revision=policy.current_revision
		WHERE policy.tenant_scope_id=$1 AND policy.current_enabled=true AND policy.current_deleted=false
		  AND policy.deleted_at IS NULL
		ORDER BY policy.site_id::text
		FOR SHARE OF policy,revision`, scopeID)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: read enabled HTTP policy facts", ErrPersistence)
	}
	defer rows.Close()
	facts := make([]httpPolicyFact, 0, expected)
	for rows.Next() {
		var fact httpPolicyFact
		var projectionBytes, revisionBytes []byte
		if err := rows.Scan(&fact.policyID, &fact.tenantScopeID, &fact.siteID, &fact.revision,
			&projectionBytes, &revisionBytes); err != nil {
			return 0, nil, fmt.Errorf("%w: scan enabled HTTP policy fact", ErrPersistence)
		}
		projection, err := decodeHTTPPolicyRevisionDocument(projectionBytes)
		if err != nil {
			return 0, nil, fmt.Errorf("%w: decode HTTP policy projection", ErrPersistence)
		}
		revision, err := decodeHTTPPolicyRevisionDocument(revisionBytes)
		if err != nil || !reflect.DeepEqual(projection, revision) {
			return 0, nil, fmt.Errorf("%w: HTTP policy projection revision mismatch", ErrPersistence)
		}
		fact.sourceRevision, fact.document = sourceRevision, projection
		facts = append(facts, fact)
	}
	if rows.Err() != nil {
		return 0, nil, fmt.Errorf("%w: iterate enabled HTTP policy facts", ErrPersistence)
	}
	if len(facts) != expected {
		return 0, nil, fmt.Errorf("%w: enabled HTTP policy revision is missing", ErrPersistence)
	}
	return uint64(publicationRevision), facts, nil
}

func decodeHTTPPolicyRevisionDocument(raw []byte) (httpPolicyRevisionDocument, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document httpPolicyRevisionDocument
	if len(raw) == 0 || len(raw) > httppolicycontrol.MaxPolicyBytes || decoder.Decode(&document) != nil ||
		decoder.Decode(&struct{}{}) != io.EOF {
		return httpPolicyRevisionDocument{}, ErrInvalidInput
	}
	return document, nil
}

func compileHTTPPolicyArtifact(
	scopeID uuid.UUID,
	sourceRevision int64,
	publicationRevision uint64,
	document *siteRuntimeV2Document,
	facts []httpPolicyFact,
) ([]byte, [sha256.Size]byte, error) {
	if scopeID == uuid.Nil || sourceRevision < 1 || sourceRevision > maxSiteRuntimeV2SafeInteger || document == nil ||
		document.ConfigurationScopeID != scopeID.String() || document.SourceRevision != sourceRevision ||
		document.Sites == nil || len(document.Sites) > maxSiteRuntimeV2Sites ||
		publicationRevision > httppolicycontrol.MaxPolicyVersion || len(facts) > httppolicycontrol.MaxSites {
		return nil, [sha256.Size]byte{}, ErrInvalidInput
	}
	sites := make(map[uuid.UUID]*siteRuntimeV2Site, len(document.Sites))
	for index := range document.Sites {
		site := &document.Sites[index]
		siteID, err := uuid.Parse(site.ID)
		if err != nil || siteID == uuid.Nil || siteID.String() != site.ID || site.HTTPPolicy != nil {
			return nil, [sha256.Size]byte{}, ErrInvalidInput
		}
		sites[siteID] = site
	}
	if len(facts) == 0 {
		return nil, [sha256.Size]byte{}, nil
	}
	if publicationRevision == 0 {
		return nil, [sha256.Size]byte{}, ErrPersistence
	}
	values := append([]httpPolicyFact(nil), facts...)
	sort.Slice(values, func(i, j int) bool { return values[i].siteID.String() < values[j].siteID.String() })
	edgeSites := make([]httppolicycontrol.EdgeSitePolicy, len(values))
	for index, fact := range values {
		if fact.tenantScopeID != scopeID || fact.policyID == uuid.Nil || fact.siteID == uuid.Nil ||
			fact.sourceRevision != sourceRevision || fact.revision < 1 || fact.revision > maxSiteRuntimeV2SafeInteger ||
			fact.document.SchemaVersion != httppolicycontrol.DocumentSchema || fact.document.PolicyID != fact.policyID ||
			fact.document.TenantScopeID != fact.tenantScopeID || fact.document.SiteID != fact.siteID ||
			fact.document.SiteOwnerUserID == uuid.Nil || fact.document.Revision != fact.revision ||
			!fact.document.Enabled || fact.document.Deleted || index > 0 && values[index-1].siteID == fact.siteID {
			return nil, [sha256.Size]byte{}, fmt.Errorf("%w: invalid HTTP policy source fact", ErrPersistence)
		}
		if sites[fact.siteID] == nil {
			return nil, [sha256.Size]byte{}, fmt.Errorf("%w: HTTP policy site is absent from the source revision", ErrPersistence)
		}
		edgeSites[index] = fact.document.edgeSite()
	}
	snapshot := httppolicycontrol.EdgeSnapshot{
		SchemaVersion: httppolicycontrol.EdgeSchemaVersion,
		PolicyVersion: publicationRevision,
		Sites:         edgeSites,
	}
	artifact, err := json.Marshal(snapshot)
	if err != nil {
		return nil, [sha256.Size]byte{}, ErrInvalidInput
	}
	artifact = append(artifact, '\n')
	if len(artifact) > httppolicycontrol.MaxPolicyBytes {
		return nil, [sha256.Size]byte{}, ErrInvalidInput
	}
	digest := sha256.Sum256(artifact)
	encodedDigest := hex.EncodeToString(digest[:])
	for _, fact := range values {
		sites[fact.siteID].HTTPPolicy = &siteRuntimeV2HTTPPolicyBinding{
			PolicyID: fact.policyID.String(), PolicyRevision: fact.revision, ArtifactSHA256: encodedDigest,
		}
	}
	return artifact, digest, nil
}

func validateSiteRuntimeV2HTTPPolicyArtifact(canonical, artifact []byte) error {
	var document siteRuntimeV2Document
	if err := json.Unmarshal(canonical, &document); err != nil {
		return ErrInvalidInput
	}
	bindings := make(map[string]*siteRuntimeV2HTTPPolicyBinding)
	for index := range document.Sites {
		if binding := document.Sites[index].HTTPPolicy; binding != nil {
			bindings[document.Sites[index].ID] = binding
		}
	}
	if len(bindings) == 0 {
		if len(artifact) != 0 {
			return ErrInvalidInput
		}
		return nil
	}
	compiled, _, _, _, err := compileSiteRuntimeV2Document(canonical)
	if err != nil || !bytes.Equal(compiled, canonical) {
		return ErrInvalidInput
	}
	if len(artifact) == 0 || len(artifact) > httppolicycontrol.MaxPolicyBytes {
		return ErrInvalidInput
	}
	decoder := json.NewDecoder(bytes.NewReader(artifact))
	decoder.DisallowUnknownFields()
	var snapshot httppolicycontrol.EdgeSnapshot
	if decoder.Decode(&snapshot) != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		snapshot.SchemaVersion != httppolicycontrol.EdgeSchemaVersion || snapshot.PolicyVersion == 0 ||
		snapshot.PolicyVersion > httppolicycontrol.MaxPolicyVersion || len(snapshot.Sites) != len(bindings) {
		return ErrInvalidInput
	}
	canonicalArtifact, err := json.Marshal(snapshot)
	if err != nil {
		return ErrInvalidInput
	}
	canonicalArtifact = append(canonicalArtifact, '\n')
	if !bytes.Equal(canonicalArtifact, artifact) {
		return ErrInvalidInput
	}
	digest := sha256.Sum256(artifact)
	encodedDigest := hex.EncodeToString(digest[:])
	for index, site := range snapshot.Sites {
		binding := bindings[site.SiteID]
		if binding == nil || binding.ArtifactSHA256 != encodedDigest ||
			index > 0 && snapshot.Sites[index-1].SiteID >= site.SiteID {
			return ErrInvalidInput
		}
		delete(bindings, site.SiteID)
	}
	if len(bindings) != 0 {
		return ErrInvalidInput
	}
	return nil
}

func (document httpPolicyRevisionDocument) edgeSite() httppolicycontrol.EdgeSitePolicy {
	return httppolicycontrol.EdgeSitePolicy{
		SiteID: document.SiteID.String(), MaxUploadBytes: document.MaxUploadBytes,
		RequestHeaders:       append([]httppolicycontrol.HeaderAction{}, document.RequestHeaders...),
		ResponseHeaders:      append([]httppolicycontrol.HeaderAction{}, document.ResponseHeaders...),
		Rewrites:             append([]httppolicycontrol.RewriteRule{}, document.Rewrites...),
		RedirectAllowedHosts: append([]string{}, document.RedirectAllowedHosts...),
		Redirects:            append([]httppolicycontrol.RedirectRule{}, document.Redirects...), CORS: cloneHTTPPolicyCORS(document.CORS),
		RefererCheck: cloneHTTPPolicyRefererCheck(document.RefererCheck),
	}
}

func cloneHTTPPolicyRefererCheck(input *httppolicycontrol.RefererCheckPolicy) *httppolicycontrol.RefererCheckPolicy {
	if input == nil {
		return nil
	}
	result := *input
	result.AllowedDomains = append([]string{}, input.AllowedDomains...)
	result.DeniedDomains = append([]string{}, input.DeniedDomains...)
	result.Extensions = append([]string{}, input.Extensions...)
	return &result
}

func cloneHTTPPolicyCORS(input *httppolicycontrol.CORSPolicy) *httppolicycontrol.CORSPolicy {
	if input == nil {
		return nil
	}
	result := *input
	result.AllowedOrigins = append([]string{}, input.AllowedOrigins...)
	result.AllowedMethods = append([]string{}, input.AllowedMethods...)
	result.AllowedHeaders = append([]string{}, input.AllowedHeaders...)
	result.ExposedHeaders = append([]string{}, input.ExposedHeaders...)
	return &result
}

func setSiteRuntimeV2Capability(values []siteRuntimeV2Capability, name string, version uint32) bool {
	for index := range values {
		if values[index].Name == name {
			values[index].APIVersion = max(values[index].APIVersion, version)
			return true
		}
	}
	return false
}
