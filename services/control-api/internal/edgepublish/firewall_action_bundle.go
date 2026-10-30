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
	"sort"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/firewallactioncontrol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const siteRuntimeV2FirewallActionPrefix = "firewall-action/"

const loadFirewallActionFactsSQL = `
		SELECT head.site_id,head.id,revision.revision,revision.document_bytes,revision.document_sha256
		FROM firewall_action_policy_heads head
		JOIN firewall_action_policy_revisions revision
		  ON revision.tenant_scope_id=head.tenant_scope_id AND revision.site_id=head.site_id
		 AND revision.policy_id=head.id
		 AND revision.revision=CASE WHEN head.deployment_state='pending' THEN head.revision ELSE head.lkg_revision END
		WHERE head.tenant_scope_id=$1 AND head.site_id=ANY($2::uuid[])
		  AND (head.deployment_state='pending' OR head.lkg_revision>0)
		ORDER BY head.site_id`

type siteRuntimeV2FirewallActionBinding struct {
	PolicyID       string `json:"policy_id"`
	PolicyRevision int64  `json:"policy_revision"`
	DocumentSHA256 string `json:"document_sha256"`
	ArtifactPath   string `json:"artifact_path"`
}

type firewallActionFact struct {
	siteID, policyID uuid.UUID
	revision         int64
	document         []byte
	digest           [sha256.Size]byte
}

func loadFirewallActionFacts(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, sites []siteRuntimeV2Site) ([]firewallActionFact, error) {
	siteIDs := make([]uuid.UUID, len(sites))
	for index, site := range sites {
		parsed, err := uuid.Parse(site.ID)
		if err != nil || parsed == uuid.Nil || parsed.String() != site.ID {
			return nil, ErrInvalidInput
		}
		siteIDs[index] = parsed
	}
	rows, err := tx.Query(ctx, loadFirewallActionFactsSQL, scopeID, siteIDs)
	if err != nil {
		return nil, fmt.Errorf("%w: load firewall action facts", ErrPersistence)
	}
	defer rows.Close()
	result := make([]firewallActionFact, 0, len(siteIDs))
	for rows.Next() {
		var fact firewallActionFact
		var digest []byte
		if err := rows.Scan(&fact.siteID, &fact.policyID, &fact.revision, &fact.document, &digest); err != nil ||
			len(digest) != sha256.Size {
			return nil, fmt.Errorf("%w: scan firewall action fact", ErrPersistence)
		}
		copy(fact.digest[:], digest)
		result = append(result, fact)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: iterate firewall action facts", ErrPersistence)
	}
	return result, nil
}

func compileFirewallActionArtifacts(scopeID uuid.UUID, document *siteRuntimeV2Document, facts []firewallActionFact) (map[string][]byte, error) {
	if scopeID == uuid.Nil || document == nil || document.ConfigurationScopeID != scopeID.String() {
		return nil, ErrInvalidInput
	}
	sites := make(map[uuid.UUID]*siteRuntimeV2Site, len(document.Sites))
	for index := range document.Sites {
		siteID, err := uuid.Parse(document.Sites[index].ID)
		if err != nil || siteID == uuid.Nil || document.Sites[index].FirewallAction != nil {
			return nil, ErrInvalidInput
		}
		sites[siteID] = &document.Sites[index]
	}
	artifacts := make(map[string][]byte, len(facts))
	for _, fact := range facts {
		site := sites[fact.siteID]
		if site == nil || fact.policyID == uuid.Nil || fact.revision < 1 || sha256.Sum256(fact.document) != fact.digest {
			return nil, ErrPersistence
		}
		policy, err := decodeFirewallActionDocument(fact.document)
		if err != nil || policy.TenantID != scopeID.String() || policy.SiteID != fact.siteID.String() ||
			policy.PolicyID != fact.policyID.String() || policy.PolicyVersion != uint64(fact.revision) {
			return nil, ErrPersistence
		}
		path := firewallActionArtifactPath(fact.siteID)
		if _, duplicate := artifacts[path]; duplicate {
			return nil, ErrPersistence
		}
		site.FirewallAction = &siteRuntimeV2FirewallActionBinding{
			PolicyID: fact.policyID.String(), PolicyRevision: fact.revision,
			DocumentSHA256: hex.EncodeToString(fact.digest[:]), ArtifactPath: path,
		}
		artifacts[path] = bytes.Clone(fact.document)
	}
	if len(artifacts) != 0 {
		for index := range document.RequiredCapabilities {
			capability := &document.RequiredCapabilities[index]
			if capability.Name != "site_runtime" {
				continue
			}
			if capability.APIVersion < edgeconfig.MinSiteRuntimeVersion {
				return nil, ErrInvalidInput
			}
			return artifacts, nil
		}
		return nil, ErrInvalidInput
	}
	return artifacts, nil
}

func validateSiteRuntimeV2FirewallActionArtifacts(canonical []byte, artifacts map[string][]byte) error {
	var document siteRuntimeV2Document
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		if len(artifacts) == 0 {
			return nil
		}
		return ErrInvalidInput
	}
	wanted := make(map[string]siteRuntimeV2FirewallActionBinding)
	for _, site := range document.Sites {
		binding := site.FirewallAction
		if binding == nil {
			continue
		}
		if !validFirewallActionArtifactPath(site.ID, binding.ArtifactPath) {
			return ErrInvalidInput
		}
		if _, duplicate := wanted[binding.ArtifactPath]; duplicate {
			return ErrInvalidInput
		}
		wanted[binding.ArtifactPath] = *binding
	}
	if len(wanted) != len(artifacts) {
		return ErrInvalidInput
	}
	paths := make([]string, 0, len(artifacts))
	for path := range artifacts {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		binding, exists := wanted[path]
		if !exists {
			return ErrInvalidInput
		}
		raw := artifacts[path]
		digest := sha256.Sum256(raw)
		if hex.EncodeToString(digest[:]) != binding.DocumentSHA256 {
			return ErrInvalidInput
		}
		policy, err := decodeFirewallActionDocument(raw)
		if err != nil || policy.TenantID != document.ConfigurationScopeID ||
			policy.SiteID != path[len(siteRuntimeV2FirewallActionPrefix):len(path)-len(".json")] ||
			policy.PolicyID != binding.PolicyID || policy.PolicyVersion != uint64(binding.PolicyRevision) {
			return ErrInvalidInput
		}
	}
	return nil
}

func decodeFirewallActionDocument(raw []byte) (firewallactioncontrol.EdgePolicy, error) {
	if len(raw) == 0 || len(raw) > 1<<20 || edgeconfig.RejectDuplicateJSONKeys(raw) != nil {
		return firewallactioncontrol.EdgePolicy{}, errors.New("invalid firewall action document")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var policy firewallactioncontrol.EdgePolicy
	if err := decoder.Decode(&policy); err != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		policy.SchemaVersion != firewallactioncontrol.SchemaVersion || policy.PolicyVersion == 0 {
		return firewallactioncontrol.EdgePolicy{}, errors.New("invalid firewall action document")
	}
	canonical, err := json.Marshal(policy)
	if err != nil || !bytes.Equal(canonical, raw) {
		return firewallactioncontrol.EdgePolicy{}, errors.New("noncanonical firewall action document")
	}
	return policy, nil
}

func firewallActionArtifactPath(siteID uuid.UUID) string {
	return siteRuntimeV2FirewallActionPrefix + siteID.String() + ".json"
}

func validFirewallActionArtifactPath(siteID, path string) bool {
	return path == siteRuntimeV2FirewallActionPrefix+siteID+".json"
}
