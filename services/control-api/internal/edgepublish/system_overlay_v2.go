package edgepublish

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// siteRuntimeV2Inputs is a site runtime v2 publication's compiled source as
// edge_publication_compile_inputs.site_runtime_v2 keeps it: non-secret facts
// and references only. Certificates appear as certificate_version_id in the
// document; HTTP policy, firewall action and capture policy as
// (policy, revision, digest) of their immutable revision rows. Nothing of the
// encrypted artifact (plaintext bundle, ciphertext, keys) is kept.
type siteRuntimeV2Inputs struct {
	// Document is the compiled runtime document before the HTTP policy and
	// firewall action bindings (re-derived from the references).
	Document           siteRuntimeV2Document      `json:"document"`
	HTTPPolicyRevision uint64                     `json:"http_policy_revision"`
	HTTPPolicies       []siteRuntimeV2PolicyRef   `json:"http_policies"`
	FirewallActions    []siteRuntimeV2PolicyRef   `json:"firewall_actions"`
	CapturePolicies    []siteRuntimeV2PolicyRef   `json:"capture_policies"`
	OriginRoutes       []siteRuntimeV2OriginRoute `json:"origin_routes"`
	Subscriptions      map[uuid.UUID]uuid.UUID    `json:"subscriptions"`
	Topology           *L2TopologySnapshot        `json:"topology,omitempty"`
	// L2Skipped: sites of a node-list publication left without L2 and why
	// (the publication audit, fix-autol2b); not kept.
	L2Skipped []siteL2PublicationSkip `json:"-"`
}

type siteRuntimeV2PolicyRef struct {
	SiteID   uuid.UUID `json:"site_id"`
	PolicyID uuid.UUID `json:"policy_id,omitempty"`
	Revision int64     `json:"revision"`
	SHA256   string    `json:"sha256,omitempty"`
}

type siteRuntimeV2OriginRoute struct {
	SiteID       uuid.UUID               `json:"site_id"`
	SiteRevision int64                   `json:"site_revision"`
	Document     siteOriginRouteDocument `json:"document"`
}

func captureSiteRuntimeV2Inputs(
	document siteRuntimeV2Document, httpPolicyRevision uint64, httpPolicies []httpPolicyFact,
	firewallActions []firewallActionFact, capturePolicies map[uuid.UUID]*siteCapturePolicyFact,
	originRoutes []siteOriginRouteFact, subscriptions map[uuid.UUID]uuid.UUID, topology *L2TopologySnapshot,
) siteRuntimeV2Inputs {
	inputs := siteRuntimeV2Inputs{Document: document, HTTPPolicyRevision: httpPolicyRevision,
		Subscriptions: map[uuid.UUID]uuid.UUID{}, Topology: topology}
	inputs.Document.Sites = slices.Clone(document.Sites)
	present := map[uuid.UUID]bool{}
	for index := range inputs.Document.Sites {
		inputs.Document.Sites[index].HTTPPolicy, inputs.Document.Sites[index].FirewallAction = nil, nil
		present[uuid.MustParse(inputs.Document.Sites[index].ID)] = true
	}
	for _, fact := range httpPolicies {
		inputs.HTTPPolicies = append(inputs.HTTPPolicies, siteRuntimeV2PolicyRef{SiteID: fact.siteID,
			PolicyID: fact.policyID, Revision: fact.revision})
	}
	for _, fact := range firewallActions {
		inputs.FirewallActions = append(inputs.FirewallActions, siteRuntimeV2PolicyRef{SiteID: fact.siteID,
			PolicyID: fact.policyID, Revision: fact.revision, SHA256: hex.EncodeToString(fact.digest[:])})
	}
	for siteID, fact := range capturePolicies {
		if fact != nil && present[siteID] {
			inputs.CapturePolicies = append(inputs.CapturePolicies, siteRuntimeV2PolicyRef{SiteID: siteID,
				Revision: fact.revision, SHA256: fact.evidenceDigest})
		}
	}
	slices.SortFunc(inputs.CapturePolicies, func(left, right siteRuntimeV2PolicyRef) int {
		return compareUUID(left.SiteID, right.SiteID)
	})
	for _, fact := range originRoutes {
		inputs.OriginRoutes = append(inputs.OriginRoutes, siteRuntimeV2OriginRoute{SiteID: fact.siteID,
			SiteRevision: fact.siteRevision, Document: fact.document})
	}
	for siteID := range present {
		if subscription := subscriptions[siteID]; subscription != uuid.Nil {
			inputs.Subscriptions[siteID] = subscription
		}
	}
	return inputs
}

// siteRuntimeV2Overlay is the v2 stop overlay: base minus drop plus the
// restored sites (each from the inputs of the last publication carrying it).
func (overlay *publicationOverlay) compileSiteRuntimeV2(
	ctx context.Context, tx pgx.Tx, service *Service, scopeID, configID uuid.UUID, sourceRevision int64,
	nodeIDs []uuid.UUID, now time.Time,
) ([]byte, [sha256.Size]byte, edgeconfig.Bundle, [sha256.Size]byte, []*agentv1.Capability, map[uuid.UUID]uuid.UUID,
	*siteRuntimeV2Inputs, error) {
	fail := func(err error) ([]byte, [sha256.Size]byte, edgeconfig.Bundle, [sha256.Size]byte, []*agentv1.Capability,
		map[uuid.UUID]uuid.UUID, *siteRuntimeV2Inputs, error) {
		return nil, [sha256.Size]byte{}, edgeconfig.Bundle{}, [sha256.Size]byte{}, nil, nil, nil, err
	}
	base := overlay.base.v2
	if base == nil {
		return fail(ErrInvalidInput)
	}
	removed := slices.Concat(overlay.drop, overlay.restoreID)
	keep := func(siteID uuid.UUID) bool { return !slices.Contains(removed, siteID) }
	inputs := siteRuntimeV2Inputs{Document: base.Document, HTTPPolicyRevision: base.HTTPPolicyRevision,
		Subscriptions: map[uuid.UUID]uuid.UUID{}, Topology: base.Topology}
	inputs.Document.Sites = nil
	required := map[string]uint32{}
	for _, capability := range base.Document.RequiredCapabilities {
		required[capability.Name] = max(required[capability.Name], capability.APIVersion)
	}
	take := func(source *siteRuntimeV2Inputs, include func(uuid.UUID) bool) {
		for _, site := range source.Document.Sites {
			if include(uuid.MustParse(site.ID)) {
				inputs.Document.Sites = append(inputs.Document.Sites, site)
			}
		}
		for _, ref := range source.HTTPPolicies {
			if include(ref.SiteID) {
				inputs.HTTPPolicies = append(inputs.HTTPPolicies, ref)
			}
		}
		for _, ref := range source.FirewallActions {
			if include(ref.SiteID) {
				inputs.FirewallActions = append(inputs.FirewallActions, ref)
			}
		}
		for _, ref := range source.CapturePolicies {
			if include(ref.SiteID) {
				inputs.CapturePolicies = append(inputs.CapturePolicies, ref)
			}
		}
		for _, route := range source.OriginRoutes {
			if include(route.SiteID) {
				inputs.OriginRoutes = append(inputs.OriginRoutes, route)
			}
		}
		for siteID, subscription := range source.Subscriptions {
			if include(siteID) {
				inputs.Subscriptions[siteID] = subscription
			}
		}
	}
	take(base, keep)
	for index, source := range overlay.restore {
		if source.v2 == nil {
			continue
		}
		restored := overlay.restoreID[index]
		take(source.v2, func(siteID uuid.UUID) bool { return siteID == restored })
		// a restored site keeps the L2 its own publication worked out
		// (node-list publications, fix-autol2b)
		if source.v2.Topology != nil && source.v2.Topology.Sites[restored] != nil &&
			(inputs.Topology == nil || inputs.Topology.Sites != nil) {
			merged := &L2TopologySnapshot{Revision: source.v2.Topology.Revision, SourceRevision: source.v2.Topology.SourceRevision,
				Passthrough: true, TargetIdentities: source.v2.Topology.TargetIdentities, Sites: map[uuid.UUID]*L2TopologySnapshot{}}
			if inputs.Topology != nil {
				copied := *inputs.Topology
				merged = &copied
				merged.Sites = maps.Clone(inputs.Topology.Sites)
			}
			merged.Sites[restored] = source.v2.Topology.Sites[restored]
			inputs.Topology = merged
		}
		for _, capability := range source.v2.Document.RequiredCapabilities {
			required[capability.Name] = max(required[capability.Name], capability.APIVersion)
		}
	}
	if inputs.Document.Streams != nil && len(overlay.dropStreams) > 0 {
		streams := *inputs.Document.Streams
		streams.StreamsV2 = slices.DeleteFunc(slices.Clone(streams.StreamsV2), func(stream edgeconfig.L4StreamRuntimeV2) bool {
			id, err := uuid.Parse(stream.StreamID)
			return err == nil && slices.Contains(overlay.dropStreams, id)
		})
		inputs.Document.Streams = &streams
	}
	if len(overlay.restoreStreams) > 0 {
		// Put back the forwards the system restored.
		streams := edgeconfig.StreamRuntime{TenantID: overlay.restoreStreamTenant}
		if inputs.Document.Streams != nil {
			streams = *inputs.Document.Streams
			if streams.TenantID != overlay.restoreStreamTenant {
				return fail(fmt.Errorf("%w: restored forwards name another tenant", ErrPersistence))
			}
		}
		streams.StreamsV2 = append(slices.Clone(streams.StreamsV2), overlay.restoreStreams...)
		slices.SortFunc(streams.StreamsV2, func(left, right edgeconfig.L4StreamRuntimeV2) int {
			return strings.Compare(left.StreamID, right.StreamID)
		})
		inputs.Document.Streams = &streams
		for _, capability := range overlay.restoreStreamCaps {
			required[capability.Name] = max(required[capability.Name], capability.APIVersion)
		}
	}
	if len(inputs.Document.Sites) == 0 {
		return fail(ErrNoActiveResources) // a v2 release carries at least one site
	}
	slices.SortFunc(inputs.Document.Sites, func(left, right siteRuntimeV2Site) int { return strings.Compare(left.ID, right.ID) })
	slices.SortFunc(inputs.HTTPPolicies, func(left, right siteRuntimeV2PolicyRef) int { return compareUUID(left.SiteID, right.SiteID) })
	slices.SortFunc(inputs.FirewallActions, func(left, right siteRuntimeV2PolicyRef) int { return compareUUID(left.SiteID, right.SiteID) })
	slices.SortFunc(inputs.CapturePolicies, func(left, right siteRuntimeV2PolicyRef) int { return compareUUID(left.SiteID, right.SiteID) })
	slices.SortFunc(inputs.OriginRoutes, func(left, right siteRuntimeV2OriginRoute) int { return compareUUID(left.SiteID, right.SiteID) })
	inputs.Document.RequiredCapabilities = nil
	for _, name := range slices.Sorted(mapsKeys(required)) {
		inputs.Document.RequiredCapabilities = append(inputs.Document.RequiredCapabilities,
			siteRuntimeV2Capability{Name: name, APIVersion: required[name]})
	}
	system, err := refreshNodeNetworks(ctx, tx, inputs.Document.System)
	if err != nil {
		return fail(err)
	}
	if system, err = refreshNodeNginx(ctx, tx, system, nodeIDs); err != nil {
		return fail(err)
	}
	inputs.Document.System = system
	// Package expiry follows the current rows, not the base publication: the
	// expiry and renewal republications (package_expiry) may be overlays.
	if err := markSiteRuntimeV2PackageExpiry(ctx, tx, scopeID, &inputs.Document, nil, now); err != nil {
		return fail(err)
	}
	// A renewed (or since activated) certificate replaces the version the
	// base publication referenced: certificate_renewal does not wait for the
	// tenant's publication (fix-dnscert3 卡 2-B).
	if err := renewSiteRuntimeV2CertificateReferences(ctx, tx, scopeID, &inputs.Document); err != nil {
		return fail(err)
	}
	captured := inputs
	captured.Document.Sites = slices.Clone(inputs.Document.Sites)

	document := inputs.Document
	document.Sites = slices.Clone(inputs.Document.Sites)
	document.ConfigVersionID, document.SourceRevision = configID.String(), sourceRevision
	if err := validateSiteRuntimeV2CertificateReferences(ctx, tx, scopeID, document, now); err != nil {
		return fail(err)
	}
	httpPolicies, err := reloadHTTPPolicyFacts(ctx, tx, scopeID, sourceRevision, inputs.HTTPPolicies)
	if err != nil {
		return fail(err)
	}
	httpPolicyArtifact, _, err := compileHTTPPolicyArtifact(scopeID, sourceRevision, inputs.HTTPPolicyRevision, &document, httpPolicies)
	if err != nil {
		return fail(err)
	}
	firewallActions, err := reloadFirewallActionFacts(ctx, tx, scopeID, inputs.FirewallActions)
	if err != nil {
		return fail(err)
	}
	firewallActionArtifacts, err := compileFirewallActionArtifacts(scopeID, &document, firewallActions)
	if err != nil {
		return fail(err)
	}
	var tenantID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT tenant_id FROM access_scopes WHERE id=$1 AND kind=$2`, scopeID, ScopeKindTenant).
		Scan(&tenantID); err != nil || tenantID == uuid.Nil {
		return fail(fmt.Errorf("%w: load tenant scope", ErrPersistence))
	}
	installationID, err := loadTelemetryInstallationID(ctx, tx)
	if err != nil {
		return fail(err)
	}
	capturePolicies, err := reloadCapturePolicyFacts(ctx, tx, scopeID, inputs.CapturePolicies)
	if err != nil {
		return fail(err)
	}
	accessLogFields, err := loadAccessLogFields(ctx, tx, nil)
	if err != nil {
		return fail(err)
	}
	// As compileSiteRuntimeV2FactsCapture: a scope without sites has no website telemetry.
	var telemetryManifest [][]byte
	if len(document.Sites) != 0 {
		manifest, err := buildSiteRuntimeV2TelemetryManifest(scopeID, tenantID, installationID, configID, sourceRevision,
			document, inputs.Subscriptions, capturePolicies, accessLogFields, service.config.StateRoot)
		if err != nil {
			return fail(err)
		}
		telemetryManifest = [][]byte{manifest}
	}
	var originRouteBundle []byte
	if len(inputs.OriginRoutes) != 0 {
		facts := make([]siteOriginRouteFact, len(inputs.OriginRoutes))
		for index, route := range inputs.OriginRoutes {
			facts[index] = siteOriginRouteFact{siteID: route.SiteID, siteRevision: route.SiteRevision, document: route.Document}
		}
		if originRouteBundle, err = compileSiteOriginRouteBundleWithTopology(scopeID, configID, sourceRevision, facts,
			inputs.Topology); err != nil {
			return fail(err)
		}
	}
	canonical, canonicalDigest, bundle, manifestDigest, capabilities, subscriptions, err := finishSiteRuntimeV2(ctx, tx, scopeID,
		nodeIDs, now, document, nil, originRouteBundle, httpPolicyArtifact, firewallActionArtifacts, telemetryManifest,
		inputs.Subscriptions, service.config.LazyCertificateCacheMax)
	if err != nil {
		return fail(err)
	}
	return canonical, canonicalDigest, bundle, manifestDigest, capabilities, subscriptions, &captured, nil
}

func mapsKeys(values map[string]uint32) func(func(string) bool) {
	return func(yield func(string) bool) {
		for key := range values {
			if !yield(key) {
				return
			}
		}
	}
}

// validateSiteRuntimeV2CertificateReferences: every TLS listener's
// certificate_version_id is still its asset's active, unrevoked, valid
// version covering the site's domains with its key envelope present (the
// node fetches the key through the certificate channel; nothing of it is in
// the release).
func validateSiteRuntimeV2CertificateReferences(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID,
	document siteRuntimeV2Document, now time.Time) error {
	for _, site := range document.Sites {
		for _, listener := range site.Listeners {
			if listener.TLS == nil {
				continue
			}
			versionID, err := uuid.Parse(listener.TLS.CertificateVersionID)
			if err != nil {
				return ErrTLSMaterialUnavailable
			}
			var sans []string
			var notBefore, notAfter time.Time
			var usable bool
			err = tx.QueryRow(ctx, `SELECT version.sans,version.not_before,version.not_after,
				(SELECT activation.version_id FROM certificate_asset_activation_facts activation
				  WHERE activation.tenant_scope_id=$1 AND activation.asset_id=version.asset_id
				  ORDER BY activation.sequence DESC LIMIT 1)=version.id
				AND NOT EXISTS(SELECT 1 FROM certificate_asset_revocation_facts revoked
				  WHERE revoked.tenant_scope_id=$1 AND revoked.asset_id=version.asset_id AND revoked.version_id=version.id)
				AND EXISTS(SELECT 1 FROM certificate_asset_private_key_envelope_facts envelope
				  WHERE envelope.tenant_scope_id=$1 AND envelope.asset_id=version.asset_id AND envelope.version_id=version.id)
				FROM certificate_asset_versions version
				JOIN certificate_assets asset ON asset.tenant_scope_id=version.tenant_scope_id AND asset.id=version.asset_id
				  AND asset.deleted_at IS NULL
				WHERE version.tenant_scope_id=$1 AND version.id=$2`, scopeID, versionID).
				Scan(&sans, &notBefore, &notAfter, &usable)
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrTLSMaterialUnavailable
			}
			if err != nil {
				return fmt.Errorf("%w: read certificate reference", ErrPersistence)
			}
			if !usable || now.Before(notBefore) || !now.Before(notAfter) ||
				certificateasset.RequireCoverage(sans, site.Domains) != nil {
				return ErrTLSMaterialUnavailable
			}
		}
	}
	return nil
}

func reloadHTTPPolicyFacts(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, sourceRevision int64,
	refs []siteRuntimeV2PolicyRef) ([]httpPolicyFact, error) {
	facts := make([]httpPolicyFact, 0, len(refs))
	for _, ref := range refs {
		var raw []byte
		if err := tx.QueryRow(ctx, `SELECT document FROM http_policy_revisions
			WHERE policy_id=$1 AND tenant_scope_id=$2 AND site_id=$3 AND revision=$4`,
			ref.PolicyID, scopeID, ref.SiteID, ref.Revision).Scan(&raw); err != nil {
			return nil, fmt.Errorf("%w: reload HTTP policy revision", ErrPersistence)
		}
		document, err := decodeHTTPPolicyRevisionDocument(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: decode HTTP policy revision", ErrPersistence)
		}
		facts = append(facts, httpPolicyFact{tenantScopeID: scopeID, policyID: ref.PolicyID, siteID: ref.SiteID,
			sourceRevision: sourceRevision, revision: ref.Revision, document: document})
	}
	return facts, nil
}

func reloadFirewallActionFacts(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID,
	refs []siteRuntimeV2PolicyRef) ([]firewallActionFact, error) {
	facts := make([]firewallActionFact, 0, len(refs))
	for _, ref := range refs {
		fact := firewallActionFact{siteID: ref.SiteID, policyID: ref.PolicyID, revision: ref.Revision}
		var digest []byte
		if err := tx.QueryRow(ctx, `SELECT document_bytes,document_sha256 FROM firewall_action_policy_revisions
			WHERE tenant_scope_id=$1 AND site_id=$2 AND policy_id=$3 AND revision=$4`,
			scopeID, ref.SiteID, ref.PolicyID, ref.Revision).Scan(&fact.document, &digest); err != nil ||
			len(digest) != sha256.Size || hex.EncodeToString(digest) != ref.SHA256 {
			return nil, fmt.Errorf("%w: reload firewall action revision", ErrPersistence)
		}
		copy(fact.digest[:], digest)
		facts = append(facts, fact)
	}
	return facts, nil
}

func reloadCapturePolicyFacts(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID,
	refs []siteRuntimeV2PolicyRef) (map[uuid.UUID]*siteCapturePolicyFact, error) {
	result := make(map[uuid.UUID]*siteCapturePolicyFact, len(refs))
	for _, ref := range refs {
		var raw, digest []byte
		if err := tx.QueryRow(ctx, `SELECT document_bytes,document_sha256 FROM site_capture_policy_revisions
			WHERE scope_id=$1 AND site_id=$2 AND revision=$3`, scopeID, ref.SiteID, ref.Revision).Scan(&raw, &digest); err != nil {
			return nil, fmt.Errorf("%w: reload site capture policy revision", ErrPersistence)
		}
		fact, err := decodeSiteCapturePolicyFact(ref.SiteID, ref.Revision, raw, digest)
		if err != nil || fact.evidenceDigest != ref.SHA256 {
			return nil, fmt.Errorf("%w: decode site capture policy revision", ErrPersistence)
		}
		result[ref.SiteID] = fact
	}
	return result, nil
}
