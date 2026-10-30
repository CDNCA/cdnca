package edgepublish

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Stop overlay: a scope with unpublished tenant edits still gets a
// system stop (traffic over limit, domain claim) and its release on the
// nodes. The release is the scope's latest publication's compiled source
// (edge_publication_compile_inputs) with only the stopped sites taken out and
// the released ones put back from the last publication that carried them; no
// row a tenant may have edited since is read. v1 rebuilds the Spec; v2
// recompiles from stored facts and references (system_overlay_v2.go).

const maxCompileInputBytes = maxSiteRuntimeV2DocumentBytes

type compileCapability struct {
	Name       agentv1.CapabilityName `json:"name"`
	APIVersion uint32                 `json:"api_version"`
}

func persistCompileInputs(ctx context.Context, tx pgx.Tx, scopeID, configID uuid.UUID, sourceRevision int64,
	overlay bool, v2 *siteRuntimeV2Inputs, capabilities []*agentv1.Capability, now time.Time) error {
	if v2 == nil {
		return ErrInvalidInput
	}
	encodedV2, err := json.Marshal(v2)
	if err != nil {
		return fmt.Errorf("%w: encode compile inputs", ErrInvalidInput)
	}
	if len(encodedV2) > maxCompileInputBytes {
		if overlay {
			// An overlay must stay marked, or a later clean-path compile would
			// take the rows it did not publish as published.
			return ErrSecurityPolicyBudget
		}
		return nil // too large to keep: a stop for this scope waits for its next publication
	}
	stored := make([]compileCapability, 0, len(capabilities))
	for _, capability := range capabilities {
		stored = append(stored, compileCapability{Name: capability.GetName(), APIVersion: capability.GetApiVersion()})
	}
	encodedCapabilities, err := json.Marshal(stored)
	if err != nil {
		return fmt.Errorf("%w: encode compile capabilities", ErrInvalidInput)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO edge_publication_compile_inputs(
		config_version_id,configuration_scope_id,source_revision,overlay,spec,site_runtime_v2,required_capabilities,created_at)
		VALUES($1,$2,$3,$4,NULL,$5,$6,$7)`, configID, scopeID, sourceRevision, overlay,
		encodedV2, encodedCapabilities, now); err != nil {
		return fmt.Errorf("%w: persist compile inputs", ErrPersistence)
	}
	return nil
}

type compileInputs struct {
	configID       uuid.UUID
	sourceRevision int64
	v2             *siteRuntimeV2Inputs
	capabilities   []*agentv1.Capability
}

const compileInputsColumns = `inputs.config_version_id,inputs.source_revision,inputs.spec,inputs.site_runtime_v2,
	inputs.required_capabilities,config.canonical_snapshot`

func scanCompileInputs(row pgx.Row) (compileInputs, error) {
	var inputs compileInputs
	var specJSON, v2JSON, capabilitiesJSON, snapshotJSON []byte
	if err := row.Scan(&inputs.configID, &inputs.sourceRevision, &specJSON, &v2JSON, &capabilitiesJSON, &snapshotJSON); err != nil {
		return compileInputs{}, err
	}
	var stored []compileCapability
	if json.Unmarshal(capabilitiesJSON, &stored) != nil {
		return compileInputs{}, fmt.Errorf("%w: decode compile capabilities", ErrPersistence)
	}
	inputs.v2 = new(siteRuntimeV2Inputs)
	if v2JSON == nil || json.Unmarshal(v2JSON, inputs.v2) != nil || inputs.v2.Document.Schema != siteRuntimeV2Schema {
		return compileInputs{}, fmt.Errorf("%w: decode site runtime v2 compile inputs", ErrPersistence)
	}
	for _, capability := range stored {
		inputs.capabilities = append(inputs.capabilities, &agentv1.Capability{Name: capability.Name, ApiVersion: capability.APIVersion})
	}
	return inputs, nil
}

// publicationOverlay is one stop overlay: base minus drop plus restore.
type publicationOverlay struct {
	base      compileInputs
	drop      []uuid.UUID
	restore   []compileInputs // one per restored site, with that site's entries
	restoreID []uuid.UUID
	// dropStreams: published L4 forwards an open package traffic stop holds
	// (migration 508).
	dropStreams []uuid.UUID
	// restoreStreams: unpublished-now forwards a package traffic stop took out
	// and the system put back, each as the last publication that carried it
	// published it, with that publication's capabilities.
	restoreStreams      []edgeconfig.L4StreamRuntimeV2
	restoreStreamTenant string
	restoreStreamCaps   []siteRuntimeV2Capability
	actor               Actor
	lastNodes           []uuid.UUID
}

// loadPublicationOverlay builds the overlay for the scope's latest
// publication, or reports false when it has no stored source.
func loadPublicationOverlay(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) (*publicationOverlay, bool, error) {
	var overlay publicationOverlay
	var userID, actorScopeID, rolloutID uuid.UUID
	err := tx.QueryRow(ctx, `SELECT actor_user_id,actor_scope_id,rollout_id FROM edge_config_publications
		WHERE configuration_scope_id=$1 AND contract_version=1 ORDER BY source_revision DESC LIMIT 1`, scopeID).
		Scan(&userID, &actorScopeID, &rolloutID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	overlay.base, err = scanCompileInputs(tx.QueryRow(ctx, `SELECT `+compileInputsColumns+`
		FROM edge_config_publications publication
		JOIN edge_publication_compile_inputs inputs ON inputs.config_version_id=publication.config_version_id
		JOIN config_versions config ON config.id=publication.config_version_id
		WHERE publication.configuration_scope_id=$1 AND publication.contract_version=1
		ORDER BY publication.source_revision DESC LIMIT 1`, scopeID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if overlay.base.sourceRevision != mustLatestPublicationRevision(ctx, tx, scopeID) {
		return nil, false, nil // the latest publication kept no source (too large to keep)
	}
	var kind string
	if err := tx.QueryRow(ctx, `SELECT kind FROM access_scopes WHERE id=$1`, actorScopeID).Scan(&kind); err != nil {
		return nil, false, err
	}
	overlay.actor = Actor{UserID: userID, ScopeID: actorScopeID, ScopeKind: kind}
	rows, err := tx.Query(ctx, `SELECT DISTINCT node_id FROM node_deployments WHERE rollout_id=$1 ORDER BY node_id`, rolloutID)
	if err != nil {
		return nil, false, err
	}
	if overlay.lastNodes, err = pgx.CollectRows(rows, pgx.RowTo[uuid.UUID]); err != nil {
		return nil, false, err
	}
	present := map[uuid.UUID]bool{}
	for _, site := range overlay.base.v2.Document.Sites {
		if id, err := uuid.Parse(site.ID); err == nil {
			present[id] = true
		}
	}
	baseIDs := make([]uuid.UUID, 0, len(present))
	for id := range present {
		baseIDs = append(baseIDs, id)
	}
	// Taken out: published sites a system stop holds now (traffic over limit,
	// domain claim, overdue secondary verification that disabled the site, a
	// suspended package subscription: bb03, migration 555).
	// A published site whose bound package is no longer valid is taken out
	// too (fix-nopkgpub); a site without a package needs none (community).
	rows, err = tx.Query(ctx, `SELECT site.id FROM sites site WHERE site.scope_id=$1 AND site.id=ANY($2::uuid[]) AND (
		site.package_subscription_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM package_subscriptions package_subscription
		  WHERE package_subscription.tenant_scope_id=site.scope_id AND package_subscription.id=site.package_subscription_id
		    AND package_subscription.admin_enabled=true AND package_subscription.deleted_at IS NULL) OR
		EXISTS(SELECT 1 FROM package_traffic_site_suspensions open WHERE open.site_id=site.id AND open.recovered_at IS NULL) OR
		EXISTS(SELECT 1 FROM domain_claim_suspensions claim WHERE claim.site_id=site.id AND claim.released_at IS NULL) OR
		EXISTS(SELECT 1 FROM identity_secondary_verification_site_holds hold WHERE hold.site_id=site.id
		  AND hold.released_at IS NULL AND hold.disabled_site) OR
		EXISTS(SELECT 1 FROM package_subscriptions suspended WHERE suspended.id=site.package_subscription_id
		  AND suspended.tenant_scope_id=site.scope_id AND suspended.suspended_at IS NOT NULL))
		ORDER BY site.id`, scopeID, baseIDs)
	if err != nil {
		return nil, false, err
	}
	if overlay.drop, err = pgx.CollectRows(rows, pgx.RowTo[uuid.UUID]); err != nil {
		return nil, false, err
	}
	// Put back: unpublished-now sites a traffic stop or a secondary
	// verification hold disabled and the system re-enabled (or whose package
	// subscription was unsuspended), live again, taken
	// from the last publication that carried them. A domain claim release
	// leaves its site disabled until the tenant enables it (an edit).
	// A site bound to a package comes back only while it is valid
	// (loadSiteFacts, fix-nopkgpub); a site without one needs none.
	rows, err = tx.Query(ctx, `SELECT site.id FROM sites site
		LEFT JOIN package_subscriptions package_subscription
		  ON package_subscription.tenant_scope_id=site.scope_id AND package_subscription.id=site.package_subscription_id
		WHERE site.scope_id=$1 AND NOT site.id=ANY($2::uuid[])
		AND site.deleted_at IS NULL AND site.enabled AND site.status='active'
		AND (site.package_subscription_id IS NULL OR (package_subscription.id IS NOT NULL
		AND package_subscription.admin_enabled=true AND package_subscription.deleted_at IS NULL))
		AND (EXISTS(SELECT 1 FROM package_traffic_site_suspensions closed WHERE closed.site_id=site.id AND closed.recovered_at IS NOT NULL)
		  OR EXISTS(SELECT 1 FROM identity_secondary_verification_site_holds closed WHERE closed.site_id=site.id
		    AND closed.released_at IS NOT NULL AND closed.disabled_site)
		  OR EXISTS(SELECT 1 FROM package_subscription_versions resumed WHERE resumed.subscription_id=site.package_subscription_id
		    AND resumed.operation='unsuspend'))
		AND NOT EXISTS(SELECT 1 FROM package_traffic_site_suspensions open WHERE open.site_id=site.id AND open.recovered_at IS NULL)
		AND NOT EXISTS(SELECT 1 FROM domain_claim_suspensions claim WHERE claim.site_id=site.id AND claim.released_at IS NULL)
		AND NOT EXISTS(SELECT 1 FROM identity_secondary_verification_site_holds hold WHERE hold.site_id=site.id
		  AND hold.released_at IS NULL AND hold.disabled_site)
		AND NOT EXISTS(SELECT 1 FROM package_subscriptions suspended WHERE suspended.id=site.package_subscription_id
		  AND suspended.tenant_scope_id=site.scope_id AND suspended.suspended_at IS NOT NULL)
		ORDER BY site.id`, scopeID, baseIDs)
	if err != nil {
		return nil, false, err
	}
	candidates, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return nil, false, err
	}
	for _, siteID := range candidates {
		// From the last publication carrying the site.
		source, err := scanCompileInputs(tx.QueryRow(ctx, `SELECT `+compileInputsColumns+`
			FROM edge_publication_compile_inputs inputs JOIN config_versions config ON config.id=inputs.config_version_id
			WHERE inputs.configuration_scope_id=$1
			  AND jsonb_path_exists(inputs.site_runtime_v2,'strict $.document.sites[*] ? (@.id == $id)',jsonb_build_object('id',$2::text))
			ORDER BY inputs.source_revision DESC LIMIT 1`, scopeID, siteID.String()))
		if errors.Is(err, pgx.ErrNoRows) {
			continue // never published: a draft
		}
		if err != nil {
			return nil, false, err
		}
		overlay.restore = append(overlay.restore, source)
		overlay.restoreID = append(overlay.restoreID, siteID)
	}
	if overlay.base.v2 != nil && overlay.base.v2.Document.Streams != nil {
		var published []uuid.UUID
		for _, stream := range overlay.base.v2.Document.Streams.StreamsV2 {
			if id, err := uuid.Parse(stream.StreamID); err == nil {
				published = append(published, id)
			}
		}
		rows, err = tx.Query(ctx, `SELECT suspension.stream_id FROM package_traffic_stream_suspensions suspension
			WHERE suspension.tenant_scope_id=$1 AND suspension.stream_id=ANY($2::uuid[]) AND suspension.recovered_at IS NULL
			UNION SELECT forward.id FROM l4_forwards forward JOIN package_subscriptions suspended
			  ON suspended.id=forward.package_subscription_id AND suspended.tenant_scope_id=forward.scope_id
			WHERE forward.scope_id=$1 AND forward.id=ANY($2::uuid[]) AND suspended.suspended_at IS NOT NULL
			ORDER BY 1`, scopeID, published)
		if err != nil {
			return nil, false, err
		}
		if overlay.dropStreams, err = pgx.CollectRows(rows, pgx.RowTo[uuid.UUID]); err != nil {
			return nil, false, err
		}
	}
	if err := overlay.loadRestoredStreams(ctx, tx, scopeID); err != nil {
		return nil, false, err
	}
	return &overlay, true, nil
}

// loadRestoredStreams finds the forwards a package traffic stop withdrew and
// the system restored (a closed 493 fact that set them back to normal, none
// open) which the base no longer carries, and takes each from the last
// publication that carried it. A forward never published is a draft.
func (overlay *publicationOverlay) loadRestoredStreams(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) error {
	published := []uuid.UUID{}
	if overlay.base.v2.Document.Streams != nil {
		for _, stream := range overlay.base.v2.Document.Streams.StreamsV2 {
			if id, err := uuid.Parse(stream.StreamID); err == nil {
				published = append(published, id)
			}
		}
	}
	// The live conditions of loadStreamFacts (store.go), plus the restore.
	rows, err := tx.Query(ctx, `SELECT forward.id FROM l4_forwards forward
		LEFT JOIN package_subscriptions package_subscription
		  ON package_subscription.tenant_scope_id=forward.scope_id AND package_subscription.id=forward.package_subscription_id
		WHERE forward.scope_id=$1 AND NOT forward.id=ANY($2::uuid[])
		  AND forward.deleted_at IS NULL AND forward.enabled AND forward.admin_status='normal'
		  AND (forward.package_subscription_id IS NULL OR (package_subscription.id IS NOT NULL
		  AND package_subscription.admin_enabled=true AND package_subscription.deleted_at IS NULL
		  AND package_subscription.suspended_at IS NULL))
		  AND (EXISTS(SELECT 1 FROM package_traffic_stream_suspensions closed WHERE closed.stream_id=forward.id
		    AND closed.recovered_at IS NOT NULL AND closed.recovered_stream_status='normal')
		    OR EXISTS(SELECT 1 FROM package_subscription_versions resumed WHERE resumed.subscription_id=forward.package_subscription_id
		      AND resumed.operation='unsuspend'))
		  AND NOT EXISTS(SELECT 1 FROM package_traffic_stream_suspensions open WHERE open.stream_id=forward.id
		    AND open.recovered_at IS NULL)
		ORDER BY forward.id`, scopeID, published)
	if err != nil {
		return err
	}
	candidates, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return err
	}
	for _, streamID := range candidates {
		source, err := scanCompileInputs(tx.QueryRow(ctx, `SELECT `+compileInputsColumns+`
			FROM edge_publication_compile_inputs inputs JOIN config_versions config ON config.id=inputs.config_version_id
			WHERE inputs.configuration_scope_id=$1
			  -- lax: an input without streams (a stop overlay, a site-only scope) is no match, not an error (2203A).
			  AND jsonb_path_exists(inputs.site_runtime_v2,'lax $.document.streams.streams_v2[*] ? (@.stream_id == $id)',
			    jsonb_build_object('id',$2::text))
			ORDER BY inputs.source_revision DESC LIMIT 1`, scopeID, streamID.String()))
		if errors.Is(err, pgx.ErrNoRows) {
			continue // never published: a draft
		}
		if err != nil {
			return err
		}
		streams := source.v2.Document.Streams
		if streams == nil {
			return fmt.Errorf("%w: compile inputs carry no streams", ErrPersistence)
		}
		for _, stream := range streams.StreamsV2 {
			if stream.StreamID == streamID.String() {
				overlay.restoreStreams = append(overlay.restoreStreams, stream)
			}
		}
		overlay.restoreStreamTenant = streams.TenantID
		overlay.restoreStreamCaps = append(overlay.restoreStreamCaps, source.v2.Document.RequiredCapabilities...)
	}
	return nil
}

func mustLatestPublicationRevision(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) int64 {
	var revision int64
	_ = tx.QueryRow(ctx, `SELECT COALESCE(max(source_revision),0) FROM edge_config_publications
		WHERE configuration_scope_id=$1 AND contract_version=1`, scopeID).Scan(&revision)
	return revision
}

func (overlay *publicationOverlay) changesSites() bool {
	return len(overlay.drop) > 0 || len(overlay.restoreID) > 0 || len(overlay.dropStreams) > 0 || len(overlay.restoreStreams) > 0
}
