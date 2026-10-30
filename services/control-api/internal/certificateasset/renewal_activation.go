package certificateasset

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Automatic renewal switch-over (fix-dnscert3 卡 2-B): the control plane, not
// a user, activates a renewed version once its key material reached the
// nodes. The facts keep the order's requester as the accountable principal
// (the fact tables need an actor membership); the audit records the system.

// ErrRenewalSuperseded: the renewal must not switch (the certificate was
// deleted, disabled, set to not auto-renew, the version revoked or already
// active, or a site's binding moved since the delivery reserved it).
var ErrRenewalSuperseded = errors.New("certificate renewal superseded")

// ErrRenewalWaiting: a bound site's earlier certificate publication is still
// in flight; the renewal is retried after it settles.
var ErrRenewalWaiting = errors.New("certificate renewal waits for an earlier publication")

// RenewalSiteRevision is a site the delivery carried the version to, at the
// binding revision it reserved (the site's current revision + 1).
type RenewalSiteRevision struct {
	SiteID          uuid.UUID
	BindingRevision int64
	Default         bool
}

// RenewalBindings is the asset's sites to switch, read under row locks.
type RenewalBindings struct {
	AssetRevision int64
	Sites         []RenewalSiteRevision
}

// LoadRenewalBindingsTx locks the renewed asset and its bound sites and
// returns where the version must go; ErrRenewalSuperseded when the renewal
// is no longer to be switched in.
func LoadRenewalBindingsTx(ctx context.Context, tx pgx.Tx, scopeID, assetID, versionID uuid.UUID,
	now time.Time) (RenewalBindings, error) {
	if ctx == nil || tx == nil || scopeID == uuid.Nil || assetID == uuid.Nil || versionID == uuid.Nil {
		return RenewalBindings{}, ErrInvalidInput
	}
	asset, err := loadAsset(ctx, tx, scopeID, assetID, true)
	if errors.Is(err, ErrNotFound) {
		return RenewalBindings{}, ErrRenewalSuperseded
	}
	if err != nil {
		return RenewalBindings{}, err
	}
	if asset.DeletedAt != nil || asset.Disabled || !asset.AutoRenew {
		return RenewalBindings{}, ErrRenewalSuperseded
	}
	version, err := loadVersion(ctx, tx, scopeID, assetID, versionID, storeTime(now))
	if errors.Is(err, ErrNotFound) {
		return RenewalBindings{}, ErrRenewalSuperseded
	}
	if err != nil {
		return RenewalBindings{}, err
	}
	if version.Status != StatusPendingActivation {
		return RenewalBindings{}, ErrRenewalSuperseded
	}
	bindings, err := loadCurrentBindingsForAssetAndLockSites(ctx, tx, scopeID, assetID)
	if err != nil {
		return RenewalBindings{}, err
	}
	result := RenewalBindings{AssetRevision: asset.Revision, Sites: make([]RenewalSiteRevision, len(bindings))}
	for index, binding := range bindings {
		// A site's earlier publication still in flight goes first (intents
		// settle in binding order): wait for it.
		var inFlight bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM certificate_publication_intents intent
			JOIN LATERAL (SELECT state FROM certificate_publication_intent_state_facts state
			  WHERE state.tenant_scope_id=intent.tenant_scope_id AND state.site_id=intent.site_id
			    AND state.binding_revision=intent.binding_revision ORDER BY sequence DESC LIMIT 1) latest ON true
			WHERE intent.tenant_scope_id=$1 AND intent.site_id=$2 AND latest.state NOT IN ('succeeded','permanent_failed'))`,
			scopeID, binding.SiteID).Scan(&inFlight); err != nil {
			return RenewalBindings{}, err
		}
		if inFlight {
			return RenewalBindings{}, ErrRenewalWaiting
		}
		next, err := nextBindingRevisionTx(ctx, tx, scopeID, binding.SiteID, binding.Revision)
		if err != nil {
			return RenewalBindings{}, err
		}
		result.Sites[index] = RenewalSiteRevision{SiteID: binding.SiteID, BindingRevision: next, Default: binding.Default}
	}
	return result, nil
}

// RenewalActivation is a delivered renewal to switch in.
type RenewalActivation struct {
	TenantScopeID uuid.UUID
	OrderID       uuid.UUID
	AssetID       uuid.UUID
	VersionID     uuid.UUID
	// Sites and their reserved binding revisions, as the delivery sent them.
	Sites []RenewalSiteRevision
	// The delivery rollout every site's publication intent settles to.
	RolloutID       uuid.UUID
	ConfigVersionID uuid.UUID
	RolloutRevision int64
	RequestID       string
}

// ActivateRenewalTx activates the renewed version, moves every bound site to
// it at the reserved binding revision (its publication intent is settled
// succeeded by the delivery rollout) and advances the order to active. It
// fails with ErrRenewalSuperseded, changing nothing, when the facts moved.
func (s *Store) ActivateRenewalTx(ctx context.Context, tx pgx.Tx, request RenewalActivation) error {
	if s == nil || s.auditor == nil || s.now == nil || ctx == nil || tx == nil || request.TenantScopeID == uuid.Nil ||
		request.OrderID == uuid.Nil || request.AssetID == uuid.Nil || request.VersionID == uuid.Nil ||
		request.RequestID == "" || (len(request.Sites) > 0 && (request.RolloutID == uuid.Nil ||
		request.ConfigVersionID == uuid.Nil || request.RolloutRevision < 1)) {
		return ErrInvalidInput
	}
	now := storeTime(s.now())
	current, err := LoadRenewalBindingsTx(ctx, tx, request.TenantScopeID, request.AssetID, request.VersionID, now)
	if err != nil {
		return err
	}
	// The same sites, each still holding the revision this round reserved
	// (a user's binding change since then superseded the round).
	if !sameRenewalSiteSet(current.Sites, request.Sites) {
		return ErrRenewalSuperseded
	}
	if err := requireRenewalReservationsTx(ctx, tx, request.TenantScopeID, request.Sites, request.RequestID); err != nil {
		return err
	}
	// The accountable principal: the order's requester when still an active
	// member acting in the tenant (or the platform), else the asset creator.
	var actor Actor
	if err := tx.QueryRow(ctx, `SELECT membership.user_id,membership.scope_id,scope.kind
		FROM certificate_orders cert_order
		JOIN certificate_assets asset ON asset.tenant_scope_id=cert_order.scope_id AND asset.id=$3
		JOIN memberships membership ON membership.status='active'
		  AND membership.user_id IN (cert_order.created_by_user_id,asset.created_by_user_id)
		JOIN users account ON account.id=membership.user_id AND account.status='active'
		JOIN access_scopes scope ON scope.id=membership.scope_id
		  AND (scope.id=cert_order.scope_id OR scope.kind='platform')
		WHERE cert_order.scope_id=$1 AND cert_order.id=$2
		ORDER BY membership.user_id=cert_order.created_by_user_id DESC,scope.id=cert_order.scope_id DESC LIMIT 1`,
		request.TenantScopeID, request.OrderID, request.AssetID).Scan(&actor.UserID, &actor.ScopeID,
		&actor.ScopeKind); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrRenewalSuperseded // nobody may stand for the certificate any more
		}
		return fmt.Errorf("resolve certificate renewal principal: %w", err)
	}
	var sequence int64
	var previousVersionID *uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT COALESCE(max(sequence),0)+1,
		(SELECT version_id FROM certificate_asset_activation_facts
		  WHERE tenant_scope_id=$1 AND asset_id=$2 ORDER BY sequence DESC LIMIT 1)
		FROM certificate_asset_activation_facts WHERE tenant_scope_id=$1 AND asset_id=$2`,
		request.TenantScopeID, request.AssetID).Scan(&sequence, &previousVersionID); err != nil {
		return err
	}
	resultingRevision := current.AssetRevision + 1
	if _, err := tx.Exec(ctx, `UPDATE certificate_assets SET revision=$3,updated_by_scope_id=$4,updated_by_user_id=$5,
		updated_at=$6 WHERE tenant_scope_id=$1 AND id=$2 AND revision=$7`, request.TenantScopeID, request.AssetID,
		resultingRevision, actor.ScopeID, actor.UserID, now, current.AssetRevision); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO certificate_asset_activation_facts (
			tenant_scope_id,asset_id,sequence,version_id,previous_version_id,
			expected_asset_revision,resulting_asset_revision,request_id,actor_scope_id,activated_by_user_id,activated_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, request.TenantScopeID, request.AssetID, sequence,
		request.VersionID, previousVersionID, current.AssetRevision, resultingRevision, request.RequestID,
		actor.ScopeID, actor.UserID, now); err != nil {
		return err
	}
	system := func(action, resourceType string, resourceID uuid.UUID, payload map[string]any) error {
		payload["operation"], payload["target_scope_id"] = action, request.TenantScopeID.String()
		payload["reason"], payload["order_id"] = "certificate_renewal", request.OrderID.String()
		return s.auditor.Append(ctx, tx, audit.Event{ScopeID: request.TenantScopeID, ActorKind: "system",
			ActorRef: "job:certificate_renewal", Action: action, ResourceType: resourceType,
			ResourceID: resourceID.String(), RequestID: request.RequestID, Result: "success", Payload: payload})
	}
	for _, site := range request.Sites {
		// The latest fact (revisions a superseded round reserved have none).
		var previous uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT version_id FROM certificate_site_binding_facts
			WHERE tenant_scope_id=$1 AND site_id=$2 ORDER BY sequence DESC LIMIT 1`, request.TenantScopeID,
			site.SiteID).Scan(&previous); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO certificate_site_binding_facts (
				tenant_scope_id,site_id,sequence,action,asset_id,version_id,is_default,
				expected_revision,resulting_revision,request_id,actor_scope_id,changed_by_user_id,changed_at
			) VALUES($1,$2,$3,'bind',$4,$5,$6,$7,$3,$8,$9,$10,$11)`, request.TenantScopeID, site.SiteID,
			site.BindingRevision, request.AssetID, request.VersionID, site.Default, site.BindingRevision-1,
			request.RequestID, actor.ScopeID, actor.UserID, now); err != nil {
			return err
		}
		if err := settleRenewalPublicationIntentTx(ctx, tx, request, site, actor); err != nil {
			return err
		}
		if err := system(operationBind, "site", site.SiteID, map[string]any{
			"asset_id": request.AssetID, "version_id": request.VersionID, "previous_version_id": previous,
			"binding_revision": site.BindingRevision, "default": site.Default, "cause": "certificate_renewal",
			"rollout_id": request.RolloutID.String(),
			"changes":    map[string]any{"version_id": map[string]any{"before": previous.String(), "after": request.VersionID.String()}},
		}); err != nil {
			return err
		}
	}
	if err := system(operationActivate, "certificate_asset_version", request.VersionID, map[string]any{
		"asset_id": request.AssetID, "previous_version_id": previousVersionID, "asset_revision": resultingRevision,
		"migrated_binding_count": len(current.Sites),
		"changes":                map[string]any{"active_version_id": map[string]any{"before": previousVersionID, "after": request.VersionID.String()}},
	}); err != nil {
		return err
	}
	// The version is on every node that serves its sites: issued -> deploying
	// -> active in one step.
	for _, step := range [][2]string{{"issued", "deploying"}, {"deploying", "active"}} {
		command, err := tx.Exec(ctx, `UPDATE certificate_orders SET status=$6,revision=revision+1,
			updated_at=GREATEST(updated_at,statement_timestamp())
			WHERE scope_id=$1 AND id=$2 AND issued_asset_id=$3 AND issued_asset_version_id=$4 AND status=$5`,
			request.TenantScopeID, request.OrderID, request.AssetID, request.VersionID, step[0], step[1])
		if err != nil {
			return fmt.Errorf("advance renewed ACME order: %w", err)
		}
		if command.RowsAffected() != 1 {
			return ErrRenewalSuperseded
		}
		if err := system("certificate.order.transition", "certificate_order", request.OrderID, map[string]any{
			"from_status": step[0], "to_status": step[1], "state": step[1],
			"changes": map[string]any{"status": map[string]any{"before": step[0], "after": step[1]}},
		}); err != nil {
			return err
		}
	}
	return nil
}

// settleRenewalPublicationIntentTx writes the site's publication intent for
// the reserved binding revision (the binding fact requires one in the same
// transaction) and settles it succeeded by the delivery rollout: the worker
// never claims it, the nodes already hold the version. The intent has no
// session (the system acted); migration 120 allows that form.
func settleRenewalPublicationIntentTx(ctx context.Context, tx pgx.Tx, request RenewalActivation,
	site RenewalSiteRevision, actor Actor) error {
	key := publicationIntentIdempotencyKey(request.TenantScopeID, site.SiteID, site.BindingRevision)
	if _, err := tx.Exec(ctx, `INSERT INTO certificate_publication_intents (
			tenant_scope_id,site_id,binding_revision,operation,asset_id,version_id,is_default,
			request_id,actor_scope_id,actor_user_id,deadline_at
		) VALUES($1,$2,$3,'publish',$4,$5,$6,$7,$8,$9,transaction_timestamp()+interval '1 hour')`,
		request.TenantScopeID, site.SiteID, site.BindingRevision, request.AssetID, request.VersionID, site.Default,
		request.RequestID, actor.ScopeID, actor.UserID); err != nil {
		return err
	}
	token := uuid.NewSHA1(request.RolloutID, []byte(key))
	publicationID := uuid.NewSHA1(request.ConfigVersionID, []byte("certificate-renewal/"+key))
	for sequence, state := range []string{"leased", "succeeded"} {
		_, err := tx.Exec(ctx, `INSERT INTO certificate_publication_intent_state_facts(
			tenant_scope_id,site_id,binding_revision,sequence,state,attempt,idempotency_key,
			lease_owner,lease_token,lease_expires_at,occurred_at,
			publication_id,publication_revision,config_version_id,rollout_id,rollout_revision
		) VALUES($1,$2,$3,$4,$5,1,$6,'control-api-certificate-renewal',$7,
			transaction_timestamp()+interval '1 minute',transaction_timestamp(),$8,$9,$10,$11,$12)`,
			request.TenantScopeID, site.SiteID, site.BindingRevision, sequence+2, state, key, token,
			renewalResult(state == "succeeded", publicationID), renewalRevision(state == "succeeded", request.RolloutRevision),
			renewalResult(state == "succeeded", request.ConfigVersionID), renewalResult(state == "succeeded", request.RolloutID),
			renewalRevision(state == "succeeded", request.RolloutRevision))
		if err != nil {
			return err
		}
	}
	return nil
}

func renewalResult(set bool, value uuid.UUID) *uuid.UUID {
	if !set {
		return nil
	}
	return &value
}

func renewalRevision(set bool, value int64) *int64 {
	if !set {
		return nil
	}
	return &value
}

// UseRenewalMaterialsInTx is UsePublicationMaterialsInTx for a renewal not
// yet switched in: the version's material for each site at its reserved
// binding revision. The version must be valid now, unrevoked and cover each
// site's domains; it need not be active (the switch follows the delivery).
func (s *Store) UseRenewalMaterialsInTx(ctx context.Context, tx pgx.Tx, scopeID, assetID, versionID uuid.UUID,
	sites []RenewalSiteRevision, resolver OpaquePublicationResolver, consumer PublicationConsumer) error {
	if s == nil || s.enveloper == nil || s.now == nil || ctx == nil || tx == nil || consumer == nil ||
		scopeID == uuid.Nil || assetID == uuid.Nil || versionID == uuid.Nil || len(sites) == 0 {
		return ErrInvalidInput
	}
	now := storeTime(s.now())
	materials := make([]PublicationMaterial, 0, len(sites))
	defer func() {
		for index := range materials {
			zeroBytes(materials[index].PrivateKeyPEM)
			materials[index].PrivateKeyPEM, materials[index].CertificatePEM = nil, nil
		}
	}()
	for _, site := range sites {
		var locked struct {
			tenantID uuid.UUID
			domains  []string
		}
		err := tx.QueryRow(ctx, `SELECT scope.tenant_id,COALESCE((
				SELECT array_agg(current_domain.canonical_domain ORDER BY current_domain.canonical_domain)
				FROM (
					SELECT DISTINCT ON (fact.canonical_domain) fact.canonical_domain,fact.action
					FROM site_domain_facts fact
					WHERE fact.scope_id=site.scope_id AND fact.site_id=site.id
					ORDER BY fact.canonical_domain,fact.global_sequence DESC
				) current_domain WHERE current_domain.action='activate'
			),ARRAY[site.domain]::text[])
			FROM sites site
			JOIN access_scopes scope ON scope.id=site.scope_id AND scope.kind='tenant'
			WHERE site.scope_id=$1 AND site.id=$2 AND site.deleted_at IS NULL
			FOR SHARE OF site`, scopeID, site.SiteID).Scan(&locked.tenantID, &locked.domains)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrRenewalSuperseded
		}
		if err != nil {
			return err
		}
		material, err := s.loadPublicationMaterial(ctx, tx, now, scopeID, locked, Binding{
			TenantScopeID: scopeID, SiteID: site.SiteID, AssetID: assetID, VersionID: versionID,
			Revision: site.BindingRevision, Default: site.Default, Bound: true,
		}, resolver)
		if err != nil {
			return err
		}
		materials = append(materials, material)
	}
	return consumer(materials)
}
