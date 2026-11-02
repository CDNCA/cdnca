package site

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
)

// ErrPublishInFlight: the site's publication is still running (接入状态
// 已发布到节点 = 发布中); 重新发布 waits for it.
var ErrPublishInFlight = errors.New("site publication is in flight")

const siteRepublishAction = "site.republish"

// Republish is 接入状态 > 已发布到节点 > 重新发布 (): it
// publishes the site's current settings again without a change. An automatic
// scope gets the actor's site.update at a new source revision (as status
// recovery does); a manual scope redelivers its last publication now through
// the system channel (node_sync, as a failed sync retry). It returns the
// site's readiness after the commit (published reads publishing).
func (s *Service) Republish(ctx context.Context, actor Actor, siteID uuid.UUID, requestID string) (AccessReadiness, error) {
	if !validActor(actor) || siteID == uuid.Nil || requestID == "" {
		return AccessReadiness{}, ErrInvalidInput
	}
	if err := s.store.republish(ctx, actor, siteID, requestID); err != nil {
		return AccessReadiness{}, err
	}
	item, err := s.store.Get(ctx, actor, siteID)
	if err != nil {
		return AccessReadiness{}, err
	}
	if item.AccessReadiness == nil {
		return AccessReadiness{}, ErrNotFound
	}
	return *item.AccessReadiness, nil
}

func (s *Store) republish(ctx context.Context, actor Actor, siteID uuid.UUID, requestID string) error {
	if len(requestID) > 128 {
		requestID = requestID[:128]
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		// IAM lock first (069), then the configuration scope (publication lock order).
		scopeID, err := mutationTargetScope(ctx, tx, actor, siteID)
		if err != nil {
			return err
		}
		if err := authorizeAutomaticMutation(ctx, tx, actor, scopeID); err != nil {
			return err
		}
		if err := lockEdgeConfigurationScope(ctx, tx, scopeID); err != nil {
			return err
		}
		var enabled bool
		var state string
		err = tx.QueryRow(ctx, `SELECT site.enabled, outcome.state FROM sites site
			CROSS JOIN LATERAL site_publication_outcome_618(site.scope_id, site.id) outcome
			WHERE site.id=$1 AND site.scope_id=$2 AND site.deleted_at IS NULL`, siteID, scopeID).Scan(&enabled, &state)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if !enabled {
			return ErrLockStateConflict
		}
		if state == "pending" {
			return ErrPublishInFlight
		}
		var previous int64
		if err := tx.QueryRow(ctx, `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1`, scopeID).
			Scan(&previous); err != nil {
			return err
		}
		// One publication per source revision: the republication takes its own.
		if _, err := tx.Exec(ctx, `SELECT advance_edge_configuration_scope_revision($1)`, scopeID); err != nil {
			return err
		}
		result, err := edgeautopublish.EnqueueTx(ctx, tx, edgeautopublish.EnqueueInput{
			Actor:         edgeautopublish.Actor{UserID: actor.UserID, ScopeID: actor.ScopeID, ScopeKind: actor.ScopeKind},
			TargetScopeID: scopeID, SourceKind: edgeautopublish.SourceSite, SourceResourceID: siteID,
			Operation: "site.update", Reason: edgeautopublish.ReasonResourceMutation,
			Permission: edgeautopublish.PermissionSitesManage, SourceRequestID: requestID,
		})
		if err != nil {
			return err
		}
		mode := edgeautopublish.ModeAutomatic
		if !result.Enqueued {
			mode = edgeautopublish.ModeManual
			if _, err := edgeautopublish.RequestRepublicationTx(ctx, tx, edgeautopublish.RepublishRequest{
				ScopeID: scopeID, Trigger: edgepublish.SystemTriggerNodeSync, SourceResourceID: siteID,
				SourceRequestID: requestID, FromRevision: previous, Immediate: true,
			}); err != nil {
				return err
			}
		}
		return s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: scopeID, ActorUserID: &actor.UserID, Action: siteRepublishAction,
			ResourceType: "site", ResourceID: siteID.String(), RequestID: requestID, Result: "success",
			Payload: map[string]any{"publish_mode": mode, "previous_state": state, "from_source_revision": previous},
		})
	})
}
