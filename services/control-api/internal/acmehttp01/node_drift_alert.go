package acmehttp01

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Epoch membership drift alerts (ADR-0003, migration 347): a candidate that
// joins a site's line group while the site's epoch is open stays out of the
// site's serving set until the epoch closes. The platform members holding
// nodes.manage are told once per (epoch, drifting node set), in the
// transaction that detected the drift. A repeat is sent only while the epoch
// is still open.
const (
	EventTypeEpochDrift = notification.EventTypeACMEHTTP01EpochDrift

	driftAlertPermission      = "nodes.manage"
	driftAlertTemplateVersion = 1
	driftAlertSourcePrefix    = "acme-http01-drift/"
	driftAlertListedNodes     = 5
)

// DriftAlertEnqueuer is notification.Store.
type DriftAlertEnqueuer interface {
	EnqueueTx(context.Context, pgx.Tx, notification.EnqueueRequest) (notification.EnqueueResult, error)
}

// EnableDriftAlerts makes epoch drift enqueue an alert to the node managers.
// Call before the runtime starts.
func (s *NodeStore) EnableDriftAlerts(enqueuer DriftAlertEnqueuer) {
	s.alerts = enqueuer
}

// alertDriftingSites finds the drift that no Publish has seen: a node joining
// the line group after the site's last challenge was published. Only drift
// alerts depend on it (the gate already keeps the node out), so it runs only
// with alerts enabled. Open epochs last one issuance, so the ordered limit
// does not starve sites in practice; an alerted drift costs one lookup.
func (s *NodeStore) alertDriftingSites(ctx context.Context, limit int) error {
	if s.alerts == nil {
		return nil
	}
	rows, err := s.pool.Query(ctx, `SELECT state.tenant_scope_id,state.site_id
		FROM acme_http01_site_overlay_states state
		WHERE state.open_epoch_id IS NOT NULL AND EXISTS (
		    SELECT 1 FROM acme_http01_site_candidate_nodes(state.tenant_scope_id, state.site_id) candidate(node_id)
		    WHERE NOT EXISTS (SELECT 1 FROM acme_http01_site_overlay_epoch_members member
		                      WHERE member.epoch_id=state.open_epoch_id AND member.node_id=candidate.node_id))
		ORDER BY 1,2 LIMIT $1`, limit)
	if err != nil {
		return err
	}
	sites, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (siteKey, error) {
		var key siteKey
		return key, row.Scan(&key.ScopeID, &key.SiteID)
	})
	if err != nil {
		return err
	}
	for _, site := range sites {
		if err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
			if err := lockOverlay(ctx, tx); err != nil {
				return err
			}
			var open *uuid.UUID
			if err := tx.QueryRow(ctx, `SELECT open_epoch_id FROM acme_http01_site_overlay_states
				WHERE tenant_scope_id=$1 AND site_id=$2`, site.ScopeID, site.SiteID).Scan(&open); err != nil || open == nil {
				return err
			}
			candidates, err := s.siteCandidates(ctx, tx, site.ScopeID, site.SiteID)
			if errors.Is(err, ErrNoTarget) {
				return nil // the next Publish refuses the site
			}
			if err != nil {
				return err
			}
			members, _, err := epochMembers(ctx, tx, *open)
			if err != nil {
				return err
			}
			s.alertDrift(ctx, tx, site, *open, epochDrift(members, candidates))
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}

// epochDrift: the candidates that are not members of the epoch.
func epochDrift(members, candidates []uuid.UUID) []uuid.UUID {
	var drift []uuid.UUID
	for _, node := range candidates {
		if !slices.Contains(members, node) {
			drift = append(drift, node)
		}
	}
	return drift
}

// alertDrift runs inside the overlay transaction under a savepoint: a
// notification failure is logged but never blocks the challenge.
func (s *NodeStore) alertDrift(ctx context.Context, tx pgx.Tx, site siteKey, epoch uuid.UUID, drift []uuid.UUID) {
	if s.alerts == nil || len(drift) == 0 {
		return
	}
	savepoint, err := tx.Begin(ctx)
	if err == nil {
		err = s.alertDriftTx(ctx, savepoint, site, epoch, drift)
		if err == nil {
			err = savepoint.Commit(ctx)
		}
		_ = savepoint.Rollback(context.Background())
	}
	if err != nil {
		slog.Warn("ACME HTTP-01 epoch drift alert not enqueued", "site_id", site.SiteID, "epoch_id", epoch, "error", err)
	}
}

func (s *NodeStore) alertDriftTx(ctx context.Context, tx pgx.Tx, site siteKey, epoch uuid.UUID, drift []uuid.UUID) error {
	digest := nodescheduler.CanonicalNodeSetDigest(drift)
	sourceEventID := driftAlertSourcePrefix + epoch.String() + "/" + hex.EncodeToString(digest[:])
	var platform uuid.UUID
	var already bool
	if err := tx.QueryRow(ctx, `SELECT scope.id, EXISTS (SELECT 1 FROM notification_events event
			WHERE event.scope_id=scope.id AND event.event_type=$1 AND event.source_event_id=$2)
		FROM access_scopes scope WHERE scope.kind='platform' AND scope.tenant_id IS NULL`,
		EventTypeEpochDrift, sourceEventID).Scan(&platform, &already); err != nil {
		return fmt.Errorf("read platform scope: %w", err)
	}
	if already {
		// Reconciliation finds the same drift on every pass.
		return nil
	}
	var domain string
	var openedAt time.Time
	if err := tx.QueryRow(ctx, `SELECT site.domain, epoch.opened_at FROM sites site
		JOIN acme_http01_site_overlay_epochs epoch ON epoch.id=$3
		WHERE site.scope_id=$1 AND site.id=$2`, site.ScopeID, site.SiteID, epoch).Scan(&domain, &openedAt); err != nil {
		return fmt.Errorf("read drifting site: %w", err)
	}
	rows, err := tx.Query(ctx, `SELECT node.name FROM unnest($1::uuid[]) drifting(node_id)
		JOIN nodes node ON node.id=drifting.node_id ORDER BY node.id`, drift)
	if err != nil {
		return fmt.Errorf("read drifting nodes: %w", err)
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return fmt.Errorf("read drifting nodes: %w", err)
	}
	listed := strings.Join(names[:min(len(names), driftAlertListedNodes)], "、")
	if len(names) > driftAlertListedNodes {
		listed += "等"
	}
	rows, err = tx.Query(ctx, `SELECT DISTINCT membership.user_id
		FROM memberships membership
		JOIN users member ON member.id=membership.user_id AND member.status='active'
		JOIN role_assignments assignment ON assignment.scope_id=membership.scope_id AND assignment.user_id=membership.user_id
		JOIN role_permissions grant_row ON grant_row.role_id=assignment.role_id AND grant_row.permission_name=$2
		WHERE membership.scope_id=$1 AND membership.status='active'
		ORDER BY membership.user_id`, platform, driftAlertPermission)
	if err != nil {
		return fmt.Errorf("read drift alert recipients: %w", err)
	}
	recipients, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return fmt.Errorf("read drift alert recipients: %w", err)
	}
	templateID := EventTypeEpochDrift + ".zh-cn"
	templates := map[notification.Channel]notification.TemplateRef{
		notification.ChannelSMS:   {ID: templateID, Version: driftAlertTemplateVersion, Channel: notification.ChannelSMS},
		notification.ChannelEmail: {ID: templateID, Version: driftAlertTemplateVersion, Channel: notification.ChannelEmail},
	}
	values := notification.TemplateContext{
		"site_domain":     notification.PublicValue(domain),
		"node_count":      notification.PublicValue(strconv.Itoa(len(drift))),
		"node_names":      notification.PublicValue(listed),
		"epoch_opened_at": notification.PublicValue(openedAt.UTC().Format(time.RFC3339)),
	}
	for _, recipient := range recipients {
		if _, err := s.alerts.EnqueueTx(ctx, tx, notification.EnqueueRequest{
			ScopeID: platform, RecipientID: recipient, SourceEventID: sourceEventID, EventType: EventTypeEpochDrift,
			Policy: notification.DeliverySystemRequired, Templates: templates,
			Contexts:       map[notification.Channel]notification.TemplateContext{notification.ChannelSMS: values, notification.ChannelEmail: values},
			AuditRequestID: sourceEventID, SubjectSiteID: &site.SiteID,
		}); err != nil {
			return fmt.Errorf("enqueue epoch drift alert: %w", err)
		}
	}
	return nil
}

// EpochDriftReplayGuard keeps a scheduled repeat of a drift alert only while
// the epoch that drifted is still open.
func EpochDriftReplayGuard(ctx context.Context, tx pgx.Tx, candidate notification.ReplayCandidate) (bool, error) {
	rest, found := strings.CutPrefix(candidate.SourceEventID, driftAlertSourcePrefix)
	epochText, _, split := strings.Cut(rest, "/")
	if !found || !split {
		return false, nil
	}
	epoch, err := uuid.Parse(epochText)
	if err != nil {
		return false, nil
	}
	var open bool
	err = tx.QueryRow(ctx, `SELECT closed_at IS NULL FROM acme_http01_site_overlay_epochs WHERE id=$1`, epoch).Scan(&open)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read drifted epoch: %w", err)
	}
	return open, nil
}

// RegisterEpochDriftReplayGuard installs EpochDriftReplayGuard.
func RegisterEpochDriftReplayGuard(store *notification.Store) error {
	if err := store.RegisterReplayGuard(EventTypeEpochDrift, EpochDriftReplayGuard); err != nil {
		return fmt.Errorf("register ACME HTTP-01 drift replay guard: %w", err)
	}
	return nil
}
