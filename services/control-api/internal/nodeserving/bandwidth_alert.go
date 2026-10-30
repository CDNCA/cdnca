package nodeserving

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Node bandwidth auto-disable alerts (NODE-N03, migration 558): a node held
// by auto_disable for bandwidth_exceeded, and its bandwidth_recovered
// release, are announced to the platform members holding nodes.manage, in
// the same transaction as the hold transition. Other auto-disable reasons
// (traffic quota, disabled windows, settings changes) are not alerted.
const (
	EventTypeNodeBandwidthExceeded  = notification.EventTypeNodeBandwidthExceeded
	EventTypeNodeBandwidthRecovered = notification.EventTypeNodeBandwidthRecovered

	bandwidthAlertSourcePrefix = "node-bandwidth/"
)

// bandwidthAlertEvent decides which alert, if any, a hold transition sends.
func bandwidthAlertEvent(source string, previousHeld bool, previousReason string, decision Decision) string {
	if source != SourceAutoDisable {
		return ""
	}
	heldForBandwidth := previousHeld && previousReason == ReasonBandwidthExceeded
	switch {
	case decision.Held && decision.Reason == ReasonBandwidthExceeded && !heldForBandwidth:
		return EventTypeNodeBandwidthExceeded
	case !decision.Held && decision.Reason == ReasonBandwidthRecovered && heldForBandwidth:
		return EventTypeNodeBandwidthRecovered
	default:
		return ""
	}
}

func bandwidthAlertSourceEventID(nodeID uuid.UUID, revision int64) string {
	return bandwidthAlertSourcePrefix + nodeID.String() + "/" + strconv.FormatInt(revision, 10)
}

func parseBandwidthAlertSourceEventID(value string) (uuid.UUID, int64, bool) {
	rest, found := strings.CutPrefix(value, bandwidthAlertSourcePrefix)
	nodeText, revisionText, split := strings.Cut(rest, "/")
	if !found || !split {
		return uuid.Nil, 0, false
	}
	nodeID, err := uuid.Parse(nodeText)
	if err != nil {
		return uuid.Nil, 0, false
	}
	revision, err := strconv.ParseInt(revisionText, 10, 64)
	if err != nil {
		return uuid.Nil, 0, false
	}
	return nodeID, revision, true
}

// formatBandwidthMbps renders a decision detail bit rate (bps) for the alert.
func formatBandwidthMbps(value any) string {
	var bps float64
	switch typed := value.(type) {
	case uint64:
		bps = float64(typed)
	case int64:
		bps = float64(typed)
	case float64:
		bps = typed
	default:
		return "-"
	}
	return strconv.FormatFloat(math.Round(bps/1e5)/10, 'f', -1, 64) + " Mbps"
}

// enqueueBandwidthAlert runs inside Apply's transaction under a savepoint: a
// notification failure is logged and never blocks the hold.
func (store *Store) enqueueBandwidthAlert(ctx context.Context, tx pgx.Tx, nodeID, scopeID uuid.UUID, eventType string,
	revision int64, detail map[string]any, now time.Time) {
	if store.alerts == nil || eventType == "" {
		return
	}
	err := func() error {
		savepoint, err := tx.Begin(ctx)
		if err != nil {
			return err
		}
		defer func() { _ = savepoint.Rollback(context.Background()) }()
		if err := store.enqueueBandwidthAlertTx(ctx, savepoint, nodeID, scopeID, eventType, revision, detail, now); err != nil {
			return err
		}
		return savepoint.Commit(ctx)
	}()
	if err != nil {
		slog.Warn("node bandwidth alert not enqueued", "node_id", nodeID, "event_type", eventType, "error", err)
	}
}

func (store *Store) enqueueBandwidthAlertTx(ctx context.Context, tx pgx.Tx, nodeID, scopeID uuid.UUID, eventType string,
	revision int64, detail map[string]any, now time.Time) error {
	name, address, platform, err := readAlertedNode(ctx, tx, nodeID, scopeID)
	if err != nil || !platform {
		// Tenant-owned (marketplace seller) nodes are not alerted yet.
		return err
	}
	recipients, err := readNodeAlertRecipients(ctx, tx, scopeID)
	if err != nil {
		return err
	}
	values := notification.TemplateContext{
		"node_name":       notification.PublicValue(name),
		"node_ip":         notification.PublicValue(address),
		"bandwidth":       notification.PublicValue(formatBandwidthMbps(detail["bandwidth_bps"])),
		"bandwidth_limit": notification.PublicValue(formatBandwidthMbps(detail["bandwidth_limit_bps"])),
		"occurred_at":     notification.PublicValue(now.UTC().Format(time.RFC3339)),
	}
	return enqueueNodeAlert(ctx, store.alerts, tx, scopeID, recipients, eventType,
		bandwidthAlertSourceEventID(nodeID, revision), values)
}

// readAlertedNode reads the node's name and address and whether it belongs
// to the platform scope.
func readAlertedNode(ctx context.Context, tx pgx.Tx, nodeID, scopeID uuid.UUID) (string, string, bool, error) {
	var name, address string
	var platform bool
	if err := tx.QueryRow(ctx, `SELECT node.name,COALESCE(host(node.ipv4),host(node.ipv6),''),
			scope.kind='platform' AND scope.tenant_id IS NULL
		FROM nodes node JOIN access_scopes scope ON scope.id=node.scope_id
		WHERE node.id=$1 AND node.scope_id=$2`, nodeID, scopeID).Scan(&name, &address, &platform); err != nil {
		return "", "", false, fmt.Errorf("read alerted node: %w", err)
	}
	if address == "" {
		address = "-"
	}
	return name, address, platform, nil
}

// readNodeAlertRecipients lists the scope's active members holding nodes.manage.
func readNodeAlertRecipients(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT membership.user_id
		FROM memberships membership
		JOIN users member ON member.id=membership.user_id AND member.status='active'
		JOIN role_assignments assignment ON assignment.scope_id=membership.scope_id AND assignment.user_id=membership.user_id
		JOIN role_permissions grant_row ON grant_row.role_id=assignment.role_id AND grant_row.permission_name=$2
		WHERE membership.scope_id=$1 AND membership.status='active'
		ORDER BY membership.user_id`, scopeID, alertRecipientPermission)
	if err != nil {
		return nil, fmt.Errorf("read node alert recipients: %w", err)
	}
	recipients, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return nil, fmt.Errorf("read node alert recipients: %w", err)
	}
	return recipients, nil
}

func enqueueNodeAlert(ctx context.Context, enqueuer AlertEnqueuer, tx pgx.Tx, scopeID uuid.UUID, recipients []uuid.UUID,
	eventType, sourceEventID string, values notification.TemplateContext) error {
	templates := map[notification.Channel]notification.TemplateRef{
		notification.ChannelSMS:   {ID: eventType + ".zh-cn", Version: alertTemplateVersion, Channel: notification.ChannelSMS},
		notification.ChannelEmail: {ID: eventType + ".zh-cn", Version: alertTemplateVersion, Channel: notification.ChannelEmail},
	}
	for _, recipient := range recipients {
		if _, err := enqueuer.EnqueueTx(ctx, tx, notification.EnqueueRequest{
			ScopeID: scopeID, RecipientID: recipient, SourceEventID: sourceEventID, EventType: eventType,
			Policy: notification.DeliverySystemRequired, Templates: templates,
			Contexts:       map[notification.Channel]notification.TemplateContext{notification.ChannelSMS: values, notification.ChannelEmail: values},
			AuditRequestID: sourceEventID,
		}); err != nil {
			return fmt.Errorf("enqueue %s: %w", eventType, err)
		}
	}
	return nil
}

// BandwidthAlertReplayGuard keeps a scheduled repeat only while the
// auto-disable hold revision that produced it is still the node's current one.
func BandwidthAlertReplayGuard(ctx context.Context, tx pgx.Tx, candidate notification.ReplayCandidate) (bool, error) {
	nodeID, revision, ok := parseBandwidthAlertSourceEventID(candidate.SourceEventID)
	if !ok {
		return false, nil
	}
	var current int64
	err := tx.QueryRow(ctx, `SELECT revision FROM node_serving_holds WHERE node_id=$1 AND source=$2`,
		nodeID, SourceAutoDisable).Scan(&current)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read node bandwidth hold: %w", err)
	}
	return current == revision, nil
}
