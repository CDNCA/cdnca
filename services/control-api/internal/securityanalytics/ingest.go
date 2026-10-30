package securityanalytics

import (
	"context"
	"crypto/sha256"
	"errors"
	"strconv"
	"time"

	contract "github.com/cdnca/cdnca/libs/edgeconfig/autodefense"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Ingest outcomes (autodefense_report_receipts.outcome).

const (
	OutcomeApplied   = "applied"
	OutcomeIgnored   = "ignored"        // minute summaries: nodes are autonomous, nothing to store
	OutcomeScope     = "rejected_scope" // the node does not serve the reported site
	OutcomeDuplicate = "duplicate"      // not stored: the receipt already exists
)

// ErrInvalidReport: the message is not a valid report of its node. The
// consumer terminates such a message (never redelivered).
var ErrInvalidReport = errors.New("autodefense report invalid")

// VerdictFact is one verdict row of VerdictTable.
type VerdictFact struct {
	ID, TenantID, SiteID, NodeID uuid.UUID
	OccurredAt, Until            time.Time
	TargetKind, Target, Reason   string
	Score, Level                 int64
	Revision, Seq                uint64
}

// NodeEvent is one platform node security event of NodeEventTable (F4).
type NodeEvent struct {
	ID, NodeID                        uuid.UUID
	OccurredAt                        time.Time
	Source, Kind, PortGroup, ClientIP string
	Count, DurationSeconds, Level     int64
	Reason, Detail                    string
}

// Facts are the ClickHouse rows of one report.
type Facts struct {
	Verdicts   []VerdictFact
	NodeEvents []NodeEvent
}

// FactWriter writes ClickHouse facts. Rows carry deterministic IDs, so a
// retried write after a crash replaces its own rows (ReplacingMergeTree).
type FactWriter interface {
	WriteFacts(ctx context.Context, facts Facts) error
}

// Ingestor applies node reports (contract section 5) to PostgreSQL and
// ClickHouse. ClickHouse is written before the PostgreSQL commit: if the
// commit fails the message is redelivered and the facts are rewritten
// under the same IDs.
type Ingestor struct {
	pool  *pgxpool.Pool
	facts FactWriter
	now   func() time.Time
	// alerts announces node security events (EnableNodeEventAlerts).
	alerts AlertEnqueuer
	// marketActions queues whole-node actions on market supply nodes
	// (EnableMarketNodeActions, ADR 0012 §19.3).
	marketActions bool
}

func NewIngestor(pool *pgxpool.Pool, facts FactWriter, now func() time.Time) (*Ingestor, error) {
	if pool == nil || facts == nil {
		return nil, ErrInvalidConfig
	}
	if now == nil {
		now = time.Now
	}
	return &Ingestor{pool: pool, facts: facts, now: now}, nil
}

// Ingest applies one report from subjectNode (the node ID of the NATS
// subject, which the gateway bound to the authenticated session). The
// community edition stores platform node security events (F4) only; the
// automatic defense reports (site and port group state, verdicts,
// candidates) belong to the commercial module and are acknowledged as
// ignored, so a commercial node pointed at a community control plane does
// not loop on redelivery.
func (ingestor *Ingestor) Ingest(ctx context.Context, subjectNode string, encoded []byte) (string, error) {
	report, err := contract.DecodeReport(encoded)
	if err != nil || report.NodeID != subjectNode {
		return "", ErrInvalidReport
	}
	if report.Kind != contract.ReportNodeEvent {
		return OutcomeIgnored, nil
	}
	nodeID := uuid.MustParse(report.NodeID)
	const scope = "node"
	outcome := ""
	err = pgx.BeginFunc(ctx, ingestor.pool, func(tx pgx.Tx) error {
		// Serialise the reports of one scope; the receipt makes them idempotent.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 801))`, report.NodeID+"/"+scope); err != nil {
			return err
		}
		var seen bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM autodefense_report_receipts WHERE node_id=$1 AND report_scope=$2 AND seq=$3)`,
			nodeID, scope, int64(report.Seq)).Scan(&seen); err != nil {
			return err
		}
		if seen {
			outcome = OutcomeDuplicate
			return nil
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM nodes WHERE id=$1)`, nodeID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrInvalidReport
		}
		event := nodeEventFact(report, nodeID)
		outcome = OutcomeApplied
		ingestor.alertNodeEvent(ctx, tx, event)
		ingestor.queueMarketNodeAction(ctx, tx, nodeID, event.OccurredAt, event.Source, event.Kind, event.Level, max(event.Count, 1), nil, nil)
		if err := ingestor.facts.WriteFacts(ctx, Facts{NodeEvents: []NodeEvent{event}}); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO autodefense_report_receipts(node_id,report_scope,seq,kind,outcome,received_at)
			VALUES($1,$2,$3,$4,$5,$6)`, nodeID, scope, int64(report.Seq), string(report.Kind), outcome, ingestor.now())
		return err
	})
	return outcome, err
}

// nodeServesSite: the site is live and node is in the target snapshot of
// the site's line group at its current revision (the same authority the
// WAF/JA4 publication uses). The gateway does not check site ownership
// (ad-07 遗留 3), so this is the tenant boundary of ingest.
func nodeServesSite(ctx context.Context, tx pgx.Tx, node, tenant, site uuid.UUID) (bool, error) {
	var served bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM unnest($1::uuid[], $2::uuid[]) AS reported(tenant, site)
		JOIN sites s ON s.scope_id=reported.tenant AND s.id=reported.site AND s.deleted_at IS NULL
		WHERE `+siteServedByNode+`)`, []uuid.UUID{tenant}, []uuid.UUID{site}, node).Scan(&served)
	return served, err
}

// siteServingNodes (a subquery on site s): the nodes serving s through s's
// own line group or, when s follows its package (node_group_id NULL,
// live-waf D2), the package's primary/backup group or an escalation route:
// the groups edgeautopublish.SiteTargetNodeIDsTx publishes to (a group of
// the site's scope or of the node's). Either the group's current endpoints
// or its current target snapshot name the node. Ingest (siteServedByNode)
// and the snapshot distribution (servingSites) share it (sec-followup).
const siteServingNodes = `SELECT DISTINCT served.node_id FROM node_line_groups g
	LEFT JOIN package_subscriptions subscription ON subscription.tenant_scope_id=s.scope_id
		AND subscription.id=s.package_subscription_id AND subscription.deleted_at IS NULL
	LEFT JOIN escalate_site_routes route ON route.tenant_scope_id=s.scope_id AND route.site_id=s.id
	CROSS JOIN LATERAL (
		SELECT endpoint.node_id FROM node_line_endpoints endpoint
		WHERE endpoint.tenant_scope_id=g.tenant_scope_id AND endpoint.line_group_id=g.id
		  AND endpoint.config_revision=g.current_revision AND endpoint.enabled AND endpoint.node_id IS NOT NULL
		UNION
		SELECT target.node_id FROM edge_target_snapshots snapshot
		JOIN edge_target_snapshot_nodes target ON target.tenant_scope_id=snapshot.tenant_scope_id
			AND target.snapshot_id=snapshot.id AND target.snapshot_revision=snapshot.revision
		WHERE snapshot.tenant_scope_id=g.tenant_scope_id AND snapshot.source_line_group_id=g.id
		  AND snapshot.source_revision=g.current_revision) served
	WHERE g.deleted_at IS NULL
	  AND g.id IN (s.node_group_id,
		(subscription.product_snapshot->'spec'->>'node_group_id')::uuid,
		(subscription.product_snapshot->'spec'->>'backup_node_group_id')::uuid,
		route.line_group_id, route.next_group_id)
	  AND g.tenant_scope_id IN (s.scope_id, (SELECT node.scope_id FROM nodes node WHERE node.id=served.node_id))`

// siteServedByNode (a condition on site s, node $3): node is one of
// siteServingNodes.
const siteServedByNode = `$3 IN (` + siteServingNodes + `)`

// deterministicID derives a fact ID from the report identity.
func deterministicID(parts ...string) uuid.UUID {
	hash := sha256.New()
	for _, part := range parts {
		hash.Write([]byte(part))
		hash.Write([]byte{0})
	}
	return uuid.NewHash(sha256.New(), uuid.NameSpaceOID, hash.Sum(nil), 5)
}

func nodeEventFact(report contract.Report, node uuid.UUID) NodeEvent {
	event := report.NodeEvent
	return NodeEvent{ID: deterministicID(report.NodeID, "node", strconv.FormatUint(report.Seq, 10)), NodeID: node,
		OccurredAt: time.Unix(report.At, 0).UTC(), Source: event.Source, Kind: event.Kind, ClientIP: event.Client, Count: event.Count,
		DurationSeconds: event.DurationSeconds, Level: int64(event.Level), Reason: event.Reason}
}

// PruneReceipts deletes receipts older than the report stream can redeliver
// (one day, kept two).
func (ingestor *Ingestor) PruneReceipts(ctx context.Context) (int64, error) {
	tag, err := ingestor.pool.Exec(ctx, `DELETE FROM autodefense_report_receipts WHERE received_at < $1`, ingestor.now().Add(-48*time.Hour))
	return tag.RowsAffected(), err
}
