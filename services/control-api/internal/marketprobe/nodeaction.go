package marketprobe

import (
	"context"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/nodeaction"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Whole-node actions (ADR 0012 §19.3, ML-23): internal/autodefense
// queues them in market_node_action_queue (migration 432); ReportNodeActions
// signs and posts the unreported rows to the market. Rows are claimed into a
// report (report_id) before sending, so a retry resends the same report and
// the market drops it as a replay. Site rows carry the current grant of their
// market key (Config.Grants); a key with no synced grant reports the action
// without a site (it still notifies, it just cannot count for that site).

const (
	nodeActionQueueRetention = 24 * time.Hour // the market refuses older actions
	nodeActionBatch          = nodeaction.MaxItems
)

// GrantResolver returns the current grant ID of a market key
// (marketsupply.Service.GrantForKey); false when none is synced.
type GrantResolver interface {
	GrantForKey(key string) (uuid.UUID, bool)
}

type queuedAction struct {
	id        int64
	item      nodeaction.Item
	marketKey *string
}

// ReportNodeActions sends the queued whole-node actions and returns how
// many were sent.
func (s *Service) ReportNodeActions(ctx context.Context) (int, error) {
	if s.cfg.Identity == nil {
		return 0, nil
	}
	self := s.cfg.Identity()
	if self.MemberID == uuid.Nil {
		return 0, nil
	}
	now := s.cfg.Now().UTC()
	if _, err := s.pool.Exec(ctx, `DELETE FROM market_node_action_queue WHERE created_at < $1`, now.Add(-nodeActionQueueRetention)); err != nil {
		return 0, err
	}
	sent := 0
	for {
		reportID, items, err := s.claimNodeActions(ctx, now)
		if err != nil || len(items) == 0 {
			return sent, err
		}
		result, err := s.market.ReportNodeActions(ctx, self, nodeaction.Report{Schema: nodeaction.SchemaV1, ReportID: reportID,
			LeafMemberID: self.MemberID, CreatedAt: now.Unix(), Items: items})
		if err != nil {
			return sent, err
		}
		if result.Rejected > 0 {
			s.skip("node_action", "items_rejected", "rejected", result.Rejected)
		}
		if _, err := s.pool.Exec(ctx, `UPDATE market_node_action_queue SET reported_at=$2 WHERE report_id=$1 AND reported_at IS NULL`,
			reportID, now); err != nil {
			return sent, err
		}
		sent += len(items)
	}
}

// claimNodeActions returns the oldest claimed but unanswered report, or claims
// up to one report's worth of new rows under a fresh report ID. Items that
// are identical for the market (same node, pool, second, source, kind, level
// and site) are merged by summing their counts.
func (s *Service) claimNodeActions(ctx context.Context, now time.Time) (uuid.UUID, []nodeaction.Item, error) {
	var reportID uuid.UUID
	var rows []queuedAction
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT report_id FROM market_node_action_queue WHERE reported_at IS NULL AND report_id IS NOT NULL
			ORDER BY id LIMIT 1`).Scan(&reportID)
		if err == pgx.ErrNoRows {
			reportID = uuid.New()
			tag, err := tx.Exec(ctx, `UPDATE market_node_action_queue SET report_id=$1 WHERE id IN (
				SELECT id FROM market_node_action_queue WHERE reported_at IS NULL AND report_id IS NULL ORDER BY id LIMIT $2
				FOR UPDATE SKIP LOCKED)`, reportID, nodeActionBatch)
			if err != nil || tag.RowsAffected() == 0 {
				reportID = uuid.Nil
				return err
			}
		} else if err != nil {
			return err
		}
		list, err := tx.Query(ctx, `SELECT id, node_id, node_pool_ref, occurred_at, source, kind, level, count, market_key, site_id
			FROM market_node_action_queue WHERE report_id=$1 ORDER BY id`, reportID)
		if err != nil {
			return err
		}
		rows, err = pgx.CollectRows(list, func(row pgx.CollectableRow) (queuedAction, error) {
			var q queuedAction
			var at time.Time
			var site *uuid.UUID
			err := row.Scan(&q.id, &q.item.NodeID, &q.item.NodePoolRef, &at, &q.item.Source, &q.item.Kind, &q.item.Level, &q.item.Count,
				&q.marketKey, &site)
			q.item.At = at.Unix()
			q.item.LeafSiteID = site
			return q, err
		})
		return err
	})
	if err != nil || reportID == uuid.Nil {
		return uuid.Nil, nil, err
	}
	return reportID, s.mergeNodeActions(rows, now), nil
}

func (s *Service) mergeNodeActions(rows []queuedAction, now time.Time) []nodeaction.Item {
	type key struct {
		pool         string
		node         uuid.UUID
		at           int64
		source, kind string
		level        int
		site         uuid.UUID
	}
	index := map[key]int{}
	var items []nodeaction.Item
	for _, q := range rows {
		it := q.item
		it.At = min(it.At, now.Unix())
		it.GrantID = nil
		if it.LeafSiteID != nil {
			grantID, ok := uuid.Nil, false
			if q.marketKey != nil && s.cfg.Grants != nil {
				grantID, ok = s.cfg.Grants.GrantForKey(*q.marketKey)
			}
			if ok {
				it.GrantID = &grantID
			} else {
				it.LeafSiteID = nil
			}
		}
		k := key{it.NodePoolRef, it.NodeID, it.At, it.Source, it.Kind, it.Level, uuid.Nil}
		if it.LeafSiteID != nil {
			k.site = *it.LeafSiteID
		}
		if i, seen := index[k]; seen {
			items[i].Count = min(items[i].Count+it.Count, nodeaction.MaxCount)
			continue
		}
		index[k] = len(items)
		items = append(items, it)
	}
	return items
}
