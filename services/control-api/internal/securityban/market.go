package securityban

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/bansync"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Market rows: a root subscriber's ban list of
// one market site, mirrored onto the leaf site that serves it. The leaf's
// market supply (marketsupply) hands over the subscriber's snapshot
// (libs/marketproto/bansync) for the grant's market tenant; ApplyMarket
// reconciles the tenant's source market rows of that leaf site with it and
// wakes the distributor, which sends them to the nodes like any other ban.
//
// Only the subscriber's own leaf site is ever written: the caller resolves it
// from the grant's tenant and ApplyMarket checks it again. A subscription
// holds at most MaxMarketTenantActive active rows over all its sites and adds
// at most MaxMarketNewPerMinute a minute, and a site takes at most
// MaxMarketMessagesPerMinute snapshots a minute. A row the leaf's operator
// released stays released for that subscriber entry.

const (
	MaxMarketTenantActive      = 10000
	MaxMarketNewPerMinute      = 600
	MaxMarketMessagesPerMinute = 20

	AuditMarketSync    = "security.ban.market_sync"
	AuditMarketRelease = "security.ban.market_release"

	// Release causes (market_supply_ban_refs.release_cause).
	releaseByBuyer        = "buyer"
	releaseBySubscription = "subscription"
)

var (
	ErrMarketSiteNotFound = errors.New("market ban list: leaf site is not the subscription's")
	ErrMarketRateLimited  = errors.New("market ban list: too many snapshots for the site")
)

// MarketSync is one subscriber snapshot (normalized) for a leaf site of the
// grant's market tenant (TenantScopeID, subscription Key for the audit).
type MarketSync struct {
	TenantScopeID uuid.UUID
	Key           string
	Request       bansync.Request
	RequestID     string
}

// MarketResult is what the leaf took: the revision it runs for the site
// (Stale: the snapshot was older, nothing written), the refused entries, and
// when the site's market rows last changed (MarketDelivery since).
type MarketResult struct {
	Revision  int64
	Stale     bool
	Accepted  int
	Refused   []bansync.Refusal
	ChangedAt time.Time
}

type marketRef struct {
	ref         uuid.UUID
	entryID     uuid.UUID
	client      string
	until       time.Time
	bannedAt    time.Time
	releasedAt  *time.Time
	releasedBy  *uuid.UUID
	cause       *string
	buyerSource string
}

func (r marketRef) active(now time.Time) bool { return r.releasedAt == nil && r.until.After(now) }

// ApplyMarket reconciles the tenant's market rows of the leaf site with the
// snapshot: a listed ban is added (or extended, or added again after it
// expired or the subscription paused), a listed release releases it, an
// active row the snapshot no longer has expires now.
func (s *Store) ApplyMarket(ctx context.Context, sync MarketSync) (MarketResult, error) {
	now := s.now().UTC().Truncate(time.Microsecond)
	req := sync.Request
	if sync.RequestID == "" {
		sync.RequestID = fmt.Sprintf("market-ban-%s-%d", req.SiteID, req.Revision)
	}
	var result MarketResult
	var counts struct{ added, extended, released, expired int }
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var live bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM sites WHERE id=$1 AND scope_id=$2 AND deleted_at IS NULL)`,
			req.LeafSiteID, sync.TenantScopeID).Scan(&live); err != nil {
			return err
		}
		if !live {
			return ErrMarketSiteNotFound
		}
		// One writer per subscription: its limits count over all its sites.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('security-ban-market/'||$1::text, 0))`,
			sync.TenantScopeID); err != nil {
			return err
		}
		var revision int64
		var windowStart, changedAt time.Time
		var messages int
		err := tx.QueryRow(ctx, `SELECT revision,window_start,window_messages,updated_at FROM market_supply_ban_sites
			WHERE tenant_scope_id=$1 AND site_id=$2`, sync.TenantScopeID, req.SiteID).Scan(&revision, &windowStart, &messages, &changedAt)
		known := err == nil
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if !known || !now.Before(windowStart.Add(time.Minute)) {
			windowStart, messages = now, 0
		}
		if messages >= MaxMarketMessagesPerMinute {
			return ErrMarketRateLimited
		}
		messages++
		if known && req.Revision < revision {
			// Older than what runs: count it, write nothing else.
			result = MarketResult{Revision: revision, Stale: true, ChangedAt: changedAt, Refused: []bansync.Refusal{}}
			_, err := tx.Exec(ctx, `UPDATE market_supply_ban_sites SET window_start=$3,window_messages=$4
				WHERE tenant_scope_id=$1 AND site_id=$2`, sync.TenantScopeID, req.SiteID, windowStart, messages)
			return err
		}
		refs, err := loadMarketRefs(ctx, tx, sync.TenantScopeID, req.SiteID)
		if err != nil {
			return err
		}
		var otherActive, recent int
		if err := tx.QueryRow(ctx, `SELECT
				count(*) FILTER (WHERE ref.site_id<>$2 AND entry.released_at IS NULL AND entry.banned_until > $3),
				count(*) FILTER (WHERE ref.entry_created_at > $3 - interval '1 minute')
			FROM market_supply_ban_refs ref JOIN security_ban_entries entry ON entry.id=ref.entry_id
			WHERE ref.tenant_scope_id=$1`, sync.TenantScopeID, req.SiteID, now).Scan(&otherActive, &recent); err != nil {
			return err
		}
		listed := map[uuid.UUID]bool{}
		for _, release := range req.Releases {
			listed[release.Ref] = true
			current, ok := refs[release.Ref]
			if !ok || !current.active(now) {
				continue
			}
			if err := releaseMarketRow(ctx, tx, current, now, releaseByBuyer); err != nil {
				return err
			}
			counts.released++
		}
		// Bans the leaf already runs keep their place under the limits.
		bans := slices.Clone(req.Bans)
		slices.SortStableFunc(bans, func(a, b bansync.Ban) int {
			ai, bi := refs[a.Ref].entryID != uuid.Nil && refs[a.Ref].active(now), refs[b.Ref].entryID != uuid.Nil && refs[b.Ref].active(now)
			switch {
			case ai && !bi:
				return -1
			case bi && !ai:
				return 1
			}
			return 0
		})
		result.Refused = []bansync.Refusal{}
		refuse := func(ref uuid.UUID, code string) {
			result.Refused = append(result.Refused, bansync.Refusal{Ref: ref, Code: code})
		}
		siteActive := 0
		for _, ban := range bans {
			listed[ban.Ref] = true
			client, ok := canonicalClient(ban.Client)
			if !ok {
				refuse(ban.Ref, bansync.RefuseInvalidClient)
				continue
			}
			until := time.Unix(ban.Until, 0).UTC()
			if !until.After(now) {
				continue // over on the subscriber too
			}
			current, known := refs[ban.Ref]
			if known && current.client != clientText(client) {
				// An entry never changes its client: refuse rather than move it.
				refuse(ban.Ref, bansync.RefuseInvalidClient)
				continue
			}
			switch {
			case known && current.active(now):
				siteActive++
				if until.After(current.until) {
					if _, err := tx.Exec(ctx, `UPDATE security_ban_entries SET banned_until=least($2, banned_at + interval '30 days')
						WHERE id=$1`, current.entryID, until); err != nil {
						return err
					}
					counts.extended++
				}
				continue
			case known && current.releasedAt != nil && (current.cause == nil || *current.cause == releaseByBuyer):
				// Released by the leaf's operator (or by the subscriber before:
				// a released entry never bans again).
				if current.cause == nil {
					refuse(ban.Ref, bansync.RefuseReleasedBySupplier)
				}
				continue
			}
			// New, expired, or released while the subscription was paused.
			if otherActive+siteActive >= MaxMarketTenantActive {
				refuse(ban.Ref, bansync.RefuseTenantLimit)
				continue
			}
			if recent >= MaxMarketNewPerMinute {
				refuse(ban.Ref, bansync.RefuseRateLimited)
				continue
			}
			id, err := uuid.NewV7()
			if err != nil {
				return err
			}
			until = minTime(until, now.Add(bansync.MaxBanDuration))
			if _, err := tx.Exec(ctx, `INSERT INTO security_ban_entries(id,tenant_scope_id,site_id,client_ip,source,reason,
				banned_at,banned_until,source_event_id) VALUES($1,$2,$3,$4,'market',$5,$6,$7,$8)`,
				id, sync.TenantScopeID, req.LeafSiteID, client, ban.Reason, now, until, "market:"+id.String()); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO market_supply_ban_refs(tenant_scope_id,site_id,ref,leaf_site_id,entry_id,
				buyer_source,entry_created_at) VALUES($1,$2,$3,$4,$5,$6,$7)
				ON CONFLICT (tenant_scope_id,site_id,ref) DO UPDATE SET leaf_site_id=EXCLUDED.leaf_site_id,
					entry_id=EXCLUDED.entry_id,buyer_source=EXCLUDED.buyer_source,
					entry_created_at=EXCLUDED.entry_created_at,release_cause=NULL`,
				sync.TenantScopeID, req.SiteID, ban.Ref, req.LeafSiteID, id, ban.Source, now); err != nil {
				return err
			}
			siteActive++
			recent++
			counts.added++
		}
		// Active rows the snapshot no longer has: over on the subscriber.
		for ref, current := range refs {
			if listed[ref] || !current.active(now) {
				continue
			}
			if _, err := tx.Exec(ctx, `UPDATE security_ban_entries SET banned_until=greatest($2, banned_at + interval '1 microsecond')
				WHERE id=$1 AND released_at IS NULL`, current.entryID, now); err != nil {
				return err
			}
			counts.expired++
		}
		changed := counts.added+counts.extended+counts.released+counts.expired > 0
		if changed || !known {
			changedAt = now
		}
		if _, err := tx.Exec(ctx, `INSERT INTO market_supply_ban_sites(tenant_scope_id,site_id,leaf_site_id,revision,
				window_start,window_messages,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7)
			ON CONFLICT (tenant_scope_id,site_id) DO UPDATE SET leaf_site_id=EXCLUDED.leaf_site_id,
				revision=greatest(market_supply_ban_sites.revision,EXCLUDED.revision),window_start=EXCLUDED.window_start,
				window_messages=EXCLUDED.window_messages,updated_at=EXCLUDED.updated_at`,
			sync.TenantScopeID, req.SiteID, req.LeafSiteID, req.Revision, windowStart, messages, changedAt); err != nil {
			return err
		}
		result.Revision, result.ChangedAt = max(req.Revision, revision), changedAt
		result.Accepted = len(req.Bans) - len(result.Refused)
		if !changed && len(result.Refused) == 0 {
			return nil
		}
		return s.audit(ctx, tx, audit.Event{ScopeID: sync.TenantScopeID, Action: AuditMarketSync, ResourceType: "site",
			ResourceID: req.LeafSiteID.String(), RequestID: sync.RequestID, Result: "success",
			ActorKind: audit.ActorSystem, ActorRef: "market:" + sync.Key,
			Payload: map[string]any{"subscription": sync.Key, "subscriber_site_id": req.SiteID.String(), "revision": req.Revision,
				"added": counts.added, "extended": counts.extended, "released": counts.released, "expired": counts.expired,
				"refused": len(result.Refused)}})
	})
	if err != nil {
		return MarketResult{}, fmt.Errorf("apply market ban list: %w", err)
	}
	if counts.added+counts.extended+counts.released+counts.expired > 0 {
		s.notify()
	}
	return result, nil
}

// MarketTenant is a market tenant holding active market rows.
type MarketTenant struct {
	ScopeID uuid.UUID
	Key     string
}

const marketKeySQL = `COALESCE((SELECT substr(account.username,5) FROM memberships membership
	JOIN users account ON account.id=membership.user_id
	WHERE membership.scope_id=ref.tenant_scope_id AND account.username LIKE 'mkt-%' ORDER BY 1 LIMIT 1),'')`

// ActiveMarketTenants lists the market tenants with active market rows.
func (s *Store) ActiveMarketTenants(ctx context.Context) ([]MarketTenant, error) {
	rows, err := s.pool.Query(ctx, `SELECT DISTINCT ref.tenant_scope_id, `+marketKeySQL+`
		FROM market_supply_ban_refs ref JOIN security_ban_entries entry ON entry.id=ref.entry_id
		WHERE entry.released_at IS NULL AND entry.banned_until > $1`, s.now().UTC())
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (MarketTenant, error) {
		var t MarketTenant
		return t, row.Scan(&t.ScopeID, &t.Key)
	})
}

// ReleaseMarketTenant releases every active market row of the tenant: its
// subscription ended or is paused (reason). A later snapshot after it serves
// again bans them anew; an entry the subscriber released meanwhile stays out.
func (s *Store) ReleaseMarketTenant(ctx context.Context, tenant MarketTenant, reason string) (int, error) {
	now := s.now().UTC().Truncate(time.Microsecond)
	released := 0
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('security-ban-market/'||$1::text, 0))`,
			tenant.ScopeID); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `UPDATE security_ban_entries entry SET released_at=greatest($2, entry.banned_at)
			FROM market_supply_ban_refs ref WHERE ref.entry_id=entry.id AND ref.tenant_scope_id=$1
			  AND entry.released_at IS NULL AND entry.banned_until > $2 RETURNING entry.id`, tenant.ScopeID, now)
		if err != nil {
			return err
		}
		ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		if err != nil || len(ids) == 0 {
			return err
		}
		released = len(ids)
		if _, err := tx.Exec(ctx, `UPDATE market_supply_ban_refs SET release_cause=$2 WHERE entry_id=ANY($1)`,
			ids, releaseBySubscription); err != nil {
			return err
		}
		return s.audit(ctx, tx, audit.Event{ScopeID: tenant.ScopeID, Action: AuditMarketRelease, ResourceType: "market_subscription",
			ResourceID: tenant.Key, RequestID: "market-ban-release-" + tenant.Key, Result: "success",
			ActorKind: audit.ActorSystem, ActorRef: "market:" + tenant.Key,
			Payload: map[string]any{"subscription": tenant.Key, "released": released, "reason": reason}})
	})
	if err != nil {
		return 0, fmt.Errorf("release market bans: %w", err)
	}
	if released > 0 {
		s.notify()
	}
	return released, nil
}

// SiteDelivery is how far the active nodes serving the site are with the
// ban list as it was at since (MarketResult.ChangedAt): a node counts as
// applied once a whole publication pass began at or after since and its
// receipt answers the revision it was last sent (a node never sent one holds
// nothing for the site, which is current too); failed when its receipt for
// that revision refused it.
func (distributor *Distributor) SiteDelivery(ctx context.Context, siteID uuid.UUID, since time.Time) (bansync.Nodes, error) {
	distributor.mu.Lock()
	passed := !distributor.passStarted.IsZero() && !distributor.passStarted.Before(since)
	distributor.mu.Unlock()
	out := bansync.Nodes{State: bansync.NodesNone}
	err := pgx.BeginTxFunc(ctx, distributor.config.Pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		serving, err := servingNodes(ctx, tx, []uuid.UUID{siteID})
		if err != nil || len(serving) == 0 {
			return err
		}
		nodes := mapKeys(serving)
		slices.SortFunc(nodes, func(a, b uuid.UUID) int { return bytes.Compare(a[:], b[:]) })
		out.Total = len(nodes)
		type state struct {
			revision, applied int64
			ok                *bool
			code              string
			published         time.Time
			reported          *time.Time
		}
		rows, err := tx.Query(ctx, `SELECT node_id,revision,applied_revision,applied,error_code,published_at,reported_at
			FROM security_ban_node_state WHERE node_id=ANY($1)`, nodes)
		if err != nil {
			return err
		}
		states := map[uuid.UUID]state{}
		for rows.Next() {
			var id uuid.UUID
			var v state
			if err := rows.Scan(&id, &v.revision, &v.applied, &v.ok, &v.code, &v.published, &v.reported); err != nil {
				rows.Close()
				return err
			}
			states[id] = v
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, node := range nodes {
			v, known := states[node]
			switch {
			case known && v.ok != nil && !*v.ok && v.code != "" && v.reported != nil && !v.reported.Before(v.published):
				out.Failed++
				if out.Reason == "" {
					out.Reason = v.code
				}
			case passed && (!known || v.applied >= v.revision):
				out.Applied++
			}
		}
		return nil
	})
	if err != nil {
		return bansync.Nodes{}, fmt.Errorf("read security ban delivery: %w", err)
	}
	switch {
	case out.Total == 0:
	case out.Failed > 0:
		out.State = bansync.NodesFailed
	case out.Applied == out.Total:
		out.State = bansync.NodesApplied
	default:
		out.State = bansync.NodesDelivering
	}
	return out, nil
}

func loadMarketRefs(ctx context.Context, tx pgx.Tx, scope, site uuid.UUID) (map[uuid.UUID]marketRef, error) {
	rows, err := tx.Query(ctx, `SELECT ref.ref,ref.entry_id,entry.client_ip,entry.banned_until,entry.banned_at,
			entry.released_at,entry.released_by,ref.release_cause,ref.buyer_source
		FROM market_supply_ban_refs ref JOIN security_ban_entries entry ON entry.id=ref.entry_id
		WHERE ref.tenant_scope_id=$1 AND ref.site_id=$2 FOR UPDATE OF entry`, scope, site)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[uuid.UUID]marketRef{}
	for rows.Next() {
		var r marketRef
		var client netip.Prefix
		if err := rows.Scan(&r.ref, &r.entryID, &client, &r.until, &r.bannedAt, &r.releasedAt, &r.releasedBy,
			&r.cause, &r.buyerSource); err != nil {
			return nil, err
		}
		r.client = clientText(client)
		out[r.ref] = r
	}
	return out, rows.Err()
}

func releaseMarketRow(ctx context.Context, tx pgx.Tx, r marketRef, now time.Time, cause string) error {
	if _, err := tx.Exec(ctx, `UPDATE security_ban_entries SET released_at=greatest($2, banned_at)
		WHERE id=$1 AND released_at IS NULL`, r.entryID, now); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE market_supply_ban_refs SET release_cause=$2 WHERE entry_id=$1`, r.entryID, cause)
	return err
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
