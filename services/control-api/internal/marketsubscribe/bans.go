package marketsubscribe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/cdnca/cdnca/libs/marketproto/bansync"
	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/cdnca/cdnca/services/control-api/internal/marketclient"
	"github.com/cdnca/cdnca/services/control-api/internal/securityban"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// The subscriber side of market ban lists: the
// security ban list of a site served by market leaves goes to each of them
// as one snapshot (libs/marketproto/bansync) — active bans and the releases
// of the last bansync.ReleaseWindow — whenever it changes, and again while the
// leaf's nodes do not run it yet (backing off up to banProbeMax) and every
// banRefresh after. site_supply_ban_deliveries keeps, per leaf, the last
// revision sent and what the leaf answered; the ban list page reads it
// (SiteBanDeliveries).
const (
	banCallTimeout = 20 * time.Second
	banRefresh     = 10 * time.Minute
	banProbeFirst  = 3 * time.Second
	banProbeMax    = 60 * time.Second
	// banMinGap: a changed list is sent at most this often to one leaf.
	banMinGap      = 3 * time.Second
	banRetryLong   = 10 * time.Minute
	banParallel    = 8
	banPassEvery   = 5 * time.Second
	unsupportedFor = 30 * time.Minute
)

// Subscriber-side reasons (site_supply_ban_deliveries.reason).
const (
	BanReasonRelayRefused = "relay_refused"
	BanReasonTimeout      = "leaf_timeout"
	BanReasonLeafError    = "leaf_error"
	BanReasonUnknown      = "leaf_reason_unknown"
)

// Delivery states (site_supply_ban_deliveries.state).
const (
	banSent        = "sent"
	banAccepted    = "accepted"
	banRejected    = "rejected"
	banUnsupported = "unsupported"
)

var banCodePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// WakeBans runs a ban pass soon (the ban list changed).
func (s *Service) WakeBans() {
	select {
	case s.banWake <- struct{}{}:
	default:
	}
}

// RunBanSync pushes ban lists until ctx ends: on WakeBans and every
// banPassEvery, never closer than banMinGap.
func (s *Service) RunBanSync(ctx context.Context, log *slog.Logger) error {
	ticker := time.NewTicker(banPassEvery)
	defer ticker.Stop()
	for {
		if _, err := s.PushBans(ctx); err != nil && ctx.Err() == nil {
			log.Warn("market ban list push", "error", err)
		}
		gap := time.NewTimer(banMinGap)
		select {
		case <-ctx.Done():
			gap.Stop()
			return nil
		case <-gap.C:
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		case <-s.banWake:
		}
	}
}

// banSnapshot is a site's list as sent: the snapshot's entries, those over
// bansync.MaxBans refused here (site_limit), and its digest.
type banSnapshot struct {
	bans     []bansync.Ban
	releases []bansync.Release
	refused  []bansync.Refusal
	digest   string
}

func (b banSnapshot) empty() bool { return len(b.bans)+len(b.releases) == 0 }

// snapshot reads the site's active bans (newest first: those over MaxBans
// are refused here) and recent releases.
func (s *Service) snapshot(ctx context.Context, siteID uuid.UUID, now time.Time) (banSnapshot, error) {
	rows, err := s.pool.Query(ctx, `SELECT id,client_ip,source,reason,banned_until,released_at FROM security_ban_entries
		WHERE site_id=$1 AND ((released_at IS NULL AND banned_until > $2) OR released_at > $3)
		ORDER BY banned_at DESC, id`, siteID, now, now.Add(-bansync.ReleaseWindow))
	if err != nil {
		return banSnapshot{}, err
	}
	defer rows.Close()
	out := banSnapshot{bans: []bansync.Ban{}, releases: []bansync.Release{}, refused: []bansync.Refusal{}}
	for rows.Next() {
		var id uuid.UUID
		var client netip.Prefix
		var source, reason string
		var until time.Time
		var released *time.Time
		if err := rows.Scan(&id, &client, &source, &reason, &until, &released); err != nil {
			return banSnapshot{}, err
		}
		if released != nil {
			if len(out.releases) < bansync.MaxReleases {
				out.releases = append(out.releases, bansync.Release{Ref: id, ReleasedAt: max(1, released.Unix())})
			}
			continue
		}
		if len(out.bans) >= bansync.MaxBans {
			out.refused = append(out.refused, bansync.Refusal{Ref: id, Code: bansync.RefuseSiteLimit})
			continue
		}
		text := client.String()
		if client.IsSingleIP() {
			text = client.Addr().String()
		}
		switch source {
		case "manual", "cc", "waf", "autodefense":
		default:
			source = "manual"
		}
		out.bans = append(out.bans, bansync.Ban{Ref: id, Client: text, Until: until.Unix(), Source: source,
			Reason: banReason(reason)})
	}
	if err := rows.Err(); err != nil {
		return banSnapshot{}, err
	}
	req := bansync.Request{SiteID: siteID, LeafSiteID: siteID, Revision: 1, Bans: out.bans, Releases: out.releases}
	if err := req.Normalize(); err != nil {
		return banSnapshot{}, fmt.Errorf("ban snapshot of %s: %w", siteID, err)
	}
	out.bans, out.releases, out.digest = req.Bans, req.Releases, req.Digest()
	return out, nil
}

// banReason is the stored reason as a snapshot carries it (no control
// characters, at most bansync.MaxReason runes).
func banReason(reason string) string {
	reason = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, reason)
	if runes := []rune(strings.TrimSpace(reason)); len(runes) > bansync.MaxReason {
		return string(runes[:bansync.MaxReason])
	}
	return strings.TrimSpace(reason)
}

// banJob is one snapshot to send to one leaf.
type banJob struct {
	siteID, supplyID, leafSite uuid.UUID
	leaf                       Leaf
	revision                   int64
	attempt                    int
	snapshot                   banSnapshot
}

// PushBans runs one pass over every site with a ban list (or with leaves
// still holding one) and its market leaves; it returns the snapshots sent.
func (s *Service) PushBans(ctx context.Context) (int, error) {
	now := s.now().UTC()
	rows, err := s.pool.Query(ctx, `SELECT DISTINCT entry.site_id FROM security_ban_entries entry
			JOIN site_supply_leaf_sites leaf ON leaf.site_id=entry.site_id AND leaf.leaf_site_id IS NOT NULL
			WHERE (entry.released_at IS NULL AND entry.banned_until > $1) OR entry.released_at > $2
		UNION SELECT site_id FROM site_supply_ban_deliveries`, now, now.Add(-bansync.ReleaseWindow))
	if err != nil {
		return 0, fmt.Errorf("list ban list sites: %w", err)
	}
	sites, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return 0, fmt.Errorf("list ban list sites: %w", err)
	}
	var jobs []banJob
	var errs []error
	for _, siteID := range sites {
		planned, err := s.planBans(ctx, siteID, now)
		if err != nil {
			errs = append(errs, fmt.Errorf("ban list of %s: %w", siteID, err))
			continue
		}
		jobs = append(jobs, planned...)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	slots := make(chan struct{}, banParallel)
	for _, job := range jobs {
		wg.Add(1)
		slots <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			if err := s.sendBans(ctx, job); err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return len(jobs), errors.Join(errs...)
}

type banRow struct {
	found          bool
	leafSite       uuid.UUID
	revision       int64
	digest, state  string
	reason         string
	attempts       int
	sentAt, nextAt time.Time
}

// planBans records, per current leaf of the site, the snapshot to send now
// (as sent) and returns those jobs; leaves the site no longer has lose their
// row, and an empty list already answered needs no row.
func (s *Service) planBans(ctx context.Context, siteID uuid.UUID, now time.Time) ([]banJob, error) {
	targets, err := s.targets(ctx, siteID)
	switch {
	case errors.Is(err, ErrNoMarketBinding):
		_, err := s.pool.Exec(ctx, `DELETE FROM site_supply_ban_deliveries WHERE site_id=$1`, siteID)
		return nil, err
	case errors.Is(err, ErrSitePackageUnavailable), errors.Is(err, ErrNoLeaves):
		// The leaves keep what they have until the supply serves again.
		return nil, nil
	case err != nil:
		return nil, err
	}
	var current []target
	var supplies, members []uuid.UUID
	var pools []string
	for _, t := range targets {
		if t.stored && t.leafSite != nil && t.revision > 0 {
			current = append(current, t)
			supplies, members, pools = append(supplies, t.supplyID), append(members, t.leaf.LeafMemberID), append(pools, t.leaf.NodePoolRef)
		}
	}
	if _, err := s.pool.Exec(ctx, `DELETE FROM site_supply_ban_deliveries delivery WHERE delivery.site_id=$1
		AND NOT EXISTS (SELECT 1 FROM unnest($2::uuid[],$3::uuid[],$4::text[]) AS keep(supply_id,member_id,pool_ref)
			WHERE keep.supply_id=delivery.supply_id AND keep.member_id=delivery.leaf_member_id AND keep.pool_ref=delivery.node_pool_ref)`,
		siteID, supplies, members, pools); err != nil {
		return nil, err
	}
	if len(current) == 0 {
		return nil, nil
	}
	snapshot, err := s.snapshot(ctx, siteID, now)
	if err != nil {
		return nil, err
	}
	var jobs []banJob
	for _, t := range current {
		row, err := s.banRow(ctx, siteID, t)
		if err != nil {
			return nil, err
		}
		changed := !row.found || row.digest != snapshot.digest || row.leafSite != *t.leafSite
		job := banJob{siteID: siteID, supplyID: t.supplyID, leafSite: *t.leafSite, leaf: t.leaf, snapshot: snapshot}
		switch {
		case !row.found && snapshot.empty():
			continue
		case !changed && snapshot.empty() && row.state != banSent:
			// The leaf holds nothing of this site any more.
			if _, err := s.pool.Exec(ctx, `DELETE FROM site_supply_ban_deliveries WHERE site_id=$1 AND supply_id=$2
				AND leaf_member_id=$3 AND node_pool_ref=$4 AND revision=$5`, siteID, t.supplyID, t.leaf.LeafMemberID,
				t.leaf.NodePoolRef, row.revision); err != nil {
				return nil, err
			}
			continue
		case changed && row.found && holdsOff(row) && now.Before(row.nextAt):
			// Refused for a while (old leaf, rate, paused): wait it out.
			continue
		case changed && row.found && now.Before(row.sentAt.Add(banMinGap)):
			continue
		case changed:
			job.revision, job.attempt = max(row.revision+1, now.UnixMilli()), 1
		case now.Before(row.nextAt):
			continue
		default:
			job.revision, job.attempt = row.revision, row.attempts+1
		}
		if err := s.markBanSent(ctx, job, now); err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	return jobs, nil
}

// holdsOff: a refusal that a changed list does not lift.
func holdsOff(row banRow) bool {
	return row.state == banUnsupported || row.state == banRejected &&
		(row.reason == bansync.ErrCodeRateLimited || row.reason == bansync.ErrCodePaused || row.reason == bansync.ErrCodeEnded ||
			row.reason == BanReasonRelayRefused)
}

func (s *Service) banRow(ctx context.Context, siteID uuid.UUID, t target) (banRow, error) {
	var row banRow
	err := s.pool.QueryRow(ctx, `SELECT leaf_site_id,revision,digest,state,reason,attempts,sent_at,next_at
		FROM site_supply_ban_deliveries WHERE site_id=$1 AND supply_id=$2 AND leaf_member_id=$3 AND node_pool_ref=$4`,
		siteID, t.supplyID, t.leaf.LeafMemberID, t.leaf.NodePoolRef).
		Scan(&row.leafSite, &row.revision, &row.digest, &row.state, &row.reason, &row.attempts, &row.sentAt, &row.nextAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return banRow{}, nil
	}
	row.found = err == nil
	return row, err
}

// markBanSent records the job before it is sent. A new revision starts with
// no reason; the leaf's last answer (accepted entries, nodes) stays until the
// next one replaces it.
func (s *Service) markBanSent(ctx context.Context, job banJob, now time.Time) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO site_supply_ban_deliveries(site_id,supply_id,leaf_member_id,node_pool_ref,
			leaf_site_id,revision,digest,state,attempts,sent_at,next_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,'sent',$8,$9,$10)
		ON CONFLICT (site_id,supply_id,leaf_member_id,node_pool_ref) DO UPDATE SET leaf_site_id=EXCLUDED.leaf_site_id,
			revision=EXCLUDED.revision,digest=EXCLUDED.digest,state='sent',attempts=EXCLUDED.attempts,
			reason=CASE WHEN EXCLUDED.attempts=1 THEN '' ELSE site_supply_ban_deliveries.reason END,
			detail=CASE WHEN EXCLUDED.attempts=1 THEN '' ELSE site_supply_ban_deliveries.detail END,
			sent_at=EXCLUDED.sent_at,next_at=EXCLUDED.next_at`,
		job.siteID, job.supplyID, job.leaf.LeafMemberID, job.leaf.NodePoolRef, job.leafSite, job.revision,
		job.snapshot.digest, job.attempt, now, now.Add(banCallTimeout+probeBackoff(job.attempt)))
	return err
}

// probeBackoff is the wait after the n-th unsettled attempt: banProbeFirst
// doubling, at most banProbeMax.
func probeBackoff(attempt int) time.Duration {
	wait := banProbeFirst
	for i := 1; i < attempt && wait < banProbeMax; i++ {
		wait *= 2
	}
	return min(wait, banProbeMax)
}

// banOutcome is what to save for one sent job.
type banOutcome struct {
	state, reason, detail string
	// answered: the leaf's entries / nodes replace the stored ones.
	answered bool
	accepted []uuid.UUID
	refused  []bansync.Refusal
	nodes    bansync.Nodes
	// newer: the leaf runs a newer revision; the next pass sends above it.
	newer int64
	next  time.Time
}

func (s *Service) sendBans(ctx context.Context, job banJob) error {
	req := bansync.Request{SiteID: job.siteID, LeafSiteID: job.leafSite, Revision: job.revision,
		Bans: job.snapshot.bans, Releases: job.snapshot.releases}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s/%s/%s/%s/%d/%d", job.siteID, job.supplyID, job.leaf.LeafMemberID,
		job.leaf.NodePoolRef, job.revision, job.attempt)))
	callCtx, cancel := context.WithTimeout(ctx, banCallTimeout)
	reply, err := s.caller.Call(callCtx, job.leaf, bansync.OpSync, nil, "bans-"+hex.EncodeToString(sum[:16]), req)
	cancel()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return s.saveBans(ctx, job, banDecision(job, reply, err, s.now().UTC()))
}

// banDecision turns a reply (or the call's error) into what to save.
func banDecision(job banJob, reply siteconf.Reply, err error, now time.Time) banOutcome {
	if err != nil {
		if status, _, rejected := marketclient.Rejected(err); rejected && status >= 400 && status < 500 &&
			status != http.StatusTooManyRequests && status != http.StatusRequestTimeout {
			// The market refuses the message: a market that predates the
			// operation, or the grant is gone (both: "relay refused").
			return banOutcome{state: banRejected, reason: BanReasonRelayRefused, detail: strconv.Itoa(status),
				next: now.Add(banRetryLong)}
		}
		return banOutcome{state: banSent, reason: BanReasonTimeout, detail: bounded(err.Error()),
			next: now.Add(probeBackoff(job.attempt))}
	}
	if !reply.OK {
		code := reply.Error
		switch {
		case bansync.Unsupported(code):
			return banOutcome{state: banUnsupported, reason: "peer_unsupported", next: now.Add(unsupportedFor)}
		case code == bansync.ErrCodeRateLimited:
			return banOutcome{state: banRejected, reason: code, next: now.Add(banProbeMax)}
		case code == bansync.ErrCodePaused || code == bansync.ErrCodeEnded:
			// The leaf lifted the subscriber's bans: none is accepted now.
			return banOutcome{state: banRejected, reason: code, answered: true, accepted: []uuid.UUID{},
				refused: []bansync.Refusal{}, nodes: bansync.Nodes{State: bansync.NodesNone}, next: now.Add(5 * time.Minute)}
		case code == bansync.ErrCodeInvalid || code == bansync.ErrCodeSiteNotFound || code == bansync.ErrCodeUnavailable:
			return banOutcome{state: banRejected, reason: code, next: now.Add(banRetryLong)}
		}
		// Another refusal (a grant the leaf has not synced yet ...): soon again.
		return banOutcome{state: banRejected, reason: BanReasonLeafError, detail: bounded(code), next: now.Add(time.Minute)}
	}
	var status bansync.Status
	if json.Unmarshal(reply.Status, &status) != nil {
		return banOutcome{state: banRejected, reason: BanReasonLeafError, detail: "status", next: now.Add(time.Minute)}
	}
	if status.Revision > job.revision {
		return banOutcome{state: banSent, newer: status.Revision, next: now}
	}
	sent := map[uuid.UUID]bool{}
	for _, ban := range job.snapshot.bans {
		sent[ban.Ref] = true
	}
	out := banOutcome{state: banAccepted, answered: true, refused: append([]bansync.Refusal{}, job.snapshot.refused...)}
	refused := map[uuid.UUID]bool{}
	for _, refusal := range status.Refused {
		if !sent[refusal.Ref] || refused[refusal.Ref] {
			continue
		}
		code := refusal.Code
		if !banCodePattern.MatchString(code) {
			code = BanReasonUnknown
		}
		refused[refusal.Ref] = true
		out.refused = append(out.refused, bansync.Refusal{Ref: refusal.Ref, Code: code})
	}
	for _, ban := range job.snapshot.bans {
		if !refused[ban.Ref] {
			out.accepted = append(out.accepted, ban.Ref)
		}
	}
	out.nodes = status.Nodes
	switch out.nodes.State {
	case bansync.NodesApplied, bansync.NodesDelivering, bansync.NodesFailed, bansync.NodesNone, bansync.NodesOff:
	default:
		out.nodes.State = bansync.NodesDelivering
	}
	if out.nodes.Reason != "" && !banCodePattern.MatchString(out.nodes.Reason) {
		out.nodes.Reason = BanReasonUnknown
	}
	switch out.nodes.State {
	case bansync.NodesApplied, bansync.NodesOff:
		out.next = now.Add(banRefresh)
	case bansync.NodesFailed:
		out.next = now.Add(banProbeMax)
	default:
		out.next = now.Add(probeBackoff(job.attempt))
	}
	return out
}

// saveBans writes outcome over the row while it still holds job's snapshot.
func (s *Service) saveBans(ctx context.Context, job banJob, outcome banOutcome) error {
	now := s.now().UTC()
	digest := job.snapshot.digest
	revision := job.revision
	if outcome.newer > 0 {
		// Resend above the leaf's revision on the next pass.
		revision, digest = outcome.newer, strings.Repeat("0", 64)
	}
	var accepted, refused, nodes any
	if outcome.answered {
		accepted = append([]uuid.UUID{}, outcome.accepted...)
		raw, _ := json.Marshal(outcome.refused)
		refused = raw
		raw, _ = json.Marshal(outcome.nodes)
		nodes = raw
	}
	_, err := s.pool.Exec(ctx, `UPDATE site_supply_ban_deliveries SET state=$7,reason=$8,detail=$9,
			accepted_refs=COALESCE($10::uuid[],accepted_refs),refused=COALESCE($11::jsonb,refused),
			nodes=COALESCE($12::jsonb,nodes),answered_at=CASE WHEN $13 THEN $14 ELSE answered_at END,next_at=$15,
			revision=$16,digest=$17
		WHERE site_id=$1 AND supply_id=$2 AND leaf_member_id=$3 AND node_pool_ref=$4 AND revision=$5 AND digest=$6`,
		job.siteID, job.supplyID, job.leaf.LeafMemberID, job.leaf.NodePoolRef, job.revision, job.snapshot.digest,
		outcome.state, outcome.reason, outcome.detail, accepted, refused, nodes, outcome.answered, now, outcome.next,
		revision, digest)
	if err != nil {
		return fmt.Errorf("save ban delivery of %s: %w", job.siteID, err)
	}
	return nil
}

// SiteBanDeliveries lists, per site, the market leaves with a saved site
// (applied or committing) on its active market supplies and what each last
// answered for the site's ban list (securityban.MarketDeliveries).
func (s *Service) SiteBanDeliveries(ctx context.Context, sites []uuid.UUID) (map[uuid.UUID][]securityban.LeafBanDelivery, error) {
	rows, err := s.pool.Query(ctx, `SELECT leaf.site_id, COALESCE(delivery.state,''), COALESCE(delivery.reason,''),
			COALESCE(delivery.accepted_refs,'{}'), COALESCE(delivery.refused,'[]'), COALESCE(delivery.nodes,'{}')
		FROM site_supply_leaf_sites leaf
		JOIN site_supplies supply ON supply.id=leaf.supply_id AND supply.kind='market_subscription' AND supply.status='active'
		LEFT JOIN site_supply_ban_deliveries delivery ON delivery.site_id=leaf.site_id AND delivery.supply_id=leaf.supply_id
			AND delivery.leaf_member_id=leaf.leaf_member_id AND delivery.node_pool_ref=leaf.node_pool_ref
		WHERE leaf.site_id=ANY($1) AND leaf.leaf_site_id IS NOT NULL AND leaf.state IN ('applied','committing')
		  AND (delivery.site_id IS NOT NULL OR EXISTS (SELECT 1 FROM site_supply_bindings binding
			WHERE binding.site_id=leaf.site_id AND binding.supply_id=leaf.supply_id))
		ORDER BY leaf.site_id, leaf.supply_id, leaf.leaf_member_id, leaf.node_pool_ref`, sites)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[uuid.UUID][]securityban.LeafBanDelivery{}
	for rows.Next() {
		var siteID uuid.UUID
		var accepted []uuid.UUID
		var refusedRaw, nodesRaw []byte
		leaf := securityban.LeafBanDelivery{Accepted: map[uuid.UUID]bool{}, Refused: map[uuid.UUID]string{}}
		if err := rows.Scan(&siteID, &leaf.State, &leaf.Reason, &accepted, &refusedRaw, &nodesRaw); err != nil {
			return nil, err
		}
		for _, ref := range accepted {
			leaf.Accepted[ref] = true
		}
		var refused []bansync.Refusal
		if err := json.Unmarshal(refusedRaw, &refused); err != nil {
			return nil, fmt.Errorf("decode ban refusals: %w", err)
		}
		for _, refusal := range refused {
			leaf.Refused[refusal.Ref] = refusal.Code
		}
		if err := json.Unmarshal(nodesRaw, &leaf.Nodes); err != nil {
			return nil, fmt.Errorf("decode ban nodes: %w", err)
		}
		out[siteID] = append(out[siteID], leaf)
	}
	return out, rows.Err()
}
