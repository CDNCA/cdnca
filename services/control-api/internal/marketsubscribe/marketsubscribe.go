// Package marketsubscribe is the subscriber side of the node market
// (docs/marketplace/03-supply-api.md §5): it keeps the market subscriptions
// this controller bought as site supplies, and rolls a site revision out to
// every leaf behind a site's market bindings in three steps — review,
// prepare on all leaves, commit on all — rolling committed leaves back to the
// previous revision when any commit fails.
package marketsubscribe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/cdnca/cdnca/services/control-api/internal/cnameallocation"
	"github.com/cdnca/cdnca/services/control-api/internal/marketclient"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrNoMarketBinding = errors.New("market subscribe: site has no market supply binding")
	ErrNoLeaves        = errors.New("market subscribe: supply has no leaf with an active grant")
	ErrStaleRevision   = errors.New("market subscribe: a newer revision of this site already exists")
	ErrInvalid         = errors.New("market subscribe: invalid input")
	ErrNotFound        = errors.New("market subscribe: site or supply not found")
	// ErrSitePackageUnavailable: the site has no valid package and every
	// subscription bound to it is the controller's (fix-nopkgpub4).
	ErrSitePackageUnavailable = errors.New("market subscribe: site has no valid package for the controller's subscriptions")
	// ErrRevisionConflict: this revision already holds different content
	// (CORE-REV-01). Nothing was sent; re-read the site and save a new revision.
	ErrRevisionConflict = errors.New("market subscribe: this revision already holds a different config")
	// ErrReceiptPending: a leaf answered but its receipt could not be saved
	// (CORE-RECEIPT-02). The Result says which leaves; apply the same revision
	// and content again to complete them.
	ErrReceiptPending = errors.New("market subscribe: leaf result not saved, pending confirmation")
)

// Leaf is one supplier behind a market subscription.
type Leaf struct {
	LeafMemberID uuid.UUID `json:"leaf_member_id"`
	NodePoolRef  string    `json:"node_pool_ref"`
	GrantID      uuid.UUID `json:"grant_id"`
}

// Market lists this controller's own market subscriptions.
type Market interface {
	SupplyTargets(ctx context.Context) ([]marketclient.SupplyTarget, error)
}

// Caller sends one relay request to a leaf and waits for its reply.
type Caller interface {
	Call(ctx context.Context, leaf Leaf, op string, domains []string, idempotencyKey string, body any) (siteconf.Reply, error)
}

type Service struct {
	pool   *pgxpool.Pool
	market Market
	caller Caller
	now    func() time.Time

	autoDefense AutoDefenseReader
	// Attack digests relayed by leaves (secdigest.go).
	cards   Cards
	digests DigestStore
	// Saved sites PreviewSite/ApplySite compile (compile.go).
	sites  SiteReader
	routes RouteReader
	// originAuth reads the site's origin auth rules (compile_origin_auth.go).
	originAuth OriginAuthReader
	// Receipt reconciliation (reconcile.go).
	reconcile ReconcilePolicy
	notices   ReceiptNotifier
}

func isNoRows(err error) bool { return errors.Is(err, pgx.ErrNoRows) }

func New(pool *pgxpool.Pool, market Market, caller Caller) *Service {
	return &Service{pool: pool, market: market, caller: caller, now: time.Now}
}

// SyncTargets records every market subscription as a supply with its current
// CNAME target and leaves. Subscriptions the market no longer lists are
// suspended, not deleted: bindings and history stay.
func (s *Service) SyncTargets(ctx context.Context, platform uuid.UUID) (int, error) {
	targets, err := s.market.SupplyTargets(ctx)
	if err != nil {
		return 0, err
	}
	type entry struct {
		fqdn   string
		leaves []Leaf
	}
	subs := map[uuid.UUID]*entry{}
	for _, t := range targets {
		e := subs[t.SubscriptionID]
		if e == nil {
			e = &entry{leaves: []Leaf{}}
			subs[t.SubscriptionID] = e
		}
		if t.Aggregate {
			e.fqdn = t.FQDN
		} else if t.GrantID != nil {
			e.leaves = append(e.leaves, Leaf{LeafMemberID: t.LeafMemberID, NodePoolRef: t.NodePoolRef, GrantID: *t.GrantID})
		}
	}
	now := s.now().UTC()
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		seen := make([]uuid.UUID, 0, len(subs))
		for id, e := range subs {
			leaves, _ := json.Marshal(e.leaves)
			if _, err := tx.Exec(ctx, `INSERT INTO site_supplies (id,platform_scope_id,kind,name,market_subscription_id,
					target,target_synced_at,leaves,status,created_at,updated_at)
				VALUES ($1,$2,'market_subscription',$3,$4,$5,$6,$7,'active',$6,$6)
				ON CONFLICT (market_subscription_id) WHERE market_subscription_id IS NOT NULL DO UPDATE SET
					target=EXCLUDED.target, target_synced_at=EXCLUDED.target_synced_at, leaves=EXCLUDED.leaves,
					status=CASE WHEN site_supplies.status='retired' THEN 'retired' ELSE 'active' END, updated_at=EXCLUDED.updated_at`,
				uuid.New(), platform, "市场订阅 "+id.String()[:8], id, e.fqdn, now, leaves); err != nil {
				return err
			}
			seen = append(seen, id)
		}
		_, err := tx.Exec(ctx, `UPDATE site_supplies SET status='suspended', updated_at=$2
			WHERE kind='market_subscription' AND status='active' AND NOT (market_subscription_id = ANY($1))`, seen, now)
		return err
	})
	return len(subs), err
}

// Bind attaches a market supply to a site. Local node groups need no row:
// they come from the site's own columns.
func (s *Service) Bind(ctx context.Context, siteID, supplyID uuid.UUID, role string, priority int) error {
	if role != "primary" && role != "backup" || priority < 0 || priority > 1_000_000 {
		return ErrInvalid
	}
	// An active supply whose grants are all gone (no leaf) takes no new
	// binding (ErrNoLeaves); bindings it already has stay, so a supply that
	// recovers its leaves serves them again.
	tag, err := s.pool.Exec(ctx, `INSERT INTO site_supply_bindings (site_id,supply_id,role,priority,line_scope,created_at)
		SELECT site.id, supply.id, $3, $4, '', $5 FROM sites site, site_supplies supply
		WHERE site.id=$1 AND site.deleted_at IS NULL AND supply.id=$2 AND supply.status='active'
			AND (supply.kind <> 'market_subscription' OR jsonb_array_length(supply.leaves) > 0
				OR EXISTS (SELECT 1 FROM site_supply_bindings b WHERE b.site_id=site.id AND b.supply_id=supply.id AND b.line_scope=''))
		ON CONFLICT (site_id,supply_id,line_scope) DO UPDATE SET role=EXCLUDED.role, priority=EXCLUDED.priority`,
		siteID, supplyID, role, priority, s.now().UTC())
	if err != nil || tag.RowsAffected() > 0 {
		return err
	}
	var leaves int
	err = s.pool.QueryRow(ctx, `SELECT jsonb_array_length(supply.leaves) FROM sites site, site_supplies supply
		WHERE site.id=$1 AND site.deleted_at IS NULL AND supply.id=$2 AND supply.status='active' AND supply.kind='market_subscription'`,
		siteID, supplyID).Scan(&leaves)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	return ErrNoLeaves
}

// Unbind detaches a market supply from a site; leaf sites are not deleted.
func (s *Service) Unbind(ctx context.Context, siteID, supplyID uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM site_supply_bindings WHERE site_id=$1 AND supply_id=$2`, siteID, supplyID)
	return err
}

// Supply is one row of the supply list.
type Supply struct {
	ID                   uuid.UUID `json:"id"`
	Name                 string    `json:"name"`
	MarketSubscriptionID uuid.UUID `json:"market_subscription_id"`
	Target               string    `json:"target"`
	Status               string    `json:"status"`
	Leaves               []Leaf    `json:"leaves"`
}

func (s *Service) Supplies(ctx context.Context) ([]Supply, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, name, market_subscription_id, target, status, leaves FROM site_supplies
		WHERE kind='market_subscription' ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Supply{}
	for rows.Next() {
		var item Supply
		var raw []byte
		if err := rows.Scan(&item.ID, &item.Name, &item.MarketSubscriptionID, &item.Target, &item.Status, &raw); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &item.Leaves); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// LeafResult is the outcome on one leaf.
type LeafResult struct {
	Leaf     Leaf               `json:"leaf"`
	State    string             `json:"state"` // applied, blocked, failed, rolled_back, inconsistent, not_applied, receipt_pending
	Blockers []siteconf.Blocker `json:"blockers,omitempty"`
	Error    string             `json:"error,omitempty"`
	// LeafSiteID is the leaf's own site, kept on receipt_pending so the
	// outcome can be reconciled even though no receipt row holds it.
	LeafSiteID *uuid.UUID `json:"leaf_site_id,omitempty"`
}

// Result of one Apply. Applied is true only when every leaf runs Revision.
type Result struct {
	Revision int64  `json:"revision"`
	Digest   string `json:"digest"`
	Applied  bool   `json:"applied"`
	// Reason is set when the outcome is not final: receipt_pending.
	Reason string       `json:"reason,omitempty"`
	Leaves []LeafResult `json:"leaves"`
}

type target struct {
	supplyID uuid.UUID
	leaf     Leaf
	leafSite *uuid.UUID
	revision int64
	digest   string // applied digest when revision > 0
	stored   bool   // a receipt row exists
	// committing: a commit was sent and its receipt is unconfirmed.
	committing bool
}

// Preview asks every leaf to validate revision without changing anything
// (step 2 of 3). Apply repeats it, so a preview is advisory.
func (s *Service) Preview(ctx context.Context, siteID uuid.UUID, revision int64, cfg siteconf.Config) (Result, error) {
	return s.run(ctx, siteID, revision, cfg, false)
}

// Apply rolls revision out to every leaf behind the site's market bindings.
// Nothing changes on any leaf unless every leaf accepts the revision.
func (s *Service) Apply(ctx context.Context, siteID uuid.UUID, revision int64, cfg siteconf.Config) (Result, error) {
	return s.run(ctx, siteID, revision, cfg, true)
}

func (s *Service) run(ctx context.Context, siteID uuid.UUID, revision int64, cfg siteconf.Config, commit bool) (Result, error) {
	if err := s.withAutoDefense(ctx, siteID, &cfg); err != nil {
		return Result{}, err
	}
	if err := cfg.Normalize(); err != nil {
		return Result{}, err
	}
	result := Result{Revision: revision, Digest: cfg.Digest()}
	raw, _ := json.Marshal(cfg)
	if err := s.claim(ctx, siteID, revision, raw, result.Digest, commit); err != nil {
		return Result{}, err
	}
	targets, err := s.targets(ctx, siteID)
	if err != nil {
		return Result{}, err
	}
	if commit {
		// Same revision and content already confirmed on every leaf: the
		// stored outcome stands, nothing is sent again.
		done := true
		for _, t := range targets {
			done = done && !t.committing && t.revision == revision && t.digest == result.Digest
		}
		if done {
			for _, t := range targets {
				result.Leaves = append(result.Leaves, LeafResult{Leaf: t.leaf, State: "applied"})
			}
			result.Applied = true
			return result, nil
		}
		// Each leaf gets its receipt row before anything is sent, so a
		// database that cannot take receipts stops the rollout here.
		for _, t := range targets {
			if !t.stored {
				if err := s.record(ctx, siteID, t, 0, "", "pending", ""); err != nil {
					return Result{}, err
				}
			}
		}
	}
	key := func(op string, t target) string {
		return fmt.Sprintf("%s-%s-%d-%s-%s", op, siteID, revision, t.leaf.LeafMemberID, t.leaf.NodePoolRef)
	}

	// Step 2: prepare everywhere.
	ok := true
	for _, t := range targets {
		lr := LeafResult{Leaf: t.leaf, State: "applied"}
		reply, err := s.caller.Call(ctx, t.leaf, siteconf.OpPrepare, cfg.Domains, key("prep", t),
			siteconf.CommitRequest{SiteID: siteID, LeafSiteID: t.leafSite, Revision: revision, Config: cfg})
		switch {
		case err != nil:
			lr.State, lr.Error, ok = "failed", err.Error(), false
		case !reply.OK:
			lr.State, lr.Blockers, lr.Error, ok = "blocked", reply.Blockers, reply.Error, false
		case reply.Digest != result.Digest:
			lr.State, lr.Error, ok = "failed", "leaf normalized the config differently", false
		default:
			// Advisory (ML-22/ML-25): applied, but not everything takes effect
			// on this supply; the page shows why.
			lr.Blockers = reply.Blockers
		}
		result.Leaves = append(result.Leaves, lr)
	}
	if !commit {
		result.Applied = false
		return result, nil
	}
	if !ok {
		for i := range result.Leaves {
			if result.Leaves[i].State == "applied" {
				result.Leaves[i].State = "not_applied"
				_, _ = s.caller.Call(ctx, targets[i].leaf, siteconf.OpAbort, nil, key("abort", targets[i]),
					siteconf.SiteRef{SiteID: siteID})
			}
		}
		return result, nil
	}

	// Step 3: commit everywhere; on the first failure, roll committed leaves back.
	committed := []int{}
	for i, t := range targets {
		// The intent is saved before the commit is sent: should the leaf apply
		// it and its receipt not be saved, the reconciler finds the leaf
		// committing and completes it (reconcile.go). No intent, no commit.
		if err := s.markCommitting(ctx, siteID, t, revision, result.Digest); err != nil {
			result.Leaves[i].State, result.Leaves[i].Error = "not_applied", "intent not saved: "+err.Error()
			for j := i + 1; j < len(targets); j++ {
				result.Leaves[j].State = "not_applied"
			}
			pending := s.rollbackCommitted(ctx, siteID, targets, committed, revision, &result)
			if pending != nil {
				result.Reason = "receipt_pending"
				return result, fmt.Errorf("%w: %v", ErrReceiptPending, pending)
			}
			if result.Reason == "receipt_pending" {
				return result, ErrReceiptPending
			}
			return result, nil
		}
		reply, err := s.caller.Call(ctx, t.leaf, siteconf.OpCommit, cfg.Domains, key("commit", t),
			siteconf.CommitRequest{SiteID: siteID, LeafSiteID: t.leafSite, Revision: revision, Digest: result.Digest, Config: cfg})
		if err == nil && reply.OK && reply.LeafSiteID != nil {
			targets[i].leafSite = reply.LeafSiteID
			committed = append(committed, i)
			if err := s.record(ctx, siteID, targets[i], revision, result.Digest, "applied", ""); err != nil {
				// The leaf runs revision but we hold no receipt: neither
				// applied nor failed. The same revision again completes it.
				result.Leaves[i].State, result.Leaves[i].LeafSiteID = "receipt_pending", reply.LeafSiteID
				result.Leaves[i].Error = "receipt not saved: " + err.Error()
				result.Reason = "receipt_pending"
			}
			continue
		}
		msg := "commit refused"
		if err != nil {
			msg = err.Error()
		} else if reply.Error != "" {
			msg = reply.Error
		}
		result.Leaves[i].State, result.Leaves[i].Error = "failed", msg
		// Committed leaves are rolled back below; only receipts that still
		// cannot be saved leave the outcome pending.
		result.Reason = ""
		var pending error
		if err := s.record(ctx, siteID, t, t.revision, "", "failed", msg); err != nil {
			pending = err
		}
		for j := i + 1; j < len(targets); j++ {
			result.Leaves[j].State = "not_applied"
		}
		if err := s.rollbackCommitted(ctx, siteID, targets, committed, revision, &result); err != nil {
			pending = err
		}
		if pending != nil {
			result.Reason = "receipt_pending"
			return result, fmt.Errorf("%w: %v", ErrReceiptPending, pending)
		}
		return result, nil
	}
	if result.Reason != "" {
		return result, ErrReceiptPending
	}
	result.Applied = true
	return result, nil
}

// rollbackCommitted rolls the committed leaves back to their previous
// revision; the error is the last receipt that could not be saved.
func (s *Service) rollbackCommitted(ctx context.Context, siteID uuid.UUID, targets []target, committed []int,
	revision int64, result *Result) error {
	var pending error
	for _, c := range committed {
		state, err := s.rollback(ctx, siteID, targets[c], revision)
		result.Leaves[c].State = state
		if err != nil {
			result.Leaves[c].State, result.Leaves[c].LeafSiteID = "receipt_pending", targets[c].leafSite
			result.Leaves[c].Error, pending = "receipt not saved after "+state+": "+err.Error(), err
		}
	}
	return pending
}

// markCommitting saves, before a commit is sent, that the leaf may now run
// revision/digest (migration 565): the reconciler completes it after the
// grace period if no receipt follows. The applied revision and digest stay
// what the leaf ran before, for rollback.
func (s *Service) markCommitting(ctx context.Context, siteID uuid.UUID, t target, revision int64, digest string) error {
	now := s.now().UTC()
	tag, err := s.pool.Exec(ctx, `UPDATE site_supply_leaf_sites SET state='committing', pending_revision=$5,
			pending_digest=$6, reconcile_attempts=0, next_reconcile_at=$7, updated_at=$8,
			node_state='', node_reason='', node_detail='', node_check_attempts=0, node_checked_at=NULL, next_node_check_at=NULL
		WHERE site_id=$1 AND supply_id=$2 AND leaf_member_id=$3 AND node_pool_ref=$4`,
		siteID, t.supplyID, t.leaf.LeafMemberID, t.leaf.NodePoolRef, revision, digest, now.Add(s.reconcilePolicy().Grace), now)
	if err == nil && tag.RowsAffected() != 1 {
		err = fmt.Errorf("leaf receipt row missing")
	}
	return err
}

// claim binds revision to one config (CORE-REV-01). A lower revision than
// the newest stored one is stale; a stored revision with another digest is a
// conflict. Apply stores the snapshot first, so of two concurrent applies of
// one revision exactly one content wins; preview only checks.
func (s *Service) claim(ctx context.Context, siteID uuid.UUID, revision int64, raw []byte, digest string, commit bool) error {
	var latest int64
	if err := s.pool.QueryRow(ctx, `SELECT COALESCE(max(revision),0) FROM site_supply_config_revisions WHERE site_id=$1`,
		siteID).Scan(&latest); err != nil {
		return err
	}
	if revision < latest {
		return ErrStaleRevision
	}
	if commit {
		if _, err := s.pool.Exec(ctx, `INSERT INTO site_supply_config_revisions (site_id,revision,config,digest,created_at)
			VALUES ($1,$2,$3,$4,$5) ON CONFLICT (site_id,revision) DO NOTHING`, siteID, revision, raw, digest, s.now().UTC()); err != nil {
			return err
		}
	}
	var stored string
	err := s.pool.QueryRow(ctx, `SELECT digest FROM site_supply_config_revisions WHERE site_id=$1 AND revision=$2`,
		siteID, revision).Scan(&stored)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return nil // preview of a revision not stored yet
	case err != nil:
		return err
	case stored != digest:
		return ErrRevisionConflict
	}
	return nil
}

// rollback returns one committed leaf to its previous revision, or removes
// the site there if this was its first revision.
// The error is set when the leaf's outcome could not be saved as a receipt.
func (s *Service) rollback(ctx context.Context, siteID uuid.UUID, t target, failed int64) (string, error) {
	key := fmt.Sprintf("rollback-%s-%d-%s-%s", siteID, failed, t.leaf.LeafMemberID, t.leaf.NodePoolRef)
	var reply siteconf.Reply
	var err error
	if t.revision == 0 {
		reply, err = s.caller.Call(ctx, t.leaf, siteconf.OpDelete, nil, key, siteconf.SiteRef{SiteID: siteID, LeafSiteID: *t.leafSite})
	} else {
		var prev siteconf.Config
		var raw []byte
		if err = s.pool.QueryRow(ctx, `SELECT config FROM site_supply_config_revisions WHERE site_id=$1 AND revision=$2`,
			siteID, t.revision).Scan(&raw); err == nil {
			if err = json.Unmarshal(raw, &prev); err == nil {
				reply, err = s.caller.Call(ctx, t.leaf, siteconf.OpCommit, prev.Domains, key, siteconf.CommitRequest{
					SiteID: siteID, LeafSiteID: t.leafSite, Revision: t.revision, Digest: prev.Digest(), Config: prev})
			}
		}
	}
	if err != nil || !reply.OK {
		msg := "rollback refused"
		if err != nil {
			msg = err.Error()
		}
		return "inconsistent", s.record(ctx, siteID, t, failed, "", "inconsistent", msg)
	}
	state := "applied"
	if t.revision == 0 {
		state, t.leafSite = "pending", nil
	}
	return "rolled_back", s.record(ctx, siteID, t, t.revision, t.digest, state, "")
}

// record saves one leaf's receipt; callers must not report an outcome the
// receipt does not hold (CORE-RECEIPT-02). An applied receipt (re)starts the
// node delivery check (node_check.go); any other state stops it.
func (s *Service) record(ctx context.Context, siteID uuid.UUID, t target, revision int64, digest, state, msg string) error {
	if len(msg) > 500 {
		msg = msg[:500]
	}
	now := s.now().UTC()
	nodeState, nextCheck := nodeTracking(state, now, s.reconcilePolicy())
	_, err := s.pool.Exec(ctx, `INSERT INTO site_supply_leaf_sites (site_id,supply_id,leaf_member_id,node_pool_ref,leaf_site_id,
			applied_revision,applied_digest,state,last_error,updated_at,node_state,next_node_check_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		ON CONFLICT (site_id,supply_id,leaf_member_id,node_pool_ref) DO UPDATE SET leaf_site_id=EXCLUDED.leaf_site_id,
			applied_revision=EXCLUDED.applied_revision, applied_digest=EXCLUDED.applied_digest, state=EXCLUDED.state,
			last_error=EXCLUDED.last_error, updated_at=EXCLUDED.updated_at,
			pending_revision=0, pending_digest='', reconcile_attempts=0, next_reconcile_at=NULL,
			node_state=EXCLUDED.node_state, node_reason='', node_detail='', node_check_attempts=0, node_checked_at=NULL,
			next_node_check_at=EXCLUDED.next_node_check_at`,
		siteID, t.supplyID, t.leaf.LeafMemberID, t.leaf.NodePoolRef, t.leafSite, revision, digest, state, msg, now,
		nodeState, nextCheck)
	return err
}

// targetsQuery lists the site's active market bindings, each with whether it
// is paused because the site has no valid package (the one rule the
// scheduler and DNS use too).
var targetsQuery = `SELECT supply.id, supply.leaves, ` + cnameallocation.SupplyPausedWithoutPackageSQL("supply", "site") + `
	FROM site_supply_bindings binding
	JOIN sites site ON site.id=binding.site_id
	JOIN site_supplies supply ON supply.id=binding.supply_id
	WHERE binding.site_id=$1 AND supply.kind='market_subscription' AND supply.status='active'
	ORDER BY binding.priority, supply.id`

type bound struct {
	id     uuid.UUID
	leaves []Leaf
	paused bool
}

// pushable drops the supplies paused for lack of a valid package (fix-nopkgpub4):
// the controller's subscriptions take no new revision until the package is
// valid again, their leaves keep what they have; the site owner's own
// subscriptions are still pushed. Only paused ones left is
// ErrSitePackageUnavailable.
func pushable(supplies []bound) ([]bound, error) {
	if len(supplies) == 0 {
		return nil, ErrNoMarketBinding
	}
	out := supplies[:0:0]
	for _, b := range supplies {
		if !b.paused {
			out = append(out, b)
		}
	}
	if len(out) == 0 {
		return nil, ErrSitePackageUnavailable
	}
	return out, nil
}

// nodeTracking is the node delivery state a receipt of state starts with:
// applied is delivering, first checked one backoff later; others untracked.
func nodeTracking(state string, now time.Time, policy ReconcilePolicy) (string, *time.Time) {
	if state != "applied" {
		return "", nil
	}
	next := now.Add(policy.Backoff)
	return NodeDelivering, &next
}

// targets lists every leaf behind the site's active, pushable market
// bindings, with what each has applied so far.
func (s *Service) targets(ctx context.Context, siteID uuid.UUID) ([]target, error) {
	rows, err := s.pool.Query(ctx, targetsQuery, siteID)
	if err != nil {
		return nil, err
	}
	var supplies []bound
	for rows.Next() {
		var b bound
		var raw []byte
		if err := rows.Scan(&b.id, &raw, &b.paused); err != nil {
			rows.Close()
			return nil, err
		}
		if err := json.Unmarshal(raw, &b.leaves); err != nil {
			rows.Close()
			return nil, err
		}
		supplies = append(supplies, b)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	supplies, err = pushable(supplies)
	if err != nil {
		return nil, err
	}
	var out []target
	for _, b := range supplies {
		if len(b.leaves) == 0 {
			return nil, fmt.Errorf("%w: %s", ErrNoLeaves, b.id)
		}
		for _, l := range b.leaves {
			t := target{supplyID: b.id, leaf: l}
			// A committing leaf (receipt unconfirmed, reconcile.go) still counts
			// as running its last confirmed revision for rollback, and is never
			// "done": the same revision is sent to it again.
			err := s.pool.QueryRow(ctx, `SELECT leaf_site_id,
					CASE WHEN state IN ('applied','committing') THEN applied_revision ELSE 0 END,
					CASE WHEN state IN ('applied','committing') THEN applied_digest ELSE '' END, state='committing'
				FROM site_supply_leaf_sites WHERE site_id=$1 AND supply_id=$2 AND leaf_member_id=$3 AND node_pool_ref=$4`,
				siteID, b.id, l.LeafMemberID, l.NodePoolRef).Scan(&t.leafSite, &t.revision, &t.digest, &t.committing)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return nil, err
			}
			t.stored = err == nil
			out = append(out, t)
		}
	}
	return out, nil
}
