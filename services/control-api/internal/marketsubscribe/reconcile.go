package marketsubscribe

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Receipt reconciliation (fix-cfgflow2 §2, migration 565). Apply marks a
// leaf's receipt committing with the revision and digest it is about to send
// (pending_*); a saved receipt turns it applied. A leaf that answered while
// its receipt could not be saved stays committing; the worker sends that
// leaf the same revision and content again after a grace period (the leaf's
// commit is idempotent per site and revision: market-<site>-<revision>, so no
// second site is created) and saves the receipt. Repeated failures back off
// and, at the limit, mark the leaf inconsistent with the reason and notify
// the platform members holding marketplace.purchase.

const (
	// ReceiptUnconfirmedEvent is the notification event of a receipt the
	// reconciler gave up on (migration 565).
	ReceiptUnconfirmedEvent = "market.supply.receipt_unconfirmed"
	// Audit actions of the reconciler (internal/audit catalog_plugin.go).
	AuditReceiptConfirmed   = "plugin.market_supply.receipt_confirmed"
	AuditReceiptUnconfirmed = "plugin.market_supply.receipt_unconfirmed"

	receiptTemplateVersion = 1
	reconcileActor         = "job:market-receipt-reconcile"
)

// ReconcilePolicy bounds the reconciler. Grace is how long a committing
// receipt is left to the Apply that wrote it before the worker takes it
// over; each failure waits Backoff·2^n (at most MaxBackoff); after
// MaxAttempts failures the leaf is marked inconsistent.
type ReconcilePolicy struct {
	Grace       time.Duration
	Backoff     time.Duration
	MaxBackoff  time.Duration
	MaxAttempts int
	BatchSize   int
}

func DefaultReconcilePolicy() ReconcilePolicy {
	return ReconcilePolicy{Grace: 2 * time.Minute, Backoff: time.Minute, MaxBackoff: time.Hour, MaxAttempts: 8, BatchSize: 50}
}

func (p ReconcilePolicy) validate() error {
	if p.Grace <= 0 || p.Backoff <= 0 || p.MaxBackoff < p.Backoff || p.MaxAttempts < 1 || p.MaxAttempts > 100 ||
		p.BatchSize < 1 || p.BatchSize > 1000 {
		return fmt.Errorf("%w: reconcile policy", ErrInvalid)
	}
	return nil
}

// pendingReceipt is one committing leaf receipt.
type pendingReceipt struct {
	siteID   uuid.UUID
	domain   string
	supplyID uuid.UUID
	supply   string
	leaf     Leaf
	leafSite *uuid.UUID
	revision int64
	digest   string
	attempts int
}

// reconcileOutcome is what to write back for one pendingReceipt.
type reconcileOutcome struct {
	state    string // applied, committing, inconsistent
	leafSite *uuid.UUID
	attempts int
	next     time.Time
	reason   string
	notify   bool
}

// reconcileDecision turns one re-sent commit's reply into the receipt to save.
func reconcileDecision(p pendingReceipt, reply siteconf.Reply, err error, now time.Time, policy ReconcilePolicy) reconcileOutcome {
	switch {
	case err == nil && reply.OK && reply.Digest != "" && reply.Digest != p.digest:
		// The leaf runs this revision with other content: retrying cannot fix it.
		return reconcileOutcome{state: "inconsistent", leafSite: p.leafSite, attempts: p.attempts + 1,
			reason: "leaf normalized the config differently", notify: true}
	case err == nil && reply.OK && reply.LeafSiteID != nil:
		return reconcileOutcome{state: "applied", leafSite: reply.LeafSiteID}
	}
	reason := "commit refused"
	switch {
	case err != nil:
		reason = err.Error()
	case reply.Error != "":
		reason = reply.Error
	case reply.OK:
		reason = "leaf returned no site"
	}
	if len(reason) > 500 {
		reason = reason[:500]
	}
	attempts := p.attempts + 1
	if attempts >= policy.MaxAttempts {
		return reconcileOutcome{state: "inconsistent", leafSite: p.leafSite, attempts: attempts, reason: reason, notify: true}
	}
	return reconcileOutcome{state: "committing", leafSite: p.leafSite, attempts: attempts, next: now.Add(policy.backoff(attempts)), reason: reason}
}

// WithReconcile sets the reconciler's clock, policy and notification store
// (nil: no notification). Without it the defaults and time.Now apply.
func (s *Service) WithReconcile(now func() time.Time, policy ReconcilePolicy, notices ReceiptNotifier) *Service {
	if now != nil {
		s.now = now
	}
	s.reconcile, s.notices = policy, notices
	return s
}

// ReceiptNotifier is notification.Store's transactional enqueue.
type ReceiptNotifier interface {
	EnqueueTx(context.Context, pgx.Tx, notification.EnqueueRequest) (notification.EnqueueResult, error)
}

// RunReconcile reconciles committing receipts and checks the node delivery
// of applied leaves (node_check.go) every interval until ctx ends.
func (s *Service) RunReconcile(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		return fmt.Errorf("%w: reconcile interval", ErrInvalid)
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if _, err := s.ReconcileReceipts(ctx); err != nil && ctx.Err() == nil {
			slog.Default().Warn("market receipt reconcile failed", "error", err)
		}
		if _, err := s.CheckNodeDelivery(ctx); err != nil && ctx.Err() == nil {
			slog.Default().Warn("market node delivery check failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// ReconcileReceipts runs one pass: every committing receipt due now (past
// its grace period or its backoff) is sent once. It returns how many it
// settled (applied or inconsistent).
func (s *Service) ReconcileReceipts(ctx context.Context) (int, error) {
	policy := s.reconcilePolicy()
	if err := policy.validate(); err != nil {
		return 0, err
	}
	now := s.now().UTC()
	due, err := s.dueReceipts(ctx, now, policy.BatchSize)
	if err != nil {
		return 0, err
	}
	settled := 0
	for _, p := range due {
		cfg, err := s.revisionConfig(ctx, p.siteID, p.revision)
		if err != nil {
			return settled, err
		}
		// A fresh relay message per attempt (the relay derives the message ID
		// from the key); the leaf's commit itself is idempotent per site and
		// revision (marketsupply sites.go market-<site>-<revision>).
		key := fmt.Sprintf("reconcile-%s-%d-%s-%s-%d", p.siteID, p.revision, p.leaf.LeafMemberID, p.leaf.NodePoolRef, p.attempts+1)
		reply, callErr := s.caller.Call(ctx, p.leaf, siteconf.OpCommit, cfg.Domains, key, siteconf.CommitRequest{
			SiteID: p.siteID, LeafSiteID: p.leafSite, Revision: p.revision, Digest: p.digest, Config: cfg})
		if ctx.Err() != nil {
			return settled, ctx.Err()
		}
		outcome := reconcileDecision(p, reply, callErr, now, policy)
		done, err := s.saveReconciled(ctx, p, outcome, now)
		if err != nil {
			return settled, err
		}
		if done {
			settled++
		}
	}
	return settled, nil
}

func (s *Service) reconcilePolicy() ReconcilePolicy {
	if s.reconcile == (ReconcilePolicy{}) {
		return DefaultReconcilePolicy()
	}
	return s.reconcile
}

// dueReceipts lists committing receipts due at now, oldest first.
func (s *Service) dueReceipts(ctx context.Context, now time.Time, limit int) ([]pendingReceipt, error) {
	rows, err := s.pool.Query(ctx, `SELECT leaf.site_id, site.domain, leaf.supply_id, supply.name,
			leaf.leaf_member_id, leaf.node_pool_ref, leaf.leaf_site_id, leaf.pending_revision, leaf.pending_digest,
			leaf.reconcile_attempts, supply.leaves
		FROM site_supply_leaf_sites leaf
		JOIN site_supplies supply ON supply.id=leaf.supply_id
		JOIN sites site ON site.id=leaf.site_id AND site.deleted_at IS NULL
		WHERE leaf.state='committing' AND leaf.next_reconcile_at <= $1
		ORDER BY leaf.next_reconcile_at, leaf.site_id LIMIT $2`, now, limit)
	if err != nil {
		return nil, fmt.Errorf("list committing receipts: %w", err)
	}
	defer rows.Close()
	var out []pendingReceipt
	for rows.Next() {
		var p pendingReceipt
		var raw []byte
		if err := rows.Scan(&p.siteID, &p.domain, &p.supplyID, &p.supply, &p.leaf.LeafMemberID, &p.leaf.NodePoolRef,
			&p.leafSite, &p.revision, &p.digest, &p.attempts, &raw); err != nil {
			return nil, fmt.Errorf("scan committing receipt: %w", err)
		}
		// The grant comes from the supply's current leaves: a leaf no longer
		// listed is still reconciled with the grant it was sent under (zero).
		var leaves []Leaf
		if err := json.Unmarshal(raw, &leaves); err != nil {
			return nil, fmt.Errorf("decode supply leaves: %w", err)
		}
		for _, l := range leaves {
			if l.LeafMemberID == p.leaf.LeafMemberID && l.NodePoolRef == p.leaf.NodePoolRef {
				p.leaf.GrantID = l.GrantID
			}
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Service) revisionConfig(ctx context.Context, siteID uuid.UUID, revision int64) (siteconf.Config, error) {
	var raw []byte
	if err := s.pool.QueryRow(ctx, `SELECT config FROM site_supply_config_revisions WHERE site_id=$1 AND revision=$2`,
		siteID, revision).Scan(&raw); err != nil {
		return siteconf.Config{}, fmt.Errorf("read reconciled revision: %w", err)
	}
	var cfg siteconf.Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return siteconf.Config{}, fmt.Errorf("decode reconciled revision: %w", err)
	}
	return cfg, nil
}

// saveReconciled writes outcome back, only while the receipt is still the
// committing one this pass read (an Apply in between owns it), with an
// audit event and, on giving up, a notification. It reports whether the
// receipt was settled.
func (s *Service) saveReconciled(ctx context.Context, p pendingReceipt, outcome reconcileOutcome, now time.Time) (bool, error) {
	settled := false
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var tag interface{ RowsAffected() int64 }
		var err error
		match := `site_id=$1 AND supply_id=$2 AND leaf_member_id=$3 AND node_pool_ref=$4 AND state='committing'
			AND pending_revision=$5 AND pending_digest=$6`
		switch outcome.state {
		case "applied":
			// Applied: the node delivery check starts (node_check.go).
			_, nextCheck := nodeTracking("applied", now, s.reconcilePolicy())
			tag, err = tx.Exec(ctx, `UPDATE site_supply_leaf_sites SET state='applied', leaf_site_id=$7,
				applied_revision=$5, applied_digest=$6, last_error='', pending_revision=0, pending_digest='',
				reconcile_attempts=0, next_reconcile_at=NULL, updated_at=$8,
				node_state='delivering', node_reason='', node_detail='', node_check_attempts=0, node_checked_at=NULL,
				next_node_check_at=$9 WHERE `+match,
				p.siteID, p.supplyID, p.leaf.LeafMemberID, p.leaf.NodePoolRef, p.revision, p.digest, outcome.leafSite, now, nextCheck)
		case "inconsistent":
			tag, err = tx.Exec(ctx, `UPDATE site_supply_leaf_sites SET state='inconsistent', leaf_site_id=$7,
				last_error=$8, pending_revision=0, pending_digest='', reconcile_attempts=$9, next_reconcile_at=NULL,
				updated_at=$10 WHERE `+match,
				p.siteID, p.supplyID, p.leaf.LeafMemberID, p.leaf.NodePoolRef, p.revision, p.digest, outcome.leafSite,
				"receipt unconfirmed: "+outcome.reason, outcome.attempts, now)
		default:
			tag, err = tx.Exec(ctx, `UPDATE site_supply_leaf_sites SET last_error=$7, reconcile_attempts=$8,
				next_reconcile_at=$9, updated_at=$10 WHERE `+match,
				p.siteID, p.supplyID, p.leaf.LeafMemberID, p.leaf.NodePoolRef, p.revision, p.digest,
				"receipt pending: "+outcome.reason, outcome.attempts, outcome.next, now)
		}
		if err != nil {
			return fmt.Errorf("save reconciled receipt: %w", err)
		}
		if tag.RowsAffected() != 1 || outcome.state == "committing" {
			return nil
		}
		settled = true
		return s.auditReconciled(ctx, tx, p, outcome, now)
	})
	return settled, err
}

func (s *Service) auditReconciled(ctx context.Context, tx pgx.Tx, p pendingReceipt, outcome reconcileOutcome, now time.Time) error {
	scope, err := platformScope(ctx, tx)
	if err != nil {
		return err
	}
	action, result, reason := AuditReceiptConfirmed, "success", ""
	if outcome.state == "inconsistent" {
		action, result, reason = AuditReceiptUnconfirmed, "failure", "receipt_unconfirmed"
	}
	source := fmt.Sprintf("market-receipt/%s/%s/%s/%s/%d", p.siteID, p.supplyID, p.leaf.LeafMemberID, p.leaf.NodePoolRef, p.revision)
	if err := audit.NewWithClock(s.pool, s.now).Append(ctx, tx, audit.Event{ScopeID: scope, Action: action,
		ResourceType: "site", ResourceID: p.siteID.String(), RequestID: source, Result: result, ReasonCode: reason,
		ActorKind: audit.ActorSystem, ActorRef: reconcileActor, OccurredAt: now,
		Payload: map[string]any{"site_domain": p.domain, "supply_id": p.supplyID.String(), "supply": p.supply,
			"leaf_member_id": p.leaf.LeafMemberID.String(), "node_pool_ref": p.leaf.NodePoolRef,
			"revision": p.revision, "attempts": outcome.attempts, "reason": outcome.reason},
		Changes: []audit.Change{{Field: "receipt_state", Before: "committing", After: outcome.state}},
	}); err != nil {
		return fmt.Errorf("audit reconciled receipt: %w", err)
	}
	if !outcome.notify || s.notices == nil {
		return nil
	}
	return s.notifyPurchasers(ctx, tx, scope, source, ReceiptUnconfirmedEvent, receiptTemplateVersion, p.siteID,
		notification.TemplateContext{"domain": notification.PublicValue(p.domain),
			"supply": notification.PublicValue(p.supply), "revision": notification.PublicValue(strconv.FormatInt(p.revision, 10)),
			"reason": notification.PublicValue(outcome.reason)})
}

func platformScope(ctx context.Context, tx pgx.Tx) (uuid.UUID, error) {
	var scope uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL`).Scan(&scope); err != nil {
		return uuid.Nil, fmt.Errorf("read platform scope: %w", err)
	}
	return scope, nil
}

// notifyPurchasers enqueues event (sms and email, zh-cn templates of version)
// for every active platform member holding marketplace.purchase.
func (s *Service) notifyPurchasers(ctx context.Context, tx pgx.Tx, scope uuid.UUID, source, event string, version uint64,
	siteID uuid.UUID, values notification.TemplateContext) error {
	rows, err := tx.Query(ctx, `SELECT DISTINCT membership.user_id FROM memberships membership
		JOIN users member ON member.id=membership.user_id AND member.status='active'
		JOIN role_assignments assignment ON assignment.scope_id=membership.scope_id AND assignment.user_id=membership.user_id
		JOIN role_permissions grant_row ON grant_row.role_id=assignment.role_id AND grant_row.permission_name='marketplace.purchase'
		WHERE membership.scope_id=$1 AND membership.status='active' ORDER BY membership.user_id`, scope)
	if err != nil {
		return err
	}
	recipients, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return err
	}
	template := event + ".zh-cn"
	templates := map[notification.Channel]notification.TemplateRef{
		notification.ChannelSMS:   {ID: template, Version: version, Channel: notification.ChannelSMS},
		notification.ChannelEmail: {ID: template, Version: version, Channel: notification.ChannelEmail},
	}
	site := siteID
	for _, recipient := range recipients {
		if _, err := s.notices.EnqueueTx(ctx, tx, notification.EnqueueRequest{ScopeID: scope, RecipientID: recipient,
			SourceEventID: source, EventType: event, Policy: notification.DeliveryTenantSubscribed,
			Templates: templates, AuditRequestID: source, SubjectSiteID: &site,
			Contexts: map[notification.Channel]notification.TemplateContext{notification.ChannelSMS: values, notification.ChannelEmail: values},
		}); err != nil {
			return fmt.Errorf("enqueue %s: %w", event, err)
		}
	}
	return nil
}
