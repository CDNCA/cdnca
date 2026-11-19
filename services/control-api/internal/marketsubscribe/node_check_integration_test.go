//go:build integration

package marketsubscribe

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func leafNodeRow(t *testing.T, svc *Service, site, member any) (state, reason, detail string, attempts int) {
	t.Helper()
	if err := svc.pool.QueryRow(t.Context(), `SELECT node_state,node_reason,node_detail,node_check_attempts
		FROM site_supply_leaf_sites WHERE site_id=$1 AND leaf_member_id=$2`, site, member).
		Scan(&state, &reason, &detail, &attempts); err != nil {
		t.Fatal(err)
	}
	return
}

// fix-mktsiteconf7 §1 (PG): an applied leaf starts delivering; the worker
// asks it after one backoff, keeps waiting while it is on its way and saves
// "effective" once it says so, with an audit event; a new apply starts over.
func TestNodeDeliveryCheckFollowsTheLeafToEffective(t *testing.T) {
	pool := testPool(t)
	svc, leaves, site, member := singleLeaf(t, pool)
	clock := &fakeClock{at: time.Date(2026, 10, 28, 15, 0, 0, 0, time.UTC)}
	policy := DefaultReconcilePolicy()
	svc.WithReconcile(clock.now, policy, nil)
	leaves.nodes = map[uuid.UUID]map[string]string{}
	if _, err := svc.Apply(t.Context(), site, 1, config("203.0.113.50")); err != nil {
		t.Fatal(err)
	}
	if state, _, _, _ := leafNodeRow(t, svc, site, member); state != NodeDelivering {
		t.Fatalf("after apply node_state = %q", state)
	}
	// Not due before one backoff.
	if n, err := svc.CheckNodeDelivery(t.Context()); err != nil || n != 0 {
		t.Fatalf("early check = %d %v", n, err)
	}
	leaves.mu.Lock()
	leaves.nodes[member] = map[string]string{"state": "delivering", "reason": "site_syncing"}
	leaves.mu.Unlock()
	clock.at = clock.at.Add(policy.Backoff + time.Second)
	if n, err := svc.CheckNodeDelivery(t.Context()); err != nil || n != 0 {
		t.Fatalf("delivering check = %d %v", n, err)
	}
	if state, reason, _, attempts := leafNodeRow(t, svc, site, member); state != NodeDelivering || reason != "site_syncing" || attempts != 1 {
		t.Fatalf("while delivering = %s %s %d", state, reason, attempts)
	}
	leaves.mu.Lock()
	leaves.nodes[member] = map[string]string{"state": "effective"}
	leaves.mu.Unlock()
	clock.at = clock.at.Add(2*policy.Backoff + time.Second)
	if n, err := svc.CheckNodeDelivery(t.Context()); err != nil || n != 1 {
		t.Fatalf("effective check = %d %v", n, err)
	}
	if state, _, _, _ := leafNodeRow(t, svc, site, member); state != NodeEffective {
		t.Fatalf("node_state = %q", state)
	}
	var audits int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE action=$1 AND resource_id=$2`,
		AuditNodeDeliveryConfirmed, site.String()).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("audit events = %d %v", audits, err)
	}
	items, err := svc.SiteLeaves(t.Context(), site)
	if err != nil || len(items) != 1 || items[0].State != "applied" || items[0].Node.State != NodeEffective || items[0].Revision != 1 {
		t.Fatalf("SiteLeaves = %+v %v", items, err)
	}
	// A new revision starts the check over.
	if _, err := svc.Apply(t.Context(), site, 2, config("203.0.113.51")); err != nil {
		t.Fatal(err)
	}
	if state, reason, _, attempts := leafNodeRow(t, svc, site, member); state != NodeDelivering || reason != "" || attempts != 0 {
		t.Fatalf("after a new apply = %s %s %d", state, reason, attempts)
	}
}

// fix-mktsiteconf7 §1 (PG): a leaf that reports a failure is saved failed
// with its reason and audited; one never settling fails as a timeout.
func TestNodeDeliveryCheckSavesFailures(t *testing.T) {
	pool := testPool(t)
	svc, leaves, site, member := singleLeaf(t, pool)
	clock := &fakeClock{at: time.Date(2026, 10, 28, 15, 0, 0, 0, time.UTC)}
	policy := DefaultReconcilePolicy()
	policy.MaxAttempts = 2
	svc.WithReconcile(clock.now, policy, nil)
	leaves.nodes = map[uuid.UUID]map[string]string{member: {"state": "failed", "reason": "security_failed", "detail": "waf:x"}}
	if _, err := svc.Apply(t.Context(), site, 1, config("203.0.113.52")); err != nil {
		t.Fatal(err)
	}
	clock.at = clock.at.Add(policy.Backoff + time.Second)
	if n, err := svc.CheckNodeDelivery(t.Context()); err != nil || n != 1 {
		t.Fatalf("failed check = %d %v", n, err)
	}
	if state, reason, detail, _ := leafNodeRow(t, svc, site, member); state != NodeFailed || reason != "security_failed" || detail != "waf:x" {
		t.Fatalf("after failure = %s %s %s", state, reason, detail)
	}
	var audits int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE action=$1 AND resource_id=$2 AND result='failure'`,
		AuditNodeDeliveryFailed, site.String()).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("failure audits = %d %v", audits, err)
	}

	leaves.mu.Lock()
	leaves.nodes[member] = map[string]string{"state": "delivering", "reason": "security_activating", "detail": "cc"}
	leaves.mu.Unlock()
	if _, err := svc.Apply(t.Context(), site, 2, config("203.0.113.53")); err != nil {
		t.Fatal(err)
	}
	for range policy.MaxAttempts {
		clock.at = clock.at.Add(policy.MaxBackoff + time.Second)
		if _, err := svc.CheckNodeDelivery(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if state, reason, detail, _ := leafNodeRow(t, svc, site, member); state != NodeFailed || reason != NodeReasonTimeout ||
		detail != "security_activating:cc" {
		t.Fatalf("after the limit = %s %s %s", state, reason, detail)
	}
}

// seedPlatformBuyer adds an active platform member holding
// marketplace.purchase (the recipients of notifyPurchasers), as the probe
// alert fixture does.
func seedPlatformBuyer(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := t.Context()
	var platform uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL`).Scan(&platform); err != nil {
		t.Fatal(err)
	}
	var role uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM roles WHERE scope_id=$1 AND name='platform_owner'`, platform).Scan(&role); err != nil {
		role = uuid.New()
		if _, err := pool.Exec(ctx, `INSERT INTO roles(id,scope_id,name,system_role) VALUES($1,$2,'platform_owner',true)`, role, platform); err != nil {
			t.Fatal(err)
		}
	}
	buyer := uuid.New()
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		for _, st := range []struct {
			q    string
			args []any
		}{
			{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'node buyer','hash')`,
				[]any{buyer, "nb" + strings.ReplaceAll(buyer.String(), "-", "")[:20]}},
			{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{platform, buyer}},
			{`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'marketplace.purchase') ON CONFLICT DO NOTHING`, []any{role}},
			{`UPDATE notification_channel_settings SET email_enabled=true, sms_enabled=true WHERE singleton`, nil},
			{`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, []any{platform, buyer, role}},
		} {
			if _, err := tx.Exec(ctx, st.q, st.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// A leaf whose node pool ref
// is long fails its node delivery; the failure notice used to carry the
// 160-odd byte source as its audit request ID, the store refused it (128
// max), the whole save rolled back and the leaf was asked again every pass.
// It now settles failed, audited and notified once, and stays settled.
func TestNodeDeliveryFailureWithALongNodePoolNotifies(t *testing.T) {
	pool := testPool(t)
	svc, leaves, site, member := singleLeafPool(t, pool, strings.Repeat("n", 128))
	seedPlatformBuyer(t, pool)
	notices, err := notification.NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	clock := &fakeClock{at: time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)}
	policy := DefaultReconcilePolicy()
	svc.WithReconcile(clock.now, policy, notices)
	leaves.nodes = map[uuid.UUID]map[string]string{member: {"state": "failed", "reason": "security_failed"}}
	if _, err := svc.Apply(t.Context(), site, 1, config("203.0.113.60")); err != nil {
		t.Fatal(err)
	}
	clock.at = clock.at.Add(policy.Backoff + time.Second)
	if n, err := svc.CheckNodeDelivery(t.Context()); err != nil || n < 1 {
		t.Fatalf("failed check = %d %v", n, err)
	}
	if state, reason, _, _ := leafNodeRow(t, svc, site, member); state != NodeFailed || reason != "security_failed" {
		t.Fatalf("after failure = %s %s", state, reason)
	}
	var events int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM notification_events WHERE event_type=$1 AND source_event_id LIKE $2`,
		NodeDeliveryFailedEvent, "market-nodes/"+site.String()+"/%").Scan(&events); err != nil || events < 1 {
		t.Fatalf("failure notifications = %d %v", events, err)
	}
}

// failingNotices refuses every notice of one site (the source names it).
type failingNotices struct{ site uuid.UUID }

func (f failingNotices) EnqueueTx(_ context.Context, _ pgx.Tx, request notification.EnqueueRequest) (notification.EnqueueResult, error) {
	if strings.Contains(request.SourceEventID, f.site.String()) {
		return notification.EnqueueResult{}, notification.ErrInvalidEnqueue
	}
	return notification.EnqueueResult{}, nil
}

// A leaf whose settled check cannot be saved does not hold
// the pass up nor get asked again every pass: the pass reports it, puts it
// off by MaxBackoff and the leaf is asked again only then.
func TestNodeDeliveryCheckPutsOffALeafItCannotSave(t *testing.T) {
	pool := testPool(t)
	svc, leaves, site, member := singleLeaf(t, pool)
	seedPlatformBuyer(t, pool)
	clock := &fakeClock{at: time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)}
	policy := DefaultReconcilePolicy()
	svc.WithReconcile(clock.now, policy, failingNotices{site: site})
	leaves.nodes = map[uuid.UUID]map[string]string{member: {"state": "failed", "reason": "security_failed"}}
	if _, err := svc.Apply(t.Context(), site, 1, config("203.0.113.61")); err != nil {
		t.Fatal(err)
	}
	statusCalls := func() int {
		leaves.mu.Lock()
		defer leaves.mu.Unlock()
		n := 0
		for _, call := range leaves.calls {
			if call == "supply.site_status:"+member.String()[:4] {
				n++
			}
		}
		return n
	}
	clock.at = clock.at.Add(policy.Backoff + time.Second)
	if _, err := svc.CheckNodeDelivery(t.Context()); !errors.Is(err, notification.ErrInvalidEnqueue) {
		t.Fatalf("unsavable check = %v", err)
	}
	if state, _, _, _ := leafNodeRow(t, svc, site, member); state != NodeDelivering {
		t.Fatalf("an unsaved check keeps delivering, got %s", state)
	}
	var next time.Time
	if err := pool.QueryRow(t.Context(), `SELECT next_node_check_at FROM site_supply_leaf_sites WHERE site_id=$1 AND leaf_member_id=$2`,
		site, member).Scan(&next); err != nil || !next.Equal(clock.at.Add(policy.MaxBackoff)) {
		t.Fatalf("next_node_check_at = %s %v, want %s", next, err, clock.at.Add(policy.MaxBackoff))
	}
	asked := statusCalls()
	clock.at = clock.at.Add(2 * time.Minute)
	if _, err := svc.CheckNodeDelivery(t.Context()); err != nil {
		t.Fatalf("pass before the put-off = %v", err)
	}
	if statusCalls() != asked {
		t.Fatal("the leaf was asked again before its put-off")
	}
}
