//go:build integration

package marketsubscribe

import (
	"testing"
	"time"
)

type fakeClock struct{ at time.Time }

func (c *fakeClock) now() time.Time { return c.at }

// fix-cfgflow2 §2 (PG): the leaf committed but its receipt could not be
// saved. The leaf row stays committing; after the grace period the worker
// sends the same revision and content again and saves the receipt as applied,
// with no second leaf site and an audit event.
func TestReconcileCompletesPendingReceipt(t *testing.T) {
	pool := testPool(t)
	svc, leaves, site, member := singleLeaf(t, pool)
	clock := &fakeClock{at: time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)}
	svc.WithReconcile(clock.now, DefaultReconcilePolicy(), nil)
	drop := injectReceiptCheck(t, pool, site, "state = 'applied'")
	if _, err := svc.Apply(t.Context(), site, 1, config("203.0.113.40")); err == nil {
		t.Fatal("apply with an unsavable receipt succeeded")
	}
	leafSite := leaves.sites[member]
	var state string
	var pending int64
	if err := pool.QueryRow(t.Context(), `SELECT state,pending_revision FROM site_supply_leaf_sites
		WHERE site_id=$1 AND leaf_member_id=$2`, site, member).Scan(&state, &pending); err != nil ||
		state != "committing" || pending != 1 {
		t.Fatalf("after failed receipt = %s %d %v", state, pending, err)
	}
	drop()
	// Within the grace period the worker leaves it to the Apply.
	if n, err := svc.ReconcileReceipts(t.Context()); err != nil || n != 0 {
		t.Fatalf("early reconcile = %d %v", n, err)
	}
	clock.at = clock.at.Add(DefaultReconcilePolicy().Grace + time.Second)
	if n, err := svc.ReconcileReceipts(t.Context()); err != nil || n != 1 {
		t.Fatalf("reconcile = %d %v", n, err)
	}
	var revision int64
	if err := pool.QueryRow(t.Context(), `SELECT state,applied_revision FROM site_supply_leaf_sites
		WHERE site_id=$1 AND leaf_member_id=$2`, site, member).Scan(&state, &revision); err != nil ||
		state != "applied" || revision != 1 || len(leaves.sites) != 1 || leaves.sites[member] != leafSite {
		t.Fatalf("after reconcile = %s %d %v, leaf sites %v", state, revision, err, leaves.sites)
	}
	var audits int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE action=$1 AND resource_id=$2`,
		AuditReceiptConfirmed, site.String()).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("audit events = %d %v", audits, err)
	}
	// Idempotent: nothing is due any more.
	if n, err := svc.ReconcileReceipts(t.Context()); err != nil || n != 0 {
		t.Fatalf("second reconcile = %d %v", n, err)
	}
}

// fix-cfgflow2 §2 (PG): a leaf that keeps refusing is retried with backoff
// and, after MaxAttempts, marked inconsistent with the reason.
func TestReconcileGivesUpWithReason(t *testing.T) {
	pool := testPool(t)
	svc, leaves, site, member := singleLeaf(t, pool)
	clock := &fakeClock{at: time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)}
	policy := DefaultReconcilePolicy()
	policy.MaxAttempts = 2
	svc.WithReconcile(clock.now, policy, nil)
	drop := injectReceiptCheck(t, pool, site, "state = 'applied'")
	if _, err := svc.Apply(t.Context(), site, 1, config("203.0.113.41")); err == nil {
		t.Fatal("apply with an unsavable receipt succeeded")
	}
	drop()
	leaves.mu.Lock()
	leaves.failCom[member] = true
	leaves.mu.Unlock()
	clock.at = clock.at.Add(policy.Grace + time.Second)
	if n, err := svc.ReconcileReceipts(t.Context()); err != nil || n != 0 {
		t.Fatalf("first failing reconcile = %d %v", n, err)
	}
	// Not due again before its backoff.
	if n, err := svc.ReconcileReceipts(t.Context()); err != nil || n != 0 {
		t.Fatalf("reconcile before backoff = %d %v", n, err)
	}
	clock.at = clock.at.Add(policy.Backoff + time.Second)
	if n, err := svc.ReconcileReceipts(t.Context()); err != nil || n != 1 {
		t.Fatalf("giving up = %d %v", n, err)
	}
	var state, lastError string
	if err := pool.QueryRow(t.Context(), `SELECT state,last_error FROM site_supply_leaf_sites
		WHERE site_id=$1 AND leaf_member_id=$2`, site, member).Scan(&state, &lastError); err != nil ||
		state != "inconsistent" || lastError != "receipt unconfirmed: leaf offline" {
		t.Fatalf("after giving up = %s %q %v", state, lastError, err)
	}
}
