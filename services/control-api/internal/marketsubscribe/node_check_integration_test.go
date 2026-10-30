//go:build integration

package marketsubscribe

import (
	"testing"
	"time"

	"github.com/google/uuid"
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
