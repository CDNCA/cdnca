//go:build integration

package acmehttp01

import (
	"testing"
)

// A node leaving a site that has no open epoch owes it nothing (ADR-0003):
// only active members of an open epoch carry the site's tokens, and closing
// the epoch already gave every remaining member a site_emptied debt. Neither
// the leave nor reconciliation opens a debt, and the node is not gated.
func TestNodeHTTP01LeaveWithoutOpenEpochOwesNoDebt(t *testing.T) {
	f := newNodeFixture(t, true, true)
	n1 := f.nodes[1]
	challenge := f.challenge(t, "a.example.test")
	if err := f.store.PublishChallenge(t.Context(), challenge); err != nil {
		t.Fatal(err)
	}
	f.healthyAll(t)
	if err := f.store.WithdrawChallenge(t.Context(), challenge); err != nil {
		t.Fatal(err)
	}
	f.healthyAll(t)
	if got := f.debtEvents(t, "a.example.test", n1); !equalStrings(got, "opened:site_emptied", "scheduled", "resolved_cleanup") {
		t.Fatalf("debt events after the epoch closed %v", got)
	}
	f.setAdmin(t, n1, "retired")
	f.reconcile(t)
	for domain, want := range map[string][]string{
		"a.example.test": {"opened:site_emptied", "scheduled", "resolved_cleanup"},
		"b.example.test": nil, // never had an epoch
	} {
		if got := f.debtEvents(t, domain, n1); !equalStrings(got, want...) {
			t.Fatalf("%s debt events after the node left %v", domain, got)
		}
		if got := f.gate(t, domain, n1); got != "" {
			t.Fatalf("%s gates the node that left: %q", domain, got)
		}
	}
	var tokens int
	if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM acme_http01_node_overlay_states state
		JOIN acme_http01_node_overlay_generations generation ON generation.id=state.current_generation_id
		JOIN acme_http01_node_overlay_generation_tokens token ON token.generation_id=generation.id
		WHERE state.node_id=$1`, n1).Scan(&tokens); err != nil {
		t.Fatal(err)
	}
	if tokens != 0 {
		t.Fatalf("node that left still carries %d tokens", tokens)
	}
}
