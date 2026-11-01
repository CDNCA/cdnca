//go:build integration

package certificateasset

import (
	"context"
	"testing"
	"time"
)

// demo-fill 11-01: a certificate publication racing the site's own
// publication got "node already has an active deployment" on attempts 1–3,
// each counted toward MaxAttempts. Busy-node attempts are not failures: with
// MaxAttempts 2, three busy attempts and one ordinary failure still leave the
// intent claimable, and only the second ordinary failure exhausts it.
func TestPublicationIntentBusyNodeAttemptsDoNotCountTowardMaxAttempts(t *testing.T) {
	pool := isolatedCertificateAssetPool(t)
	tenant := createCertificateTenant(t, pool, "publication-intent-busy")
	store := newPublicationStore(t, pool, &testEnvelopeCipher{}, certificateTestClock)
	pki := newCertificateFixture(t, leafOptions{domains: []string{"www.example.com"}})
	createBoundPublicationAsset(t, store, tenant, pki, tenant.siteOne)
	config := DefaultPublicationIntentStoreConfig()
	config.MaxAttempts, config.RetryBase, config.RetryMaximum = 2, 10*time.Millisecond, 10*time.Millisecond
	config.Jitter = func(time.Duration) time.Duration { return 0 }
	intents, err := NewPublicationIntentStore(pool, config)
	if err != nil {
		t.Fatal(err)
	}
	claim := func() PublicationIntentLease {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for {
			lease, found, err := intents.ClaimPublicationIntent(context.Background(), "busy-worker")
			if err != nil {
				t.Fatal(err)
			}
			if found {
				return lease
			}
			if time.Now().After(deadline) {
				t.Fatal("no publication intent to claim")
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	latestState := func() string {
		t.Helper()
		var state string
		if err := pool.QueryRow(context.Background(), `SELECT state FROM certificate_publication_intent_state_facts
			WHERE tenant_scope_id=$1 AND site_id=$2 ORDER BY binding_revision DESC,sequence DESC LIMIT 1`,
			tenant.actor.ScopeID, tenant.siteOne).Scan(&state); err != nil {
			t.Fatal(err)
		}
		return state
	}
	for attempt := 1; attempt <= 3; attempt++ {
		lease := claim()
		if lease.Attempt != attempt {
			t.Fatalf("busy attempt %d claimed as %d", attempt, lease.Attempt)
		}
		if err := intents.FailPublicationIntent(context.Background(), lease, PublicationFailureNodeBusy); err != nil {
			t.Fatal(err)
		}
		if state := latestState(); state != "retry_wait" {
			t.Fatalf("after busy attempt %d state = %s, want retry_wait", attempt, state)
		}
	}
	ordinary := claim()
	if err := intents.FailPublicationIntent(context.Background(), ordinary, "publication_unavailable"); err != nil {
		t.Fatal(err)
	}
	if state := latestState(); state != "retry_wait" {
		t.Fatalf("first counted failure after 3 busy attempts: state = %s, want retry_wait", state)
	}
	last := claim()
	if last.Attempt != 5 {
		t.Fatalf("attempt = %d, want 5", last.Attempt)
	}
	if err := intents.FailPublicationIntent(context.Background(), last, "publication_unavailable"); err != nil {
		t.Fatal(err)
	}
	if state := latestState(); state != "permanent_failed" {
		t.Fatalf("second counted failure: state = %s, want permanent_failed", state)
	}
}
