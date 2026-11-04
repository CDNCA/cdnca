//go:build integration

package acmehttp01

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/google/uuid"
)

// seedEnrollment records an initial node certificate issued at issuedAt (the
// enrollment of a host under the node ID); FKs are off while seeding.
func (f *nodeFixture) seedEnrollment(t *testing.T, node uuid.UUID, issuedAt time.Time) {
	t.Helper()
	certificateID := uuid.New()
	digest := sha256.Sum256(certificateID[:])
	seedTx(t, f.pool, func(exec func(string, ...any)) {
		exec(`INSERT INTO node_certificates(id,node_id,issuance_kind,enrollment_authorization_id,
			serial_number,csr_sha256,certificate_public_key_sha256,uri_san,not_before,not_after,renewal_at,
			leaf_certificate_pem,issuing_chain_pem,leaf_certificate_sha256,status,issued_at)
			VALUES($1,$2,'initial',$3,$4,$5,$5,$6,$7,$7::timestamptz+interval '2 days',$7::timestamptz+interval '1 day',
			  'test',ARRAY['test'::bytea],$5,'active',$7)`, certificateID, node, uuid.New(),
			hex.EncodeToString(digest[:8]), digest[:], "spiffe://cdn-platform/node/"+node.String(), issuedAt)
	})
}

// A node reinstalled (same node ID, new host) while a challenge is live: its
// latest healthy generation was healthy on the previous host, so the status no
// longer counts it as serving the token, and the reconciler sends the new host
// a generation above it carrying the same token.
func TestNodeHTTP01ReinstallWithLiveTokenRedelivers(t *testing.T) {
	f := newNodeFixture(t, true)
	node := f.nodes[0]
	f.seedEnrollment(t, node, f.clock.Now().Add(-time.Hour))
	challenge := f.challenge(t, "a.example.test")
	if err := f.store.PublishChallenge(t.Context(), challenge); err != nil {
		t.Fatal(err)
	}
	first := f.deliver(t)[node]
	f.receipt(t, first, "healthy", "")
	if status := f.status(t, challenge); len(status.Confirmed) != 1 || len(status.Serving) != 1 {
		t.Fatalf("before reinstall %+v", status)
	}

	f.clock.Advance(time.Minute)
	f.seedEnrollment(t, node, f.clock.Now()) // reinstall
	f.clock.Advance(time.Second)
	status := f.status(t, challenge)
	if len(status.Confirmed) != 0 || len(status.Serving) != 0 || len(status.Pending) != 1 || status.Pending[0] != node {
		t.Fatalf("after reinstall the new host is not serving the token: %+v", status)
	}
	if removed, err := f.store.ChallengeRemoved(t.Context(), challenge); err != nil || !removed {
		t.Fatalf("the new host holds no token: removed=%v err=%v", removed, err)
	}
	result, err := f.store.Reconcile(t.Context(), 100)
	if err != nil || result.Regenerated != 1 {
		t.Fatalf("reinstall reconcile %+v %v", result, err)
	}
	next := f.deliver(t)[node]
	if next.Generation != first.Generation+1 || next.Attempt != 1 {
		t.Fatalf("new host delivery %+v (previous host %+v)", next, first)
	}
	if got := f.servedTokens(t, node, false); len(got) != 1 || got[0] != challenge.Token {
		t.Fatalf("new generation tokens %v", got)
	}
	f.receipt(t, next, "healthy", "")
	if status := f.status(t, challenge); len(status.Confirmed) != 1 || len(status.Serving) != 1 {
		t.Fatalf("after the new host confirmed %+v", status)
	}
	if result, err := f.store.Reconcile(t.Context(), 100); err != nil || result != (NodeReconcileResult{}) {
		t.Fatalf("converged reinstalled node reconciled again: %+v %v", result, err)
	}
}

// Reinstalled with no live token: nothing to send (the agent takes any higher
// revision, the next challenge reaches the new host as usual).
func TestNodeHTTP01ReinstallWithoutLiveTokenIsQuiet(t *testing.T) {
	f := newNodeFixture(t, true, true)
	served, untouched := f.nodes[0], f.nodes[1]
	f.seedEnrollment(t, served, f.clock.Now().Add(-time.Hour))
	f.seedEnrollment(t, untouched, f.clock.Now().Add(-time.Hour))
	challenge := f.challenge(t, "a.example.test")
	if err := f.store.PublishChallenge(t.Context(), challenge); err != nil {
		t.Fatal(err)
	}
	for _, delivery := range f.deliver(t) {
		f.receipt(t, delivery, "healthy", "")
	}
	if err := f.store.WithdrawChallenge(t.Context(), challenge); err != nil {
		t.Fatal(err)
	}
	for _, delivery := range f.deliver(t) {
		f.receipt(t, delivery, "healthy", "")
	}
	if got := f.servedTokens(t, served, true); len(got) != 0 {
		t.Fatalf("withdrawn token still served: %v", got)
	}
	if result, err := f.store.Reconcile(t.Context(), 100); err != nil || result != (NodeReconcileResult{}) {
		t.Fatalf("converged before reinstall: %+v %v", result, err)
	}

	f.clock.Advance(time.Minute)
	f.seedEnrollment(t, served, f.clock.Now())
	f.seedEnrollment(t, untouched, f.clock.Now())
	f.clock.Advance(time.Second)
	if result, err := f.store.Reconcile(t.Context(), 100); err != nil || result != (NodeReconcileResult{}) {
		t.Fatalf("reinstall without a live token made work: %+v %v", result, err)
	}
	if got := f.deliver(t); len(got) != 0 {
		t.Fatalf("reinstall without a live token delivered %v", got)
	}

	// The next challenge reaches the new hosts as for any node.
	next := f.challenge(t, "a.example.test")
	if err := f.store.PublishChallenge(t.Context(), next); err != nil {
		t.Fatal(err)
	}
	deliveries := f.deliver(t)
	if len(deliveries) != 2 {
		t.Fatalf("next challenge deliveries %v", deliveries)
	}
	for _, delivery := range deliveries {
		f.receipt(t, delivery, "healthy", "")
	}
	if status := f.status(t, next); len(status.Confirmed) != 2 {
		t.Fatalf("next challenge status %+v", status)
	}
}

// A node enrolled once keeps its whole history: a generation made after its
// only enrollment confirms the token, reconcile does nothing, and ordinary
// generation advance (a second challenge) is unchanged.
func TestNodeHTTP01FirstEnrollmentUnchanged(t *testing.T) {
	f := newNodeFixture(t, true)
	node := f.nodes[0]
	f.seedEnrollment(t, node, f.clock.Now().Add(-time.Hour))
	first := f.challenge(t, "a.example.test")
	if err := f.store.PublishChallenge(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	delivery := f.deliver(t)[node]
	f.receipt(t, delivery, "healthy", "")
	if status := f.status(t, first); len(status.Confirmed) != 1 || len(status.Serving) != 1 {
		t.Fatalf("first challenge %+v", status)
	}
	f.clock.Advance(time.Minute)
	if result, err := f.store.Reconcile(t.Context(), 100); err != nil || result != (NodeReconcileResult{}) {
		t.Fatalf("enrolled-once node reconciled: %+v %v", result, err)
	}
	second := f.challenge(t, "b.example.test")
	if err := f.store.PublishChallenge(t.Context(), second); err != nil {
		t.Fatal(err)
	}
	next := f.deliver(t)[node]
	if next.Generation != delivery.Generation+1 || next.Attempt != 1 {
		t.Fatalf("ordinary advance %+v after %+v", next, delivery)
	}
	f.receipt(t, next, "healthy", "")
	if status := f.status(t, first); len(status.Confirmed) != 1 {
		t.Fatalf("first after advance %+v", status)
	}
	if status := f.status(t, second); len(status.Confirmed) != 1 {
		t.Fatalf("second after advance %+v", status)
	}
	if result, err := f.store.Reconcile(t.Context(), 100); err != nil || result != (NodeReconcileResult{}) {
		t.Fatalf("enrolled-once node reconciled after advance: %+v %v", result, err)
	}
}
