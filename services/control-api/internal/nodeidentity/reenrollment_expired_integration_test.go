//go:build integration

package nodeidentity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestReenrollmentCompletesExpiredLifecycleAtomically(t *testing.T) {
	for _, previous := range []string{"current", "overlap"} {
		t.Run(previous, func(t *testing.T) {
			pool := openIdentityTestDatabase(t, true)
			now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
			clock := &identityTestClock{value: now}
			signer := newIdentityTestCA(t, now)
			service := newIdentityTestService(t, pool, signer, clock)
			fixture := seedIdentityNode(t, pool, now, "pending", "initial_enrollment")
			request := validAuthorizeRequest(t, testCSR(t, false))
			request.EnrollmentToken = fixture.token
			auth, err := service.Authorize(t.Context(), request)
			if err != nil {
				t.Fatal(err)
			}
			first, err := service.Complete(t.Context(), CompleteRequest{RequestID: uuid.NewString(), AuthorizationID: auth.ID,
				GatewayWorkloadIdentity: request.GatewayWorkloadIdentity, GatewayInstanceID: request.GatewayInstanceID})
			if err != nil {
				t.Fatal(err)
			}
			if previous == "overlap" {
				if _, err := pool.Exec(t.Context(), `UPDATE node_certificates SET rotation_status='overlap',overlap_until=not_after,lifecycle_revision=lifecycle_revision+1 WHERE id=$1`, first.Certificate.ID); err != nil {
					t.Fatal(err)
				}
			}
			clock.set(first.Certificate.NotAfter.Add(time.Hour))
			retry := reenrollRequest(t, pool, fixture, clock)
			retry.EnrollmentToken = issueIdentityToken(t, pool, fixture, clock.now(), "re_enrollment")
			nextAuth, err := service.Authorize(t.Context(), retry)
			if err != nil {
				t.Fatal(err)
			}
			complete := CompleteRequest{RequestID: uuid.NewString(), AuthorizationID: nextAuth.ID,
				GatewayWorkloadIdentity: retry.GatewayWorkloadIdentity, GatewayInstanceID: retry.GatewayInstanceID}
			// A downstream persistence failure must also roll back retirement.
			if _, err := pool.Exec(t.Context(), `CREATE FUNCTION reject_reenrollment_test() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected'; END $$;
				CREATE TRIGGER reject_reenrollment_test BEFORE INSERT ON node_certificate_events FOR EACH ROW EXECUTE FUNCTION reject_reenrollment_test()`); err != nil {
				t.Fatal(err)
			}
			if _, err := service.Complete(t.Context(), complete); !errors.Is(err, ErrPersistence) {
				t.Fatalf("injected result=%v", err)
			}
			var rotation string
			if err := pool.QueryRow(t.Context(), `SELECT rotation_status FROM node_certificates WHERE id=$1`, first.Certificate.ID).Scan(&rotation); err != nil || rotation != previous {
				t.Fatalf("non-atomic retirement=%s %v", rotation, err)
			}
			if _, err := pool.Exec(t.Context(), `DROP TRIGGER reject_reenrollment_test ON node_certificate_events; DROP FUNCTION reject_reenrollment_test()`); err != nil {
				t.Fatal(err)
			}
			result, err := service.Complete(context.Background(), complete)
			if err != nil {
				t.Fatalf("complete expired %s: %v", previous, err)
			}
			replayed, err := service.Complete(t.Context(), complete)
			if err != nil || replayed.Certificate.ID != result.Certificate.ID {
				t.Fatalf("replay=%v", err)
			}
			if result.Certificate.NodeID != fixture.nodeID || result.Certificate.ID == first.Certificate.ID {
				t.Fatal("node identity changed or old certificate reused")
			}
			if err := pool.QueryRow(t.Context(), `SELECT rotation_status FROM node_certificates WHERE id=$1`, first.Certificate.ID).Scan(&rotation); err != nil || rotation != "retired" {
				t.Fatalf("expired certificate=%s %v", rotation, err)
			}
			var currentCount int
			if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM node_certificates WHERE node_id=$1 AND rotation_status='current' AND status='active'`, fixture.nodeID).Scan(&currentCount); err != nil || currentCount != 1 {
				t.Fatalf("current=%d err=%v", currentCount, err)
			}
		})
	}
}
