//go:build integration

package nodeidentity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/node"
	"github.com/google/uuid"
)

// TestDeletedNodeAuthorizationIsNotFound proves the Gateway side of a node
// purge: once the node row is gone, the authorization snapshot that every
// session refresh and every reconnect asks for resolves to "not found"
// (gRPC NotFound), so the live session ends at its next refresh — at most
// half the one-minute snapshot TTL — and the old certificate cannot connect.
func TestDeletedNodeAuthorizationIsNotFound(t *testing.T) {
	pool := openIdentityTestDatabase(t, true)
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	clock := &identityTestClock{value: now}
	signer := newIdentityTestCA(t, now)
	service := newIdentityTestService(t, pool, signer, clock)
	platform := seedIdentityPlatformNode(t, pool, now, "active", "initial_enrollment")

	authorize := validAuthorizeRequest(t, testCSR(t, false))
	authorize.EnrollmentToken = platform.token
	authorization, err := service.Authorize(context.Background(), authorize)
	if err != nil {
		t.Fatal(err)
	}
	completion, err := service.Complete(context.Background(), CompleteRequest{
		RequestID: uuid.NewString(), AuthorizationID: authorization.ID,
		GatewayWorkloadIdentity: authorize.GatewayWorkloadIdentity, GatewayInstanceID: authorize.GatewayInstanceID,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := GetAuthorizationRequest{
		NodeID:                  platform.nodeID,
		CertificateSerialNumber: completion.Certificate.SerialNumber,
		CertificateSHA256:       certificateDERDigest(t, completion.Certificate),
		GatewayWorkloadIdentity: authorize.GatewayWorkloadIdentity,
		GatewayInstanceID:       authorize.GatewayInstanceID,
	}
	if snapshot, err := service.GetAuthorization(context.Background(), request); err != nil || !snapshot.ConnectionAllowed {
		t.Fatalf("authorization before delete = %#v, %v", snapshot, err)
	}

	var revision int64
	if err := pool.QueryRow(context.Background(), `SELECT revision FROM nodes WHERE id=$1`, platform.nodeID).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	retired := node.StateRetired
	if _, err := node.NewService(node.NewStoreWithClock(pool, func() time.Time { return now }, nil)).UpdateNode(context.Background(),
		node.Actor{UserID: platform.userID, ScopeID: platform.scopeID},
		node.UpdateRequest{ID: platform.nodeID, ExpectedRevision: revision, Fields: node.UpdateFields{AdminState: &retired},
			IdempotencyKey: "purge-authorization", RequestID: "purge-authorization"}); err != nil {
		t.Fatalf("delete node: %v", err)
	}

	if _, err := service.GetAuthorization(context.Background(), request); !errors.Is(err, ErrCertificateNotFound) {
		t.Fatalf("authorization refresh after delete = %v, want %v", err, ErrCertificateNotFound)
	}
}
