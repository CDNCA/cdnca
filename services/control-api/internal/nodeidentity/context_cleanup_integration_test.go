//go:build integration

package nodeidentity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestNodeIdentityEnrollmentFailureResetsSigningLeaseAfterContextCancellation(t *testing.T) {
	pool := openIdentityTestDatabase(t, true)
	now := time.Date(2026, 7, 22, 10, 15, 0, 0, time.UTC)
	clock := &identityTestClock{value: now}
	baseSigner := newIdentityTestCA(t, now)
	seedIdentityCAEpoch(t, pool, baseSigner, now)

	ctx, cancel := context.WithCancel(context.Background())
	signer := cancelingIdentitySigner{cancel: cancel}
	config := DefaultConfig()
	config.Clock = clock.now
	service, err := NewService(NewStore(pool), signer, config)
	if err != nil {
		t.Fatal(err)
	}
	fixture := seedIdentityNode(t, pool, now, "pending", "initial_enrollment")
	authorize := validAuthorizeRequest(t, testCSR(t, false))
	authorize.EnrollmentToken = fixture.token
	authorization, err := service.Authorize(context.Background(), authorize)
	if err != nil {
		t.Fatal(err)
	}
	complete := CompleteRequest{RequestID: uuid.NewString(), AuthorizationID: authorization.ID,
		GatewayWorkloadIdentity: authorize.GatewayWorkloadIdentity, GatewayInstanceID: authorize.GatewayInstanceID}
	if _, err := service.Complete(ctx, complete); !errors.Is(err, ErrSigningFailed) {
		t.Fatalf("Complete() error = %v", err)
	}

	var status string
	var leaseID *uuid.UUID
	if err := pool.QueryRow(context.Background(), `SELECT status,signing_lease_id
		FROM node_identity_authorizations WHERE id=$1`, authorization.ID).Scan(&status, &leaseID); err != nil {
		t.Fatal(err)
	}
	if status != "authorized" || leaseID != nil {
		t.Fatalf("failed enrollment authorization = status %q lease %v, want authorized without lease", status, leaseID)
	}
}

type cancelingIdentitySigner struct {
	cancel context.CancelFunc
}

func (signer cancelingIdentitySigner) SignNodeCertificate(context.Context, SignRequest) (SignedCertificate, error) {
	signer.cancel()
	return SignedCertificate{}, errors.New("test signer failure after cancellation")
}
