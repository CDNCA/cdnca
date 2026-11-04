//go:build integration

package nodeidentity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Console "重装此节点": a re_enrollment token issued for one node lets a new
// host take over that node while the previous host still holds a live
// certificate. The node ID and admin state stay, the old certificate is
// revoked, and the token works once and only for its own node.
func TestReEnrollmentTokenReplacesLiveHost(t *testing.T) {
	pool := openIdentityTestDatabase(t, true)
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	clock := &identityTestClock{value: now}
	signer := newIdentityTestCA(t, now)
	service := newIdentityTestService(t, pool, signer, clock)
	ctx := context.Background()

	fixture := seedIdentityNode(t, pool, now, "draining", "initial_enrollment")
	oldRequest := validAuthorizeRequest(t, testCSR(t, false))
	oldRequest.EnrollmentToken = fixture.token
	oldCertificate := enrollIdentity(t, service, oldRequest)
	oldDigest := certificateDERDigest(t, oldCertificate)
	snapshotOf := func(certificate Certificate) AuthorizationSnapshot {
		t.Helper()
		snapshot, err := service.GetAuthorization(ctx, GetAuthorizationRequest{NodeID: fixture.nodeID,
			CertificateSerialNumber: certificate.SerialNumber, CertificateSHA256: certificateDERDigest(t, certificate),
			GatewayWorkloadIdentity: oldRequest.GatewayWorkloadIdentity, GatewayInstanceID: oldRequest.GatewayInstanceID})
		if err != nil {
			t.Fatalf("GetAuthorization(%s) error = %v", certificate.SerialNumber, err)
		}
		return snapshot
	}
	if before := snapshotOf(oldCertificate); !before.ConnectionAllowed || before.CertificateRevoked {
		t.Fatalf("old host before reinstall = %#v", before)
	}

	// Another node's re_enrollment token never touches this node.
	other := seedIdentityNode(t, pool, now, "active", "initial_enrollment")
	otherRequest := reenrollRequest(t, pool, other, clock)
	otherRequest.EnrollmentToken = issueIdentityToken(t, pool, other, now, "re_enrollment")
	if certificate := enrollIdentity(t, service, otherRequest); certificate.NodeID != other.nodeID {
		t.Fatalf("other node token issued a certificate for %s", certificate.NodeID)
	}
	assertCertificateStatus(t, pool, oldCertificate.ID, "active")

	token := issueIdentityToken(t, pool, fixture, now, "re_enrollment")
	newRequest := reenrollRequest(t, pool, fixture, clock)
	newRequest.EnrollmentToken = token
	newRequest.GatewayInstanceID = "gateway-reinstall"
	newAuthorization, err := service.Authorize(ctx, newRequest)
	if err != nil {
		t.Fatalf("Authorize(re_enrollment) error = %v", err)
	}
	complete := CompleteRequest{RequestID: uuid.NewString(), AuthorizationID: newAuthorization.ID,
		GatewayWorkloadIdentity: newRequest.GatewayWorkloadIdentity, GatewayInstanceID: newRequest.GatewayInstanceID}
	completion, err := service.Complete(ctx, complete)
	if err != nil {
		t.Fatalf("Complete(re_enrollment over live certificate) error = %v", err)
	}
	newCertificate := completion.Certificate
	if newCertificate.NodeID != fixture.nodeID || newCertificate.ID == oldCertificate.ID {
		t.Fatalf("reinstall certificate = %#v, want node %s and a new certificate", newCertificate, fixture.nodeID)
	}
	if replayed, err := service.Complete(ctx, complete); err != nil || replayed.Certificate.ID != newCertificate.ID {
		t.Fatalf("Complete(replay) = %#v, %v", replayed, err)
	}

	assertCertificateStatus(t, pool, oldCertificate.ID, "revoked")
	var reason, bindingStatus string
	var revocationRevision int64
	if err := pool.QueryRow(ctx, `SELECT reason,binding_status,authorization_revision FROM node_certificate_revocations
		WHERE certificate_id=$1 AND leaf_der_sha256=$2`, oldCertificate.ID, oldDigest[:]).Scan(
		&reason, &bindingStatus, &revocationRevision); err != nil || reason != reEnrollmentRevocationReason || bindingStatus != "bound" {
		t.Fatalf("revocation fact = %q/%q, %v", reason, bindingStatus, err)
	}
	var adminState string
	var current int
	if err := pool.QueryRow(ctx, `SELECT node.admin_state,
		(SELECT count(*) FROM node_certificates WHERE node_id=node.id AND status='active' AND rotation_status='current')
		FROM nodes node WHERE node.id=$1`, fixture.nodeID).Scan(&adminState, &current); err != nil ||
		adminState != "draining" || current != 1 {
		t.Fatalf("node after reinstall = %q with %d current certificates, %v", adminState, current, err)
	}
	if after := snapshotOf(oldCertificate); !after.CertificateRevoked || after.ConnectionAllowed {
		t.Fatalf("old host after reinstall = %#v", after)
	}
	newSnapshot, err := service.GetAuthorization(ctx, GetAuthorizationRequest{NodeID: fixture.nodeID,
		CertificateSerialNumber: newCertificate.SerialNumber, CertificateSHA256: certificateDERDigest(t, newCertificate),
		GatewayWorkloadIdentity: newRequest.GatewayWorkloadIdentity, GatewayInstanceID: newRequest.GatewayInstanceID})
	if err != nil || !newSnapshot.ConnectionAllowed || newSnapshot.CertificateRevoked ||
		newSnapshot.AuthorizationRevision <= uint64(revocationRevision) {
		t.Fatalf("new host after reinstall = %#v, %v", newSnapshot, err)
	}
	var auditRevoked string
	if err := pool.QueryRow(ctx, `SELECT payload->'revoked_replaced_certificate_ids'->>0 FROM audit_events
		WHERE action='node_certificate.lifecycle.enroll' AND resource_id=$1`, newCertificate.ID.String()).Scan(&auditRevoked); err != nil ||
		auditRevoked != oldCertificate.ID.String() {
		t.Fatalf("enroll audit revoked = %q, %v", auditRevoked, err)
	}

	// The token is one-time: a third host cannot reuse it.
	reuse := reenrollRequest(t, pool, fixture, clock)
	reuse.EnrollmentToken = token
	if _, err := service.Authorize(ctx, reuse); !errors.Is(err, ErrTokenConsumed) {
		t.Fatalf("Authorize(reused re_enrollment token) error = %v", err)
	}
	assertCertificateStatus(t, pool, newCertificate.ID, "active")
}

func enrollIdentity(t *testing.T, service *Service, request AuthorizeRequest) Certificate {
	t.Helper()
	authorization, err := service.Authorize(context.Background(), request)
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	completion, err := service.Complete(context.Background(), CompleteRequest{RequestID: uuid.NewString(),
		AuthorizationID: authorization.ID, GatewayWorkloadIdentity: request.GatewayWorkloadIdentity,
		GatewayInstanceID: request.GatewayInstanceID})
	if err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
	return completion.Certificate
}

func assertCertificateStatus(t *testing.T, pool *pgxpool.Pool, id uuid.UUID, want string) {
	t.Helper()
	var status string
	if err := pool.QueryRow(context.Background(), `SELECT status FROM node_certificates WHERE id=$1`, id).Scan(&status); err != nil || status != want {
		t.Fatalf("certificate %s status = %q, want %q (%v)", id, status, want, err)
	}
}
