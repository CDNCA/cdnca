//go:build integration

package nodecertlifecycle

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestLifecycleCAEpochRotationAndRevocation(t *testing.T) {
	fixture := newLifecycleFixture(t)
	ca1, _ := testCertificateAuthority(t, fixture.clock.Now())
	request := RotateCAEpochRequest{
		RequestID: uuid.New(), KeyID: "node-ca-1", CACertificatePEM: certificatePEM(ca1),
		RequestTraceID: "trace-ca-1",
	}
	if _, err := fixture.store.RotateCAEpoch(context.Background(), fixture.nodeAdminActor, request); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("RotateCAEpoch(node admin without node_ca.manage) error = %v", err)
	}
	tenantID, tenantScopeID, tenantUserID, tenantRoleID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	err := pgx.BeginFunc(context.Background(), fixture.pool, func(tx pgx.Tx) error {
		statements := []struct {
			query string
			args  []any
		}{
			{`INSERT INTO tenants(id,display_name) VALUES($1,'Lifecycle tenant')`, []any{tenantID}},
			{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{tenantScopeID, tenantID}},
			{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'Tenant CA operator','test-only')`, []any{tenantUserID, "tenant-ca-" + hex.EncodeToString(tenantUserID[:6])}},
			{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{tenantScopeID, tenantUserID}},
			// A tenant role holding node_ca.manage cannot be created any more
			// (042 custom RBAC facts, 094 tenant permission guard); the store
			// must still refuse it, so the row and its grant are written with
			// triggers off and the assignment goes through every trigger.
			{`SET LOCAL session_replication_role='replica'`, nil},
			{`INSERT INTO roles(id,scope_id,name,description) VALUES($1,$2,'tenant_ca_operator','Tenant CA operator')`, []any{tenantRoleID, tenantScopeID}},
			{`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'node_ca.manage')`, []any{tenantRoleID}},
			{`SET LOCAL session_replication_role='origin'`, nil},
			{`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, []any{tenantScopeID, tenantUserID, tenantRoleID}},
		}
		for _, statement := range statements {
			if _, err := tx.Exec(context.Background(), statement.query, statement.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.RotateCAEpoch(context.Background(), Actor{
		UserID: tenantUserID, ScopeID: tenantScopeID, ScopeKind: "tenant",
	}, request); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("RotateCAEpoch(tenant with node_ca.manage) error = %v", err)
	}
	epoch1, err := fixture.store.RotateCAEpoch(context.Background(), fixture.actor, request)
	if err != nil || epoch1.Epoch != 1 || epoch1.Status != EpochActive || epoch1.Replayed {
		t.Fatalf("RotateCAEpoch(initial) = %#v, %v", epoch1, err)
	}
	replay, err := fixture.store.RotateCAEpoch(context.Background(), fixture.actor, request)
	if err != nil || !replay.Replayed || replay.ID != epoch1.ID {
		t.Fatalf("RotateCAEpoch(replay) = %#v, %v", replay, err)
	}
	originalNow := fixture.clock.Now()
	fixture.clock.Set(ca1.NotAfter)
	expiredReplay, err := fixture.store.RotateCAEpoch(context.Background(), fixture.actor, request)
	if err != nil || !expiredReplay.Replayed || expiredReplay.ID != epoch1.ID {
		t.Fatalf("RotateCAEpoch(replay after CA expiry) = %#v, %v", expiredReplay, err)
	}
	expiredNew := request
	expiredNew.RequestID = uuid.New()
	expiredNew.ExpectedCurrentEpoch = 1
	expiredNew.KeyID = "expired-node-ca"
	if _, err := fixture.store.RotateCAEpoch(context.Background(), fixture.actor, expiredNew); !errors.Is(err, ErrCAEpochExpired) {
		t.Fatalf("RotateCAEpoch(new expired CA) error = %v", err)
	}
	fixture.clock.Set(originalNow)
	conflict := request
	conflict.KeyID = "node-ca-conflict"
	if _, err := fixture.store.RotateCAEpoch(context.Background(), fixture.actor, conflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("RotateCAEpoch(conflicting replay) error = %v", err)
	}

	ca2, _ := testCertificateAuthority(t, fixture.clock.Now())
	wrongRevision := RotateCAEpochRequest{RequestID: uuid.New(), ExpectedCurrentEpoch: 0,
		KeyID: "node-ca-2", CACertificatePEM: certificatePEM(ca2), RequestTraceID: "trace-ca-wrong-revision"}
	if _, err := fixture.store.RotateCAEpoch(context.Background(), fixture.actor, wrongRevision); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("RotateCAEpoch(wrong expected epoch) error = %v", err)
	}
	wrongRevision.ExpectedCurrentEpoch = 1
	epoch2, err := fixture.store.RotateCAEpoch(context.Background(), fixture.actor, wrongRevision)
	if err != nil || epoch2.Epoch != 2 || epoch2.Status != EpochActive {
		t.Fatalf("RotateCAEpoch(second) = %#v, %v", epoch2, err)
	}

	revoke := RevokeCAEpochRequest{RequestID: uuid.New(), EpochID: epoch1.ID,
		Reason: "retired key compromised", RequestTraceID: "trace-ca-revoke"}
	if err := fixture.store.RevokeCAEpoch(context.Background(), fixture.actor, revoke); err != nil {
		t.Fatalf("RevokeCAEpoch() error = %v", err)
	}
	if err := fixture.store.RevokeCAEpoch(context.Background(), fixture.actor, revoke); err != nil {
		t.Fatalf("RevokeCAEpoch(replay) error = %v", err)
	}
	conflictingRevoke := revoke
	conflictingRevoke.Reason = "different reason"
	if err := fixture.store.RevokeCAEpoch(context.Background(), fixture.actor, conflictingRevoke); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("RevokeCAEpoch(conflicting replay) error = %v", err)
	}
	var firstStatus, secondStatus string
	if err := fixture.pool.QueryRow(context.Background(), `SELECT status FROM node_ca_key_epochs WHERE id=$1`, epoch1.ID).Scan(&firstStatus); err != nil {
		t.Fatal(err)
	}
	if err := fixture.pool.QueryRow(context.Background(), `SELECT status FROM node_ca_key_epochs WHERE id=$1`, epoch2.ID).Scan(&secondStatus); err != nil {
		t.Fatal(err)
	}
	if firstStatus != EpochRevoked || secondStatus != EpochActive {
		t.Fatalf("epoch states = %q/%q", firstStatus, secondStatus)
	}
}

func TestLifecycleLegacyAdoptionValidationReplayAndConcurrency(t *testing.T) {
	fixture := newLifecycleFixture(t)
	ca1, ca1Key, epoch1 := fixture.rotateCA(t, 0, "adoption-ca-1")
	legacy := fixture.seedLegacyCertificate(t, ca1, ca1Key, 0x21, fixture.clock.Now().Add(-time.Minute), "active")
	request := AdoptCertificateRequest{RequestID: uuid.New(), NodeID: legacy.nodeID,
		SerialNumber: legacy.serial, LeafDERSHA256: legacy.derHash, CAEpochID: epoch1.ID,
		RequestTraceID: "trace-adopt"}

	badActor := fixture.actor
	badActor.UserID = uuid.New()
	if _, err := fixture.store.AdoptCertificate(context.Background(), badActor, request); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("AdoptCertificate(wrong actor) error = %v", err)
	}
	if _, err := fixture.store.AdoptCertificate(context.Background(), fixture.unprivilegedActor, request); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("AdoptCertificate(member without nodes.manage) error = %v", err)
	}
	wrongNode := request
	wrongNode.NodeID = uuid.New()
	if _, err := fixture.store.AdoptCertificate(context.Background(), fixture.actor, wrongNode); !errors.Is(err, ErrNotFound) {
		t.Fatalf("AdoptCertificate(wrong node) error = %v", err)
	}
	wrongSerial := request
	wrongSerial.SerialNumber = "22"
	if _, err := fixture.store.AdoptCertificate(context.Background(), fixture.actor, wrongSerial); !errors.Is(err, ErrNotFound) {
		t.Fatalf("AdoptCertificate(wrong serial) error = %v", err)
	}
	wrongHash := request
	wrongHash.LeafDERSHA256[0] ^= 0xff
	if _, err := fixture.store.AdoptCertificate(context.Background(), fixture.actor, wrongHash); !errors.Is(err, ErrCertificateInvalid) {
		t.Fatalf("AdoptCertificate(wrong DER hash) error = %v", err)
	}
	unknownCA := request
	unknownCA.CAEpochID = uuid.New()
	if _, err := fixture.store.AdoptCertificate(context.Background(), fixture.actor, unknownCA); !errors.Is(err, ErrCAEpochConflict) {
		t.Fatalf("AdoptCertificate(unknown CA) error = %v", err)
	}
	_, _, epoch2 := fixture.rotateCA(t, 1, "adoption-ca-2")
	wrongCA := request
	wrongCA.CAEpochID = epoch2.ID
	if _, err := fixture.store.AdoptCertificate(context.Background(), fixture.actor, wrongCA); !errors.Is(err, ErrCertificateInvalid) {
		t.Fatalf("AdoptCertificate(wrong CA) error = %v", err)
	}
	narrowCA, narrowKey := testCertificateAuthorityWithValidity(t,
		fixture.clock.Now().Add(-30*time.Minute), fixture.clock.Now().Add(30*time.Minute))
	narrowEpoch, err := fixture.store.RotateCAEpoch(context.Background(), fixture.actor, RotateCAEpochRequest{
		RequestID: uuid.New(), ExpectedCurrentEpoch: 2, KeyID: "adoption-narrow-ca",
		CACertificatePEM: certificatePEM(narrowCA), RequestTraceID: "trace-adoption-narrow-ca",
	})
	if err != nil {
		t.Fatal(err)
	}
	outsideCA := fixture.seedLegacyCertificate(t, narrowCA, narrowKey, 0x25,
		fixture.clock.Now().Add(-time.Minute), "active",
		fixture.clock.Now().Add(-time.Hour), fixture.clock.Now().Add(10*time.Minute))
	outsideRequest := AdoptCertificateRequest{RequestID: uuid.New(), NodeID: outsideCA.nodeID,
		SerialNumber: outsideCA.serial, LeafDERSHA256: outsideCA.derHash, CAEpochID: narrowEpoch.ID,
		RequestTraceID: "trace-adopt-outside-ca-validity"}
	if _, err := fixture.store.AdoptCertificate(context.Background(), fixture.actor, outsideRequest); !errors.Is(err, ErrCertificateInvalid) {
		t.Fatalf("AdoptCertificate(leaf validity exceeds CA) error = %v", err)
	}
	lifecycleDigest := sha256.Sum256([]byte("schema-valid-invalid-ca-binding"))
	if _, err := fixture.pool.Exec(context.Background(), `UPDATE node_certificates SET
		owner_scope_id=$2,installation_id=$3,ca_epoch_id=$4,leaf_der_sha256=$5,
		rotation_status='current',lifecycle_revision=1,lifecycle_request_id=$6,
		lifecycle_request_digest=$7,lifecycle_bound_at=$8 WHERE id=$1`, outsideCA.certificateID,
		fixture.actor.ScopeID, fixture.installationID, narrowEpoch.ID, outsideCA.derHash[:], uuid.New(),
		lifecycleDigest[:], fixture.clock.Now()); err != nil {
		t.Fatal(err)
	}
	outsideSnapshot := fixture.lookup(t, outsideCA)
	if outsideSnapshot.ConnectionAllowed || outsideSnapshot.DenialReason != denialBindingInvalid {
		t.Fatalf("LookupAuthorization(leaf validity exceeds CA) = %#v", outsideSnapshot)
	}

	adopted, err := fixture.store.AdoptCertificate(context.Background(), fixture.actor, request)
	if err != nil || adopted.RotationStatus != RotationCurrent || adopted.Revision != 1 || adopted.Replayed {
		t.Fatalf("AdoptCertificate() = %#v, %v", adopted, err)
	}
	replayed, err := fixture.store.AdoptCertificate(context.Background(), fixture.actor, request)
	if err != nil || !replayed.Replayed || replayed.CertificateID != adopted.CertificateID {
		t.Fatalf("AdoptCertificate(replay) = %#v, %v", replayed, err)
	}
	conflict := request
	conflict.CAEpochID = epoch2.ID
	if _, err := fixture.store.AdoptCertificate(context.Background(), fixture.actor, conflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("AdoptCertificate(conflicting replay) error = %v", err)
	}

	concurrent := fixture.seedLegacyCertificate(t, ca1, ca1Key, 0x23, fixture.clock.Now().Add(-time.Minute), "active")
	start := make(chan struct{})
	errorsByCall := make(chan error, 2)
	for range 2 {
		go func(requestID uuid.UUID) {
			<-start
			_, err := fixture.store.AdoptCertificate(context.Background(), fixture.actor, AdoptCertificateRequest{
				RequestID: requestID, NodeID: concurrent.nodeID, SerialNumber: concurrent.serial,
				LeafDERSHA256: concurrent.derHash, CAEpochID: epoch1.ID, RequestTraceID: "trace-concurrent-adopt",
			})
			errorsByCall <- err
		}(uuid.New())
	}
	close(start)
	var successes, conflicts int
	for range 2 {
		err := <-errorsByCall
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrIdempotencyConflict), errors.Is(err, ErrRevisionConflict):
			conflicts++
		default:
			t.Fatalf("concurrent AdoptCertificate error = %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent adoption successes/conflicts = %d/%d", successes, conflicts)
	}

	revokedLegacy := fixture.seedLegacyCertificate(t, ca1, ca1Key, 0x24, fixture.clock.Now().Add(-time.Minute), "active")
	if _, err := fixture.pool.Exec(context.Background(), `INSERT INTO node_certificate_revocations(
		request_id,request_digest,certificate_id,node_id,reason,revoked_at,authorization_revision)
		VALUES($1,$2,$3,$4,'legacy revocation',$5,2)`, uuid.New(), digestBytes(8),
		revokedLegacy.certificateID, revokedLegacy.nodeID, fixture.clock.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.AdoptCertificate(context.Background(), fixture.actor, AdoptCertificateRequest{
		RequestID: uuid.New(), NodeID: revokedLegacy.nodeID, SerialNumber: revokedLegacy.serial,
		LeafDERSHA256: revokedLegacy.derHash, CAEpochID: epoch1.ID, RequestTraceID: "trace-revoked-legacy-adopt",
	}); !errors.Is(err, ErrCertificateRevoked) {
		t.Fatalf("AdoptCertificate(legacy revocation) error = %v", err)
	}
}

func TestLifecycleRenewalProofBindingOverlapAndOfflineLookup(t *testing.T) {
	fixture := newLifecycleFixture(t)
	ca, caKey, epoch := fixture.rotateCA(t, 0, "renewal-ca")
	early := fixture.seedAdoptedCertificate(t, ca, caKey, epoch, 0x31, fixture.clock.Now().Add(10*time.Minute), "active")
	earlyRenewal := fixture.seedRenewalRequest(t, early, "spiffe://cdn-platform/gateway/renewal", "gateway-1")
	if _, err := fixture.store.RecordGatewayMTLSProof(context.Background(), fixture.proofRequest(earlyRenewal, early, epoch)); !errors.Is(err, ErrRenewalTooEarly) {
		t.Fatalf("RecordGatewayMTLSProof(too early) error = %v", err)
	}

	current := fixture.seedAdoptedCertificate(t, ca, caKey, epoch, 0x32, fixture.clock.Now().Add(-time.Minute), "active")
	renewal := fixture.seedRenewalRequest(t, current, "spiffe://cdn-platform/gateway/renewal", "gateway-2")
	proofRequest := fixture.proofRequest(renewal, current, epoch)
	wrongWorkload := proofRequest
	wrongWorkload.Principal.workloadIdentity = "spiffe://cdn-platform/gateway/wrong"
	if _, err := fixture.store.RecordGatewayMTLSProof(context.Background(), wrongWorkload); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("RecordGatewayMTLSProof(wrong workload) error = %v", err)
	}
	wrongInstance := proofRequest
	wrongInstance.Principal.instanceID = "gateway-wrong"
	if _, err := fixture.store.RecordGatewayMTLSProof(context.Background(), wrongInstance); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("RecordGatewayMTLSProof(wrong instance) error = %v", err)
	}
	wrongNode := proofRequest
	wrongNode.NodeID = uuid.New()
	if _, err := fixture.store.RecordGatewayMTLSProof(context.Background(), wrongNode); !errors.Is(err, ErrNotFound) {
		t.Fatalf("RecordGatewayMTLSProof(wrong node) error = %v", err)
	}
	wrongLeaf := proofRequest
	wrongLeaf.CurrentLeafDERSHA256[0] ^= 0xff
	if _, err := fixture.store.RecordGatewayMTLSProof(context.Background(), wrongLeaf); !errors.Is(err, ErrCertificateInvalid) {
		t.Fatalf("RecordGatewayMTLSProof(wrong leaf) error = %v", err)
	}
	wrongEpoch := proofRequest
	wrongEpoch.TargetCAEpochID = uuid.New()
	if _, err := fixture.store.RecordGatewayMTLSProof(context.Background(), wrongEpoch); !errors.Is(err, ErrCAEpochConflict) {
		t.Fatalf("RecordGatewayMTLSProof(wrong epoch) error = %v", err)
	}

	proof, err := fixture.store.RecordGatewayMTLSProof(context.Background(), proofRequest)
	if err != nil || proof.Status != ProofGatewayMTLS || proof.Revision != 1 || proof.Replayed {
		t.Fatalf("RecordGatewayMTLSProof() = %#v, %v", proof, err)
	}
	proofReplay, err := fixture.store.RecordGatewayMTLSProof(context.Background(), proofRequest)
	if err != nil || !proofReplay.Replayed || proofReplay.MessageSHA256 != proof.MessageSHA256 {
		t.Fatalf("RecordGatewayMTLSProof(replay) = %#v, %v", proofReplay, err)
	}
	proofMessage, err := GatewayMTLSProofMessage(proof, proofRequest.Principal)
	if err != nil || sha256.Sum256(proofMessage) != proof.MessageSHA256 {
		t.Fatalf("persisted proof digest does not match the trusted principal: %v", err)
	}
	wrongReplayInstance := proofRequest
	wrongReplayInstance.Principal.instanceID = "gateway-replay-wrong"
	if _, err := fixture.store.RecordGatewayMTLSProof(context.Background(), wrongReplayInstance); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("RecordGatewayMTLSProof(replay wrong instance) error = %v", err)
	}
	otherInstanceMessage, err := GatewayMTLSProofMessage(proof, wrongReplayInstance.Principal)
	if err != nil || sha256.Sum256(otherInstanceMessage) == proof.MessageSHA256 {
		t.Fatalf("replay proof digest did not bind the Gateway instance: %v", err)
	}
	wrongReplayLeaf := proofRequest
	wrongReplayLeaf.CurrentLeafDERSHA256[0] ^= 0xff
	if _, err := fixture.store.RecordGatewayMTLSProof(context.Background(), wrongReplayLeaf); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("RecordGatewayMTLSProof(replay wrong leaf) error = %v", err)
	}
	otherLeafFact := proof
	otherLeafFact.CurrentLeafDERSHA256 = wrongReplayLeaf.CurrentLeafDERSHA256
	otherLeafMessage, err := GatewayMTLSProofMessage(otherLeafFact, proofRequest.Principal)
	if err != nil || sha256.Sum256(otherLeafMessage) == proof.MessageSHA256 {
		t.Fatalf("replay proof digest did not bind the leaf DER digest: %v", err)
	}

	issued := fixture.seedIssuedRenewal(t, renewal, current, ca, caKey, 0x33)
	rotation, err := fixture.store.BindIssuedRenewal(context.Background(), BindIssuedRenewalRequest{
		RenewalRequestID: renewal.requestID, NodeID: current.nodeID, NewSerialNumber: issued.serial,
		NewLeafDERSHA256: issued.derHash, RequestTraceID: "trace-bind-renewal",
	})
	if err != nil || rotation.Replayed || rotation.CurrentCertificate.SerialNumber != issued.serial ||
		rotation.PreviousCertificate.RotationStatus != RotationOverlap || rotation.CurrentCertificate.RotationStatus != RotationCurrent {
		t.Fatalf("BindIssuedRenewal() = %#v, %v", rotation, err)
	}
	if _, err := fixture.pool.Exec(context.Background(), `UPDATE node_certificate_renewal_requests
		SET completed_at=completed_at+interval '1 second' WHERE request_id=$1`, renewal.requestID); err == nil {
		t.Fatal("database allowed same-status mutation of completed renewal state")
	}
	newSnapshot := fixture.lookup(t, issued)
	oldSnapshot := fixture.lookup(t, current)
	if !newSnapshot.ConnectionAllowed || !newSnapshot.DeploymentsAllowed {
		t.Fatalf("current certificate authorization = %#v", newSnapshot)
	}
	if !oldSnapshot.ConnectionAllowed || oldSnapshot.DeploymentsAllowed || oldSnapshot.RotationStatus != RotationOverlap {
		t.Fatalf("overlap certificate authorization = %#v", oldSnapshot)
	}

	fixture.clock.Set(rotation.PreviousCertificate.OverlapUntil.Add(time.Microsecond))
	oldSnapshot = fixture.lookup(t, current)
	if oldSnapshot.ConnectionAllowed || oldSnapshot.DenialReason != denialOverlapExpired {
		t.Fatalf("expired overlap authorization = %#v", oldSnapshot)
	}
	replay, err := fixture.store.BindIssuedRenewal(context.Background(), BindIssuedRenewalRequest{
		RenewalRequestID: renewal.requestID, NodeID: current.nodeID, NewSerialNumber: issued.serial,
		NewLeafDERSHA256: issued.derHash, RequestTraceID: "trace-bind-renewal",
	})
	if err != nil || !replay.Replayed {
		t.Fatalf("BindIssuedRenewal(replay) = %#v, %v", replay, err)
	}
	if _, err := fixture.store.BindIssuedRenewal(context.Background(), BindIssuedRenewalRequest{
		RenewalRequestID: renewal.requestID, NodeID: current.nodeID, NewSerialNumber: "34",
		NewLeafDERSHA256: issued.derHash, RequestTraceID: "trace-bind-conflict",
	}); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("BindIssuedRenewal(conflicting replay) error = %v", err)
	}

	if _, err := fixture.pool.Exec(context.Background(), `UPDATE nodes SET admin_state='disabled',updated_at=$2 WHERE id=$1`,
		issued.nodeID, fixture.clock.Now()); err != nil {
		t.Fatal(err)
	}
	offline := fixture.lookup(t, issued)
	if offline.ConnectionAllowed || offline.DeploymentsAllowed || offline.DenialReason != denialNodeInactive {
		t.Fatalf("offline node authorization = %#v", offline)
	}
	fixture.clock.Set(current.leaf.NotAfter.Add(time.Second))
	lateProofReplay, err := fixture.store.RecordGatewayMTLSProof(context.Background(), proofRequest)
	if err != nil || !lateProofReplay.Replayed || lateProofReplay.MessageSHA256 != proof.MessageSHA256 {
		t.Fatalf("RecordGatewayMTLSProof(replay after request/certificate expiry) = %#v, %v", lateProofReplay, err)
	}
}

func TestLifecycleRenewalProofReplaysLegacyV1Digest(t *testing.T) {
	for _, test := range []struct {
		name    string
		message func(RenewalProofFact, GatewayMTLSPrincipal) ([]byte, error)
	}{
		{name: "without instance field", message: legacyGatewayMTLSProofMessage},
		{name: "with instance field", message: legacyInstanceBoundGatewayMTLSProofMessage},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newLifecycleFixture(t)
			ca, caKey, epoch := fixture.rotateCA(t, 0, "legacy-proof-ca")
			current := fixture.seedAdoptedCertificate(t, ca, caKey, epoch, 0x35,
				fixture.clock.Now().Add(-time.Minute), "active")
			renewalID := uuid.New()
			csrDER := []byte("legacy-v1-renewal-csr")
			csrDigest := sha256.Sum256(csrDER)
			principal := GatewayMTLSPrincipal{
				workloadIdentity: "spiffe://cdn-platform/gateway/legacy-proof",
				instanceID:       "gateway-legacy-proof",
			}
			fact := RenewalProofFact{
				RenewalRequestID: renewalID, NodeID: current.nodeID,
				OwnerScopeID: fixture.actor.ScopeID, InstallationID: fixture.installationID,
				CurrentSerialNumber: current.serial, CurrentLeafDERSHA256: current.derHash,
				TargetCAEpochID: epoch.ID, CSRSHA256: csrDigest,
			}
			legacyMessage, err := test.message(fact, principal)
			if err != nil {
				t.Fatal(err)
			}
			legacyDigest := sha256.Sum256(legacyMessage)
			if _, err := fixture.pool.Exec(context.Background(), `INSERT INTO node_certificate_renewal_requests(
				request_id,request_digest,node_id,current_certificate_id,current_serial_number,csr_der,csr_sha256,
				gateway_workload_identity,gateway_instance_id,status,created_at,expires_at,
				owner_scope_id,installation_id,ca_epoch_id,current_leaf_der_sha256,pop_status,pop_revision,
				pop_method,pop_message_sha256,pop_observed_at)
				VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'pending',$10,$11,$12,$13,$14,$15,
				'gateway_mtls_proven',1,'gateway_mtls',$16,$10)`, renewalID, digestBytes(17), current.nodeID,
				current.certificateID, current.serial, csrDER, csrDigest[:], principal.workloadIdentity,
				principal.instanceID, fixture.clock.Now(), fixture.clock.Now().Add(time.Hour), fixture.actor.ScopeID,
				fixture.installationID, epoch.ID, current.derHash[:], legacyDigest[:]); err != nil {
				t.Fatal(err)
			}
			request := RecordGatewayMTLSProofRequest{
				RenewalRequestID: renewalID, NodeID: current.nodeID, CurrentSerialNumber: current.serial,
				CurrentLeafDERSHA256: current.derHash, TargetCAEpochID: epoch.ID, Principal: principal,
				RequestTraceID: "trace-legacy-v1-proof-replay",
			}
			replay, err := fixture.store.RecordGatewayMTLSProof(context.Background(), request)
			if err != nil || !replay.Replayed || replay.MessageSHA256 != legacyDigest {
				t.Fatalf("RecordGatewayMTLSProof(legacy v1 replay) = %#v, %v", replay, err)
			}
			wrongInstance := request
			wrongInstance.Principal.instanceID = "gateway-other"
			if _, err := fixture.store.RecordGatewayMTLSProof(context.Background(), wrongInstance); !errors.Is(err, ErrPermissionDenied) {
				t.Fatalf("RecordGatewayMTLSProof(legacy v1 wrong instance) error = %v", err)
			}
		})
	}
}

func TestLifecycleCertificateRevocationSchedulingReplayAndTTL(t *testing.T) {
	fixture := newLifecycleFixture(t)
	ca, caKey, epoch := fixture.rotateCA(t, 0, "revocation-ca")
	futureCertificate := fixture.seedAdoptedCertificate(t, ca, caKey, epoch, 0x41, fixture.clock.Now().Add(-time.Minute), "active")
	effectiveAt := fixture.clock.Now().Add(30 * time.Second)
	request := RevokeCertificateRequest{RequestID: uuid.New(), NodeID: futureCertificate.nodeID,
		SerialNumber: futureCertificate.serial, LeafDERSHA256: futureCertificate.derHash,
		Reason: "scheduled replacement", EffectiveAt: effectiveAt, RequestTraceID: "trace-future-revoke"}
	revocation, err := fixture.store.RevokeCertificate(context.Background(), fixture.actor, request)
	if err != nil || revocation.Replayed || !revocation.EffectiveAt.Equal(effectiveAt) {
		t.Fatalf("RevokeCertificate(future) = %#v, %v", revocation, err)
	}
	before := fixture.lookup(t, futureCertificate)
	if !before.ConnectionAllowed || !before.SnapshotExpiresAt.Equal(effectiveAt) {
		t.Fatalf("future revocation authorization = %#v", before)
	}
	replay, err := fixture.store.RevokeCertificate(context.Background(), fixture.actor, request)
	if err != nil || !replay.Replayed || replay.RequestID != request.RequestID {
		t.Fatalf("RevokeCertificate(replay) = %#v, %v", replay, err)
	}
	conflict := request
	conflict.Reason = "different scheduled reason"
	if _, err := fixture.store.RevokeCertificate(context.Background(), fixture.actor, conflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("RevokeCertificate(conflicting replay) error = %v", err)
	}
	advance := RevokeCertificateRequest{RequestID: uuid.New(), NodeID: futureCertificate.nodeID,
		SerialNumber: futureCertificate.serial, LeafDERSHA256: futureCertificate.derHash,
		Reason: "emergency acceleration", RequestTraceID: "trace-accelerated-revoke"}
	type revokeResult struct {
		value Revocation
		err   error
	}
	results := make(chan revokeResult, 2)
	var revokeWG sync.WaitGroup
	for range 2 {
		revokeWG.Add(1)
		go func() {
			defer revokeWG.Done()
			value, err := fixture.store.RevokeCertificate(context.Background(), fixture.actor, advance)
			results <- revokeResult{value: value, err: err}
		}()
	}
	revokeWG.Wait()
	close(results)
	var writes, replays int
	for result := range results {
		if result.err != nil {
			t.Fatalf("RevokeCertificate(concurrent acceleration) error = %v", result.err)
		}
		if result.value.Replayed {
			replays++
		} else {
			writes++
		}
	}
	if writes != 1 || replays != 1 {
		t.Fatalf("concurrent acceleration writes/replays = %d/%d", writes, replays)
	}
	var revocationFacts int
	if err := fixture.pool.QueryRow(context.Background(), `SELECT count(*) FROM node_certificate_revocations
		WHERE certificate_id=$1`, futureCertificate.certificateID).Scan(&revocationFacts); err != nil {
		t.Fatal(err)
	}
	if revocationFacts != 2 {
		t.Fatalf("revocation fact count = %d, want 2", revocationFacts)
	}
	accelerated := fixture.lookup(t, futureCertificate)
	if accelerated.ConnectionAllowed || accelerated.DenialReason != denialCertificateRevoked ||
		accelerated.SnapshotExpiresAt.After(fixture.clock.Now()) {
		t.Fatalf("accelerated revocation authorization = %#v", accelerated)
	}
	fixture.clock.Set(effectiveAt)
	after := fixture.lookup(t, futureCertificate)
	if after.ConnectionAllowed || after.DenialReason != denialCertificateRevoked {
		t.Fatalf("effective scheduled revocation authorization = %#v", after)
	}

	immediateCertificate := fixture.seedAdoptedCertificate(t, ca, caKey, epoch, 0x42, fixture.clock.Now().Add(-time.Minute), "active")
	immediateRequest := RevokeCertificateRequest{RequestID: uuid.New(), NodeID: immediateCertificate.nodeID,
		SerialNumber: immediateCertificate.serial, LeafDERSHA256: immediateCertificate.derHash,
		Reason: "key compromise", RequestTraceID: "trace-immediate-revoke"}
	immediate, err := fixture.store.RevokeCertificate(context.Background(), fixture.actor, immediateRequest)
	if err != nil || immediate.Replayed || !immediate.EffectiveAt.Equal(fixture.clock.Now()) {
		t.Fatalf("RevokeCertificate(immediate) = %#v, %v", immediate, err)
	}
	var status string
	if err := fixture.pool.QueryRow(context.Background(), `SELECT status FROM node_certificates WHERE id=$1`, immediateCertificate.certificateID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "revoked" {
		t.Fatalf("immediately revoked certificate status = %q", status)
	}
	if _, err := fixture.pool.Exec(context.Background(), `UPDATE node_certificates
		SET revoked_at=revoked_at+interval '1 second' WHERE id=$1`, immediateCertificate.certificateID); err == nil {
		t.Fatal("database allowed mutation of certificate revocation fact")
	}
	denied := fixture.lookup(t, immediateCertificate)
	if denied.ConnectionAllowed || denied.DenialReason != denialCertificateRevoked {
		t.Fatalf("immediate revocation authorization = %#v", denied)
	}
	if replay, err := fixture.store.RevokeCertificate(context.Background(), fixture.actor, immediateRequest); err != nil || !replay.Replayed {
		t.Fatalf("RevokeCertificate(immediate replay) = %#v, %v", replay, err)
	}

	legacyRevocationCertificate := fixture.seedAdoptedCertificate(t, ca, caKey, epoch, 0x43,
		fixture.clock.Now().Add(-time.Minute), "active")
	if _, err := fixture.pool.Exec(context.Background(), `INSERT INTO node_certificate_revocations(
		request_id,request_digest,certificate_id,node_id,reason,revoked_at,authorization_revision)
		VALUES($1,$2,$3,$4,'legacy revocation after binding',$5,99)`, uuid.New(), digestBytes(9),
		legacyRevocationCertificate.certificateID, legacyRevocationCertificate.nodeID, fixture.clock.Now()); err != nil {
		t.Fatal(err)
	}
	legacyDenied := fixture.lookup(t, legacyRevocationCertificate)
	if legacyDenied.ConnectionAllowed || legacyDenied.DenialReason != denialCertificateRevoked {
		t.Fatalf("bound certificate with legacy revocation authorization = %#v", legacyDenied)
	}
}

func TestLifecycleAuditFailureRollsBackCertificateRevocation(t *testing.T) {
	fixture := newLifecycleFixture(t)
	ca, caKey, epoch := fixture.rotateCA(t, 0, "rollback-ca")
	certificate := fixture.seedAdoptedCertificate(t, ca, caKey, epoch, 0x51, fixture.clock.Now().Add(-time.Minute), "active")
	var beforeRevision int64
	if err := fixture.pool.QueryRow(context.Background(), `SELECT authorization_revision FROM node_identity_state WHERE node_id=$1`,
		certificate.nodeID).Scan(&beforeRevision); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(context.Background(), `
		CREATE FUNCTION reject_lifecycle_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'injected audit failure'; END $$;
		CREATE TRIGGER reject_lifecycle_audit BEFORE INSERT ON audit_events
		FOR EACH ROW EXECUTE FUNCTION reject_lifecycle_audit()`); err != nil {
		t.Fatal(err)
	}
	request := RevokeCertificateRequest{RequestID: uuid.New(), NodeID: certificate.nodeID,
		SerialNumber: certificate.serial, LeafDERSHA256: certificate.derHash,
		Reason: "must roll back", RequestTraceID: "trace-audit-failure"}
	if _, err := fixture.store.RevokeCertificate(context.Background(), fixture.actor, request); !errors.Is(err, ErrPersistence) {
		t.Fatalf("RevokeCertificate(audit failure) error = %v", err)
	}
	var status string
	var afterRevision int64
	var revocations int
	if err := fixture.pool.QueryRow(context.Background(), `SELECT status FROM node_certificates WHERE id=$1`, certificate.certificateID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if err := fixture.pool.QueryRow(context.Background(), `SELECT authorization_revision FROM node_identity_state WHERE node_id=$1`,
		certificate.nodeID).Scan(&afterRevision); err != nil {
		t.Fatal(err)
	}
	if err := fixture.pool.QueryRow(context.Background(), `SELECT count(*) FROM node_certificate_revocations WHERE request_id=$1`,
		request.RequestID).Scan(&revocations); err != nil {
		t.Fatal(err)
	}
	if status != "active" || afterRevision != beforeRevision || revocations != 0 {
		t.Fatalf("audit failure leaked state: status=%q revision=%d->%d revocations=%d",
			status, beforeRevision, afterRevision, revocations)
	}
}

func TestLifecycleMigrationDownRejectsLiveFactsWithoutChanges(t *testing.T) {
	fixture := newLifecycleFixture036(t)
	ca, caKey, epoch := fixture.rotateCA(t, 0, "rollback-gate-ca")
	current := fixture.seedAdoptedCertificate(t, ca, caKey, epoch, 0x61,
		fixture.clock.Now().Add(-time.Minute), "active")
	renewal := fixture.seedRenewalRequest(t, current, "spiffe://cdn-platform/gateway/rollback", "gateway-rollback")
	if _, err := fixture.store.RecordGatewayMTLSProof(context.Background(), fixture.proofRequest(renewal, current, epoch)); err != nil {
		t.Fatal(err)
	}
	issued := fixture.seedIssuedRenewal(t, renewal, current, ca, caKey, 0x62)
	if _, err := fixture.store.BindIssuedRenewal(context.Background(), BindIssuedRenewalRequest{
		RenewalRequestID: renewal.requestID, NodeID: issued.nodeID, NewSerialNumber: issued.serial,
		NewLeafDERSHA256: issued.derHash, RequestTraceID: "trace-rollback-gate-bind",
	}); err != nil {
		t.Fatal(err)
	}
	for index, delay := range []time.Duration{40 * time.Second, 20 * time.Second} {
		if _, err := fixture.store.RevokeCertificate(context.Background(), fixture.actor, RevokeCertificateRequest{
			RequestID: uuid.New(), NodeID: issued.nodeID, SerialNumber: issued.serial,
			LeafDERSHA256: issued.derHash, Reason: fmt.Sprintf("rollback gate schedule %d", index),
			EffectiveAt: fixture.clock.Now().Add(delay), RequestTraceID: fmt.Sprintf("trace-rollback-gate-%d", index),
		}); err != nil {
			t.Fatal(err)
		}
	}
	var beforeRevision int64
	var beforeRevocations int
	if err := fixture.pool.QueryRow(context.Background(), `SELECT authorization_revision FROM node_identity_state
		WHERE node_id=$1`, issued.nodeID).Scan(&beforeRevision); err != nil {
		t.Fatal(err)
	}
	if err := fixture.pool.QueryRow(context.Background(), `SELECT count(*) FROM node_certificate_revocations
		WHERE certificate_id=$1`, issued.certificateID).Scan(&beforeRevocations); err != nil {
		t.Fatal(err)
	}
	if err := databasetest.MigrateThrough(context.Background(), fixture.pool, "down", lifecycleMigrationHead); err == nil {
		t.Fatal("migration 036 down accepted live lifecycle facts")
	}
	if version := migrationVersion(t, fixture.pool); version != 36 {
		t.Fatalf("migration version after rejected down = %d, want 36", version)
	}
	var afterRevision int64
	var afterRevocations int
	var oldRotation, newRotation string
	if err := fixture.pool.QueryRow(context.Background(), `SELECT authorization_revision FROM node_identity_state
		WHERE node_id=$1`, issued.nodeID).Scan(&afterRevision); err != nil {
		t.Fatal(err)
	}
	if err := fixture.pool.QueryRow(context.Background(), `SELECT count(*) FROM node_certificate_revocations
		WHERE certificate_id=$1`, issued.certificateID).Scan(&afterRevocations); err != nil {
		t.Fatal(err)
	}
	if err := fixture.pool.QueryRow(context.Background(), `SELECT rotation_status FROM node_certificates WHERE id=$1`,
		current.certificateID).Scan(&oldRotation); err != nil {
		t.Fatal(err)
	}
	if err := fixture.pool.QueryRow(context.Background(), `SELECT rotation_status FROM node_certificates WHERE id=$1`,
		issued.certificateID).Scan(&newRotation); err != nil {
		t.Fatal(err)
	}
	if beforeRevocations != 2 || afterRevocations != beforeRevocations || afterRevision != beforeRevision ||
		oldRotation != RotationOverlap || newRotation != RotationCurrent {
		t.Fatalf("rejected down changed facts: revocations=%d/%d revision=%d/%d rotation=%s/%s",
			beforeRevocations, afterRevocations, beforeRevision, afterRevision, oldRotation, newRotation)
	}
}

func TestLifecycleMigrationDownSerializesWithConcurrentLifecycleWrite(t *testing.T) {
	fixture := newLifecycleFixture036(t)
	ca, _ := testCertificateAuthority(t, fixture.clock.Now())
	caPEM := certificatePEM(ca)
	_, caDigest, publicKeyDigest, err := validateCACertificate(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := fixture.pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Rollback(context.Background()) })
	epochID := uuid.New()
	requestID := uuid.New()
	requestDigest := sha256.Sum256([]byte("concurrent-down-ca-epoch"))
	if _, err := writer.Exec(context.Background(), `INSERT INTO node_ca_key_epochs(
		id,installation_id,epoch,key_id,ca_certificate_pem,ca_certificate_sha256,public_key_sha256,
		not_before,not_after,status,request_id,request_digest,created_by_scope_id,created_by_user_id,created_at)
		VALUES($1,$2,1,'concurrent-down-ca',$3,$4,$5,$6,$7,'active',$8,$9,$10,$11,$12)`,
		epochID, fixture.installationID, caPEM, caDigest[:], publicKeyDigest[:], ca.NotBefore, ca.NotAfter,
		requestID, requestDigest[:], fixture.actor.ScopeID, fixture.actor.UserID, fixture.clock.Now()); err != nil {
		t.Fatal(err)
	}

	downResult := make(chan error, 1)
	go func() {
		downResult <- databasetest.MigrateThrough(context.Background(), fixture.pool, "down", lifecycleMigrationHead)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		select {
		case err := <-downResult:
			t.Fatalf("migration down returned before the concurrent writer committed: %v", err)
		default:
		}
		var waiting bool
		if err := fixture.pool.QueryRow(context.Background(), `SELECT EXISTS(
			SELECT 1 FROM pg_locks
			WHERE relation='node_ca_key_epochs'::regclass
			  AND mode='AccessExclusiveLock' AND NOT granted
		)`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("migration down did not wait for the lifecycle history lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := writer.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-downResult; err == nil {
		t.Fatal("migration down accepted a lifecycle fact committed while it waited for history locks")
	}
	if version := migrationVersion(t, fixture.pool); version != 36 {
		t.Fatalf("migration version after concurrent rejected down = %d, want 36", version)
	}
	var epochCount int
	if err := fixture.pool.QueryRow(context.Background(), `SELECT count(*) FROM node_ca_key_epochs WHERE id=$1`, epochID).Scan(&epochCount); err != nil {
		t.Fatal(err)
	}
	if epochCount != 1 {
		t.Fatalf("concurrent lifecycle fact count = %d, want 1", epochCount)
	}
}

type lifecycleTestClock struct {
	mu    sync.RWMutex
	value time.Time
}

func (clock *lifecycleTestClock) Now() time.Time {
	clock.mu.RLock()
	defer clock.mu.RUnlock()
	return clock.value
}

func (clock *lifecycleTestClock) Set(value time.Time) {
	clock.mu.Lock()
	clock.value = value
	clock.mu.Unlock()
}

type lifecycleFixture struct {
	pool              *pgxpool.Pool
	store             *Store
	clock             *lifecycleTestClock
	actor             Actor
	unprivilegedActor Actor
	nodeAdminActor    Actor
	installationID    string
}

type lifecycleCertificate struct {
	nodeID        uuid.UUID
	certificateID uuid.UUID
	serial        string
	derHash       [32]byte
	leaf          *x509.Certificate
}

type lifecycleRenewal struct {
	requestID uuid.UUID
	csrHash   [32]byte
	workload  string
	instance  string
}

// lifecycleNodeInsertSQL inserts a node ($1 id, $2 scope, $3 name, $4 admin
// state, $5 creator, $6 time). From migration 211 on nodes.display_id is NOT
// NULL and is allocated from the per-scope sequence, as node.Store does; the
// 036 fixture schema has no display ID yet.
func lifecycleNodeInsertSQL(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	var displayIDs bool
	if err := pool.QueryRow(context.Background(),
		`SELECT to_regclass(current_schema() || '.node_display_id_sequences') IS NOT NULL`).Scan(&displayIDs); err != nil {
		t.Fatal(err)
	}
	if !displayIDs {
		return `INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,created_at,updated_at)
			VALUES($1,$2,$3,$4,$5,$6,$6)`
	}
	return `WITH display AS (
			INSERT INTO node_display_id_sequences(scope_id,next_value,updated_at) VALUES($2,2,$6)
			ON CONFLICT(scope_id) DO UPDATE SET next_value=node_display_id_sequences.next_value+1,
				updated_at=EXCLUDED.updated_at
			RETURNING next_value-1 AS display_id
		)
		INSERT INTO nodes(id,display_id,scope_id,name,admin_state,created_by_user_id,created_at,updated_at)
		SELECT $1,display.display_id,$2,$3,$4,$5,$6,$6 FROM display`
}

func newLifecycleFixture(t *testing.T) *lifecycleFixture {
	t.Helper()
	// The store under test (and its audit log) runs against the release head.
	return newLifecycleFixtureOn(t, databasetest.MigratedPool(t, nil))
}

// newLifecycleFixture036 is newLifecycleFixture on a schema loaded through 036
// only, for the 036 down guard tests (268's down is a one-way gate).
func newLifecycleFixture036(t *testing.T) *lifecycleFixture {
	t.Helper()
	pool := openLifecycleTestDatabase(t, true)
	// The store records live 036 facts through today's audit writer (036
	// down never touches audit_events).
	databasetest.AddUnifiedAuditColumns(t, pool)
	return newLifecycleFixtureOn(t, pool)
}

func newLifecycleFixtureOn(t *testing.T, pool *pgxpool.Pool) *lifecycleFixture {
	t.Helper()
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)
	clock := &lifecycleTestClock{value: now}
	store, err := NewStore(pool, Config{Clock: clock.Now, OverlapWindow: 20 * time.Second,
		AuthorizationSnapshotTTL: 2 * time.Minute, MaxScheduledRevocation: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform"}
	unprivilegedActor := Actor{UserID: uuid.New(), ScopeID: actor.ScopeID, ScopeKind: "platform"}
	nodeAdminActor := Actor{UserID: uuid.New(), ScopeID: actor.ScopeID, ScopeKind: "platform"}
	roleID := uuid.New()
	nodeAdminRoleID := uuid.New()
	installationID := "control-lifecycle-test"
	username := "lifecycle-" + hex.EncodeToString(actor.UserID[:6])
	unprivilegedUsername := "lifecycle-" + hex.EncodeToString(unprivilegedActor.UserID[:6])
	nodeAdminUsername := "lifecycle-" + hex.EncodeToString(nodeAdminActor.UserID[:6])
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, []any{actor.ScopeID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'Lifecycle operator','test-only')`, []any{actor.UserID, username}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'Lifecycle observer','test-only')`, []any{unprivilegedActor.UserID, unprivilegedUsername}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'Lifecycle node admin','test-only')`, []any{nodeAdminActor.UserID, nodeAdminUsername}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{actor.ScopeID, actor.UserID}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{actor.ScopeID, unprivilegedActor.UserID}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{actor.ScopeID, nodeAdminActor.UserID}},
		// Platform roles as system roles: since 042 a custom role can only be
		// created through custom RBAC facts.
		{`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,'lifecycle_manager','Lifecycle test manager',true)`, []any{roleID, actor.ScopeID}},
		{`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'nodes.manage'),($1,'node_ca.manage')`, []any{roleID}},
		{`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, []any{actor.ScopeID, actor.UserID, roleID}},
		{`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,'lifecycle_node_admin','Lifecycle node admin',true)`, []any{nodeAdminRoleID, actor.ScopeID}},
		{`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'nodes.manage')`, []any{nodeAdminRoleID}},
		{`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, []any{actor.ScopeID, nodeAdminActor.UserID, nodeAdminRoleID}},
		{`INSERT INTO control_installation_entitlement(installation_id) VALUES($1)`, []any{installationID}},
	}
	for _, statement := range statements {
		if _, err := pool.Exec(context.Background(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	return &lifecycleFixture{pool: pool, store: store, clock: clock, actor: actor,
		unprivilegedActor: unprivilegedActor, nodeAdminActor: nodeAdminActor, installationID: installationID}
}

func (fixture *lifecycleFixture) rotateCA(t *testing.T, expected int64, keyID string) (*x509.Certificate, *ecdsa.PrivateKey, CAEpoch) {
	t.Helper()
	ca, key := testCertificateAuthority(t, fixture.clock.Now())
	epoch, err := fixture.store.RotateCAEpoch(context.Background(), fixture.actor, RotateCAEpochRequest{
		RequestID: uuid.New(), ExpectedCurrentEpoch: expected, KeyID: keyID,
		CACertificatePEM: certificatePEM(ca), RequestTraceID: "trace-" + keyID,
	})
	if err != nil {
		t.Fatalf("RotateCAEpoch(%s) error = %v", keyID, err)
	}
	return ca, key, epoch
}

func (fixture *lifecycleFixture) seedLegacyCertificate(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey,
	serialValue int64, renewalAt time.Time, adminState string, validity ...time.Time,
) lifecycleCertificate {
	t.Helper()
	now := fixture.clock.Now()
	nodeID := uuid.New()
	certificateID := uuid.New()
	tokenID := uuid.New()
	authorizationID := uuid.New()
	leaf := testLeafCertificate(t, ca, caKey, nodeID, big.NewInt(serialValue), now)
	if len(validity) == 2 {
		leaf = testLeafCertificateWithValidity(t, ca, caKey, nodeID, big.NewInt(serialValue), validity[0], validity[1])
	}
	leafPEM := certificatePEM(leaf)
	leafDERHash := sha256.Sum256(leaf.Raw)
	leafStoredHash := sha256.Sum256(leafPEM)
	publicKeyDER, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicKeyHash := sha256.Sum256(publicKeyDER)
	csrHash := sha256.Sum256([]byte("initial-csr-" + nodeID.String()))
	tokenHash := sha256.Sum256([]byte("token-" + tokenID.String()))
	machineHash := sha256.Sum256([]byte("machine-" + nodeID.String()))
	capabilities := []byte(`{"version":1}`)
	capabilitiesHash := sha256.Sum256(capabilities)
	artifactPublicKey := sha256.Sum256([]byte("artifact-" + nodeID.String()))
	artifactKeyID := "x25519:" + hex.EncodeToString(artifactPublicKey[:])
	leaseID := uuid.New()
	serial := leaf.SerialNumber.Text(16)
	err = pgx.BeginFunc(context.Background(), fixture.pool, func(tx pgx.Tx) error {
		statements := []struct {
			query string
			args  []any
		}{
			{lifecycleNodeInsertSQL(t, fixture.pool), []any{nodeID, fixture.actor.ScopeID, "lifecycle-node-" + serial, adminState, fixture.actor.UserID, now}},
			{`INSERT INTO node_enrollment_tokens(id,node_id,purpose,token_hash,created_by_user_id,created_at,expires_at)
			  VALUES($1,$2,'initial_enrollment',$3,$4,$5,$6)`, []any{tokenID, nodeID, tokenHash[:], fixture.actor.UserID, now.Add(-time.Hour), now.Add(time.Hour)}},
			{`INSERT INTO node_enrollment_authorizations(id,token_id,node_id,purpose,request_id,request_digest,authorized_at)
			  VALUES($1,$2,$3,'initial_enrollment',$4,$5,$6)`, []any{authorizationID, tokenID, nodeID, "enroll-" + authorizationID.String(), digestBytes(1), now.Add(-time.Minute)}},
			{`INSERT INTO node_identity_authorizations(
				id,token_id,node_id,purpose,request_id,request_digest,token_hash,csr_der,csr_sha256,
				machine_fingerprint_sha256,protocol_min_major,protocol_min_minor,protocol_max_major,
				protocol_max_minor,selected_protocol_major,selected_protocol_minor,capabilities_snapshot,
				capabilities_sha256,gateway_workload_identity,gateway_instance_id,artifact_key_id,
				artifact_public_key,status,authorized_at,expires_at)
			  VALUES($1,$2,$3,'initial_enrollment',$4,$5,$6,$7,$8,$9,1,0,1,0,1,0,$10,$11,
				'spiffe://cdn-platform/gateway/lifecycle','gateway-seed',$12,$13,'authorized',$14,$15)`, []any{
				authorizationID, tokenID, nodeID, uuid.New(), digestBytes(2), tokenHash[:], []byte("initial-csr"), csrHash[:],
				machineHash[:], capabilities, capabilitiesHash[:], artifactKeyID, artifactPublicKey[:], now.Add(-time.Minute), now.Add(time.Hour),
			}},
		}
		for _, statement := range statements {
			if _, err := tx.Exec(context.Background(), statement.query, statement.args...); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(context.Background(), `UPDATE node_identity_authorizations SET
			status='signing',signing_attempt=1,signing_lease_id=$2,signing_lease_expires_at=$3 WHERE id=$1`,
			authorizationID, leaseID, now.Add(time.Minute)); err != nil {
			return err
		}
		if _, err := tx.Exec(context.Background(), `INSERT INTO node_certificates(
			id,node_id,issuance_kind,enrollment_authorization_id,serial_number,csr_sha256,
			certificate_public_key_sha256,uri_san,not_before,not_after,renewal_at,
			leaf_certificate_pem,issuing_chain_pem,leaf_certificate_sha256,status,issued_at)
			VALUES($1,$2,'initial',$3,$4,$5,$6,$7,$8,$9,$10,$11,ARRAY[$12::bytea],$13,'active',$14)`,
			certificateID, nodeID, authorizationID, serial, csrHash[:], publicKeyHash[:],
			"spiffe://cdn-platform/node/"+nodeID.String(), leaf.NotBefore, leaf.NotAfter, renewalAt,
			leafPEM, certificatePEM(ca), leafStoredHash[:], now.Add(-time.Minute)); err != nil {
			return err
		}
		_, err := tx.Exec(context.Background(), `UPDATE node_identity_authorizations SET
			status='issued',signing_lease_id=NULL,signing_lease_expires_at=NULL,
			issued_certificate_id=$2,completed_at=$3 WHERE id=$1`, authorizationID, certificateID, now)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return lifecycleCertificate{nodeID: nodeID, certificateID: certificateID, serial: serial, derHash: leafDERHash, leaf: leaf}
}

func (fixture *lifecycleFixture) seedAdoptedCertificate(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey,
	epoch CAEpoch, serial int64, renewalAt time.Time, adminState string,
) lifecycleCertificate {
	t.Helper()
	certificate := fixture.seedLegacyCertificate(t, ca, caKey, serial, renewalAt, adminState)
	if _, err := fixture.store.AdoptCertificate(context.Background(), fixture.actor, AdoptCertificateRequest{
		RequestID: uuid.New(), NodeID: certificate.nodeID, SerialNumber: certificate.serial,
		LeafDERSHA256: certificate.derHash, CAEpochID: epoch.ID, RequestTraceID: "trace-seed-adoption",
	}); err != nil {
		t.Fatalf("AdoptCertificate(seed) error = %v", err)
	}
	return certificate
}

func (fixture *lifecycleFixture) seedRenewalRequest(t *testing.T, current lifecycleCertificate,
	workload, instance string,
) lifecycleRenewal {
	t.Helper()
	requestID := uuid.New()
	csrHash := sha256.Sum256([]byte("renewal-csr-" + requestID.String()))
	requestDigest := sha256.Sum256([]byte("renewal-request-" + requestID.String()))
	if _, err := fixture.pool.Exec(context.Background(), `INSERT INTO node_certificate_renewal_requests(
		request_id,request_digest,node_id,current_certificate_id,current_serial_number,csr_der,csr_sha256,
		gateway_workload_identity,gateway_instance_id,status,created_at,expires_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'pending',$10,$11)`, requestID, requestDigest[:], current.nodeID,
		current.certificateID, current.serial, []byte("renewal-csr"), csrHash[:], workload, instance,
		fixture.clock.Now(), fixture.clock.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	return lifecycleRenewal{requestID: requestID, csrHash: csrHash, workload: workload, instance: instance}
}

func (fixture *lifecycleFixture) proofRequest(renewal lifecycleRenewal, current lifecycleCertificate,
	epoch CAEpoch,
) RecordGatewayMTLSProofRequest {
	return RecordGatewayMTLSProofRequest{RenewalRequestID: renewal.requestID, NodeID: current.nodeID,
		CurrentSerialNumber: current.serial, CurrentLeafDERSHA256: current.derHash, TargetCAEpochID: epoch.ID,
		Principal:      GatewayMTLSPrincipal{workloadIdentity: renewal.workload, instanceID: renewal.instance},
		RequestTraceID: "trace-proof"}
}

func (fixture *lifecycleFixture) seedIssuedRenewal(t *testing.T, renewal lifecycleRenewal,
	current lifecycleCertificate, ca *x509.Certificate, caKey *ecdsa.PrivateKey, serialValue int64,
) lifecycleCertificate {
	t.Helper()
	now := fixture.clock.Now()
	certificateID := uuid.New()
	leaf := testLeafCertificate(t, ca, caKey, current.nodeID, big.NewInt(serialValue), now)
	leafPEM := certificatePEM(leaf)
	derHash := sha256.Sum256(leaf.Raw)
	storedHash := sha256.Sum256(leafPEM)
	publicKeyDER, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicKeyHash := sha256.Sum256(publicKeyDER)
	leaseID := uuid.New()
	err = pgx.BeginFunc(context.Background(), fixture.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(context.Background(), `UPDATE node_certificate_renewal_requests SET
			status='signing',signing_attempt=signing_attempt+1,signing_lease_id=$2,signing_lease_expires_at=$3
			WHERE request_id=$1`, renewal.requestID, leaseID, now.Add(time.Minute)); err != nil {
			return err
		}
		if _, err := tx.Exec(context.Background(), `INSERT INTO node_certificates(
			id,node_id,issuance_kind,renewal_request_id,replaces_certificate_id,serial_number,csr_sha256,
			certificate_public_key_sha256,uri_san,not_before,not_after,renewal_at,
			leaf_certificate_pem,issuing_chain_pem,leaf_certificate_sha256,status,issued_at)
			VALUES($1,$2,'renewal',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,ARRAY[$13::bytea],$14,'active',$15)`,
			certificateID, current.nodeID, renewal.requestID, current.certificateID, leaf.SerialNumber.Text(16),
			renewal.csrHash[:], publicKeyHash[:], "spiffe://cdn-platform/node/"+current.nodeID.String(),
			leaf.NotBefore, leaf.NotAfter, now.Add(30*time.Minute), leafPEM, certificatePEM(ca), storedHash[:], now); err != nil {
			return err
		}
		_, err := tx.Exec(context.Background(), `UPDATE node_certificate_renewal_requests SET
			status='issued',signing_lease_id=NULL,signing_lease_expires_at=NULL,
			issued_certificate_id=$2,completed_at=$3 WHERE request_id=$1`, renewal.requestID, certificateID, now)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return lifecycleCertificate{nodeID: current.nodeID, certificateID: certificateID,
		serial: leaf.SerialNumber.Text(16), derHash: derHash, leaf: leaf}
}

func (fixture *lifecycleFixture) lookup(t *testing.T, certificate lifecycleCertificate) AuthorizationSnapshot {
	t.Helper()
	snapshot, err := fixture.store.LookupAuthorization(context.Background(), LookupRequest{
		NodeID: certificate.nodeID, SerialNumber: certificate.serial, LeafDERSHA256: certificate.derHash,
	})
	if err != nil {
		t.Fatalf("LookupAuthorization(%s) error = %v", certificate.serial, err)
	}
	return snapshot
}

func digestBytes(value byte) []byte {
	return []byte(fmt.Sprintf("%032d", value))
}
