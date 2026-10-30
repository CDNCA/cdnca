//go:build integration

package nodeidentity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/node"
	certlifecycle "github.com/cdnca/cdnca/services/control-api/internal/nodecertlifecycle"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestNodeIdentityLifecycle(t *testing.T) {
	pool := openIdentityTestDatabase(t, true)
	now := time.Date(2026, 7, 22, 8, 0, 0, 0, time.UTC)
	clock := &identityTestClock{value: now}
	signer := newIdentityTestCA(t, now)
	service := newIdentityTestService(t, pool, signer, clock)
	fixture := seedIdentityNode(t, pool, now, "pending", "initial_enrollment")

	request := validAuthorizeRequest(t, testCSR(t, false))
	request.EnrollmentToken = fixture.token
	request.PeerIP = ""
	authorization, err := service.Authorize(context.Background(), request)
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if authorization.NodeID != fixture.nodeID || authorization.Replayed || len(authorization.ArtifactEncryptionKeyID) != 71 {
		t.Fatalf("Authorize() = %#v", authorization)
	}
	replayed, err := service.Authorize(context.Background(), request)
	if err != nil || !replayed.Replayed || replayed.ID != authorization.ID {
		t.Fatalf("Authorize(replay) = %#v, %v", replayed, err)
	}
	conflict := cloneAuthorizeRequest(request)
	conflict.MachineFingerprintSHA256[0] = 1
	if _, err := service.Authorize(context.Background(), conflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("Authorize(conflict) error = %v", err)
	}
	consumed := cloneAuthorizeRequest(request)
	consumed.RequestID = uuid.NewString()
	if _, err := service.Authorize(context.Background(), consumed); !errors.Is(err, ErrTokenConsumed) {
		t.Fatalf("Authorize(consumed token) error = %v", err)
	}

	complete := CompleteRequest{RequestID: uuid.NewString(), AuthorizationID: authorization.ID,
		GatewayWorkloadIdentity: request.GatewayWorkloadIdentity, GatewayInstanceID: request.GatewayInstanceID}
	wrongGateway := complete
	wrongGateway.GatewayInstanceID = "gateway-other"
	if _, err := service.Complete(context.Background(), wrongGateway); !errors.Is(err, ErrGatewayBinding) {
		t.Fatalf("Complete(wrong Gateway) error = %v", err)
	}
	completion, err := service.Complete(context.Background(), complete)
	if err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
	certificate := completion.Certificate
	certificateSHA256 := certificateDERDigest(t, certificate)
	if completion.ArtifactEncryptionKeyID != authorization.ArtifactEncryptionKeyID || completion.ArtifactEncryptionKeyID == "" {
		t.Fatalf("Complete() artifact key ID = %q", completion.ArtifactEncryptionKeyID)
	}
	assertPublicCertificate(t, certificate, fixture.nodeID, signer.root)
	assertInitialLifecycleFact(t, pool, fixture, authorization, complete, certificate, signer)
	assertEnrollmentAudit(t, pool, fixture, authorization, complete, certificate)
	replayedCompletion, err := service.Complete(context.Background(), complete)
	if err != nil || replayedCompletion.Certificate.ID != certificate.ID ||
		replayedCompletion.ArtifactEncryptionKeyID != completion.ArtifactEncryptionKeyID {
		t.Fatalf("Complete(replay) = %#v, %v", replayedCompletion, err)
	}
	assertPublicCertificate(t, replayedCompletion.Certificate, fixture.nodeID, signer.root)
	assertEnrollmentAudit(t, pool, fixture, authorization, complete, certificate)
	conflictingComplete := complete
	conflictingComplete.RequestID = uuid.NewString()
	if _, err := service.Complete(context.Background(), conflictingComplete); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("Complete(conflicting request ID) error = %v", err)
	}
	telemetrySiteID := uuid.New()
	liveOnlySiteID := uuid.New()
	if _, err := pool.Exec(context.Background(), `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)
		ON CONFLICT (scope_id,user_id) DO NOTHING`, fixture.scopeID, fixture.userID); err != nil {
		t.Fatal(err)
	}
	telemetrySiteTx, err := pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer telemetrySiteTx.Rollback(context.Background())
	if _, err := telemetrySiteTx.Exec(context.Background(), `INSERT INTO sites
		(id,scope_id,display_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,updated_by_user_id)
		VALUES($1,$2,1,$3,$4,ARRAY['192.0.2.10:80'],ARRAY['192.0.2.10'],$3,$3)`,
		telemetrySiteID, fixture.scopeID, fixture.userID, "telemetry-"+telemetrySiteID.String()[:8]+".example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := telemetrySiteTx.Exec(context.Background(), `INSERT INTO site_origin_pools(site_id) VALUES($1)`, telemetrySiteID); err != nil {
		t.Fatal(err)
	}
	if _, err := telemetrySiteTx.Exec(context.Background(), `INSERT INTO site_origins(site_id,position,host,port,weight,enabled)
		VALUES($1,1,'192.0.2.10',80,1,true)`, telemetrySiteID); err != nil {
		t.Fatal(err)
	}
	if _, err := telemetrySiteTx.Exec(context.Background(), `INSERT INTO sites
		(id,scope_id,display_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,updated_by_user_id)
		VALUES($1,$2,2,$3,$4,ARRAY['192.0.2.11:80'],ARRAY['192.0.2.11'],$3,$3)`,
		liveOnlySiteID, fixture.scopeID, fixture.userID, "live-only-"+liveOnlySiteID.String()[:8]+".example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := telemetrySiteTx.Exec(context.Background(), `INSERT INTO site_origin_pools(site_id) VALUES($1)`, liveOnlySiteID); err != nil {
		t.Fatal(err)
	}
	if _, err := telemetrySiteTx.Exec(context.Background(), `INSERT INTO site_origins(site_id,position,host,port,weight,enabled)
		VALUES($1,1,'192.0.2.11',80,1,true)`, liveOnlySiteID); err != nil {
		t.Fatal(err)
	}
	if err := telemetrySiteTx.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	configVersionID := seedTelemetryCurrentConfig(t, pool, fixture, telemetrySiteID, now.Add(-100*24*time.Hour))

	snapshot, err := service.GetAuthorization(context.Background(), GetAuthorizationRequest{NodeID: fixture.nodeID,
		CertificateSerialNumber: certificate.SerialNumber, CertificateSHA256: certificateSHA256,
		GatewayWorkloadIdentity: request.GatewayWorkloadIdentity,
		GatewayInstanceID:       "gateway-takeover"})
	if err != nil || !snapshot.ConnectionAllowed || !snapshot.DeploymentsAllowed || snapshot.AdministrativeState != "active" ||
		snapshot.ArtifactEncryptionKeyID != authorization.ArtifactEncryptionKeyID ||
		snapshot.InstallationID != "node-identity-test" || snapshot.TenantID != fixture.tenantID ||
		len(snapshot.TelemetrySites) != 1 || snapshot.TelemetrySites[0] != (TelemetrySiteScope{
		SiteID: telemetrySiteID, TenantID: fixture.tenantID, ConfigurationScopeID: fixture.scopeID, ConfigVersionID: configVersionID,
	}) {
		t.Fatalf("GetAuthorization(takeover replica) = %#v, %v", snapshot, err)
	}
	singleByteMismatch := certificateSHA256
	singleByteMismatch[0] ^= 0xff
	wrongCertificateSHA256 := sameSerialWrongCertificateDigest(t, signer, certificate, fixture.nodeID)
	for _, test := range []struct {
		name   string
		digest [32]byte
	}{
		{name: "single byte mismatch", digest: singleByteMismatch},
		{name: "same serial wrong certificate", digest: wrongCertificateSHA256},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := service.GetAuthorization(context.Background(), GetAuthorizationRequest{NodeID: fixture.nodeID,
				CertificateSerialNumber: certificate.SerialNumber, CertificateSHA256: test.digest,
				GatewayWorkloadIdentity: request.GatewayWorkloadIdentity, GatewayInstanceID: "gateway-takeover"})
			if !errors.Is(err, ErrCertificateNotFound) {
				t.Fatalf("GetAuthorization(%s) error = %v, want ErrCertificateNotFound", test.name, err)
			}
		})
	}
	if _, err := service.GetAuthorization(context.Background(), GetAuthorizationRequest{NodeID: fixture.nodeID,
		CertificateSerialNumber: certificate.SerialNumber, CertificateSHA256: certificateSHA256,
		GatewayWorkloadIdentity: "spiffe://cdn-platform/gateway/other-workload",
		GatewayInstanceID:       "gateway-takeover"}); !errors.Is(err, ErrCertificateNotFound) {
		t.Fatalf("GetAuthorization(wrong workload) error = %v", err)
	}

	historicalSiteID, expiredSiteID, rollbackSiteID, reconciliationSiteID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	historicalConfigID := seedTelemetryConfig(t, pool, fixture, historicalSiteID, now.Add(-40*24*time.Hour))
	seedTelemetryDeploymentFact(t, pool, fixture, historicalConfigID, configVersionID, "apply", "healthy", "healthy", now.Add(-30*24*time.Hour))
	expiredConfigID := seedTelemetryConfig(t, pool, fixture, expiredSiteID, now.Add(-120*24*time.Hour))
	seedTelemetryDeploymentFact(t, pool, fixture, expiredConfigID, configVersionID, "apply", "healthy", "healthy", now.Add(-91*24*time.Hour))
	rollbackConfigID := seedTelemetryConfig(t, pool, fixture, rollbackSiteID, now.Add(-35*24*time.Hour))
	seedTelemetryDeploymentFact(t, pool, fixture, rollbackConfigID, configVersionID, "rollback", "reverted", "reverted", now.Add(-20*24*time.Hour))
	reconciliationConfigID := seedTelemetryConfig(t, pool, fixture, reconciliationSiteID, now.Add(-25*24*time.Hour))

	releasedOnlyConfigID := seedTelemetryConfig(t, pool, fixture, uuid.New(), now.Add(-10*24*time.Hour))
	failedConfigID := seedTelemetryConfig(t, pool, fixture, uuid.New(), now.Add(-10*24*time.Hour))
	seedTelemetryDeploymentFact(t, pool, fixture, failedConfigID, configVersionID, "apply", "failed", "", now.Add(-9*24*time.Hour))
	rollbackFailedConfigID := seedTelemetryConfig(t, pool, fixture, uuid.New(), now.Add(-10*24*time.Hour))
	rollbackFailedDeploymentID := seedTelemetryDeploymentFact(t, pool, fixture, rollbackFailedConfigID, configVersionID,
		"rollback", "rollback_failed", "", now.Add(-8*24*time.Hour))
	cancelledConfigID := seedTelemetryConfig(t, pool, fixture, uuid.New(), now.Add(-10*24*time.Hour))
	seedTelemetryDeploymentFact(t, pool, fixture, cancelledConfigID, configVersionID, "apply", "cancelled", "", now.Add(-7*24*time.Hour))
	activatedConfigID := seedTelemetryConfig(t, pool, fixture, uuid.New(), now.Add(-10*24*time.Hour))
	seedTelemetryDeploymentFact(t, pool, fixture, activatedConfigID, configVersionID, "apply", "activated", "activated", now.Add(-6*24*time.Hour))
	seedTelemetryReconciliationFact(t, pool, fixture, rollbackFailedDeploymentID, configVersionID, reconciliationConfigID, now.Add(-5*24*time.Hour))

	historySnapshot, err := service.GetAuthorization(context.Background(), GetAuthorizationRequest{NodeID: fixture.nodeID,
		CertificateSerialNumber: certificate.SerialNumber, CertificateSHA256: certificateSHA256,
		GatewayWorkloadIdentity: request.GatewayWorkloadIdentity,
		GatewayInstanceID:       "gateway-takeover"})
	if err != nil {
		t.Fatalf("GetAuthorization(history) error = %v", err)
	}
	assertTelemetryBindings(t, historySnapshot.TelemetrySites, map[TelemetrySiteScope]struct{}{
		{SiteID: telemetrySiteID, TenantID: fixture.tenantID, ConfigurationScopeID: fixture.scopeID, ConfigVersionID: configVersionID}:             {},
		{SiteID: historicalSiteID, TenantID: fixture.tenantID, ConfigurationScopeID: fixture.scopeID, ConfigVersionID: historicalConfigID}:         {},
		{SiteID: rollbackSiteID, TenantID: fixture.tenantID, ConfigurationScopeID: fixture.scopeID, ConfigVersionID: rollbackConfigID}:             {},
		{SiteID: reconciliationSiteID, TenantID: fixture.tenantID, ConfigurationScopeID: fixture.scopeID, ConfigVersionID: reconciliationConfigID}: {},
	})
	for _, rejected := range []uuid.UUID{expiredConfigID, releasedOnlyConfigID, failedConfigID, rollbackFailedConfigID,
		cancelledConfigID, activatedConfigID} {
		for _, binding := range historySnapshot.TelemetrySites {
			if binding.ConfigVersionID == rejected {
				t.Fatalf("unproven config %s entered telemetry authorization", rejected)
			}
		}
	}
	crossFixture := seedIdentityNode(t, pool, now, "active", "initial_enrollment")
	if _, err := pool.Exec(context.Background(), `UPDATE node_config_state
		SET configuration_scope_id=$2,current_config_version_id=NULL,previous_config_version_id=NULL WHERE node_id=$1`,
		fixture.nodeID, crossFixture.scopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.GetAuthorization(context.Background(), GetAuthorizationRequest{NodeID: fixture.nodeID,
		CertificateSerialNumber: certificate.SerialNumber, CertificateSHA256: certificateSHA256,
		GatewayWorkloadIdentity: request.GatewayWorkloadIdentity,
		GatewayInstanceID:       "gateway-takeover"}); !errors.Is(err, ErrPersistence) {
		t.Fatalf("GetAuthorization(cross-scope config state) error = %v", err)
	}
	if _, err := pool.Exec(context.Background(), `UPDATE node_config_state
		SET configuration_scope_id=$2,current_config_version_id=$3 WHERE node_id=$1`, fixture.nodeID, fixture.scopeID, configVersionID); err != nil {
		t.Fatal(err)
	}
	crossCSR := testCSR(t, false)
	crossCSRHash := sha256.Sum256(crossCSR)
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO node_certificate_renewal_requests (
			request_id,request_digest,node_id,current_certificate_id,current_serial_number,csr_der,csr_sha256,
			gateway_workload_identity,gateway_instance_id,status,created_at,expires_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'pending',$10,$11)`, uuid.New(), bytesOf(32, 1),
		crossFixture.nodeID, certificate.ID, certificate.SerialNumber, crossCSR, crossCSRHash[:],
		request.GatewayWorkloadIdentity, "gateway-cross-node", now, now.Add(time.Minute)); err == nil {
		t.Fatal("database accepted cross-node certificate renewal binding")
	}

	renewRequest := RenewRequest{RequestID: uuid.NewString(), NodeID: fixture.nodeID,
		CurrentSerialNumber: certificate.SerialNumber, CurrentCertificateSHA256: certificateSHA256,
		CertificateSigningRequestDER: testCSR(t, false),
		GatewayWorkloadIdentity:      request.GatewayWorkloadIdentity, GatewayInstanceID: "gateway-takeover"}
	wrongNodeRenewal := renewRequest
	wrongNodeRenewal.RequestID = uuid.NewString()
	wrongNodeRenewal.NodeID = crossFixture.nodeID
	if _, err := service.Renew(context.Background(), wrongNodeRenewal); !errors.Is(err, ErrCertificateNotFound) {
		t.Fatalf("Renew(wrong node) error = %v", err)
	}
	if _, err := service.Renew(context.Background(), renewRequest); !errors.Is(err, ErrRenewalTooEarly) {
		t.Fatalf("Renew(before renewal window) error = %v", err)
	}
	var renewalCount int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM node_certificate_renewal_requests
		WHERE node_id=$1`, fixture.nodeID).Scan(&renewalCount); err != nil || renewalCount != 0 {
		t.Fatalf("unproven Renew persisted %d requests: %v", renewalCount, err)
	}

	secondToken := issueIdentityToken(t, pool, fixture, now, "re_enrollment")
	secondRequest := validAuthorizeRequest(t, testCSR(t, false))
	secondRequest.EnrollmentToken = secondToken
	secondRequest.ArtifactEncryptionPublicKey = bytesOf(32, 9)
	secondAuthorization, err := service.Authorize(context.Background(), secondRequest)
	if err != nil {
		t.Fatalf("Authorize(re-enrollment) error = %v", err)
	}
	secondComplete := CompleteRequest{RequestID: uuid.NewString(), AuthorizationID: secondAuthorization.ID,
		GatewayWorkloadIdentity: secondRequest.GatewayWorkloadIdentity, GatewayInstanceID: secondRequest.GatewayInstanceID}
	signer.mu.Lock()
	serialBeforeRejectedEnrollment := signer.serial
	signer.mu.Unlock()
	if _, err := service.Complete(context.Background(), secondComplete); !errors.Is(err, ErrCertificateInvalid) {
		t.Fatalf("Complete(re-enrollment with current certificate) error = %v", err)
	}
	signer.mu.Lock()
	serialAfterRejectedEnrollment := signer.serial
	signer.mu.Unlock()
	if serialAfterRejectedEnrollment != serialBeforeRejectedEnrollment {
		t.Fatal("re-enrollment with an existing current certificate reached the signer")
	}
	var oldStatus, newStatus string
	if err := pool.QueryRow(context.Background(), `SELECT status FROM node_artifact_encryption_keys WHERE id=$1`, authorization.ArtifactEncryptionKeyID).Scan(&oldStatus); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT status FROM node_artifact_encryption_keys WHERE id=$1`, secondAuthorization.ArtifactEncryptionKeyID).Scan(&newStatus); err != nil {
		t.Fatal(err)
	}
	if oldStatus != "active" || newStatus != "pending" {
		t.Fatalf("artifact key states = %q/%q", oldStatus, newStatus)
	}
	secondCertificate := certificate

	beforeRevoke, err := service.GetAuthorization(context.Background(), GetAuthorizationRequest{NodeID: fixture.nodeID,
		CertificateSerialNumber: secondCertificate.SerialNumber, CertificateSHA256: certificateSHA256,
		GatewayWorkloadIdentity: request.GatewayWorkloadIdentity,
		GatewayInstanceID:       "gateway-takeover"})
	if err != nil {
		t.Fatal(err)
	}
	revoke := RevokeRequest{RequestID: uuid.NewString(), NodeID: fixture.nodeID, SerialNumber: secondCertificate.SerialNumber, Reason: "operator rotation"}
	if err := service.Revoke(context.Background(), revoke); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if err := service.Revoke(context.Background(), revoke); err != nil {
		t.Fatalf("Revoke(replay) error = %v", err)
	}
	afterRevoke, err := service.GetAuthorization(context.Background(), GetAuthorizationRequest{NodeID: fixture.nodeID,
		CertificateSerialNumber: secondCertificate.SerialNumber, CertificateSHA256: certificateSHA256,
		GatewayWorkloadIdentity: request.GatewayWorkloadIdentity,
		GatewayInstanceID:       "gateway-takeover"})
	if err != nil || !afterRevoke.CertificateRevoked || afterRevoke.ConnectionAllowed || afterRevoke.AuthorizationRevision <= beforeRevoke.AuthorizationRevision {
		t.Fatalf("authorization after revoke = %#v, %v", afterRevoke, err)
	}
	var identityUpdatedBefore time.Time
	if err := pool.QueryRow(context.Background(), `SELECT updated_at FROM node_identity_state WHERE node_id=$1`, fixture.nodeID).Scan(&identityUpdatedBefore); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `UPDATE nodes SET admin_state='disabled',revision=revision+1,updated_at=$2 WHERE id=$1`, fixture.nodeID, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	var identityUpdatedAfter time.Time
	if err := pool.QueryRow(context.Background(), `SELECT updated_at FROM node_identity_state WHERE node_id=$1`, fixture.nodeID).Scan(&identityUpdatedAfter); err != nil {
		t.Fatal(err)
	}
	if identityUpdatedAfter.Before(identityUpdatedBefore) {
		t.Fatalf("identity updated_at regressed from %s to %s", identityUpdatedBefore, identityUpdatedAfter)
	}
	afterDisable, err := service.GetAuthorization(context.Background(), GetAuthorizationRequest{NodeID: fixture.nodeID,
		CertificateSerialNumber: certificate.SerialNumber, CertificateSHA256: certificateSHA256,
		GatewayWorkloadIdentity: request.GatewayWorkloadIdentity,
		GatewayInstanceID:       "gateway-takeover"})
	if err != nil || afterDisable.AdministrativeState != "disabled" || afterDisable.AuthorizationRevision <= afterRevoke.AuthorizationRevision || afterDisable.ConnectionAllowed {
		t.Fatalf("authorization after disable = %#v, %v", afterDisable, err)
	}
	remainingBindings := MaxTelemetrySiteScopes + 1 - len(afterDisable.TelemetrySites)
	for remainingBindings > 0 {
		batchSize := min(remainingBindings, 1000)
		siteIDs := make([]uuid.UUID, batchSize)
		for index := range siteIDs {
			siteIDs[index] = uuid.New()
		}
		bulkConfigID := seedTelemetryConfigWithSites(t, pool, fixture, siteIDs, now.Add(-24*time.Hour))
		seedTelemetryDeploymentFact(t, pool, fixture, bulkConfigID, configVersionID, "apply", "healthy", "healthy", now.Add(-time.Hour))
		remainingBindings -= batchSize
	}
	if _, err := service.GetAuthorization(context.Background(), GetAuthorizationRequest{NodeID: fixture.nodeID,
		CertificateSerialNumber: certificate.SerialNumber, CertificateSHA256: certificateSHA256,
		GatewayWorkloadIdentity: request.GatewayWorkloadIdentity,
		GatewayInstanceID:       "gateway-takeover"}); !errors.Is(err, ErrPersistence) {
		t.Fatalf("GetAuthorization(limit+1 telemetry tuples) error = %v", err)
	}

	var privateMaterialRows int
	if err := pool.QueryRow(context.Background(), `
		SELECT count(*) FROM information_schema.columns
		WHERE table_schema=current_schema() AND table_name LIKE 'node_%' AND column_name LIKE '%private%'`).Scan(&privateMaterialRows); err != nil {
		t.Fatal(err)
	}
	if privateMaterialRows != 0 {
		t.Fatalf("node identity schema has %d private-material columns", privateMaterialRows)
	}
	if _, err := pool.Exec(context.Background(), `DELETE FROM node_certificates WHERE id=$1`, certificate.ID); err == nil {
		t.Fatal("database allowed deletion of immutable certificate fact")
	}
	if _, err := pool.Exec(context.Background(), `UPDATE node_identity_authorizations SET csr_sha256=$2 WHERE id=$1`, authorization.ID, bytesOf(32, 4)); err == nil {
		t.Fatal("database allowed mutation of immutable authorization content")
	}
}

func seedTelemetryCurrentConfig(
	t *testing.T,
	pool *pgxpool.Pool,
	fixture identityFixture,
	siteID uuid.UUID,
	publishedAt time.Time,
) uuid.UUID {
	t.Helper()
	configVersionID := seedTelemetryConfig(t, pool, fixture, siteID, publishedAt)
	if _, err := pool.Exec(context.Background(), `INSERT INTO node_config_state
		(node_id,configuration_scope_id,current_config_version_id,revision,updated_at)
		VALUES($1,$2,$3,1,$4)`, fixture.nodeID, fixture.scopeID, configVersionID, publishedAt); err != nil {
		t.Fatal(err)
	}
	return configVersionID
}

func seedTelemetryConfig(
	t *testing.T,
	pool *pgxpool.Pool,
	fixture identityFixture,
	siteID uuid.UUID,
	publishedAt time.Time,
) uuid.UUID {
	t.Helper()
	return seedTelemetryConfigWithSites(t, pool, fixture, []uuid.UUID{siteID}, publishedAt)
}

func seedTelemetryConfigWithSites(
	t *testing.T,
	pool *pgxpool.Pool,
	fixture identityFixture,
	siteIDs []uuid.UUID,
	publishedAt time.Time,
) uuid.UUID {
	t.Helper()
	configVersionID := uuid.New()
	snapshot := telemetryV2SnapshotForTest(t, fixture.scopeID, configVersionID, siteIDs)
	digest := sha256.Sum256(snapshot)
	if _, err := parseTelemetryCanonicalSnapshot(snapshot, digest[:], fixture.scopeID, fixture.tenantID, configVersionID); err != nil {
		t.Fatalf("telemetry canonical snapshot fixture: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO config_versions
		(id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,generator_name,generator_version,
		 status,idempotency_key,request_digest,created_at,published_at)
		VALUES($1,$2,$3,$4,'telemetry-test','1','releasable',$5,$6,$7,$7)`,
		configVersionID, fixture.scopeID, snapshot, digest[:], "telemetry-"+configVersionID.String(), bytesOf(32, 3), publishedAt); err != nil {
		t.Fatal(err)
	}
	return configVersionID
}

func seedTelemetryDeploymentFact(
	t *testing.T,
	pool *pgxpool.Pool,
	fixture identityFixture,
	configVersionID, previousConfigVersionID uuid.UUID,
	action, state, eventState string,
	occurredAt time.Time,
) uuid.UUID {
	t.Helper()
	rolloutID, deploymentID := uuid.New(), uuid.New()
	requestDigest := sha256.Sum256([]byte("telemetry-rollout-" + rolloutID.String()))
	command := []byte("telemetry-command-" + deploymentID.String())
	commandDigest := sha256.Sum256(command)
	createdAt, deadline := occurredAt.Add(-time.Minute), occurredAt.Add(time.Hour)
	if _, err := pool.Exec(context.Background(), `INSERT INTO rollouts (
		id,configuration_scope_id,config_version_id,action,status,idempotency_key,request_digest,
		request_id,correlation_id,activation_timeout_ms,observation_window_ms,required_consecutive_successes,
		deadline_at,created_at,queued_at,updated_at,contract_version)
		VALUES($1,$2,$3,$4,'queued',$5,$6,$7,$8,60000,60000,1,$9,$10,$10,$10,0)`,
		rolloutID, fixture.scopeID, configVersionID, action, "telemetry-"+rolloutID.String(), requestDigest[:],
		uuid.New(), uuid.New(), deadline, createdAt); err != nil {
		t.Fatal(err)
	}
	var previous *uuid.UUID
	if action == "rollback" {
		previous = &previousConfigVersionID
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO node_deployments (
		id,rollout_id,node_id,attempt,config_version_id,previous_config_version_id,action,state,
		command_event_id,command_bytes,command_sha256,deadline_at,created_at,updated_at)
		VALUES($1,$2,$3,1,$4,$5,$6,$7,$8,$9,$10,$11,$12,$12)`,
		deploymentID, rolloutID, fixture.nodeID, configVersionID, previous, action, state, uuid.New(), command,
		commandDigest[:], deadline, createdAt); err != nil {
		t.Fatal(err)
	}
	if eventState != "" {
		payload := []byte("telemetry-event-" + deploymentID.String() + "-" + eventState)
		payloadDigest := sha256.Sum256(payload)
		if _, err := pool.Exec(context.Background(), `INSERT INTO deployment_status_events (
			id,deployment_id,event_id,attempt,transition_sequence,state,payload,payload_sha256,occurred_at,received_at)
			VALUES($1,$2,$3,1,1,$4,$5,$6,$7,$7)`, uuid.New(), deploymentID, uuid.New(), eventState,
			payload, payloadDigest[:], occurredAt); err != nil {
			t.Fatal(err)
		}
	}
	return deploymentID
}

func seedTelemetryReconciliationFact(
	t *testing.T,
	pool *pgxpool.Pool,
	fixture identityFixture,
	sourceDeploymentID, previousConfigVersionID, observedConfigVersionID uuid.UUID,
	reconciledAt time.Time,
) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `INSERT INTO node_config_reconciliations (
		id,request_id,request_digest,node_id,configuration_scope_id,source_deployment_id,
		source_deployment_attempt,previous_config_version_id,observed_config_version_id,resolution,evidence,reconciled_at)
		VALUES($1,$2,$3,$4,$5,$6,1,$7,$8,'operator_confirmed','telemetry authority test',$9)`,
		uuid.New(), uuid.New(), bytesOf(32, 7), fixture.nodeID, fixture.scopeID, sourceDeploymentID,
		previousConfigVersionID, observedConfigVersionID, reconciledAt); err != nil {
		t.Fatal(err)
	}
}

func assertTelemetryBindings(t *testing.T, got []TelemetrySiteScope, want map[TelemetrySiteScope]struct{}) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("telemetry bindings count = %d, want %d: %#v", len(got), len(want), got)
	}
	for _, binding := range got {
		if _, exists := want[binding]; !exists {
			t.Fatalf("unexpected telemetry binding: %#v", binding)
		}
		delete(want, binding)
	}
	if len(want) != 0 {
		t.Fatalf("missing telemetry bindings: %#v", want)
	}
}

func TestTelemetryCanonicalSnapshotAuthorityValidation(t *testing.T) {
	scopeID, tenantID, configVersionID, siteID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	valid := telemetryV2SnapshotForTest(t, scopeID, configVersionID, []uuid.UUID{siteID})
	validDigest := sha256.Sum256(valid)
	bindings, err := parseTelemetryCanonicalSnapshot(valid, validDigest[:], scopeID, tenantID, configVersionID)
	if err != nil || len(bindings) != 1 || bindings[0] != (TelemetrySiteScope{
		SiteID: siteID, TenantID: tenantID, ConfigurationScopeID: scopeID, ConfigVersionID: configVersionID,
	}) {
		t.Fatalf("valid canonical snapshot = %#v, %v", bindings, err)
	}
	duplicate := telemetryV2SnapshotForTest(t, scopeID, configVersionID, []uuid.UUID{siteID, siteID})
	tests := []struct {
		name             string
		raw              []byte
		storedDigest     []byte
		authorityScopeID uuid.UUID
		authorityTenant  uuid.UUID
		authorityConfig  uuid.UUID
	}{
		{name: "hash mismatch", raw: valid, storedDigest: bytesOf(32, 9), authorityScopeID: scopeID, authorityTenant: tenantID, authorityConfig: configVersionID},
		{name: "malformed JSON", raw: []byte(`{"schema":`), authorityScopeID: scopeID, authorityTenant: tenantID, authorityConfig: configVersionID},
		{name: "config-source v1 snapshot", raw: []byte(`{"schema":"cdnca.edge.config-source/v1","sites":[]}`), authorityScopeID: scopeID, authorityTenant: tenantID, authorityConfig: configVersionID},
		{name: "snapshot scope conflict", raw: telemetryV2SnapshotForTest(t, uuid.New(), configVersionID, []uuid.UUID{siteID}),
			authorityScopeID: scopeID, authorityTenant: tenantID, authorityConfig: configVersionID},
		{name: "snapshot config conflict", raw: telemetryV2SnapshotForTest(t, scopeID, uuid.New(), []uuid.UUID{siteID}),
			authorityScopeID: scopeID, authorityTenant: tenantID, authorityConfig: configVersionID},
		{name: "duplicate site tuple", raw: duplicate, authorityScopeID: scopeID, authorityTenant: tenantID, authorityConfig: configVersionID},
		{name: "missing tenant authority", raw: valid, authorityScopeID: scopeID, authorityConfig: configVersionID},
		{name: "missing config authority", raw: valid, authorityScopeID: scopeID, authorityTenant: tenantID},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			storedDigest := test.storedDigest
			if storedDigest == nil {
				digest := sha256.Sum256(test.raw)
				storedDigest = digest[:]
			}
			if _, err := parseTelemetryCanonicalSnapshot(test.raw, storedDigest, test.authorityScopeID,
				test.authorityTenant, test.authorityConfig); !errors.Is(err, ErrPersistence) {
				t.Fatalf("parseTelemetryCanonicalSnapshot() error = %v", err)
			}
		})
	}
}

func TestNodeIdentityConcurrentReplayAndIssuance(t *testing.T) {
	pool := openIdentityTestDatabase(t, true)
	now := time.Date(2026, 7, 22, 9, 0, 0, 0, time.UTC)
	clock := &identityTestClock{value: now}
	signer := newIdentityTestCA(t, now)
	service := newIdentityTestService(t, pool, signer, clock)
	fixture := seedIdentityNode(t, pool, now, "pending", "initial_enrollment")
	request := validAuthorizeRequest(t, testCSR(t, false))
	request.EnrollmentToken = fixture.token

	start := make(chan struct{})
	type authorizeResult struct {
		value Authorization
		err   error
	}
	results := make(chan authorizeResult, 2)
	for range 2 {
		go func() {
			<-start
			value, err := service.Authorize(context.Background(), request)
			results <- authorizeResult{value, err}
		}()
	}
	close(start)
	first, second := <-results, <-results
	if first.err != nil || second.err != nil || first.value.ID != second.value.ID || first.value.Replayed == second.value.Replayed {
		t.Fatalf("concurrent Authorize = (%#v,%v) (%#v,%v)", first.value, first.err, second.value, second.err)
	}

	signingStarted, releaseSigner := signer.blockOnce()
	completeResult := make(chan struct {
		completion EnrollmentCompletion
		err        error
	}, 1)
	complete := CompleteRequest{RequestID: uuid.NewString(), AuthorizationID: first.value.ID,
		GatewayWorkloadIdentity: request.GatewayWorkloadIdentity, GatewayInstanceID: request.GatewayInstanceID}
	go func() {
		value, err := service.Complete(context.Background(), complete)
		completeResult <- struct {
			completion EnrollmentCompletion
			err        error
		}{value, err}
	}()
	<-signingStarted
	if _, err := service.Complete(context.Background(), complete); !errors.Is(err, ErrIssuanceInProgress) {
		t.Fatalf("concurrent Complete() error = %v", err)
	}
	close(releaseSigner)
	completed := <-completeResult
	if completed.err != nil {
		t.Fatalf("first Complete() error = %v", completed.err)
	}

	renew := RenewRequest{RequestID: uuid.NewString(), NodeID: fixture.nodeID, CurrentSerialNumber: completed.completion.Certificate.SerialNumber,
		CurrentCertificateSHA256:     certificateDERDigest(t, completed.completion.Certificate),
		CertificateSigningRequestDER: testCSR(t, false), GatewayWorkloadIdentity: request.GatewayWorkloadIdentity,
		GatewayInstanceID: "gateway-02"}
	if _, err := service.Renew(context.Background(), renew); !errors.Is(err, ErrRenewalTooEarly) {
		t.Fatalf("Renew(before renewal window) error = %v", err)
	}

	revoke := RevokeRequest{RequestID: uuid.NewString(), NodeID: fixture.nodeID,
		SerialNumber: completed.completion.Certificate.SerialNumber, Reason: "concurrent revocation"}
	revokeStart := make(chan struct{})
	revokeResults := make(chan error, 2)
	for range 2 {
		go func() { <-revokeStart; revokeResults <- service.Revoke(context.Background(), revoke) }()
	}
	close(revokeStart)
	if firstErr, secondErr := <-revokeResults, <-revokeResults; firstErr != nil || secondErr != nil {
		t.Fatalf("concurrent Revoke() errors = %v / %v", firstErr, secondErr)
	}
}

func TestNodeIdentityReplayPreflightDoesNotDependOnIDGenerator(t *testing.T) {
	pool := openIdentityTestDatabase(t, true)
	now := time.Date(2026, 7, 22, 9, 30, 0, 0, time.UTC)
	clock := &identityTestClock{value: now}
	signer := newIdentityTestCA(t, now)
	service := newIdentityTestService(t, pool, signer, clock)

	fixture := seedIdentityNode(t, pool, now, "pending", "initial_enrollment")
	authorize := validAuthorizeRequest(t, testCSR(t, false))
	authorize.EnrollmentToken = fixture.token
	authorization, err := service.Authorize(context.Background(), authorize)
	if err != nil {
		t.Fatal(err)
	}
	completeRequest := CompleteRequest{RequestID: uuid.NewString(), AuthorizationID: authorization.ID,
		GatewayWorkloadIdentity: authorize.GatewayWorkloadIdentity, GatewayInstanceID: authorize.GatewayInstanceID}
	completion, err := service.Complete(context.Background(), completeRequest)
	if err != nil {
		t.Fatal(err)
	}

	incompleteFixture := seedIdentityNode(t, pool, now, "pending", "initial_enrollment")
	incompleteAuthorize := validAuthorizeRequest(t, testCSR(t, false))
	incompleteAuthorize.EnrollmentToken = incompleteFixture.token
	incompleteAuthorize.ArtifactEncryptionPublicKey = bytesOf(32, 10)
	incompleteAuthorization, err := service.Authorize(context.Background(), incompleteAuthorize)
	if err != nil {
		t.Fatal(err)
	}

	idCalls := 0
	config := DefaultConfig()
	config.Clock = clock.now
	config.NewID = func() (uuid.UUID, error) {
		idCalls++
		return uuid.Nil, errors.New("test ID generator unavailable")
	}
	failingIDService, err := NewService(NewStore(pool), signer, config)
	if err != nil {
		t.Fatal(err)
	}

	replayed, err := failingIDService.Complete(context.Background(), completeRequest)
	if err != nil || replayed.Certificate.ID != completion.Certificate.ID ||
		replayed.ArtifactEncryptionKeyID != completion.ArtifactEncryptionKeyID || replayed.ArtifactEncryptionKeyID == "" {
		t.Fatalf("Complete(replay without IDs) = %#v, %v", replayed, err)
	}
	if idCalls != 0 {
		t.Fatalf("Complete(replay) requested %d IDs", idCalls)
	}

	invalidRequestID := completeRequest
	invalidRequestID.RequestID = "not-a-request-id"
	if _, err := failingIDService.Complete(context.Background(), invalidRequestID); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Complete(invalid request ID) error = %v", err)
	}
	for name, mutate := range map[string]func(*CompleteRequest){
		"workload": func(request *CompleteRequest) {
			request.GatewayWorkloadIdentity = "spiffe://cdn-platform/gateway/other"
		},
		"instance": func(request *CompleteRequest) { request.GatewayInstanceID = "gateway-other" },
	} {
		t.Run("complete_wrong_"+name, func(t *testing.T) {
			wrong := completeRequest
			mutate(&wrong)
			if _, err := failingIDService.Complete(context.Background(), wrong); !errors.Is(err, ErrGatewayBinding) {
				t.Fatalf("Complete() error = %v", err)
			}
		})
	}
	unknownAuthorization := completeRequest
	unknownAuthorization.AuthorizationID = uuid.New()
	if _, err := failingIDService.Complete(context.Background(), unknownAuthorization); !errors.Is(err, ErrAuthorizationNotFound) {
		t.Fatalf("Complete(unknown authorization) error = %v", err)
	}
	if idCalls != 0 {
		t.Fatalf("Complete preflight errors requested %d IDs", idCalls)
	}
	if _, err := failingIDService.Complete(context.Background(), CompleteRequest{RequestID: uuid.NewString(),
		AuthorizationID: incompleteAuthorization.ID, GatewayWorkloadIdentity: incompleteAuthorize.GatewayWorkloadIdentity,
		GatewayInstanceID: incompleteAuthorize.GatewayInstanceID}); !errors.Is(err, ErrPersistence) {
		t.Fatalf("Complete(incomplete without IDs) error = %v", err)
	}
	if idCalls != 1 {
		t.Fatalf("Complete(incomplete) requested %d IDs", idCalls)
	}

	renewRequest := RenewRequest{RequestID: uuid.NewString(), NodeID: fixture.nodeID,
		CurrentSerialNumber:          completion.Certificate.SerialNumber,
		CurrentCertificateSHA256:     certificateDERDigest(t, completion.Certificate),
		CertificateSigningRequestDER: testCSR(t, false),
		GatewayWorkloadIdentity:      authorize.GatewayWorkloadIdentity, GatewayInstanceID: "gateway-renew-blocked"}
	if _, err := failingIDService.Renew(context.Background(), renewRequest); !errors.Is(err, ErrRenewalTooEarly) {
		t.Fatalf("Renew(before renewal window without IDs) error = %v", err)
	}
	if idCalls != 1 {
		t.Fatalf("blocked Renew changed ID calls to %d", idCalls)
	}
}

func TestRenewalIssuedReplayRequiresExactCurrentCertificateDER(t *testing.T) {
	pool := openIdentityTestDatabase(t, true)
	now := time.Date(2026, 7, 22, 9, 45, 0, 0, time.UTC)
	clock := &identityTestClock{value: now}
	signer := newIdentityTestCA(t, now)
	service := newIdentityTestService(t, pool, signer, clock)
	fixture := seedIdentityNode(t, pool, now, "pending", "initial_enrollment")
	authorize := validAuthorizeRequest(t, testCSR(t, false))
	authorize.EnrollmentToken = fixture.token
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
	current := completion.Certificate
	renew := RenewRequest{
		RequestID: uuid.NewString(), NodeID: fixture.nodeID, CurrentSerialNumber: current.SerialNumber,
		CurrentCertificateSHA256: certificateDERDigest(t, current), CertificateSigningRequestDER: testCSR(t, false),
		GatewayWorkloadIdentity: authorize.GatewayWorkloadIdentity, GatewayInstanceID: "gateway-issued-replay",
	}
	normalized, err := normalizeRenew(renew)
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(pool)
	renewalNow := current.RenewalAt
	clock.set(renewalNow)
	claim, err := store.prepareRenewal(context.Background(), normalized, func() (uuid.UUID, error) { return uuid.New(), nil }, renewalNow,
		renewalNow.Add(time.Minute), renewalNow.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := service.sign(context.Background(), claim.NodeID, claim.CSRDER, "renewal", renewalNow)
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := service.prepareCertificate(signed, normalized.CSR, claim.NodeID, claim.CSRHash, renewalNow)
	if err != nil {
		t.Fatal(err)
	}
	certificateID, eventID := uuid.New(), uuid.New()
	persisted.ID = certificateID
	persisted.Certificate.ID = certificateID
	persisted.RenewalRequestID = &claim.RequestID
	persisted.ReplacesCertificateID = &claim.CurrentCertificateID
	issued, err := store.finalizeRenewal(context.Background(), claim, persisted, renewalNow, eventID)
	if err != nil {
		t.Fatal(err)
	}

	signer.mu.Lock()
	signerSerial := signer.serial
	signer.mu.Unlock()
	var certificateCount, renewalCount int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM node_certificates WHERE node_id=$1`, fixture.nodeID).Scan(&certificateCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM node_certificate_renewal_requests WHERE node_id=$1`, fixture.nodeID).Scan(&renewalCount); err != nil {
		t.Fatal(err)
	}

	replayed, err := service.Renew(context.Background(), renew)
	if err != nil || replayed.ID != issued.ID {
		t.Fatalf("Renew(exact DER issued replay) = %#v, %v", replayed, err)
	}
	wrongLeaf := renew
	wrongLeaf.CurrentCertificateSHA256 = sameSerialWrongCertificateDigest(t, signer, current, fixture.nodeID)
	if _, err := service.Renew(context.Background(), wrongLeaf); !errors.Is(err, ErrCertificateNotFound) {
		t.Fatalf("Renew(same serial wrong DER) error = %v, want ErrCertificateNotFound", err)
	}
	newRenewal := renew
	newRenewal.RequestID = uuid.NewString()
	newRenewal.CertificateSigningRequestDER = testCSR(t, false)
	if _, err := service.Renew(context.Background(), newRenewal); !errors.Is(err, ErrCertificateNotFound) {
		t.Fatalf("Renew(new request with replaced certificate) error = %v, want ErrCertificateNotFound", err)
	}

	signer.mu.Lock()
	finalSignerSerial := signer.serial
	signer.mu.Unlock()
	var finalCertificateCount, finalRenewalCount int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM node_certificates WHERE node_id=$1`, fixture.nodeID).Scan(&finalCertificateCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM node_certificate_renewal_requests WHERE node_id=$1`, fixture.nodeID).Scan(&finalRenewalCount); err != nil {
		t.Fatal(err)
	}
	if finalSignerSerial != signerSerial || finalCertificateCount != certificateCount || finalRenewalCount != renewalCount {
		t.Fatalf("replay/new renewal mutated signer or persistence: signer=%d/%d certificates=%d/%d renewals=%d/%d",
			signerSerial, finalSignerSerial, certificateCount, finalCertificateCount, renewalCount, finalRenewalCount)
	}
}

func TestRenewalWindowRejectsWithoutWritesAndExpiredRequestCanRecover(t *testing.T) {
	pool := openIdentityTestDatabase(t, true)
	issuedAt := time.Date(2026, 9, 15, 7, 7, 21, 0, time.UTC)
	clock := &identityTestClock{value: issuedAt}
	signer := newIdentityTestCA(t, issuedAt)
	service := newIdentityTestService(t, pool, signer, clock)
	fixture := seedIdentityNode(t, pool, issuedAt, "pending", "initial_enrollment")
	authorize := validAuthorizeRequest(t, testCSR(t, false))
	authorize.EnrollmentToken = fixture.token
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
	current := completion.Certificate
	oldRequest := RenewRequest{
		RequestID: uuid.NewString(), NodeID: fixture.nodeID, CurrentSerialNumber: current.SerialNumber,
		CurrentCertificateSHA256: certificateDERDigest(t, current), CertificateSigningRequestDER: testCSR(t, false),
		GatewayWorkloadIdentity: authorize.GatewayWorkloadIdentity, GatewayInstanceID: "gateway-renewal-window",
	}
	normalizedOld, err := normalizeRenew(oldRequest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO node_certificate_renewal_requests (
			request_id,request_digest,node_id,current_certificate_id,current_serial_number,
			csr_der,csr_sha256,gateway_workload_identity,gateway_instance_id,status,created_at,expires_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'expired',$10,$11)`,
		normalizedOld.RequestID, normalizedOld.RequestDigest[:], normalizedOld.NodeID, current.ID,
		normalizedOld.CurrentSerial, normalizedOld.CSRDER, normalizedOld.CSRHash[:],
		normalizedOld.GatewayWorkloadIdentity, normalizedOld.GatewayInstanceID,
		current.RenewalAt.Add(-20*time.Minute), current.RenewalAt.Add(-10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	signer.mu.Lock()
	serialBefore := signer.serial
	signer.mu.Unlock()

	clock.set(current.RenewalAt.Add(-time.Second))
	assertRenewalRetryError(t, service, oldRequest, ErrAuthorizationExpired,
		RenewalReasonRequestExpired, current.RenewalAt, time.Second)
	newRequest := oldRequest
	newRequest.RequestID = uuid.NewString()
	newRequest.CertificateSigningRequestDER = testCSR(t, false)
	assertRenewalRetryError(t, service, newRequest, ErrRenewalTooEarly,
		RenewalReasonTooEarly, current.RenewalAt, time.Second)
	var oldStatus string
	var renewalCount int
	if err := pool.QueryRow(context.Background(), `SELECT status FROM node_certificate_renewal_requests WHERE request_id=$1`,
		normalizedOld.RequestID).Scan(&oldStatus); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM node_certificate_renewal_requests WHERE node_id=$1`,
		fixture.nodeID).Scan(&renewalCount); err != nil || renewalCount != 1 || oldStatus != "expired" {
		t.Fatalf("pre-window renewals = count %d old %q err %v", renewalCount, oldStatus, err)
	}
	signer.mu.Lock()
	serialAfterRejected := signer.serial
	signer.mu.Unlock()
	if serialAfterRejected != serialBefore {
		t.Fatalf("pre-window renewal called signer: serial %d -> %d", serialBefore, serialAfterRejected)
	}

	clock.set(current.RenewalAt)
	assertRenewalRetryError(t, service, oldRequest, ErrAuthorizationExpired,
		RenewalReasonRequestExpired, current.RenewalAt, 0)
	signingStarted, releaseSigner := signer.blockOnce()
	type renewResult struct {
		certificate Certificate
		err         error
	}
	result := make(chan renewResult, 1)
	go func() {
		certificate, renewErr := service.Renew(context.Background(), newRequest)
		result <- renewResult{certificate: certificate, err: renewErr}
	}()
	<-signingStarted
	if _, err := service.Renew(context.Background(), newRequest); !errors.Is(err, ErrIssuanceInProgress) {
		t.Fatalf("concurrent Renew() error = %v, want ErrIssuanceInProgress", err)
	}
	close(releaseSigner)
	issued := <-result
	if issued.err != nil {
		t.Fatal(issued.err)
	}
	renewed := issued.certificate
	replayed, err := service.Renew(context.Background(), newRequest)
	if err != nil || replayed.ID != renewed.ID {
		t.Fatalf("Renew(replay) = %#v, %v; want certificate %s", replayed, err, renewed.ID)
	}
	if renewed.ID == uuid.Nil || renewed.ID == current.ID || !renewed.NotAfter.After(current.NotAfter) {
		t.Fatalf("renewed certificate = %#v, current %#v", renewed, current)
	}
	var oldRequestStatus, newRequestStatus, oldRotation, newRotation string
	if err := pool.QueryRow(context.Background(), `SELECT status FROM node_certificate_renewal_requests WHERE request_id=$1`,
		normalizedOld.RequestID).Scan(&oldRequestStatus); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT status FROM node_certificate_renewal_requests WHERE request_id=$1`,
		newRequest.RequestID).Scan(&newRequestStatus); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT rotation_status FROM node_certificates WHERE id=$1`, current.ID).Scan(&oldRotation); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT rotation_status FROM node_certificates WHERE id=$1`, renewed.ID).Scan(&newRotation); err != nil {
		t.Fatal(err)
	}
	if oldRequestStatus != "expired" || newRequestStatus != "issued" || oldRotation != "overlap" || newRotation != "current" {
		t.Fatalf("renewal states = requests %q/%q certificates %q/%q", oldRequestStatus, newRequestStatus, oldRotation, newRotation)
	}
	signer.mu.Lock()
	serialAfterIssued := signer.serial
	signer.mu.Unlock()
	if serialAfterIssued != serialBefore+1 {
		t.Fatalf("successful recovery signer calls = %d -> %d", serialBefore, serialAfterIssued)
	}
}

func assertRenewalRetryError(
	t *testing.T,
	service *Service,
	request RenewRequest,
	cause error,
	reason string,
	retryAt time.Time,
	retryAfter time.Duration,
) {
	t.Helper()
	_, err := service.Renew(context.Background(), request)
	var retry *RenewalRetryError
	if !errors.Is(err, cause) || !errors.As(err, &retry) || retry == nil || retry.Reason != reason ||
		!retry.RetryAt.Equal(retryAt.UTC().Truncate(time.Second)) || retry.RetryAfter != retryAfter {
		t.Fatalf("Renew() error = %#v, want cause %v reason %q retry %s/%s", err, cause, reason, retryAt, retryAfter)
	}
}

func TestNodeIdentityEnrollmentAndTokenExpiration(t *testing.T) {
	pool := openIdentityTestDatabase(t, true)
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)
	clock := &identityTestClock{value: now}
	signer := newIdentityTestCA(t, now)
	service := newIdentityTestService(t, pool, signer, clock)
	expiryNow := clock.now()
	expiredFixture := seedIdentityNode(t, pool, expiryNow, "pending", "initial_enrollment")
	expiredRequest := validAuthorizeRequest(t, testCSR(t, false))
	expiredRequest.EnrollmentToken = expiredFixture.token
	expiredRequest.ArtifactEncryptionPublicKey = bytesOf(32, 9)
	expiredAuthorization, err := service.Authorize(context.Background(), expiredRequest)
	if err != nil {
		t.Fatal(err)
	}
	clock.set(expiryNow.Add(6 * time.Minute))
	if _, err := service.Complete(context.Background(), CompleteRequest{RequestID: uuid.NewString(), AuthorizationID: expiredAuthorization.ID,
		GatewayWorkloadIdentity: expiredRequest.GatewayWorkloadIdentity, GatewayInstanceID: expiredRequest.GatewayInstanceID}); !errors.Is(err, ErrAuthorizationExpired) {
		t.Fatalf("Complete(expired authorization) error = %v", err)
	}
	tokenNow := clock.now()
	tokenFixture := seedIdentityNode(t, pool, tokenNow, "pending", "initial_enrollment")
	tokenRequest := validAuthorizeRequest(t, testCSR(t, false))
	tokenRequest.EnrollmentToken = tokenFixture.token
	tokenRequest.ArtifactEncryptionPublicKey = bytesOf(32, 10)
	clock.set(tokenNow.Add(61 * time.Minute))
	if _, err := service.Authorize(context.Background(), tokenRequest); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("Authorize(expired token) error = %v", err)
	}
}

func TestNodeIdentityFinalizeEnrollmentAtomicity(t *testing.T) {
	tests := []struct {
		name             string
		triggerSQL       string
		seedOldActiveKey bool
	}{
		{"certificate", `CREATE TRIGGER fail_identity_finalize BEFORE INSERT ON node_certificates
			FOR EACH ROW EXECUTE FUNCTION fail_identity_finalize()`, false},
		{"old_artifact_key", `CREATE TRIGGER fail_identity_finalize BEFORE UPDATE ON node_artifact_encryption_keys
			FOR EACH ROW WHEN (OLD.status='active' AND NEW.status='retired') EXECUTE FUNCTION fail_identity_finalize()`, true},
		{"artifact_key", `CREATE TRIGGER fail_identity_finalize BEFORE UPDATE ON node_artifact_encryption_keys
			FOR EACH ROW WHEN (OLD.status='pending' AND NEW.status='active') EXECUTE FUNCTION fail_identity_finalize()`, false},
		{"node", `CREATE TRIGGER fail_identity_finalize BEFORE UPDATE ON nodes
			FOR EACH ROW WHEN (OLD.admin_state='pending' AND NEW.admin_state='active') EXECUTE FUNCTION fail_identity_finalize()`, false},
		{"identity_state", `CREATE TRIGGER fail_identity_finalize BEFORE UPDATE ON node_identity_state
			FOR EACH ROW WHEN (NEW.active_artifact_key_id IS DISTINCT FROM OLD.active_artifact_key_id)
			EXECUTE FUNCTION fail_identity_finalize()`, false},
		{"event", `CREATE TRIGGER fail_identity_finalize BEFORE INSERT ON node_certificate_events
			FOR EACH ROW EXECUTE FUNCTION fail_identity_finalize()`, false},
		{"authorization", `CREATE TRIGGER fail_identity_finalize BEFORE UPDATE ON node_identity_authorizations
			FOR EACH ROW WHEN (NEW.status='issued') EXECUTE FUNCTION fail_identity_finalize()`, false},
		{"audit", `CREATE TRIGGER fail_identity_finalize BEFORE INSERT ON audit_events
			FOR EACH ROW EXECUTE FUNCTION fail_identity_finalize()`, false},
		{"commit", `CREATE CONSTRAINT TRIGGER fail_identity_finalize AFTER INSERT ON node_certificate_events
			DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION fail_identity_finalize()`, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pool := openIdentityTestDatabase(t, true)
			now := time.Date(2026, 7, 22, 11, 0, 0, 0, time.UTC)
			clock := &identityTestClock{value: now}
			signer := newIdentityTestCA(t, now)
			service := newIdentityTestService(t, pool, signer, clock)
			fixture := seedIdentityNode(t, pool, now, "pending", "initial_enrollment")
			authorize := validAuthorizeRequest(t, testCSR(t, false))
			authorize.EnrollmentToken = fixture.token
			oldArtifactKeyID := ""
			if test.seedOldActiveKey {
				oldAuthorization, err := service.Authorize(context.Background(), authorize)
				if err != nil {
					t.Fatal(err)
				}
				oldArtifactKeyID = oldAuthorization.ArtifactEncryptionKeyID
				if _, err := pool.Exec(context.Background(), `UPDATE node_artifact_encryption_keys SET
					status='active',activated_at=$2 WHERE id=$1`, oldArtifactKeyID, now); err != nil {
					t.Fatal(err)
				}
				if _, err := pool.Exec(context.Background(), `UPDATE node_identity_state SET
					active_artifact_key_id=$2,authorization_revision=authorization_revision+1,updated_at=$3
					WHERE node_id=$1`, fixture.nodeID, oldArtifactKeyID, now); err != nil {
					t.Fatal(err)
				}
				authorize = validAuthorizeRequest(t, testCSR(t, false))
				authorize.EnrollmentToken = issueIdentityToken(t, pool, fixture, now, "re_enrollment")
				authorize.ArtifactEncryptionPublicKey = bytesOf(32, 9)
			}
			authorization, err := service.Authorize(context.Background(), authorize)
			if err != nil {
				t.Fatal(err)
			}
			var nodeState string
			var nodeRevision, identityRevision int64
			var activeKey *string
			if err := pool.QueryRow(context.Background(), `SELECT node.admin_state,node.revision,
				state.active_artifact_key_id,state.authorization_revision
				FROM nodes node JOIN node_identity_state state ON state.node_id=node.id WHERE node.id=$1`,
				fixture.nodeID).Scan(&nodeState, &nodeRevision, &activeKey, &identityRevision); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(context.Background(), `CREATE FUNCTION fail_identity_finalize()
				RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected finalize failure'; END; $$`); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(context.Background(), test.triggerSQL); err != nil {
				t.Fatal(err)
			}
			complete := CompleteRequest{RequestID: uuid.NewString(), AuthorizationID: authorization.ID,
				GatewayWorkloadIdentity: authorize.GatewayWorkloadIdentity,
				GatewayInstanceID:       authorize.GatewayInstanceID}
			if _, err := service.Complete(context.Background(), complete); !errors.Is(err, ErrPersistence) {
				t.Fatalf("Complete() error = %v", err)
			}
			assertFailedEnrollmentFinalize(t, pool, fixture.nodeID, authorization.ID,
				authorization.ArtifactEncryptionKeyID, nodeState, nodeRevision, activeKey, identityRevision)
			if oldArtifactKeyID != "" {
				var oldStatus string
				if err := pool.QueryRow(context.Background(), `SELECT status FROM node_artifact_encryption_keys
					WHERE id=$1`, oldArtifactKeyID).Scan(&oldStatus); err != nil || oldStatus != "active" {
					t.Fatalf("old artifact key status = %q, %v", oldStatus, err)
				}
			}
		})
	}
}

func TestNodeIdentityRejectsMissingOrMismatchedActiveCAEpoch(t *testing.T) {
	for _, test := range []struct {
		name          string
		seedDifferent bool
	}{
		{"missing", false},
		{"mismatched_signer", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			pool := openIdentityTestDatabase(t, true)
			now := time.Date(2026, 7, 22, 11, 30, 0, 0, time.UTC)
			clock := &identityTestClock{value: now}
			signer := newIdentityTestCA(t, now)
			if test.seedDifferent {
				seedIdentityCAEpoch(t, pool, newIdentityTestCA(t, now), now)
			}
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
				GatewayWorkloadIdentity: authorize.GatewayWorkloadIdentity,
				GatewayInstanceID:       authorize.GatewayInstanceID}
			if _, err := service.Complete(context.Background(), complete); !errors.Is(err, ErrCertificateInvalid) {
				t.Fatalf("Complete() error = %v", err)
			}
			var certificateCount int
			var authorizationStatus, artifactStatus string
			if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM node_certificates
				WHERE enrollment_authorization_id=$1`, authorization.ID).Scan(&certificateCount); err != nil {
				t.Fatal(err)
			}
			if err := pool.QueryRow(context.Background(), `SELECT status FROM node_identity_authorizations
				WHERE id=$1`, authorization.ID).Scan(&authorizationStatus); err != nil {
				t.Fatal(err)
			}
			if err := pool.QueryRow(context.Background(), `SELECT status FROM node_artifact_encryption_keys
				WHERE id=$1`, authorization.ArtifactEncryptionKeyID).Scan(&artifactStatus); err != nil {
				t.Fatal(err)
			}
			if certificateCount != 0 || authorizationStatus != "authorized" || artifactStatus != "pending" {
				t.Fatalf("untrusted CA persisted certificate=%d authorization=%q artifact=%q",
					certificateCount, authorizationStatus, artifactStatus)
			}
			if test.name == "missing" {
				seedIdentityCAEpoch(t, pool, signer, now)
				if _, err := service.Complete(context.Background(), complete); err != nil {
					t.Fatalf("Complete() after CA epoch recovery: %v", err)
				}
			}
		})
	}
}

// An issued certificate keeps status='active' after its validity window closes,
// because nothing in the schema moves an expired certificate out of 'active'.
// Re-enrollment must therefore consult not_after: otherwise a node that stays
// offline for longer than one certificate TTL is rejected with
// ErrCertificateInvalid forever and can never come back.
func TestNodeIdentityExpiredCertificateDoesNotBlockReenrollment(t *testing.T) {
	pool := openIdentityTestDatabase(t, true)
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	clock := &identityTestClock{value: now}
	signer := newIdentityTestCA(t, now)
	service := newIdentityTestService(t, pool, signer, clock)
	fixture := seedIdentityNode(t, pool, now, "pending", "initial_enrollment")

	authorize := validAuthorizeRequest(t, testCSR(t, false))
	authorize.EnrollmentToken = fixture.token
	authorization, err := service.Authorize(context.Background(), authorize)
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	complete := CompleteRequest{RequestID: uuid.NewString(), AuthorizationID: authorization.ID,
		GatewayWorkloadIdentity: authorize.GatewayWorkloadIdentity,
		GatewayInstanceID:       authorize.GatewayInstanceID}
	completion, err := service.Complete(context.Background(), complete)
	if err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
	issued := completion.Certificate

	// The node is offline past its certificate TTL and comes back with a fresh
	// enrollment token and a fresh identity directory.
	clock.set(issued.NotAfter.Add(time.Hour))
	if _, err := service.Authorize(context.Background(), reenrollRequest(t, pool, fixture, clock)); err != nil {
		t.Fatalf("Authorize(re-enroll) error = %v", err)
	}
	var status, rotation string
	if err := pool.QueryRow(context.Background(), `SELECT status,rotation_status FROM node_certificates WHERE id=$1`,
		issued.ID).Scan(&status, &rotation); err != nil {
		t.Fatal(err)
	}
	if status != "active" || rotation != "current" {
		t.Fatalf("expired certificate = %q/%q, want active/current", status, rotation)
	}
}

// A certificate that is still inside its validity window keeps blocking
// enrollment, so the expiry predicate does not weaken the live-certificate
// guard.
func TestNodeIdentityLiveCertificateStillBlocksReenrollment(t *testing.T) {
	pool := openIdentityTestDatabase(t, true)
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	clock := &identityTestClock{value: now}
	signer := newIdentityTestCA(t, now)
	service := newIdentityTestService(t, pool, signer, clock)
	fixture := seedIdentityNode(t, pool, now, "pending", "initial_enrollment")

	authorize := validAuthorizeRequest(t, testCSR(t, false))
	authorize.EnrollmentToken = fixture.token
	authorization, err := service.Authorize(context.Background(), authorize)
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	complete := CompleteRequest{RequestID: uuid.NewString(), AuthorizationID: authorization.ID,
		GatewayWorkloadIdentity: authorize.GatewayWorkloadIdentity,
		GatewayInstanceID:       authorize.GatewayInstanceID}
	completion, err := service.Complete(context.Background(), complete)
	if err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
	issued := completion.Certificate

	clock.set(issued.NotAfter.Add(-time.Minute))
	reenroll := reenrollRequest(t, pool, fixture, clock)
	reauthorization, err := service.Authorize(context.Background(), reenroll)
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if _, err := service.Complete(context.Background(), CompleteRequest{
		RequestID: uuid.NewString(), AuthorizationID: reauthorization.ID,
		GatewayWorkloadIdentity: reenroll.GatewayWorkloadIdentity,
		GatewayInstanceID:       reenroll.GatewayInstanceID,
	}); !errors.Is(err, ErrCertificateInvalid) {
		t.Fatalf("Complete() error = %v, want ErrCertificateInvalid", err)
	}
}

// Self-registered (UUIDv8) nodes complete enrollment but stay pending until an
// administrator initializes them; until then the authorization snapshot
// refuses both the agent session and every deployment.
func TestNodeIdentitySelfRegisteredNodeStaysPendingAfterEnrollment(t *testing.T) {
	pool := openIdentityTestDatabase(t, true)
	now := time.Date(2026, 7, 22, 13, 0, 0, 0, time.UTC)
	clock := &identityTestClock{value: now}
	signer := newIdentityTestCA(t, now)
	service := newIdentityTestService(t, pool, signer, clock)
	selfRegistered := uuid.New()
	selfRegistered[6] = (selfRegistered[6] & 0x0f) | 0x80
	if !node.IsSelfRegisteredNodeID(selfRegistered) {
		t.Fatal("fixture ID is not self-registered")
	}
	fixture := seedIdentityNodeWithID(t, pool, now, "pending", "initial_enrollment", selfRegistered)

	request := validAuthorizeRequest(t, testCSR(t, false))
	request.EnrollmentToken = fixture.token
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
	var state string
	if err := pool.QueryRow(context.Background(), `SELECT admin_state FROM nodes WHERE id=$1`, fixture.nodeID).Scan(&state); err != nil || state != "pending" {
		t.Fatalf("admin_state after enrollment = %q, %v; want pending", state, err)
	}
	snapshot, err := service.GetAuthorization(context.Background(), GetAuthorizationRequest{NodeID: fixture.nodeID,
		CertificateSerialNumber: completion.Certificate.SerialNumber,
		CertificateSHA256:       certificateDERDigest(t, completion.Certificate),
		GatewayWorkloadIdentity: request.GatewayWorkloadIdentity, GatewayInstanceID: request.GatewayInstanceID})
	if err != nil || snapshot.AdministrativeState != "pending" || !snapshot.ConnectionAllowed || snapshot.DeploymentsAllowed {
		// Pending keeps a session (heartbeat, certificate renewal) but receives no deployments.
		t.Fatalf("GetAuthorization(pending self-registered) = %#v, %v", snapshot, err)
	}
	// 待初始化节点必须能在续期窗口内续签短期证书，否则 24 小时后只能删掉重装。
	clock.set(completion.Certificate.RenewalAt)
	renewed, err := service.Renew(context.Background(), RenewRequest{RequestID: uuid.NewString(), NodeID: fixture.nodeID,
		CurrentSerialNumber:          completion.Certificate.SerialNumber,
		CurrentCertificateSHA256:     certificateDERDigest(t, completion.Certificate),
		CertificateSigningRequestDER: testCSR(t, false),
		GatewayWorkloadIdentity:      request.GatewayWorkloadIdentity, GatewayInstanceID: request.GatewayInstanceID})
	if err != nil || renewed.SerialNumber == completion.Certificate.SerialNumber {
		t.Fatalf("Renew(pending self-registered) = %#v, %v", renewed, err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT admin_state FROM nodes WHERE id=$1`, fixture.nodeID).Scan(&state); err != nil || state != "pending" {
		t.Fatalf("admin_state after renewal = %q, %v; want pending", state, err)
	}
	clock.set(now)

	// Console-reserved (UUIDv7-style) nodes keep the legacy activation.
	reserved := seedIdentityNode(t, pool, now, "pending", "initial_enrollment")
	reservedRequest := validAuthorizeRequest(t, testCSR(t, false))
	reservedRequest.EnrollmentToken = reserved.token
	reservedRequest.ArtifactEncryptionPublicKey = bytesOf(32, 11)
	reservedAuthorization, err := service.Authorize(context.Background(), reservedRequest)
	if err != nil {
		t.Fatalf("Authorize(reserved) error = %v", err)
	}
	if _, err := service.Complete(context.Background(), CompleteRequest{RequestID: uuid.NewString(),
		AuthorizationID: reservedAuthorization.ID, GatewayWorkloadIdentity: reservedRequest.GatewayWorkloadIdentity,
		GatewayInstanceID: reservedRequest.GatewayInstanceID}); err != nil {
		t.Fatalf("Complete(reserved) error = %v", err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT admin_state FROM nodes WHERE id=$1`, reserved.nodeID).Scan(&state); err != nil || state != "active" {
		t.Fatalf("reserved admin_state after enrollment = %q, %v; want active", state, err)
	}
}

// A re-enrolling node mints a fresh artifact encryption keypair, so the request
// must not reuse validAuthorizeRequest's fixed key material: the derived
// artifact key id is the primary key of node_artifact_encryption_keys.
func reenrollRequest(t *testing.T, pool *pgxpool.Pool, fixture identityFixture, clock *identityTestClock) AuthorizeRequest {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	request := validAuthorizeRequest(t, testCSR(t, false))
	request.EnrollmentToken = issueIdentityToken(t, pool, fixture, clock.now(), "initial_enrollment")
	request.ArtifactEncryptionPublicKey = key
	return request
}

func TestNodeIdentityHistoricalEnrollmentRecoveryAndAuthorizationGate(t *testing.T) {
	pool := openIdentityTestDatabase(t, true)
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	clock := &identityTestClock{value: now}
	signer := newIdentityTestCA(t, now)
	service := newIdentityTestService(t, pool, signer, clock)
	fixture := seedIdentityPlatformNode(t, pool, now, "pending", "initial_enrollment")
	authorize := validAuthorizeRequest(t, testCSR(t, false))
	authorize.EnrollmentToken = fixture.token
	authorization, err := service.Authorize(context.Background(), authorize)
	if err != nil {
		t.Fatal(err)
	}
	historical, leafDERHash := seedHistoricalIssuedEnrollment(t, pool, service, authorization, authorize, now)
	recovery := CompleteRequest{RequestID: authorize.RequestID, AuthorizationID: authorization.ID,
		GatewayWorkloadIdentity: authorize.GatewayWorkloadIdentity,
		GatewayInstanceID:       authorize.GatewayInstanceID}
	recovered, err := service.Complete(context.Background(), recovery)
	if err != nil || recovered.Certificate.ID != historical.ID ||
		recovered.ArtifactEncryptionKeyID != authorization.ArtifactEncryptionKeyID {
		t.Fatalf("Complete(historical recovery) = %#v, %v", recovered, err)
	}
	conflict := recovery
	conflict.RequestID = uuid.NewString()
	if _, err := service.Complete(context.Background(), conflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("Complete(historical conflicting request) error = %v", err)
	}
	if _, err := service.GetAuthorization(context.Background(), GetAuthorizationRequest{NodeID: fixture.nodeID,
		CertificateSerialNumber: historical.SerialNumber, CertificateSHA256: leafDERHash,
		GatewayWorkloadIdentity: authorize.GatewayWorkloadIdentity,
		GatewayInstanceID:       "gateway-recovery"}); !errors.Is(err, ErrCertificateNotFound) {
		t.Fatalf("GetAuthorization(legacy_unbound) error = %v", err)
	}

	roleID := uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO roles(id,scope_id,name,description,system_role)
		  VALUES($1,$2,'platform_owner','Identity recovery',true)`, []any{roleID, fixture.scopeID}},
		{`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'nodes.manage')`, []any{roleID}},
		{`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, []any{fixture.scopeID, fixture.userID, roleID}},
	} {
		if _, err := pool.Exec(context.Background(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	var epochID uuid.UUID
	if err := pool.QueryRow(context.Background(), `SELECT id FROM node_ca_key_epochs WHERE status='active'`).Scan(&epochID); err != nil {
		t.Fatal(err)
	}
	lifecycleStore, err := certlifecycle.NewStore(pool, certlifecycle.Config{Clock: clock.now,
		OverlapWindow: 20 * time.Second, AuthorizationSnapshotTTL: time.Minute,
		MaxScheduledRevocation: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycleStore.AdoptCertificate(context.Background(), certlifecycle.Actor{
		UserID: fixture.userID, ScopeID: fixture.scopeID, ScopeKind: "platform",
	}, certlifecycle.AdoptCertificateRequest{RequestID: uuid.New(), NodeID: fixture.nodeID,
		SerialNumber: historical.SerialNumber, LeafDERSHA256: leafDERHash,
		CAEpochID: epochID, RequestTraceID: "trace-historical-enrollment-adoption"}); err != nil {
		t.Fatalf("AdoptCertificate(historical enrollment) error = %v", err)
	}
	recoveredAfterAdoption, err := service.Complete(context.Background(), recovery)
	if err != nil || recoveredAfterAdoption.Certificate.ID != historical.ID {
		t.Fatalf("Complete(historical recovery after adoption) = %#v, %v", recoveredAfterAdoption, err)
	}
	snapshot, err := service.GetAuthorization(context.Background(), GetAuthorizationRequest{NodeID: fixture.nodeID,
		CertificateSerialNumber: historical.SerialNumber, CertificateSHA256: leafDERHash,
		GatewayWorkloadIdentity: authorize.GatewayWorkloadIdentity,
		GatewayInstanceID:       "gateway-recovery"})
	if err != nil || !snapshot.ConnectionAllowed || !snapshot.DeploymentsAllowed {
		t.Fatalf("GetAuthorization(adopted historical certificate) = %#v, %v", snapshot, err)
	}
	effectiveAt := now.Add(30 * time.Second)
	if _, err := lifecycleStore.RevokeCertificate(context.Background(), certlifecycle.Actor{
		UserID: fixture.userID, ScopeID: fixture.scopeID, ScopeKind: "platform",
	}, certlifecycle.RevokeCertificateRequest{RequestID: uuid.New(), NodeID: fixture.nodeID,
		SerialNumber: historical.SerialNumber, LeafDERSHA256: leafDERHash,
		Reason: "scheduled recovery revocation", EffectiveAt: effectiveAt,
		RequestTraceID: "trace-historical-scheduled-revocation"}); err != nil {
		t.Fatalf("RevokeCertificate(schedule) error = %v", err)
	}
	beforeEffective, err := service.GetAuthorization(context.Background(), GetAuthorizationRequest{NodeID: fixture.nodeID,
		CertificateSerialNumber: historical.SerialNumber, CertificateSHA256: leafDERHash,
		GatewayWorkloadIdentity: authorize.GatewayWorkloadIdentity,
		GatewayInstanceID:       "gateway-recovery"})
	if err != nil || !beforeEffective.ConnectionAllowed || beforeEffective.CertificateRevoked ||
		!beforeEffective.SnapshotExpirationTime.Equal(effectiveAt) {
		t.Fatalf("GetAuthorization(before scheduled revocation) = %#v, %v", beforeEffective, err)
	}
	clock.set(effectiveAt)
	afterEffective, err := service.GetAuthorization(context.Background(), GetAuthorizationRequest{NodeID: fixture.nodeID,
		CertificateSerialNumber: historical.SerialNumber, CertificateSHA256: leafDERHash,
		GatewayWorkloadIdentity: authorize.GatewayWorkloadIdentity,
		GatewayInstanceID:       "gateway-recovery"})
	if err != nil || !afterEffective.CertificateRevoked || afterEffective.ConnectionAllowed || afterEffective.DeploymentsAllowed {
		t.Fatalf("GetAuthorization(at scheduled revocation) = %#v, %v", afterEffective, err)
	}
	clock.set(effectiveAt.Add(time.Second))
	afterBoundary, err := service.GetAuthorization(context.Background(), GetAuthorizationRequest{NodeID: fixture.nodeID,
		CertificateSerialNumber: historical.SerialNumber, CertificateSHA256: leafDERHash,
		GatewayWorkloadIdentity: authorize.GatewayWorkloadIdentity,
		GatewayInstanceID:       "gateway-recovery"})
	if err != nil || !afterBoundary.CertificateRevoked || afterBoundary.ConnectionAllowed || afterBoundary.DeploymentsAllowed {
		t.Fatalf("GetAuthorization(after scheduled revocation) = %#v, %v", afterBoundary, err)
	}
}

func certificateDERDigest(t *testing.T, certificate Certificate) [32]byte {
	t.Helper()
	leaf, err := parseSinglePEMCertificate(certificate.LeafCertificatePEM)
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(leaf.Raw)
}

func sameSerialWrongCertificateDigest(
	t *testing.T,
	signer *identityTestCA,
	certificate Certificate,
	nodeID uuid.UUID,
) [32]byte {
	t.Helper()
	serial, ok := new(big.Int).SetString(certificate.SerialNumber, 16)
	if !ok {
		t.Fatalf("invalid certificate serial %q", certificate.SerialNumber)
	}
	uri, err := url.Parse(NodeSPIFFEPrefix + nodeID.String())
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: nodeID.String()},
		NotBefore:    certificate.NotBefore,
		NotAfter:     certificate.NotAfter,
		URIs:         []*url.URL{uri},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, signer.root, &key.PublicKey, signer.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(der)
	if digest == certificateDERDigest(t, certificate) {
		t.Fatal("wrong certificate fixture reused the stored leaf DER")
	}
	return digest
}

func seedHistoricalIssuedEnrollment(
	t *testing.T,
	pool *pgxpool.Pool,
	service *Service,
	authorization Authorization,
	authorize AuthorizeRequest,
	now time.Time,
) (Certificate, [32]byte) {
	t.Helper()
	csr, _, csrHash, err := validateCSR(authorize.CertificateSigningRequestDER)
	if err != nil || csrHash != authorization.CertificateSigningRequestSHA256 {
		t.Fatal("historical CSR mismatch")
	}
	signed, err := service.sign(context.Background(), authorization.NodeID,
		authorize.CertificateSigningRequestDER, "initial", now)
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := service.prepareCertificate(signed, csr, authorization.NodeID, csrHash, now)
	if err != nil {
		t.Fatal(err)
	}
	persisted.ID = uuid.New()
	persisted.Certificate.ID = persisted.ID
	persisted.EnrollmentAuthorizationID = &authorization.ID
	leaseID, eventID := uuid.New(), uuid.New()
	err = pgx.BeginFunc(context.Background(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(context.Background(), `UPDATE node_identity_authorizations SET
			status='signing',signing_attempt=1,signing_lease_id=$2,signing_lease_expires_at=$3
			WHERE id=$1`, authorization.ID, leaseID, now.Add(time.Minute)); err != nil {
			return err
		}
		if err := insertCertificate(context.Background(), tx, persisted, "initial", now); err != nil {
			return err
		}
		if _, err := tx.Exec(context.Background(), `UPDATE node_artifact_encryption_keys SET
			status='active',activated_at=$2 WHERE id=$1`, authorization.ArtifactEncryptionKeyID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(context.Background(), `UPDATE nodes SET admin_state='active',revision=revision+1,
			updated_at=$2 WHERE id=$1`, authorization.NodeID, now); err != nil {
			return err
		}
		var revision int64
		if err := tx.QueryRow(context.Background(), `UPDATE node_identity_state SET active_artifact_key_id=$2,
			authorization_revision=authorization_revision+1,updated_at=$3 WHERE node_id=$1
			RETURNING authorization_revision`, authorization.NodeID, authorization.ArtifactEncryptionKeyID, now).Scan(&revision); err != nil {
			return err
		}
		if _, err := tx.Exec(context.Background(), `INSERT INTO node_certificate_events
			(id,node_id,certificate_id,event_type,authorization_revision,occurred_at)
			VALUES($1,$2,$3,'issued',$4,$5)`, eventID, authorization.NodeID, persisted.ID, revision, now); err != nil {
			return err
		}
		_, err := tx.Exec(context.Background(), `UPDATE node_identity_authorizations SET status='issued',
			signing_lease_id=NULL,signing_lease_expires_at=NULL,issued_certificate_id=$2,completed_at=$3
			WHERE id=$1`, authorization.ID, persisted.ID, now)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return persisted.Certificate, persisted.LeafDERHash
}

func assertFailedEnrollmentFinalize(
	t *testing.T,
	pool *pgxpool.Pool,
	nodeID, authorizationID uuid.UUID,
	artifactKeyID, expectedNodeState string,
	expectedNodeRevision int64,
	expectedActiveKey *string,
	expectedIdentityRevision int64,
) {
	t.Helper()
	var certificateCount, eventCount, auditCount int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM node_certificates
		WHERE enrollment_authorization_id=$1`, authorizationID).Scan(&certificateCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM node_certificate_events
		WHERE node_id=$1`, nodeID).Scan(&eventCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events
		WHERE action='node_certificate.lifecycle.enroll' AND payload->>'node_id'=$1`, nodeID.String()).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	var authorizationStatus string
	var issuedCertificateID *uuid.UUID
	var completedAt *time.Time
	if err := pool.QueryRow(context.Background(), `SELECT status,issued_certificate_id,completed_at
		FROM node_identity_authorizations WHERE id=$1`, authorizationID).Scan(&authorizationStatus,
		&issuedCertificateID, &completedAt); err != nil {
		t.Fatal(err)
	}
	var artifactStatus string
	var activatedAt, deactivatedAt *time.Time
	var deactivationReason *string
	if err := pool.QueryRow(context.Background(), `SELECT status,activated_at,deactivated_at,deactivation_reason
		FROM node_artifact_encryption_keys WHERE id=$1`, artifactKeyID).Scan(&artifactStatus,
		&activatedAt, &deactivatedAt, &deactivationReason); err != nil {
		t.Fatal(err)
	}
	var nodeState string
	var nodeRevision, identityRevision int64
	var activeKey *string
	if err := pool.QueryRow(context.Background(), `SELECT node.admin_state,node.revision,
		state.active_artifact_key_id,state.authorization_revision
		FROM nodes node JOIN node_identity_state state ON state.node_id=node.id WHERE node.id=$1`, nodeID).Scan(
		&nodeState, &nodeRevision, &activeKey, &identityRevision); err != nil {
		t.Fatal(err)
	}
	if certificateCount != 0 || eventCount != 0 || auditCount != 0 || authorizationStatus == "issued" ||
		issuedCertificateID != nil || completedAt != nil || artifactStatus != "pending" || activatedAt != nil ||
		deactivatedAt != nil || deactivationReason != nil || nodeState != expectedNodeState ||
		nodeRevision != expectedNodeRevision || !equalOptionalString(activeKey, expectedActiveKey) ||
		identityRevision != expectedIdentityRevision {
		t.Fatalf("partial finalize persisted: certificates=%d events=%d audits=%d authorization=%q issued=%v completed=%v artifact=%q activated=%v deactivated=%v reason=%v node=%q/%d active_key=%v identity_revision=%d",
			certificateCount, eventCount, auditCount, authorizationStatus, issuedCertificateID, completedAt, artifactStatus,
			activatedAt, deactivatedAt, deactivationReason, nodeState, nodeRevision, activeKey, identityRevision)
	}
}

func equalOptionalString(left, right *string) bool {
	return (left == nil && right == nil) || (left != nil && right != nil && *left == *right)
}

type identityFixture struct {
	nodeID, scopeID, tenantID, userID uuid.UUID
	token                             string
}

func seedIdentityPlatformNode(t *testing.T, pool *pgxpool.Pool, now time.Time, state, purpose string) identityFixture {
	t.Helper()
	var scopeID, userID uuid.UUID
	if err := pool.QueryRow(context.Background(), `SELECT scope.id,membership.user_id
		FROM access_scopes scope JOIN memberships membership ON membership.scope_id=scope.id
		WHERE scope.kind='platform' AND membership.status='active' LIMIT 1`).Scan(&scopeID, &userID); err != nil {
		t.Fatal(err)
	}
	nodeID := uuid.New()
	var displayID int64
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO node_display_id_sequences(scope_id,next_value,updated_at) VALUES($1,2,$2)
		ON CONFLICT(scope_id) DO UPDATE
		SET next_value=node_display_id_sequences.next_value+1,updated_at=EXCLUDED.updated_at
		RETURNING next_value-1`, scopeID, now).Scan(&displayID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO nodes
			(id,scope_id,display_id,name,admin_state,created_by_user_id,created_at,updated_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$7)`, nodeID, scopeID, displayID, "identity-platform-node-"+nodeID.String()[:8],
		state, userID, now); err != nil {
		t.Fatal(err)
	}
	fixture := identityFixture{nodeID: nodeID, scopeID: scopeID, userID: userID}
	fixture.token = issueIdentityToken(t, pool, fixture, now, purpose)
	return fixture
}

func seedIdentityNode(t *testing.T, pool *pgxpool.Pool, now time.Time, state, purpose string) identityFixture {
	t.Helper()
	return seedIdentityNodeWithID(t, pool, now, state, purpose, uuid.New())
}

func seedIdentityNodeWithID(t *testing.T, pool *pgxpool.Pool, now time.Time, state, purpose string, nodeID uuid.UUID) identityFixture {
	t.Helper()
	tenantID, scopeID, userID := uuid.New(), uuid.New(), uuid.New()
	username := "identity_" + userID.String()[:12]
	tx, err := pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(context.Background(), `INSERT INTO tenants (id,display_name) VALUES ($1,$2)`,
		tenantID, "Identity tenant "+tenantID.String()[:8]); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(context.Background(), `INSERT INTO access_scopes (id,kind,tenant_id) VALUES ($1,'tenant',$2)`,
		scopeID, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(context.Background(), `
		INSERT INTO users (id,username,display_name,password_hash) VALUES ($1,$2,'Identity test','unused')`,
		userID, username); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(context.Background(), `
		INSERT INTO nodes (id,scope_id,display_id,name,admin_state,created_by_user_id,created_at,updated_at)
		VALUES ($1,$2,1,$3,$4,$5,$6,$6)`, nodeID, scopeID, "identity-node-"+nodeID.String()[:8], state,
		userID, now); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	fixture := identityFixture{nodeID: nodeID, scopeID: scopeID, tenantID: tenantID, userID: userID}
	fixture.token = issueIdentityToken(t, pool, fixture, now, purpose)
	return fixture
}

func issueIdentityToken(t *testing.T, pool *pgxpool.Pool, fixture identityFixture, now time.Time, purpose string) string {
	t.Helper()
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	raw := base64.RawURLEncoding.EncodeToString(secret)
	digest := sha256.Sum256([]byte(raw))
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO node_enrollment_tokens
			(id,node_id,purpose,token_hash,created_by_user_id,created_at,expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`, uuid.New(), fixture.nodeID, purpose, digest[:], fixture.userID, now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	return raw
}

type identityTestClock struct {
	mu    sync.Mutex
	value time.Time
}

func (clock *identityTestClock) now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.value
}
func (clock *identityTestClock) set(value time.Time) {
	clock.mu.Lock()
	clock.value = value
	clock.mu.Unlock()
}

type identityTestCA struct {
	mu      sync.Mutex
	root    *x509.Certificate
	rootKey *ecdsa.PrivateKey
	rootPEM []byte
	serial  int64
	fail    bool
	block   bool
	started chan struct{}
	release chan struct{}
}

func newIdentityTestCA(t *testing.T, now time.Time) *identityTestCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Identity test CA"},
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(400 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &identityTestCA{root: root, rootKey: key, rootPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), serial: 100}
}

func (signer *identityTestCA) SignNodeCertificate(ctx context.Context, request SignRequest) (SignedCertificate, error) {
	signer.mu.Lock()
	if signer.fail {
		signer.fail = false
		signer.mu.Unlock()
		return SignedCertificate{}, errors.New("test signer failure")
	}
	signer.serial++
	serial := signer.serial
	block, started, release := signer.block, signer.started, signer.release
	signer.block = false
	signer.mu.Unlock()
	if block {
		close(started)
		select {
		case <-release:
		case <-ctx.Done():
			return SignedCertificate{}, ctx.Err()
		}
	}
	csr, err := x509.ParseCertificateRequest(request.CertificateSigningRequestDER)
	if err != nil {
		return SignedCertificate{}, err
	}
	uri, err := url.Parse(request.URISAN)
	if err != nil {
		return SignedCertificate{}, err
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: request.NodeID.String()},
		NotBefore: request.NotBefore, NotAfter: request.NotAfter, URIs: []*url.URL{uri}, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, signer.root, csr.PublicKey, signer.rootKey)
	if err != nil {
		return SignedCertificate{}, err
	}
	return SignedCertificate{LeafCertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		IssuingChainPEM: [][]byte{append([]byte(nil), signer.rootPEM...)}}, nil
}

func (signer *identityTestCA) failOnce() { signer.mu.Lock(); signer.fail = true; signer.mu.Unlock() }
func (signer *identityTestCA) blockOnce() (<-chan struct{}, chan struct{}) {
	signer.mu.Lock()
	defer signer.mu.Unlock()
	signer.block, signer.started, signer.release = true, make(chan struct{}), make(chan struct{})
	return signer.started, signer.release
}

func newIdentityTestService(t *testing.T, pool *pgxpool.Pool, signer CertificateSigner, clock *identityTestClock) *Service {
	t.Helper()
	testCA, ok := signer.(*identityTestCA)
	if !ok {
		t.Fatal("identity integration signer must expose its verified test CA")
	}
	seedIdentityCAEpoch(t, pool, testCA, clock.now())
	config := DefaultConfig()
	config.Clock = clock.now
	service, err := NewService(NewStore(pool), signer, config)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func seedIdentityCAEpoch(t *testing.T, pool *pgxpool.Pool, signer *identityTestCA, now time.Time) {
	t.Helper()
	installationID := "node-identity-test"
	actorScopeID, actorUserID := uuid.New(), uuid.New()
	publicKeyDER, err := x509.MarshalPKIXPublicKey(signer.root.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	certificateHash := sha256.Sum256(signer.root.Raw)
	publicKeyHash := sha256.Sum256(publicKeyDER)
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, []any{actorScopeID}},
		{`INSERT INTO users(id,username,display_name,password_hash)
		  VALUES($1,$2,'Identity CA operator','test-only')`,
			[]any{actorUserID, "identity-ca-" + actorUserID.String()[:12]}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{actorScopeID, actorUserID}},
		{`INSERT INTO control_installation_entitlement(installation_id) VALUES($1)`, []any{installationID}},
		{`INSERT INTO node_ca_key_epochs(
			id,installation_id,epoch,key_id,ca_certificate_pem,ca_certificate_sha256,public_key_sha256,
			not_before,not_after,status,request_id,request_digest,created_by_scope_id,created_by_user_id,created_at)
		  VALUES($1,$2,1,'identity-test-ca',$3,$4,$5,$6,$7,'active',$8,$9,$10,$11,$12)`,
			[]any{uuid.New(), installationID, signer.rootPEM, certificateHash[:], publicKeyHash[:],
				signer.root.NotBefore, signer.root.NotAfter, uuid.New(), bytesOf(32, 7), actorScopeID, actorUserID, now}},
	}
	for _, statement := range statements {
		if _, err := pool.Exec(context.Background(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
}

func assertPublicCertificate(t *testing.T, certificate Certificate, nodeID uuid.UUID, root *x509.Certificate) {
	t.Helper()
	leaf, err := parseSinglePEMCertificate(certificate.LeafCertificatePEM)
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != NodeSPIFFEPrefix+nodeID.String() {
		t.Fatalf("certificate URI SAN = %v", leaf.URIs)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: certificate.NotBefore.Add(time.Second),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("verify certificate chain: %v", err)
	}
}

func assertInitialLifecycleFact(
	t *testing.T,
	pool *pgxpool.Pool,
	fixture identityFixture,
	authorization Authorization,
	request CompleteRequest,
	certificate Certificate,
	signer *identityTestCA,
) {
	t.Helper()
	var ownerScopeID, caEpochID uuid.UUID
	var installationID, rotationStatus string
	var leafDERHash, lifecycleDigest []byte
	var lifecycleRevision int64
	var lifecycleRequestID uuid.UUID
	var lifecycleBoundAt time.Time
	if err := pool.QueryRow(context.Background(), `SELECT owner_scope_id,installation_id,ca_epoch_id,
		leaf_der_sha256,rotation_status,lifecycle_revision,lifecycle_request_id,
		lifecycle_request_digest,lifecycle_bound_at
		FROM node_certificates WHERE id=$1`, certificate.ID).Scan(&ownerScopeID, &installationID,
		&caEpochID, &leafDERHash, &rotationStatus, &lifecycleRevision, &lifecycleRequestID,
		&lifecycleDigest, &lifecycleBoundAt); err != nil {
		t.Fatal(err)
	}
	leaf, err := parseSinglePEMCertificate(certificate.LeafCertificatePEM)
	if err != nil {
		t.Fatal(err)
	}
	expectedLeafDERHash := sha256.Sum256(leaf.Raw)
	requestID := uuid.MustParse(request.RequestID)
	expectedDigest, err := canonicalEnrollmentLifecycleDigest(authorization.ID, fixture.nodeID,
		fixture.scopeID, installationID, caEpochID, authorization.CertificateSigningRequestSHA256,
		expectedLeafDERHash, request.GatewayWorkloadIdentity, request.GatewayInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if ownerScopeID != fixture.scopeID || installationID != "node-identity-test" || caEpochID == uuid.Nil ||
		!equalDigest(leafDERHash, expectedLeafDERHash[:]) || rotationStatus != "current" ||
		lifecycleRevision != 1 || lifecycleRequestID != requestID ||
		!equalDigest(lifecycleDigest, expectedDigest[:]) || lifecycleBoundAt.IsZero() {
		t.Fatalf("initial lifecycle fact = owner=%s installation=%q epoch=%s leaf=%x status=%q revision=%d request=%s digest=%x bound=%s",
			ownerScopeID, installationID, caEpochID, leafDERHash, rotationStatus, lifecycleRevision,
			lifecycleRequestID, lifecycleDigest, lifecycleBoundAt)
	}
	var storedCAHash []byte
	if err := pool.QueryRow(context.Background(), `SELECT ca_certificate_sha256 FROM node_ca_key_epochs WHERE id=$1`,
		caEpochID).Scan(&storedCAHash); err != nil {
		t.Fatal(err)
	}
	expectedCAHash := sha256.Sum256(signer.root.Raw)
	if !equalDigest(storedCAHash, expectedCAHash[:]) {
		t.Fatalf("CA epoch digest = %x, want %x", storedCAHash, expectedCAHash)
	}
}

func assertEnrollmentAudit(
	t *testing.T,
	pool *pgxpool.Pool,
	fixture identityFixture,
	authorization Authorization,
	request CompleteRequest,
	certificate Certificate,
) {
	t.Helper()
	var count int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events
		WHERE action='node_certificate.lifecycle.enroll' AND request_id=$1`, request.RequestID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("initial enrollment audit count = %d, want 1", count)
	}
	var scopeID uuid.UUID
	var actorUserID *uuid.UUID
	var action, resourceType, resourceID, requestID, result string
	var nodeID, authorizationID, artifactKeyID, certificateStatus, rotationStatus string
	var lifecycleRevision, authorizationRevision, currentAuthorizationRevision, streamPosition int64
	var eventHash []byte
	var payloadFields int
	if err := pool.QueryRow(context.Background(), `SELECT event.scope_id,event.actor_user_id,event.action,
		event.resource_type,event.resource_id,event.request_id,event.result,
		event.payload->>'node_id',event.payload->>'authorization_id',
		event.payload->>'artifact_encryption_key_id',event.payload->>'certificate_status',
		event.payload->>'rotation_status',(event.payload->>'lifecycle_revision')::bigint,
		(event.payload->>'authorization_revision')::bigint,event.stream_position,event.event_hash,
		(SELECT count(*) FROM jsonb_object_keys(event.payload))
		FROM audit_events event
		WHERE event.action='node_certificate.lifecycle.enroll' AND event.request_id=$1`, request.RequestID).Scan(
		&scopeID, &actorUserID, &action, &resourceType, &resourceID, &requestID, &result,
		&nodeID, &authorizationID, &artifactKeyID, &certificateStatus, &rotationStatus,
		&lifecycleRevision, &authorizationRevision, &streamPosition, &eventHash, &payloadFields); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT authorization_revision FROM node_identity_state
		WHERE node_id=$1`, fixture.nodeID).Scan(&currentAuthorizationRevision); err != nil {
		t.Fatal(err)
	}
	if scopeID != fixture.scopeID || actorUserID != nil || action != "node_certificate.lifecycle.enroll" ||
		resourceType != "node_certificate" || resourceID != certificate.ID.String() || requestID != request.RequestID ||
		result != "success" || nodeID != fixture.nodeID.String() || authorizationID != authorization.ID.String() ||
		artifactKeyID != authorization.ArtifactEncryptionKeyID || certificateStatus != "active" ||
		rotationStatus != "current" || lifecycleRevision != 1 ||
		authorizationRevision != currentAuthorizationRevision || streamPosition < 1 || len(eventHash) != 32 ||
		payloadFields != 7 {
		t.Fatalf("initial enrollment audit = scope=%s actor=%v action=%q resource=%q/%q request=%q result=%q node=%q authorization=%q artifact=%q status=%q/%q revisions=%d/%d current=%d position=%d hash=%x payload_fields=%d",
			scopeID, actorUserID, action, resourceType, resourceID, requestID, result, nodeID,
			authorizationID, artifactKeyID, certificateStatus, rotationStatus, lifecycleRevision,
			authorizationRevision, currentAuthorizationRevision, streamPosition, eventHash, payloadFields)
	}
	if err := audit.New(pool).VerifyScope(context.Background(), fixture.scopeID); err != nil {
		t.Fatalf("verify initial enrollment audit chain: %v", err)
	}
}
