//go:build integration

package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/controlinternal"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/nodeidentity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestControlInternalRuntimeEnrollmentLifecycle(t *testing.T) {
	pool := openControlRuntimeDatabase(t)
	fixture := seedControlRuntimeNode(t, pool)
	pki := newControlRuntimePKI(t)
	seedControlRuntimeCAEpoch(t, pool, pki.nodeCA)
	cfg := config.Config{
		ControlInternalGRPCAddr:    unusedControlAddress(t),
		ControlInternalServerCert:  pki.serverCertificate,
		ControlInternalServerKey:   pki.serverKey,
		ControlInternalGatewayCA:   pki.transportCA,
		ControlInternalGatewayURI:  controlinternal.DefaultGatewayWorkloadURISAN,
		NodeCACertificateChainFile: pki.nodeCA,
		NodeCAPrivateKeyFile:       pki.nodeCAKey,
		ShutdownPeriod:             2 * time.Second,
	}
	runtime, err := openControlInternalRuntime(context.Background(), cfg, pool)
	if err != nil {
		t.Fatalf("openControlInternalRuntime() error = %v", err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	serveContext, stop := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- runtime.Serve(serveContext) }()
	waitControlReady(t, runtime.Ready)

	connection := dialControlRuntime(t, runtime.Address(), pki, pki.gatewayCertificate, pki.gatewayKey)
	t.Cleanup(func() { _ = connection.Close() })
	callContext, cancelCall := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelCall()
	health, err := grpc_health_v1.NewHealthClient(connection).Check(callContext, &grpc_health_v1.HealthCheckRequest{
		Service: controlv1.ControlInternalService_ServiceDesc.ServiceName,
	})
	if err != nil || health.GetStatus() != grpc_health_v1.HealthCheckResponse_SERVING {
		t.Fatalf("ControlInternal health = (%v, %v)", health, err)
	}

	csrDER, csrPublicKey := newControlRuntimeCSR(t)
	artifactKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	requestID := uuid.NewString()
	gatewayID := uuid.NewString()
	client := controlv1.NewControlInternalServiceClient(connection)
	authorizeRequest := &controlv1.AuthorizeEnrollmentRequest{
		Request: &commonv1.RequestMetadata{
			RequestId: requestID, SentTime: timestamppb.Now(), CorrelationId: uuid.NewString(),
		},
		EnrollmentToken:              fixture.token,
		CertificateSigningRequestDer: csrDER,
		MachineFingerprintSha256:     bytes.Repeat([]byte{0x41}, sha256.Size),
		SupportedProtocolVersions: &commonv1.ProtocolVersionRange{
			Minimum: &commonv1.ProtocolVersion{Major: 1}, Maximum: &commonv1.ProtocolVersion{Major: 1},
		},
		Capabilities: &agentv1.AgentCapabilities{
			AgentVersion: "1.0.0", BuildId: "control-runtime-integration", OperatingSystem: "linux",
			Architecture: "amd64", OpenrestyVersion: "1.27.1",
			Features: []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1, ApiVersion: 1}},
		},
		GatewayInstanceId:           gatewayID,
		ArtifactEncryptionPublicKey: artifactKey.PublicKey().Bytes(),
	}
	authorization, err := client.AuthorizeEnrollment(callContext, authorizeRequest)
	if err != nil {
		t.Fatalf("AuthorizeEnrollment() error = %v", err)
	}
	if authorization.GetNodeId() != fixture.nodeID.String() || authorization.GetReplayed() ||
		authorization.GetArtifactEncryptionKeyId() == "" {
		t.Fatalf("AuthorizeEnrollment() = %#v", authorization)
	}
	replayedAuthorization, err := client.AuthorizeEnrollment(callContext, authorizeRequest)
	if err != nil || !replayedAuthorization.GetReplayed() ||
		replayedAuthorization.GetAuthorizationId() != authorization.GetAuthorizationId() {
		t.Fatalf("AuthorizeEnrollment(replay) = (%#v, %v)", replayedAuthorization, err)
	}

	completionRequestID := uuid.NewString()
	completion, err := client.CompleteEnrollment(callContext, &controlv1.CompleteEnrollmentRequest{
		Request: &commonv1.RequestMetadata{
			RequestId: completionRequestID, SentTime: timestamppb.Now(), CorrelationId: authorizeRequest.Request.CorrelationId,
		},
		AuthorizationId: authorization.GetAuthorizationId(), GatewayInstanceId: gatewayID,
	})
	if err != nil {
		t.Fatalf("CompleteEnrollment() error = %v", err)
	}
	if completion.GetNodeId() != fixture.nodeID.String() || completion.GetCertificate() == nil ||
		completion.GetArtifactEncryptionKeyId() != authorization.GetArtifactEncryptionKeyId() {
		t.Fatalf("CompleteEnrollment() = %#v", completion)
	}
	leaf := verifyControlRuntimeNodeCertificate(t, completion.GetCertificate(), pki.nodeCA, fixture.nodeID, csrPublicKey)
	leafDigest := sha256.Sum256(leaf.Raw)

	replayedCompletion, err := client.CompleteEnrollment(callContext, &controlv1.CompleteEnrollmentRequest{
		Request: &commonv1.RequestMetadata{
			RequestId: completionRequestID, SentTime: timestamppb.Now(), CorrelationId: authorizeRequest.Request.CorrelationId,
		},
		AuthorizationId: authorization.GetAuthorizationId(), GatewayInstanceId: gatewayID,
	})
	if err != nil || replayedCompletion.GetCertificate().GetSerialNumber() != completion.GetCertificate().GetSerialNumber() ||
		replayedCompletion.GetArtifactEncryptionKeyId() != completion.GetArtifactEncryptionKeyId() {
		t.Fatalf("CompleteEnrollment(replay) = (%#v, %v)", replayedCompletion, err)
	}

	_, err = client.GetNodeAuthorization(callContext, &controlv1.GetNodeAuthorizationRequest{
		Request: &commonv1.RequestMetadata{
			RequestId: uuid.NewString(), SentTime: timestamppb.Now(), CorrelationId: authorizeRequest.Request.CorrelationId,
		},
		NodeId: fixture.nodeID.String(), CertificateSerialNumber: completion.GetCertificate().GetSerialNumber(), GatewayInstanceId: uuid.NewString(),
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("GetNodeAuthorization(missing certificate digest) error = %v", err)
	}

	snapshot, err := client.GetNodeAuthorization(callContext, &controlv1.GetNodeAuthorizationRequest{
		Request: &commonv1.RequestMetadata{
			RequestId: uuid.NewString(), SentTime: timestamppb.Now(), CorrelationId: authorizeRequest.Request.CorrelationId,
		},
		NodeId: fixture.nodeID.String(), CertificateSerialNumber: completion.GetCertificate().GetSerialNumber(), GatewayInstanceId: uuid.NewString(),
		CertificateSha256: leafDigest[:],
	})
	if err != nil || !snapshot.GetConnectionAllowed() || !snapshot.GetDeploymentsAllowed() ||
		snapshot.GetAdministrativeState() != controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_ACTIVE ||
		snapshot.GetArtifactEncryptionKeyId() != completion.GetArtifactEncryptionKeyId() ||
		snapshot.GetInstallationId() == "" || snapshot.GetTenantId() != fixture.tenantID.String() ||
		len(snapshot.GetTelemetrySiteScopes()) != 1 || snapshot.GetTelemetrySiteScopes()[0].GetSiteId() != fixture.siteID.String() ||
		snapshot.GetTelemetrySiteScopes()[0].GetTenantId() != fixture.tenantID.String() ||
		snapshot.GetTelemetrySiteScopes()[0].GetConfigurationScopeId() != fixture.scopeID.String() ||
		snapshot.GetTelemetrySiteScopes()[0].GetConfigVersionId() != fixture.configVersionID.String() {
		t.Fatalf("GetNodeAuthorization() = (%#v, %v)", snapshot, err)
	}
	if fixture.scopeID == fixture.tenantID {
		t.Fatal("fixture must keep configuration scope and tenant IDs distinct")
	}
	assertControlRuntimeIdentityFacts(t, pool, fixture.nodeID, completion.GetCertificate().GetSerialNumber(), completion.GetArtifactEncryptionKeyId())

	stop()
	select {
	case err := <-serveDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve() cancellation error = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ControlInternal runtime did not stop")
	}
}

// A platform node serving two tenant configuration scopes gets, over the real
// ControlInternal RPC, no top-level tenant and every site bound to its own
// tenant and to its configuration scope (access_scopes.id, not the tenant).
func TestControlInternalRuntimeMultiScopeTelemetryAttribution(t *testing.T) {
	pool := openControlRuntimeDatabase(t)
	pki := newControlRuntimePKI(t)
	seedControlRuntimeCAEpoch(t, pool, pki.nodeCA)
	runtime, err := openControlInternalRuntime(context.Background(), config.Config{
		ControlInternalGRPCAddr:    unusedControlAddress(t),
		ControlInternalServerCert:  pki.serverCertificate,
		ControlInternalServerKey:   pki.serverKey,
		ControlInternalGatewayCA:   pki.transportCA,
		ControlInternalGatewayURI:  controlinternal.DefaultGatewayWorkloadURISAN,
		NodeCACertificateChainFile: pki.nodeCA,
		NodeCAPrivateKeyFile:       pki.nodeCAKey,
		ShutdownPeriod:             2 * time.Second,
	}, pool)
	if err != nil {
		t.Fatalf("openControlInternalRuntime() error = %v", err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	serveContext, stop := context.WithCancel(context.Background())
	t.Cleanup(stop)
	go func() { _ = runtime.Serve(serveContext) }()
	waitControlReady(t, runtime.Ready)
	connection := dialControlRuntime(t, runtime.Address(), pki, pki.gatewayCertificate, pki.gatewayKey)
	t.Cleanup(func() { _ = connection.Close() })
	client := controlv1.NewControlInternalServiceClient(connection)
	callContext, cancelCall := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelCall()

	nodeID, token := seedControlRuntimePlatformNode(t, pool)
	csrDER, _ := newControlRuntimeCSR(t)
	artifactKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	gatewayID := uuid.NewString()
	authorization, err := client.AuthorizeEnrollment(callContext, &controlv1.AuthorizeEnrollmentRequest{
		Request:         &commonv1.RequestMetadata{RequestId: uuid.NewString(), SentTime: timestamppb.Now(), CorrelationId: uuid.NewString()},
		EnrollmentToken: token, CertificateSigningRequestDer: csrDER,
		MachineFingerprintSha256: bytes.Repeat([]byte{0x42}, sha256.Size),
		SupportedProtocolVersions: &commonv1.ProtocolVersionRange{
			Minimum: &commonv1.ProtocolVersion{Major: 1}, Maximum: &commonv1.ProtocolVersion{Major: 1},
		},
		Capabilities: &agentv1.AgentCapabilities{
			AgentVersion: "1.0.0", BuildId: "control-runtime-multi-scope", OperatingSystem: "linux",
			Architecture: "amd64", OpenrestyVersion: "1.27.1",
			Features: []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1, ApiVersion: 1}},
		},
		GatewayInstanceId: gatewayID, ArtifactEncryptionPublicKey: artifactKey.PublicKey().Bytes(),
	})
	if err != nil {
		t.Fatalf("AuthorizeEnrollment() error = %v", err)
	}
	completion, err := client.CompleteEnrollment(callContext, &controlv1.CompleteEnrollmentRequest{
		Request:         &commonv1.RequestMetadata{RequestId: uuid.NewString(), SentTime: timestamppb.Now(), CorrelationId: uuid.NewString()},
		AuthorizationId: authorization.GetAuthorizationId(), GatewayInstanceId: gatewayID,
	})
	if err != nil {
		t.Fatalf("CompleteEnrollment() error = %v", err)
	}
	block, _ := pem.Decode(completion.GetCertificate().GetLeafCertificatePem())
	if block == nil {
		t.Fatal("invalid node leaf PEM")
	}
	leafDigest := sha256.Sum256(block.Bytes)

	tenants := []controlRuntimeNodeFixture{
		seedControlRuntimeTenantConfig(t, pool, nodeID),
		seedControlRuntimeTenantConfig(t, pool, nodeID),
	}
	snapshot, err := client.GetNodeAuthorization(callContext, &controlv1.GetNodeAuthorizationRequest{
		Request: &commonv1.RequestMetadata{RequestId: uuid.NewString(), SentTime: timestamppb.Now(), CorrelationId: uuid.NewString()},
		NodeId:  nodeID.String(), CertificateSerialNumber: completion.GetCertificate().GetSerialNumber(),
		GatewayInstanceId: uuid.NewString(), CertificateSha256: leafDigest[:],
	})
	if err != nil || !snapshot.GetConnectionAllowed() || snapshot.GetTenantId() != "" ||
		len(snapshot.GetTelemetrySiteScopes()) != len(tenants) {
		t.Fatalf("GetNodeAuthorization(multi-scope) = (%v, %v)", snapshot, err)
	}
	want := make(map[string]controlRuntimeNodeFixture, len(tenants))
	for _, tenant := range tenants {
		if tenant.scopeID == tenant.tenantID {
			t.Fatal("fixture must keep configuration scope and tenant IDs distinct")
		}
		want[tenant.siteID.String()] = tenant
	}
	for _, site := range snapshot.GetTelemetrySiteScopes() {
		tenant, ok := want[site.GetSiteId()]
		if !ok || site.GetTenantId() != tenant.tenantID.String() ||
			site.GetConfigurationScopeId() != tenant.scopeID.String() ||
			site.GetConfigVersionId() != tenant.configVersionID.String() {
			t.Fatalf("multi-scope telemetry site = %v, want tenant %s scope %s", site, tenant.tenantID, tenant.scopeID)
		}
		delete(want, site.GetSiteId())
	}
}

type controlRuntimeNodeFixture struct {
	nodeID, tenantID, scopeID, siteID, configVersionID uuid.UUID
	token                                              string
}

func seedControlRuntimeNode(t *testing.T, pool *pgxpool.Pool) controlRuntimeNodeFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	tenantID, scopeID, userID, nodeID, siteID, configVersionID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	username := "control-runtime-" + userID.String()
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	token := base64.RawURLEncoding.EncodeToString(secret)
	tokenHash := sha256.Sum256([]byte(token))
	snapshot, snapshotDigest := controlRuntimeTelemetrySnapshotFor(t, scopeID, configVersionID, siteID, "control-runtime.example.test")
	transaction, err := pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback(context.Background())
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tenants (id,display_name) VALUES ($1,$2)`, []any{tenantID, "Control runtime tenant"}},
		{`INSERT INTO access_scopes (id,kind,tenant_id) VALUES ($1,'tenant',$2)`, []any{scopeID, tenantID}},
		{`INSERT INTO users (id,username,display_name,password_hash) VALUES ($1,$2,'Control runtime user','unused')`, []any{userID, username}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{scopeID, userID}},
		{`INSERT INTO nodes (id,scope_id,display_id,name,admin_state,created_by_user_id,created_at,updated_at)
			  VALUES ($1,$2,1,$3,'pending',$4,$5,$5)`, []any{nodeID, scopeID, "control-runtime-node-" + nodeID.String()[:8], userID, now}},
		{`INSERT INTO sites
			  (id,scope_id,display_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,updated_by_user_id)
			  VALUES($1,$2,1,$3,$4,ARRAY['192.0.2.20:80'],ARRAY['192.0.2.20'],$3,$3)`,
			[]any{siteID, scopeID, userID, "control-runtime-" + siteID.String()[:8] + ".example.test"}},
		{`INSERT INTO site_origin_pools(site_id) VALUES($1)`, []any{siteID}},
		{`INSERT INTO site_origins(site_id,position,host,port,weight,enabled)
			  VALUES($1,1,'192.0.2.20',80,1,true)`, []any{siteID}},
		{`INSERT INTO config_versions
			  (id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,generator_name,generator_version,
			   status,idempotency_key,request_digest,created_at,published_at)
			  VALUES($1,$2,$3,$4,'control-runtime','1','releasable',$5,$6,$7,$7)`,
			[]any{configVersionID, scopeID, snapshot, snapshotDigest[:], "control-runtime-" + configVersionID.String(), bytes.Repeat([]byte{0x31}, sha256.Size), now}},
		{`INSERT INTO node_config_state
			  (node_id,configuration_scope_id,current_config_version_id,revision,updated_at)
			  VALUES($1,$2,$3,1,$4)`, []any{nodeID, scopeID, configVersionID, now}},
		{`INSERT INTO node_enrollment_tokens
		  (id,node_id,purpose,token_hash,created_by_user_id,created_at,expires_at)
		  VALUES ($1,$2,'initial_enrollment',$3,$4,$5,$6)`, []any{uuid.New(), nodeID, tokenHash[:], userID, now, now.Add(time.Hour)}},
	}
	for _, statement := range statements {
		if _, err := transaction.Exec(context.Background(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := transaction.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	return controlRuntimeNodeFixture{nodeID: nodeID, tenantID: tenantID, scopeID: scopeID, siteID: siteID,
		configVersionID: configVersionID, token: token}
}

func seedControlRuntimePlatformNode(t *testing.T, pool *pgxpool.Pool) (uuid.UUID, string) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	var scopeID, userID uuid.UUID
	if err := pool.QueryRow(context.Background(), `SELECT scope.id,membership.user_id
		FROM access_scopes scope JOIN memberships membership ON membership.scope_id=scope.id
		WHERE scope.kind='platform' AND membership.status='active' ORDER BY scope.id,membership.user_id LIMIT 1`).Scan(&scopeID, &userID); err != nil {
		t.Fatal(err)
	}
	var displayID int64
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO node_display_id_sequences(scope_id,next_value,updated_at) VALUES($1,2,$2)
		ON CONFLICT(scope_id) DO UPDATE
		SET next_value=node_display_id_sequences.next_value+1,updated_at=EXCLUDED.updated_at
		RETURNING next_value-1`, scopeID, now).Scan(&displayID); err != nil {
		t.Fatal(err)
	}
	nodeID := uuid.New()
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	token := base64.RawURLEncoding.EncodeToString(secret)
	tokenHash := sha256.Sum256([]byte(token))
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO nodes (id,scope_id,display_id,name,admin_state,created_by_user_id,created_at,updated_at)
			  VALUES ($1,$2,$3,$4,'pending',$5,$6,$6)`, []any{nodeID, scopeID, displayID, "control-runtime-platform-" + nodeID.String()[:8], userID, now}},
		{`INSERT INTO node_enrollment_tokens
			  (id,node_id,purpose,token_hash,created_by_user_id,created_at,expires_at)
			  VALUES ($1,$2,'initial_enrollment',$3,$4,$5,$6)`, []any{uuid.New(), nodeID, tokenHash[:], userID, now, now.Add(time.Hour)}},
	} {
		if _, err := pool.Exec(context.Background(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	return nodeID, token
}

// seedControlRuntimeTenantConfig creates a tenant whose configuration scope ID
// differs from its tenant ID and makes nodeID serve one released version of it.
func seedControlRuntimeTenantConfig(t *testing.T, pool *pgxpool.Pool, nodeID uuid.UUID) controlRuntimeNodeFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	tenantID, scopeID, userID, siteID, configVersionID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	snapshot, snapshotDigest := controlRuntimeTelemetrySnapshotFor(t, scopeID, configVersionID, siteID, "control-runtime-"+siteID.String()[:8]+".example.test")
	transaction, err := pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback(context.Background())
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tenants (id,display_name) VALUES ($1,$2)`, []any{tenantID, "Control runtime tenant " + tenantID.String()[:8]}},
		{`INSERT INTO access_scopes (id,kind,tenant_id) VALUES ($1,'tenant',$2)`, []any{scopeID, tenantID}},
		{`INSERT INTO users (id,username,display_name,password_hash) VALUES ($1,$2,'Control runtime user','unused')`,
			[]any{userID, "control-runtime-" + userID.String()}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{scopeID, userID}},
		{`INSERT INTO sites
			  (id,scope_id,display_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,updated_by_user_id)
			  VALUES($1,$2,1,$3,$4,ARRAY['192.0.2.20:80'],ARRAY['192.0.2.20'],$3,$3)`,
			[]any{siteID, scopeID, userID, "control-runtime-" + siteID.String()[:8] + ".example.test"}},
		{`INSERT INTO site_origin_pools(site_id) VALUES($1)`, []any{siteID}},
		{`INSERT INTO site_origins(site_id,position,host,port,weight,enabled)
			  VALUES($1,1,'192.0.2.20',80,1,true)`, []any{siteID}},
		{`INSERT INTO config_versions
			  (id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,generator_name,generator_version,
			   status,idempotency_key,request_digest,created_at,published_at)
			  VALUES($1,$2,$3,$4,'control-runtime','1','releasable',$5,$6,$7,$7)`,
			[]any{configVersionID, scopeID, snapshot, snapshotDigest[:], "control-runtime-" + configVersionID.String(), bytes.Repeat([]byte{0x31}, sha256.Size), now}},
		{`INSERT INTO node_config_state
			  (node_id,configuration_scope_id,current_config_version_id,revision,updated_at)
			  VALUES($1,$2,$3,1,$4)`, []any{nodeID, scopeID, configVersionID, now}},
	} {
		if _, err := transaction.Exec(context.Background(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := transaction.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	return controlRuntimeNodeFixture{nodeID: nodeID, tenantID: tenantID, scopeID: scopeID, siteID: siteID, configVersionID: configVersionID}
}

// controlRuntimeTelemetrySnapshotFor is a published site runtime v2 document
// with one plain HTTP listener for siteID (the fields telemetry reads).
func controlRuntimeTelemetrySnapshotFor(t *testing.T, scopeID, configVersionID, siteID uuid.UUID, domain string) ([]byte, [sha256.Size]byte) {
	t.Helper()
	snapshot, err := json.Marshal(map[string]any{
		"schema": "cdnca.edge.site-runtime/v2", "configuration_scope_id": scopeID.String(), "source_revision": 1,
		"config_version_id": configVersionID.String(),
		"sites": []map[string]any{{"id": siteID.String(), "revision": 1, "domains": []string{domain},
			"listeners": []map[string]any{{"id": "http", "position": 0, "address_family": "ipv4", "port": 80,
				"protocols": []string{"http1"}}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot, sha256.Sum256(snapshot)
}

func seedControlRuntimeCAEpoch(t *testing.T, pool *pgxpool.Pool, certificateFile string) {
	t.Helper()
	encoded, err := os.ReadFile(certificateFile)
	if err != nil {
		t.Fatal(err)
	}
	block, remainder := pem.Decode(encoded)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(remainder)) != 0 {
		t.Fatal("invalid node CA certificate fixture")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	certificateHash := sha256.Sum256(certificate.Raw)
	publicKeyHash := sha256.Sum256(publicKeyDER)
	scopeID, userID := uuid.New(), uuid.New()
	now := time.Now().UTC().Truncate(time.Microsecond)
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, []any{scopeID}},
		{`INSERT INTO users(id,username,display_name,password_hash)
		  VALUES($1,$2,'Control runtime CA operator','test-only')`, []any{userID, "control-runtime-ca-" + userID.String()[:12]}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{scopeID, userID}},
		{`INSERT INTO control_installation_entitlement(installation_id) VALUES('control-runtime-test')`, nil},
		{`INSERT INTO node_ca_key_epochs(
			id,installation_id,epoch,key_id,ca_certificate_pem,ca_certificate_sha256,public_key_sha256,
			not_before,not_after,status,request_id,request_digest,created_by_scope_id,created_by_user_id,created_at)
		  VALUES($1,'control-runtime-test',1,'control-runtime-ca',$2,$3,$4,$5,$6,'active',$7,$8,$9,$10,$11)`,
			[]any{uuid.New(), encoded, certificateHash[:], publicKeyHash[:], certificate.NotBefore, certificate.NotAfter,
				uuid.New(), bytes.Repeat([]byte{0x62}, sha256.Size), scopeID, userID, now}},
	}
	for _, statement := range statements {
		if _, err := pool.Exec(context.Background(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
}

func newControlRuntimeCSR(t *testing.T) ([]byte, ed25519.PublicKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return der, publicKey
}

func verifyControlRuntimeNodeCertificate(
	t *testing.T,
	bundle *agentv1.CertificateBundle,
	rootFile string,
	nodeID uuid.UUID,
	csrPublicKey ed25519.PublicKey,
) *x509.Certificate {
	t.Helper()
	block, rest := pem.Decode(bundle.GetLeafCertificatePem())
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatal("invalid node leaf PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	rootPEM, err := os.ReadFile(rootFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		t.Fatal("append node CA")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("verify node certificate: %v", err)
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != nodeidentity.NodeSPIFFEPrefix+nodeID.String() {
		t.Fatalf("node certificate URI SAN = %v", leaf.URIs)
	}
	publicKey, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok || !bytes.Equal(publicKey, csrPublicKey) {
		t.Fatal("node certificate public key differs from CSR")
	}
	if bundle.GetSerialNumber() != strings.ToLower(leaf.SerialNumber.Text(16)) {
		t.Fatalf("bundle serial = %q, leaf serial = %s", bundle.GetSerialNumber(), leaf.SerialNumber)
	}
	return leaf
}

func assertControlRuntimeIdentityFacts(t *testing.T, pool *pgxpool.Pool, nodeID uuid.UUID, serialNumber, keyID string) {
	t.Helper()
	var certificateCount, keyCount int
	if err := pool.QueryRow(context.Background(), `
		SELECT
			(SELECT count(*) FROM node_certificates WHERE node_id=$1 AND serial_number=$2 AND status='active'),
			(SELECT count(*) FROM node_artifact_encryption_keys WHERE node_id=$1 AND id=$3 AND status='active')`,
		nodeID, serialNumber, keyID).Scan(&certificateCount, &keyCount); err != nil {
		t.Fatal(err)
	}
	if certificateCount != 1 || keyCount != 1 {
		t.Fatalf("persisted identity facts certificate=%d artifact_key=%d", certificateCount, keyCount)
	}
}

func openControlRuntimeDatabase(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "control_runtime_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop test schema: %v", err)
		}
	})
	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	poolConfig.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		t.Fatal(err)
	}
	return pool
}
