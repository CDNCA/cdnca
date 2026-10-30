//go:build integration

package nodeidentity

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
)

func TestNodeSessionFactsPostgres(t *testing.T) {
	pool := openIdentityTestDatabase(t, true)
	now := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	clock := &identityTestClock{value: now}
	service := newIdentityTestService(t, pool, newIdentityTestCA(t, now), clock)
	fixture := seedIdentityPlatformNode(t, pool, now, "pending", "initial_enrollment")
	authorize := validAuthorizeRequest(t, testCSR(t, false))
	authorize.EnrollmentToken = fixture.token
	auth, err := service.Authorize(t.Context(), authorize)
	if err != nil {
		t.Fatal(err)
	}
	completion, err := service.Complete(t.Context(), CompleteRequest{RequestID: uuid.NewString(), AuthorizationID: auth.ID, GatewayWorkloadIdentity: authorize.GatewayWorkloadIdentity, GatewayInstanceID: authorize.GatewayInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	certSHA := certificateDERDigest(t, completion.Certificate)
	facts := &controlv1.GatewaySessionFactsV1{SchemaVersion: 1, NodeId: fixture.nodeID.String(), SessionEpoch: 1,
		CertificateSha256: certSHA[:], SelectedProtocolVersion: &commonv1.ProtocolVersion{Major: 1}, ArtifactEncryptionKeyId: completion.ArtifactEncryptionKeyID,
		Capabilities: &agentv1.AgentCapabilities{AgentVersion: "1.0.22", BuildId: "2166adcd3719d10e69ce427c2ca6af59d572792f", OperatingSystem: "linux", Architecture: "amd64", Features: []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE, ApiVersion: 1}}}}
	request := GetAuthorizationRequest{NodeID: fixture.nodeID, CertificateSerialNumber: completion.Certificate.SerialNumber, CertificateSHA256: certSHA, GatewayWorkloadIdentity: authorize.GatewayWorkloadIdentity, GatewayInstanceID: uuid.NewString(), SessionFacts: facts}
	clock.value = now.Add(6 * time.Minute)
	snapshot, err := service.GetAuthorization(t.Context(), request)
	encoded, _ := (proto.MarshalOptions{Deterministic: true}).Marshal(facts)
	digest := sha256.Sum256(encoded)
	if err != nil || !snapshot.ConnectionAllowed || !bytes.Equal(snapshot.SessionFactsSHA256, digest[:]) {
		t.Fatalf("post-enrollment session receipt: allowed=%v receipt=%x err=%v", snapshot.ConnectionAllowed, snapshot.SessionFactsSHA256, err)
	}
	t.Run("tenant-node-preserves-authenticated-connect", func(t *testing.T) {
		issuedAt := clock.now()
		tenant := seedIdentityNode(t, pool, issuedAt, "pending", "initial_enrollment")
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		request := validAuthorizeRequest(t, testCSR(t, false))
		request.RequestID, request.EnrollmentToken = uuid.NewString(), tenant.token
		request.ArtifactEncryptionPublicKey = key.PublicKey().Bytes()
		authorized, err := service.Authorize(t.Context(), request)
		if err != nil {
			t.Fatal(err)
		}
		completed, err := service.Complete(t.Context(), CompleteRequest{RequestID: uuid.NewString(), AuthorizationID: authorized.ID, GatewayWorkloadIdentity: request.GatewayWorkloadIdentity, GatewayInstanceID: request.GatewayInstanceID})
		if err != nil {
			t.Fatal(err)
		}
		clock.set(issuedAt.Add(6 * time.Minute))
		defer clock.set(issuedAt)
		certHash := certificateDERDigest(t, completed.Certificate)
		tenantFacts := proto.Clone(facts).(*controlv1.GatewaySessionFactsV1)
		tenantFacts.NodeId, tenantFacts.CertificateSha256, tenantFacts.ArtifactEncryptionKeyId = tenant.nodeID.String(), certHash[:], completed.ArtifactEncryptionKeyID
		value, err := service.GetAuthorization(t.Context(), GetAuthorizationRequest{NodeID: tenant.nodeID, CertificateSerialNumber: completed.Certificate.SerialNumber, CertificateSHA256: certHash, GatewayWorkloadIdentity: request.GatewayWorkloadIdentity, GatewayInstanceID: request.GatewayInstanceID, SessionFacts: tenantFacts})
		if err != nil || !value.ConnectionAllowed || !value.DeploymentsAllowed || value.TenantID != tenant.tenantID || len(value.SessionFactsSHA256) != 32 {
			t.Fatalf("tenant authenticated Connect: allowed=%v receipt=%d err=%v", value.ConnectionAllowed, len(value.SessionFactsSHA256), err)
		}
	})
	clone := func() GetAuthorizationRequest {
		result := request
		result.SessionFacts = proto.Clone(facts).(*controlv1.GatewaySessionFactsV1)
		return result
	}
	count := func() int {
		var total int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM node_session_capabilities WHERE node_id=$1`, fixture.nodeID).Scan(&total); err != nil {
			t.Fatal(err)
		}
		return total
	}
	t.Run("exact-replay-and-read-only", func(t *testing.T) {
		replay, err := service.GetAuthorization(t.Context(), request)
		if err != nil || !bytes.Equal(replay.SessionFactsSHA256, digest[:]) || count() != 1 {
			t.Fatalf("replay %x %v", replay.SessionFactsSHA256, err)
		}
		read := request
		read.SessionFacts = nil
		value, err := service.GetAuthorization(t.Context(), read)
		if err != nil || !value.ConnectionAllowed || len(value.SessionFactsSHA256) != 0 || count() != 1 {
			t.Fatalf("legacy read changed session evidence: %v", err)
		}
	})
	for name, mutate := range map[string]func(*GetAuthorizationRequest){
		"wrong-node":    func(r *GetAuthorizationRequest) { r.SessionFacts.NodeId = uuid.NewString() },
		"wrong-cert":    func(r *GetAuthorizationRequest) { r.SessionFacts.CertificateSha256[0] ^= 1 },
		"unknown-facts": func(r *GetAuthorizationRequest) { r.SessionFacts.ProtoReflect().SetUnknown([]byte{0x80, 0x06, 1}) },
		"unknown-capabilities": func(r *GetAuthorizationRequest) {
			r.SessionFacts.Capabilities.ProtoReflect().SetUnknown([]byte{0x80, 0x06, 1})
		},
		"unknown-feature": func(r *GetAuthorizationRequest) { r.SessionFacts.Capabilities.Features[0].Name = 999 },
		"duplicate-feature": func(r *GetAuthorizationRequest) {
			r.SessionFacts.Capabilities.Features = append(r.SessionFacts.Capabilities.Features, r.SessionFacts.Capabilities.Features[0])
		},
		"zero-epoch":    func(r *GetAuthorizationRequest) { r.SessionFacts.SessionEpoch = 0 },
		"wrong-schema":  func(r *GetAuthorizationRequest) { r.SessionFacts.SchemaVersion = 2 },
		"empty-version": func(r *GetAuthorizationRequest) { r.SessionFacts.Capabilities.AgentVersion = "" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := clone()
			mutate(&bad)
			if _, err := service.GetAuthorization(t.Context(), bad); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("invalid facts accepted: %v", err)
			}
			if count() != 1 {
				t.Fatal("invalid facts wrote")
			}
		})
	}
	for name, mutate := range map[string]func(*GetAuthorizationRequest){
		"changed-caps":     func(r *GetAuthorizationRequest) { r.SessionFacts.Capabilities.AgentVersion = "1.0.23" },
		"changed-reporter": func(r *GetAuthorizationRequest) { r.GatewayInstanceID = uuid.NewString() },
	} {
		t.Run(name, func(t *testing.T) {
			bad := clone()
			mutate(&bad)
			if _, err := service.GetAuthorization(t.Context(), bad); !errors.Is(err, ErrIdempotencyConflict) {
				t.Fatalf("conflicting replay accepted: %v", err)
			}
		})
	}
	t.Run("protocol-and-key-authority", func(t *testing.T) {
		for _, mutate := range []func(*GetAuthorizationRequest){func(r *GetAuthorizationRequest) { r.SessionFacts.SelectedProtocolVersion.Major = 2 }, func(r *GetAuthorizationRequest) { r.SessionFacts.ArtifactEncryptionKeyId = "x25519:wrong" }} {
			bad := clone()
			mutate(&bad)
			if _, err := service.GetAuthorization(t.Context(), bad); !errors.Is(err, ErrNodeStateDenied) {
				t.Fatalf("wrong authority accepted: %v", err)
			}
		}
	})
	t.Run("expired-certificate-cannot-replay", func(t *testing.T) {
		clock.value = now.Add(DefaultCertificateTTL + time.Hour)
		defer func() { clock.value = now.Add(6 * time.Minute) }()
		if _, err := service.GetAuthorization(t.Context(), request); !errors.Is(err, ErrNodeStateDenied) {
			t.Fatalf("expired replay: %v", err)
		}
	})
	t.Run("reconnect-fences-older-registration", func(t *testing.T) {
		next := clone()
		next.SessionFacts.SessionEpoch = 2
		next.SessionFacts.Capabilities.AgentVersion = "1.0.23"
		if _, err := service.GetAuthorization(t.Context(), next); err != nil {
			t.Fatal(err)
		}
		if _, err := service.GetAuthorization(t.Context(), request); !errors.Is(err, ErrIdempotencyConflict) {
			t.Fatalf("stale epoch: %v", err)
		}
		if count() != 2 {
			t.Fatal("reconnect lost old immutable evidence")
		}
		request = next
		facts = next.SessionFacts
	})
	t.Run("append-only-and-safe-down", func(t *testing.T) {
		var pgError *pgconn.PgError
		for _, sql := range []string{`UPDATE node_session_capabilities SET registered_at=now()`, `DELETE FROM node_session_capabilities`, `TRUNCATE node_session_capabilities`} {
			_, err := pool.Exec(t.Context(), sql)
			if !errors.As(err, &pgError) || pgError.Code != "P2771" {
				t.Fatalf("immutable evidence: %v", err)
			}
		}
		// 277 拒绝丢弃会话证据的回滚闸门由 TestNodeSessionCapabilitiesMigration277 在 277 发布头上验证；
		// 发布头之后的迁移（含不可回滚的 268 之后各号）不在这里逐个回滚。
	})
	t.Run("concurrent-same-epoch-cannot-replace-winner", func(t *testing.T) {
		type result struct {
			request GetAuthorizationRequest
			err     error
		}
		results := make(chan result, 2)
		start := make(chan struct{})
		before := count()
		for _, version := range []string{"1.0.24", "1.0.25"} {
			candidate := clone()
			candidate.SessionFacts.SessionEpoch++
			candidate.SessionFacts.Capabilities.AgentVersion = version
			go func() {
				<-start
				_, err := service.GetAuthorization(t.Context(), candidate)
				results <- result{candidate, err}
			}()
		}
		close(start)
		var winner, loser GetAuthorizationRequest
		for range 2 {
			result := <-results
			if result.err == nil {
				if winner.SessionFacts != nil {
					t.Fatal("conflicting same epoch had two winners")
				}
				winner = result.request
			} else if errors.Is(result.err, ErrPersistence) || errors.Is(result.err, ErrIdempotencyConflict) {
				loser = result.request
			} else {
				t.Fatal(result.err)
			}
		}
		if winner.SessionFacts == nil || loser.SessionFacts == nil || count() != before+1 {
			t.Fatal("concurrent session evidence was lost or duplicated")
		}
		if _, err := service.GetAuthorization(t.Context(), loser); !errors.Is(err, ErrIdempotencyConflict) {
			t.Fatalf("loser replay replaced winner: %v", err)
		}
		request, facts = winner, winner.SessionFacts
	})
	t.Run("postgres-connection-loss-rolls-back-and-reconnects", func(t *testing.T) {
		config := pool.Config()
		config.MaxConns, config.MinConns = 1, 0
		config.ConnConfig.RuntimeParams["application_name"] = "session-facts-fault-" + uuid.NewString()
		faultPool, err := pgxpool.NewWithConfig(t.Context(), config)
		if err != nil {
			t.Fatal(err)
		}
		defer faultPool.Close()
		var pid uint32
		if err := faultPool.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
			t.Fatal(err)
		}
		faultService, err := NewService(NewStore(faultPool), service.signer, service.config)
		if err != nil {
			t.Fatal(err)
		}
		block, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer block.Rollback(context.Background())
		if _, err := block.Exec(t.Context(), `LOCK TABLE node_session_capabilities IN ACCESS EXCLUSIVE MODE`); err != nil {
			t.Fatal(err)
		}
		next := clone()
		next.SessionFacts.SessionEpoch++
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		finished := make(chan error, 1)
		go func() { _, err := faultService.GetAuthorization(ctx, next); finished <- err }()
		for {
			var waiting bool
			if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND application_name=$2 AND wait_event_type='Lock')`, pid, config.ConnConfig.RuntimeParams["application_name"]).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
			if waiting {
				break
			}
			select {
			case <-ctx.Done():
				t.Fatal("dedicated test connection did not enter controlled lock wait")
			case <-time.After(10 * time.Millisecond):
			}
		}
		var terminated bool
		if err := pool.QueryRow(ctx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE pid=$1 AND application_name=$2 AND wait_event_type='Lock'`, pid, config.ConnConfig.RuntimeParams["application_name"]).Scan(&terminated); err != nil || !terminated {
			t.Fatalf("terminate only dedicated test connection: %v", err)
		}
		if err := <-finished; !errors.Is(err, ErrPersistence) {
			t.Fatalf("lost PostgreSQL connection granted receipt: %v", err)
		}
		if err := block.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		before := count()
		if value, err := faultService.GetAuthorization(ctx, next); err != nil || len(value.SessionFactsSHA256) != 32 || count() != before+1 {
			t.Fatalf("recovered connection did not append exactly one fact: %v", err)
		}
		request, facts = next, next.SessionFacts
	})
	t.Run("renewal-preserves-overlap-traffic-not-upgrade-authority", func(t *testing.T) {
		clock.set(completion.Certificate.RenewalAt)
		certificate, err := service.Renew(t.Context(), RenewRequest{RequestID: uuid.NewString(), NodeID: fixture.nodeID, CurrentSerialNumber: request.CertificateSerialNumber, CurrentCertificateSHA256: request.CertificateSHA256, CertificateSigningRequestDER: testCSR(t, false), GatewayWorkloadIdentity: request.GatewayWorkloadIdentity, GatewayInstanceID: request.GatewayInstanceID})
		if err != nil {
			t.Fatal(err)
		}
		read := request
		read.SessionFacts = nil
		if value, err := service.GetAuthorization(t.Context(), read); err != nil || !value.ConnectionAllowed || value.DeploymentsAllowed {
			t.Fatalf("overlap traffic boundary: connection=%v deployment=%v err=%v", value.ConnectionAllowed, value.DeploymentsAllowed, err)
		}
		before := count()
		if value, err := service.GetAuthorization(t.Context(), request); err != nil || len(value.SessionFactsSHA256) != 0 ||
			value.DeploymentsAllowed || count() != before {
			t.Fatalf("old overlap certificate kept upgrade authority: receipt=%d err=%v", len(value.SessionFactsSHA256), err)
		}
		request.CertificateSerialNumber, request.CertificateSHA256 = certificate.SerialNumber, certificateDERDigest(t, certificate)
		request.SessionFacts = proto.Clone(facts).(*controlv1.GatewaySessionFactsV1)
		request.SessionFacts.SessionEpoch++
		request.SessionFacts.CertificateSha256 = bytes.Clone(request.CertificateSHA256[:])
		if value, err := service.GetAuthorization(t.Context(), request); err != nil || len(value.SessionFactsSHA256) != 32 {
			t.Fatalf("renewed current certificate rejected: %v", err)
		}
		completion.Certificate = certificate
	})
	// A node whose deployments are paused for a long time (draining) still
	// records its current Agent capabilities, without upgrade authority.
	t.Run("paused-deployments-refresh-capabilities", func(t *testing.T) {
		if _, err := pool.Exec(t.Context(), `UPDATE nodes SET admin_state='draining',revision=revision+1 WHERE id=$1`, fixture.nodeID); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := pool.Exec(context.Background(), `UPDATE nodes SET admin_state='active',revision=revision+1 WHERE id=$1`, fixture.nodeID); err != nil {
				t.Fatal(err)
			}
		}()
		next := request
		next.SessionFacts = proto.Clone(request.SessionFacts).(*controlv1.GatewaySessionFactsV1)
		next.SessionFacts.SessionEpoch++
		next.SessionFacts.Capabilities.Features = append(next.SessionFacts.Capabilities.Features,
			&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_SIGNER_TRUST, ApiVersion: 1})
		before := count()
		value, err := service.GetAuthorization(t.Context(), next)
		if err != nil || value.DeploymentsAllowed || !value.ConnectionAllowed || len(value.SessionFactsSHA256) != 32 || count() != before+1 {
			t.Fatalf("paused node facts: deployments=%v receipt=%d err=%v", value.DeploymentsAllowed, len(value.SessionFactsSHA256), err)
		}
		var snapshot []byte
		if err := pool.QueryRow(t.Context(), `SELECT capabilities_snapshot FROM node_session_capabilities WHERE node_id=$1 ORDER BY session_epoch DESC LIMIT 1`, fixture.nodeID).Scan(&snapshot); err != nil {
			t.Fatal(err)
		}
		var stored agentv1.AgentCapabilities
		if err := proto.Unmarshal(snapshot, &stored); err != nil || len(stored.Features) != 2 {
			t.Fatalf("paused node capabilities not refreshed: %v %v", stored.Features, err)
		}
		request = next
	})
	t.Run("revoked-certificate-cannot-replay", func(t *testing.T) {
		if err := service.Revoke(t.Context(), RevokeRequest{RequestID: uuid.NewString(), NodeID: fixture.nodeID, SerialNumber: completion.Certificate.SerialNumber, Reason: "session facts test"}); err != nil {
			t.Fatal(err)
		}
		if _, err := service.GetAuthorization(t.Context(), request); !errors.Is(err, ErrNodeStateDenied) {
			t.Fatalf("revoked replay: %v", err)
		}
	})
}

func TestNodeSessionCapabilitiesMigration277(t *testing.T) {
	// 只装载 1..277：空表可回滚，有会话证据时 down 必须以 P2772 拒绝且不改账本。
	const head = 277
	pool := openIdentityTestDatabase(t, false)
	ctx := t.Context()
	if err := databasetest.MigrateThrough(ctx, pool, "up", head); err != nil {
		t.Fatal(err)
	}
	if err := databasetest.MigrateThrough(ctx, pool, "down", head); err != nil {
		t.Fatalf("empty 277 rollback: %v", err)
	}
	if identityMigrationVersion(t, pool) != head-1 {
		t.Fatal("empty rollback did not reach 276")
	}
	if err := databasetest.MigrateThrough(ctx, pool, "up", head); err != nil {
		t.Fatal(err)
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `SET session_replication_role = replica`); err != nil {
		conn.Release()
		t.Fatal(err)
	}
	digest := make([]byte, 32)
	_, insertErr := conn.Exec(ctx, `INSERT INTO node_session_capabilities(
		node_id,session_epoch,certificate_id,certificate_sha256,artifact_key_id,
		selected_protocol_major,selected_protocol_minor,capabilities_snapshot,capabilities_sha256,
		facts_snapshot,facts_sha256,gateway_workload_identity,gateway_instance_id,registered_at
	) VALUES($1,1,$2,$3,'artifact-key',1,0,'\x01',$3,'\x01',$3,'gateway','gateway-1',now())`,
		uuid.New(), uuid.New(), digest)
	_, resetErr := conn.Exec(ctx, `SET session_replication_role = origin`)
	conn.Release()
	if insertErr != nil || resetErr != nil {
		t.Fatalf("seed session evidence: insert=%v reset=%v", insertErr, resetErr)
	}
	var pgError *pgconn.PgError
	if err := databasetest.MigrateThrough(ctx, pool, "down", head); !errors.As(err, &pgError) || pgError.Code != "P2772" {
		t.Fatalf("unsafe down: %v", err)
	}
	if identityMigrationVersion(t, pool) != head {
		t.Fatal("refused down modified the ledger")
	}
}
