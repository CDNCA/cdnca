//go:build integration

package edgeautopublish_test

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish/capabilitytest"
	"github.com/google/uuid"
)

func TestCertificatePublicationExpiredEnrollmentAuthorization(t *testing.T) {
	pool := openAutomaticDatabase(t)
	actor := seedAutomaticIntegrationIdentity(t, pool)
	nodeID := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := pool.Exec(t.Context(), `INSERT INTO nodes(
		id,display_id,scope_id,name,admin_state,created_by_user_id,created_at,updated_at)
		VALUES($1,1,$2,'certificate-capability-node','active',$3,$4,$4)`, nodeID,
		actor.tenantScope, actor.tenantUser, now.Add(-20*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO edge_automatic_publication_policy_facts(
		target_scope_id,revision,mode,node_ids,activation_timeout_ms,observation_window_ms,
		required_consecutive_successes,max_attempts,deadline_window_seconds,
		actor_scope_id,actor_user_id,reason,created_at)
		VALUES($1,1,'automatic',$2,30000,15000,2,3,600,$1,$3,'certificate_capability_test',$4)`,
		actor.tenantScope, []uuid.UUID{nodeID}, actor.tenantUser, now); err != nil {
		t.Fatal(err)
	}
	identity := capabilitytest.SeedNodePublicationIdentityForTest(t, pool, actor.tenantScope, actor.tenantUser,
		nodeID, &agentv1.AgentCapabilities{AgentVersion: "1.0.0", BuildId: "certificate-capability-test",
			OperatingSystem: "linux", Architecture: "amd64", Features: edgeautopublish.CertificatePublicationCapabilities(),
		}, now.Add(-10*time.Minute), true)
	if !identity.Authorization.ExpiresAt.Before(now) {
		t.Fatal("enrollment authorization is not expired")
	}
	digest := sha256.Sum256(nodeID[:])
	if _, err := pool.Exec(t.Context(), `INSERT INTO node_presence(
		node_id,status,session_epoch,heartbeat_sequence,event_id,request_id,payload_digest,occurred_at,projected_at,
		last_seen_at,confirmed_session_epoch,confirmed_heartbeat_sequence,confirmed_event_id,confirmed_request_id,
		confirmed_payload_digest,online_since,openresty_state,firewall_state,
		filesystem_total_bytes,filesystem_available_bytes,cache_used_bytes,updated_at)
		VALUES($1,'online',1,1,$2,$3,$4,$5,$5,$5,1,1,$2,$3,$4,$5,'running','running',100,50,0,$5)`,
		nodeID, uuid.New(), uuid.New(), digest[:], now); err != nil {
		t.Fatal(err)
	}
	resolver, err := edgeautopublish.NewCertificateTargetResolver(pool, edgepublish.NewSnapshotTargetResolver())
	if err != nil {
		t.Fatal(err)
	}
	command := certificateasset.CertificatePublicationCommandV1{TenantScopeID: actor.tenantScope}
	policy, err := resolver.ResolveCertificateTarget(t.Context(), command)
	if err != nil || len(policy.NodeIDs) != 1 || policy.NodeIDs[0] != nodeID || policy.PolicyRevision != 1 {
		t.Fatalf("issued identity after enrollment TTL must resolve: policy=%+v err=%v", policy, err)
	}
	foreign := command
	foreign.TenantScopeID = actor.platformScope
	if _, err := resolver.ResolveCertificateTarget(t.Context(), foreign); err == nil {
		t.Fatal("foreign scope accepted")
	}
	if _, err := pool.Exec(t.Context(), `UPDATE node_presence SET status='offline',offline_since=$2,
		revision=revision+1,updated_at=$2 WHERE node_id=$1`, nodeID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.ResolveCertificateTarget(t.Context(), command); err == nil {
		t.Fatal("offline certificate target accepted")
	}
	if _, err := pool.Exec(t.Context(), `UPDATE node_presence SET status='online',offline_since=NULL,
		revision=revision+1,updated_at=$2 WHERE node_id=$1`, nodeID, now); err != nil {
		t.Fatal(err)
	}
	capabilitytest.SeedNodePublicationIdentityForTest(t, pool, actor.tenantScope, actor.tenantUser, nodeID,
		&agentv1.AgentCapabilities{AgentVersion: "next", BuildId: "pending", OperatingSystem: "linux", Architecture: "amd64"},
		now.Add(-time.Minute), false)
	if _, err := resolver.ResolveCertificateTarget(t.Context(), command); err != nil {
		t.Fatalf("pending authorization replaced issued capabilities: %v", err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE node_certificates SET status='revoked',revoked_at=$2,
		revocation_reason='test' WHERE id=$1`, identity.Completion.Certificate.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.ResolveCertificateTarget(t.Context(), command); err == nil {
		t.Fatal("revoked certificate target accepted")
	}
}

// node-e2e 10-31：演示站 78/85 属平台 scope，承载租户站点；证书发布校验只认
// node.scope_id=租户 scope，证书永远 retry_wait/publication_unavailable。
// 承载判定须与选节点和密文下发（tenant_carries_node_287）一致。
func TestCertificatePublicationCarriedPlatformNode(t *testing.T) {
	pool := openAutomaticDatabase(t)
	actor := seedAutomaticIntegrationIdentity(t, pool)
	nodeID := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := pool.Exec(t.Context(), `INSERT INTO nodes(
		id,display_id,scope_id,name,admin_state,created_by_user_id,created_at,updated_at)
		VALUES($1,1,$2,'certificate-platform-node','active',$3,$4,$4)`, nodeID,
		actor.platformScope, actor.platformUser, now.Add(-20*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO edge_automatic_publication_policy_facts(
		target_scope_id,revision,mode,node_ids,activation_timeout_ms,observation_window_ms,
		required_consecutive_successes,max_attempts,deadline_window_seconds,
		actor_scope_id,actor_user_id,reason,created_at)
		VALUES($1,1,'automatic',$2,30000,15000,2,3,600,$1,$3,'certificate_platform_node_test',$4)`,
		actor.tenantScope, []uuid.UUID{nodeID}, actor.tenantUser, now); err != nil {
		t.Fatal(err)
	}
	capabilitytest.SeedNodePublicationIdentityForTest(t, pool, actor.platformScope, actor.platformUser,
		nodeID, &agentv1.AgentCapabilities{AgentVersion: "1.0.0", BuildId: "certificate-platform-node-test",
			OperatingSystem: "linux", Architecture: "amd64", Features: edgeautopublish.CertificatePublicationCapabilities(),
		}, now.Add(-10*time.Minute), true)
	digest := sha256.Sum256(nodeID[:])
	if _, err := pool.Exec(t.Context(), `INSERT INTO node_presence(
		node_id,status,session_epoch,heartbeat_sequence,event_id,request_id,payload_digest,occurred_at,projected_at,
		last_seen_at,confirmed_session_epoch,confirmed_heartbeat_sequence,confirmed_event_id,confirmed_request_id,
		confirmed_payload_digest,online_since,openresty_state,firewall_state,
		filesystem_total_bytes,filesystem_available_bytes,cache_used_bytes,updated_at)
		VALUES($1,'online',1,1,$2,$3,$4,$5,$5,$5,1,1,$2,$3,$4,$5,'running','running',100,50,0,$5)`,
		nodeID, uuid.New(), uuid.New(), digest[:], now); err != nil {
		t.Fatal(err)
	}
	resolver, err := edgeautopublish.NewCertificateTargetResolver(pool, edgepublish.NewSnapshotTargetResolver())
	if err != nil {
		t.Fatal(err)
	}
	command := certificateasset.CertificatePublicationCommandV1{TenantScopeID: actor.tenantScope}
	// 未承载该租户的平台节点：不能收到租户证书。
	_, err = resolver.ResolveCertificateTarget(t.Context(), command)
	// 拒绝要带原因码与节点 ID（进 intent failure_code）。
	var rejection *edgeautopublish.CertificateTargetRejection
	if !errors.As(err, &rejection) || rejection.Code != edgeautopublish.CertificateTargetNodeNotCarried ||
		rejection.NodeID != nodeID || rejection.Transient {
		t.Fatalf("uncarried platform node: err=%v, want %s for node %s", err, edgeautopublish.CertificateTargetNodeNotCarried, nodeID)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO node_config_state(node_id,configuration_scope_id,updated_at)
		VALUES($1,$2,now())`, nodeID, actor.tenantScope); err != nil {
		t.Fatal(err)
	}
	policy, err := resolver.ResolveCertificateTarget(t.Context(), command)
	if err != nil || len(policy.NodeIDs) != 1 || policy.NodeIDs[0] != nodeID {
		t.Fatalf("carried platform node must resolve: policy=%+v err=%v", policy, err)
	}
}
