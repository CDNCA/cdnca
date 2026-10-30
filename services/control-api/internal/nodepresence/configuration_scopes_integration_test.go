//go:build integration

package nodepresence

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/node"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
)

// TestNodeConfigurationScopesShowsEveryTenantOnASharedNode reads a platform
// node serving two tenants: one with a deployment waiting in the agent queue,
// one whose last apply the agent superseded, and a publication refused for a
// conflict on this node. A node of another scope is not found.
func TestNodeConfigurationScopesShowsEveryTenantOnASharedNode(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is required")
	}
	ctx := context.Background()
	pool, adminPool, schema := openPresenceTestDatabase(t, databaseURL)
	defer pool.Close()
	defer adminPool.Close()
	defer func() {
		_, _ = adminPool.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
	}()
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		t.Fatal(err)
	}

	var platform uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&platform); errors.Is(err, pgx.ErrNoRows) {
		platform = uuid.New()
	} else if err != nil {
		t.Fatal(err)
	}
	user, nodeID := uuid.New(), uuid.New()
	alpha, beta := uuid.New(), uuid.New() // tenant scopes; their tenant IDs differ, as in production
	alphaTenant, betaTenant := uuid.New(), uuid.New()
	alphaVersion, betaVersion := uuid.New(), uuid.New()
	alphaRollout, betaRollout := uuid.New(), uuid.New()
	alphaDeployment, betaDeployment := uuid.New(), uuid.New()
	now := time.Now().UTC().Truncate(time.Microsecond)
	digest := sha256.Sum256([]byte("scopes"))
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{`SET LOCAL session_replication_role = replica`, nil},
			{`INSERT INTO access_scopes(id,kind) SELECT $1,'platform' WHERE NOT EXISTS (SELECT 1 FROM access_scopes WHERE kind='platform')`, []any{platform}},
			{`INSERT INTO tenants(id,display_name) VALUES($1,'Alpha'),($2,'Beta')`, []any{alphaTenant, betaTenant}},
			{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2),($3,'tenant',$4)`, []any{alpha, alphaTenant, beta, betaTenant}},
			{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'scopes','x')`, []any{user, "scopes-" + user.String()[:8]}},
			{`INSERT INTO nodes(id,display_id,scope_id,name,admin_state,created_by_user_id) VALUES($1,95000,$2,'shared','active',$3)`, []any{nodeID, platform, user}},
		} {
			if _, err := tx.Exec(ctx, statement.query, statement.args...); err != nil {
				return fmt.Errorf("%.60s: %w", statement.query, err)
			}
		}
		for _, item := range []struct {
			scope, version, rollout, deployment uuid.UUID
			current                             any
			state                               string
		}{
			{alpha, alphaVersion, alphaRollout, alphaDeployment, nil, "agent_queued"},
			{beta, betaVersion, betaRollout, betaDeployment, betaVersion, "healthy"},
		} {
			for _, statement := range []struct {
				query string
				args  []any
			}{
				{`INSERT INTO config_versions(id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,generator_name,
					generator_version,status,idempotency_key,request_digest,created_at,published_at)
					VALUES($1,$2,'\x01',$3,'test','1','releasable',$4,$3,$5,$5)`,
					[]any{item.version, item.scope, digest[:], "scopes-" + item.version.String()[:8], now}},
				{`INSERT INTO rollouts(id,configuration_scope_id,config_version_id,action,status,idempotency_key,request_digest,
					request_id,correlation_id,activation_timeout_ms,observation_window_ms,required_consecutive_successes,deadline_at,
					created_at,updated_at,queued_at) VALUES($1,$2,$3,'apply','running',$4,$5,$6,$6,1000,1000,1,$7::timestamptz+interval '1 hour',$7,$7,$7)`,
					[]any{item.rollout, item.scope, item.version, "scopes-" + item.rollout.String()[:8], digest[:], uuid.New(), now}},
				{`INSERT INTO node_config_state(node_id,configuration_scope_id,current_config_version_id,updated_at) VALUES($1,$2,$3,$4)`,
					[]any{nodeID, item.scope, item.current, now}},
				{`INSERT INTO node_deployments(id,rollout_id,node_id,attempt,config_version_id,action,state,configuration_scope_id,
					command_event_id,command_bytes,command_sha256,deadline_at,created_at,updated_at,queued_per_scope)
					VALUES($1,$2,$3,1,$4,'apply',$5,$6,$7,'\x01',$8,$9::timestamptz+interval '1 hour',$9,$9,true)`,
					[]any{item.deployment, item.rollout, nodeID, item.version, item.state, item.scope, uuid.New(), digest[:], now}},
			} {
				if _, err := tx.Exec(ctx, statement.query, statement.args...); err != nil {
					return fmt.Errorf("%.60s: %w", statement.query, err)
				}
			}
		}
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{`INSERT INTO node_presence(node_id,status,session_epoch,heartbeat_sequence,event_id,request_id,payload_digest,
				occurred_at,projected_at,offline_since,openresty_state,firewall_state,filesystem_total_bytes,
				filesystem_available_bytes,cache_used_bytes,active_deployments,revision,updated_at)
				VALUES($1,'offline',1,1,$2,$2,$3,$4,$4,$4,'running','running',1,1,0,'[]',1,$4)`, []any{nodeID, uuid.New(), digest[:], now}},
			{`INSERT INTO node_presence_scope_identities(node_id,configuration_scope_id,session_epoch,heartbeat_sequence,
				current_config_version_id,last_apply_deployment_id,last_apply_attempt,last_apply_config_version_id,
				last_apply_state,last_apply_finished_at,updated_at) VALUES($1,$2,1,1,$3,$4,1,$3,'superseded',$5,$5)`,
				[]any{nodeID, beta, betaVersion, betaDeployment, now}},
		} {
			if _, err := tx.Exec(ctx, statement.query, statement.args...); err != nil {
				return fmt.Errorf("%.60s: %w", statement.query, err)
			}
		}
		// What edgepublish records when it refuses a publication on this node.
		return audit.NewWithClock(nil, func() time.Time { return now }).Append(ctx, tx, audit.Event{
			ScopeID: alpha, ActorUserID: &user, Action: "edge_publication.node_scope_conflict", ResourceType: "node",
			ResourceID: nodeID.String(), RequestID: "publish-refused", Result: "denied",
			Payload: map[string]any{"reason": "port 80 (ipv4) would mix plaintext and TLS with another tenant",
				"node_id": nodeID.String()},
		})
	})
	if err != nil {
		t.Fatal(err)
	}

	inventory := NewInventory(pool, nil, time.Minute, func() time.Time { return now }, nil)
	result, err := inventory.ConfigurationScopes(ctx, platform, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Scopes) != 2 || result.Scopes[0].TenantName != "Alpha" || result.Scopes[1].TenantName != "Beta" {
		t.Fatalf("scopes %+v", result.Scopes)
	}
	first, second := result.Scopes[0], result.Scopes[1]
	if first.ScopeID != alpha || first.TenantID == nil || *first.TenantID != alphaTenant || first.CurrentConfigVersionID != nil ||
		first.LatestDeployment == nil || first.LatestDeployment.State != "agent_queued" || first.LastApply != nil {
		t.Fatalf("queued tenant %+v", first)
	}
	if second.CurrentConfigVersionID == nil || *second.CurrentConfigVersionID != betaVersion ||
		second.LastApply == nil || second.LastApply.State != "superseded" || second.LatestDeployment.State != "healthy" {
		t.Fatalf("superseded tenant %+v", second)
	}
	if len(result.Rejections) != 1 || result.Rejections[0].ScopeID != alpha || result.Rejections[0].TenantName != "Alpha" ||
		result.Rejections[0].Reason != "port 80 (ipv4) would mix plaintext and TLS with another tenant" {
		t.Fatalf("rejections %+v", result.Rejections)
	}
	if first.TelemetryExcluded != "" || second.TelemetryExcluded != "" {
		t.Fatalf("exclusions without a reader: %+v", result.Scopes)
	}
	// The isolated scope is reported with the reader's reason, in the same
	// read transaction.
	inventory.WithTelemetryExclusions(func(_ context.Context, tx pgx.Tx, readNode uuid.UUID, _ time.Time) (map[uuid.UUID]string, error) {
		if tx == nil || readNode != nodeID {
			t.Fatalf("exclusion reader got tx=%v node=%s", tx, readNode)
		}
		return map[uuid.UUID]string{beta: "invalid_config_version"}, nil
	})
	result, err = inventory.ConfigurationScopes(ctx, platform, nodeID)
	if err != nil || result.Scopes[0].TelemetryExcluded != "" || result.Scopes[1].TelemetryExcluded != "invalid_config_version" {
		t.Fatalf("isolated scopes %+v err=%v", result.Scopes, err)
	}
	if _, err := inventory.ConfigurationScopes(ctx, alpha, nodeID); !errors.Is(err, node.ErrNotFound) {
		t.Fatalf("node read from another scope: %v", err)
	}
	if len(result.CapabilityRegressions) != 0 {
		t.Fatalf("regressions without a session: %+v", result.CapabilityRegressions)
	}

	// The agent was rolled back after Beta's latest healthy deployment used
	// TLS passthrough (tcp v4): its new session declares tcp v3.
	regressed := uuid.New()
	command, err := proto.Marshal(&agentv1.DeploymentCommand{DeploymentId: regressed.String(), Attempt: 1,
		ConfigVersionId: betaVersion.String(), RequiredCapabilities: []*agentv1.Capability{
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1, ApiVersion: 1},
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY, ApiVersion: 4}}})
	if err != nil {
		t.Fatal(err)
	}
	session := func(epoch int64, tcp uint32, agentVersion string) []any {
		snapshot, err := proto.Marshal(&agentv1.AgentCapabilities{AgentVersion: agentVersion, Features: []*agentv1.Capability{
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1, ApiVersion: 1},
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY, ApiVersion: tcp}}})
		if err != nil {
			t.Fatal(err)
		}
		snapshotDigest := sha256.Sum256(snapshot)
		return []any{nodeID, epoch, uuid.New(), digest[:], "x25519:test", snapshot, snapshotDigest[:], now}
	}
	err = pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{`SET LOCAL session_replication_role = replica`, nil},
			{`INSERT INTO node_deployments(id,rollout_id,node_id,attempt,config_version_id,action,state,configuration_scope_id,
				command_event_id,command_bytes,command_sha256,deadline_at,created_at,updated_at,queued_per_scope)
				VALUES($1,$2,$3,2,$4,'apply','healthy',$5,$6,$7,$8,$9::timestamptz+interval '1 hour',$9,$9::timestamptz+interval '1 second',true)`,
				[]any{regressed, betaRollout, nodeID, betaVersion, beta, uuid.New(), command, digest[:], now}},
			{`INSERT INTO node_session_capabilities(node_id,session_epoch,certificate_id,certificate_sha256,artifact_key_id,
				selected_protocol_major,selected_protocol_minor,capabilities_snapshot,capabilities_sha256,facts_snapshot,facts_sha256,
				gateway_workload_identity,gateway_instance_id,registered_at) VALUES($1,$2,$3,$4,$5,1,0,$6,$7,'\x01',$4,'gw','gw-1',$8)`,
				session(1, 4, "1.0.34")},
			{`INSERT INTO node_session_capabilities(node_id,session_epoch,certificate_id,certificate_sha256,artifact_key_id,
				selected_protocol_major,selected_protocol_minor,capabilities_snapshot,capabilities_sha256,facts_snapshot,facts_sha256,
				gateway_workload_identity,gateway_instance_id,registered_at) VALUES($1,$2,$3,$4,$5,1,0,$6,$7,'\x01',$4,'gw','gw-1',$8)`,
				session(2, 3, "1.0.33")},
		} {
			if _, err := tx.Exec(ctx, statement.query, statement.args...); err != nil {
				return fmt.Errorf("%.60s: %w", statement.query, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err = inventory.ConfigurationScopes(ctx, platform, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.CapabilityRegressions) != 1 {
		t.Fatalf("regressions = %+v", result.CapabilityRegressions)
	}
	if got := result.CapabilityRegressions[0]; got.ScopeID != beta || got.DeploymentID != regressed || got.ConfigVersionID != betaVersion ||
		got.Feature != FeatureL4TLSPassthrough || got.Required != 4 || got.Declared != 3 || got.AgentVersion != "1.0.33" {
		t.Fatalf("regression = %+v", got)
	}
	var indexed bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass('audit_events_node_scope_conflict_292_idx') IS NOT NULL`).Scan(&indexed); err != nil || !indexed {
		t.Fatalf("rejection index present=%v err=%v", indexed, err)
	}
}
