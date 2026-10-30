//go:build integration

package edgepublish

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
)

// 现状刻画（见 docs/architecture/multi-tenant-node-sharing.md）：node_config_state 每节点只有一个
// configuration_scope_id，第一个发布到 platform 节点的租户独占该节点；第二个租户即使有自己的站点、
// 指向同一批 platform 节点，发布也会被拒，且不会部分认领。多租户共享节点改造落地后，此测试需随之改写。
func TestSecondTenantCannotPublishToPlatformNodesClaimedByFirstTenant(t *testing.T) {
	tenantA := newPublishFixture(t)
	ctx := context.Background()
	shared := []uuid.UUID{uuid.New(), uuid.New()}
	for _, nodeID := range shared {
		seedPublishNode(t, tenantA.pool, tenantA.platformScopeID, tenantA.platformUserID, nodeID)
	}
	free := uuid.New()
	seedPublishNode(t, tenantA.pool, tenantA.platformScopeID, tenantA.platformUserID, free)

	tenantA.createSite(t, "tenant-a-shared.example", 80, false)
	for index, nodeID := range shared {
		tenantA.nodeID = nodeID
		advancePublishSourceRevision(t, tenantA, index)
		published, err := tenantA.service.Publish(ctx, tenantA.publishRequest(
			fmt.Sprintf("tenant-a-shared-%d", index), nodeID))
		if err != nil {
			t.Fatalf("tenant A publish to platform node %d: %v", index, err)
		}
		activatePublishedDeployment(t, tenantA.pool, published.RolloutID)
	}

	tenantB := seedSecondPublishTenant(t, tenantA)
	tenantB.createSite(t, "tenant-b-shared.example", 80, false)

	sharedRequest := tenantB.publishRequest("tenant-b-shared", shared[0])
	sharedRequest.NodeIDs = append([]uuid.UUID(nil), shared...)
	_, err := tenantB.service.Publish(ctx, sharedRequest)
	if !errors.Is(err, ErrTargetIneligible) && !errors.Is(err, errConfigurationScopeConflict) {
		t.Fatalf("tenant B publish to tenant A platform nodes err=%v, want target ineligible/scope conflict", err)
	}

	mixedRequest := tenantB.publishRequest("tenant-b-mixed", free)
	mixedRequest.NodeIDs = []uuid.UUID{free, shared[1]}
	if _, err := tenantB.service.Publish(ctx, mixedRequest); !errors.Is(err, ErrTargetIneligible) &&
		!errors.Is(err, errConfigurationScopeConflict) {
		t.Fatalf("tenant B publish to free+claimed nodes err=%v, want target ineligible/scope conflict", err)
	}
	var freeStates int
	if err := tenantA.pool.QueryRow(ctx, `SELECT count(*) FROM node_config_state
		WHERE node_id=$1 AND configuration_scope_id IS NOT NULL`, free).Scan(&freeStates); err != nil {
		t.Fatal(err)
	}
	if freeStates != 0 {
		t.Fatalf("rejected mixed publication partially claimed the free node")
	}

	rows, err := tenantA.pool.Query(ctx, `SELECT configuration_scope_id FROM node_config_state
		WHERE node_id=ANY($1) ORDER BY node_id`, shared)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	claimed := 0
	for rows.Next() {
		var scopeID uuid.UUID
		if err := rows.Scan(&scopeID); err != nil {
			t.Fatal(err)
		}
		if scopeID != tenantA.scopeID {
			t.Fatalf("shared node configuration scope=%s, want tenant A %s", scopeID, tenantA.scopeID)
		}
		claimed++
	}
	if err := rows.Err(); err != nil || claimed != len(shared) {
		t.Fatalf("shared node states=%d err=%v", claimed, err)
	}

	// 对照：tenant B 本身可以发布，只要目标节点没有被别的租户占用。
	tenantB.nodeID = free
	if _, err := tenantB.service.Publish(ctx, tenantB.publishRequest("tenant-b-free", free)); err != nil {
		t.Fatalf("tenant B publish to an unclaimed platform node: %v", err)
	}
}

var errConfigurationScopeConflict = edgedeployment.ErrConfigurationScopeConflict

// seedSecondPublishTenant 在同一个库里建第二个租户（scope、用户、sites.manage 角色），
// 复用 tenantA 的 platform 发布者与发布服务。
func seedSecondPublishTenant(t *testing.T, base *publishFixture) *publishFixture {
	t.Helper()
	ctx := context.Background()
	tenantID, scopeID, userID, roleID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	username := "publish-b-" + strings.ReplaceAll(userID.String(), "-", "")[:20]
	statements := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO tenants (id,display_name) VALUES ($1,'Edge publish tenant B')`, []any{tenantID}},
		{`INSERT INTO access_scopes (id,kind,tenant_id) VALUES ($1,'tenant',$2)`, []any{scopeID, tenantID}},
		{`INSERT INTO users (id,username,display_name,password_hash) VALUES ($1,$2,'Edge publish user B','not-used')`,
			[]any{userID, username}},
		{`INSERT INTO memberships (scope_id,user_id) VALUES ($1,$2)`, []any{scopeID, userID}},
		{`INSERT INTO roles (id,scope_id,name,description,system_role)
			VALUES ($1,$2,'tenant_owner','Edge publication tenant B manager',true)`, []any{roleID, scopeID}},
		{`INSERT INTO role_permissions (role_id,permission_name) VALUES ($1,'sites.manage')`, []any{roleID}},
		{`INSERT INTO role_assignments (scope_id,user_id,role_id) VALUES ($1,$2,$3)`, []any{scopeID, userID, roleID}},
	}
	for _, statement := range statements {
		if _, err := base.pool.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	second := *base
	second.tenantID, second.scopeID, second.userID = tenantID, scopeID, userID
	// Its own package: a site without one is never published (fix-nopkgpub).
	second.subscriptionID = seedPublishPackage(t, base.pool, scopeID, userID, base.platformScopeID, base.platformUserID)
	return &second
}

// advancePublishSourceRevision: a source revision is published once
// (publicationExistsForSourceRevision), so each further node claim publishes
// a new revision, as the node scheduler's republication does. (These tests
// used to rely on the site IPv6 projection advancing it, fixed by 335.)
func advancePublishSourceRevision(t *testing.T, fixture *publishFixture, index int) {
	t.Helper()
	if index == 0 {
		return
	}
	if _, err := fixture.pool.Exec(context.Background(), `SELECT advance_edge_configuration_scope_revision($1)`,
		fixture.scopeID); err != nil {
		t.Fatal(err)
	}
}

// A node whose latest session declared MULTI_TENANT_RUNTIME (capability 33)
// serves both tenants: each gets its own configuration state on it, while a
// node without the capability still belongs to the first tenant only.
func TestSecondTenantPublishesToMultiTenantRuntimeNode(t *testing.T) {
	tenantA := newPublishFixture(t)
	ctx := context.Background()
	shared, legacy := uuid.New(), uuid.New()
	for _, nodeID := range []uuid.UUID{shared, legacy} {
		seedPublishNode(t, tenantA.pool, tenantA.platformScopeID, tenantA.platformUserID, nodeID)
	}
	tenantA.createSite(t, "tenant-a-runtime.example", 80, false)
	for index, nodeID := range []uuid.UUID{shared, legacy} {
		tenantA.nodeID = nodeID
		advancePublishSourceRevision(t, tenantA, index)
		published, err := tenantA.service.Publish(ctx, tenantA.publishRequest(fmt.Sprintf("tenant-a-runtime-%d", index), nodeID))
		if err != nil {
			t.Fatalf("tenant A publish to platform node %d: %v", index, err)
		}
		activatePublishedDeployment(t, tenantA.pool, published.RolloutID)
	}
	capabilities, err := proto.Marshal(&agentv1.AgentCapabilities{
		AgentVersion: "1.0.35", BuildId: "test", OperatingSystem: "linux", Architecture: "amd64",
		Features: append(v2DefaultNodeFeatures(),
			&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_ACTIVE_CONFIG_IDENTITY, ApiVersion: 1},
			&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_MULTI_TENANT_RUNTIME, ApiVersion: 1}),
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(capabilities)
	// Only the capability snapshot matters here; the fixture node has no
	// certificate row for the session to reference.
	if err := pgx.BeginFunc(ctx, tenantA.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO node_session_capabilities(node_id,session_epoch,certificate_id,
			certificate_sha256,artifact_key_id,selected_protocol_major,selected_protocol_minor,capabilities_snapshot,
			capabilities_sha256,facts_snapshot,facts_sha256,gateway_workload_identity,gateway_instance_id,registered_at)
			VALUES($1,1,$2,$3,'k',1,0,$4,$3,'\x00',$3,'gw','gw-1',now())`, shared, uuid.New(), digest[:], capabilities)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	tenantB := seedSecondPublishTenant(t, tenantA)
	tenantB.createSite(t, "tenant-b-runtime.example", 80, false)
	if _, err := tenantB.service.Publish(ctx, tenantB.publishRequest("tenant-b-legacy", legacy)); !errors.Is(err, ErrTargetIneligible) {
		t.Fatalf("tenant B publish to a node without MULTI_TENANT_RUNTIME err=%v, want target ineligible", err)
	}
	tenantB.nodeID = shared
	// Tenant A's configuration on the shared node claiming tenant B's domain
	// cannot be composed with B's: the publication is refused, naming the
	// node and the rule, and leaves nothing behind.
	var currentA uuid.UUID
	var snapshotA []byte
	if err := tenantA.pool.QueryRow(ctx, `SELECT version.id, version.canonical_snapshot FROM node_config_state state
		JOIN config_versions version ON version.id=state.current_config_version_id
		WHERE state.node_id=$1 AND state.configuration_scope_id=$2`, shared, tenantA.scopeID).Scan(&currentA, &snapshotA); err != nil {
		t.Fatal(err)
	}
	// withA is A's site runtime document with one more stream or site.
	withA := func(key string, item map[string]any) []byte {
		t.Helper()
		var claimed map[string]any
		if err := json.Unmarshal(snapshotA, &claimed); err != nil {
			t.Fatal(err)
		}
		if key == "streams" {
			streams, _ := claimed["streams"].(map[string]any)
			if streams == nil {
				streams = map[string]any{"tenant_id": uuid.NewString()}
			}
			list, _ := streams["streams_v2"].([]any)
			streams["streams_v2"] = append(list, item)
			claimed["streams"] = streams
		} else {
			list, _ := claimed[key].([]any)
			claimed[key] = append(list, item)
		}
		raw, err := json.Marshal(claimed)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	setSnapshotA := func(raw []byte) {
		t.Helper()
		if err := pgx.BeginFunc(ctx, tenantA.pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `UPDATE config_versions SET canonical_snapshot=$2 WHERE id=$1`, currentA, raw)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	// A plain TCP port of A's L4 forwarding cannot also serve B's website:
	// nothing on the wire tells the two apart.
	setSnapshotA(withA("streams", map[string]any{"stream_id": uuid.NewString(), "listener": map[string]any{"protocol": "tcp", "address": "*", "port": 80}}))
	if _, err := tenantB.service.Publish(ctx, tenantB.publishRequest("tenant-b-l4", shared)); !errors.Is(err, ErrCrossScopeConflict) ||
		!strings.Contains(err.Error(), "tcp port 80 is already used by another tenant's L4 forwarding") {
		t.Fatalf("publication onto another tenant's TCP L4 port err=%v", err)
	}
	setSnapshotA(withA("sites", map[string]any{"id": uuid.NewString(), "domains": []string{"tenant-b-runtime.example"},
		"listeners": []map[string]any{{"id": "public-80", "port": 80, "protocols": []string{"http1"}}}}))
	_, err = tenantB.service.Publish(ctx, tenantB.publishRequest("tenant-b-conflict", shared))
	if !errors.Is(err, ErrCrossScopeConflict) || !strings.Contains(err.Error(), shared.String()) ||
		!strings.Contains(err.Error(), "domain tenant-b-runtime.example") || strings.Contains(err.Error(), tenantA.scopeID.String()) {
		t.Fatalf("conflicting publication err=%v", err)
	}
	var rows int
	if err := tenantA.pool.QueryRow(ctx, `SELECT count(*) FROM config_versions WHERE configuration_scope_id=$1`,
		tenantB.scopeID).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("rejected publication left %d config versions (%v)", rows, err)
	}
	// Both refusals are kept, on the node, for the administrator.
	var reasons []string
	if err := tenantA.pool.QueryRow(ctx, `SELECT array_agg(payload->>'reason' ORDER BY stream_position) FROM audit_events
		WHERE scope_id=$1 AND action=$2 AND resource_type='node' AND resource_id=$3 AND result='denied'`,
		tenantB.scopeID, CrossScopeConflictAction, shared.String()).Scan(&reasons); err != nil || len(reasons) != 2 ||
		!strings.Contains(reasons[0], "L4 forwarding") || !strings.Contains(reasons[1], "domain tenant-b-runtime.example") {
		t.Fatalf("refusal audit reasons=%q err=%v", reasons, err)
	}
	// waf-share (73 adm-fix-a2: tenant B retried 349 times as node 667d0b7b
	// served tenant A's managed WAF): A's site runs the OWASP CRS managed WAF
	// (默认防护, 942100 excluded); B still publishes onto the node, and B's
	// own managed WAF of another profile pack and exclusions shares it too
	// (dynamic routing: one tier location per profile pack, the site's
	// exclusions in each request's transaction ID).
	managedWAF := func(raw []byte, pack string, exclusions ...int) []byte {
		t.Helper()
		var document siteRuntimeV2Document
		if err := json.Unmarshal(raw, &document); err != nil || len(document.Sites) == 0 || len(document.Sites[0].Listeners) == 0 {
			t.Fatalf("site runtime document: %v", err)
		}
		document.Sites[0].Listeners[0].Security = &edgeconfig.ListenerSecurity{ManagedWAF: &edgeconfig.ManagedWAF{
			Profile: edgeconfig.CRSProfileRef{PackID: pack, Version: "1.0.0", SHA256: strings.Repeat("a", 64)}, Exclusions: exclusions}}
		changed, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		return changed
	}
	setSnapshotA(managedWAF(snapshotA, "system/crs-pl1", 942100))
	if _, err := tenantB.service.Publish(ctx, tenantB.publishRequest("tenant-b-runtime", shared)); err != nil {
		t.Fatalf("tenant B publish to a MULTI_TENANT_RUNTIME node serving tenant A's managed WAF: %v", err)
	}
	var snapshotB []byte
	if err := tenantA.pool.QueryRow(ctx, `SELECT version.canonical_snapshot FROM node_deployments deployment
		JOIN config_versions version ON version.id=deployment.config_version_id
		WHERE deployment.node_id=$1 AND deployment.configuration_scope_id=$2`, shared, tenantB.scopeID).Scan(&snapshotB); err != nil {
		t.Fatal(err)
	}
	if err := pgx.BeginFunc(ctx, tenantA.pool, func(tx pgx.Tx) error {
		return validateCrossScopeComposition(ctx, tx, tenantB.scopeID, []uuid.UUID{shared}, managedWAF(snapshotB, "system/crs-pl2", 941100))
	}); err != nil {
		t.Fatalf("tenant B's managed WAF beside tenant A's on the shared node: %v", err)
	}
	var scopes []uuid.UUID
	if err := tenantA.pool.QueryRow(ctx, `SELECT array_agg(configuration_scope_id ORDER BY configuration_scope_id)
		FROM node_config_state WHERE node_id=$1`, shared).Scan(&scopes); err != nil {
		t.Fatal(err)
	}
	want := []uuid.UUID{tenantA.scopeID, tenantB.scopeID}
	slices.SortFunc(want, func(left, right uuid.UUID) int { return strings.Compare(left.String(), right.String()) })
	if !slices.Equal(scopes, want) {
		t.Fatalf("shared node scopes=%v, want both tenants %v", scopes, want)
	}
	var queued bool
	if err := tenantA.pool.QueryRow(ctx, `SELECT queued_per_scope FROM node_deployments
		WHERE node_id=$1 AND configuration_scope_id=$2`, shared, tenantB.scopeID).Scan(&queued); err != nil || !queued {
		t.Fatalf("tenant B deployment queued_per_scope=%v err=%v", queued, err)
	}
}
