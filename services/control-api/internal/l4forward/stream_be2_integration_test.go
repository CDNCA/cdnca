package l4forward

import (
	"fmt"
	"slices"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// streamBe2LineGroup inserts a sealed platform general line group with one
// enabled endpoint on a new active node, and returns the group and node.
func streamBe2LineGroup(t *testing.T, pool *pgxpool.Pool, scope, user uuid.UUID, address string) (uuid.UUID, uuid.UUID) {
	t.Helper()
	group, node, endpoint := uuid.New(), uuid.New(), uuid.New()
	name := "stream-be2-" + group.String()[:8]
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id)
			  VALUES($1,$2,$3,'active',$4,(SELECT COALESCE(max(display_id),0)+1 FROM nodes))`, []any{node, scope, name, user}},
			{`INSERT INTO node_line_groups(id,tenant_scope_id,name,current_revision,created_by_user_id,updated_by_user_id,created_at,updated_at)
			  VALUES($1,$2,$3,1,$4,$4,now(),now())`, []any{group, scope, name, user}},
			{`INSERT INTO node_line_group_revisions(line_group_id,tenant_scope_id,revision,name,resolved_value,probe_interval_ms,probe_timeout_ms,
			  failure_threshold,recovery_threshold,failure_debounce_ms,recovery_debounce_ms,endpoint_count,configuration_digest,created_by_user_id,created_at)
			  VALUES($1,$2,1,$3,'lg-'||replace($1::uuid::text,'-',''),10000,3000,3,3,0,0,1,$4,$5,now())`, []any{group, scope, name, make([]byte, 32), user}},
			{`INSERT INTO node_line_endpoints(id,node_id,tenant_scope_id,line_group_id,config_revision,address,address_family,port,region,carrier,priority,weight,enabled)
			  VALUES($1,$2,$3,$4,1,$5,4,443,'','',0,1,true)`, []any{endpoint, node, scope, group, address}},
			{`INSERT INTO node_line_endpoint_health(tenant_scope_id,line_group_id,config_revision,endpoint_id,status,consecutive_successes,
			  consecutive_failures,last_sequence,last_changed_at,row_revision,created_at,updated_at)
			  VALUES($1,$2,1,$3,'unknown',0,0,0,now(),1,now(),now())`, []any{scope, group, endpoint}},
			{`UPDATE node_line_group_revisions SET sealed_at=now() WHERE tenant_scope_id=$1 AND line_group_id=$2`, []any{scope, group}},
		} {
			if _, err := tx.Exec(t.Context(), statement.query, statement.args...); err != nil {
				return fmt.Errorf("%.60s: %w", statement.query, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return group, node
}

func streamBe2TargetNodes(t *testing.T, pool *pgxpool.Pool, scope uuid.UUID) []uuid.UUID {
	t.Helper()
	var nodes []uuid.UUID
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		var err error
		nodes, err = edgeautopublish.ScopeTargetNodeIDsTx(t.Context(), tx, scope)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return nodes
}

// 更多操作 修改CNAME域名 / 修改CNAME生成模式 / 修改线路分组 (migration 491,
// 方案 B; migration 506 a stream belongs to no website): a stream's own value
// wins over its package's, and a website's line never reaches a stream;
// "" / an omitted line clears the override. Items are applied one
// by one against their own revision (a stale one fails alone), unknown
// resources reject the batch, and the stream's own line group adds its nodes
// to the publication targets.
func TestStreamOverridesInheritanceBatchCASAndTargets(t *testing.T) {
	fixture := newStreamAddonFixture(t)
	service, actor := NewService(NewStore(fixture.pool)), fixture.actor
	platform := Actor{UserID: fixture.admin.UserID, ScopeID: fixture.admin.ScopeID, ScopeKind: "platform"}
	ctx := t.Context()
	packageGroup, packageNode := streamBe2LineGroup(t, fixture.pool, platform.ScopeID, platform.UserID, "192.0.2.81")
	siteGroup, siteNode := streamBe2LineGroup(t, fixture.pool, platform.ScopeID, platform.UserID, "192.0.2.82")
	streamGroup, streamNode := streamBe2LineGroup(t, fixture.pool, platform.ScopeID, platform.UserID, "192.0.2.83")
	backupGroup, backupNode := streamBe2LineGroup(t, fixture.pool, platform.ScopeID, platform.UserID, "192.0.2.84")
	if _, err := fixture.pool.Exec(ctx, `INSERT INTO platform_system_other_settings(platform_scope_id,revision,settings,updated_at)
		VALUES($1,1,'{"dns_config":{"zones":[{"name":"Stream.Example"}]}}',now())`, platform.ScopeID); err != nil {
		t.Fatal(err)
	}
	subscription := fixture.subscriptionOnLine(t, actor.UserID, -1, packageGroup)

	create := func(port uint16) Forward {
		fields := streamBeTemplate(subscription)
		fields.Name, fields.Protocol, fields.ListenPort, fields.UpstreamAddress, fields.UpstreamPort =
			fmt.Sprintf("be2-%d", port), ProtocolTCP, port, "192.0.2.90", 80
		key := uuid.NewString()
		created, err := service.Create(ctx, actor, CreateRequest{Fields: fields, IdempotencyKey: key, RequestID: key})
		if err != nil {
			t.Fatal(err)
		}
		return created.Forward
	}
	get := func(id uuid.UUID) Forward {
		item, err := service.Get(ctx, platform, id)
		if err != nil {
			t.Fatal(err)
		}
		return item
	}
	first, second := create(24201), create(24202)

	// Inheritance: the package. A website of the scope on another group (no
	// package) is not the streams' line, though its nodes are scope targets.
	if line := get(first.ID).Line; line.NodeGroupID == nil || *line.NodeGroupID != packageGroup {
		t.Fatalf("package line = %+v", line)
	}
	if _, err := fixture.pool.Exec(ctx, `UPDATE sites SET node_group_id=$2,node_group_name='site group' WHERE id=$1`, fixture.siteID, siteGroup); err != nil {
		t.Fatal(err)
	}
	if line := get(first.ID).Line; line.NodeGroupID == nil || *line.NodeGroupID != packageGroup {
		t.Fatalf("a website's line reached a stream: %+v", line)
	}
	if nodes := streamBe2TargetNodes(t, fixture.pool, actor.ScopeID); slices.Contains(nodes, streamNode) ||
		!slices.Contains(nodes, siteNode) || !slices.Contains(nodes, packageNode) {
		t.Fatalf("targets before override = %v", nodes)
	}
	// Without any website the package's nodes are still the streams' targets.
	if _, err := fixture.pool.Exec(ctx, `UPDATE sites SET node_group_id=NULL,deleted_at=now() WHERE id=$1`, fixture.siteID); err != nil {
		t.Fatal(err)
	}
	if nodes := streamBe2TargetNodes(t, fixture.pool, actor.ScopeID); !slices.Contains(nodes, packageNode) || slices.Contains(nodes, siteNode) {
		t.Fatalf("stream-only targets = %v", nodes)
	}

	batch := func(request BatchActionRequest) (BatchActionResult, error) {
		key := uuid.NewString()
		request.IdempotencyKey, request.RequestID = key, key
		return service.BatchAction(ctx, platform, request)
	}
	// 修改线路分组: first applies, second is stale and fails alone.
	current := get(second.ID)
	result, err := batch(BatchActionRequest{Action: BatchActionLineGroup, NodeGroupID: &streamGroup, BackupNodeGroupID: &backupGroup,
		Items: []BatchActionItem{{ID: first.ID, ExpectedRevision: first.Revision}, {ID: second.ID, ExpectedRevision: current.Revision + 1}}})
	if err != nil || result.Items[0].Status != BatchItemUpdated || result.Items[1].Status != BatchItemFailed ||
		result.Items[1].Error.Code != "version_conflict" {
		t.Fatalf("line_group batch = %s, %v", mustJSON(t, result), err)
	}
	overridden := get(first.ID)
	if overridden.Line.NodeGroupID == nil || *overridden.Line.NodeGroupID != streamGroup || overridden.Line.BackupNodeGroupID == nil ||
		*overridden.Line.BackupNodeGroupID != backupGroup || overridden.Overrides.NodeGroupID == nil ||
		overridden.Revision != first.Revision+1 || overridden.PublishIntent.Version <= first.PublishIntent.Version {
		t.Fatalf("overridden = %s", mustJSON(t, overridden))
	}
	if line := get(second.ID).Line; line.NodeGroupID == nil || *line.NodeGroupID != packageGroup || get(second.ID).Revision != current.Revision {
		t.Fatalf("conflicting stream changed: %+v", line)
	}
	if nodes := streamBe2TargetNodes(t, fixture.pool, actor.ScopeID); !slices.Contains(nodes, streamNode) ||
		!slices.Contains(nodes, backupNode) || !slices.Contains(nodes, packageNode) {
		t.Fatalf("targets with override = %v", nodes)
	}
	var lineAudits int
	if err := fixture.pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action='stream.line_group.set' AND resource_id=$1`,
		first.ID.String()).Scan(&lineAudits); err != nil || lineAudits != 1 {
		t.Fatalf("line audit = %d, %v", lineAudits, err)
	}
	// List filter uses the effective line.
	listed, err := service.List(ctx, platform, ListFilter{Page: 1, Limit: 10, NodeGroupID: &streamGroup})
	if err != nil || len(listed.Items) != 1 || listed.Items[0].ID != first.ID {
		t.Fatalf("node_group filter = %+v, %v", listed, err)
	}

	// 修改CNAME域名: the stream's own domain wins; no hostname without a stream allocation.
	domain := " Stream.Example "
	overridden = get(first.ID)
	result, err = batch(BatchActionRequest{Action: BatchActionCNAMEDomain, CNAMEDomain: &domain,
		Items: []BatchActionItem{{ID: first.ID, ExpectedRevision: overridden.Revision}}})
	if err != nil || result.Items[0].Status != BatchItemUpdated {
		t.Fatalf("cname_domain batch = %s, %v", mustJSON(t, result), err)
	}
	if got := get(first.ID); got.CNAMEDomain == nil || *got.CNAMEDomain != "stream.example" || got.CNAMEHostname != nil ||
		got.Overrides.CNAMEDomain == nil {
		t.Fatalf("cname domain = %s", mustJSON(t, got))
	}
	unknown := "other.example"
	if _, err := batch(BatchActionRequest{Action: BatchActionCNAMEDomain, CNAMEDomain: &unknown,
		Items: []BatchActionItem{{ID: first.ID, ExpectedRevision: get(first.ID).Revision}}}); err == nil {
		t.Fatal("unknown CNAME domain accepted")
	}
	// 修改CNAME生成模式.
	mode := "package"
	result, err = batch(BatchActionRequest{Action: BatchActionCNAMEMode, CNAMEMode: &mode,
		Items: []BatchActionItem{{ID: first.ID, ExpectedRevision: get(first.ID).Revision}}})
	if err != nil || result.Items[0].Stream.Overrides.CNAMEMode == nil || *result.Items[0].Stream.Overrides.CNAMEMode != "package" {
		t.Fatalf("cname_mode batch = %s, %v", mustJSON(t, result), err)
	}
	// Invalid values and a deleted line group reject the batch.
	bad := "dns"
	if _, err := batch(BatchActionRequest{Action: BatchActionCNAMEMode, CNAMEMode: &bad,
		Items: []BatchActionItem{{ID: first.ID, ExpectedRevision: 1}}}); err == nil {
		t.Fatal("invalid mode accepted")
	}
	if _, err := batch(BatchActionRequest{Action: BatchActionLineGroup, BackupNodeGroupID: &backupGroup,
		Items: []BatchActionItem{{ID: first.ID, ExpectedRevision: 1}}}); err == nil {
		t.Fatal("backup group without primary accepted")
	}
	missing := uuid.New()
	if _, err := batch(BatchActionRequest{Action: BatchActionLineGroup, NodeGroupID: &missing,
		Items: []BatchActionItem{{ID: first.ID, ExpectedRevision: get(first.ID).Revision}}}); err == nil {
		t.Fatal("unknown line group accepted")
	}

	// Clearing: "" and an empty line fall back to the package.
	empty := ""
	if _, err := batch(BatchActionRequest{Action: BatchActionCNAMEDomain, CNAMEDomain: &empty,
		Items: []BatchActionItem{{ID: first.ID, ExpectedRevision: get(first.ID).Revision}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := batch(BatchActionRequest{Action: BatchActionLineGroup,
		Items: []BatchActionItem{{ID: first.ID, ExpectedRevision: get(first.ID).Revision}}}); err != nil {
		t.Fatal(err)
	}
	cleared := get(first.ID)
	if cleared.Overrides.CNAMEDomain != nil || cleared.Overrides.NodeGroupID != nil || cleared.Line.NodeGroupID == nil ||
		*cleared.Line.NodeGroupID != packageGroup || cleared.Overrides.CNAMEMode == nil {
		t.Fatalf("cleared = %s", mustJSON(t, cleared))
	}
	if nodes := streamBe2TargetNodes(t, fixture.pool, actor.ScopeID); slices.Contains(nodes, streamNode) || slices.Contains(nodes, backupNode) {
		t.Fatalf("targets after clearing = %v", nodes)
	}
	// Tenants cannot run 更多操作.
	key := uuid.NewString()
	if _, err := service.BatchAction(ctx, actor, BatchActionRequest{Action: BatchActionCNAMEMode, CNAMEMode: &mode,
		Items: []BatchActionItem{{ID: first.ID, ExpectedRevision: 1}}, IdempotencyKey: key, RequestID: key}); err == nil {
		t.Fatal("tenant batch action accepted")
	}
}
