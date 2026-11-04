//go:build integration

package node

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// 删除被拒时说明被什么占用。节点在一个普通线路组、一个隐藏的市场供货组（名称带
// "市场供给 " 前缀，回给前端的是去掉前缀的卖家名）、一个 L2 配置里，并有一个排队中的缓存任务：
// 单个删除与批量删除都返回 node_in_use，原因按 供货组 → 线路组 → L2 → 缓存任务 列出。
func TestNodePurgeRefusalNamesWhatHoldsTheNode(t *testing.T) {
	f := newPurgeHistoryFixture(t)
	held := f.platformNode(t, "in-use-held")
	peer := f.platformNode(t, "in-use-peer")
	f.publishTo(t, held)

	general := f.lineGroup(t, "华东 A 组", "general", map[uuid.UUID]string{held: "198.51.100.71"})
	supply := f.lineGroup(t, "市场供给 卖家组", "market_supply", map[uuid.UUID]string{held: "198.51.100.72", peer: "198.51.100.73"})
	l2 := uuid.New()
	f.exec(t, `INSERT INTO l2_topology_configs(id,tenant_scope_id,name,region,mode,load_method,created_by_user_id,updated_by_user_id,created_at,updated_at)
		VALUES($1,$2,'L2 回源','华东','cache','rr',$3,$3,now(),now())`, l2, f.platformScope, f.operator)
	f.exec(t, `INSERT INTO l2_topology_nodes(id,tenant_scope_id,config_id,node_id,created_by_user_id,updated_by_user_id,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$5,now(),now())`, uuid.New(), f.platformScope, l2, held, f.operator)
	f.purgeOn(t, "in-use", held)

	wantReasons := func(t *testing.T, reasons []InUseReason) {
		t.Helper()
		if len(reasons) != 4 {
			t.Fatalf("reasons = %+v, want 4", reasons)
		}
		got := reasons[0]
		if got.Kind != InUseMarketSupply || got.ID != supply.String() || got.Name != "卖家组" ||
			got.GroupNodes == nil || *got.GroupNodes != 2 || got.NormalSubscriptions == nil || *got.NormalSubscriptions != 0 {
			t.Fatalf("market supply reason = %+v", got)
		}
		if got := reasons[1]; got.Kind != InUseLineGroup || got.ID != general.String() || got.Name != "华东 A 组" ||
			got.GroupNodes != nil || got.NormalSubscriptions != nil {
			t.Fatalf("line group reason = %+v", got)
		}
		if got := reasons[2]; got.Kind != InUseL2 || got.ID != l2.String() || got.Name != "L2 回源" {
			t.Fatalf("L2 reason = %+v", got)
		}
		if got := reasons[3]; got.Kind != InUseCacheOperation || got.Count == nil || *got.Count != 1 {
			t.Fatalf("cache operation reason = %+v", got)
		}
	}

	err := f.retire(t, held)
	var inUse *InUseError
	if !errors.As(err, &inUse) || !errors.Is(err, ErrInUse) {
		t.Fatalf("delete held node: %v, want *InUseError", err)
	}
	wantReasons(t, inUse.Reasons)

	var revision int64
	if err := f.pool.QueryRow(t.Context(), `SELECT revision FROM nodes WHERE id=$1`, held).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	batch, err := NewService(NewStore(f.pool)).BatchAdminState(t.Context(), Actor{UserID: f.operator, ScopeID: f.platformScope},
		BatchAdminStateRequest{AdminState: StateRetired, Items: []BatchAdminStateItem{{ID: held, ExpectedRevision: revision}},
			IdempotencyKey: "in-use-batch", RequestID: "in-use-batch"})
	if err != nil || len(batch.Items) != 1 || batch.Items[0].Status != "failed" || batch.Items[0].Error == nil ||
		batch.Items[0].Error.Code != "node_in_use" {
		t.Fatalf("batch delete held node: %+v %v", batch, err)
	}
	wantReasons(t, batch.Items[0].Error.Reasons)
	if got := f.count(t, `SELECT count(*) FROM nodes WHERE id=$1`, held); got != 1 {
		t.Fatal("held node was deleted")
	}

	// Only the supply group left: the peer is held by it alone.
	if err := f.retire(t, peer); !errors.As(err, &inUse) || len(inUse.Reasons) != 1 ||
		inUse.Reasons[0].Kind != InUseMarketSupply || inUse.Reasons[0].Name != "卖家组" {
		t.Fatalf("delete supply-only node: %v", err)
	}
}

// lineGroup seeds a sealed revision 1 line group of the platform scope with
// one endpoint per node (address as given).
func (f *purgeHistoryFixture) lineGroup(t *testing.T, name, purpose string, nodes map[uuid.UUID]string) uuid.UUID {
	t.Helper()
	groupID := uuid.New()
	resolved := "lg-" + groupID.String()[:8]
	err := pgx.BeginFunc(t.Context(), f.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO node_line_groups(id,tenant_scope_id,name,region,resolved_value,ipv4_resolved_value,
			current_revision,created_by_user_id,updated_by_user_id,created_at,updated_at,purpose)
			VALUES($1,$2,$3,'',$4,$4,1,$5,$5,now(),now(),$6)`, groupID, f.platformScope, name, resolved, f.operator, purpose); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO node_line_group_revisions(line_group_id,tenant_scope_id,revision,name,region,resolved_value,
			ipv4_resolved_value,probe_interval_ms,probe_timeout_ms,failure_threshold,recovery_threshold,
			failure_debounce_ms,recovery_debounce_ms,endpoint_count,configuration_digest,created_by_user_id,created_at)
			VALUES($1,$2,1,$3,'',$4,$4,10000,3000,3,3,0,0,$5,$6,$7,now())`,
			groupID, f.platformScope, name, resolved, len(nodes), make([]byte, 32), f.operator); err != nil {
			return err
		}
		for nodeID, address := range nodes {
			endpointID := uuid.New()
			if _, err := tx.Exec(t.Context(), `INSERT INTO node_line_endpoints(id,node_id,tenant_scope_id,line_group_id,config_revision,address,
				address_family,port,priority,weight,enabled) VALUES($1,$2,$3,$4,1,$5,4,443,0,1,true)`,
				endpointID, nodeID, f.platformScope, groupID, address); err != nil {
				return err
			}
			if _, err := tx.Exec(t.Context(), `INSERT INTO node_line_endpoint_health(tenant_scope_id,line_group_id,config_revision,endpoint_id,status,
				consecutive_successes,consecutive_failures,last_sequence,last_changed_at,row_revision,created_at,updated_at)
				SELECT $1,$2,1,$3,'unknown',0,0,0,created_at,1,created_at,created_at
				FROM node_line_group_revisions WHERE line_group_id=$2`, f.platformScope, groupID, endpointID); err != nil {
				return err
			}
		}
		_, err := tx.Exec(t.Context(), `UPDATE node_line_group_revisions SET sealed_at=created_at WHERE line_group_id=$1`, groupID)
		return err
	})
	if err != nil {
		t.Fatalf("seed line group %s: %v", name, err)
	}
	return groupID
}
