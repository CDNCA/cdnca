//go:build integration

package edgepublish

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSnapshotTargetResolverIsTenantBoundDigestBoundAndDeterministic(t *testing.T) {
	pool := openPublishTestDatabase(t, true)
	scopeID, snapshotID, nodeIDs := seedResolverSnapshot(t, pool)
	digest := nodescheduler.CanonicalNodeSetDigest(nodeIDs)
	resolver := NewSnapshotTargetResolver()

	var resolved TargetSnapshot
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		var err error
		resolved, err = resolver.ResolveTarget(t.Context(), tx, scopeID, TargetSnapshotReference{
			ID: snapshotID, Revision: 1, SHA256: digest,
		})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(resolved.Reference.SHA256[:], digest[:]) || !sameUUIDs(resolved.NodeIDs, nodeIDs) {
		t.Fatalf("resolved snapshot = %#v", resolved)
	}

	wrongDigest := digest
	wrongDigest[0]++
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		_, err := resolver.ResolveTarget(t.Context(), tx, scopeID, TargetSnapshotReference{
			ID: snapshotID, Revision: 1, SHA256: wrongDigest,
		})
		return err
	}); !errors.Is(err, ErrTargetSnapshotConflict) {
		t.Fatalf("wrong digest error = %v", err)
	}

	otherScope := uuid.New()
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		_, err := resolver.ResolveTarget(t.Context(), tx, otherScope, TargetSnapshotReference{
			ID: snapshotID, Revision: 1, SHA256: digest,
		})
		return err
	}); !errors.Is(err, ErrTargetSnapshotConflict) {
		t.Fatalf("wrong tenant error = %v", err)
	}

	t.Run("missing snapshot", func(t *testing.T) {
		err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			_, err := resolver.ResolveTarget(t.Context(), tx, scopeID, TargetSnapshotReference{
				ID: uuid.New(), Revision: 1, SHA256: digest,
			})
			return err
		})
		if !errors.Is(err, ErrTargetSnapshotConflict) {
			t.Fatalf("missing snapshot error = %v", err)
		}
	})

	t.Run("wrong revision", func(t *testing.T) {
		err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			_, err := resolver.ResolveTarget(t.Context(), tx, scopeID, TargetSnapshotReference{
				ID: snapshotID, Revision: 2, SHA256: digest,
			})
			return err
		})
		if !errors.Is(err, ErrTargetSnapshotConflict) {
			t.Fatalf("wrong revision error = %v", err)
		}
	})

	t.Run("missing child", func(t *testing.T) {
		if _, err := pool.Exec(t.Context(), `ALTER TABLE edge_target_snapshot_nodes DISABLE TRIGGER USER`); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(t.Context(), `DELETE FROM edge_target_snapshot_nodes
			WHERE tenant_scope_id=$1 AND snapshot_id=$2 AND node_id=$3`, scopeID, snapshotID, nodeIDs[0]); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(t.Context(), `ALTER TABLE edge_target_snapshot_nodes ENABLE TRIGGER USER`); err != nil {
			t.Fatal(err)
		}
		err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			_, err := resolver.ResolveTarget(t.Context(), tx, scopeID, TargetSnapshotReference{
				ID: snapshotID, Revision: 1, SHA256: digest,
			})
			return err
		})
		if !errors.Is(err, ErrTargetSnapshotConflict) {
			t.Fatalf("missing child error = %v", err)
		}
	})

	if _, err := pool.Exec(t.Context(), `
		UPDATE edge_target_snapshots SET node_count=node_count+1
		WHERE tenant_scope_id=$1 AND id=$2 AND revision=1`, scopeID, snapshotID); err == nil ||
		!strings.Contains(err.Error(), "immutable") {
		t.Fatalf("snapshot tamper error = %v", err)
	}
}

func TestSnapshotTargetResolverCompilesCanonicalDualStackL2Bundle(t *testing.T) {
	pool := openPublishTestDatabase(t, true)
	scopeID, snapshotID, nodeIDs := seedResolverSnapshot(t, pool)
	reference := TargetSnapshotReference{ID: snapshotID, Revision: 1, SHA256: nodescheduler.CanonicalNodeSetDigest(nodeIDs)}
	configID := uuid.New()
	var wire []byte
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		target, err := NewSnapshotTargetResolver().ResolveTarget(t.Context(), tx, scopeID, reference)
		if err != nil {
			return err
		}
		fact := siteFact{
			id: uuid.New(), revision: 1, domain: "resolver.example.test", httpPorts: []string{"80"},
			ipv6Enabled: true, ipv6DesiredSet: true, balance: "round_robin", failoverTries: 1,
			connectTimeoutMS: 3000, readTimeoutMS: 30000,
			origins: []snapshotOrigin{{Host: "192.0.2.10", Port: 8080, Weight: 1}},
		}
		document, _, err := compileSiteRuntimeV2Source(t.Context(), tx, scopeID, configID, 1,
			[]siteFact{fact}, target.Topology, time.Now().UTC())
		if err != nil {
			return err
		}
		route, err := basicSiteOriginRouteFactWithTopology(document.Sites[0], target.Topology)
		if err != nil {
			t.Fatalf("compile persisted L2 endpoints into origin route: %v (endpoints=%+v)", err, target.Topology.Endpoints)
		}
		originRoutes, err := compileSiteOriginRouteBundleWithTopology(scopeID, configID, 1, []siteOriginRouteFact{route}, target.Topology)
		if err != nil {
			return err
		}
		raw, err := json.Marshal(document)
		if err != nil {
			return err
		}
		canonical, _, _, _, err := compileSiteRuntimeV2Document(raw)
		if err != nil {
			return err
		}
		wire, err = marshalSiteRuntimeV2BundleWithOriginRoutes(canonical, nil, originRoutes)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	bundle, err := edgeconfig.UnmarshalBundle(wire)
	if err != nil {
		t.Fatal(err)
	}
	var routes siteOriginRouteBundleDocument
	if err := json.Unmarshal(bundle.Files[siteOriginRouteBundlePath], &routes); err != nil {
		t.Fatal(err)
	}
	if len(routes.Targets) != len(nodeIDs) || len(routes.Sites) != 1 {
		t.Fatalf("resolved bundle identity = %+v", routes)
	}
	wantHosts := map[string]bool{"192.0.2.61": true, "2001:db8::62": true}
	for _, candidate := range routes.Sites[0].Document.Pools {
		if candidate.Kind != "l2" {
			continue
		}
		for _, endpoint := range candidate.Endpoints {
			if !wantHosts[endpoint.Host] || endpoint.TopologyRevision != 1 || endpoint.NodeID == "" ||
				!siteOriginRouteMTLSIdentityPattern.MatchString(endpoint.MTLSIdentitySHA256) {
				t.Fatalf("noncanonical or unbound persisted endpoint = %+v", endpoint)
			}
			delete(wantHosts, endpoint.Host)
		}
	}
	if len(wantHosts) != 0 {
		t.Fatalf("missing persisted dual-stack hosts: %v", wantHosts)
	}
}

func seedResolverSnapshot(t *testing.T, pool *pgxpool.Pool) (uuid.UUID, uuid.UUID, []uuid.UUID) {
	t.Helper()
	tenantID, scopeID, userID := uuid.New(), uuid.New(), uuid.New()
	groupID := uuid.New()
	endpointIDs := []uuid.UUID{uuid.New(), uuid.New()}
	l2NodeIDs := []uuid.UUID{uuid.New(), uuid.New()}
	nodeIDs := []uuid.UUID{uuid.New(), uuid.New()}
	sort.Slice(nodeIDs, func(left, right int) bool { return bytes.Compare(nodeIDs[left][:], nodeIDs[right][:]) < 0 })
	snapshotID := uuid.New()
	username := "resolver-" + strings.ReplaceAll(userID.String(), "-", "")[:20]
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		statements := []struct {
			query string
			args  []any
		}{
			{`INSERT INTO tenants(id,display_name) VALUES($1,'Resolver tenant')`, []any{tenantID}},
			{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{scopeID, tenantID}},
			{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'Resolver user','test')`, []any{userID, username}},
			{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{scopeID, userID}},
			{`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id) VALUES($1,$2,$3,'active',$4,1)`, []any{nodeIDs[0], scopeID, "resolver-node-a", userID}},
			{`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id) VALUES($1,$2,$3,'active',$4,2)`, []any{nodeIDs[1], scopeID, "resolver-node-b", userID}},
			{`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id) VALUES($1,$2,$3,'active',$4,3)`, []any{l2NodeIDs[0], scopeID, "resolver-l2-a", userID}},
			{`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id) VALUES($1,$2,$3,'active',$4,4)`, []any{l2NodeIDs[1], scopeID, "resolver-l2-b", userID}},
			{`INSERT INTO node_line_groups(id,tenant_scope_id,name,current_revision,created_by_user_id,updated_by_user_id,created_at,updated_at)
			 VALUES($1,$2,'resolver-group',1,$3,$3,now(),now())`, []any{groupID, scopeID, userID}},
			{`INSERT INTO node_line_group_revisions(line_group_id,tenant_scope_id,revision,name,resolved_value,probe_interval_ms,probe_timeout_ms,
			 failure_threshold,recovery_threshold,failure_debounce_ms,recovery_debounce_ms,endpoint_count,configuration_digest,created_by_user_id,created_at)
			 VALUES($1,$2,1,'resolver-group','lg-'||replace($1::uuid::text,'-',''),10000,3000,3,3,0,0,2,$3,$4,now())`, []any{groupID, scopeID, make([]byte, 32), userID}},
			{`INSERT INTO node_line_endpoints(id,node_id,tenant_scope_id,line_group_id,config_revision,address,address_family,port,region,carrier,priority,weight,enabled)
			 VALUES($1,$2,$3,$4,1,'192.0.2.61',4,443,'','',0,1,true)`, []any{endpointIDs[0], l2NodeIDs[0], scopeID, groupID}},
			{`INSERT INTO node_line_endpoints(id,node_id,tenant_scope_id,line_group_id,config_revision,address,address_family,port,region,carrier,priority,weight,enabled)
			 VALUES($1,$2,$3,$4,1,'2001:db8::62',6,443,'','',0,1,true)`, []any{endpointIDs[1], l2NodeIDs[1], scopeID, groupID}},
		}
		for _, statement := range statements {
			if _, err := tx.Exec(t.Context(), statement.query, statement.args...); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(t.Context(), `
			INSERT INTO node_line_endpoint_health(tenant_scope_id,line_group_id,config_revision,endpoint_id,status,consecutive_successes,consecutive_failures,last_sequence,last_changed_at,row_revision,created_at,updated_at)
			SELECT $1,$2,1,id,'unknown',0,0,0,now(),1,now(),now()
			FROM node_line_endpoints WHERE tenant_scope_id=$1 AND line_group_id=$2`, scopeID, groupID); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `UPDATE node_line_group_revisions SET sealed_at=now()
			WHERE tenant_scope_id=$1 AND line_group_id=$2 AND revision=1`, scopeID, groupID); err != nil {
			return err
		}
		digest := nodescheduler.CanonicalNodeSetDigest(nodeIDs)
		if _, err := tx.Exec(t.Context(), `INSERT INTO edge_target_snapshots(
			id,tenant_scope_id,revision,source_line_group_id,source_revision,source_configuration_digest,node_set_digest,node_count,created_at)
			VALUES($1,$2,1,$3,1,$4,$5,2,now())`, snapshotID, scopeID, groupID, make([]byte, 32), digest[:]); err != nil {
			return err
		}
		for _, nodeID := range nodeIDs {
			if _, err := tx.Exec(t.Context(), `INSERT INTO edge_target_snapshot_nodes(tenant_scope_id,snapshot_id,snapshot_revision,node_id)
				VALUES($1,$2,1,$3)`, scopeID, snapshotID, nodeID); err != nil {
				return err
			}
			identity := sha256.Sum256([]byte(nodeID.String()))
			if _, err := tx.Exec(t.Context(), `INSERT INTO edge_target_snapshot_identities(
				tenant_scope_id,snapshot_id,snapshot_revision,identity_id,topology_revision,node_id,tier,
				source_line_group_id,source_revision,endpoint_id,mtls_identity_sha256,created_at)
				VALUES($1,$2,1,$3,1,$3,'l1',$4,1,NULL,$5,now())`, scopeID, snapshotID, nodeID, groupID, identity[:]); err != nil {
				return err
			}
		}
		for index, nodeID := range l2NodeIDs {
			identity := sha256.Sum256([]byte(nodeID.String()))
			if _, err := tx.Exec(t.Context(), `INSERT INTO edge_target_snapshot_identities(
				tenant_scope_id,snapshot_id,snapshot_revision,identity_id,topology_revision,node_id,tier,
				source_line_group_id,source_revision,endpoint_id,mtls_identity_sha256,created_at)
				VALUES($1,$2,1,$3,1,$4,'l2',$5,1,$3,$6,now())`, scopeID, snapshotID, endpointIDs[index], nodeID, groupID, identity[:]); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return scopeID, snapshotID, nodeIDs
}

func sameUUIDs(left, right []uuid.UUID) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
