//go:build integration

package edgepublish

import (
	"slices"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// per-node-dist (待出包前全量跑): two nodes, each in its own line group, and a
// forward on each group plus one following no group. Every node gets the
// same signed root; a node declaring L4_STREAM_SELECTION is withheld the
// other group's forward, the groupless forward goes to both, and an older
// node is withheld nothing.
func TestSiteObjectKeyWithholdsForwardsOfOtherLineGroups(t *testing.T) {
	scope := NewSystemRepublishScope(t)
	nodeA, nodeB, nodeOld := scope.AddNode(t, 12), scope.AddNode(t, 12), scope.AddNode(t, 12)
	// The fixture forwards send PROXY protocol v1 (createStream).
	older := append(systemRepublishFeatures(12),
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_PROXY_PROTOCOL, ApiVersion: 1})
	selection := append(slices.Clone(older),
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_L4_STREAM_SELECTION, ApiVersion: 1})
	seedNodeSessionCapabilitiesForTest(t, scope.Pool, nodeA, "1.0.35-sel", selection)
	seedNodeSessionCapabilitiesForTest(t, scope.Pool, nodeB, "1.0.35-sel", selection)
	seedNodeSessionCapabilitiesForTest(t, scope.Pool, nodeOld, "1.0.35-old", older)
	groupA := seedStreamLineGroup(t, scope, "198.51.100.81", nodeA)
	groupB := seedStreamLineGroup(t, scope, "198.51.100.82", nodeB, nodeOld)
	streamA := scope.fixture.createStream(t, "group-a", 9601, "203.0.113.61", 9701).Forward.ID
	streamB := scope.fixture.createStream(t, "group-b", 9602, "203.0.113.62", 9702).Forward.ID
	streamAll := scope.fixture.createStream(t, "no-group", 9603, "203.0.113.63", 9703).Forward.ID
	scope.Exec(t, `UPDATE l4_forwards SET node_group_id=$2 WHERE id=$1`, streamA, groupA)
	scope.Exec(t, `UPDATE l4_forwards SET node_group_id=$2 WHERE id=$1`, streamB, groupB)
	// No line group of its own, and the fixture package's snapshot names none (092: the package is NOT NULL).
	scope.Exec(t, `UPDATE l4_forwards SET node_group_id=NULL,backup_node_group_id=NULL WHERE id=$1`, streamAll)
	scope.AdvanceRevision(t)

	request := scope.fixture.publishRequest("per-node-streams", nodeA)
	request.NodeIDs = []uuid.UUID{nodeA, nodeB, nodeOld}
	result, err := scope.fixture.service.Publish(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	roots := map[string]bool{}
	withheld := map[uuid.UUID][]string{}
	for _, nodeID := range request.NodeIDs {
		release := receivedV2Release(t, scope.fixture, result, nodeID, scope.fixture.nodeKeys[nodeID])
		roots[release.RootSHA256] = true
		if release.Scope.Streams == nil || len(release.Scope.Streams.StreamsV2) != 3 {
			t.Fatalf("node %s root streams = %+v", nodeID, release.Scope.Streams)
		}
		withheld[nodeID] = release.L4WithheldStreams
	}
	if len(roots) != 1 {
		t.Fatalf("nodes got %d roots, want one shared signed root", len(roots))
	}
	if !slices.Equal(withheld[nodeA], []string{streamB.String()}) || !slices.Equal(withheld[nodeB], []string{streamA.String()}) {
		t.Fatalf("withheld A=%v B=%v (stream A %s, B %s)", withheld[nodeA], withheld[nodeB], streamA, streamB)
	}
	if withheld[nodeOld] != nil {
		t.Fatalf("older node withheld %v", withheld[nodeOld])
	}
}

// seedStreamLineGroup is a sealed line group of the scope at revision 1
// whose enabled endpoints are nodes.
func seedStreamLineGroup(t *testing.T, scope *SystemRepublishScope, address string, nodes ...uuid.UUID) uuid.UUID {
	t.Helper()
	groupID := uuid.New()
	if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO node_line_groups(id,tenant_scope_id,name,current_revision,
			created_by_user_id,updated_by_user_id,created_at,updated_at) VALUES($1::uuid,$2,'per-node-'||$1::uuid::text,1,$3,$3,now(),now())`,
			groupID, scope.ScopeID, scope.UserID); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO node_line_group_revisions(line_group_id,tenant_scope_id,revision,name,
			resolved_value,probe_interval_ms,probe_timeout_ms,failure_threshold,recovery_threshold,failure_debounce_ms,
			recovery_debounce_ms,endpoint_count,configuration_digest,created_by_user_id,created_at)
			VALUES($1::uuid,$2,1,'per-node-'||$1::uuid::text,'lg-'||replace($1::uuid::text,'-',''),10000,3000,3,3,0,0,$3,$4,$5,now())`,
			groupID, scope.ScopeID, len(nodes), make([]byte, 32), scope.UserID); err != nil {
			return err
		}
		for index, nodeID := range nodes {
			if _, err := tx.Exec(t.Context(), `INSERT INTO node_line_endpoints(id,node_id,tenant_scope_id,line_group_id,
				config_revision,address,address_family,port,region,carrier,priority,weight,enabled)
				VALUES($1,$2,$3,$4,1,$5::inet,4,443,'','',0,1,true)`, uuid.New(), nodeID, scope.ScopeID, groupID,
				address[:len(address)-1]+string(rune('1'+index))); err != nil {
				return err
			}
		}
		// 227/234: the current revision is sealed only with one health row per endpoint.
		if _, err := tx.Exec(t.Context(), `INSERT INTO node_line_endpoint_health(tenant_scope_id,line_group_id,config_revision,
			endpoint_id,status,consecutive_successes,consecutive_failures,last_sequence,last_changed_at,row_revision,created_at,updated_at)
			SELECT $1,$2,1,id,'unknown',0,0,0,now(),1,now(),now()
			FROM node_line_endpoints WHERE tenant_scope_id=$1 AND line_group_id=$2`, scope.ScopeID, groupID); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `UPDATE node_line_group_revisions SET sealed_at=now()
			WHERE tenant_scope_id=$1 AND line_group_id=$2 AND revision=1`, scope.ScopeID, groupID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return groupID
}
