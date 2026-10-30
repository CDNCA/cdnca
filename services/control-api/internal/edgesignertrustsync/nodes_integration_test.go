//go:build integration

package edgesignertrustsync

import (
	"crypto/sha256"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
)

// ActiveNodes gates delivery on the capability of each node's latest session:
// an Agent downgraded below EDGE_SIGNER_TRUST stops receiving bundles, a node
// that never connected gets none.
func TestActiveNodesUseLatestSessionCapability(t *testing.T) {
	pool := signerTrustPool(t)
	upgraded := seedNode(t, pool)
	sibling := func() uuid.UUID {
		nodeID := uuid.New()
		if _, err := pool.Exec(t.Context(), `WITH source AS (SELECT scope_id,created_by_user_id FROM nodes WHERE id=$2),
			allocated AS (UPDATE node_display_id_sequences SET next_value=next_value+1, updated_at=now()
				WHERE scope_id=(SELECT scope_id FROM source) RETURNING next_value-1 AS display_id)
			INSERT INTO nodes (id,display_id,scope_id,name,admin_state,created_by_user_id)
			SELECT $1,allocated.display_id,source.scope_id,$3,'active',source.created_by_user_id FROM source,allocated`,
			nodeID, upgraded, "signer-trust-node-"+nodeID.String()[:8]); err != nil {
			t.Fatal(err)
		}
		return nodeID
	}
	downgraded, silent := sibling(), sibling()
	session := func(nodeID uuid.UUID, epoch int64, signerTrust bool) {
		features := []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1, ApiVersion: 1}}
		if signerTrust {
			features = append(features, &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_SIGNER_TRUST, ApiVersion: 1})
		}
		snapshot, err := proto.Marshal(&agentv1.AgentCapabilities{AgentVersion: "1.0.35", Features: features})
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(snapshot)
		if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role = replica`); err != nil {
				return err
			}
			_, err := tx.Exec(t.Context(), `INSERT INTO node_session_capabilities(node_id,session_epoch,certificate_id,
				certificate_sha256,artifact_key_id,selected_protocol_major,selected_protocol_minor,capabilities_snapshot,
				capabilities_sha256,facts_snapshot,facts_sha256,gateway_workload_identity,gateway_instance_id,registered_at)
				VALUES($1,$2,$3,$4,'x25519:test',1,0,$5,$4,'\x01',$4,'gw','gw-1',$6)`,
				nodeID, epoch, uuid.New(), digest[:], snapshot, time.Now())
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	session(upgraded, 1, false)
	session(upgraded, 2, true)
	session(downgraded, 1, true)
	session(downgraded, 2, false)
	nodes, err := ActiveNodes(pool)(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, node := range nodes {
		got[node.ID] = node.Capable
	}
	if len(got) != 3 || !got[upgraded.String()] || got[downgraded.String()] || got[silent.String()] {
		t.Fatalf("ActiveNodes = %+v", nodes)
	}
}
