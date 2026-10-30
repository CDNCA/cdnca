//go:build integration

package securityactivation

import (
	"crypto/sha256"
	"slices"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
)

// A v2 activation refused because target nodes lack
// SITE_QUIC (OpenResty without the HTTP/3 module; edgepublish refuses v2 HTTPS without it) is
// recorded as a capability wait, stays waiting while the nodes still lack
// it, and is started by the activation worker once both nodes' latest
// sessions declare SITE_QUIC.
func TestActivationRefusedForSiteQUICWaitsAndResumesAfterUpgrade(t *testing.T) {
	fixture := newV2ActivationFixture(t)
	store := newProductionActivationStore(t, fixture.activationFixture)
	nodes := []uuid.UUID{fixture.canaryNodeID, fixture.expandNodeID}
	sessions := func(epoch int64, http3 bool) {
		t.Helper()
		features := []*agentv1.Capability{
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1, ApiVersion: 1},
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_2, ApiVersion: 1},
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_WEBSOCKET, ApiVersion: 1},
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_IPV4, ApiVersion: 1},
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_IPV6, ApiVersion: 1},
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME, ApiVersion: edgeconfig.DynamicRoutingSiteRuntimeVersion},
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_CC, ApiVersion: 4},
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_WAF, ApiVersion: 1},
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_ATOMIC_RELEASE, ApiVersion: 1},
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_CONFIG_PRECHECK, ApiVersion: 1},
		}
		if http3 {
			features = append(features, &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_QUIC, ApiVersion: 1})
		}
		slices.SortFunc(features, func(left, right *agentv1.Capability) int { return int(left.Name) - int(right.Name) })
		if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role = replica`); err != nil {
				return err
			}
			for _, nodeID := range nodes {
				snapshot, err := proto.MarshalOptions{Deterministic: true}.Marshal(&agentv1.AgentCapabilities{
					AgentVersion: "1.0.35", BuildId: "h3", OperatingSystem: "linux", Architecture: "amd64", Features: features})
				if err != nil {
					return err
				}
				digest := sha256.Sum256(snapshot)
				if _, err := tx.Exec(t.Context(), `INSERT INTO node_session_capabilities(node_id,session_epoch,certificate_id,
					certificate_sha256,artifact_key_id,selected_protocol_major,selected_protocol_minor,capabilities_snapshot,
					capabilities_sha256,facts_snapshot,facts_sha256,gateway_workload_identity,gateway_instance_id,registered_at)
					VALUES($1,$2,$3,$4,'x25519:test',1,0,$5,$4,'\x01',$4,'gw','gw-1',$6)`,
					nodeID, 1000+epoch, uuid.New(), digest[:], snapshot, fixture.now); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	sessions(1, false)

	input := prepareProductionStart(t, fixture.activationFixture, store, "h3-wait", nodes, 1)
	input.SiteRuntimeSchema = ""
	refusal := &edgepublish.TargetCapabilityError{NodeID: nodes[0], AgentVersion: "1.0.35",
		Capability: agentv1.CapabilityName_CAPABILITY_NAME_SITE_QUIC, Required: 1, OtherNodeIDs: nodes[1:]}
	if err := store.recordCapabilityWait(t.Context(), fixture.actor, input, refusal); err != nil {
		t.Fatal(err)
	}
	waitState := func() (string, int32, *uuid.UUID) {
		t.Helper()
		var status string
		var capability int32
		var candidate *uuid.UUID
		if err := fixture.pool.QueryRow(t.Context(), `SELECT status,capability,resumed_candidate_id
			FROM security_activation_capability_waits WHERE site_id=$1 AND policy_id=$2`, fixture.siteID, fixture.policyID).
			Scan(&status, &capability, &candidate); err != nil {
			t.Fatalf("capability wait: %v", err)
		}
		return status, capability, candidate
	}
	if status, capability, _ := waitState(); status != "waiting" ||
		capability != int32(agentv1.CapabilityName_CAPABILITY_NAME_SITE_QUIC) {
		t.Fatalf("SITE_QUIC wait = %s capability %d", status, capability)
	}

	worker, err := NewWorker(store)
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.reconcile(t.Context()); err != nil {
		t.Fatalf("reconcile while nodes lack SITE_QUIC: %v", err)
	}
	if status, _, _ := waitState(); status != "waiting" {
		t.Fatalf("wait resumed before the nodes declared SITE_QUIC: %s", status)
	}

	sessions(2, true)
	if err := worker.reconcile(t.Context()); err != nil {
		t.Fatalf("reconcile after the upgrade: %v", err)
	}
	if status, _, candidate := waitState(); status != "resumed" || candidate == nil {
		t.Fatalf("wait after the nodes declared SITE_QUIC = %s, candidate %v", status, candidate)
	}
}
