//go:build integration

package artifactsetdist

import (
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	"github.com/cdnca/cdnca/libs/entitlement/enginemodule/enginemoduletest"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/audit/audittest"
	"github.com/cdnca/cdnca/services/control-api/internal/edgestatus"
	"github.com/jackc/pgx/v5"
)

// An amd64 node declaring WAF_CRS_MODULE gets the amd64 engine module (not
// the arm64 one) in its set; the node refusing it (signature_invalid) keeps
// its set and is audited as node.engine_module.install_reject with the
// node's address; once it accepts, node.engine_module.install records the
// module before -> after.
func TestDistributorDeliversTheNodesEngineModule(t *testing.T) {
	harness := newDistHarness(t)
	harness.reject = map[string]string{}
	harness.exec(`UPDATE nodes SET ipv4='192.0.2.10' WHERE id=$1`, harness.nodeID)
	harness.sessionWith(harness.nodeID, 2, &agentv1.AgentCapabilities{AgentVersion: "1.0.35", OperatingSystem: "linux",
		Architecture: "amd64", OpenrestyVersion: enginemoduletest.DefaultOpenResty, Features: []*agentv1.Capability{
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_ARTIFACT_SET, ApiVersion: 1},
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_WAF_CRS_MODULE, ApiVersion: 1}}})
	amd, amdBytes := engineModuleArtifact(t, "amd64")
	arm, armBytes := engineModuleArtifact(t, "arm64")
	harness.source.artifacts = []LocalArtifact{amd, arm}
	harness.source.objects = map[string][]byte{amd.SHA256: amdBytes, arm.SHA256: armBytes}
	harness.reject[amd.ArtifactID] = artifactset.ReasonSignatureInvalid

	deliver := func() artifactset.Receipt {
		for range 16 {
			harness.sweep()
			item := harness.one(harness.pending()[0].mediaType)
			if receipt := harness.agent(item); item.mediaType == artifactset.MediaTypeSet {
				return receipt
			}
		}
		t.Fatal("set never delivered")
		return artifactset.Receipt{}
	}
	receipt := deliver()
	if len(receipt.Items) != 1 || receipt.Items[0].ArtifactID != amd.ArtifactID ||
		receipt.Result != artifactset.ResultRejected || receipt.Items[0].Reason != artifactset.ReasonSignatureInvalid {
		t.Fatalf("first receipt %+v", receipt)
	}
	if harness.count(`SELECT count(*) FROM node_artifact_sets WHERE node_id=$1`, harness.plainNodeID) != 0 {
		t.Fatal("node without ARTIFACT_SET/WAF_CRS_MODULE got a set")
	}
	delete(harness.reject, amd.ArtifactID)
	harness.clock = harness.clock.Add(11 * time.Minute)
	if receipt = deliver(); receipt.Result != artifactset.ResultApplied {
		t.Fatalf("retried receipt %+v", receipt)
	}
	// 统一日志（迁移 361）起 payload 的 changes 移到 changes 列。
	rows, err := harness.pool.Query(harness.ctx, `SELECT action,result,payload,changes FROM audit_events
		WHERE resource_type='node_engine_module' AND resource_id=$1 ORDER BY stream_position`, harness.nodeID.String())
	if err != nil {
		t.Fatal(err)
	}
	events, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (auditEvent, error) {
		var event auditEvent
		var changes []byte
		if err := row.Scan(&event.action, &event.result, &event.payload, &changes); err != nil {
			return event, err
		}
		event.changes = audittest.DecodeChanges(t, changes)
		return event, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].action != edgestatus.EngineModuleRejectAuditAction || events[0].result != "failure" ||
		events[0].payload["reason_code"] != artifactset.ReasonSignatureInvalid ||
		events[1].action != edgestatus.EngineModuleInstallAuditAction || events[1].result != "success" {
		t.Fatalf("engine module audits %+v", events)
	}
	for _, event := range events {
		if event.payload["ip"] != "192.0.2.10" || event.payload["artifact_id"] != amd.ArtifactID || event.payload["actor_kind"] != "node" {
			t.Fatalf("audit payload %v", event.payload)
		}
	}
	install := events[1].changes
	if len(install) != 1 || install[0].Field != "engine_module" || install[0].Before != nil {
		t.Fatalf("install change %+v", install)
	}
	if after, _ := install[0].After.(map[string]any); after["artifact_id"] != amd.ArtifactID {
		t.Fatalf("install change after %+v", install[0].After)
	}
}
