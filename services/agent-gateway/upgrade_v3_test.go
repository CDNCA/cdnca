package gateway

// Control signs execution v3 for same-version re-releases and cross-version
// plans whose rollback sequence differs from the forward one (libs/entitlement upgrade_execution.go). The
// Gateway only accepted v2, Nak'ed the durable command and dropped the session on every redelivery. The
// edge-agent reports every upgrade status as status v2 (updater emitStatus), which the Gateway refused too.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

// gatewayTestExecution is the execution document as libs/entitlement emits it (field subset plus fields the
// Gateway does not read, so the decoder must ignore them).
func gatewayTestExecution(schema, planID string, planRevision uint64, batchID string,
	executionSequence, releaseSequence, currentReleaseSequence uint64) map[string]any {
	execution := map[string]any{
		"schema": schema, "audience": "cdnca-edge-agent", "purpose": "edge-agent-upgrade", "action": "execute",
		"plan_id": planID, "plan_revision": planRevision, "batch_id": batchID,
		"release_sequence": releaseSequence, "component": "edge-agent", "operation": "upgrade",
		"current_version": "1.0.27", "target_version": "1.0.27",
	}
	if executionSequence != 0 {
		execution["execution_sequence"] = executionSequence
	}
	if currentReleaseSequence != 0 {
		execution["current_release_sequence"] = currentReleaseSequence
	}
	return execution
}

func gatewayTestCommandWithExecution(t *testing.T, base UpgradeCommandRecord, execution map[string]any) []byte {
	t.Helper()
	var command upgradeCommandWire
	if err := json.Unmarshal(base.Encoded, &command); err != nil {
		t.Fatal(err)
	}
	inner, err := json.Marshal(execution)
	if err != nil {
		t.Fatal(err)
	}
	command.SignedExecution, err = json.Marshal(upgradeExecutionEnvelopeWire{
		ControlAlgorithm: "Ed25519", ControlKeyID: "control-1", Execution: inner,
		ControlSignature: "control-signature", EdgeAlgorithm: "Ed25519", EdgeKeyID: "edge-1",
		EdgeSignature: "edge-signature",
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(command.SignedExecution)
	command.SignedExecutionSHA256 = hex.EncodeToString(digest[:])
	encoded, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestGatewayUpgradeCommandAcceptsExecutionV3(t *testing.T) {
	base := validUpgradeCommandRecord(t)
	for _, test := range []struct {
		name      string
		execution map[string]any
	}{
		{name: "same-version re-release", execution: gatewayTestExecution("cdnca.upgrade.execution/v3",
			base.PlanID, base.PlanRevision, base.BatchID, 7, 12, 11)},
		{name: "cross-version with distinct rollback sequence", execution: gatewayTestExecution(
			"cdnca.upgrade.execution/v3", base.PlanID, base.PlanRevision, base.BatchID, 7, 12, 0)},
		{name: "v2", execution: gatewayTestExecution(upgradeExecutionV2Schema,
			base.PlanID, base.PlanRevision, base.BatchID, 0, 12, 0)},
	} {
		t.Run(test.name, func(t *testing.T) {
			encoded := gatewayTestCommandWithExecution(t, base, test.execution)
			record, err := decodeUpgradeCommandRecord(encoded)
			if err != nil || record.CommandID != base.CommandID || record.PlanID != base.PlanID ||
				record.BatchID != base.BatchID || record.SHA256 != sha256.Sum256(encoded) {
				t.Fatalf("decodeUpgradeCommandRecord() = (%#v, %v)", record, err)
			}
		})
	}
}

func TestGatewayUpgradeCommandRejectsInconsistentExecutionSequences(t *testing.T) {
	base := validUpgradeCommandRecord(t)
	v3 := "cdnca.upgrade.execution/v3"
	for _, test := range []struct {
		name      string
		execution map[string]any
	}{
		{name: "v3 without execution sequence", execution: gatewayTestExecution(v3,
			base.PlanID, base.PlanRevision, base.BatchID, 0, 12, 11)},
		{name: "v3 without release sequence", execution: gatewayTestExecution(v3,
			base.PlanID, base.PlanRevision, base.BatchID, 7, 0, 0)},
		{name: "v3 re-release not newer than installed", execution: gatewayTestExecution(v3,
			base.PlanID, base.PlanRevision, base.BatchID, 7, 11, 11)},
		{name: "v2 with execution sequence", execution: gatewayTestExecution(upgradeExecutionV2Schema,
			base.PlanID, base.PlanRevision, base.BatchID, 7, 12, 0)},
		{name: "v2 with installed release sequence", execution: gatewayTestExecution(upgradeExecutionV2Schema,
			base.PlanID, base.PlanRevision, base.BatchID, 0, 12, 11)},
		{name: "unknown schema", execution: gatewayTestExecution("cdnca.upgrade.execution/v4",
			base.PlanID, base.PlanRevision, base.BatchID, 7, 12, 0)},
		{name: "v3 plan mismatch", execution: gatewayTestExecution(v3,
			"00000000-0000-4000-8000-000000000099", base.PlanRevision, base.BatchID, 7, 12, 0)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := decodeUpgradeCommandRecord(gatewayTestCommandWithExecution(t, base, test.execution)); err == nil {
				t.Fatal("inconsistent upgrade execution was accepted")
			}
		})
	}
}

// agentUpgradeStatusV2 is the status wire edge-agent updater emitStatus produces (edgeUpgradeStatusWireV2:
// the v1 fields then active_evidence, null outside healthy/rolled_back).
func agentUpgradeStatusV2(t *testing.T, command UpgradeCommandRecord, revision uint64, state string,
	transaction string, evidence json.RawMessage) []byte {
	t.Helper()
	type wireV1 struct {
		Schema                 string    `json:"schema"`
		StatusID               string    `json:"status_id"`
		StatusRevision         uint64    `json:"status_revision"`
		CommandID              string    `json:"command_id"`
		PlanID                 string    `json:"plan_id"`
		PlanRevision           uint64    `json:"plan_revision"`
		InstallationID         string    `json:"installation_id"`
		NodeID                 string    `json:"node_id"`
		CommandSHA256          string    `json:"command_sha256"`
		State                  string    `json:"state"`
		CurrentVersion         string    `json:"current_version"`
		PreviousVersion        string    `json:"previous_version"`
		InstallerTransactionID string    `json:"installer_transaction_id"`
		ErrorCode              string    `json:"error_code"`
		AlertRequired          bool      `json:"alert_required"`
		ObservedAt             time.Time `json:"observed_at"`
	}
	type wireV2 struct {
		wireV1
		ActiveEvidence json.RawMessage `json:"active_evidence"`
	}
	statusID := sha256.Sum256([]byte(command.CommandID + "/" + state))
	encoded, err := json.Marshal(wireV2{wireV1: wireV1{
		Schema: "cdnca.edge.upgrade.status/v2", StatusID: canonicalTestUUID(statusID[:16]), StatusRevision: revision,
		CommandID: command.CommandID, PlanID: command.PlanID, PlanRevision: command.PlanRevision,
		InstallationID: command.InstallationID, NodeID: command.NodeID,
		CommandSHA256: hex.EncodeToString(command.SHA256[:]), State: state, InstallerTransactionID: transaction,
		ObservedAt: time.Unix(200, 123000).UTC(),
	}, ActiveEvidence: evidence})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func canonicalTestUUID(raw []byte) string {
	value := append([]byte(nil), raw...)
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	encoded := hex.EncodeToString(value)
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
}

// testActiveEvidence is updater ActiveProbeEvidence in its struct field order; extra is appended verbatim.
func testActiveEvidence(drop, extra string) json.RawMessage {
	digest := `"` + hex.EncodeToString(make([]byte, sha256.Size)) + `"`
	fields := [][2]string{{"schema", `"cdnca.edge.upgrade.active-probe/v1"`}, {"active_artifact_sha256", digest},
		{"active_config_sha256", digest}, {"last_known_good_artifact_sha256", digest},
		{"last_known_good_config_sha256", digest}, {"probe_observed_at", `"1970-01-01T00:03:19Z"`},
		{"probe_deadline", `"1970-01-01T00:04:00Z"`}, {"evidence_sha256", digest}}
	encoded := "{"
	for _, field := range fields {
		if field[0] == drop {
			continue
		}
		if len(encoded) > 1 {
			encoded += ","
		}
		encoded += `"` + field[0] + `":` + field[1]
	}
	return json.RawMessage(encoded + extra + "}")
}

func TestGatewayAcceptsAgentUpgradeStatusV2(t *testing.T) {
	command := validUpgradeCommandRecord(t)
	accepted := agentUpgradeStatusV2(t, command, 1, "accepted", "", nil)
	record, err := decodeUpgradeStatusRecord(accepted)
	if err != nil || record.State != "accepted" || record.CommandID != command.CommandID ||
		commandStatusDigest(accepted) != hex.EncodeToString(command.SHA256[:]) {
		t.Fatalf("agent accepted status v2 = (%#v, %v)", record, err)
	}
	healthy := agentUpgradeStatusV2(t, command, 4, "healthy", "txn-1", testActiveEvidence("", ""))
	if record, err := decodeUpgradeStatusRecord(healthy); err != nil || record.State != "healthy" {
		t.Fatalf("agent healthy status v2 = (%#v, %v)", record, err)
	}

	bus := &fakeUpgradeBus{}
	gateway := &Gateway{config: DefaultConfig(), upgrades: bus, now: func() time.Time { return time.Unix(300, 0) }}
	delivery := &fakeUpgradeDelivery{command: command}
	pending := pendingUpgradeCommandSet{command.CommandID: {command: command, deliveries: []UpgradeCommandDelivery{delivery}}}
	ack, err := gateway.persistUpgradeStatusAndAckCommand(t.Context(), command.NodeID, command.InstallationID,
		accepted, pending, true)
	if err != nil || ack == nil || string(bus.published) != string(accepted) || delivery.acks.Load() != 1 || len(pending) != 0 {
		t.Fatalf("accepted v2 status = (%+v, %v), published %q acks %d", ack, err, bus.published, delivery.acks.Load())
	}
}

func TestGatewayRejectsMalformedUpgradeStatusV2(t *testing.T) {
	command := validUpgradeCommandRecord(t)
	for _, test := range []struct {
		name    string
		encoded []byte
	}{
		{name: "evidence with unknown field", encoded: agentUpgradeStatusV2(t, command, 4, "healthy", "txn-1",
			testActiveEvidence("", `,"extra":"x"`))},
		{name: "evidence missing field", encoded: agentUpgradeStatusV2(t, command, 4, "healthy", "txn-1",
			testActiveEvidence("evidence_sha256", ""))},
		{name: "evidence not an object", encoded: agentUpgradeStatusV2(t, command, 4, "healthy", "txn-1",
			json.RawMessage(`"evidence"`))},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := decodeUpgradeStatusRecord(test.encoded); err == nil {
				t.Fatal("malformed status was accepted")
			}
		})
	}
}
