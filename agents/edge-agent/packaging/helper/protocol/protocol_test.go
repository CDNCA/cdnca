package protocol

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const testDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func testReceipt() Receipt {
	return Receipt{
		SchemaVersion: 1, InstallerTransactionID: "txn-123", ReleaseSequence: 2,
		ArtifactSHA256: testDigest, CurrentVersion: "1.1.0", PreviousVersion: "1.0.0",
		Status: "active", IssuedAt: time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC),
		Signature: Signature{KeyID: "helper-2026-01", Value: base64.RawStdEncoding.EncodeToString(make([]byte, 64))},
	}
}

func testPreparedAck() PreparedAck {
	return PreparedAck{
		SchemaVersion: 1, TransactionID: "txn-123", InstallPayloadSHA256: testDigest,
		ReleaseSequence: 2, ArtifactSHA256: testDigest, ManifestSHA256: testDigest,
		ExecutableSHA256: testDigest, SBOMSHA256: testDigest,
		PreviousVersion: "1.0.0", TargetVersion: "1.1.0",
	}
}

func TestCanonicalRequestShapes(t *testing.T) {
	receipt := testReceipt()
	ack := testPreparedAck()
	receiptJSON, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	ackJSON, err := json.Marshal(ack)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		request Request
		want    string
	}{
		{"current", Request{ProtocolVersion: 1, Operation: OperationCurrent}, `{"protocol_version":1,"operation":"current"}`},
		{"query", Request{ProtocolVersion: 1, Operation: OperationQuery, TransactionID: "txn-123"}, `{"protocol_version":1,"operation":"query","transaction_id":"txn-123"}`},
		{"install", Request{ProtocolVersion: 1, Operation: OperationInstall, TransactionID: "txn-123", ReleaseSequence: 2, CurrentVersion: "1.0.0", TargetVersion: "1.1.0", Platform: "linux", Architecture: "amd64", ArtifactSHA256: testDigest, ArtifactSize: 1234, AuditBasename: "artifact", CurrentReceipt: &receipt}, ""},
		{"rollback", Request{ProtocolVersion: 1, Operation: OperationRollback, TransactionID: "txn-123", ReleaseSequence: 2, ArtifactSHA256: testDigest, ExpectedCurrentVersion: "1.1.0", RollbackVersion: "1.0.0", ActiveReceipt: &receipt, PreviousReceipt: &receipt}, ""},
		{"prepare-v2", Request{ProtocolVersion: JournalVersion, Operation: OperationPrepareInstall, TransactionID: "txn-123", ReleaseSequence: 2, CurrentVersion: "1.0.0", TargetVersion: "1.1.0", Platform: "linux", Architecture: "amd64", ArtifactSHA256: testDigest, ArtifactSize: 1234, AuditBasename: "artifact", CurrentReceipt: &receipt}, `{"protocol_version":2,"operation":"prepare_install","transaction_id":"txn-123","release_sequence":2,"current_version":"1.0.0","target_version":"1.1.0","platform":"linux","architecture":"amd64","artifact_sha256":"` + testDigest + `","artifact_size":1234,"audit_basename":"artifact","current_receipt":` + string(receiptJSON) + `}`},
		{"inspect-v2", Request{ProtocolVersion: JournalVersion, Operation: OperationInspectTransaction, TransactionID: "txn-123"}, `{"protocol_version":2,"operation":"inspect_transaction","transaction_id":"txn-123"}`},
		{"mark-installing-v4", Request{ProtocolVersion: JournalV4Version, Operation: OperationMarkInstalling, TransactionID: "txn-123", InstallPayloadSHA256: testDigest, PreparedAck: &ack}, `{"protocol_version":4,"operation":"mark_installing","transaction_id":"txn-123","install_payload_sha256":"` + testDigest + `","prepared_ack":` + string(ackJSON) + `}`},
		{"activate-v2", Request{ProtocolVersion: JournalVersion, Operation: OperationActivateInstall, TransactionID: "txn-123", InstallPayloadSHA256: testDigest, PreparedAck: &ack}, `{"protocol_version":2,"operation":"activate_install","transaction_id":"txn-123","install_payload_sha256":"` + testDigest + `","prepared_ack":` + string(ackJSON) + `}`},
		{"abort-prepared-v2", Request{ProtocolVersion: JournalVersion, Operation: OperationAbortPrepared, TransactionID: "txn-123", InstallPayloadSHA256: testDigest, PreparedAck: &ack}, `{"protocol_version":2,"operation":"abort_prepared","transaction_id":"txn-123","install_payload_sha256":"` + testDigest + `","prepared_ack":` + string(ackJSON) + `}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			packet, err := MarshalRequest(test.request)
			if err != nil {
				t.Fatal(err)
			}
			if test.want != "" && string(packet) != test.want {
				t.Fatalf("packet = %s", packet)
			}
			parsed, err := ParseRequest(packet)
			if err != nil {
				t.Fatal(err)
			}
			reencoded, err := MarshalRequest(parsed)
			if err != nil || !bytes.Equal(packet, reencoded) {
				t.Fatalf("canonical round trip failed: %v", err)
			}
		})
	}
}

func TestProtocolVersionsRejectCrossVersionOperations(t *testing.T) {
	receipt := testReceipt()
	ack := testPreparedAck()
	for _, request := range []Request{
		{ProtocolVersion: Version, Operation: OperationPrepareInstall, TransactionID: "txn-123", ReleaseSequence: 2, CurrentVersion: "1.0.0", TargetVersion: "1.1.0", Platform: "linux", Architecture: "amd64", ArtifactSHA256: testDigest, ArtifactSize: 1234, AuditBasename: "artifact", CurrentReceipt: &receipt},
		{ProtocolVersion: JournalVersion, Operation: OperationInstall, TransactionID: "txn-123", ReleaseSequence: 2, CurrentVersion: "1.0.0", TargetVersion: "1.1.0", Platform: "linux", Architecture: "amd64", ArtifactSHA256: testDigest, ArtifactSize: 1234, AuditBasename: "artifact", CurrentReceipt: &receipt},
		{ProtocolVersion: Version, Operation: OperationActivateInstall, TransactionID: "txn-123", InstallPayloadSHA256: testDigest, PreparedAck: &ack},
		{ProtocolVersion: Version, Operation: OperationAbortPrepared, TransactionID: "txn-123", InstallPayloadSHA256: testDigest, PreparedAck: &ack},
		{ProtocolVersion: JournalVersion, Operation: OperationMarkInstalling, TransactionID: "txn-123", InstallPayloadSHA256: testDigest, PreparedAck: &ack},
		{ProtocolVersion: 4, Operation: OperationInspectTransaction, TransactionID: "txn-123"},
	} {
		if _, err := MarshalRequest(request); err == nil {
			t.Fatalf("accepted cross-version request: %#v", request)
		}
	}
}

func TestMarkInstallingExtensionUsesNegotiatedProtocolVersion(t *testing.T) {
	ack := testPreparedAck()
	request := Request{
		ProtocolVersion: 4, Operation: OperationMarkInstalling,
		TransactionID: ack.TransactionID, InstallPayloadSHA256: ack.InstallPayloadSHA256, PreparedAck: &ack,
	}
	if _, err := MarshalRequest(request); err != nil {
		t.Fatalf("mark_installing extension was rejected: %v", err)
	}
}

func TestAbortPreparedRequestRequiresExactPreparedBinding(t *testing.T) {
	ack := testPreparedAck()
	valid := Request{
		ProtocolVersion: JournalVersion, Operation: OperationAbortPrepared,
		TransactionID: ack.TransactionID, InstallPayloadSHA256: ack.InstallPayloadSHA256, PreparedAck: &ack,
	}
	if _, err := MarshalRequest(valid); err != nil {
		t.Fatalf("valid abort prepared request: %v", err)
	}
	differentDigest := strings.Repeat("a", 64)
	differentAck := ack
	differentAck.InstallPayloadSHA256 = differentDigest
	for _, request := range []Request{
		{ProtocolVersion: JournalVersion, Operation: OperationAbortPrepared, TransactionID: ack.TransactionID, InstallPayloadSHA256: ack.InstallPayloadSHA256},
		{ProtocolVersion: JournalVersion, Operation: OperationAbortPrepared, TransactionID: "txn-other", InstallPayloadSHA256: ack.InstallPayloadSHA256, PreparedAck: &ack},
		{ProtocolVersion: JournalVersion, Operation: OperationAbortPrepared, TransactionID: ack.TransactionID, InstallPayloadSHA256: differentDigest, PreparedAck: &ack},
		{ProtocolVersion: JournalVersion, Operation: OperationAbortPrepared, TransactionID: ack.TransactionID, InstallPayloadSHA256: ack.InstallPayloadSHA256, PreparedAck: &differentAck},
		{ProtocolVersion: JournalVersion, Operation: OperationAbortPrepared, TransactionID: ack.TransactionID, InstallPayloadSHA256: ack.InstallPayloadSHA256, PreparedAck: &ack, ReleaseSequence: ack.ReleaseSequence},
	} {
		if _, err := MarshalRequest(request); err == nil {
			t.Fatalf("accepted unbound abort prepared request: %#v", request)
		}
	}
}

func TestPreparedAckRejectsEqualVersions(t *testing.T) {
	ack := testPreparedAck()
	ack.TargetVersion = ack.PreviousVersion
	request := Request{
		ProtocolVersion: JournalVersion, Operation: OperationAbortPrepared,
		TransactionID: ack.TransactionID, InstallPayloadSHA256: ack.InstallPayloadSHA256, PreparedAck: &ack,
	}
	if _, err := MarshalRequest(request); err == nil {
		t.Fatal("accepted prepared acknowledgement with equal previous and target versions")
	}
}

func TestRejectsNonCanonicalAndMalformedRequests(t *testing.T) {
	valid := `{"protocol_version":1,"operation":"query","transaction_id":"txn-123"}`
	cases := []string{
		` {"protocol_version":1,"operation":"query","transaction_id":"txn-123"}`,
		`{"operation":"query","protocol_version":1,"transaction_id":"txn-123"}`,
		`{"protocol_version":1,"operation":"query","transaction_id":"txn-123","unknown":1}`,
		`{"protocol_version":1,"operation":"query","transaction_id":"txn-123","transaction_id":"txn-123"}`,
		valid + "\n",
		`{"protocol_version":1,"operation":"query","transaction_id":null}`,
	}
	for _, packet := range cases {
		if _, err := ParseRequest([]byte(packet)); err == nil {
			t.Fatalf("accepted non-canonical packet %q", packet)
		}
	}
	if _, err := ParseRequest(bytes.Repeat([]byte{'x'}, MaxPacketBytes+1)); err == nil {
		t.Fatal("accepted oversized packet")
	}
}

func TestResponseRequiresExactStableShape(t *testing.T) {
	receipt := testReceipt()
	ack := testPreparedAck()
	status := TransactionStatus{TransactionID: ack.TransactionID, Phase: TransactionPrepared, PreparedAck: &ack}
	for _, response := range []Response{
		Success(receipt), Failure(ErrorTransactionUnknown),
		Prepared(JournalVersion, ack), Inspected(JournalVersion, status),
		SuccessForVersion(JournalVersion, receipt), FailureForVersion(JournalVersion, ErrorTransactionConflict),
	} {
		packet, err := MarshalResponse(response)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseResponse(packet); err != nil {
			t.Fatal(err)
		}
	}
	for _, packet := range []string{
		`{"protocol_version":1,"ok":false,"error_code":"ERR_NOT_FROZEN"}`,
		`{"protocol_version":1,"ok":true,"error_code":"ERR_INTERNAL"}`,
		`{"protocol_version":1,"ok":false}`,
		`{"protocol_version":2,"ok":true,"receipt":` + string(mustJSON(t, receipt)) + `,"prepared_ack":` + string(mustJSON(t, ack)) + `}`,
		`{"protocol_version":2,"ok":true,"transaction_status":{"transaction_id":"txn-123","phase":"unknown","prepared_ack":` + string(mustJSON(t, ack)) + `}}`,
	} {
		if _, err := ParseResponse([]byte(packet)); err == nil {
			t.Fatalf("accepted invalid response %s", packet)
		}
	}
}

func TestTransactionStatusShapesAreExact(t *testing.T) {
	ack := testPreparedAck()
	receipt := testReceipt()
	receipt.InstallerTransactionID = ack.TransactionID
	receipt.ReleaseSequence = ack.ReleaseSequence
	receipt.ArtifactSHA256 = ack.ArtifactSHA256
	receipt.CurrentVersion = ack.TargetVersion
	receipt.PreviousVersion = ack.PreviousVersion
	statuses := []TransactionStatus{
		{TransactionID: "missing", Phase: TransactionUnknown},
		{TransactionID: ack.TransactionID, Phase: TransactionPrepared, PreparedAck: &ack},
		{TransactionID: ack.TransactionID, Phase: TransactionAborted, PreparedAck: &ack},
		{TransactionID: ack.TransactionID, Phase: TransactionInstalling, PreparedAck: &ack},
		{TransactionID: ack.TransactionID, Phase: TransactionActive, PreparedAck: &ack, Receipt: &receipt},
	}
	rolledBack := receipt
	rolledBack.Status = "rolled_back"
	rolledBack.CurrentVersion = ack.PreviousVersion
	rolledBack.PreviousVersion = ack.TargetVersion
	statuses = append(statuses, TransactionStatus{TransactionID: ack.TransactionID, Phase: TransactionRolledBack, PreparedAck: &ack, Receipt: &rolledBack})
	for _, status := range statuses {
		packet, err := MarshalResponse(Inspected(JournalVersion, status))
		if err != nil {
			t.Fatalf("status %s: %v", status.Phase, err)
		}
		if _, err := ParseResponse(packet); err != nil {
			t.Fatalf("status %s round trip: %v", status.Phase, err)
		}
	}
	for _, status := range []TransactionStatus{
		{TransactionID: ack.TransactionID, Phase: TransactionAborted},
		{TransactionID: ack.TransactionID, Phase: TransactionAborted, PreparedAck: &ack, Receipt: &receipt},
	} {
		if _, err := MarshalResponse(Inspected(JournalVersion, status)); err == nil {
			t.Fatalf("accepted invalid aborted status: %#v", status)
		}
	}
}

func TestArtifactLimitMatchesFrozenBundle(t *testing.T) {
	receipt := testReceipt()
	request := Request{ProtocolVersion: 1, Operation: OperationInstall, TransactionID: "txn-123", ReleaseSequence: 2, CurrentVersion: "1.0.0", TargetVersion: "1.1.0", Platform: "linux", Architecture: "amd64", ArtifactSHA256: testDigest, ArtifactSize: MaxArtifactBytes, AuditBasename: "artifact", CurrentReceipt: &receipt}
	if _, err := MarshalRequest(request); err != nil {
		t.Fatalf("maximum canonical bundle rejected: %v", err)
	}
	request.ArtifactSize++
	if _, err := MarshalRequest(request); err == nil {
		t.Fatal("bundle above frozen limit accepted")
	}
}

func TestQueryRecoveryUsesInstallTimeout(t *testing.T) {
	if OperationTimeout(OperationQuery) != OperationTimeout(OperationInstall) {
		t.Fatalf("query timeout = %s, install timeout = %s", OperationTimeout(OperationQuery), OperationTimeout(OperationInstall))
	}
	if OperationTimeout(OperationCurrent) >= OperationTimeout(OperationQuery) {
		t.Fatalf("current timeout = %s, query timeout = %s", OperationTimeout(OperationCurrent), OperationTimeout(OperationQuery))
	}
	if OperationTimeout(OperationInspectTransaction) != OperationTimeout(OperationCurrent) {
		t.Fatalf("inspect timeout = %s, current timeout = %s", OperationTimeout(OperationInspectTransaction), OperationTimeout(OperationCurrent))
	}
	if OperationTimeout(OperationPrepareInstall) != OperationTimeout(OperationMarkInstalling) ||
		OperationTimeout(OperationMarkInstalling) != OperationTimeout(OperationActivateInstall) ||
		OperationTimeout(OperationActivateInstall) != OperationTimeout(OperationAbortPrepared) ||
		OperationTimeout(OperationAbortPrepared) != OperationTimeout(OperationInstall) {
		t.Fatalf("v2 mutation timeouts differ: prepare=%s activate=%s abort=%s install=%s", OperationTimeout(OperationPrepareInstall), OperationTimeout(OperationActivateInstall), OperationTimeout(OperationAbortPrepared), OperationTimeout(OperationInstall))
	}
}

func TestPrintableFieldGrammarAndSignatureAreStrict(t *testing.T) {
	receipt := testReceipt()
	receipt.CurrentVersion = strings.Repeat("a", 129)
	if _, err := MarshalResponse(Success(receipt)); err == nil {
		t.Fatal("accepted oversized identifier")
	}
	receipt = testReceipt()
	receipt.Signature.Value += "="
	if _, err := MarshalResponse(Success(receipt)); err == nil {
		t.Fatal("accepted padded signature")
	}
}

func TestProtocolV3CanonicalDualSequenceShapes(t *testing.T) {
	receipt := testReceipt()
	receipt.SchemaVersion = 2
	receipt.ExecutionSequence = 23
	receipt.ReleaseSequence = 7
	ack := testPreparedAck()
	ack.SchemaVersion = 2
	ack.ExecutionSequence = receipt.ExecutionSequence
	ack.ReleaseSequence = receipt.ReleaseSequence
	rolledBackReceipt := receipt
	rolledBackReceipt.Status = "rolled_back"
	rolledBackReceipt.CurrentVersion = ack.PreviousVersion
	rolledBackReceipt.PreviousVersion = ack.TargetVersion
	request := Request{
		ProtocolVersion: JournalV3Version, Operation: OperationPrepareInstall,
		TransactionID: ack.TransactionID, ExecutionSequence: ack.ExecutionSequence,
		ReleaseSequence: ack.ReleaseSequence, Action: ActionRollback,
		CurrentVersion: "2.0.0", TargetVersion: "1.0.0", Platform: "linux", Architecture: "amd64",
		ArtifactSHA256: testDigest, ArtifactSize: 1234, AuditBasename: "artifact", CurrentReceipt: &receipt,
	}
	packet, err := MarshalRequest(request)
	if err != nil {
		t.Fatalf("MarshalRequest() error = %v", err)
	}
	parsed, err := ParseRequest(packet)
	if err != nil || parsed.ExecutionSequence != request.ExecutionSequence ||
		parsed.ReleaseSequence != request.ReleaseSequence || parsed.Action != ActionRollback {
		t.Fatalf("v3 round trip = (%#v, %v)", parsed, err)
	}
	for _, response := range []Response{
		Prepared(JournalV3Version, ack),
		SuccessForVersion(JournalV3Version, receipt),
		Inspected(JournalV3Version, TransactionStatus{TransactionID: ack.TransactionID,
			Phase: TransactionRolledBack, PreparedAck: &ack, Receipt: &rolledBackReceipt}),
	} {
		encoded, err := MarshalResponse(response)
		if err != nil {
			t.Fatalf("MarshalResponse() error = %v", err)
		}
		if _, err := ParseResponse(encoded); err != nil {
			t.Fatalf("ParseResponse() error = %v", err)
		}
	}
}

func TestProtocolV2RejectsV3FieldsAndV3RequiresV3Responses(t *testing.T) {
	receipt := testReceipt()
	request := Request{ProtocolVersion: JournalVersion, Operation: OperationPrepareInstall,
		TransactionID: "txn-123", ExecutionSequence: 4, ReleaseSequence: 3, Action: ActionUpgrade,
		CurrentVersion: "1.0.0", TargetVersion: "2.0.0", Platform: "linux", Architecture: "amd64",
		ArtifactSHA256: testDigest, ArtifactSize: 1234, AuditBasename: "artifact", CurrentReceipt: &receipt}
	if _, err := MarshalRequest(request); err == nil {
		t.Fatal("protocol v2 accepted v3 fields")
	}
	v3 := request
	v3.ProtocolVersion = JournalV3Version
	if _, err := MarshalRequest(v3); err != nil {
		t.Fatalf("protocol v3 rejected evidence-migratable legacy current receipt: %v", err)
	}
	legacyAck := testPreparedAck()
	if _, err := MarshalResponse(Prepared(JournalV3Version, legacyAck)); err == nil {
		t.Fatal("protocol v3 accepted legacy prepared acknowledgement")
	}
}

func TestCurrentProtocolAcceptsV3ReceiptWithoutWeakeningJournalVersions(t *testing.T) {
	receipt := testReceipt()
	receipt.SchemaVersion = 2
	receipt.ExecutionSequence = 4
	packet, err := MarshalResponse(Success(receipt))
	if err != nil {
		t.Fatalf("current protocol rejected v3 receipt: %v", err)
	}
	if _, err := ParseResponse(packet); err != nil {
		t.Fatalf("current protocol v3 receipt round trip: %v", err)
	}
	if _, err := MarshalResponse(SuccessForVersion(JournalVersion, receipt)); err == nil {
		t.Fatal("journal v2 accepted v3 receipt")
	}

	legacy := testReceipt()
	if _, err := MarshalResponse(SuccessForVersion(JournalV3Version, legacy)); err == nil {
		t.Fatal("journal v3 accepted legacy receipt")
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	packet, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return packet
}
