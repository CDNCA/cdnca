package protocol

import "testing"

// A prepared ack whose previous and target versions are equal is a
// same-version re-release, valid only on the v3 journal protocol.
func TestPreparedAckSameVersionOnlyV3(t *testing.T) {
	ack := testPreparedAck()
	ack.SchemaVersion, ack.ExecutionSequence = 2, 9
	ack.TargetVersion = ack.PreviousVersion
	if err := validatePreparedAck(ack, JournalV3Version); err != nil {
		t.Fatalf("v3 same-version ack rejected: %v", err)
	}
	legacy := testPreparedAck()
	legacy.TargetVersion = legacy.PreviousVersion
	if validatePreparedAck(legacy, JournalVersion) == nil {
		t.Fatal("v2 same-version ack accepted")
	}
}
