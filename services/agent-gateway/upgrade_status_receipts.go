package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/proto"
)

var (
	errUpgradeStatusAckConflict = errors.New("upgrade status acknowledgement conflicts with durable state")
	errUpgradeStatusAckLimit    = errors.New("upgrade status acknowledgements exceed their limit")
	errUpgradeStatusAckNotFound = errors.New("upgrade status acknowledgement was not found")
)

type upgradeStatusAckRecord struct {
	NodeID         string
	InstallationID string
	Ack            *agentv1.UpgradeStatusAck
}

type upgradeStatusAckStore interface {
	listUpgradeStatusAcks(context.Context, string, int) ([]upgradeStatusAckRecord, error)
	saveUpgradeStatusAck(context.Context, upgradeStatusAckRecord, int) (upgradeStatusAckRecord, error)
	saveUpgradeStatusAckHorizon(context.Context, upgradeStatusAckRecord, int) (upgradeStatusAckRecord, error)
	confirmUpgradeStatusAck(context.Context, string, *agentv1.UpgradeStatusAckReceipt, int) (*agentv1.UpgradeStatusAckReceipt, error)
	hasCompletedUpgradeCommand(context.Context, UpgradeCommandRecord, int) (bool, error)
}

func validateUpgradeStatusAckRecord(record upgradeStatusAckRecord) error {
	if !canonicalUpgradeUUID(record.NodeID) || !canonicalUpgradeUUID(record.InstallationID) || record.Ack == nil ||
		cacheControlMessageHasUnknown(record.Ack.ProtoReflect()) || !canonicalUpgradeUUID(record.Ack.GetStatusEventId()) ||
		!canonicalUpgradeUUID(record.Ack.GetCommandId()) || record.Ack.GetStatusRevision() == 0 ||
		len(record.Ack.GetStatusSha256()) != sha256.Size || record.Ack.GetPersistedTime() == nil ||
		record.Ack.GetPersistedTime().CheckValid() != nil || record.Ack.GetPublishedStream() != UpgradeStatusStream ||
		record.Ack.GetPublishedSequence() == 0 {
		return fmt.Errorf("upgrade status acknowledgement record is invalid")
	}
	return nil
}

func validateUpgradeStatusAckReceiptShape(receipt *agentv1.UpgradeStatusAckReceipt) error {
	if receipt == nil || cacheControlMessageHasUnknown(receipt.ProtoReflect()) ||
		!canonicalUpgradeUUID(receipt.GetStatusEventId()) || !canonicalUpgradeUUID(receipt.GetCommandId()) ||
		receipt.GetStatusRevision() == 0 || len(receipt.GetStatusSha256()) != sha256.Size ||
		receipt.GetPersistedTime() == nil || receipt.GetPersistedTime().CheckValid() != nil ||
		receipt.GetPublishedStream() != UpgradeStatusStream || receipt.GetPublishedSequence() == 0 ||
		len(receipt.GetAckSha256()) != sha256.Size {
		return fmt.Errorf("upgrade status acknowledgement receipt is invalid")
	}
	return nil
}

func validateUpgradeStatusAckReceipt(record upgradeStatusAckRecord, receipt *agentv1.UpgradeStatusAckReceipt) error {
	if validateUpgradeStatusAckRecord(record) != nil || validateUpgradeStatusAckReceiptShape(receipt) != nil {
		return fmt.Errorf("upgrade status acknowledgement receipt is invalid")
	}
	digest, err := upgradeStatusAckSHA256(record.Ack)
	if err != nil || receipt.GetStatusEventId() != record.Ack.GetStatusEventId() ||
		receipt.GetCommandId() != record.Ack.GetCommandId() || receipt.GetStatusRevision() != record.Ack.GetStatusRevision() ||
		!bytes.Equal(receipt.GetStatusSha256(), record.Ack.GetStatusSha256()) ||
		!proto.Equal(receipt.GetPersistedTime(), record.Ack.GetPersistedTime()) ||
		receipt.GetPublishedStream() != record.Ack.GetPublishedStream() ||
		receipt.GetPublishedSequence() != record.Ack.GetPublishedSequence() ||
		!bytes.Equal(receipt.GetAckSha256(), digest[:]) {
		return fmt.Errorf("upgrade status acknowledgement receipt does not match durable state")
	}
	return nil
}

func upgradeStatusAckSHA256(ack *agentv1.UpgradeStatusAck) ([sha256.Size]byte, error) {
	if ack == nil || cacheControlMessageHasUnknown(ack.ProtoReflect()) {
		return [sha256.Size]byte{}, fmt.Errorf("upgrade status acknowledgement is invalid")
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(ack)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("marshal upgrade status acknowledgement: %w", err)
	}
	return sha256.Sum256(encoded), nil
}

func cloneUpgradeStatusAckRecord(record upgradeStatusAckRecord) upgradeStatusAckRecord {
	result := record
	if record.Ack != nil {
		result.Ack = proto.Clone(record.Ack).(*agentv1.UpgradeStatusAck)
	}
	return result
}

func sameUpgradeStatusAckRecord(left, right upgradeStatusAckRecord) bool {
	return left.NodeID == right.NodeID && left.InstallationID == right.InstallationID && proto.Equal(left.Ack, right.Ack)
}

func sameUpgradeStatusAckBinding(left, right upgradeStatusAckRecord) bool {
	if validateUpgradeStatusAckRecord(left) != nil || validateUpgradeStatusAckRecord(right) != nil ||
		left.NodeID != right.NodeID || left.InstallationID != right.InstallationID {
		return false
	}
	return left.Ack.GetStatusEventId() == right.Ack.GetStatusEventId() &&
		left.Ack.GetCommandId() == right.Ack.GetCommandId() &&
		left.Ack.GetStatusRevision() == right.Ack.GetStatusRevision() &&
		bytes.Equal(left.Ack.GetStatusSha256(), right.Ack.GetStatusSha256()) &&
		left.Ack.GetPublishedStream() == right.Ack.GetPublishedStream() &&
		left.Ack.GetPublishedSequence() == right.Ack.GetPublishedSequence()
}

func findUpgradeStatusAck(records []upgradeStatusAckRecord, nodeID, installationID string,
	statusRecord UpgradeStatusRecord,
) (upgradeStatusAckRecord, bool, error) {
	for _, record := range records {
		if validateUpgradeStatusAckRecord(record) != nil || record.NodeID != nodeID {
			return upgradeStatusAckRecord{}, false, errUpgradeStatusAckConflict
		}
		if record.Ack.GetStatusEventId() != statusRecord.StatusID {
			continue
		}
		if record.InstallationID != installationID || record.Ack.GetCommandId() != statusRecord.CommandID ||
			record.Ack.GetStatusRevision() != statusRecord.StatusRevision ||
			!bytes.Equal(record.Ack.GetStatusSha256(), statusRecord.SHA256[:]) {
			return upgradeStatusAckRecord{}, false, errUpgradeStatusAckConflict
		}
		return cloneUpgradeStatusAckRecord(record), true, nil
	}
	return upgradeStatusAckRecord{}, false, nil
}

func sortUpgradeStatusAckRecords(records []upgradeStatusAckRecord) {
	sort.Slice(records, func(left, right int) bool {
		if records[left].Ack.GetPublishedSequence() == records[right].Ack.GetPublishedSequence() {
			return records[left].Ack.GetStatusEventId() < records[right].Ack.GetStatusEventId()
		}
		return records[left].Ack.GetPublishedSequence() < records[right].Ack.GetPublishedSequence()
	})
}
