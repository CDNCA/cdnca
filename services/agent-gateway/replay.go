package gateway

import (
	"crypto/sha256"
	"errors"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/proto"
)

var (
	ErrMessageIDConflict = errors.New("message ID was reused with different content")
	ErrStreamSequence    = errors.New("stream sequence is not strictly increasing")
)

type replayRecord struct {
	sequence uint64
	digest   [sha256.Size]byte
}

type messageReplayWindow struct {
	capacity int
	entries  map[string]replayRecord
	order    []string
}

func newMessageReplayWindow(capacity int) *messageReplayWindow {
	return &messageReplayWindow{capacity: capacity, entries: make(map[string]replayRecord, capacity)}
}

func (w *messageReplayWindow) accept(request *agentv1.ConnectRequest, lastSequence uint64) (bool, error) {
	wire, err := proto.MarshalOptions{Deterministic: true}.Marshal(request)
	if err != nil {
		return false, err
	}
	messageID := request.GetStream().GetMessageId()
	record := replayRecord{sequence: request.GetStream().GetSequence(), digest: sha256.Sum256(wire)}
	if previous, ok := w.entries[messageID]; ok {
		if previous != record {
			return false, ErrMessageIDConflict
		}
		return true, nil
	}
	if record.sequence <= lastSequence {
		return false, ErrStreamSequence
	}
	w.entries[messageID] = record
	w.order = append(w.order, messageID)
	if len(w.order) > w.capacity {
		delete(w.entries, w.order[0])
		w.order = w.order[1:]
	}
	return false, nil
}
