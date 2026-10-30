package edgeoutbox

import (
	"time"

	"github.com/google/uuid"
)

type BatchResult struct {
	Claimed           int
	Published         int
	Duplicates        int
	RetryableFailures int
	PermanentFailures int
	// Superseded: commands closed unsent because their deployment already
	// ended or a newer deployment of the same node and scope replaced it.
	Superseded int
}

type claimedCommand struct {
	outboxID          uuid.UUID
	deploymentID      uuid.UUID
	deploymentAttempt int
	nodeID            uuid.UUID
	subject           string
	payload           []byte
	payloadSHA256     []byte
	publishAttempts   int
	claimToken        time.Time
	commandEventID    uuid.UUID
	deploymentNodeID  uuid.UUID
	rolloutID         uuid.UUID
	configVersionID   uuid.UUID
	commandBytes      []byte
	commandSHA256     []byte
	// superseded: the deployment ended (timed out, refused, cancelled) or a
	// newer deployment of its node and scope exists; never sent (fix-cfgflow2 §3).
	superseded bool
}

type failure struct {
	class     string
	code      string
	retryable bool
}

func (f failure) safeText(limit int) string {
	value := f.class + ":" + f.code
	if len(value) > limit {
		return value[:limit]
	}
	return value
}

type publishAck struct {
	stream    string
	duplicate bool
}
