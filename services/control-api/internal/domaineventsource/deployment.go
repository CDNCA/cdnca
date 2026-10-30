package domaineventsource

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// DeploymentStatus is one accepted node deployment transition. Command bytes,
// credentials and agent metadata are intentionally not accepted.
type DeploymentStatus struct {
	EventID            uuid.UUID // the agent status event id; becomes the source fact id
	TenantScopeID      uuid.UUID
	DeploymentID       uuid.UUID
	NodeID             uuid.UUID
	RolloutID          uuid.UUID
	Attempt            uint32
	TransitionSequence uint64
	State              string
	OccurredAt         time.Time
}

func NewDeploymentStatusFact(input DeploymentStatus) (Fact, error) {
	if input.EventID == uuid.Nil || input.DeploymentID == uuid.Nil || input.NodeID == uuid.Nil ||
		input.RolloutID == uuid.Nil || input.Attempt == 0 || input.Attempt > 1<<31-1 ||
		input.TransitionSequence == 0 || input.TransitionSequence > 1<<62 {
		return Fact{}, fmt.Errorf("%w: deployment identity or bounds", ErrInvalidEvent)
	}
	return Fact{
		ID: input.EventID, EventType: DeploymentStatusChangedType, TenantScopeID: input.TenantScopeID,
		Subject: "deployment/" + input.DeploymentID.String(),
		DedupKey: fmt.Sprintf("%s/%s/%d/%d", DeploymentStatusChangedType, input.DeploymentID,
			input.Attempt, input.TransitionSequence),
		OccurredAt: input.OccurredAt,
		Data: map[string]any{
			"deployment_id": input.DeploymentID.String(), "rollout_id": input.RolloutID.String(),
			"node_id": input.NodeID.String(), "attempt": input.Attempt,
			"transition_sequence": input.TransitionSequence, "state": input.State,
		},
	}, nil
}

// Timestamp renders t the way the event contracts store timestamps.
func Timestamp(t time.Time) string {
	return t.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano)
}
