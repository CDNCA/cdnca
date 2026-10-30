package telemetryclient

import (
	"context"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
)

type connectionsCursor struct{ spool *eventspool.Spool }

func NewConnectionsDurableCursor(spool *eventspool.Spool) DurableCursor {
	return connectionsCursor{spool}
}

func (c connectionsCursor) AcknowledgedSequence(ctx context.Context) (uint64, error) {
	return c.spool.ConnectionsAcknowledgedSequence(ctx)
}
