package nodepresence

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

const (
	DispositionAck  = "ack"
	DispositionNak  = "nak"
	DispositionTerm = "term"
)

type HeartbeatProjector interface {
	Project(context.Context, Envelope) (ProjectionResult, error)
	ConfirmOnline(context.Context, ProjectionResult) (bool, error)
}

type LeaseWriter interface {
	Put(context.Context, LeaseRecord) error
}

type Processor struct {
	validator        *Validator
	projector        HeartbeatProjector
	leases           LeaseWriter
	nakDelay         time.Duration
	operationTimeout time.Duration
}

func NewProcessor(validator *Validator, projector HeartbeatProjector, leases LeaseWriter,
	nakDelay, operationTimeout time.Duration,
) (*Processor, error) {
	if validator == nil || projector == nil || leases == nil || nakDelay <= 0 || operationTimeout <= 0 {
		return nil, fmt.Errorf("invalid heartbeat processor configuration")
	}
	return &Processor{
		validator: validator, projector: projector, leases: leases,
		nakDelay: nakDelay, operationTimeout: operationTimeout,
	}, nil
}

func (p *Processor) Process(ctx context.Context, delivery Delivery) (string, error) {
	if delivery == nil {
		return "", fmt.Errorf("heartbeat delivery is required")
	}
	envelope, err := p.validator.Decode(delivery.Subject(), delivery.Data())
	if err != nil {
		slog.Warn("heartbeat dropped", "subject", delivery.Subject(), "error", err)
		return p.term(ctx, delivery)
	}
	operationCtx, cancel := context.WithTimeout(ctx, p.operationTimeout)
	projection, err := p.projector.Project(operationCtx, envelope)
	cancel()
	if err != nil {
		if errors.Is(err, ErrNodeNotFound) || errors.Is(err, ErrProjectionConflict) || errors.Is(err, ErrInvalidHeartbeat) {
			// A dropped heartbeat leaves presence stale; without this line the
			// node just turns offline with no trace of why.
			slog.Warn("heartbeat dropped", "node_id", envelope.NodeID, "session_epoch", envelope.Heartbeat.GetSessionEpoch(),
				"heartbeat_sequence", envelope.Heartbeat.GetHeartbeatSequence(), "error", err)
			return p.term(ctx, delivery)
		}
		return p.nak(ctx, delivery)
	}
	if projection.RefreshLease {
		operationCtx, cancel = context.WithTimeout(ctx, p.operationTimeout)
		err = p.leases.Put(operationCtx, LeaseRecord{
			NodeID: projection.NodeID, SessionEpoch: projection.SessionEpoch,
			HeartbeatSequence: projection.HeartbeatSequence, EventID: projection.EventID,
			LastSeenAt: projection.ProjectedAt, ExpiresAt: projection.LeaseExpiresAt,
		})
		cancel()
		if err != nil {
			return p.nak(ctx, delivery)
		}
		operationCtx, cancel = context.WithTimeout(ctx, p.operationTimeout)
		_, err = p.projector.ConfirmOnline(operationCtx, projection)
		cancel()
		if err != nil {
			return p.nak(ctx, delivery)
		}
	}
	operationCtx, cancel = context.WithTimeout(ctx, p.operationTimeout)
	err = delivery.Ack(operationCtx)
	cancel()
	if err != nil {
		return DispositionAck, err
	}
	return DispositionAck, nil
}

func (p *Processor) nak(ctx context.Context, delivery Delivery) (string, error) {
	operationCtx, cancel := context.WithTimeout(ctx, p.operationTimeout)
	err := delivery.Nak(operationCtx, p.nakDelay)
	cancel()
	if err != nil {
		return DispositionNak, err
	}
	return DispositionNak, nil
}

func (p *Processor) term(ctx context.Context, delivery Delivery) (string, error) {
	operationCtx, cancel := context.WithTimeout(ctx, p.operationTimeout)
	err := delivery.Term(operationCtx)
	cancel()
	if err != nil {
		return DispositionTerm, err
	}
	return DispositionTerm, nil
}
