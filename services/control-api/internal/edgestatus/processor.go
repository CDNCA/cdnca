package edgestatus

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

type Processor struct {
	validator        *Validator
	projector        Projector
	nakDelay         time.Duration
	operationTimeout time.Duration
	logger           *slog.Logger
}

// deliveryAttempts is implemented by deliveries that know how many times the
// broker has handed the message out (JetStream metadata).
type deliveryAttempts interface {
	NumDelivered() uint64
}

func NewProcessor(validator *Validator, projector Projector, nakDelay, operationTimeout time.Duration) (*Processor, error) {
	if validator == nil || projector == nil || nakDelay <= 0 || operationTimeout <= 0 {
		return nil, fmt.Errorf("invalid deployment status processor configuration")
	}
	return &Processor{
		validator: validator, projector: projector, nakDelay: nakDelay, operationTimeout: operationTimeout,
		logger: slog.Default(),
	}, nil
}

// SetLogger replaces the logger refusals and retries are written to.
func (p *Processor) SetLogger(logger *slog.Logger) {
	if logger != nil {
		p.logger = logger
	}
}

func (p *Processor) Process(ctx context.Context, delivery Delivery) (string, error) {
	if ctx == nil || delivery == nil {
		return "", fmt.Errorf("deployment status context and delivery are required")
	}
	envelope, err := p.validator.Decode(delivery.Subject(), delivery.Data())
	if err != nil {
		// A dropped status must leave a trace; the gateway has
		// already told the node it was persisted.
		p.logger.Error("deployment status rejected: undecodable, terminated",
			"subject", delivery.Subject(), "deliveries", numDelivered(delivery), "error", err)
		return p.term(ctx, delivery)
	}
	operationCtx, cancel := context.WithTimeout(ctx, p.operationTimeout)
	_, err = p.projector.Project(operationCtx, envelope)
	cancel()
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		attempts := numDelivered(delivery)
		attrs := []any{
			"deployment_id", envelope.DeploymentID.String(), "attempt", envelope.Status.GetAttempt(),
			"transition_sequence", envelope.Status.GetTransitionSequence(),
			"state", envelope.Status.GetState().String(), "node_id", envelope.NodeID.String(),
			"event_id", envelope.EventID.String(), "deliveries", attempts, "error", err,
		}
		if permanentProjectionError(err) {
			p.logger.Error("deployment status rejected: projection refused, terminated", attrs...)
			// The node has dropped this status, so the deployment
			// would stay running and hold its node's scope queue. End it.
			if finalizer, ok := p.projector.(RefusalFinalizer); ok {
				operationCtx, cancel := context.WithTimeout(ctx, p.operationTimeout)
				ended, finalizeErr := finalizer.FinalizeRefused(operationCtx, envelope, err)
				cancel()
				if finalizeErr != nil {
					if ctx.Err() != nil {
						return "", ctx.Err()
					}
					p.logger.Error("refused deployment status not finalized", append(attrs, "finalize_error", finalizeErr)...)
					if attempts > 0 && attempts < refusalFinalizeDeliveries {
						return p.nak(ctx, delivery)
					}
				} else if ended {
					p.logger.Error("deployment failed: its status was refused", attrs...)
				}
			}
			return p.term(ctx, delivery)
		}
		// An endless silent retry looked exactly like a lost
		// receipt. Log the first few and then once a minute (1s redelivery).
		if attempts <= 3 || attempts%60 == 0 {
			p.logger.Warn("deployment status not stored, will be redelivered", attrs...)
		}
		return p.nak(ctx, delivery)
	}
	operationCtx, cancel = context.WithTimeout(ctx, p.operationTimeout)
	err = delivery.Ack(operationCtx)
	cancel()
	if err != nil {
		return DispositionAck, err
	}
	return DispositionAck, nil
}

// refusalFinalizeDeliveries bounds the redeliveries spent retrying a failed
// FinalizeRefused; the deadline timeout (348) still ends the deployment.
const refusalFinalizeDeliveries = 10

func numDelivered(delivery Delivery) uint64 {
	if counted, ok := delivery.(deliveryAttempts); ok {
		return counted.NumDelivered()
	}
	return 0
}

func permanentProjectionError(err error) bool {
	return errors.Is(err, ErrInvalidStatus) || errors.Is(err, ErrDeploymentMissing) ||
		errors.Is(err, ErrBindingConflict) || errors.Is(err, ErrPayloadConflict) ||
		errors.Is(err, ErrInvalidTransition) || errors.Is(err, ErrProjectionConflict)
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
