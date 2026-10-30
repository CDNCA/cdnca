package firewalldispatch

import (
	"context"
	"errors"
	"fmt"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/securitycoordmetrics"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
)

type Dispatcher struct {
	db       dispatchDB
	messages messageTransport
	config   Config
	now      func() time.Time
	metrics  *securitycoordmetrics.Registry
}

func New(pool *pgxpool.Pool, connection *nats.Conn, config Config) (*Dispatcher, error) {
	if pool == nil {
		return nil, fmt.Errorf("%w: PostgreSQL pool is required", ErrInvalidConfig)
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	messages, err := newNATSTransport(connection, config)
	if err != nil {
		return nil, err
	}
	return newDispatcher(&postgresDB{pool: pool}, messages, config)
}

func newDispatcher(db dispatchDB, messages messageTransport, config Config) (*Dispatcher, error) {
	if db == nil || messages == nil {
		return nil, fmt.Errorf("%w: store and message transport are required", ErrInvalidConfig)
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	return &Dispatcher{db: db, messages: messages, config: config, now: func() time.Time { return time.Now().UTC() },
		metrics: securitycoordmetrics.NewRegistry()}, nil
}

func (d *Dispatcher) DispatchBatch(ctx context.Context) (result BatchResult, resultErr error) {
	defer func() {
		reason := securitycoordmetrics.ReasonNone
		if resultErr != nil {
			reason = securitycoordmetrics.ReasonDependencyUnavailable
		}
		d.metrics.RecordFirewallDispatch(securitycoordmetrics.FirewallDispatch{
			Claimed: result.Claimed, Published: result.Published, Duplicates: result.Duplicates,
			Retryable: result.Retryable, Exhausted: result.Exhausted, Reason: reason,
		})
	}()
	if ctx == nil {
		return BatchResult{}, fmt.Errorf("dispatch context is required")
	}
	leaseContext, cancelLease := context.WithTimeout(ctx, d.config.LeaseTimeout)
	defer cancelLease()
	tx, err := d.db.begin(leaseContext)
	if err != nil {
		return BatchResult{}, err
	}
	defer func() { _ = tx.rollback(context.Background()) }()
	if err := leaseContext.Err(); err != nil {
		return BatchResult{}, err
	}
	now := d.now()
	claims, err := tx.claim(leaseContext, d.config.BatchSize, now)
	if err != nil {
		return BatchResult{}, err
	}
	result = BatchResult{Claimed: len(claims)}
	for _, claim := range claims {
		if err := leaseContext.Err(); err != nil {
			return result, err
		}
		_, subject, messageID, invalid := validateClaim(claim, now, d.config.MaxCommandBytes, d.config.CommandSubjectPrefix, true)
		if invalid.code != "" {
			d.metrics.RecordFirewallFailure(dispatchMetricReason(invalid.code))
			if err := d.settleFailure(leaseContext, tx, claim, invalid.code, true, now); err != nil {
				return result, err
			}
			result.Exhausted++
			continue
		}
		operationContext, cancel := context.WithTimeout(leaseContext, d.config.OperationTimeout)
		ack, publishErr := d.messages.publish(operationContext, subject, claim.commandBytes, messageID, d.config.CommandStream)
		cancel()
		if ctx.Err() != nil || leaseContext.Err() != nil {
			if ctx.Err() != nil {
				return result, ctx.Err()
			}
			return result, leaseContext.Err()
		}
		failureCode := classifyPublishResult(ack, publishErr, d.config.CommandStream)
		if failureCode != "" {
			d.metrics.RecordFirewallFailure(dispatchMetricReason(failureCode))
			terminal := claim.attempts+1 >= d.config.MaxAttempts
			if err := d.settleFailure(leaseContext, tx, claim, failureCode, terminal, now); err != nil {
				return result, err
			}
			if terminal {
				result.Exhausted++
			} else {
				result.Retryable++
			}
			continue
		}
		if claim.state == StateRetryable {
			if err := tx.promoteRetryable(leaseContext, claim.id); err != nil {
				return result, err
			}
		}
		if err := tx.markPublished(leaseContext, claim.id, claim.attempts+1, now); err != nil {
			return result, err
		}
		result.Published++
		if ack.duplicate {
			result.Duplicates++
		}
	}
	if err := tx.commit(leaseContext); err != nil {
		return result, err
	}
	return result, nil
}

func (d *Dispatcher) MetricsSnapshot() securitycoordmetrics.Snapshot {
	if d == nil || d.metrics == nil {
		return securitycoordmetrics.Snapshot{}
	}
	return d.metrics.Snapshot()
}

func (d *Dispatcher) settleFailure(ctx context.Context, tx dispatchTx, claim claimedCommand, code string, terminal bool, now time.Time) error {
	if claim.state == StateRetryable {
		if err := tx.promoteRetryable(ctx, claim.id); err != nil {
			return err
		}
	}
	attempts := claim.attempts + 1
	if attempts > d.config.MaxAttempts {
		attempts = d.config.MaxAttempts
	}
	available := now.Add(retryDelay(d.config.BaseBackoff, d.config.MaxBackoff, attempts))
	return tx.markFailure(ctx, claim.id, attempts, available, code, terminal, now)
}

func (d *Dispatcher) HandleStatus(ctx context.Context, payload []byte) (disposition AckDisposition, resultErr error) {
	observation := securitycoordmetrics.FirewallACK{Disposition: securitycoordmetrics.ACKRejected}
	defer func() { d.metrics.RecordFirewallACK(observation) }()
	if ctx == nil {
		return AckRejected, fmt.Errorf("status context is required")
	}
	if len(payload) == 0 || len(payload) > d.config.MaxStatusBytes {
		return AckRejected, ErrStatusConflict
	}
	status := new(agentv1.FirewallStatus)
	if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(payload, status); err != nil {
		return AckRejected, ErrStatusConflict
	}
	operationContext, cancel := context.WithTimeout(ctx, d.config.LeaseTimeout)
	defer cancel()
	tx, err := d.db.begin(operationContext)
	if err != nil {
		return AckRejected, err
	}
	defer func() { _ = tx.rollback(context.Background()) }()
	claim, err := tx.loadForStatus(operationContext, status)
	if err != nil {
		return AckRejected, err
	}
	fingerprint, err := validateStatus(payload, claim, d.config.MaxStatusBytes)
	if err != nil {
		return AckRejected, err
	}
	disposition, err = tx.markAcked(operationContext, claim.id, claim.state, status, fingerprint, d.now())
	if err != nil {
		return AckRejected, err
	}
	if err := tx.commit(operationContext); err != nil {
		return AckRejected, err
	}
	observation.Disposition = ackMetricDisposition(disposition)
	observation.Terminal = terminalMetricOutcome(status.State)
	observation.Recovery = status.Operation == agentv1.FirewallOperation_FIREWALL_OPERATION_RECOVER
	if source, ok := tx.(interface {
		securityCoordinationOutcome() securitycoordmetrics.GlobalOutcome
	}); ok {
		observation.GlobalOutcome = source.securityCoordinationOutcome()
	}
	return disposition, nil
}

func (d *Dispatcher) Run(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("dispatcher context is required")
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		result, err := d.DispatchBatch(ctx)
		if err != nil {
			return err
		}
		statuses, ok := d.messages.(statusTransport)
		if !ok {
			return fmt.Errorf("%w: status transport is required", ErrInvalidConfig)
		}
		statusContext, cancel := context.WithTimeout(ctx, d.config.PollInterval)
		delivery, statusErr := statuses.nextStatus(statusContext)
		cancel()
		if statusErr == nil {
			if _, err := d.HandleStatus(ctx, delivery.payload()); err != nil {
				if errors.Is(err, ErrStatusConflict) {
					_ = delivery.term(context.Background())
				} else {
					_ = delivery.nak(context.Background())
				}
				return err
			}
			if err := delivery.ack(ctx); err != nil {
				return err
			}
			continue
		}
		if !errors.Is(statusErr, context.DeadlineExceeded) && !errors.Is(statusErr, nats.ErrTimeout) {
			return statusErr
		}
		if result.Claimed > 0 {
			continue
		}
	}
}

func classifyPublishResult(ack *publishAck, err error, expectedStream string) string {
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, nats.ErrTimeout) {
			return "publish_timeout"
		}
		return "publish_unknown"
	}
	if ack == nil {
		return "puback_missing"
	}
	if ack.stream != expectedStream {
		return "puback_stream_mismatch"
	}
	if ack.sequence == 0 {
		return "puback_invalid"
	}
	return ""
}

func dispatchMetricReason(code string) securitycoordmetrics.Reason {
	switch code {
	case "publish_timeout":
		return securitycoordmetrics.ReasonPublishTimeout
	case "publish_unknown":
		return securitycoordmetrics.ReasonPublishUnknown
	case "puback_missing":
		return securitycoordmetrics.ReasonPubACKMissing
	case "puback_stream_mismatch", "puback_invalid":
		return securitycoordmetrics.ReasonPubACKRejected
	default:
		return securitycoordmetrics.ReasonIntegrityRejected
	}
}

func ackMetricDisposition(value AckDisposition) securitycoordmetrics.ACKDisposition {
	switch value {
	case AckSettled:
		return securitycoordmetrics.ACKSettled
	case AckReplayed:
		return securitycoordmetrics.ACKReplayed
	case AckRescued:
		return securitycoordmetrics.ACKRescued
	default:
		return securitycoordmetrics.ACKRejected
	}
}

func terminalMetricOutcome(value agentv1.FirewallStatusState) securitycoordmetrics.TerminalOutcome {
	switch value {
	case agentv1.FirewallStatusState_FIREWALL_STATUS_STATE_APPLIED:
		return securitycoordmetrics.TerminalApplied
	case agentv1.FirewallStatusState_FIREWALL_STATUS_STATE_FAILED:
		return securitycoordmetrics.TerminalFailed
	case agentv1.FirewallStatusState_FIREWALL_STATUS_STATE_ROLLED_BACK:
		return securitycoordmetrics.TerminalRolledBack
	default:
		return securitycoordmetrics.TerminalNone
	}
}
