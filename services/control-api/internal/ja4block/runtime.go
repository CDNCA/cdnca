package ja4block

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

var ErrRuntimeRunning = errors.New("JA4 block runtime already running")

type RuntimeService interface {
	RunOne(context.Context, string) (RunResult, error)
	RecordEdgeReceipt(context.Context, Actor, EdgeReceiptInput) (Workflow, error)
}

type EdgeReceiptClaim struct {
	Token   uuid.UUID
	Actor   Actor
	Receipt EdgeReceiptInput
}

type EdgeReceiptQueue interface {
	Claim(context.Context, string, time.Time, time.Duration) (EdgeReceiptClaim, bool, error)
	Complete(context.Context, EdgeReceiptClaim) error
	Retry(context.Context, EdgeReceiptClaim, string, time.Time) error
	Reject(context.Context, EdgeReceiptClaim, string) error
}

type RuntimeConfig struct {
	WorkerID         string
	PollInterval     time.Duration
	ErrorBackoff     time.Duration
	OperationTimeout time.Duration
	ReceiptLease     time.Duration
}

type RuntimeResult struct {
	PolicyClaimed   bool
	ReceiptClaimed  bool
	ReceiptReplayed bool
}

type Runtime struct {
	service  RuntimeService
	receipts EdgeReceiptQueue
	config   RuntimeConfig
	now      func() time.Time
	running  atomic.Bool
}

func NewRuntime(service RuntimeService, receipts EdgeReceiptQueue, config RuntimeConfig, now func() time.Time) (*Runtime, error) {
	if nilInterface(service) || nilInterface(receipts) || !keyPattern.MatchString(config.WorkerID) ||
		config.PollInterval <= 0 || config.ErrorBackoff <= 0 || config.OperationTimeout <= 0 ||
		config.ReceiptLease <= config.OperationTimeout || now == nil {
		return nil, ErrInvalidConfiguration
	}
	return &Runtime{service: service, receipts: receipts, config: config, now: now}, nil
}

func (runtime *Runtime) RunOnce(ctx context.Context) (RuntimeResult, error) {
	if runtime == nil || ctx == nil {
		return RuntimeResult{}, ErrInvalidInput
	}
	operationCtx, cancel := context.WithTimeout(ctx, runtime.config.OperationTimeout)
	policy, policyErr := runtime.service.RunOne(operationCtx, runtime.config.WorkerID)
	cancel()
	result := RuntimeResult{PolicyClaimed: policy.Claimed}
	if policyErr != nil {
		return result, policyErr
	}
	claimCtx, cancel := context.WithTimeout(ctx, runtime.config.OperationTimeout)
	claim, found, err := runtime.receipts.Claim(claimCtx, runtime.config.WorkerID, runtime.now().UTC(), runtime.config.ReceiptLease)
	cancel()
	if err != nil || !found {
		return result, err
	}
	result.ReceiptClaimed = true
	recordCtx, cancel := context.WithTimeout(ctx, runtime.config.OperationTimeout)
	workflow, recordErr := runtime.service.RecordEdgeReceipt(recordCtx, claim.Actor, claim.Receipt)
	cancel()
	if recordErr != nil {
		settleCtx, settleCancel := context.WithTimeout(ctx, runtime.config.OperationTimeout)
		if terminalReceiptError(recordErr) {
			err = runtime.receipts.Reject(settleCtx, claim, stableDependencyCode(recordErr))
		} else {
			err = runtime.receipts.Retry(settleCtx, claim, stableDependencyCode(recordErr), runtime.now().UTC().Add(runtime.config.ErrorBackoff))
		}
		settleCancel()
		if err != nil {
			return result, err
		}
		return result, recordErr
	}
	result.ReceiptReplayed = workflow.Replayed
	completeCtx, cancel := context.WithTimeout(ctx, runtime.config.OperationTimeout)
	err = runtime.receipts.Complete(completeCtx, claim)
	cancel()
	return result, err
}

func (runtime *Runtime) Ready() error {
	if runtime == nil || nilInterface(runtime.service) || nilInterface(runtime.receipts) {
		return ErrInvalidConfiguration
	}
	return nil
}

func (*Runtime) Close() error { return nil }

func (runtime *Runtime) Run(ctx context.Context) error {
	if runtime == nil || ctx == nil {
		return ErrInvalidInput
	}
	if !runtime.running.CompareAndSwap(false, true) {
		return ErrRuntimeRunning
	}
	defer runtime.running.Store(false)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		_, err := runtime.RunOnce(ctx)
		delay := runtime.config.PollInterval
		if err != nil {
			delay = runtime.config.ErrorBackoff
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func terminalReceiptError(err error) bool {
	return errors.Is(err, ErrInvalidInput) || errors.Is(err, ErrPermissionDenied) || errors.Is(err, ErrScopeConflict) ||
		errors.Is(err, ErrRevisionConflict) || errors.Is(err, ErrIdempotencyConflict) || errors.Is(err, ErrNotFound)
}
