package notification

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type Worker struct {
	store               *Store
	sender              Sender
	anonymousDispatcher AnonymousDispatcher
	config              WorkerConfig
	retry               *RetryPolicy
}

func NewWorker(store *Store, sender Sender, config WorkerConfig) (*Worker, error) {
	return newWorker(store, sender, nil, config)
}

func NewWorkerWithAnonymousDispatcher(
	store *Store,
	sender Sender,
	dispatcher AnonymousDispatcher,
	config WorkerConfig,
) (*Worker, error) {
	if dispatcher == nil {
		return nil, ErrInvalidWorker
	}
	return newWorker(store, sender, dispatcher, config)
}

func newWorker(
	store *Store,
	sender Sender,
	dispatcher AnonymousDispatcher,
	config WorkerConfig,
) (*Worker, error) {
	if store == nil || store.pool == nil || sender == nil || !validWorkerConfig(config) {
		return nil, ErrInvalidWorker
	}
	retry, err := NewRetryPolicy(config.MaxAttempts, config.BaseDelay, config.MaxDelay, store.now)
	if err != nil {
		return nil, ErrInvalidWorker
	}
	return &Worker{
		store: store, sender: sender, anonymousDispatcher: dispatcher,
		config: config, retry: retry,
	}, nil
}

type deliveryProcessResult struct {
	action      RetryAction
	disposition SendDisposition
	noopACK     bool
	stopErr     error
}

func (w *Worker) ProcessBatch(ctx context.Context) (WorkerBatchResult, error) {
	if w == nil || ctx == nil {
		return WorkerBatchResult{}, ErrInvalidWorker
	}
	var result WorkerBatchResult
	for processed := 0; processed < w.config.BatchSize; processed++ {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		claimed, err := w.store.claim(ctx, w.config)
		if err != nil {
			return result, err
		}
		if claimed.exhausted > 0 {
			result.Exhausted += claimed.exhausted
			continue
		}
		if claimed.unknown > 0 {
			result.Unknown += claimed.unknown
			continue
		}
		if claimed.withdrawn > 0 {
			result.Withdrawn += claimed.withdrawn
			continue
		}
		if len(claimed.deliveries) == 0 {
			break
		}
		result.Claimed++
		processed, err := w.processDelivery(ctx, claimed.deliveries[0])
		if err != nil {
			return result, err
		}
		switch {
		case processed.disposition == SendAccepted:
			result.Accepted++
		case processed.disposition == SendUnknown:
			result.Unknown++
		case processed.action == "":
			result.Succeeded++
			if processed.noopACK {
				result.NoopAcknowledged++
			}
		case processed.action == RetryScheduled:
			result.RetryScheduled++
		case processed.action == RetryStopped:
			result.PermanentFailed++
		case processed.action == RetryExhausted:
			result.Exhausted++
		}
		if processed.stopErr != nil {
			return result, processed.stopErr
		}
	}
	return result, nil
}

func (w *Worker) processDelivery(ctx context.Context, delivery claimedDelivery) (deliveryProcessResult, error) {
	deadlineBase := time.Now()
	remaining, err := w.store.confirmLeaseFresh(ctx, delivery, w.config.LeaseSafetyMargin)
	if err != nil {
		return deliveryProcessResult{}, err
	}
	sendDeadline := deadlineBase.Add(remaining - w.config.LeaseSafetyMargin)
	if !time.Now().Before(sendDeadline) {
		return deliveryProcessResult{}, ErrLeaseUnsafe
	}
	sendContext, cancel := context.WithDeadline(ctx, sendDeadline)
	defer cancel()
	if err := sendContext.Err(); err != nil {
		return deliveryProcessResult{}, err
	}
	if err := w.store.beginDispatch(ctx, delivery); err != nil {
		return deliveryProcessResult{}, err
	}
	sendResult, noopACK := w.dispatchResult(sendContext, delivery)
	var stopErr error
	if sendContext.Err() != nil || ctx.Err() != nil {
		stopErr = sendContext.Err()
		if ctx.Err() != nil {
			stopErr = ctx.Err()
		}
		sendResult = SendResult{Disposition: SendUnknown, Provider: sendResult.Provider, Observation: sendResult.Observation}
	}
	// Once the provider has been called its outcome must be settled: a shutdown that
	// arrives after the check above must not abort the settlement and leave the delivery
	// dispatching until its lease expires. The settlement is bounded by the lease instead.
	settleBudget := remaining - w.config.LeaseSafetyMargin
	if settleBudget > 5*time.Second {
		settleBudget = 5 * time.Second
	}
	if settleBudget <= 0 {
		return deliveryProcessResult{}, ErrLeaseUnsafe
	}
	settleContext, settleCancel := context.WithTimeout(context.WithoutCancel(ctx), settleBudget)
	defer settleCancel()
	if sendResult.Failure == nil {
		if !validSendSuccess(sendResult) {
			sendResult = SendResult{Failure: &Failure{Class: FailurePermanent, Code: "sender_contract_invalid"}, Observation: sendResult.Observation}
		} else {
			if err := w.store.settleSendResult(settleContext, delivery, sendResult, "", "", 0); err != nil {
				return deliveryProcessResult{}, err
			}
			return deliveryProcessResult{
				disposition: sendResult.Disposition, noopACK: noopACK, stopErr: stopErr,
			}, nil
		}
	}
	classifiedFailure := *sendResult.Failure
	if sendResult.Disposition != "" || sendResult.Provider != "" || sendResult.ProviderDeliveryID != "" ||
		!validFailure(classifiedFailure) {
		classifiedFailure = Failure{Class: FailurePermanent, Code: "sender_contract_invalid"}
	}
	decision, err := w.retry.Decide(delivery.AttemptNumber, classifiedFailure)
	if err != nil {
		return deliveryProcessResult{}, fmt.Errorf("decide notification retry: %w", err)
	}
	if err := w.store.settleSendResult(
		settleContext, delivery, SendResult{Failure: &classifiedFailure, Observation: sendResult.Observation},
		decision.Action, classifiedFailure.Code, decision.Delay,
	); err != nil {
		return deliveryProcessResult{}, err
	}
	return deliveryProcessResult{action: decision.Action}, nil
}

func (w *Worker) dispatch(ctx context.Context, delivery claimedDelivery) (*Failure, bool) {
	result, noopACK := w.dispatchResult(ctx, delivery)
	return result.Failure, noopACK
}

func (w *Worker) dispatchResult(ctx context.Context, delivery claimedDelivery) (SendResult, bool) {
	switch recipient := delivery.Recipient.(type) {
	case memberRecipient:
		result := w.sender.Send(ctx, memberAttempt(delivery, recipient.userID))
		return result, false
	case anonymousRecipient:
		if w.anonymousDispatcher == nil {
			return SendResult{Failure: &Failure{Class: FailureTemporary, Code: "dispatch_unavailable"}}, false
		}
		result := w.anonymousDispatcher.Dispatch(ctx, anonymousAttempt(delivery, recipient.reference))
		if result.Failure != nil {
			if result.Disposition != "" || !validFailure(*result.Failure) {
				return SendResult{Failure: &Failure{Class: FailurePermanent, Code: "dispatch_contract_invalid"}}, false
			}
			return SendResult{Failure: result.Failure, Observation: result.Observation}, false
		}
		switch result.Disposition {
		case AnonymousDispatchDelivered:
			return SendResult{Disposition: SendDelivered, Observation: result.Observation}, false
		case AnonymousDispatchAccepted:
			return SendResult{Disposition: SendAccepted, Provider: result.Provider, ProviderDeliveryID: result.ProviderDeliveryID, Observation: result.Observation}, false
		case AnonymousDispatchUnknown:
			return SendResult{Disposition: SendUnknown, Provider: result.Provider, Observation: result.Observation}, false
		case AnonymousDispatchNoopACK:
			return SendResult{Disposition: SendDelivered}, true
		default:
			return SendResult{Failure: &Failure{Class: FailurePermanent, Code: "dispatch_contract_invalid"}}, false
		}
	default:
		return SendResult{Failure: &Failure{Class: FailurePermanent, Code: "sender_contract_invalid"}}, false
	}
}

func validSendSuccess(result SendResult) bool {
	if result.Failure != nil || (result.Disposition != SendDelivered && result.Disposition != SendAccepted && result.Disposition != SendUnknown) {
		return false
	}
	switch result.Disposition {
	case SendDelivered:
		return (result.Provider == "" || validProviderIdentity(result.Provider)) &&
			(result.ProviderDeliveryID == "" || validProviderIdentity(result.ProviderDeliveryID))
	case SendAccepted:
		return result.Provider != "" && validProviderIdentity(result.Provider) &&
			validProviderIdentity(result.ProviderDeliveryID)
	case SendUnknown:
		return result.Provider != "" && validProviderIdentity(result.Provider) && result.ProviderDeliveryID == ""
	default:
		return false
	}
}

func memberAttempt(delivery claimedDelivery, recipientID uuid.UUID) DeliveryAttempt {
	return DeliveryAttempt{
		OutboxID: delivery.OutboxID, ScopeID: delivery.ScopeID, EventID: delivery.EventID,
		RecipientID: recipientID, EventType: delivery.EventType, SourceEventID: delivery.SourceEventID,
		Channel: delivery.Channel, Template: delivery.Template, Subject: delivery.Subject,
		Body: delivery.Body, DedupKey: delivery.DedupKey, AttemptNumber: delivery.AttemptNumber,
		LeaseToken: delivery.LeaseToken, LeaseExpiresAt: delivery.LeaseExpiresAt, Params: delivery.Params,
	}
}

func anonymousAttempt(delivery claimedDelivery, reference uuid.UUID) AnonymousDeliveryAttempt {
	return AnonymousDeliveryAttempt{
		OutboxID: delivery.OutboxID, ScopeID: delivery.ScopeID, EventID: delivery.EventID,
		AnonymousDispatchReference: reference, EventType: delivery.EventType,
		SourceEventID: delivery.SourceEventID, Channel: delivery.Channel,
		Template: delivery.Template, Subject: delivery.Subject, Body: delivery.Body,
		DedupKey: delivery.DedupKey, AttemptNumber: delivery.AttemptNumber,
		LeaseToken: delivery.LeaseToken, LeaseExpiresAt: delivery.LeaseExpiresAt,
	}
}

func validWorkerConfig(config WorkerConfig) bool {
	return config.BatchSize > 0 && config.BatchSize <= 256 &&
		config.LeaseDuration > 0 && config.LeaseDuration <= 15*time.Minute &&
		config.LeaseSafetyMargin > 0 && config.LeaseSafetyMargin < config.LeaseDuration &&
		config.MaxAttempts > 0 && config.MaxAttempts <= 100 &&
		config.BaseDelay > 0 && config.MaxDelay >= config.BaseDelay && config.MaxDelay <= 24*time.Hour
}
