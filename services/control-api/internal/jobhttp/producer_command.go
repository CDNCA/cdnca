package jobhttp

import (
	"context"
	"errors"
)

// ProducerCommandRouter executes cancel/retry of a job whose producer keeps
// its own projection (fix-cacheflow2 §2, CACHE-ADD-05: a cache operation's
// cache_operations/node rows, cancel outbox and retry scheduling). The
// producer moves its projection and the unified job in one transaction with
// its own audit and receipt; the task center then reads the job back.
type ProducerCommandRouter interface {
	ExecuteProducerCommand(context.Context, ProducerCommandInput) (ProducerCommandResult, error)
}

type ProducerCommandInput struct {
	Principal      Principal
	Audience       Audience
	Job            Job
	Operation      CommandOperation
	IdempotencyKey string
	RequestID      string
	// ReplayOnly asks whether this key was already accepted, without running
	// the command: the caller's If-Match is stale (merge-p22, the generic path
	// also answers a recorded key as a replay before comparing revisions).
	ReplayOnly bool
}

type ProducerCommandResult struct {
	Replayed bool
}

// producerCommand runs input on the job's producer when one is registered for
// its kind; handled is false for every other job (replay included: it is a
// dead-letter command of the unified job only).
func (service *Service) producerCommand(
	ctx context.Context,
	principal Principal,
	input CommandRequest,
	requestID string,
) (CommandResult, bool, error) {
	if len(service.producers) == 0 || input.Operation == CommandReplay {
		return CommandResult{}, false, nil
	}
	scope := ReadScope{Kind: principal.ScopeKind, ID: principal.ScopeID}
	job, err := service.reader.Get(ctx, scope, input.TaskID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			// The generic path records the denied lookup.
			return CommandResult{}, false, nil
		}
		return CommandResult{}, true, normalizeReaderError(ctx, err)
	}
	router, ok := service.producers[job.Kind]
	if !ok {
		return CommandResult{}, false, nil
	}
	if validateJob(job) != nil || job.TaskID != input.TaskID {
		return CommandResult{}, true, ErrInvalidStoreResponse
	}
	stale := input.ExpectedRevision != "" && job.Revision != input.ExpectedRevision
	routed, err := router.ExecuteProducerCommand(ctx, ProducerCommandInput{
		Principal: principal, Audience: input.Audience, Job: job, Operation: input.Operation,
		IdempotencyKey: input.IdempotencyKey, RequestID: requestID, ReplayOnly: stale,
	})
	if stale && (err != nil && errors.Is(err, ErrNotFound) || err == nil && !routed.Replayed) {
		return CommandResult{}, true, ErrRevisionConflict
	}
	if err != nil {
		return CommandResult{}, true, normalizeCommandError(ctx, err)
	}
	current, err := service.reader.Get(ctx, scope, input.TaskID)
	if err != nil {
		return CommandResult{}, true, normalizeReaderError(ctx, err)
	}
	if validateJob(current) != nil || current.TaskID != input.TaskID {
		return CommandResult{}, true, ErrInvalidStoreResponse
	}
	return CommandResult{Data: current, Replayed: routed.Replayed}, true, nil
}
