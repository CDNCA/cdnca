package acmeworker

import (
	"context"
	"sync"
	"time"
)

type ReconcilerConfig struct {
	Clock         Clock
	Interval      time.Duration
	ErrorBackoff  time.Duration
	BatchSize     int
	MaxConcurrent int
}

func DefaultReconcilerConfig() ReconcilerConfig {
	return ReconcilerConfig{
		Clock: time.Now, Interval: time.Minute, ErrorBackoff: time.Second,
		BatchSize: 100, MaxConcurrent: 4,
	}
}

type ReconcileResult struct {
	Request IssueRequest
	Issue   IssueResult
	Error   error
}

type Reconciler struct {
	config     ReconcilerConfig
	issuer     CertificateIssuer
	operations OperationStore
	wait       func(context.Context, time.Duration) error
}

func NewReconciler(config ReconcilerConfig, issuer CertificateIssuer, operations OperationStore) (*Reconciler, error) {
	return newReconciler(config, issuer, operations, waitForRenewalContext)
}

func newReconciler(
	config ReconcilerConfig,
	issuer CertificateIssuer,
	operations OperationStore,
	wait func(context.Context, time.Duration) error,
) (*Reconciler, error) {
	if config.Clock == nil || config.Interval <= 0 || config.ErrorBackoff <= 0 ||
		config.ErrorBackoff > time.Hour || config.BatchSize < 1 || config.BatchSize > 1000 ||
		config.MaxConcurrent < 1 || config.MaxConcurrent > 100 || issuer == nil || operations == nil {
		return nil, failure(CodeInvalidInput, nil)
	}
	if wait == nil {
		return nil, failure(CodeInvalidInput, nil)
	}
	return &Reconciler{config: config, issuer: issuer, operations: operations, wait: wait}, nil
}

func (r *Reconciler) RunOnce(ctx context.Context) ([]ReconcileResult, error) {
	requests, err := r.operations.Recoverable(ctx, r.config.Clock().UTC(), r.config.BatchSize)
	if err != nil {
		return nil, err
	}
	results := make([]ReconcileResult, len(requests))
	jobs := make(chan int)
	var wait sync.WaitGroup
	workers := min(r.config.MaxConcurrent, len(requests))
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for index := range jobs {
				request := requests[index]
				issue, issueErr := r.issuer.Issue(ctx, request)
				results[index] = ReconcileResult{Request: request, Issue: issue, Error: issueErr}
			}
		}()
	}

	next := 0
sendLoop:
	for ; next < len(requests); next++ {
		select {
		case jobs <- next:
		case <-ctx.Done():
			break sendLoop
		}
	}
	close(jobs)
	wait.Wait()
	for ; next < len(requests); next++ {
		results[next] = ReconcileResult{Request: requests[next], Error: contextFailure(ctx.Err())}
	}
	return results, nil
}

func (r *Reconciler) Run(ctx context.Context) error {
	for {
		delay := r.config.Interval
		if _, err := r.RunOnce(ctx); err != nil {
			delay = r.config.ErrorBackoff
		}
		if err := r.wait(ctx, delay); err != nil {
			return err
		}
	}
}
