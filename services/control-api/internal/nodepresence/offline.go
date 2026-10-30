package nodepresence

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type OfflineRepository interface {
	OfflineCandidates(context.Context, time.Time, int) ([]OfflineCandidate, error)
	MarkOffline(context.Context, OfflineCandidate, time.Time) (bool, error)
}

type LeaseReader interface {
	Exists(context.Context, uuid.UUID) (bool, error)
}

type OfflineWorker struct {
	repository       OfflineRepository
	leases           LeaseReader
	offlineAfter     time.Duration
	interval         time.Duration
	operationTimeout time.Duration
	batchSize        int
	now              func() time.Time
}

func NewOfflineWorker(repository OfflineRepository, leases LeaseReader, offlineAfter, interval,
	operationTimeout time.Duration, batchSize int,
) (*OfflineWorker, error) {
	if repository == nil || leases == nil || offlineAfter <= 0 || interval <= 0 ||
		operationTimeout <= 0 || batchSize <= 0 {
		return nil, fmt.Errorf("invalid offline worker configuration")
	}
	return &OfflineWorker{
		repository: repository, leases: leases, offlineAfter: offlineAfter,
		interval: interval, operationTimeout: operationTimeout, batchSize: batchSize, now: time.Now,
	}, nil
}

func (w *OfflineWorker) RunOnce(ctx context.Context) (int, error) {
	cutoff := w.now().UTC().Add(-w.offlineAfter)
	operationCtx, cancel := context.WithTimeout(ctx, w.operationTimeout)
	candidates, err := w.repository.OfflineCandidates(operationCtx, cutoff, w.batchSize)
	cancel()
	if err != nil {
		return 0, err
	}
	transitioned := 0
	for _, candidate := range candidates {
		operationCtx, cancel = context.WithTimeout(ctx, w.operationTimeout)
		exists, err := w.leases.Exists(operationCtx, candidate.NodeID)
		cancel()
		if err != nil {
			return transitioned, err
		}
		if exists {
			continue
		}
		operationCtx, cancel = context.WithTimeout(ctx, w.operationTimeout)
		changed, err := w.repository.MarkOffline(operationCtx, candidate, cutoff)
		cancel()
		if err != nil {
			return transitioned, err
		}
		if changed {
			transitioned++
		}
	}
	return transitioned, nil
}

func (w *OfflineWorker) Run(ctx context.Context, onError func(error)) error {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		if _, err := w.RunOnce(ctx); err != nil && ctx.Err() == nil && onError != nil {
			onError(err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
