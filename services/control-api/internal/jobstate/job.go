package jobstate

import (
	"fmt"
	"sync"
	"time"
)

type Job struct {
	mu sync.RWMutex

	idempotencyKey string
	digest         RequestDigest
	state          State
	attempt        uint32
	maxRetries     uint32
	items          []ItemResult
	itemIndex      map[string]int
	clock          Clock
	createdAt      time.Time
	startedAt      time.Time
	updatedAt      time.Time
	completedAt    time.Time
}

func newJob(request Request, digest RequestDigest, clock Clock) *Job {
	now := clock().UTC()
	job := &Job{
		idempotencyKey: request.IdempotencyKey,
		digest:         digest,
		state:          StateQueued,
		maxRetries:     request.MaxRetries,
		items:          make([]ItemResult, len(request.ItemIDs)),
		itemIndex:      make(map[string]int, len(request.ItemIDs)),
		clock:          clock,
		createdAt:      now,
		updatedAt:      now,
	}
	for index, itemID := range request.ItemIDs {
		job.items[index] = ItemResult{ItemID: itemID, State: ItemPending}
		job.itemIndex[itemID] = index
	}
	return job
}

func (job *Job) Start() (Snapshot, error) {
	job.mu.Lock()
	defer job.mu.Unlock()
	if job.state != StateQueued {
		return Snapshot{}, fmt.Errorf("%w: %s to %s", ErrInvalidTransition, job.state, StateRunning)
	}
	if job.attempt >= job.maxRetries+1 {
		return Snapshot{}, ErrRetriesExhausted
	}
	if err := job.transitionLocked(StateRunning); err != nil {
		return Snapshot{}, err
	}
	job.attempt++
	job.startedAt = job.stampLocked()
	job.completedAt = time.Time{}
	return job.snapshotLocked(), nil
}

// Retry queues only failed items. Successful items remain final and are not dispatched again.
func (job *Job) Retry() (Snapshot, error) {
	job.mu.Lock()
	defer job.mu.Unlock()
	if job.state != StateFailed && job.state != StatePartialFailed {
		return Snapshot{}, fmt.Errorf("%w: %s to %s", ErrInvalidTransition, job.state, StateQueued)
	}
	if job.attempt >= job.maxRetries+1 {
		return Snapshot{}, ErrRetriesExhausted
	}
	if err := job.transitionLocked(StateQueued); err != nil {
		return Snapshot{}, err
	}
	for index := range job.items {
		if job.items[index].State != ItemFailed {
			continue
		}
		job.items[index].State = ItemPending
		job.items[index].Code = ""
		job.items[index].Sequence = 0
		job.items[index].CompletedAt = time.Time{}
	}
	job.completedAt = time.Time{}
	job.stampLocked()
	return job.snapshotLocked(), nil
}

func (job *Job) Cancel() (Snapshot, error) {
	job.mu.Lock()
	defer job.mu.Unlock()
	if job.state == StateCancelled {
		return job.snapshotLocked(), nil
	}
	if job.state != StateQueued && job.state != StateRunning {
		return Snapshot{}, fmt.Errorf("%w: %s to %s", ErrInvalidTransition, job.state, StateCancelled)
	}
	if err := job.transitionLocked(StateCancelled); err != nil {
		return Snapshot{}, err
	}
	now := job.stampLocked()
	for index := range job.items {
		if job.items[index].State != ItemPending {
			continue
		}
		job.items[index].State = ItemCancelled
		job.items[index].Code = CodeCancelled
		job.items[index].Attempt = job.attempt
		job.items[index].CompletedAt = now
	}
	job.completedAt = now
	return job.snapshotLocked(), nil
}

// Apply records a terminal item result. It returns false for duplicate, stale,
// or terminal-state reports so at-least-once delivery cannot regress the job.
func (job *Job) Apply(report Report) (bool, error) {
	if err := validateReport(report); err != nil {
		return false, err
	}
	job.mu.Lock()
	defer job.mu.Unlock()
	index, exists := job.itemIndex[report.ItemID]
	if !exists {
		return false, ErrInvalidReport
	}
	if report.Attempt < job.attempt {
		return false, nil
	}
	if report.Attempt > job.attempt || job.attempt == 0 {
		return false, ErrInvalidReport
	}
	item := &job.items[index]
	if item.State != ItemPending {
		if report.Attempt == item.Attempt && report.Sequence == item.Sequence &&
			(report.State != item.State || report.Code != item.Code) {
			return false, ErrReportConflict
		}
		return false, nil
	}
	if job.state != StateRunning {
		if job.state.Terminal() {
			return false, nil
		}
		if job.state == StateQueued && report.Attempt == job.attempt {
			return false, nil
		}
		return false, ErrInvalidTransition
	}

	now := job.stampLocked()
	item.State = report.State
	item.Code = report.Code
	item.Attempt = report.Attempt
	item.Sequence = report.Sequence
	item.CompletedAt = now
	if err := job.finishIfCompleteLocked(now); err != nil {
		return false, err
	}
	return true, nil
}

func validateReport(report Report) error {
	if !validSafeText(report.ItemID, maxItemIDRunes, false) || report.Attempt == 0 || report.Sequence == 0 ||
		(report.State != ItemSucceeded && report.State != ItemFailed && report.State != ItemCancelled) ||
		(report.State == ItemSucceeded && report.Code != "") ||
		(report.State == ItemFailed && !validStableIdentifier(report.Code)) ||
		(report.State == ItemCancelled && report.Code != CodeCancelled) {
		return ErrInvalidReport
	}
	return nil
}

func (job *Job) CanCancel() bool {
	job.mu.RLock()
	defer job.mu.RUnlock()
	return job.state == StateQueued || job.state == StateRunning
}

func (job *Job) Snapshot() Snapshot {
	job.mu.RLock()
	defer job.mu.RUnlock()
	return job.snapshotLocked()
}

func (job *Job) transitionLocked(to State) error {
	if !CanTransition(job.state, to) {
		return fmt.Errorf("%w: %s to %s", ErrInvalidTransition, job.state, to)
	}
	job.state = to
	return nil
}

func (job *Job) finishIfCompleteLocked(now time.Time) error {
	progress := progress(job.items)
	if progress.Completed != progress.Total {
		return nil
	}
	to, _ := aggregateState(progress.Total, progress.Succeeded, progress.Failed, progress.Cancelled)
	if err := job.transitionLocked(to); err != nil {
		return err
	}
	job.completedAt = now
	return nil
}

func (job *Job) stampLocked() time.Time {
	now := job.clock().UTC()
	if now.Before(job.updatedAt) {
		now = job.updatedAt
	}
	job.updatedAt = now
	return now
}

func (job *Job) snapshotLocked() Snapshot {
	items := make([]ItemResult, len(job.items))
	copy(items, job.items)
	return Snapshot{
		IdempotencyKey: job.idempotencyKey,
		Digest:         job.digest,
		State:          job.state,
		Attempt:        job.attempt,
		MaxRetries:     job.maxRetries,
		Progress:       progress(items),
		Items:          items,
		CreatedAt:      job.createdAt,
		StartedAt:      job.startedAt,
		UpdatedAt:      job.updatedAt,
		CompletedAt:    job.completedAt,
	}
}

func progress(items []ItemResult) Progress {
	result := Progress{Total: len(items)}
	for _, item := range items {
		switch item.State {
		case ItemSucceeded:
			result.Succeeded++
		case ItemFailed:
			result.Failed++
		case ItemCancelled:
			result.Cancelled++
		case ItemPending:
			result.Pending++
		}
	}
	result.Completed = result.Succeeded + result.Failed + result.Cancelled
	return result
}
