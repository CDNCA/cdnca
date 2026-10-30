package originroute

import (
	"context"
	"errors"
	"fmt"
)

type BatchCandidate struct {
	Publisher *Publisher
	Policy    []byte
}

func ApplyBatch(ctx context.Context, candidates []BatchCandidate) ([]ApplyResult, error) {
	if len(candidates) == 0 {
		return nil, invalid("origin route batch must contain at least one site")
	}
	seen := make(map[*Publisher]struct{}, len(candidates))
	for index, candidate := range candidates {
		if candidate.Publisher == nil {
			return nil, invalid("batch candidate %d publisher is required", index)
		}
		if _, duplicate := seen[candidate.Publisher]; duplicate {
			return nil, invalid("batch candidates must use distinct site publishers")
		}
		seen[candidate.Publisher] = struct{}{}
		policy, err := Parse(candidate.Policy)
		if err != nil {
			return nil, err
		}
		if err := ValidateLocalBindings(ctx, policy, candidate.Publisher.addresses); err != nil {
			return nil, err
		}
		if _, err := Compile(policy, candidate.Publisher.stateRoot, candidate.Publisher.luaRoot); err != nil {
			return nil, err
		}
	}

	snapshots := make([]string, len(candidates))
	for index, candidate := range candidates {
		digest, err := candidate.Publisher.batchSnapshot(ctx)
		if err != nil {
			return nil, err
		}
		snapshots[index] = digest
	}

	results := make([]ApplyResult, len(candidates))
	for index, candidate := range candidates {
		result, err := candidate.Publisher.Apply(ctx, candidate.Policy)
		if err == nil {
			results[index] = result
			continue
		}
		rollbackErr := rollbackBatch(ctx, candidates[:index], snapshots[:index])
		if rollbackErr != nil {
			return nil, errors.Join(err, ErrRollback, rollbackErr)
		}
		return nil, err
	}
	return results, nil
}

func (publisher *Publisher) batchSnapshot(ctx context.Context) (string, error) {
	publisher.mu.Lock()
	defer publisher.mu.Unlock()
	if err := publisher.ensureState(); err != nil {
		return "", err
	}
	unlock, err := publisher.lock(ctx)
	if err != nil {
		return "", err
	}
	defer unlock()
	if err := publisher.reconcile(); err != nil {
		return "", err
	}
	current, err := publisher.pointer("current")
	if err != nil {
		return "", err
	}
	lkg, err := publisher.pointer("lkg")
	if err != nil {
		return "", err
	}
	if current != lkg {
		return "", fmt.Errorf("%w: origin route current and LKG differ after reconciliation", ErrRollback)
	}
	return current, nil
}

func rollbackBatch(ctx context.Context, candidates []BatchCandidate, snapshots []string) error {
	var result error
	for index := len(candidates) - 1; index >= 0; index-- {
		if err := candidates[index].Publisher.restoreBatchSnapshot(ctx, snapshots[index]); err != nil {
			result = errors.Join(result, err)
		}
	}
	return result
}

func (publisher *Publisher) restoreBatchSnapshot(ctx context.Context, digest string) error {
	publisher.mu.Lock()
	defer publisher.mu.Unlock()
	unlock, err := publisher.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	if err := publisher.reconcile(); err != nil {
		return err
	}
	current, err := publisher.pointer("current")
	if err != nil {
		return err
	}
	if current == digest {
		return nil
	}
	if digest != "" {
		if _, err := publisher.readRelease(digest); err != nil {
			return err
		}
		if err := publisher.writeJournal(publicationJournal{
			Schema: publicationJournalSchema, CandidateDigest: digest, PreviousDigest: current,
		}); err != nil {
			return err
		}
	}
	if err := publisher.restore(digest); err != nil {
		return err
	}
	if digest == "" {
		if err := publisher.removePointer("lkg"); err != nil {
			return err
		}
	} else if err := publisher.setPointer("lkg", digest); err != nil {
		return err
	}
	return publisher.clearJournal()
}
