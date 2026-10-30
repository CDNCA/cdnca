package notification

import "time"

type RetryPolicy struct {
	maxAttempts int
	baseDelay   time.Duration
	maxDelay    time.Duration
	now         Clock
}

func NewRetryPolicy(maxAttempts int, baseDelay, maxDelay time.Duration, now Clock) (*RetryPolicy, error) {
	if maxAttempts <= 0 || maxAttempts > 100 || baseDelay <= 0 || maxDelay < baseDelay || now == nil {
		return nil, ErrInvalidRetryPolicy
	}
	return &RetryPolicy{maxAttempts: maxAttempts, baseDelay: baseDelay, maxDelay: maxDelay, now: now}, nil
}

func (p *RetryPolicy) Decide(completedAttempts int, failure Failure) (RetryDecision, error) {
	if p == nil {
		return RetryDecision{}, ErrInvalidRetryPolicy
	}
	if completedAttempts <= 0 || !validFailure(failure) {
		return RetryDecision{}, ErrInvalidFailure
	}
	decision := RetryDecision{FailureCode: failure.Code}
	if failure.Class == FailurePermanent {
		decision.Action = RetryStopped
		return decision, nil
	}
	if completedAttempts >= p.maxAttempts {
		decision.Action = RetryExhausted
		return decision, nil
	}
	delay := boundedDelay(p.baseDelay, p.maxDelay, completedAttempts)
	if failure.RetryAfter > delay {
		delay = failure.RetryAfter
	}
	if delay > p.maxDelay {
		delay = p.maxDelay
	}
	decision.Action = RetryScheduled
	decision.NextAttempt = completedAttempts + 1
	decision.Delay = delay
	decision.RetryAt = p.now().UTC().Add(delay)
	return decision, nil
}

func validFailure(failure Failure) bool {
	return (failure.Class == FailureTemporary || failure.Class == FailurePermanent) &&
		templateIDPattern.MatchString(failure.Code) && !isSensitiveName(failure.Code) &&
		failure.RetryAfter >= 0 && (failure.Class == FailureTemporary || failure.RetryAfter == 0)
}

func boundedDelay(base, maximum time.Duration, completedAttempts int) time.Duration {
	delay := base
	for current := 1; current < completedAttempts && delay < maximum; current++ {
		if delay > maximum/2 {
			return maximum
		}
		delay *= 2
	}
	if delay > maximum {
		return maximum
	}
	return delay
}
