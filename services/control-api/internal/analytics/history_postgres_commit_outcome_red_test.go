package analytics

import (
	"context"
	"errors"
	"testing"
)

func TestMapHistoryCommitOutcomeV1(t *testing.T) {
	if err := mapHistoryCommitOutcomeV1(nil); err != nil {
		t.Fatalf("nil commit error mapped to %v", err)
	}

	commitFailure := errors.New("commit result lost")
	for _, cause := range []error{commitFailure, context.DeadlineExceeded} {
		mapped := mapHistoryCommitOutcomeV1(cause)
		if !errors.Is(mapped, ErrIngestWriteOutcomeUnknown) {
			t.Fatalf("mapped error %v does not identify unknown write outcome", mapped)
		}
		if !errors.Is(mapped, cause) {
			t.Fatalf("mapped error %v does not retain cause %v", mapped, cause)
		}
	}
}
