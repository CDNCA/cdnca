package analytics

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestMapRecoveryWriteOutcomeV1DistinguishesFencingFromAmbiguousCommit(t *testing.T) {
	if err := mapRecoveryWriteOutcomeV1(nil); err != nil {
		t.Fatalf("nil recovery write error mapped to %v", err)
	}

	for _, test := range []struct {
		name string
		code string
		want error
	}{
		{name: "claim token fenced", code: "P9803", want: ErrIngestRecoveryFenced},
		{name: "claim no longer active", code: "P9802", want: ErrIngestRecoveryFenced},
	} {
		t.Run(test.name, func(t *testing.T) {
			mapped := mapRecoveryWriteOutcomeV1(&pgconn.PgError{Code: test.code})
			if !errors.Is(mapped, test.want) {
				t.Fatalf("mapped error = %v, want %v", mapped, test.want)
			}
			if errors.Is(mapped, ErrIngestWriteOutcomeUnknown) {
				t.Fatalf("deterministic fencing mapped as unknown outcome: %v", mapped)
			}
		})
	}

	for _, cause := range []error{context.DeadlineExceeded, errors.New("connection lost after query dispatch")} {
		mapped := mapRecoveryWriteOutcomeV1(cause)
		if !errors.Is(mapped, ErrIngestWriteOutcomeUnknown) {
			t.Fatalf("mapped error %v does not identify unknown write outcome", mapped)
		}
		if !errors.Is(mapped, cause) {
			t.Fatalf("mapped error %v does not retain cause %v", mapped, cause)
		}
	}
}
