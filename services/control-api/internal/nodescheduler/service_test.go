package nodescheduler

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestWriteReplayMatchesCurrentAndCompletedV226Digests(t *testing.T) {
	current := sha256.Sum256([]byte("current"))
	v226 := sha256.Sum256([]byte("v226"))
	other := sha256.Sum256([]byte("other"))
	completedAt := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
	response := []byte(`{"group":{"revision":1}}`)
	tests := []struct {
		name       string
		existing   [32]byte
		completed  *time.Time
		response   []byte
		compatible [][32]byte
		want       bool
	}{
		{name: "current digest", existing: current, completed: &completedAt, response: response, want: true},
		{name: "completed v226 digest", existing: v226, completed: &completedAt, response: response, compatible: [][32]byte{v226}, want: true},
		{name: "mismatched digest", existing: other, completed: &completedAt, response: response, compatible: [][32]byte{v226}},
		{name: "unfinished v226 receipt", existing: v226, response: response, compatible: [][32]byte{v226}},
		{name: "empty v226 response", existing: v226, completed: &completedAt, compatible: [][32]byte{v226}},
		{name: "v226 digest not enabled", existing: v226, completed: &completedAt, response: response},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := writeReplayMatches(test.existing[:], current, test.completed, test.response, test.compatible...); got != test.want {
				t.Fatalf("writeReplayMatches() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestClassifyWriteErrorResolvedValueConflictIsInvalidInput(t *testing.T) {
	err := classifyWriteError(&pgconn.PgError{
		Code:           "23505",
		ConstraintName: "node_line_groups_scope_resolved_value_unique",
	})
	if !errors.Is(err, ErrInvalidInput) || errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("classified error = %v", err)
	}
}
