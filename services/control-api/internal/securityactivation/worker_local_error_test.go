package securityactivation

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// A guard refusal (P8802) on one candidate must not stop the worker; connection-class errors still do.
func TestCandidateLocalError(t *testing.T) {
	for code, want := range map[string]bool{"P8802": true, "23505": true, "22023": true, "08006": false, "53300": false, "57P01": false, "XX000": false} {
		err := fmt.Errorf("reconcile: %w", &pgconn.PgError{Code: code})
		if got := candidateLocalError(err); got != want {
			t.Errorf("code %s: candidateLocalError = %v, want %v", code, got, want)
		}
	}
	if candidateLocalError(errors.New("plain")) {
		t.Error("a non-database error counted as candidate-local")
	}
}
