package httpapi

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestSiteRetryableConflict(t *testing.T) {
	for code, want := range map[string]bool{"40P01": true, "40001": true, "23505": false} {
		err := fmt.Errorf("delete site: %w", &pgconn.PgError{Code: code})
		if got := siteRetryableConflict(err); got != want {
			t.Fatalf("%s = %v, want %v", code, got, want)
		}
	}
	if siteRetryableConflict(errors.New("other")) {
		t.Fatal("plain error treated as retryable")
	}
}
