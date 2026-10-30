package dnsacme

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestMapWriteErrorTreatsActiveDNSProviderClaimAsRevisionConflict(t *testing.T) {
	err := mapWriteError(&pgconn.PgError{Code: "P8903", Message: "active DNS provider mutation claim"})
	if !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("mapWriteError(P8903) = %v, want ErrRevisionConflict", err)
	}
}
