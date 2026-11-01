package analytics

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// 098 对"准备不连号"与"身份不符"共用 P9803：不连号必须单独映射，不能报成 receipt conflict。
func TestMapReceiptPGErrorSeparatesNonContiguousPreparation(t *testing.T) {
	gap := mapReceiptPGError(&pgconn.PgError{Code: "P9803", Message: "analytics ingest preparation sequence is not contiguous"})
	if !errors.Is(gap, ErrIngestPreparationNotContiguous) || errors.Is(gap, ErrIngestReceiptConflict) {
		t.Fatalf("non-contiguous preparation mapped to %v", gap)
	}
	identity := mapReceiptPGError(&pgconn.PgError{Code: "P9803", Message: "analytics ingest receipt identity does not match"})
	if !errors.Is(identity, ErrIngestReceiptConflict) {
		t.Fatalf("identity mismatch mapped to %v", identity)
	}
}
