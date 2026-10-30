package originauthcontrol

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type publicationCapacityTx struct {
	pgx.Tx
	rows      pgx.Rows
	queryArgs []any
}

func (tx *publicationCapacityTx) Query(_ context.Context, _ string, args ...any) (pgx.Rows, error) {
	tx.queryArgs = args
	return tx.rows, nil
}

type publicationCapacityRows struct {
	pgx.Rows
	remaining int
	scanned   int
	closed    bool
}

func (rows *publicationCapacityRows) Close() { rows.closed = true }

func (rows *publicationCapacityRows) Next() bool {
	if rows.remaining == 0 {
		return false
	}
	rows.remaining--
	return true
}

func (rows *publicationCapacityRows) Scan(destinations ...any) error {
	if len(destinations) != 14 {
		return fmt.Errorf("scan destinations = %d, want 14", len(destinations))
	}
	rowID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(fmt.Sprintf("rule:%d", rows.scanned)))
	*destinations[0].(*uuid.UUID) = rowID
	*destinations[1].(*uuid.UUID) = rowID
	*destinations[2].(*int) = 1
	*destinations[3].(*string) = ProviderS3
	*destinations[4].(*string) = AlgorithmS3
	*destinations[5].(*string) = "https://bucket.s3.us-east-1.amazonaws.com"
	*destinations[6].(*string) = ""
	*destinations[7].(*string) = "/"
	*destinations[8].(*string) = "us-east-1"
	*destinations[9].(*string) = "s3"
	*destinations[10].(*int) = 3600
	*destinations[11].(*uuid.UUID) = rowID
	*destinations[12].(**uuid.UUID) = nil
	*destinations[13].(**time.Time) = nil
	rows.scanned++
	return nil
}

func (rows *publicationCapacityRows) Err() error { return nil }

func TestBuildPublicationSnapshotRejectsRule10001(t *testing.T) {
	rows := &publicationCapacityRows{remaining: maximumPublicationRules + 1}
	tx := &publicationCapacityTx{rows: rows}
	_, _, err := buildPublicationSnapshot(t.Context(), tx, uuid.New(), 1)
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("buildPublicationSnapshot() error = %v, want ErrValidation", err)
	}
	if rows.scanned != maximumPublicationRules || !rows.closed {
		t.Fatalf("rows scanned = %d, closed = %t", rows.scanned, rows.closed)
	}
	if len(tx.queryArgs) != 2 || tx.queryArgs[1] != maximumPublicationRules+1 {
		t.Fatalf("query args = %#v", tx.queryArgs)
	}
}
