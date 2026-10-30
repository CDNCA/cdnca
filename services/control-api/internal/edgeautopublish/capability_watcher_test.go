package edgeautopublish

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// untouchedTx panics on any use: invalid input must be refused before the
// transaction is read.
type untouchedTx struct{ pgx.Tx }

func TestRequestNodeReadyRepublicationsRefusesInvalidInputBeforeReading(t *testing.T) {
	ctx, tx, nodeID := context.Background(), untouchedTx{}, uuid.New()
	for name, call := range map[string]func() (int, error){
		"nil context": func() (int, error) {
			return RequestNodeReadyRepublicationsTx(nil, tx, nodeID, "ip-intel-ready/x", 0) //nolint:staticcheck // nil context is the case under test
		},
		"nil tx":    func() (int, error) { return RequestNodeReadyRepublicationsTx(ctx, nil, nodeID, "ip-intel-ready/x", 0) },
		"nil node":  func() (int, error) { return RequestNodeReadyRepublicationsTx(ctx, tx, uuid.Nil, "ip-intel-ready/x", 0) },
		"no source": func() (int, error) { return RequestNodeReadyRepublicationsTx(ctx, tx, nodeID, "", 0) },
	} {
		if queued, err := call(); !errors.Is(err, ErrInvalidInput) || queued != 0 {
			t.Fatalf("%s: queued=%d err=%v want %v", name, queued, err, ErrInvalidInput)
		}
	}
}
