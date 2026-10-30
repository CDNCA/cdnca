package analytics

import (
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresIngestHistoryValidateReceiptRejectsIdentityConflicts(t *testing.T) {
	generation := authorityGenerationV1()
	receipt, err := NewIngestReceiptV1(generation, generation.HistoryStartSequence, authorityDecodedIngestV1(t))
	if err != nil {
		t.Fatal(err)
	}
	history := &postgresIngestHistoryV1{pool: &pgxpool.Pool{}, generation: generation}

	if err := history.validateReceipt(receipt); err != nil {
		t.Fatalf("valid receipt rejected: %v", err)
	}

	conflicts := []struct {
		name   string
		mutate func(*IngestReceiptV1)
	}{
		{name: "message ID", mutate: func(value *IngestReceiptV1) { value.MessageID = "changed-message" }},
		{name: "payload digest", mutate: func(value *IngestReceiptV1) { value.PayloadSHA256[0] ^= 0xff }},
		{name: "canonical event digest", mutate: func(value *IngestReceiptV1) { value.CanonicalEventSHA256[0] ^= 0xff }},
		{name: "generation digest", mutate: func(value *IngestReceiptV1) { value.GenerationSHA256[0] ^= 0xff }},
		{name: "receipt identity digest", mutate: func(value *IngestReceiptV1) { value.ReceiptIdentitySHA256[0] ^= 0xff }},
		{name: "ClickHouse token", mutate: func(value *IngestReceiptV1) { value.ClickHouseToken += "-changed" }},
	}
	for _, test := range conflicts {
		t.Run(test.name, func(t *testing.T) {
			candidate := receipt
			test.mutate(&candidate)
			if err := history.validateReceipt(candidate); !errors.Is(err, ErrIngestReceiptConflict) {
				t.Fatalf("validateReceipt error = %v, want %v", err, ErrIngestReceiptConflict)
			}
		})
	}

	zeroDigests := []struct {
		name   string
		mutate func(*IngestReceiptV1)
	}{
		{name: "empty message ID", mutate: func(value *IngestReceiptV1) { value.MessageID = "" }},
		{name: "zero payload digest", mutate: func(value *IngestReceiptV1) { value.PayloadSHA256 = [sha256.Size]byte{} }},
		{name: "zero canonical event digest", mutate: func(value *IngestReceiptV1) { value.CanonicalEventSHA256 = [sha256.Size]byte{} }},
		{name: "zero generation digest", mutate: func(value *IngestReceiptV1) { value.GenerationSHA256 = [sha256.Size]byte{} }},
		{name: "zero receipt identity digest", mutate: func(value *IngestReceiptV1) { value.ReceiptIdentitySHA256 = [sha256.Size]byte{} }},
	}
	for _, test := range zeroDigests {
		t.Run(test.name, func(t *testing.T) {
			candidate := receipt
			test.mutate(&candidate)
			if err := history.validateReceipt(candidate); !errors.Is(err, ErrIngestReceiptConflict) {
				t.Fatalf("validateReceipt error = %v, want %v", err, ErrIngestReceiptConflict)
			}
		})
	}
}
