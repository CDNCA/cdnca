package controlbackuphistory

import (
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/controlbackup"
)

func TestFileReaderDoesNotTrustUnverifiedTerminal(t *testing.T) {
	reader, now := paginationReader(t, 21)
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("P", ed25519.SeedSize)))
	directory := filepath.Join(reader.manifestDirectory, "runs", "run-00")
	start := readSignedStart(t, filepath.Join(directory, "start.signed.json"))
	terminal, err := controlbackup.SignBackupRunTerminal(controlbackup.BackupRunTerminal{
		Schema: controlbackup.BackupRunTerminalSchema, BackupID: "run-00", StartSHA256: start.PayloadSHA256,
		CompletedAt: *now, State: controlbackup.BackupRunFailed, ResultCode: "backup_capture_failed",
	}, "run-key", key)
	if err != nil {
		t.Fatal(err)
	}
	terminal.PayloadSHA256 = strings.Repeat("0", 64)
	writeSigned(t, filepath.Join(directory, "terminal.signed.json"), terminal)
	page, err := reader.List(t.Context(), Query{BackupID: "run-00"})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("page=%+v, err=%v", page, err)
	}
	record := page.Items[0]
	if record.State != "unknown" || !record.OutcomeUnknown || record.SignatureValid || record.ReasonCode != "signature_invalid" || record.CompletedAt != nil || record.ManifestSHA256 != "" || record.ResultCode != "backup_outcome_unknown" {
		t.Fatalf("unverified terminal leaked a result: %+v", record)
	}
}

func TestFileReaderRejectsSourceBindingAsUnknown(t *testing.T) {
	reader, _ := paginationReader(t, 21)
	reader.sourceClusterID = "other-control"
	page, err := reader.List(t.Context(), Query{BackupID: "run-00"})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("page=%+v, err=%v", page, err)
	}
	record := page.Items[0]
	if record.ReasonCode != "binding_conflict" || record.SignatureValid || !record.OutcomeUnknown || record.StartedAt != nil {
		t.Fatalf("unbound record was trusted: %+v", record)
	}
}

func TestFileReaderUnverifiedStartsPaginateWithoutInventingDates(t *testing.T) {
	reader, _ := paginationReader(t, 31)
	for _, name := range []string{"run-00", "run-01"} {
		if err := os.WriteFile(filepath.Join(reader.manifestDirectory, "runs", name, "start.signed.json"), []byte("invalid"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	first, err := reader.List(t.Context(), Query{Limit: 30})
	if err != nil || first.TotalCount != 31 || len(first.Items) != 30 || first.NextCursor == "" {
		t.Fatalf("first=%+v, err=%v", first, err)
	}
	second, err := reader.List(t.Context(), Query{Limit: 30, Cursor: first.NextCursor})
	if err != nil || second.TotalCount != 31 || len(second.Items) != 1 || second.NextCursor != "" {
		t.Fatalf("second=%+v, err=%v", second, err)
	}
	for _, record := range []Record{first.Items[29], second.Items[0]} {
		if record.StartedAt != nil || record.CompletedAt != nil || record.SignatureValid || !record.OutcomeUnknown {
			t.Fatalf("unverified run acquired facts: %+v", record)
		}
	}
	if first.Items[29].BackupID != "run-01" || second.Items[0].BackupID != "run-00" {
		t.Fatal("unknown timestamps must use the backup ID tie-breaker")
	}
}

func TestFileReaderUnavailableAndCancellationDoNotReturnEmptySuccess(t *testing.T) {
	reader, _ := paginationReader(t, 21)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := reader.List(ctx, Query{}); err != context.Canceled {
		t.Fatalf("cancelled err=%v", err)
	}
	reader.manifestDirectory = filepath.Join(reader.manifestDirectory, "missing")
	if _, err := reader.List(t.Context(), Query{}); err != ErrUnavailable {
		t.Fatalf("missing history err=%v", err)
	}
}
