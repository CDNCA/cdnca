package controlbackuphistory

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/controlbackup"
)

func TestFileReaderReadsTerminalAndUnknownRuns(t *testing.T) {
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("A", ed25519.SeedSize)))
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	installation, source := "11111111-1111-4111-8111-111111111111", "control-a"
	started := time.Date(2026, 9, 28, 1, 0, 0, 0, time.UTC)
	writeRunFact(t, root, controlbackup.BackupRunStart{Schema: controlbackup.BackupRunStartSchema, BackupID: "finished", InstallationID: installation, SourceClusterID: source, PlanSHA256: strings.Repeat("a", 64), StartedAt: started}, key, false)
	terminalTime := started.Add(2 * time.Minute)
	runDir := filepath.Join(root, "runs", "finished")
	signedStart := readSignedStart(t, filepath.Join(runDir, "start.signed.json"))
	terminal := controlbackup.BackupRunTerminal{Schema: controlbackup.BackupRunTerminalSchema, BackupID: "finished", StartSHA256: signedStart.PayloadSHA256, CompletedAt: terminalTime, State: controlbackup.BackupRunSucceeded, ResultCode: "backup_succeeded", ManifestSHA256: strings.Repeat("b", 64), RecoveryPointAt: timePtrForTest(started.Add(-time.Minute)), ObservedRPOSeconds: int64Ptr(60)}
	signedTerminal, err := controlbackup.SignBackupRunTerminal(terminal, "run-key", key)
	if err != nil {
		t.Fatal(err)
	}
	writeSigned(t, filepath.Join(runDir, "terminal.signed.json"), signedTerminal)
	writeRunFact(t, root, controlbackup.BackupRunStart{Schema: controlbackup.BackupRunStartSchema, BackupID: "in-progress", InstallationID: installation, SourceClusterID: source, PlanSHA256: strings.Repeat("c", 64), StartedAt: started.Add(time.Minute)}, key, false)
	reader, err := NewFileReader(root, installation, source, map[string]ed25519.PublicKey{"run-key": key.Public().(ed25519.PublicKey)}, []byte(strings.Repeat("x", 32)), func() time.Time { return started.Add(time.Hour) })
	if err != nil {
		t.Fatal(err)
	}
	page, err := reader.List(t.Context(), Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if page.TotalCount != 2 || len(page.Items) != 2 {
		t.Fatalf("page=%+v", page)
	}
	if page.Items[0].BackupID != "in-progress" || !page.Items[0].OutcomeUnknown || page.Items[0].CompletedAt != nil || page.Items[0].ReasonCode != "terminal_unavailable" {
		t.Fatalf("unknown=%+v", page.Items[0])
	}
	if page.Items[1].BackupID != "finished" || page.Items[1].OutcomeUnknown || !page.Items[1].SignatureValid || page.Items[1].ReasonCode != "terminal_recorded" {
		t.Fatalf("finished=%+v", page.Items[1])
	}
}

func TestFileReaderRejectsTamperedAndUnboundAsUnknown(t *testing.T) {
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("B", ed25519.SeedSize)))
	root := t.TempDir()
	_ = os.Chmod(root, 0o700)
	start := controlbackup.BackupRunStart{Schema: controlbackup.BackupRunStartSchema, BackupID: "tampered", InstallationID: "11111111-1111-4111-8111-111111111111", SourceClusterID: "other", PlanSHA256: strings.Repeat("a", 64), StartedAt: time.Now().UTC()}
	writeRunFact(t, root, start, key, true)
	reader, err := NewFileReader(root, "11111111-1111-4111-8111-111111111111", "expected", map[string]ed25519.PublicKey{"run-key": key.Public().(ed25519.PublicKey)}, []byte(strings.Repeat("x", 32)), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	page, err := reader.List(t.Context(), Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || !page.Items[0].OutcomeUnknown || page.Items[0].SignatureValid || page.Items[0].ReasonCode != "signature_invalid" && page.Items[0].ReasonCode != "binding_conflict" {
		t.Fatalf("item=%+v", page.Items)
	}
}

func TestFileReaderCursorPaginationAndTamper(t *testing.T) {
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("C", ed25519.SeedSize)))
	root := t.TempDir()
	_ = os.Chmod(root, 0o700)
	base := time.Date(2026, 9, 28, 1, 0, 0, 0, time.UTC)
	for index := 0; index < 11; index++ {
		writeRunFact(t, root, controlbackup.BackupRunStart{Schema: controlbackup.BackupRunStartSchema, BackupID: "run-" + string(rune('a'+index)), InstallationID: "11111111-1111-4111-8111-111111111111", SourceClusterID: "control-a", PlanSHA256: strings.Repeat("a", 64), StartedAt: base.Add(time.Duration(index) * time.Minute)}, key, false)
	}
	reader, _ := NewFileReader(root, "11111111-1111-4111-8111-111111111111", "control-a", map[string]ed25519.PublicKey{"run-key": key.Public().(ed25519.PublicKey)}, []byte(strings.Repeat("x", 32)), func() time.Time { return base.Add(time.Hour) })
	first, err := reader.List(t.Context(), Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Items) != 10 || first.NextCursor == "" {
		t.Fatalf("first=%+v", first)
	}
	second, err := reader.List(t.Context(), Query{Limit: 10, Cursor: first.NextCursor})
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Items) != 1 || second.Items[0].BackupID == first.Items[0].BackupID || second.NextCursor != "" {
		t.Fatalf("second=%+v", second)
	}
	if _, err := reader.List(t.Context(), Query{Limit: 10, Cursor: first.NextCursor + "x"}); err != ErrInvalidCursor {
		t.Fatalf("tampered err=%v", err)
	}
}

func writeRunFact(t *testing.T, root string, start controlbackup.BackupRunStart, key ed25519.PrivateKey, tamper bool) {
	t.Helper()
	dir := filepath.Join(root, "runs", start.BackupID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	signed, err := controlbackup.SignBackupRunStart(start, "run-key", key)
	if err != nil {
		t.Fatal(err)
	}
	if tamper {
		signed.PayloadSHA256 = strings.Repeat("0", 64)
	}
	writeSigned(t, filepath.Join(dir, "start.signed.json"), signed)
}

func writeSigned(t *testing.T, path string, value controlbackup.SignedBackupRunFact) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
}
func readSignedStart(t *testing.T, path string) controlbackup.SignedBackupRunFact {
	t.Helper()
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var value controlbackup.SignedBackupRunFact
	if err := json.Unmarshal(encoded, &value); err != nil {
		t.Fatal(err)
	}
	return value
}
func timePtrForTest(value time.Time) *time.Time { return &value }
func int64Ptr(value int64) *int64               { return &value }

// fix-flags2 E4: an installation with no backup runner reads as an empty page
// flagged unconfigured, never as an outage; it issues no cursors.
func TestUnconfiguredReaderAnswersEmptyPage(t *testing.T) {
	now := time.Date(2026, 10, 22, 8, 0, 0, 0, time.UTC)
	page, err := Unconfigured{Now: func() time.Time { return now }}.List(context.Background(), Query{Limit: 10})
	if err != nil || !page.Unconfigured || page.Items == nil || len(page.Items) != 0 || page.TotalCount != 0 ||
		page.Schema != "cdnca.control-backup-history/v1" || !page.SnapshotAt.Equal(now) {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	encoded, _ := json.Marshal(page)
	if !strings.Contains(string(encoded), `"unconfigured":true`) || !strings.Contains(string(encoded), `"items":[]`) {
		t.Fatalf("encoded=%s", encoded)
	}
	if _, err := (Unconfigured{Now: time.Now}).List(context.Background(), Query{Cursor: "x"}); err != ErrInvalidCursor {
		t.Fatalf("cursor err=%v", err)
	}
}
