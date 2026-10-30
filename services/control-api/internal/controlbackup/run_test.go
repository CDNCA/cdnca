package controlbackup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func backupRunFixture() (BackupRunStart, ed25519.PrivateKey, map[string]ed25519.PublicKey, BackupRunExpectation) {
	start := BackupRunStart{Schema: BackupRunStartSchema, BackupID: "run-1",
		InstallationID: "11111111-1111-4111-8111-111111111111", SourceClusterID: "control-test",
		PlanSHA256: strings.Repeat("a", 64), StartedAt: time.Date(2026, 9, 28, 1, 2, 3, 0, time.UTC)}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, ed25519.SeedSize))
	keys := map[string]ed25519.PublicKey{"run-key": key.Public().(ed25519.PublicKey)}
	return start, key, keys, BackupRunExpectation{InstallationID: start.InstallationID,
		SourceClusterID: start.SourceClusterID, BackupID: start.BackupID, PlanSHA256: start.PlanSHA256}
}

func TestBackupRunSignatureBindingAndUnknown(t *testing.T) {
	start, key, keys, expected := backupRunFixture()
	signed, err := SignBackupRunStart(start, "run-key", key)
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := VerifyBackupRun(signed, nil, keys, expected)
	if err != nil || unknown.Terminal != nil || unknown.Start != start {
		t.Fatalf("start-only verification: %#v, %v", unknown, err)
	}
	terminal := BackupRunTerminal{Schema: BackupRunTerminalSchema, BackupID: start.BackupID,
		StartSHA256: signed.PayloadSHA256, CompletedAt: start.StartedAt.Add(time.Minute),
		State: BackupRunFailed, ResultCode: "backup_capture_failed"}
	signedTerminal, err := SignBackupRunTerminal(terminal, "run-key", key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBackupRun(signed, &signedTerminal, keys, expected); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"installation", "source", "backup", "plan"} {
		t.Run(field, func(t *testing.T) {
			wrong := expected
			switch field {
			case "installation":
				wrong.InstallationID = "22222222-2222-4222-8222-222222222222"
			case "source":
				wrong.SourceClusterID = "another-control"
			case "backup":
				wrong.BackupID = "another-backup"
			case "plan":
				wrong.PlanSHA256 = strings.Repeat("b", 64)
			}
			if _, err := VerifyBackupRun(signed, &signedTerminal, keys, wrong); !errors.Is(err, ErrBackupRunConflict) {
				t.Fatalf("wrong binding accepted: %v", err)
			}
		})
	}
	for _, mutation := range []string{"payload", "key", "signature-domain", "duplicate-key", "terminal-binding", "time"} {
		t.Run(mutation, func(t *testing.T) {
			altered, last := signed, signedTerminal
			switch mutation {
			case "payload":
				altered.Payload = append(append([]byte(nil), signed.Payload...), ' ')
			case "key":
				altered.SigningKeyID = "untrusted"
			case "signature-domain":
				altered.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, signed.Payload))
			case "duplicate-key":
				altered.Payload = []byte(strings.Replace(string(signed.Payload), `"backup_id":"run-1"`, `"backup_id":"other","backup_id":"run-1"`, 1))
				digest := sha256.Sum256(altered.Payload)
				altered.PayloadSHA256 = hex.EncodeToString(digest[:])
				altered.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, append([]byte(backupRunSignatureDomain), altered.Payload...)))
			case "terminal-binding":
				value := terminal
				value.StartSHA256 = strings.Repeat("b", 64)
				last, _ = SignBackupRunTerminal(value, "run-key", key)
			case "time":
				value := terminal
				value.CompletedAt = start.StartedAt.Add(-time.Second)
				last, _ = SignBackupRunTerminal(value, "run-key", key)
			}
			if _, err := VerifyBackupRun(altered, &last, keys, expected); !errors.Is(err, ErrBackupRunIntegrity) {
				t.Fatalf("unsafe signature accepted: %v", err)
			}
		})
	}
	encoded, _ := json.Marshal(signed)
	if _, err := DecodeBackupRunFact(encoded); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeBackupRunFact(append(encoded, encoded...)); err == nil {
		t.Fatal("trailing envelope accepted")
	}
}

func TestBackupRunStoreExclusiveClaimAndImmutableTerminal(t *testing.T) {
	start, key, keys, expected := backupRunFixture()
	directory := privateRunDirectory(t)
	store, err := NewFileBackupRunStore(directory, keys, expected)
	if err != nil {
		t.Fatal(err)
	}
	var winners atomic.Int32
	var group sync.WaitGroup
	for range 24 {
		group.Add(1)
		go func() {
			defer group.Done()
			_, created, err := store.Begin(start, "run-key", key)
			if created {
				winners.Add(1)
			}
			if err != nil && !errors.Is(err, ErrBackupRunIntegrity) {
				t.Errorf("begin: %v", err)
			}
		}()
	}
	group.Wait()
	if winners.Load() != 1 {
		t.Fatalf("execution grants = %d", winners.Load())
	}
	first, err := ReadBackupRun(directory, start.BackupID, keys, expected)
	if err != nil || first.Terminal != nil {
		t.Fatalf("initial: %#v %v", first, err)
	}
	terminal := BackupRunTerminal{Schema: BackupRunTerminalSchema, BackupID: start.BackupID,
		StartSHA256: first.SignedStart.PayloadSHA256, CompletedAt: start.StartedAt.Add(time.Minute),
		State: BackupRunFailed, ResultCode: "backup_capture_failed"}
	for range 2 {
		if _, err := store.Finish(terminal, "run-key", key); err != nil {
			t.Fatal(err)
		}
	}
	changed := terminal
	changed.ResultCode = "backup_manifest_failed"
	if _, err := store.Finish(changed, "run-key", key); !errors.Is(err, ErrBackupRunConflict) {
		t.Fatalf("terminal changed: %v", err)
	}
	start.StartedAt = start.StartedAt.Add(time.Hour)
	replay, created, err := store.Begin(start, "run-key", key)
	if err != nil || created || replay.Terminal == nil || *replay.Terminal != terminal {
		t.Fatalf("replay: %#v %t %v", replay, created, err)
	}
	wrong := expected
	wrong.PlanSHA256 = strings.Repeat("b", 64)
	if err := os.WriteFile(filepath.Join(directory, "runs", start.BackupID, "terminal.signed.json"), []byte("bad"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadBackupRun(directory, start.BackupID, keys, wrong); !errors.Is(err, ErrBackupRunConflict) {
		t.Fatalf("result read before binding: %v", err)
	}
}

func TestBackupRunStoreRejectsUnsafeFilesAndRetainsUnknown(t *testing.T) {
	for _, mode := range []string{"legacy", "symlink-root", "partial-start", "terminal-store-failure"} {
		t.Run(mode, func(t *testing.T) {
			start, key, keys, expected := backupRunFixture()
			directory := privateRunDirectory(t)
			store, err := NewFileBackupRunStore(directory, keys, expected)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "legacy":
				err = os.WriteFile(filepath.Join(directory, start.BackupID+".signed.json"), []byte("legacy"), 0o600)
			case "symlink-root":
				err = os.Symlink(t.TempDir(), filepath.Join(directory, "runs"))
			case "partial-start":
				err = os.MkdirAll(filepath.Join(directory, "runs", start.BackupID), 0o700)
			}
			if err != nil {
				t.Fatal(err)
			}
			first, created, err := store.Begin(start, "run-key", key)
			if mode != "terminal-store-failure" {
				if err == nil || created {
					t.Fatalf("unsafe run granted: %t %v", created, err)
				}
				return
			}
			if err != nil || !created {
				t.Fatalf("begin: %t %v", created, err)
			}
			if err := os.Mkdir(filepath.Join(directory, "runs", start.BackupID, "terminal.signed.json.tmp"), 0o700); err != nil {
				t.Fatal(err)
			}
			_, err = store.Finish(BackupRunTerminal{Schema: BackupRunTerminalSchema, BackupID: start.BackupID,
				StartSHA256: first.SignedStart.PayloadSHA256, CompletedAt: start.StartedAt.Add(time.Minute),
				State: BackupRunFailed, ResultCode: "backup_capture_failed"}, "run-key", key)
			if !errors.Is(err, ErrBackupRunStore) {
				t.Fatalf("finish: %v", err)
			}
			replay, created, err := store.Begin(start, "run-key", key)
			if err != nil || created || replay.Terminal != nil {
				t.Fatalf("unknown replay: %#v %t %v", replay, created, err)
			}
		})
	}
}

type outcomeFreeze struct {
	acquireErr, releaseErr error
	released               bool
}

func (freeze *outcomeFreeze) Acquire(context.Context, string) (WriteFreezeLease, error) {
	return freeze, freeze.acquireErr
}
func (*outcomeFreeze) ID() string { return "freeze-ops12" }
func (freeze *outcomeFreeze) Release(context.Context) error {
	freeze.released = true
	return freeze.releaseErr
}

func TestBackupRunErrorRequiresConfirmedRelease(t *testing.T) {
	for _, mode := range []string{"capture", "freeze", "release", "capture-and-release"} {
		t.Run(mode, func(t *testing.T) {
			events := []string{}
			manifest := testManifest()
			freeze := &outcomeFreeze{}
			failure := errors.New("sensitive dependency details")
			if mode == "freeze" {
				freeze.acquireErr = failure
			}
			if strings.Contains(mode, "release") {
				freeze.releaseErr = failure
			}
			captureErr := error(nil)
			if strings.Contains(mode, "capture") {
				captureErr = failure
			}
			orchestrator := BackupOrchestrator{Freeze: freeze, Capturers: []ComponentCapturer{
				staticCapturer{events: &events, checkpoint: manifest.Checkpoints[0], err: captureErr},
				staticCapturer{events: &events, checkpoint: manifest.Checkpoints[1]},
				staticCapturer{events: &events, checkpoint: manifest.Checkpoints[2]},
			}, Store: &recordingManifestStore{events: &events}, SigningKeyID: "run-key",
				PrivateKey: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize)), Now: func() time.Time { return manifest.CreatedAt }}
			result, err := orchestrator.Run(context.Background(), backupRequestFromManifest(manifest))
			var typed *BackupRunError
			if !errors.As(err, &typed) || typed.OutcomeUnknown != (mode != "capture") || !errors.Is(err, failure) || strings.Contains(err.Error(), "sensitive") {
				t.Fatalf("outcome: %#v %v", typed, err)
			}
			if mode != "freeze" && !freeze.released {
				t.Fatal("release not attempted")
			}
			if mode != "capture" && result.SignedManifest.PayloadSHA256 != "" {
				t.Fatal("unknown outcome exposed success")
			}
		})
	}
}

func privateRunDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}
