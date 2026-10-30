package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testEventID = "019b143c-7e64-7cc6-b886-a1354a006281"
	testDigest  = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func TestJournalPersistsReplayConflictAndExclusiveLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	first, err := openJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openJournal(path); err == nil {
		t.Fatal("second writer acquired journal lock")
	}
	now := time.Date(2026, 7, 23, 1, 2, 3, 0, time.UTC)
	if result, err := first.Record(testEventID, testDigest, now); err != nil || result != recordAccepted {
		t.Fatalf("first record = %d, %v", result, err)
	}
	if result, err := first.Record(testEventID, testDigest, now); err != nil || result != recordReplay {
		t.Fatalf("replay = %d, %v", result, err)
	}
	conflicting := "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if result, err := first.Record(testEventID, conflicting, now); err != nil || result != recordConflict {
		t.Fatalf("conflict = %d, %v", result, err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	restarted, err := openJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	if result, err := restarted.Record(testEventID, testDigest, now); err != nil || result != recordReplay {
		t.Fatalf("restart replay = %d, %v", result, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("journal mode = %o", info.Mode().Perm())
	}
}

func TestJournalConcurrentSingleWinner(t *testing.T) {
	journal, err := openJournal(filepath.Join(t.TempDir(), "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	var accepted atomic.Int64
	var replayed atomic.Int64
	var wait sync.WaitGroup
	for range 64 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, recordErr := journal.Record(testEventID, testDigest, time.Now())
			if recordErr != nil {
				t.Errorf("record: %v", recordErr)
				return
			}
			if result == recordAccepted {
				accepted.Add(1)
			} else if result == recordReplay {
				replayed.Add(1)
			}
		}()
	}
	wait.Wait()
	if accepted.Load() != 1 || replayed.Load() != 63 {
		t.Fatalf("accepted=%d replayed=%d", accepted.Load(), replayed.Load())
	}
}

func TestJournalDoesNotAcknowledgeBeforeFsync(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	journal, err := openJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	syncCalls := 0
	journal.syncFile = func(file *os.File) error {
		syncCalls++
		if syncCalls == 1 {
			return errors.New("injected fsync failure")
		}
		return file.Sync()
	}
	if _, err := journal.Record(testEventID, testDigest, time.Now()); err == nil {
		t.Fatal("fsync failure was acknowledged")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Fatalf("failed append was not rolled back: size=%d", info.Size())
	}
	if result, err := journal.Record(testEventID, testDigest, time.Now()); err != nil || result != recordAccepted {
		t.Fatalf("retry after fsync failure = %d, %v", result, err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := openJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if result, err := restarted.Record(testEventID, testDigest, time.Now()); err != nil || result != recordReplay {
		t.Fatalf("restart after fsync failure = %d, %v", result, err)
	}
}

func TestJournalShortWriteRollsBackBeforeRetry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	journal, err := openJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	writeCalls := 0
	journal.writeFile = func(file *os.File, data []byte) (int, error) {
		writeCalls++
		if writeCalls == 1 {
			return file.Write(data[:len(data)/2])
		}
		return file.Write(data)
	}
	if _, err := journal.Record(testEventID, testDigest, time.Now()); err == nil {
		t.Fatal("short write was acknowledged")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Fatalf("short write tail remained: size=%d", info.Size())
	}
	if result, err := journal.Record(testEventID, testDigest, time.Now()); err != nil || result != recordAccepted {
		t.Fatalf("retry after short write = %d, %v", result, err)
	}
}

func TestJournalRollbackFailurePermanentlyPoisonsWriter(t *testing.T) {
	tests := []struct {
		name   string
		inject func(*journal)
	}{
		{name: "truncate", inject: func(journal *journal) {
			journal.writeFile = func(file *os.File, data []byte) (int, error) { return file.Write(data[:len(data)/2]) }
			journal.truncateFile = func(*os.File, int64) error { return errors.New("injected truncate failure") }
		}},
		{name: "rollback sync", inject: func(journal *journal) {
			journal.syncFile = func(*os.File) error { return errors.New("injected sync failure") }
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			journal, err := openJournal(filepath.Join(t.TempDir(), "events.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			test.inject(journal)
			if _, err := journal.Record(testEventID, testDigest, time.Now()); err == nil {
				t.Fatal("rollback failure was acknowledged")
			}
			if !journal.poisoned || journal.file != nil {
				t.Fatal("rollback failure did not poison and close journal")
			}
			if _, err := journal.Record(testEventID, testDigest, time.Now()); err == nil {
				t.Fatal("poisoned journal accepted a later request")
			}
		})
	}
}

func TestOpenJournalSecuresPermissionsAndRejectsUnsafeFiles(t *testing.T) {
	t.Run("existing wide permissions", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "events.jsonl")
		if err := os.WriteFile(path, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		journal, err := openJournal(path)
		if err != nil {
			t.Fatal(err)
		}
		defer journal.Close()
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("journal permissions = %v", info.Mode().Perm())
		}
	})

	t.Run("symlink", func(t *testing.T) {
		directory := t.TempDir()
		target := filepath.Join(directory, "target")
		if err := os.WriteFile(target, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(directory, "journal")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := openJournal(link); err == nil {
			t.Fatal("journal symlink was accepted")
		}
	})

	t.Run("non regular", func(t *testing.T) {
		if _, err := openJournal(t.TempDir()); err == nil {
			t.Fatal("journal directory was accepted")
		}
	})
}

func TestOpenJournalFailsClosedOnPartialTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	valid, err := json.Marshal(journalEntry{EventID: testEventID, BodySHA256: testDigest, ReceivedAt: time.Now().UTC().Format(time.RFC3339Nano)})
	if err != nil {
		t.Fatal(err)
	}
	content := append(append(valid, '\n'), []byte(`{"event_id":`)...)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openJournal(path); err == nil {
		t.Fatal("partial journal tail was accepted")
	}
}

func TestJournalRepairsValidNoNewlineBeforeAppendAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	first, err := json.Marshal(journalEntry{
		EventID: testEventID, BodySHA256: testDigest, ReceivedAt: time.Now().UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, first, 0o600); err != nil {
		t.Fatal(err)
	}
	journal, err := openJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	secondID := "019b143c-7e64-7cc6-b886-a1354a006296"
	secondDigest := "2123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if result, err := journal.Record(secondID, secondDigest, time.Now()); err != nil || result != recordAccepted {
		t.Fatalf("append after no-newline record = %d, %v", result, err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(content, append(first, '\n')) {
		t.Fatal("valid no-newline record was not separated before append")
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := openJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if result, err := restarted.Record(testEventID, testDigest, time.Now()); err != nil || result != recordReplay {
		t.Fatalf("first record after restart = %d, %v", result, err)
	}
	if result, err := restarted.Record(secondID, secondDigest, time.Now()); err != nil || result != recordReplay {
		t.Fatalf("second record after restart = %d, %v", result, err)
	}
}
