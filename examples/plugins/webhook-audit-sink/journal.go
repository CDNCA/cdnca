package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"
)

type recordResult uint8

const (
	recordAccepted recordResult = iota
	recordReplay
	recordConflict
)

type journalEntry struct {
	EventID    string `json:"event_id"`
	BodySHA256 string `json:"body_sha256"`
	ReceivedAt string `json:"received_at"`
}

type journal struct {
	mu           sync.Mutex
	file         *os.File
	entries      map[string]string
	writeFile    func(*os.File, []byte) (int, error)
	truncateFile func(*os.File, int64) error
	syncFile     func(*os.File) error
	poisoned     bool
}

func openJournal(path string) (*journal, error) {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, errors.New("journal must be a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect journal: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open journal: %w", err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock journal: %w", err)
	}
	if err := secureJournalFile(file); err != nil {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
		return nil, err
	}

	result := &journal{
		file: file, entries: make(map[string]string),
		writeFile:    func(file *os.File, data []byte) (int, error) { return file.Write(data) },
		truncateFile: func(file *os.File, size int64) error { return file.Truncate(size) },
		syncFile:     func(file *os.File) error { return file.Sync() },
	}
	if err := result.load(); err != nil {
		_ = result.Close()
		return nil, err
	}
	return result, nil
}

func secureJournalFile(file *os.File) error {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("journal must be a regular file")
	}
	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("secure journal permissions: %w", err)
	}
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return errors.New("journal permissions are not 0600")
	}
	return nil
}

func (j *journal) load() error {
	if _, err := j.file.Seek(0, 0); err != nil {
		return fmt.Errorf("seek journal: %w", err)
	}
	scanner := bufio.NewScanner(j.file)
	scanner.Buffer(make([]byte, 4096), 64*1024)
	for line := 1; scanner.Scan(); line++ {
		var entry journalEntry
		decoder := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		decoder.DisallowUnknownFields()
		if err := validateJSON(scanner.Bytes()); err != nil || decoder.Decode(&entry) != nil ||
			!validUUID(entry.EventID) || !validSHA256(entry.BodySHA256) {
			return fmt.Errorf("invalid journal record at line %d", line)
		}
		if _, err := time.Parse(time.RFC3339Nano, entry.ReceivedAt); err != nil {
			return fmt.Errorf("invalid journal timestamp at line %d", line)
		}
		if previous, exists := j.entries[entry.EventID]; exists && previous != entry.BodySHA256 {
			return fmt.Errorf("conflicting journal record at line %d", line)
		}
		j.entries[entry.EventID] = entry.BodySHA256
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read journal: %w", err)
	}
	_, err := j.file.Seek(0, 2)
	return err
}

func (j *journal) Record(eventID, bodySHA256 string, receivedAt time.Time) (recordResult, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.poisoned || j.file == nil {
		return recordAccepted, errors.New("journal is unavailable")
	}

	if previous, exists := j.entries[eventID]; exists {
		if previous == bodySHA256 {
			return recordReplay, nil
		}
		return recordConflict, nil
	}
	entry, err := json.Marshal(journalEntry{
		EventID: eventID, BodySHA256: bodySHA256, ReceivedAt: receivedAt.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return recordAccepted, err
	}
	entry = append(entry, '\n')
	offset, err := j.ensureAppendBoundaryLocked()
	if err != nil {
		return recordAccepted, err
	}
	written, err := j.writeFile(j.file, entry)
	if err != nil || written != len(entry) {
		return recordAccepted, j.recoverAppendLocked(offset, errors.New("append journal failed"))
	}
	if err := j.syncFile(j.file); err != nil {
		return recordAccepted, j.recoverAppendLocked(offset, fmt.Errorf("sync journal: %w", err))
	}
	j.entries[eventID] = bodySHA256
	return recordAccepted, nil
}

func (j *journal) ensureAppendBoundaryLocked() (int64, error) {
	offset, err := j.file.Seek(0, 2)
	if err != nil {
		j.poisonLocked()
		return 0, errors.New("journal offset unavailable")
	}
	if offset == 0 {
		return offset, nil
	}
	var lastByte [1]byte
	if _, err := j.file.ReadAt(lastByte[:], offset-1); err != nil {
		j.poisonLocked()
		return 0, fmt.Errorf("journal boundary unavailable: %w", err)
	}
	if lastByte[0] == '\n' {
		return offset, nil
	}
	separator := []byte{'\n'}
	written, err := j.writeFile(j.file, separator)
	if err != nil || written != len(separator) {
		return 0, j.recoverAppendLocked(offset, errors.New("journal boundary repair failed"))
	}
	if err := j.syncFile(j.file); err != nil {
		return 0, j.recoverAppendLocked(offset, fmt.Errorf("journal boundary sync failed: %w", err))
	}
	return offset + 1, nil
}

func (j *journal) recoverAppendLocked(offset int64, appendErr error) error {
	if err := j.truncateFile(j.file, offset); err != nil {
		j.poisonLocked()
		return fmt.Errorf("%w; rollback truncate failed: %v", appendErr, err)
	}
	if _, err := j.file.Seek(offset, 0); err != nil {
		j.poisonLocked()
		return fmt.Errorf("%w; rollback seek failed: %v", appendErr, err)
	}
	if err := j.syncFile(j.file); err != nil {
		j.poisonLocked()
		return fmt.Errorf("%w; rollback sync failed: %v", appendErr, err)
	}
	return appendErr
}

func (j *journal) poisonLocked() {
	j.poisoned = true
	if j.file == nil {
		return
	}
	_ = syscall.Flock(int(j.file.Fd()), syscall.LOCK_UN)
	_ = j.file.Close()
	j.file = nil
}

func (j *journal) Ready() bool {
	if j == nil {
		return false
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return !j.poisoned && j.file != nil
}

func (j *journal) Close() error {
	if j == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.file == nil {
		return nil
	}
	_ = syscall.Flock(int(j.file.Fd()), syscall.LOCK_UN)
	err := j.file.Close()
	j.file = nil
	return err
}
