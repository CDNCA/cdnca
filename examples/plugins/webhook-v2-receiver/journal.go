package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"
	"time"
)

type journalEntry struct {
	DeliveryID string `json:"delivery_id"`
	EventID    string `json:"event_id"`
	BodySHA256 string `json:"body_sha256"`
	ReceivedAt string `json:"received_at"`
	// Site is the business change of a site event, written once: on the
	// first delivery of that event ID. Replays only add a delivery line.
	Site *siteChange `json:"site,omitempty"`
}

type journal struct {
	mu         sync.Mutex
	path       string
	file       *os.File
	deliveries map[string]string
	events     map[string]string
	write      func(*os.File, []byte) (int, error)
	sync       func(*os.File) error
	truncate   func(*os.File, int64) error
	poisoned   bool
}

func openJournal(path string) (*journal, error) {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, errors.New("journal must be a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := secureJournal(file); err != nil {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
		return nil, err
	}
	result := &journal{path: path, file: file, deliveries: map[string]string{}, events: map[string]string{},
		write:    func(file *os.File, data []byte) (int, error) { return file.Write(data) },
		sync:     func(file *os.File) error { return file.Sync() },
		truncate: func(file *os.File, size int64) error { return file.Truncate(size) }}
	if err := result.load(); err != nil {
		_ = result.Close()
		return nil, err
	}
	return result, nil
}

func secureJournal(file *os.File) error {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || file.Chmod(0o600) != nil {
		return errors.New("journal must be a regular 0600 file")
	}
	info, err = file.Stat()
	if err != nil || info.Mode().Perm() != 0o600 {
		return errors.New("journal permissions are not 0600")
	}
	return nil
}

func (j *journal) load() error {
	if _, err := j.file.Seek(0, 0); err != nil {
		return err
	}
	scanner := bufio.NewScanner(j.file)
	scanner.Buffer(make([]byte, 4096), 64*1024)
	for line := 1; scanner.Scan(); line++ {
		var entry journalEntry
		decoder := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&entry) != nil || decoder.Decode(&struct{}{}) != io.EOF || !validUUID(entry.DeliveryID) || !validUUID(entry.EventID) || !hexDigestPattern.MatchString(entry.BodySHA256) {
			return fmt.Errorf("invalid journal record at line %d", line)
		}
		if _, err := time.Parse(time.RFC3339Nano, entry.ReceivedAt); err != nil {
			return fmt.Errorf("invalid journal timestamp at line %d", line)
		}
		if entry.Site != nil && (!validUUID(entry.Site.SiteID) || !siteChanges[entry.Site.Change] || entry.Site.SubjectSequence == 0) {
			return fmt.Errorf("invalid site record at line %d", line)
		}
		if previous, exists := j.deliveries[entry.DeliveryID]; exists && previous != entry.BodySHA256 {
			return fmt.Errorf("conflicting delivery record at line %d", line)
		}
		if previous, exists := j.events[entry.EventID]; exists && previous != entry.BodySHA256 {
			return fmt.Errorf("conflicting event record at line %d", line)
		}
		j.deliveries[entry.DeliveryID] = entry.BodySHA256
		j.events[entry.EventID] = entry.BodySHA256
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	_, err := j.file.Seek(0, 2)
	return err
}

func (j *journal) Record(deliveryID, eventID, digest string, receivedAt time.Time, site *siteChange) (recordResult, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.poisoned || j.file == nil {
		return recordAccepted, errors.New("journal unavailable")
	}
	if previous, exists := j.deliveries[deliveryID]; exists {
		if previous == digest {
			return recordReplay, nil
		}
		return recordConflict, nil
	}
	previous, processed := j.events[eventID]
	if processed && previous != digest {
		return recordConflict, nil
	}
	record := journalEntry{DeliveryID: deliveryID, EventID: eventID, BodySHA256: digest, ReceivedAt: receivedAt.UTC().Format(time.RFC3339Nano)}
	if !processed {
		record.Site = site
	}
	entry, err := json.Marshal(record)
	if err != nil {
		return recordAccepted, err
	}
	entry = append(entry, '\n')
	offset, err := j.file.Seek(0, 2)
	if err != nil {
		j.poisonLocked()
		return recordAccepted, err
	}
	written, err := j.write(j.file, entry)
	if err != nil || written != len(entry) {
		return recordAccepted, j.rollbackLocked(offset, errors.New("journal append failed"))
	}
	if err := j.sync(j.file); err != nil {
		return recordAccepted, j.rollbackLocked(offset, err)
	}
	j.deliveries[deliveryID] = digest
	j.events[eventID] = digest
	if processed && site != nil {
		return recordEventDuplicate, nil
	}
	return recordAccepted, nil
}

func (j *journal) rollbackLocked(offset int64, cause error) error {
	if err := j.truncate(j.file, offset); err != nil {
		j.poisonLocked()
		return fmt.Errorf("%w: rollback failed: %v", cause, err)
	}
	if _, err := j.file.Seek(offset, 0); err != nil {
		j.poisonLocked()
		return fmt.Errorf("%w: rollback seek failed: %v", cause, err)
	}
	if err := j.sync(j.file); err != nil {
		j.poisonLocked()
		return fmt.Errorf("%w: rollback sync failed: %v", cause, err)
	}
	return cause
}

func (j *journal) poisonLocked() {
	j.poisoned = true
	if j.file != nil {
		_ = syscall.Flock(int(j.file.Fd()), syscall.LOCK_UN)
		_ = j.file.Close()
		j.file = nil
	}
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
