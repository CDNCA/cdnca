package securityreleaseruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const maxStateBytes = 256 << 10

type persistedRecord struct {
	Record Record `json:"record"`
	SHA256 string `json:"sha256"`
}

type diskStore struct {
	mu        sync.Mutex
	root      string
	statePath string
	lockPath  string
}

func newDiskStore(root string) (*diskStore, error) {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root || root == string(filepath.Separator) {
		return nil, ErrInvalidConfig
	}
	if err := os.Mkdir(root, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, fmt.Errorf("create security release state: %w", err)
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return nil, ErrInvalidConfig
	}
	return &diskStore{
		root: root, statePath: filepath.Join(root, "security-release-runtime.json"),
		lockPath: filepath.Join(root, "security-release-runtime.lock"),
	}, nil
}

func (store *diskStore) withLock(ctx context.Context, operation func() error) error {
	if store == nil || ctx == nil || operation == nil {
		return ErrInvalidConfig
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	file, err := os.OpenFile(store.lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open security release lock: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return ErrCorruptState
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Nlink != 1 {
		return ErrCorruptState
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err == nil {
			defer unix.Flock(int(file.Fd()), unix.LOCK_UN) //nolint:errcheck
			return operation()
		} else if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return fmt.Errorf("lock security release state: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (store *diskStore) loadLocked() (*Record, error) {
	info, err := os.Lstat(store.statePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maxStateBytes {
		return nil, ErrCorruptState
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Nlink != 1 {
		return nil, ErrCorruptState
	}
	file, err := os.Open(store.statePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maxStateBytes+1))
	decoder.DisallowUnknownFields()
	var persisted persistedRecord
	if err := decoder.Decode(&persisted); err != nil {
		return nil, ErrCorruptState
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, ErrCorruptState
	}
	encoded, err := json.Marshal(persisted.Record)
	digest := sha256.Sum256(encoded)
	if err != nil || !validRecord(persisted.Record) || persisted.SHA256 != hex.EncodeToString(digest[:]) {
		return nil, ErrCorruptState
	}
	return &persisted.Record, nil
}

func (store *diskStore) saveLocked(record *Record) error {
	if record == nil || !validRecord(*record) {
		return ErrCorruptState
	}
	recordBytes, err := json.Marshal(record)
	if err != nil {
		return ErrCorruptState
	}
	digest := sha256.Sum256(recordBytes)
	encoded, err := json.Marshal(persistedRecord{Record: *record, SHA256: hex.EncodeToString(digest[:])})
	if err != nil || len(encoded) > maxStateBytes {
		return ErrCorruptState
	}
	temporary, err := os.CreateTemp(store.root, ".security-release-runtime-")
	if err != nil {
		return err
	}
	name := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(name)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := io.Copy(temporary, bytes.NewReader(encoded)); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, store.statePath); err != nil {
		return err
	}
	directory, err := os.Open(store.root)
	if err != nil {
		return err
	}
	err = directory.Sync()
	closeErr := directory.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	committed = true
	return nil
}
