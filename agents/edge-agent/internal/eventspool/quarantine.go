package eventspool

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"time"
)

var quarantineNamePattern = regexp.MustCompile(`^line-[0-9a-f]{64}\.json$`)

type quarantinedLine struct {
	SchemaVersion uint16    `json:"schema_version"`
	Code          string    `json:"code"`
	Generation    uint64    `json:"generation"`
	Offset        int64     `json:"offset"`
	Bytes         int64     `json:"bytes"`
	SourceDevice  uint64    `json:"source_device"`
	SourceInode   uint64    `json:"source_inode"`
	ContentSHA256 string    `json:"content_sha256"`
	ObservedAt    time.Time `json:"observed_at"`
}

func (t *Tailer) quarantineLine(code string, source sourceIdentity, generation uint64, offset, size int64, content []byte) error {
	unlock, err := lockPrivateFile(context.Background(), t.quarantineLockPath, t.stateDevice)
	if err != nil {
		return err
	}
	defer unlock()
	contentDigest := sha256.Sum256(content)
	identityDigest := sha256.Sum256([]byte(fmt.Sprintf("%d:%d:%d:%d:%s:%x", source.device, source.inode, generation, offset, code, contentDigest)))
	record := quarantinedLine{
		SchemaVersion: SchemaVersion, Code: code, Generation: generation, Offset: offset, Bytes: size,
		SourceDevice: source.device, SourceInode: source.inode, ContentSHA256: hex.EncodeToString(contentDigest[:]),
		ObservedAt: t.config.Now().UTC(),
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return ErrCorruptState
	}
	destination := filepath.Join(t.quarantineDir, "line-"+hex.EncodeToString(identityDigest[:])+".json")
	if _, err := os.Lstat(destination); err == nil {
		return validateQuarantineFile(destination, t.stateDevice)
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrUnsafePath
	}
	used, err := quarantineBytes(t.quarantineDir, t.stateDevice)
	if err != nil {
		return err
	}
	if used+int64(len(encoded)+1) > t.config.MaxQuarantineBytes {
		return ErrQuarantineLimit
	}
	return writeStateJSON(t.quarantineDir, destination, record)
}

func quarantineBytes(directory string, device uint64) (int64, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return 0, err
	}
	var total int64
	for _, entry := range entries {
		if !quarantineNamePattern.MatchString(entry.Name()) || entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return 0, ErrCorruptState
		}
		path := filepath.Join(directory, entry.Name())
		file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return 0, ErrUnsafePath
		}
		info, statErr := file.Stat()
		stat, ok := infoSys(info)
		_ = file.Close()
		if statErr != nil || !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || stat.Nlink != 1 || uint64(stat.Dev) != device {
			return 0, ErrUnsafePath
		}
		total += info.Size()
	}
	return total, nil
}

func validateQuarantineFile(path string, device uint64) error {
	var record quarantinedLine
	exists, err := readStateJSON(path, &record, device)
	if err != nil || !exists || record.SchemaVersion != SchemaVersion || record.Code == "" || record.Generation == 0 ||
		record.Offset < 0 || record.Bytes < 0 || record.SourceDevice == 0 || record.SourceInode == 0 || len(record.ContentSHA256) != sha256.Size*2 || record.ObservedAt.IsZero() {
		return ErrCorruptState
	}
	return nil
}
