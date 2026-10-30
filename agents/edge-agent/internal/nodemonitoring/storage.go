package nodemonitoring

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	activeFileName = ".node-monitoring-active.json"
	lkgFileName    = ".node-monitoring-lkg.json"
)

func prepareStateDir(path string) error {
	if path == "" || !filepath.IsAbs(path) {
		return ErrInvalidOptions
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return fmt.Errorf("create node monitoring state directory: %w", err)
		}
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return ErrInvalidOptions
	}
	return nil
}

func loadStoredConfig(path string) (*Config, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Mode().Perm()&0o077 != 0 || info.Size() < 1 || info.Size() > maximumConfigBytes {
		return nil, ErrCorruptState
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read node monitoring state: %w", err)
	}
	config, err := decodeConfig(payload)
	if err != nil {
		return nil, ErrCorruptState
	}
	return &config, nil
}

func storeConfig(stateDir, name string, config Config) error {
	payload, err := canonicalConfig(config)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(stateDir, ".node-monitoring-*.tmp")
	if err != nil {
		return fmt.Errorf("create node monitoring state: %w", err)
	}
	temporaryPath := temporary.Name()
	ok := false
	defer func() {
		_ = temporary.Close()
		if !ok {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("protect node monitoring state: %w", err)
	}
	if _, err := temporary.Write(payload); err != nil {
		return fmt.Errorf("write node monitoring state: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync node monitoring state: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close node monitoring state: %w", err)
	}
	if err := os.Rename(temporaryPath, filepath.Join(stateDir, name)); err != nil {
		return fmt.Errorf("activate node monitoring state: %w", err)
	}
	directory, err := os.Open(stateDir)
	if err != nil {
		return fmt.Errorf("open node monitoring state directory: %w", err)
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return fmt.Errorf("sync node monitoring state directory: %w", err)
	}
	if err := directory.Close(); err != nil {
		return fmt.Errorf("close node monitoring state directory: %w", err)
	}
	ok = true
	return nil
}

func canonicalConfig(config Config) ([]byte, error) {
	payload, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("encode node monitoring state: %w", err)
	}
	return payload, nil
}
