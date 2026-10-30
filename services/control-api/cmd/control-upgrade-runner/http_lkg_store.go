//go:build !windows

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/cdnca/cdnca/services/control-api/internal/controlplaneupgrade"
	"github.com/google/uuid"
)

const httpLKGSchema = "cdnca.control-upgrade-http-lkg/v1"

var (
	ErrHTTPLKGNotFound    = errors.New("control upgrade HTTP LKG not found")
	ErrHTTPLKGInvalid     = errors.New("control upgrade HTTP LKG is invalid")
	ErrHTTPLKGConflict    = errors.New("control upgrade HTTP LKG revision conflict")
	ErrHTTPLKGUnavailable = errors.New("control upgrade HTTP LKG is unavailable")
)

type httpLKGEnvelope struct {
	Schema         string `json:"schema"`
	InstallationID string `json:"installation_id"`
	Operation      string `json:"operation"`
	ETag           string `json:"etag"`
	Revision       uint64 `json:"revision"`
	Digest         string `json:"digest"`
	Bundle         []byte `json:"bundle"`
}

type HTTPLKGStore struct {
	path           string
	parent         string
	installationID string
	operation      string
	maxBodyBytes   int64
	maxFileBytes   int64
}

func NewHTTPLKGStore(path, installationID, operation string, maxBodyBytes int64) (*HTTPLKGStore, error) {
	parsed, err := uuid.Parse(installationID)
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) == "." ||
		err != nil || parsed == uuid.Nil || parsed.String() != installationID ||
		operation != controlplaneupgrade.SystemdControlUpgradeOperation || maxBodyBytes < 1 || maxBodyBytes > 2<<20 {
		return nil, ErrHTTPLKGInvalid
	}
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	stat, ok := lkgStat(info)
	if err != nil || !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 ||
		stat.Uid != uint32(os.Geteuid()) {
		return nil, ErrHTTPLKGInvalid
	}
	return &HTTPLKGStore{path: path, parent: parent, installationID: installationID, operation: operation,
		maxBodyBytes: maxBodyBytes, maxFileBytes: maxBodyBytes*2 + 4096}, nil
}

func (store *HTTPLKGStore) Load() (HTTPPlan, error) {
	info, err := os.Lstat(store.path)
	if errors.Is(err, os.ErrNotExist) {
		return HTTPPlan{}, ErrHTTPLKGNotFound
	}
	stat, ok := lkgStat(info)
	if err != nil || !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o600 || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) ||
		info.Size() < 1 || info.Size() > store.maxFileBytes {
		return HTTPPlan{}, ErrHTTPLKGInvalid
	}
	encoded, err := readStableRegularFile(store.path, info, store.maxFileBytes)
	if err != nil {
		return HTTPPlan{}, ErrHTTPLKGInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var envelope httpLKGEnvelope
	if decoder.Decode(&envelope) != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		envelope.Schema != httpLKGSchema || envelope.InstallationID != store.installationID ||
		envelope.Operation != store.operation {
		return HTTPPlan{}, ErrHTTPLKGInvalid
	}
	canonical, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return HTTPPlan{}, ErrHTTPLKGInvalid
	}
	plan := HTTPPlan{Bundle: envelope.Bundle, ETag: envelope.ETag, Revision: envelope.Revision,
		Digest: envelope.Digest, Replayed: true}
	if validateHTTPPlan(plan, store.maxBodyBytes) != nil {
		return HTTPPlan{}, ErrHTTPLKGInvalid
	}
	return cloneHTTPPlan(plan), nil
}

func (store *HTTPLKGStore) Save(plan HTTPPlan) error {
	if validateHTTPPlan(plan, store.maxBodyBytes) != nil {
		return ErrHTTPLKGInvalid
	}
	current, err := store.Load()
	switch {
	case err == nil && plan.Revision < current.Revision:
		return ErrHTTPLKGConflict
	case err == nil && plan.Revision == current.Revision && !sameHTTPPlan(plan, current):
		return ErrHTTPLKGConflict
	case err == nil && plan.Revision == current.Revision:
		return nil
	case errors.Is(err, ErrHTTPLKGNotFound):
	case err != nil:
		return err
	}
	envelope := httpLKGEnvelope{Schema: httpLKGSchema, InstallationID: store.installationID,
		Operation: store.operation, ETag: plan.ETag, Revision: plan.Revision, Digest: plan.Digest,
		Bundle: append([]byte(nil), plan.Bundle...)}
	encoded, err := json.Marshal(envelope)
	if err != nil || int64(len(encoded)) > store.maxFileBytes {
		return ErrHTTPLKGInvalid
	}
	temporary, err := os.CreateTemp(store.parent, ".plan-lkg-*.tmp")
	if err != nil {
		return ErrHTTPLKGUnavailable
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return ErrHTTPLKGUnavailable
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return ErrHTTPLKGUnavailable
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return ErrHTTPLKGUnavailable
	}
	if err := temporary.Close(); err != nil {
		return ErrHTTPLKGUnavailable
	}
	if err := os.Rename(temporaryPath, store.path); err != nil {
		return ErrHTTPLKGUnavailable
	}
	directory, err := os.Open(store.parent)
	if err != nil {
		return ErrHTTPLKGUnavailable
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return ErrHTTPLKGUnavailable
	}
	return nil
}

func validateHTTPPlan(plan HTTPPlan, maximum int64) error {
	revision, digest, err := parseHTTPPlanETag(plan.ETag)
	actual := sha256.Sum256(plan.Bundle)
	if err != nil || len(plan.Bundle) == 0 || int64(len(plan.Bundle)) > maximum || revision != plan.Revision ||
		digest != plan.Digest || fmt.Sprintf("%x", actual) != plan.Digest {
		return ErrHTTPLKGInvalid
	}
	return nil
}

func sameHTTPPlan(left, right HTTPPlan) bool {
	return left.ETag == right.ETag && left.Revision == right.Revision && left.Digest == right.Digest &&
		bytes.Equal(left.Bundle, right.Bundle)
}

func lkgStat(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return stat, ok
}
