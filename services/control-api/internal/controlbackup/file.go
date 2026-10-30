package controlbackup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const trustedFileLimit = 1 << 20

func ReadTrustedFile(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("trusted file path must be absolute")
	}
	cleaned := filepath.Clean(path)
	if cleaned != path {
		return nil, errors.New("trusted file path must be clean")
	}
	info, err := os.Lstat(cleaned)
	if errors.Is(err, os.ErrNotExist) {
		return nil, os.ErrNotExist
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() <= 0 || info.Size() > trustedFileLimit || info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("trusted file must be a bounded, non-writable regular file")
	}
	encoded, err := os.ReadFile(cleaned)
	if err != nil {
		return nil, errors.New("read trusted file")
	}
	return encoded, nil
}

func DecodeStrictJSON(encoded []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("JSON document has trailing data")
	}
	return nil
}

func DecodeEd25519PrivateKey(encoded []byte) (ed25519.PrivateKey, error) {
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("signing private key must be one PKCS8 PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("parse signing private key")
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("signing private key is not Ed25519")
	}
	return key, nil
}

func DecodeEd25519PublicKey(encoded []byte) (ed25519.PublicKey, error) {
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("signing public key must be one PKIX PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("parse signing public key")
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("signing public key is not Ed25519")
	}
	return key, nil
}

type FileManifestStore struct {
	directory string
}

func NewFileManifestStore(directory string) (*FileManifestStore, error) {
	if err := validatePrivateDirectory(directory); err != nil {
		return nil, err
	}
	return &FileManifestStore{directory: directory}, nil
}

func (store *FileManifestStore) Put(_ context.Context, signed SignedManifest) error {
	var manifest Manifest
	if err := DecodeStrictJSON(signed.Payload, &manifest); err != nil || manifest.Validate() != nil {
		return ErrInvalidManifest
	}
	return writeImmutableJSON(filepath.Join(store.directory, manifest.BackupID+".signed.json"), signed)
}

type FileReceiptStore struct {
	directory string
	mu        sync.Mutex
}

func NewFileReceiptStore(directory string) (*FileReceiptStore, error) {
	if err := validatePrivateDirectory(directory); err != nil {
		return nil, err
	}
	return &FileReceiptStore{directory: directory}, nil
}

func (store *FileReceiptStore) Get(_ context.Context, operationID string) (RestoreReceipt, bool, error) {
	if !identifierPattern.MatchString(operationID) {
		return RestoreReceipt{}, false, ErrInvalidManifest
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	encoded, err := ReadTrustedFile(filepath.Join(store.directory, operationID+".json"))
	if errors.Is(err, os.ErrNotExist) {
		return RestoreReceipt{}, false, nil
	}
	if err != nil {
		return RestoreReceipt{}, false, errors.New("read restore receipt")
	}
	var receipt RestoreReceipt
	if err := DecodeStrictJSON(encoded, &receipt); err != nil || receipt.OperationID != operationID {
		return RestoreReceipt{}, false, errors.New("invalid restore receipt")
	}
	return receipt, true, nil
}

func (store *FileReceiptStore) Put(_ context.Context, receipt RestoreReceipt) error {
	if !identifierPattern.MatchString(receipt.OperationID) {
		return ErrInvalidManifest
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	path := filepath.Join(store.directory, receipt.OperationID+".json")
	if encoded, err := os.ReadFile(path); err == nil {
		var previous RestoreReceipt
		if DecodeStrictJSON(encoded, &previous) != nil || previous.TargetID != receipt.TargetID ||
			previous.BackupID != receipt.BackupID || previous.ManifestSHA256 != receipt.ManifestSHA256 {
			return ErrIdempotencyConflict
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("read existing restore receipt")
	}
	return writeImmutableJSON(path, receipt)
}

func validatePrivateDirectory(directory string) error {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return errors.New("state directory must be an absolute clean path")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("state directory must be private and non-symlink")
	}
	return nil
}

func writeImmutableJSON(path string, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if existing, readErr := os.ReadFile(path); readErr == nil {
		if bytes.Equal(existing, encoded) {
			return nil
		}
		return ErrIdempotencyConflict
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return errors.New("read immutable state")
	}
	temporary, err := os.OpenFile(path+".tmp", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create immutable state: %w", err)
	}
	temporaryPath := temporary.Name()
	cleanup := true
	defer func() {
		_ = temporary.Close()
		if cleanup {
			_ = os.Remove(temporaryPath)
		}
	}()
	if _, err := temporary.Write(encoded); err != nil {
		return errors.New("write immutable state")
	}
	if err := temporary.Sync(); err != nil {
		return errors.New("sync immutable state")
	}
	if err := temporary.Close(); err != nil {
		return errors.New("close immutable state")
	}
	if err := os.Link(temporaryPath, path); err != nil {
		if existing, readErr := os.ReadFile(path); readErr == nil && bytes.Equal(existing, encoded) {
			return nil
		}
		return fmt.Errorf("publish immutable state: %w", err)
	}
	if err := os.Remove(temporaryPath); err != nil {
		return errors.New("remove immutable state staging")
	}
	cleanup = false
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return errors.New("open immutable state directory")
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		_ = os.Remove(path)
		_ = directory.Sync()
		return errors.New("sync immutable state directory")
	}
	return nil
}

func ValidatePlanSecretFields(encoded []byte) error {
	lowered := strings.ToLower(string(encoded))
	for _, forbidden := range []string{"secret_value", "private_key_value", "password", "token_value"} {
		if strings.Contains(lowered, `"`+forbidden+`"`) {
			return errors.New("plan contains a secret value field")
		}
	}
	return nil
}
