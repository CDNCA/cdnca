package analyticsgeo

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const MaximumTrustedAuthorityKeys = 8

var (
	ErrSignedFileConfiguration = errors.New("analytics geo signed file configuration invalid")
	ErrSignedFileTrigger       = errors.New("analytics geo signed file trigger invalid")
	ErrSignedFileSecurity      = errors.New("analytics geo signed file security invalid")
	ErrSignedFileCapacity      = errors.New("analytics geo signed file capacity exceeded")
	ErrSignedFileDigest        = errors.New("analytics geo signed file digest invalid")
	ErrSignedFileDecode        = errors.New("analytics geo signed file decode invalid")
	ErrSignedFileUntrustedKey  = errors.New("analytics geo signed file key is untrusted")
)

const (
	AuthorityReasonFileRejected     AuthorityReason = "file_rejected"
	AuthorityReasonArtifactRejected AuthorityReason = "artifact_rejected"
	AuthorityReasonUntrustedKey     AuthorityReason = "untrusted_key"
)

type TrustedEd25519Keyring struct {
	keys map[string]ed25519.PublicKey
}

type SignedCatalogArtifact struct {
	DataBase64     string `json:"data_base64"`
	ExpectedSHA256 string `json:"expected_sha256"`
}

type SignedAuthorityArtifact struct {
	SchemaVersion         string                  `json:"schema_version"`
	Revision              uint64                  `json:"revision"`
	KeyID                 string                  `json:"key_id"`
	CurrentCatalogVersion string                  `json:"current_catalog_version"`
	ExpiresAt             string                  `json:"expires_at"`
	Catalogs              []SignedCatalogArtifact `json:"catalogs"`
	SignatureBase64       string                  `json:"signature_base64"`
}

type FileTrigger struct {
	Path           string
	ExpectedSHA256 string
}

type SignedFileLoaderConfig struct {
	Keyring                  TrustedEd25519Keyring
	Now                      func() time.Time
	MaxArtifactBytes         int64
	MaxAggregateCatalogBytes int
}

type SignedFileLoader struct {
	pollMu                   sync.Mutex
	stateMu                  sync.RWMutex
	keyring                  TrustedEd25519Keyring
	now                      func() time.Time
	maxArtifactBytes         int64
	maxAggregateCatalogBytes int
	authority                *Authority
	lastArtifactSHA256       string
}

func NewTrustedEd25519Keyring(keys map[string]ed25519.PublicKey) (TrustedEd25519Keyring, error) {
	if len(keys) == 0 || len(keys) > MaximumTrustedAuthorityKeys {
		return TrustedEd25519Keyring{}, ErrSignedFileConfiguration
	}
	cloned := make(map[string]ed25519.PublicKey, len(keys))
	for keyID, publicKey := range keys {
		if !validVersion(keyID) || len(publicKey) != ed25519.PublicKeySize {
			return TrustedEd25519Keyring{}, ErrSignedFileConfiguration
		}
		cloned[keyID] = bytes.Clone(publicKey)
	}
	return TrustedEd25519Keyring{keys: cloned}, nil
}

func NewSignedFileLoader(config SignedFileLoaderConfig) (*SignedFileLoader, error) {
	if len(config.Keyring.keys) == 0 || len(config.Keyring.keys) > MaximumTrustedAuthorityKeys || config.Now == nil ||
		config.MaxArtifactBytes <= 0 || config.MaxAggregateCatalogBytes <= 0 ||
		config.MaxAggregateCatalogBytes > maximumCatalogDocuments*maximumCatalogBytes {
		return nil, ErrSignedFileConfiguration
	}
	keys := make(map[string]ed25519.PublicKey, len(config.Keyring.keys))
	for keyID, publicKey := range config.Keyring.keys {
		if !validVersion(keyID) || len(publicKey) != ed25519.PublicKeySize {
			return nil, ErrSignedFileConfiguration
		}
		keys[keyID] = bytes.Clone(publicKey)
	}
	return &SignedFileLoader{
		keyring: TrustedEd25519Keyring{keys: keys}, now: config.Now,
		maxArtifactBytes: config.MaxArtifactBytes, maxAggregateCatalogBytes: config.MaxAggregateCatalogBytes,
	}, nil
}

func (loader *SignedFileLoader) Poll(ctx context.Context, trigger FileTrigger) error {
	if loader == nil || ctx == nil {
		return ErrSignedFileConfiguration
	}
	loader.pollMu.Lock()
	defer loader.pollMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validFileTrigger(trigger) {
		loader.rejectCurrent(AuthorityReasonFileRejected)
		return ErrSignedFileTrigger
	}
	data, err := readSecureArtifact(ctx, trigger.Path, loader.maxArtifactBytes)
	if err != nil {
		loader.rejectCurrent(AuthorityReasonFileRejected)
		return err
	}
	actualDigest := sha256.Sum256(data)
	actualHex := hex.EncodeToString(actualDigest[:])
	expected, decodeErr := hex.DecodeString(trigger.ExpectedSHA256)
	if decodeErr != nil || subtle.ConstantTimeCompare(expected, actualDigest[:]) != 1 {
		loader.rejectCurrent(AuthorityReasonFileRejected)
		return ErrSignedFileDigest
	}
	loader.stateMu.RLock()
	duplicate := loader.authority != nil && loader.lastArtifactSHA256 == actualHex
	loader.stateMu.RUnlock()
	if duplicate {
		return nil
	}

	snapshot, err := decodeSignedAuthorityArtifact(data, loader.maxAggregateCatalogBytes)
	if err != nil {
		loader.rejectCurrent(AuthorityReasonArtifactRejected)
		return err
	}
	publicKey, trusted := loader.keyring.keys[snapshot.KeyID]
	if !trusted {
		loader.rejectCurrent(AuthorityReasonUntrustedKey)
		return ErrSignedFileUntrustedKey
	}
	current := loader.currentAuthority()
	if current != nil {
		current.mu.RLock()
		currentRevision := current.revision
		current.mu.RUnlock()
		if snapshot.Revision <= currentRevision {
			current.rememberRejection(AuthorityReasonRevisionRejected)
			return ErrAuthorityRevision
		}
	}
	candidate, err := NewAuthority(AuthorityConfig{
		KeyID: snapshot.KeyID, PublicKey: publicKey, Now: loader.now,
		MaxAggregateBytes: loader.maxAggregateCatalogBytes,
	})
	if err != nil {
		loader.rejectCurrent(AuthorityReasonArtifactRejected)
		return err
	}
	if err := candidate.Reload(ctx, snapshot); err != nil {
		loader.rejectCurrent(authorityReasonForError(err))
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	loader.stateMu.Lock()
	loader.authority = candidate
	loader.lastArtifactSHA256 = actualHex
	loader.stateMu.Unlock()
	return nil
}

func (loader *SignedFileLoader) Lookup(ctx context.Context, version string, address netip.Addr) (AuthorityLookup, error) {
	authority := loader.currentAuthority()
	if authority == nil {
		return AuthorityLookup{}, ErrAuthorityUnavailable
	}
	return authority.Lookup(ctx, version, address)
}

func (loader *SignedFileLoader) currentAuthority() *Authority {
	if loader == nil {
		return nil
	}
	loader.stateMu.RLock()
	defer loader.stateMu.RUnlock()
	return loader.authority
}

func (loader *SignedFileLoader) rejectCurrent(reason AuthorityReason) {
	if authority := loader.currentAuthority(); authority != nil {
		authority.rememberRejection(reason)
	}
}

func validFileTrigger(trigger FileTrigger) bool {
	return filepath.IsAbs(trigger.Path) && filepath.Clean(trigger.Path) == trigger.Path &&
		len(trigger.ExpectedSHA256) == sha256.Size*2 && trigger.ExpectedSHA256 == strings.ToLower(trigger.ExpectedSHA256)
}

func readSecureArtifact(ctx context.Context, path string, maximum int64) ([]byte, error) {
	if err := rejectSymlinkComponents(path); err != nil {
		return nil, err
	}
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrSignedFileSecurity
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		unix.Close(descriptor)
		return nil, ErrSignedFileSecurity
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0o400 && before.Mode().Perm() != 0o600 {
		return nil, ErrSignedFileSecurity
	}
	if before.Size() <= 0 || before.Size() > maximum {
		return nil, ErrSignedFileCapacity
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, ErrSignedFileSecurity
	}
	if int64(len(data)) > maximum {
		return nil, ErrSignedFileCapacity
	}
	after, statErr := file.Stat()
	pathInfo, pathErr := os.Lstat(path)
	if statErr != nil || pathErr != nil || pathInfo.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(before, after) || !os.SameFile(before, pathInfo) {
		return nil, ErrSignedFileSecurity
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return data, nil
}

func rejectSymlinkComponents(path string) error {
	current := string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimPrefix(path, current), current) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			return ErrSignedFileTrigger
		}
		if err != nil {
			return ErrSignedFileSecurity
		}
		if info.Mode()&os.ModeSymlink != 0 {
			// macOS exposes system-owned /var and /tmp as root-level aliases.
			if filepath.Dir(current) != string(filepath.Separator) {
				return ErrSignedFileSecurity
			}
			target, err := os.Stat(current)
			if err != nil || !target.IsDir() {
				return ErrSignedFileSecurity
			}
		}
	}
	return nil
}

func decodeSignedAuthorityArtifact(data []byte, maximumCatalogBytes int) (SignedAuthoritySnapshot, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var artifact SignedAuthorityArtifact
	if decoder.Decode(&artifact) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return SignedAuthoritySnapshot{}, ErrSignedFileDecode
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, artifact.ExpiresAt)
	if err != nil {
		return SignedAuthoritySnapshot{}, ErrSignedFileDecode
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(artifact.SignatureBase64)
	if err != nil {
		return SignedAuthoritySnapshot{}, ErrSignedFileDecode
	}
	catalogs := make([]CatalogInput, len(artifact.Catalogs))
	totalBytes := 0
	for index, encoded := range artifact.Catalogs {
		data, err := base64.StdEncoding.Strict().DecodeString(encoded.DataBase64)
		if err != nil {
			return SignedAuthoritySnapshot{}, ErrSignedFileDecode
		}
		if len(data) > maximumCatalogBytes-totalBytes {
			return SignedAuthoritySnapshot{}, ErrAuthorityCapacity
		}
		totalBytes += len(data)
		catalogs[index] = CatalogInput{Data: data, ExpectedSHA256: encoded.ExpectedSHA256}
	}
	return SignedAuthoritySnapshot{
		SchemaVersion: artifact.SchemaVersion, Revision: artifact.Revision, KeyID: artifact.KeyID,
		CurrentCatalogVersion: artifact.CurrentCatalogVersion, ExpiresAt: expiresAt,
		Catalogs: catalogs, Signature: signature,
	}, nil
}

func authorityReasonForError(err error) AuthorityReason {
	switch {
	case errors.Is(err, ErrAuthoritySignature):
		return AuthorityReasonSignatureRejected
	case errors.Is(err, ErrAuthorityRevision):
		return AuthorityReasonRevisionRejected
	case errors.Is(err, ErrAuthorityExpired):
		return AuthorityReasonCandidateExpired
	case errors.Is(err, ErrAuthorityCapacity):
		return AuthorityReasonCapacityRejected
	default:
		return AuthorityReasonSnapshotRejected
	}
}
