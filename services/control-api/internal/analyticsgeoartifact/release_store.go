package analyticsgeoartifact

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticsgeo"
	"golang.org/x/sys/unix"
)

const (
	releaseArtifactsDirectory = "artifacts"
	releaseFactsDirectory     = "releases"
	releaseStateFilename      = "state.json"
	maximumReleaseFactBytes   = 16 << 10
	maximumReleaseStateBytes  = 32 << 10
)

var (
	ErrReleaseStoreConfiguration = errors.New("analytics geo release store configuration invalid")
	ErrReleaseStoreSecurity      = errors.New("analytics geo release store security invalid")
	ErrReleaseStoreIO            = errors.New("analytics geo release store IO failed")
	ErrReleaseStoreIntegrity     = errors.New("analytics geo release store integrity invalid")
	ErrReleaseStoreUnavailable   = errors.New("analytics geo release store unavailable")
)

type SourceRef struct {
	Provider string `json:"provider"`
	Version  string `json:"version"`
	SHA256   string `json:"sha256"`
}

type ReleaseRequest struct {
	ReleaseID  string
	Artifact   CompiledArtifact
	Source     SourceRef
	RollbackOf string
}

type ReleaseFact struct {
	ReleaseID            string    `json:"release_id"`
	Revision             uint64    `json:"revision"`
	Source               SourceRef `json:"source"`
	KeyID                string    `json:"key_id"`
	CatalogVersion       string    `json:"catalog_version"`
	CurrentCatalogSHA256 string    `json:"current_catalog_sha256"`
	ArtifactSHA256       string    `json:"artifact_sha256"`
	ContentSHA256        string    `json:"content_sha256"`
	SignatureSHA256      string    `json:"signature_sha256"`
	IssuedAt             time.Time `json:"issued_at"`
	ExpiresAt            time.Time `json:"expires_at"`
	CreatedAt            time.Time `json:"created_at"`
	RollbackOf           string    `json:"rollback_of,omitempty"`
}

type ReleaseState struct {
	Active ReleaseFact  `json:"active"`
	LKG    *ReleaseFact `json:"lkg,omitempty"`
}

type ReleaseStoreConfig struct {
	Directory        string
	MaxArtifactBytes int64
	Now              func() time.Time
	TrustedKeys      map[string]ed25519.PublicKey
}

type ReleaseStore struct {
	mu               sync.Mutex
	directory        string
	maxArtifactBytes int64
	now              func() time.Time
	trustedKeys      map[string]ed25519.PublicKey
}

type PreparedRelease struct {
	store   *ReleaseStore
	fact    ReleaseFact
	trigger analyticsgeo.FileTrigger
}

type releaseArtifactIdentity struct {
	revision             uint64
	keyID                string
	catalogVersion       string
	currentCatalogSHA256 string
	artifactSHA256       string
	contentSHA256        string
	signatureSHA256      string
	issuedAt             time.Time
	expiresAt            time.Time
}

type releaseContentCatalog struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

type releaseContentIdentity struct {
	CurrentCatalogVersion string                  `json:"current_catalog_version"`
	Catalogs              []releaseContentCatalog `json:"catalogs"`
}

func NewReleaseStore(config ReleaseStoreConfig) (*ReleaseStore, error) {
	if !filepath.IsAbs(config.Directory) || filepath.Clean(config.Directory) != config.Directory ||
		config.MaxArtifactBytes <= 0 || config.MaxArtifactBytes > maximumArtifactBytes || config.Now == nil ||
		len(config.TrustedKeys) == 0 || len(config.TrustedKeys) > analyticsgeo.MaximumTrustedAuthorityKeys {
		return nil, ErrReleaseStoreConfiguration
	}
	keys := make(map[string]ed25519.PublicKey, len(config.TrustedKeys))
	for keyID, publicKey := range config.TrustedKeys {
		if !validVersion(keyID) || len(publicKey) != ed25519.PublicKeySize {
			return nil, ErrReleaseStoreConfiguration
		}
		keys[keyID] = bytes.Clone(publicKey)
	}
	directory, err := openPublisherDirectory(config.Directory)
	if err != nil {
		return nil, ErrReleaseStoreSecurity
	}
	defer directory.Close()
	unlock, err := lockPublisherDirectory(directory)
	if err != nil {
		return nil, err
	}
	defer unlock()
	for _, name := range []string{releaseArtifactsDirectory, releaseFactsDirectory} {
		subdirectory, err := ensureReleaseSubdirectory(directory, name)
		if err != nil {
			return nil, err
		}
		subdirectory.Close()
	}
	return &ReleaseStore{
		directory: config.Directory, maxArtifactBytes: config.MaxArtifactBytes,
		now: config.Now, trustedKeys: keys,
	}, nil
}

func (store *ReleaseStore) Prepare(ctx context.Context, request ReleaseRequest) (PreparedRelease, error) {
	if store == nil || ctx == nil {
		return PreparedRelease{}, ErrReleaseStoreConfiguration
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return PreparedRelease{}, err
	}
	createdAt := store.now()
	if !canonicalTime(createdAt) || !validReleaseRequestIdentity(request) {
		return PreparedRelease{}, ErrInvalidRequest
	}
	identity, err := store.inspectArtifact(request.Artifact.Bytes)
	if err != nil {
		return PreparedRelease{}, err
	}
	if request.Artifact.Revision != identity.revision ||
		!request.Artifact.IssuedAt.Equal(identity.issuedAt) || !request.Artifact.ExpiresAt.Equal(identity.expiresAt) ||
		request.Artifact.SHA256 != identity.artifactSHA256 {
		return PreparedRelease{}, ErrArtifactIntegrity
	}
	fact := ReleaseFact{
		ReleaseID: request.ReleaseID, Revision: identity.revision, Source: request.Source,
		KeyID: identity.keyID, CatalogVersion: identity.catalogVersion,
		CurrentCatalogSHA256: identity.currentCatalogSHA256, ArtifactSHA256: identity.artifactSHA256,
		ContentSHA256: identity.contentSHA256, SignatureSHA256: identity.signatureSHA256,
		IssuedAt: identity.issuedAt, ExpiresAt: identity.expiresAt, CreatedAt: createdAt, RollbackOf: request.RollbackOf,
	}
	directory, unlock, err := store.openLockedDirectory()
	if err != nil {
		return PreparedRelease{}, err
	}
	defer directory.Close()
	defer unlock()

	releases, err := openReleaseSubdirectory(directory, releaseFactsDirectory)
	if err != nil {
		return PreparedRelease{}, err
	}
	defer releases.Close()
	if existing, exists, readErr := store.readReleaseFact(releases, request.ReleaseID); readErr != nil {
		return PreparedRelease{}, readErr
	} else if exists {
		if !sameReleaseIdentity(existing, fact) {
			return PreparedRelease{}, ErrRevisionConflict
		}
		fact = existing
		if err := store.validateReleaseFact(directory, fact); err != nil {
			return PreparedRelease{}, err
		}
		return store.prepared(fact), nil
	}

	artifacts, err := openReleaseSubdirectory(directory, releaseArtifactsDirectory)
	if err != nil {
		return PreparedRelease{}, err
	}
	defer artifacts.Close()
	artifactFilename := releaseArtifactFilename(fact.ArtifactSHA256)
	if existing, exists, readErr := readReleaseFile(artifacts, artifactFilename, store.maxArtifactBytes); readErr != nil {
		return PreparedRelease{}, readErr
	} else if exists {
		if !bytes.Equal(existing, request.Artifact.Bytes) {
			return PreparedRelease{}, ErrReleaseStoreIntegrity
		}
	} else if err := writeImmutableReleaseFile(ctx, artifacts, artifactFilename, request.Artifact.Bytes); err != nil {
		return PreparedRelease{}, err
	}
	factData, err := json.Marshal(fact)
	if err != nil {
		return PreparedRelease{}, ErrReleaseStoreIntegrity
	}
	if err := writeImmutableReleaseFile(ctx, releases, releaseFactFilename(fact.ReleaseID), factData); err != nil {
		return PreparedRelease{}, err
	}
	return store.prepared(fact), nil
}

func (candidate PreparedRelease) Fact() ReleaseFact {
	return candidate.fact
}

func (candidate PreparedRelease) Trigger() analyticsgeo.FileTrigger {
	return candidate.trigger
}

func (store *ReleaseStore) Commit(ctx context.Context, candidate PreparedRelease) error {
	if store == nil || ctx == nil || candidate.store != store || candidate.fact.ReleaseID == "" ||
		candidate.trigger != store.trigger(candidate.fact) {
		return ErrReleaseStoreConfiguration
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	directory, unlock, err := store.openLockedDirectory()
	if err != nil {
		return err
	}
	defer directory.Close()
	defer unlock()
	if err := store.validateReleaseFact(directory, candidate.fact); err != nil {
		return err
	}

	current, exists, err := store.readState(directory)
	if err != nil {
		return err
	}
	if exists && current.Active == candidate.fact {
		return nil
	}
	if exists {
		switch {
		case candidate.fact.Revision < current.Active.Revision:
			return ErrRevision
		case candidate.fact.Revision == current.Active.Revision:
			return ErrRevisionConflict
		}
	}
	if candidate.fact.RollbackOf != "" {
		target, targetExists, targetErr := store.readFactByID(directory, candidate.fact.RollbackOf)
		if targetErr != nil {
			return targetErr
		}
		if !targetExists || target.ContentSHA256 != candidate.fact.ContentSHA256 {
			return ErrReleaseStoreIntegrity
		}
		if err := store.validateReleaseFact(directory, target); err != nil {
			return err
		}
	}
	next := ReleaseState{Active: candidate.fact}
	if exists {
		previous := current.Active
		next.LKG = &previous
	}
	stateData, err := json.Marshal(next)
	if err != nil || len(stateData) > maximumReleaseStateBytes {
		return ErrReleaseStoreIntegrity
	}
	if err := writeAtomicArtifact(ctx, directory, releaseStateFilename, stateData); err != nil {
		return err
	}
	return nil
}

func (store *ReleaseStore) State(ctx context.Context) (ReleaseState, error) {
	if store == nil || ctx == nil {
		return ReleaseState{}, ErrReleaseStoreConfiguration
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return ReleaseState{}, err
	}
	directory, unlock, err := store.openLockedDirectory()
	if err != nil {
		return ReleaseState{}, err
	}
	defer directory.Close()
	defer unlock()
	state, exists, err := store.readState(directory)
	if err != nil {
		return ReleaseState{}, err
	}
	if !exists {
		return ReleaseState{}, ErrReleaseStoreUnavailable
	}
	return state, nil
}

func (store *ReleaseStore) ArtifactTrigger(fact ReleaseFact) analyticsgeo.FileTrigger {
	if store == nil {
		return analyticsgeo.FileTrigger{}
	}
	return store.trigger(fact)
}

func (store *ReleaseStore) prepared(fact ReleaseFact) PreparedRelease {
	return PreparedRelease{store: store, fact: fact, trigger: store.trigger(fact)}
}

func (store *ReleaseStore) trigger(fact ReleaseFact) analyticsgeo.FileTrigger {
	return analyticsgeo.FileTrigger{
		Path:           filepath.Join(store.directory, releaseArtifactsDirectory, releaseArtifactFilename(fact.ArtifactSHA256)),
		ExpectedSHA256: fact.ArtifactSHA256,
	}
}

func (store *ReleaseStore) openLockedDirectory() (*os.File, func(), error) {
	directory, err := openPublisherDirectory(store.directory)
	if err != nil {
		return nil, nil, ErrReleaseStoreSecurity
	}
	unlock, err := lockPublisherDirectory(directory)
	if err != nil {
		directory.Close()
		return nil, nil, err
	}
	return directory, unlock, nil
}

func (store *ReleaseStore) inspectArtifact(data []byte) (releaseArtifactIdentity, error) {
	if len(data) == 0 || int64(len(data)) > store.maxArtifactBytes {
		return releaseArtifactIdentity{}, ErrCapacity
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var wire signedAuthorityArtifact
	if decoder.Decode(&wire) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return releaseArtifactIdentity{}, ErrArtifactIntegrity
	}
	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(canonical, data) {
		return releaseArtifactIdentity{}, ErrArtifactIntegrity
	}
	publicKey, trusted := store.trustedKeys[wire.KeyID]
	if !trusted {
		return releaseArtifactIdentity{}, ErrArtifactIntegrity
	}
	metadata, err := validateArtifactWire(data, wire.KeyID, publicKey)
	if err != nil {
		return releaseArtifactIdentity{}, err
	}
	content := releaseContentIdentity{CurrentCatalogVersion: wire.CurrentCatalogVersion}
	seen := make(map[string]struct{}, len(wire.Catalogs))
	currentDigest := ""
	for _, encoded := range wire.Catalogs {
		catalogData, decodeErr := base64.StdEncoding.Strict().DecodeString(encoded.DataBase64)
		if decodeErr != nil {
			return releaseArtifactIdentity{}, ErrArtifactIntegrity
		}
		catalogDecoder := json.NewDecoder(bytes.NewReader(catalogData))
		catalogDecoder.DisallowUnknownFields()
		var document catalogDocument
		if catalogDecoder.Decode(&document) != nil || catalogDecoder.Decode(&struct{}{}) != io.EOF || !validVersion(document.Version) {
			return releaseArtifactIdentity{}, ErrArtifactIntegrity
		}
		catalogCanonical, marshalErr := json.Marshal(document)
		if marshalErr != nil || !bytes.Equal(catalogCanonical, catalogData) {
			return releaseArtifactIdentity{}, ErrArtifactIntegrity
		}
		if _, duplicate := seen[document.Version]; duplicate {
			return releaseArtifactIdentity{}, ErrArtifactIntegrity
		}
		seen[document.Version] = struct{}{}
		content.Catalogs = append(content.Catalogs, releaseContentCatalog{Version: document.Version, SHA256: encoded.ExpectedSHA256})
		if document.Version == wire.CurrentCatalogVersion {
			currentDigest = encoded.ExpectedSHA256
		}
	}
	if currentDigest == "" {
		return releaseArtifactIdentity{}, ErrArtifactIntegrity
	}
	sort.Slice(content.Catalogs, func(left, right int) bool { return content.Catalogs[left].Version < content.Catalogs[right].Version })
	contentData, err := json.Marshal(content)
	if err != nil {
		return releaseArtifactIdentity{}, ErrArtifactIntegrity
	}
	contentDigest := sha256.Sum256(contentData)
	signature, err := base64.StdEncoding.Strict().DecodeString(wire.SignatureBase64)
	if err != nil {
		return releaseArtifactIdentity{}, ErrArtifactIntegrity
	}
	signatureDigest := sha256.Sum256(signature)
	return releaseArtifactIdentity{
		revision: metadata.revision, keyID: wire.KeyID, catalogVersion: wire.CurrentCatalogVersion,
		currentCatalogSHA256: currentDigest, artifactSHA256: metadata.digest,
		contentSHA256: hex.EncodeToString(contentDigest[:]), signatureSHA256: hex.EncodeToString(signatureDigest[:]),
		issuedAt: metadata.issuedAt, expiresAt: metadata.expiresAt,
	}, nil
}

func (store *ReleaseStore) validateReleaseFact(directory *os.File, fact ReleaseFact) error {
	if !validReleaseFactIdentity(fact) {
		return ErrReleaseStoreIntegrity
	}
	artifacts, err := openReleaseSubdirectory(directory, releaseArtifactsDirectory)
	if err != nil {
		return err
	}
	defer artifacts.Close()
	data, exists, err := readReleaseFile(artifacts, releaseArtifactFilename(fact.ArtifactSHA256), store.maxArtifactBytes)
	if err != nil {
		return err
	}
	if !exists {
		return ErrReleaseStoreIntegrity
	}
	identity, err := store.inspectArtifact(data)
	if err != nil {
		return err
	}
	if fact.Revision != identity.revision || fact.KeyID != identity.keyID || fact.CatalogVersion != identity.catalogVersion ||
		fact.CurrentCatalogSHA256 != identity.currentCatalogSHA256 || fact.ArtifactSHA256 != identity.artifactSHA256 ||
		fact.ContentSHA256 != identity.contentSHA256 || fact.SignatureSHA256 != identity.signatureSHA256 ||
		!fact.IssuedAt.Equal(identity.issuedAt) || !fact.ExpiresAt.Equal(identity.expiresAt) {
		return ErrReleaseStoreIntegrity
	}
	return nil
}

func (store *ReleaseStore) readState(directory *os.File) (ReleaseState, bool, error) {
	data, exists, err := readReleaseFile(directory, releaseStateFilename, maximumReleaseStateBytes)
	if err != nil || !exists {
		return ReleaseState{}, exists, err
	}
	var state ReleaseState
	if decodeCanonicalReleaseJSON(data, &state) != nil || state.Active.ReleaseID == "" ||
		state.LKG != nil && state.LKG.ReleaseID == state.Active.ReleaseID {
		return ReleaseState{}, true, ErrReleaseStoreIntegrity
	}
	active, activeExists, err := store.readFactByID(directory, state.Active.ReleaseID)
	if err != nil || !activeExists || active != state.Active {
		if err != nil {
			return ReleaseState{}, true, err
		}
		return ReleaseState{}, true, ErrReleaseStoreIntegrity
	}
	if err := store.validateReleaseFact(directory, state.Active); err != nil {
		return ReleaseState{}, true, err
	}
	if state.LKG != nil {
		lkg, lkgExists, err := store.readFactByID(directory, state.LKG.ReleaseID)
		if err != nil || !lkgExists || lkg != *state.LKG || state.LKG.Revision >= state.Active.Revision {
			if err != nil {
				return ReleaseState{}, true, err
			}
			return ReleaseState{}, true, ErrReleaseStoreIntegrity
		}
		if err := store.validateReleaseFact(directory, *state.LKG); err != nil {
			return ReleaseState{}, true, err
		}
	}
	return state, true, nil
}

func (store *ReleaseStore) readFactByID(directory *os.File, releaseID string) (ReleaseFact, bool, error) {
	if !validVersion(releaseID) {
		return ReleaseFact{}, false, ErrReleaseStoreIntegrity
	}
	releases, err := openReleaseSubdirectory(directory, releaseFactsDirectory)
	if err != nil {
		return ReleaseFact{}, false, err
	}
	defer releases.Close()
	return store.readReleaseFact(releases, releaseID)
}

func (store *ReleaseStore) readReleaseFact(directory *os.File, releaseID string) (ReleaseFact, bool, error) {
	data, exists, err := readReleaseFile(directory, releaseFactFilename(releaseID), maximumReleaseFactBytes)
	if err != nil || !exists {
		return ReleaseFact{}, exists, err
	}
	var fact ReleaseFact
	if decodeCanonicalReleaseJSON(data, &fact) != nil || fact.ReleaseID != releaseID || !validReleaseFactIdentity(fact) {
		return ReleaseFact{}, true, ErrReleaseStoreIntegrity
	}
	return fact, true, nil
}

func validReleaseRequestIdentity(request ReleaseRequest) bool {
	return validVersion(request.ReleaseID) && validVersion(request.Source.Provider) && validVersion(request.Source.Version) &&
		validSHA256Hex(request.Source.SHA256) && (request.RollbackOf == "" || validVersion(request.RollbackOf))
}

func validReleaseFactIdentity(fact ReleaseFact) bool {
	return fact.Revision > 0 && validVersion(fact.ReleaseID) && validVersion(fact.Source.Provider) &&
		validVersion(fact.Source.Version) && validSHA256Hex(fact.Source.SHA256) && validVersion(fact.KeyID) &&
		validVersion(fact.CatalogVersion) && validSHA256Hex(fact.CurrentCatalogSHA256) &&
		validSHA256Hex(fact.ArtifactSHA256) && validSHA256Hex(fact.ContentSHA256) &&
		validSHA256Hex(fact.SignatureSHA256) && canonicalTime(fact.IssuedAt) && canonicalTime(fact.ExpiresAt) &&
		fact.ExpiresAt.After(fact.IssuedAt) && canonicalTime(fact.CreatedAt) &&
		(fact.RollbackOf == "" || validVersion(fact.RollbackOf))
}

func validSHA256Hex(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}

func sameReleaseIdentity(left, right ReleaseFact) bool {
	left.CreatedAt = time.Time{}
	right.CreatedAt = time.Time{}
	return left == right
}

func decodeCanonicalReleaseJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(destination) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return ErrReleaseStoreIntegrity
	}
	canonical, err := json.Marshal(destination)
	if err != nil || !bytes.Equal(canonical, data) {
		return ErrReleaseStoreIntegrity
	}
	return nil
}

func ensureReleaseSubdirectory(directory *os.File, name string) (*os.File, error) {
	if err := unix.Mkdirat(int(directory.Fd()), name, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, ErrReleaseStoreIO
	}
	return openReleaseSubdirectory(directory, name)
}

func openReleaseSubdirectory(directory *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrReleaseStoreSecurity
	}
	result := os.NewFile(uintptr(fd), name)
	if result == nil {
		unix.Close(fd)
		return nil, ErrReleaseStoreIO
	}
	info, err := result.Stat()
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		result.Close()
		return nil, ErrReleaseStoreSecurity
	}
	return result, nil
}

func readReleaseFile(directory *os.File, name string, maximum int64) ([]byte, bool, error) {
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, ErrReleaseStoreSecurity
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		unix.Close(fd)
		return nil, false, ErrReleaseStoreIO
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return nil, false, ErrReleaseStoreSecurity
	}
	if info.Size() <= 0 || info.Size() > maximum {
		return nil, false, ErrCapacity
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, false, ErrReleaseStoreIO
	}
	if int64(len(data)) > maximum {
		return nil, false, ErrCapacity
	}
	return data, true, nil
}

func writeImmutableReleaseFile(ctx context.Context, directory *os.File, name string, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	temporaryName, file, err := createTemporaryArtifact(directory, name)
	if err != nil {
		return err
	}
	defer func() {
		_ = file.Close()
		_ = unix.Unlinkat(int(directory.Fd()), temporaryName, 0)
	}()
	if _, err := file.Write(data); err != nil {
		return ErrReleaseStoreIO
	}
	if err := file.Sync(); err != nil {
		return ErrReleaseStoreIO
	}
	if err := file.Close(); err != nil {
		return ErrReleaseStoreIO
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := unix.Linkat(int(directory.Fd()), temporaryName, int(directory.Fd()), name, 0); err != nil {
		return ErrReleaseStoreIO
	}
	if err := directory.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		_ = unix.Unlinkat(int(directory.Fd()), name, 0)
		return ErrReleaseStoreIO
	}
	return nil
}

func releaseArtifactFilename(digest string) string { return digest + ".json" }
func releaseFactFilename(releaseID string) string  { return releaseID + ".json" }
