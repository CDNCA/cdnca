package analyticsgeoartifact

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticsgeo"
	"golang.org/x/sys/unix"
)

const publisherLockFilename = ".geo-authority.publish.lock"

var (
	ErrPublisherConfiguration = errors.New("analytics geo artifact publisher configuration invalid")
	ErrPublisherSecurity      = errors.New("analytics geo artifact publisher security invalid")
	ErrPublisherIO            = errors.New("analytics geo artifact publisher IO failed")
	ErrArtifactIntegrity      = errors.New("analytics geo artifact integrity invalid")
)

type FilePublisherConfig struct {
	Directory        string
	Filename         string
	KeyID            string
	PublicKey        ed25519.PublicKey
	MaxArtifactBytes int
}

type FilePublisher struct {
	mu               sync.Mutex
	directory        string
	filename         string
	keyID            string
	publicKey        ed25519.PublicKey
	maxArtifactBytes int
}

type artifactMetadata struct {
	revision  uint64
	issuedAt  time.Time
	expiresAt time.Time
	digest    string
}

func NewFilePublisher(config FilePublisherConfig) (*FilePublisher, error) {
	if !filepath.IsAbs(config.Directory) || filepath.Clean(config.Directory) != config.Directory ||
		config.Filename == "" || config.Filename == "." || filepath.Base(config.Filename) != config.Filename ||
		!validVersion(config.KeyID) || len(config.PublicKey) != ed25519.PublicKeySize ||
		config.MaxArtifactBytes <= 0 || config.MaxArtifactBytes > maximumArtifactBytes {
		return nil, ErrPublisherConfiguration
	}
	directory, err := openPublisherDirectory(config.Directory)
	if err != nil {
		return nil, err
	}
	directory.Close()
	return &FilePublisher{
		directory: config.Directory, filename: config.Filename, keyID: config.KeyID,
		publicKey: bytes.Clone(config.PublicKey), maxArtifactBytes: config.MaxArtifactBytes,
	}, nil
}

func (publisher *FilePublisher) Publish(ctx context.Context, artifact CompiledArtifact) (analyticsgeo.FileTrigger, error) {
	if publisher == nil || ctx == nil {
		return analyticsgeo.FileTrigger{}, ErrPublisherConfiguration
	}
	publisher.mu.Lock()
	defer publisher.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return analyticsgeo.FileTrigger{}, err
	}
	candidate, err := publisher.validateArtifact(artifact)
	if err != nil {
		return analyticsgeo.FileTrigger{}, err
	}
	directory, err := openPublisherDirectory(publisher.directory)
	if err != nil {
		return analyticsgeo.FileTrigger{}, err
	}
	defer directory.Close()
	unlock, err := lockPublisherDirectory(directory)
	if err != nil {
		return analyticsgeo.FileTrigger{}, err
	}
	defer unlock()

	existing, exists, err := publisher.readExisting(directory)
	if err != nil {
		return analyticsgeo.FileTrigger{}, err
	}
	if exists {
		switch {
		case candidate.revision < existing.revision:
			return analyticsgeo.FileTrigger{}, ErrRevision
		case candidate.revision == existing.revision && candidate.digest != existing.digest:
			return analyticsgeo.FileTrigger{}, ErrRevisionConflict
		case candidate.revision == existing.revision:
			return publisher.trigger(candidate.digest), nil
		}
	}
	if err := ctx.Err(); err != nil {
		return analyticsgeo.FileTrigger{}, err
	}
	if err := writeAtomicArtifact(ctx, directory, publisher.filename, artifact.Bytes); err != nil {
		return analyticsgeo.FileTrigger{}, err
	}
	return publisher.trigger(candidate.digest), nil
}

func (publisher *FilePublisher) trigger(digest string) analyticsgeo.FileTrigger {
	return analyticsgeo.FileTrigger{Path: filepath.Join(publisher.directory, publisher.filename), ExpectedSHA256: digest}
}

func (publisher *FilePublisher) validateArtifact(artifact CompiledArtifact) (artifactMetadata, error) {
	if len(artifact.Bytes) == 0 || len(artifact.Bytes) > publisher.maxArtifactBytes {
		return artifactMetadata{}, ErrCapacity
	}
	metadata, err := validateArtifactWire(artifact.Bytes, publisher.keyID, publisher.publicKey)
	if err != nil {
		return artifactMetadata{}, err
	}
	if artifact.Revision != metadata.revision || !artifact.IssuedAt.Equal(metadata.issuedAt) ||
		!artifact.ExpiresAt.Equal(metadata.expiresAt) || artifact.SHA256 != metadata.digest {
		return artifactMetadata{}, ErrArtifactIntegrity
	}
	return metadata, nil
}

func (publisher *FilePublisher) readExisting(directory *os.File) (artifactMetadata, bool, error) {
	fd, err := unix.Openat(int(directory.Fd()), publisher.filename, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return artifactMetadata{}, false, nil
	}
	if err != nil {
		return artifactMetadata{}, false, ErrPublisherSecurity
	}
	file := os.NewFile(uintptr(fd), publisher.filename)
	if file == nil {
		unix.Close(fd)
		return artifactMetadata{}, false, ErrPublisherIO
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return artifactMetadata{}, false, ErrPublisherSecurity
	}
	if info.Size() <= 0 || info.Size() > int64(publisher.maxArtifactBytes) {
		return artifactMetadata{}, false, ErrCapacity
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(publisher.maxArtifactBytes)+1))
	if err != nil {
		return artifactMetadata{}, false, ErrPublisherIO
	}
	if len(data) > publisher.maxArtifactBytes {
		return artifactMetadata{}, false, ErrCapacity
	}
	metadata, err := validateArtifactWire(data, publisher.keyID, publisher.publicKey)
	if err != nil {
		return artifactMetadata{}, false, err
	}
	return metadata, true, nil
}

func validateArtifactWire(data []byte, keyID string, publicKey ed25519.PublicKey) (artifactMetadata, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var wire signedAuthorityArtifact
	if decoder.Decode(&wire) != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		wire.SchemaVersion != artifactSchemaVersion || wire.KeyID != keyID || wire.Revision == 0 || len(wire.Catalogs) == 0 {
		return artifactMetadata{}, ErrArtifactIntegrity
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, wire.ExpiresAt)
	if err != nil || !canonicalTime(expiresAt) {
		return artifactMetadata{}, ErrArtifactIntegrity
	}
	digests := make([]string, len(wire.Catalogs))
	var issuedAt time.Time
	for index, catalog := range wire.Catalogs {
		catalogData, err := base64.StdEncoding.Strict().DecodeString(catalog.DataBase64)
		if err != nil || len(catalogData) == 0 {
			return artifactMetadata{}, ErrArtifactIntegrity
		}
		digest := sha256.Sum256(catalogData)
		expected, err := hex.DecodeString(catalog.ExpectedSHA256)
		if err != nil || catalog.ExpectedSHA256 != strings.ToLower(catalog.ExpectedSHA256) ||
			subtle.ConstantTimeCompare(expected, digest[:]) != 1 {
			return artifactMetadata{}, ErrArtifactIntegrity
		}
		catalogDecoder := json.NewDecoder(bytes.NewReader(catalogData))
		catalogDecoder.DisallowUnknownFields()
		var document catalogDocument
		if catalogDecoder.Decode(&document) != nil || catalogDecoder.Decode(&struct{}{}) != io.EOF ||
			!canonicalTime(document.PublishedAt) || len(document.Entries) == 0 {
			return artifactMetadata{}, ErrArtifactIntegrity
		}
		if issuedAt.IsZero() {
			issuedAt = document.PublishedAt
		} else if !issuedAt.Equal(document.PublishedAt) {
			return artifactMetadata{}, ErrArtifactIntegrity
		}
		digests[index] = catalog.ExpectedSHA256
	}
	manifest, err := json.Marshal(analyticsgeo.AuthorityManifest{
		SchemaVersion: wire.SchemaVersion, Revision: wire.Revision, KeyID: wire.KeyID,
		CurrentCatalogVersion: wire.CurrentCatalogVersion, ExpiresAt: wire.ExpiresAt, CatalogSHA256: digests,
	})
	if err != nil {
		return artifactMetadata{}, ErrArtifactIntegrity
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(wire.SignatureBase64)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, manifest, signature) {
		return artifactMetadata{}, ErrArtifactIntegrity
	}
	digest := sha256.Sum256(data)
	return artifactMetadata{
		revision: wire.Revision, issuedAt: issuedAt, expiresAt: expiresAt, digest: hex.EncodeToString(digest[:]),
	}, nil
}

func openPublisherDirectory(path string) (*os.File, error) {
	if err := rejectPublisherSymlinkComponents(path); err != nil {
		return nil, err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrPublisherSecurity
	}
	directory := os.NewFile(uintptr(fd), path)
	if directory == nil {
		unix.Close(fd)
		return nil, ErrPublisherIO
	}
	info, err := directory.Stat()
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
		directory.Close()
		return nil, ErrPublisherSecurity
	}
	return directory, nil
}

func rejectPublisherSymlinkComponents(path string) error {
	current := string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimPrefix(path, current), current) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return ErrPublisherSecurity
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if filepath.Dir(current) != string(filepath.Separator) {
				return ErrPublisherSecurity
			}
			target, err := os.Stat(current)
			if err != nil || !target.IsDir() {
				return ErrPublisherSecurity
			}
		}
	}
	return nil
}

func lockPublisherDirectory(directory *os.File) (func(), error) {
	fd, err := unix.Openat(int(directory.Fd()), publisherLockFilename,
		unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, ErrPublisherSecurity
	}
	if err := unix.Fchmod(fd, 0o600); err != nil || unix.Flock(fd, unix.LOCK_EX) != nil {
		unix.Close(fd)
		return nil, ErrPublisherIO
	}
	return func() {
		_ = unix.Flock(fd, unix.LOCK_UN)
		_ = unix.Close(fd)
	}, nil
}

func writeAtomicArtifact(ctx context.Context, directory *os.File, filename string, data []byte) error {
	temporaryName, temporary, err := createTemporaryArtifact(directory, filename)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			temporary.Close()
		}
		_ = unix.Unlinkat(int(directory.Fd()), temporaryName, 0)
	}()
	if _, err := temporary.Write(data); err != nil {
		return ErrPublisherIO
	}
	if err := temporary.Sync(); err != nil {
		return ErrPublisherIO
	}
	if err := temporary.Close(); err != nil {
		return ErrPublisherIO
	}
	closed = true
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := unix.Renameat(int(directory.Fd()), temporaryName, int(directory.Fd()), filename); err != nil {
		return ErrPublisherIO
	}
	if err := directory.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return ErrPublisherIO
	}
	return nil
}

func createTemporaryArtifact(directory *os.File, filename string) (string, *os.File, error) {
	for range 8 {
		random := make([]byte, 12)
		if _, err := rand.Read(random); err != nil {
			return "", nil, ErrPublisherIO
		}
		name := "." + filename + "." + hex.EncodeToString(random) + ".tmp"
		fd, err := unix.Openat(int(directory.Fd()), name,
			unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return "", nil, ErrPublisherIO
		}
		file := os.NewFile(uintptr(fd), name)
		if file == nil {
			unix.Close(fd)
			return "", nil, ErrPublisherIO
		}
		return name, file, nil
	}
	return "", nil, ErrPublisherIO
}
