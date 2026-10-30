package nativebackup

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"filippo.io/age"
)

const manifestFile = "manifest.json"

var ErrArtifactCorrupt = errors.New("backup artifact does not match its signed manifest")

// NewBackupID returns a sortable, unique bundle name.
func NewBackupID(now time.Time) string {
	suffix := make([]byte, 5)
	_, _ = rand.Read(suffix)
	encoded := strings.ToLower(base32NoPad(suffix))
	return now.UTC().Format("20060102T150405Z") + "-" + encoded[:8]
}

func base32NoPad(value []byte) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	var output strings.Builder
	var buffer, bits uint
	for _, octet := range value {
		buffer = buffer<<8 | uint(octet)
		bits += 8
		for bits >= 5 {
			bits -= 5
			output.WriteByte(alphabet[(buffer>>bits)&31])
		}
	}
	if bits > 0 {
		output.WriteByte(alphabet[(buffer<<(5-bits))&31])
	}
	return output.String()
}

func encodeBase64(value []byte) string { return base64.StdEncoding.EncodeToString(value) }
func decodeBase64(value string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(value)
}

func parseRecipients(values []string) ([]age.Recipient, error) {
	if len(values) == 0 || len(values) > 8 {
		return nil, errors.New("one to eight backup recipients are required")
	}
	recipients := make([]age.Recipient, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		recipient, err := age.ParseX25519Recipient(value)
		if err != nil || seen[value] {
			return nil, errors.New("invalid backup recipient")
		}
		seen[value] = true
		recipients = append(recipients, recipient)
	}
	return recipients, nil
}

// BundleWriter stages encrypted components and publishes the bundle with one
// rename, so a crashed backup never leaves a directory that looks complete.
type BundleWriter struct {
	final      string
	staging    string
	recipients []age.Recipient
	names      []string
	records    []ComponentRecord
	now        func() time.Time
}

func NewBundleWriter(outputDirectory, backupID string, recipients []string, now func() time.Time) (*BundleWriter, error) {
	if !backupIDPattern.MatchString(backupID) {
		return nil, ErrManifestInvalid
	}
	parsed, err := parseRecipients(recipients)
	if err != nil {
		return nil, err
	}
	if err := ensurePrivateDirectory(outputDirectory); err != nil {
		return nil, err
	}
	final := filepath.Join(outputDirectory, backupID)
	if _, err := os.Lstat(final); !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("backup already exists")
	}
	staging, err := os.MkdirTemp(outputDirectory, "."+backupID+".partial-")
	if err != nil {
		return nil, err
	}
	return &BundleWriter{final: final, staging: staging, recipients: parsed, names: append([]string(nil), recipients...), now: now}, nil
}

func (writer *BundleWriter) Recipients() []string { return append([]string(nil), writer.names...) }

type countingHash struct {
	hash  hash.Hash
	bytes int64
}

func newCountingHash() *countingHash { return &countingHash{hash: sha256.New()} }
func (counter *countingHash) Write(value []byte) (int, error) {
	counter.bytes += int64(len(value))
	return counter.hash.Write(value)
}
func (counter *countingHash) sum() string { return hex.EncodeToString(counter.hash.Sum(nil)) }

// Add encrypts what produce writes and records both digests. The plaintext
// never touches the disk outside the component's own scratch space.
func (writer *BundleWriter) Add(name ComponentName, produce func(io.Writer) (map[string]string, error)) error {
	if len(writer.records) >= len(ComponentOrder) || ComponentOrder[len(writer.records)] != name {
		return fmt.Errorf("component %s is out of order", name)
	}
	file, err := os.OpenFile(filepath.Join(writer.staging, string(name)+".tar.age"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	cipher, plain := newCountingHash(), newCountingHash()
	encrypted, err := age.Encrypt(io.MultiWriter(file, cipher), writer.recipients...)
	if err != nil {
		return err
	}
	detail, err := produce(io.MultiWriter(encrypted, plain))
	if err != nil {
		return err
	}
	if plain.bytes == 0 {
		return fmt.Errorf("component %s produced no data", name)
	}
	if err := encrypted.Close(); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	writer.records = append(writer.records, ComponentRecord{Name: name, File: string(name) + ".tar.age",
		CiphertextSHA256: cipher.sum(), CiphertextBytes: cipher.bytes, PlaintextSHA256: plain.sum(),
		PlaintextBytes: plain.bytes, CapturedAt: writer.now().UTC(), Detail: detail})
	return nil
}

// Publish signs the manifest and atomically moves the bundle into place.
func (writer *BundleWriter) Publish(manifest Manifest, ring KeyRing) (SignedManifest, string, error) {
	manifest.Components = writer.records
	manifest.Recipients = writer.Recipients()
	signed, err := SignManifest(manifest, ring.Signing)
	if err != nil {
		return SignedManifest{}, "", err
	}
	encoded, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		return SignedManifest{}, "", err
	}
	if err := writeExclusive(filepath.Join(writer.staging, manifestFile), append(encoded, '\n')); err != nil {
		return SignedManifest{}, "", err
	}
	if err := syncDirectory(writer.staging); err != nil {
		return SignedManifest{}, "", err
	}
	if err := os.Rename(writer.staging, writer.final); err != nil {
		return SignedManifest{}, "", err
	}
	if err := os.Chmod(writer.final, 0o700); err != nil {
		return SignedManifest{}, "", err
	}
	return signed, writer.final, syncDirectory(filepath.Dir(writer.final))
}

func (writer *BundleWriter) Abort() { _ = os.RemoveAll(writer.staging) }

// Bundle is a published backup directory whose manifest was verified against
// a pinned signer fingerprint.
type Bundle struct {
	Directory string
	Manifest  Manifest
	Signed    SignedManifest
}

func ReadSignedManifest(directory string) (SignedManifest, error) {
	encoded, err := readPrivateFile(filepath.Join(directory, manifestFile), 1<<20)
	if err != nil {
		return SignedManifest{}, err
	}
	var signed SignedManifest
	if err := json.Unmarshal(encoded, &signed); err != nil {
		return SignedManifest{}, ErrManifestInvalid
	}
	return signed, nil
}

func OpenBundle(directory, pinnedFingerprint string) (Bundle, error) {
	signed, err := ReadSignedManifest(directory)
	if err != nil {
		return Bundle{}, err
	}
	manifest, err := VerifyManifest(signed, pinnedFingerprint)
	if err != nil {
		return Bundle{}, err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return Bundle{}, err
	}
	want := map[string]bool{manifestFile: true}
	for _, component := range manifest.Components {
		want[component.File] = true
	}
	for _, entry := range entries {
		if !want[entry.Name()] {
			return Bundle{}, fmt.Errorf("unexpected file in backup: %s", entry.Name())
		}
	}
	return Bundle{Directory: directory, Manifest: manifest, Signed: signed}, nil
}

// VerifyCiphertext checks every artifact digest without decrypting.
func (bundle Bundle) VerifyCiphertext() error {
	for _, component := range bundle.Manifest.Components {
		if err := verifyFileDigest(filepath.Join(bundle.Directory, component.File), component.CiphertextSHA256, component.CiphertextBytes); err != nil {
			return fmt.Errorf("%s: %w", component.Name, err)
		}
	}
	return nil
}

func verifyFileDigest(path, want string, size int64) error {
	file, err := os.Open(path)
	if err != nil {
		return ErrArtifactCorrupt
	}
	defer file.Close()
	counter := newCountingHash()
	if _, err := io.Copy(counter, file); err != nil || counter.sum() != want || counter.bytes != size {
		return ErrArtifactCorrupt
	}
	return nil
}

// Open returns the decrypted component stream. The ciphertext digest is
// checked first; the plaintext digest is checked when the stream ends, and a
// mismatch is reported instead of io.EOF.
func (bundle Bundle) Open(name ComponentName, identity age.Identity) (io.ReadCloser, error) {
	component, found := bundle.Manifest.Component(name)
	if !found {
		return nil, ErrManifestInvalid
	}
	path := filepath.Join(bundle.Directory, component.File)
	if err := verifyFileDigest(path, component.CiphertextSHA256, component.CiphertextBytes); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	reader, err := age.Decrypt(file, identity)
	if err != nil {
		_ = file.Close()
		return nil, errors.New("backup cannot be decrypted with this identity")
	}
	return &verifyingReader{reader: reader, closer: file, hash: newCountingHash(), want: component.PlaintextSHA256, size: component.PlaintextBytes}, nil
}

type verifyingReader struct {
	reader io.Reader
	closer io.Closer
	hash   *countingHash
	want   string
	size   int64
}

func (reader *verifyingReader) Read(buffer []byte) (int, error) {
	count, err := reader.reader.Read(buffer)
	reader.hash.Write(buffer[:count])
	if errors.Is(err, io.EOF) && (reader.hash.sum() != reader.want || reader.hash.bytes != reader.size) {
		return count, ErrArtifactCorrupt
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return count, ErrArtifactCorrupt
	}
	return count, err
}

func (reader *verifyingReader) Close() error { return reader.closer.Close() }

// VerifyAll decrypts every component to the end (nothing is written).
func (bundle Bundle) VerifyAll(identity age.Identity) error {
	for _, component := range bundle.Manifest.Components {
		stream, err := bundle.Open(component.Name, identity)
		if err != nil {
			return fmt.Errorf("%s: %w", component.Name, err)
		}
		_, copyErr := io.Copy(io.Discard, stream)
		_ = stream.Close()
		if copyErr != nil {
			return fmt.Errorf("%s: %w", component.Name, copyErr)
		}
	}
	return nil
}

// BundleSummary is what the console lists; it carries no secret.
type BundleSummary struct {
	BackupID      string     `json:"backup_id"`
	Reason        string     `json:"reason"`
	CreatedAt     time.Time  `json:"created_at"`
	Version       string     `json:"version"`
	SchemaVersion uint64     `json:"schema_version"`
	Bytes         int64      `json:"bytes"`
	Signer        string     `json:"signer_fingerprint"`
	SignatureOK   bool       `json:"signature_ok"`
	Components    []string   `json:"components"`
	UploadedTo    []string   `json:"uploaded_to,omitempty"`
	DeletedAt     *time.Time `json:"deleted_at,omitempty"`
}

// ListBundles reads published bundles newest first. A bundle whose signature
// does not verify against the local signer is listed with SignatureOK=false.
func ListBundles(directory, localFingerprint string) ([]BundleSummary, error) {
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var summaries []BundleSummary
	for _, entry := range entries {
		if !entry.IsDir() || !backupIDPattern.MatchString(entry.Name()) {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		signed, err := ReadSignedManifest(path)
		if err != nil {
			continue
		}
		manifest, verifyErr := VerifyManifest(signed, localFingerprint)
		if verifyErr != nil {
			if manifest, err = ReadUnverifiedManifest(signed); err != nil {
				continue
			}
		}
		summary := BundleSummary{BackupID: manifest.BackupID, Reason: manifest.Reason, CreatedAt: manifest.CreatedAt,
			Version: manifest.Control.Version, SchemaVersion: manifest.Control.SchemaVersion,
			Signer: manifest.SignerKeyHint, SignatureOK: verifyErr == nil}
		for _, component := range manifest.Components {
			summary.Bytes += component.CiphertextBytes
			summary.Components = append(summary.Components, string(component.Name))
		}
		summaries = append(summaries, summary)
	}
	sort.Slice(summaries, func(left, right int) bool { return summaries[left].BackupID > summaries[right].BackupID })
	return summaries, nil
}
