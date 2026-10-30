package analyticsgeoartifact

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticsgeo"
)

func TestFilePublisherPersistsExactReplayAcrossRestartAndFeedsLoader(t *testing.T) {
	compiler, privateKey := newCompilerFixture(t, 16, 100, 1<<20, 1<<20)
	issuedAt := time.Date(2026, 8, 8, 8, 0, 0, 0, time.UTC)
	artifact, err := compiler.Compile(t.Context(), validCompileRequest(issuedAt))
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	config := FilePublisherConfig{
		Directory: directory, Filename: "geo-authority.json", KeyID: "geo-publisher-1",
		PublicKey: privateKey.Public().(ed25519.PublicKey), MaxArtifactBytes: 1 << 20,
	}
	publisher, err := NewFilePublisher(config)
	if err != nil {
		t.Fatal(err)
	}
	first, err := publisher.Publish(t.Context(), artifact)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(first.Path)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewFilePublisher(config)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := restarted.Publish(t.Context(), artifact)
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.Lstat(replayed.Path)
	if err != nil {
		t.Fatal(err)
	}
	if first != replayed || first.ExpectedSHA256 != artifact.SHA256 || !os.SameFile(before, after) || after.Mode().Perm() != 0o600 {
		t.Fatalf("replay replaced artifact: first=%#v replay=%#v before=%#v after=%#v", first, replayed, before, after)
	}

	keyring, err := analyticsgeo.NewTrustedEd25519Keyring(map[string]ed25519.PublicKey{
		"geo-publisher-1": privateKey.Public().(ed25519.PublicKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	loader, err := analyticsgeo.NewSignedFileLoader(analyticsgeo.SignedFileLoaderConfig{
		Keyring: keyring, Now: func() time.Time { return issuedAt },
		MaxArtifactBytes: 1 << 20, MaxAggregateCatalogBytes: 1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := loader.Poll(t.Context(), replayed); err != nil {
		t.Fatal(err)
	}
}

func TestFilePublisherRejectsSameRevisionConflictRollbackAndInvalidArtifact(t *testing.T) {
	issuedAt := time.Date(2026, 8, 8, 8, 0, 0, 0, time.UTC)
	compiler, privateKey := newCompilerFixture(t, 16, 100, 1<<20, 1<<20)
	initial, err := compiler.Compile(t.Context(), validCompileRequest(issuedAt))
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := NewFilePublisher(FilePublisherConfig{
		Directory: t.TempDir(), Filename: "geo-authority.json", KeyID: "geo-publisher-1",
		PublicKey: privateKey.Public().(ed25519.PublicKey), MaxArtifactBytes: 1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Publish(t.Context(), initial); err != nil {
		t.Fatal(err)
	}

	conflictCompiler, _ := newCompilerFixture(t, 16, 100, 1<<20, 1<<20)
	changedRequest := validCompileRequest(issuedAt)
	changedRequest.Catalogs = cloneCatalogs(changedRequest.Catalogs)
	changedRequest.Catalogs[1].Entries[0].Carrier = "changed"
	changed, err := conflictCompiler.Compile(t.Context(), changedRequest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Publish(t.Context(), changed); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("same revision conflict error = %v", err)
	}

	rollbackCompiler, _ := newCompilerFixture(t, 16, 100, 1<<20, 1<<20)
	rollbackRequest := validCompileRequest(issuedAt)
	rollbackRequest.Revision--
	rollback, err := rollbackCompiler.Compile(t.Context(), rollbackRequest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Publish(t.Context(), rollback); !errors.Is(err, ErrRevision) {
		t.Fatalf("rollback error = %v", err)
	}

	tampered := initial
	tampered.Bytes = bytes.Clone(initial.Bytes)
	tampered.Bytes[len(tampered.Bytes)-1] ^= 1
	if _, err := publisher.Publish(t.Context(), tampered); !errors.Is(err, ErrArtifactIntegrity) {
		t.Fatalf("tampered artifact error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := publisher.Publish(cancelled, initial); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled publish error = %v", err)
	}
}

func TestFilePublisherRejectsUnsafePathsFilesAndCapacity(t *testing.T) {
	compiler, privateKey := newCompilerFixture(t, 16, 100, 1<<20, 1<<20)
	artifact, err := compiler.Compile(t.Context(), validCompileRequest(time.Date(2026, 8, 8, 8, 0, 0, 0, time.UTC)))
	if err != nil {
		t.Fatal(err)
	}
	realDirectory := t.TempDir()
	linkedDirectory := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(realDirectory, linkedDirectory); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFilePublisher(FilePublisherConfig{
		Directory: linkedDirectory, Filename: "geo-authority.json", KeyID: "geo-publisher-1",
		PublicKey: privateKey.Public().(ed25519.PublicKey), MaxArtifactBytes: 1 << 20,
	}); !errors.Is(err, ErrPublisherSecurity) {
		t.Fatalf("symlink directory error = %v", err)
	}

	directory := t.TempDir()
	target := filepath.Join(directory, "target.json")
	if err := os.WriteFile(target, []byte("do not replace through link"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "geo-authority.json")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	publisher, err := NewFilePublisher(FilePublisherConfig{
		Directory: directory, Filename: "geo-authority.json", KeyID: "geo-publisher-1",
		PublicKey: privateKey.Public().(ed25519.PublicKey), MaxArtifactBytes: 1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Publish(t.Context(), artifact); !errors.Is(err, ErrPublisherSecurity) {
		t.Fatalf("symlink target error = %v", err)
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "do not replace through link" {
		t.Fatalf("symlink target changed: %q %v", data, err)
	}

	small, err := NewFilePublisher(FilePublisherConfig{
		Directory: t.TempDir(), Filename: "geo-authority.json", KeyID: "geo-publisher-1",
		PublicKey: privateKey.Public().(ed25519.PublicKey), MaxArtifactBytes: len(artifact.Bytes) - 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := small.Publish(t.Context(), artifact); !errors.Is(err, ErrCapacity) {
		t.Fatalf("oversized artifact error = %v", err)
	}
}
