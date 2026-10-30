package analyticsgeo

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTrustedEd25519KeyringValidationCloneAndSuccessfulPoll(t *testing.T) {
	privateKey := loaderPrivateKey(0x31)
	publicKey := bytes.Clone(privateKey.Public().(ed25519.PublicKey))
	keys := map[string]ed25519.PublicKey{"geo-key-1": publicKey}
	keyring, err := NewTrustedEd25519Keyring(keys)
	if err != nil {
		t.Fatal(err)
	}
	publicKey[0] ^= 0xff
	delete(keys, "geo-key-1")

	clock := &authorityTestClock{now: time.Date(2026, 8, 8, 5, 0, 0, 0, time.UTC)}
	loader, err := NewSignedFileLoader(SignedFileLoaderConfig{
		Keyring: keyring, Now: clock.Now, MaxArtifactBytes: 1 << 20, MaxAggregateCatalogBytes: 1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, current := authorityCatalogInputs()
	snapshot := loaderSnapshot(t, privateKey, "geo-key-1", 1, clock.Now().Add(time.Hour), []CatalogInput{current})
	trigger := writeSignedArtifact(t, t.TempDir(), "authority.json", snapshot, 0o600)
	if err := loader.Poll(t.Context(), trigger); err != nil {
		t.Fatal(err)
	}
	if err := loader.Poll(t.Context(), trigger); err != nil {
		t.Fatalf("duplicate Poll() error = %v", err)
	}
	result, err := loader.Lookup(t.Context(), "", netip.MustParseAddr("203.0.113.129"))
	if err != nil || result.Revision != 1 || result.Attribution.Carrier != "specific" || result.State != AuthorityStateActive {
		t.Fatalf("Lookup() = %#v, %v", result, err)
	}

	for _, invalid := range []map[string]ed25519.PublicKey{
		nil,
		{"bad key": privateKey.Public().(ed25519.PublicKey)},
		{"geo-key": make(ed25519.PublicKey, ed25519.PublicKeySize-1)},
	} {
		if _, err := NewTrustedEd25519Keyring(invalid); !errors.Is(err, ErrSignedFileConfiguration) {
			t.Fatalf("NewTrustedEd25519Keyring(%v) error = %v", invalid, err)
		}
	}
	tooMany := make(map[string]ed25519.PublicKey, MaximumTrustedAuthorityKeys+1)
	for index := 0; index <= MaximumTrustedAuthorityKeys; index++ {
		tooMany["geo-key-"+string(rune('a'+index))] = privateKey.Public().(ed25519.PublicKey)
	}
	if _, err := NewTrustedEd25519Keyring(tooMany); !errors.Is(err, ErrSignedFileConfiguration) {
		t.Fatalf("oversized keyring error = %v", err)
	}
}

func TestSignedFileLoaderRejectsUnsafePathsTypesAndPermissions(t *testing.T) {
	privateKey := loaderPrivateKey(0x32)
	clock := &authorityTestClock{now: time.Date(2026, 8, 8, 5, 0, 0, 0, time.UTC)}
	artifact := loaderArtifact(t, loaderSnapshotFromCurrent(t, privateKey, "geo-key-1", 1, clock.Now()))
	digest := sha256.Sum256(artifact)
	wantDigest := hex.EncodeToString(digest[:])

	t.Run("owner read only accepted", func(t *testing.T) {
		loader := newLoaderFixture(t, clock, map[string]ed25519.PublicKey{"geo-key-1": privateKey.Public().(ed25519.PublicKey)}, 1<<20, 1<<20)
		trigger := writeArtifactBytes(t, t.TempDir(), "authority.json", artifact, 0o400)
		if err := loader.Poll(t.Context(), trigger); err != nil {
			t.Fatal(err)
		}
	})

	for _, mode := range []os.FileMode{0o640, 0o604, 0o700} {
		t.Run("mode "+mode.String(), func(t *testing.T) {
			loader := newLoaderFixture(t, clock, map[string]ed25519.PublicKey{"geo-key-1": privateKey.Public().(ed25519.PublicKey)}, 1<<20, 1<<20)
			trigger := writeArtifactBytes(t, t.TempDir(), "authority.json", artifact, mode)
			if err := loader.Poll(t.Context(), trigger); !errors.Is(err, ErrSignedFileSecurity) {
				t.Fatalf("Poll() error = %v", err)
			}
		})
	}

	directory := t.TempDir()
	loader := newLoaderFixture(t, clock, map[string]ed25519.PublicKey{"geo-key-1": privateKey.Public().(ed25519.PublicKey)}, 1<<20, 1<<20)
	if err := loader.Poll(t.Context(), FileTrigger{Path: directory, ExpectedSHA256: wantDigest}); !errors.Is(err, ErrSignedFileSecurity) {
		t.Fatalf("directory Poll() error = %v", err)
	}

	targetDir := t.TempDir()
	target := writeArtifactBytes(t, targetDir, "target.json", artifact, 0o600)
	symlink := filepath.Join(targetDir, "authority-link.json")
	if err := os.Symlink(target.Path, symlink); err != nil {
		t.Fatal(err)
	}
	if err := loader.Poll(t.Context(), FileTrigger{Path: symlink, ExpectedSHA256: target.ExpectedSHA256}); !errors.Is(err, ErrSignedFileSecurity) {
		t.Fatalf("symlink Poll() error = %v", err)
	}

	realDir := t.TempDir()
	componentTarget := filepath.Join(realDir, "real")
	if err := os.Mkdir(componentTarget, 0o700); err != nil {
		t.Fatal(err)
	}
	componentFile := writeArtifactBytes(t, componentTarget, "authority.json", artifact, 0o600)
	componentLink := filepath.Join(realDir, "linked")
	if err := os.Symlink(componentTarget, componentLink); err != nil {
		t.Fatal(err)
	}
	linkedPath := filepath.Join(componentLink, filepath.Base(componentFile.Path))
	if err := loader.Poll(t.Context(), FileTrigger{Path: linkedPath, ExpectedSHA256: componentFile.ExpectedSHA256}); !errors.Is(err, ErrSignedFileSecurity) {
		t.Fatalf("symlink component Poll() error = %v", err)
	}

	if err := loader.Poll(t.Context(), FileTrigger{Path: "authority.json", ExpectedSHA256: wantDigest}); !errors.Is(err, ErrSignedFileTrigger) {
		t.Fatalf("relative Poll() error = %v", err)
	}
	uncleanDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(uncleanDir, "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	unclean := filepath.Join(uncleanDir, "child", "..", "authority.json")
	if err := loader.Poll(t.Context(), FileTrigger{Path: unclean, ExpectedSHA256: wantDigest}); !errors.Is(err, ErrSignedFileTrigger) {
		t.Fatalf("unclean Poll() error = %v", err)
	}
}

func TestSignedFileLoaderStrictArtifactFailuresRetainLKG(t *testing.T) {
	privateKey := loaderPrivateKey(0x33)
	clock := &authorityTestClock{now: time.Date(2026, 8, 8, 5, 0, 0, 0, time.UTC)}
	loader := newLoaderFixture(t, clock, map[string]ed25519.PublicKey{"geo-key-1": privateKey.Public().(ed25519.PublicKey)}, 1<<20, 1<<20)
	initial := loaderSnapshotFromCurrent(t, privateKey, "geo-key-1", 1, clock.Now())
	if err := loader.Poll(t.Context(), writeSignedArtifact(t, t.TempDir(), "initial.json", initial, 0o600)); err != nil {
		t.Fatal(err)
	}

	candidate := loaderSnapshotFromCurrent(t, privateKey, "geo-key-1", 2, clock.Now())
	validCandidate := loaderArtifact(t, candidate)
	unknown := func() []byte {
		var value map[string]any
		if err := json.Unmarshal(validCandidate, &value); err != nil {
			t.Fatal(err)
		}
		value["unknown"] = true
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}()
	tamperedSignature := candidate
	tamperedSignature.Signature = bytes.Clone(candidate.Signature)
	tamperedSignature.Signature[0] ^= 0xff

	tests := []struct {
		name       string
		data       []byte
		triggerSHA string
		wantErr    error
		wantReason AuthorityReason
	}{
		{name: "whole file digest mismatch", data: validCandidate, triggerSHA: string(bytes.Repeat([]byte{'0'}, sha256.Size*2)), wantErr: ErrSignedFileDigest, wantReason: AuthorityReasonFileRejected},
		{name: "unknown JSON field", data: unknown, wantErr: ErrSignedFileDecode, wantReason: AuthorityReasonArtifactRejected},
		{name: "trailing JSON", data: append(bytes.Clone(validCandidate), '\n', '{', '}'), wantErr: ErrSignedFileDecode, wantReason: AuthorityReasonArtifactRejected},
		{name: "tampered signature", data: loaderArtifact(t, tamperedSignature), wantErr: ErrAuthoritySignature, wantReason: AuthorityReasonSignatureRejected},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			trigger := writeArtifactBytes(t, t.TempDir(), "candidate.json", test.data, 0o600)
			if test.triggerSHA != "" {
				trigger.ExpectedSHA256 = test.triggerSHA
			}
			if err := loader.Poll(t.Context(), trigger); !errors.Is(err, test.wantErr) {
				t.Fatalf("Poll() error = %v, want %v", err, test.wantErr)
			}
			assertLoaderLKG(t, loader, 1, test.wantReason)
		})
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := loader.Poll(cancelled, writeArtifactBytes(t, t.TempDir(), "cancelled.json", validCandidate, 0o600)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Poll() error = %v", err)
	}
	result, err := loader.Lookup(t.Context(), "", netip.MustParseAddr("203.0.113.129"))
	if err != nil || result.Revision != 1 {
		t.Fatalf("cancelled poll changed LKG: %#v, %v", result, err)
	}
}

func TestSignedFileLoaderBoundedReadKeyRotationAndGlobalRevision(t *testing.T) {
	firstKey, secondKey := loaderPrivateKey(0x34), loaderPrivateKey(0x35)
	clock := &authorityTestClock{now: time.Date(2026, 8, 8, 5, 0, 0, 0, time.UTC)}
	loader := newLoaderFixture(t, clock, map[string]ed25519.PublicKey{
		"geo-key-1": firstKey.Public().(ed25519.PublicKey), "geo-key-2": secondKey.Public().(ed25519.PublicKey),
	}, 1<<20, 1<<20)
	first := loaderSnapshotFromCurrent(t, firstKey, "geo-key-1", 1, clock.Now())
	second := loaderSnapshotFromCurrent(t, secondKey, "geo-key-2", 2, clock.Now())
	if err := loader.Poll(t.Context(), writeSignedArtifact(t, t.TempDir(), "first.json", first, 0o600)); err != nil {
		t.Fatal(err)
	}
	if err := loader.Poll(t.Context(), writeSignedArtifact(t, t.TempDir(), "second.json", second, 0o600)); err != nil {
		t.Fatal(err)
	}
	rollback := loaderSnapshotFromCurrent(t, firstKey, "geo-key-1", 1, clock.Now().Add(time.Minute))
	if err := loader.Poll(t.Context(), writeSignedArtifact(t, t.TempDir(), "rollback.json", rollback, 0o600)); !errors.Is(err, ErrAuthorityRevision) {
		t.Fatalf("rollback Poll() error = %v", err)
	}
	assertLoaderLKG(t, loader, 2, AuthorityReasonRevisionRejected)

	untrustedKey := loaderPrivateKey(0x36)
	untrusted := loaderSnapshotFromCurrent(t, untrustedKey, "geo-key-3", 3, clock.Now())
	if err := loader.Poll(t.Context(), writeSignedArtifact(t, t.TempDir(), "untrusted.json", untrusted, 0o600)); !errors.Is(err, ErrSignedFileUntrustedKey) {
		t.Fatalf("untrusted Poll() error = %v", err)
	}
	assertLoaderLKG(t, loader, 2, AuthorityReasonUntrustedKey)

	artifact := loaderArtifact(t, second)
	smallLoader := newLoaderFixture(t, clock, map[string]ed25519.PublicKey{"geo-key-2": secondKey.Public().(ed25519.PublicKey)}, int64(len(artifact)-1), 1<<20)
	if err := smallLoader.Poll(t.Context(), writeArtifactBytes(t, t.TempDir(), "oversized.json", artifact, 0o600)); !errors.Is(err, ErrSignedFileCapacity) {
		t.Fatalf("oversized artifact Poll() error = %v", err)
	}

	boundedCatalogLoader := newLoaderFixture(t, clock, map[string]ed25519.PublicKey{"geo-key-2": secondKey.Public().(ed25519.PublicKey)}, 1<<20, 64)
	if err := boundedCatalogLoader.Poll(t.Context(), writeSignedArtifact(t, t.TempDir(), "catalog-capacity.json", second, 0o600)); !errors.Is(err, ErrAuthorityCapacity) {
		t.Fatalf("catalog capacity Poll() error = %v", err)
	}
}

func newLoaderFixture(
	t *testing.T,
	clock *authorityTestClock,
	keys map[string]ed25519.PublicKey,
	maxArtifact int64,
	maxCatalog int,
) *SignedFileLoader {
	t.Helper()
	keyring, err := NewTrustedEd25519Keyring(keys)
	if err != nil {
		t.Fatal(err)
	}
	loader, err := NewSignedFileLoader(SignedFileLoaderConfig{
		Keyring: keyring, Now: clock.Now, MaxArtifactBytes: maxArtifact, MaxAggregateCatalogBytes: maxCatalog,
	})
	if err != nil {
		t.Fatal(err)
	}
	return loader
}

func loaderPrivateKey(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
}

func loaderSnapshotFromCurrent(t *testing.T, key ed25519.PrivateKey, keyID string, revision uint64, now time.Time) SignedAuthoritySnapshot {
	t.Helper()
	_, current := authorityCatalogInputs()
	return loaderSnapshot(t, key, keyID, revision, now.Add(time.Hour), []CatalogInput{current})
}

func loaderSnapshot(
	t *testing.T,
	key ed25519.PrivateKey,
	keyID string,
	revision uint64,
	expiresAt time.Time,
	catalogs []CatalogInput,
) SignedAuthoritySnapshot {
	t.Helper()
	snapshot := SignedAuthoritySnapshot{
		SchemaVersion: AuthoritySchemaV1, Revision: revision, KeyID: keyID,
		CurrentCatalogVersion: "geo-2026.08", ExpiresAt: expiresAt, Catalogs: catalogs,
	}
	resignAuthoritySnapshot(t, key, &snapshot)
	return snapshot
}

func loaderArtifact(t *testing.T, snapshot SignedAuthoritySnapshot) []byte {
	t.Helper()
	catalogs := make([]SignedCatalogArtifact, len(snapshot.Catalogs))
	for index, catalog := range snapshot.Catalogs {
		catalogs[index] = SignedCatalogArtifact{
			DataBase64: base64.StdEncoding.EncodeToString(catalog.Data), ExpectedSHA256: catalog.ExpectedSHA256,
		}
	}
	encoded, err := json.Marshal(SignedAuthorityArtifact{
		SchemaVersion: snapshot.SchemaVersion, Revision: snapshot.Revision, KeyID: snapshot.KeyID,
		CurrentCatalogVersion: snapshot.CurrentCatalogVersion, ExpiresAt: snapshot.ExpiresAt.Format(time.RFC3339Nano),
		Catalogs: catalogs, SignatureBase64: base64.StdEncoding.EncodeToString(snapshot.Signature),
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func writeSignedArtifact(t *testing.T, directory, name string, snapshot SignedAuthoritySnapshot, mode os.FileMode) FileTrigger {
	t.Helper()
	return writeArtifactBytes(t, directory, name, loaderArtifact(t, snapshot), mode)
}

func writeArtifactBytes(t *testing.T, directory, name string, data []byte, mode os.FileMode) FileTrigger {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	return FileTrigger{Path: path, ExpectedSHA256: hex.EncodeToString(digest[:])}
}

func assertLoaderLKG(t *testing.T, loader *SignedFileLoader, revision uint64, reason AuthorityReason) {
	t.Helper()
	result, err := loader.Lookup(t.Context(), "", netip.MustParseAddr("203.0.113.129"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Revision != revision || result.Attribution.Carrier != "specific" ||
		result.State != AuthorityStateLKG || result.Reason != reason {
		t.Fatalf("loader LKG = %#v", result)
	}
}
