package analyticsgeoartifact

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticsgeo"
	"github.com/google/uuid"
)

func TestReleaseStoreCommitReplayStateAndLoaderTrigger(t *testing.T) {
	fixture := newReleaseStoreFixture(t)
	request := fixture.request(t, 7, "", nil)
	candidate, err := fixture.store.Prepare(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.State(t.Context()); err == nil {
		t.Fatal("Prepare made an uncommitted candidate visible")
	}
	want := expectedReleaseFact(t, request, fixture.now)
	if candidate.Fact() != want || candidate.Trigger().ExpectedSHA256 != request.Artifact.SHA256 {
		t.Fatalf("prepared release = (%#v, %#v)", candidate.Fact(), candidate.Trigger())
	}
	if err := fixture.store.Commit(t.Context(), candidate); err != nil {
		t.Fatal(err)
	}

	state, err := fixture.store.State(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if state.Active != want || state.LKG != nil {
		t.Fatalf("state = %#v, want active %#v without LKG", state, want)
	}
	trigger := fixture.store.ArtifactTrigger(state.Active)
	if !filepath.IsAbs(trigger.Path) || trigger.ExpectedSHA256 != request.Artifact.SHA256 {
		t.Fatalf("trigger = %#v", trigger)
	}
	artifactBefore := exactFile(t, trigger.Path, request.Artifact.Bytes)
	releasePath := filepath.Join(fixture.directory, "releases", request.ReleaseID+".json")
	releaseBefore := canonicalFile(t, releasePath)
	statePath := filepath.Join(fixture.directory, "state.json")
	stateBefore := canonicalFile(t, statePath)

	replay, err := fixture.store.Prepare(t.Context(), request)
	commitErr := fixture.store.Commit(t.Context(), replay)
	if err != nil || commitErr != nil {
		t.Fatalf("exact replay = (%v, %v, %v)", replay, err, commitErr)
	}
	assertSameFileAndBytes(t, trigger.Path, artifactBefore, request.Artifact.Bytes)
	assertSameFileAndBytes(t, releasePath, releaseBefore.info, releaseBefore.data)
	assertSameFileAndBytes(t, statePath, stateBefore.info, stateBefore.data)
	if matches, _ := filepath.Glob(filepath.Join(fixture.directory, "**", "*.tmp")); len(matches) != 0 {
		t.Fatalf("temporary files remain: %v", matches)
	}

	keyring, err := analyticsgeo.NewTrustedEd25519Keyring(map[string]ed25519.PublicKey{"geo-publisher-1": fixture.publicKey})
	if err != nil {
		t.Fatal(err)
	}
	loader, err := analyticsgeo.NewSignedFileLoader(analyticsgeo.SignedFileLoaderConfig{
		Keyring: keyring, Now: func() time.Time { return fixture.now }, MaxArtifactBytes: 1 << 20,
		MaxAggregateCatalogBytes: 1 << 20,
	})
	if err != nil || loader.Poll(t.Context(), trigger) != nil {
		t.Fatalf("loader trigger = (%#v, %v)", trigger, err)
	}
}

func TestReleaseStoreRevisionConflictDurableLKGAndRestart(t *testing.T) {
	fixture := newReleaseStoreFixture(t)
	first := fixture.request(t, 7, "", nil)
	commitRelease(t, fixture.store, first)

	sameRevision := fixture.request(t, 7, "", func(request *CompileRequest) {
		request.Catalogs[1].Entries[0].Carrier = "changed"
	})
	if candidate, err := fixture.store.Prepare(t.Context(), sameRevision); err == nil {
		if err := fixture.store.Commit(t.Context(), candidate); err == nil {
			t.Fatal("same revision changed content committed")
		}
	}
	lower := fixture.request(t, 6, "", nil)
	if candidate, err := fixture.store.Prepare(t.Context(), lower); err == nil {
		if err := fixture.store.Commit(t.Context(), candidate); err == nil {
			t.Fatal("lower revision committed")
		}
	}

	fixture.clock = fixture.clock.Add(time.Minute)
	second := fixture.request(t, 8, "", func(request *CompileRequest) {
		request.Catalogs[1].Entries[0].Carrier = "changed"
	})
	commitRelease(t, fixture.store, second)
	state, err := fixture.store.State(t.Context())
	if err != nil || state.Active.ReleaseID != second.ReleaseID || state.Active.Revision != 8 || state.LKG == nil ||
		state.LKG.ReleaseID != first.ReleaseID || state.LKG.Revision != 7 {
		t.Fatalf("second state = (%#v, %v)", state, err)
	}

	restarted, err := NewReleaseStore(fixture.config())
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := restarted.State(t.Context())
	if err != nil || !reflect.DeepEqual(reloaded, state) {
		t.Fatalf("restart state = (%#v, %v), want %#v", reloaded, err, state)
	}
}

func TestReleaseStoreRollbackRequiresHistoricalContentAtHigherRevision(t *testing.T) {
	fixture := newReleaseStoreFixture(t)
	first := fixture.request(t, 7, "", nil)
	commitRelease(t, fixture.store, first)
	fixture.clock = fixture.clock.Add(time.Minute)
	second := fixture.request(t, 8, "", func(request *CompileRequest) {
		request.Catalogs[1].Entries[0].Carrier = "changed"
	})
	commitRelease(t, fixture.store, second)

	wrongContent := fixture.request(t, 9, first.ReleaseID, func(request *CompileRequest) {
		request.Catalogs[1].Entries[0].Carrier = "changed"
	})
	if candidate, err := fixture.store.Prepare(t.Context(), wrongContent); err == nil {
		if err := fixture.store.Commit(t.Context(), candidate); err == nil {
			t.Fatal("rollback with content different from its target committed")
		}
	}
	missingTarget := fixture.request(t, 9, uuid.NewString(), nil)
	if candidate, err := fixture.store.Prepare(t.Context(), missingTarget); err == nil {
		if err := fixture.store.Commit(t.Context(), candidate); err == nil {
			t.Fatal("rollback to an unknown release committed")
		}
	}

	fixture.clock = fixture.clock.Add(time.Minute)
	rollback := fixture.request(t, 9, first.ReleaseID, nil)
	commitRelease(t, fixture.store, rollback)
	state, err := fixture.store.State(t.Context())
	firstFact := expectedReleaseFact(t, first, fixture.now)
	rollbackFact := expectedReleaseFact(t, rollback, fixture.clock)
	if err != nil || state.Active.ReleaseID != rollback.ReleaseID || state.Active.RollbackOf != first.ReleaseID ||
		state.Active.ContentSHA256 != firstFact.ContentSHA256 || state.Active.ContentSHA256 != rollbackFact.ContentSHA256 ||
		state.Active.ArtifactSHA256 == firstFact.ArtifactSHA256 || state.LKG == nil || state.LKG.ReleaseID != second.ReleaseID {
		t.Fatalf("rollback state = (%#v, %v)", state, err)
	}
}

func TestReleaseStoreRejectsUntrustedTamperedOversizedAndCorruptState(t *testing.T) {
	fixture := newReleaseStoreFixture(t)
	valid := fixture.request(t, 7, "", nil)

	untrustedConfig := fixture.config()
	untrustedConfig.Directory = t.TempDir()
	otherPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, ed25519.SeedSize))
	untrustedConfig.TrustedKeys = map[string]ed25519.PublicKey{"other-key": otherPrivate.Public().(ed25519.PublicKey)}
	untrusted, err := NewReleaseStore(untrustedConfig)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := untrusted.Prepare(t.Context(), valid); err == nil {
		t.Fatal("artifact signed by an unknown key was accepted")
	}

	for _, request := range []ReleaseRequest{
		withUnknownArtifactField(t, valid),
		withTamperedSignature(t, valid),
		withArtifactMetadataMismatch(valid),
		withInvalidSource(valid),
	} {
		if _, err := fixture.store.Prepare(t.Context(), request); err == nil {
			t.Fatalf("invalid release request was accepted: %#v", request)
		}
	}
	smallConfig := fixture.config()
	smallConfig.Directory = t.TempDir()
	smallConfig.MaxArtifactBytes = int64(len(valid.Artifact.Bytes) - 1)
	small, err := NewReleaseStore(smallConfig)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := small.Prepare(t.Context(), valid); err == nil {
		t.Fatal("oversized artifact was accepted")
	}

	commitRelease(t, fixture.store, valid)
	state, err := fixture.store.State(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	trigger := fixture.store.ArtifactTrigger(state.Active)
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, valid.Artifact.Bytes, 0o600); err != nil || os.Remove(trigger.Path) != nil ||
		os.Symlink(target, trigger.Path) != nil {
		t.Fatal("replace artifact with symlink")
	}
	if _, err := fixture.store.State(t.Context()); err == nil {
		t.Fatal("symlink artifact was accepted")
	}

	corrupt := newReleaseStoreFixture(t)
	release := corrupt.request(t, 7, "", nil)
	commitRelease(t, corrupt.store, release)
	releasePath := filepath.Join(corrupt.directory, "releases", release.ReleaseID+".json")
	if err := os.WriteFile(releasePath, []byte(`{"unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := corrupt.store.State(t.Context()); err == nil {
		t.Fatal("corrupt release fact was accepted")
	}

	realDirectory := t.TempDir()
	linkedDirectory := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(realDirectory, linkedDirectory); err != nil {
		t.Fatal(err)
	}
	linkedConfig := fixture.config()
	linkedConfig.Directory = linkedDirectory
	if _, err := NewReleaseStore(linkedConfig); err == nil {
		t.Fatal("symlink store directory was accepted")
	}
}

type releaseStoreFixture struct {
	store     *ReleaseStore
	directory string
	publicKey ed25519.PublicKey
	issuedAt  time.Time
	now       time.Time
	clock     time.Time
}

func newReleaseStoreFixture(t *testing.T) *releaseStoreFixture {
	t.Helper()
	_, privateKey := newCompilerFixture(t, 16, 100, 1<<20, 1<<20)
	issuedAt := time.Date(2026, 8, 8, 8, 0, 0, 0, time.UTC)
	fixture := &releaseStoreFixture{directory: t.TempDir(), publicKey: privateKey.Public().(ed25519.PublicKey),
		issuedAt: issuedAt, now: issuedAt.Add(5 * time.Minute), clock: issuedAt.Add(5 * time.Minute)}
	store, err := NewReleaseStore(fixture.config())
	if err != nil {
		t.Fatal(err)
	}
	fixture.store = store
	return fixture
}

func (fixture *releaseStoreFixture) config() ReleaseStoreConfig {
	return ReleaseStoreConfig{Directory: fixture.directory, MaxArtifactBytes: 1 << 20,
		Now: func() time.Time { return fixture.clock }, TrustedKeys: map[string]ed25519.PublicKey{"geo-publisher-1": fixture.publicKey}}
}

func (fixture *releaseStoreFixture) request(t *testing.T, revision uint64, rollbackOf string, mutate func(*CompileRequest)) ReleaseRequest {
	t.Helper()
	compiler, _ := newCompilerFixture(t, 16, 100, 1<<20, 1<<20)
	compileRequest := validCompileRequest(fixture.issuedAt)
	compileRequest.Revision = revision
	compileRequest.Catalogs = cloneCatalogs(compileRequest.Catalogs)
	if mutate != nil {
		mutate(&compileRequest)
	}
	artifact, err := compiler.Compile(t.Context(), compileRequest)
	if err != nil {
		t.Fatal(err)
	}
	sourceDigest := sha256.Sum256([]byte("fixture-source"))
	return ReleaseRequest{ReleaseID: uuid.NewString(), Artifact: artifact,
		Source: SourceRef{Provider: "fixture", Version: "2026.08", SHA256: hex.EncodeToString(sourceDigest[:])}, RollbackOf: rollbackOf}
}

func commitRelease(t *testing.T, store *ReleaseStore, request ReleaseRequest) {
	t.Helper()
	candidate, err := store.Prepare(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(t.Context(), candidate); err != nil {
		t.Fatal(err)
	}
}

func expectedReleaseFact(t *testing.T, request ReleaseRequest, createdAt time.Time) ReleaseFact {
	t.Helper()
	var wire signedAuthorityArtifact
	if err := json.Unmarshal(request.Artifact.Bytes, &wire); err != nil {
		t.Fatal(err)
	}
	current, content := releaseContentDigests(t, wire)
	signature, err := base64.StdEncoding.Strict().DecodeString(wire.SignatureBase64)
	if err != nil {
		t.Fatal(err)
	}
	signatureDigest := sha256.Sum256(signature)
	return ReleaseFact{ReleaseID: request.ReleaseID, Revision: wire.Revision, Source: request.Source, KeyID: wire.KeyID,
		CatalogVersion: wire.CurrentCatalogVersion, CurrentCatalogSHA256: current, ArtifactSHA256: request.Artifact.SHA256,
		ContentSHA256: content, SignatureSHA256: hex.EncodeToString(signatureDigest[:]), IssuedAt: request.Artifact.IssuedAt,
		ExpiresAt: request.Artifact.ExpiresAt, CreatedAt: createdAt, RollbackOf: request.RollbackOf}
}

func releaseContentDigests(t *testing.T, wire signedAuthorityArtifact) (string, string) {
	t.Helper()
	type contentCatalog struct {
		Version string `json:"version"`
		SHA256  string `json:"sha256"`
	}
	type contentIdentity struct {
		CurrentCatalogVersion string           `json:"current_catalog_version"`
		Catalogs              []contentCatalog `json:"catalogs"`
	}
	identity := contentIdentity{CurrentCatalogVersion: wire.CurrentCatalogVersion}
	current := ""
	for _, encoded := range wire.Catalogs {
		data, err := base64.StdEncoding.Strict().DecodeString(encoded.DataBase64)
		if err != nil {
			t.Fatal(err)
		}
		var catalog catalogDocument
		if err := json.Unmarshal(data, &catalog); err != nil {
			t.Fatal(err)
		}
		identity.Catalogs = append(identity.Catalogs, contentCatalog{Version: catalog.Version, SHA256: encoded.ExpectedSHA256})
		if catalog.Version == wire.CurrentCatalogVersion {
			current = encoded.ExpectedSHA256
		}
	}
	sort.Slice(identity.Catalogs, func(left, right int) bool { return identity.Catalogs[left].Version < identity.Catalogs[right].Version })
	encoded, err := json.Marshal(identity)
	if err != nil || current == "" {
		t.Fatalf("content identity = (%s, %v)", current, err)
	}
	digest := sha256.Sum256(encoded)
	return current, hex.EncodeToString(digest[:])
}

type exactFileState struct {
	info os.FileInfo
	data []byte
}

func exactFile(t *testing.T, path string, want []byte) os.FileInfo {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("file %s = (%v, %v)", path, info, err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, want) {
		t.Fatalf("file %s differs from exact artifact", path)
	}
	return info
}

func canonicalFile(t *testing.T, path string) exactFileState {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("file %s = (%v, %v)", path, info, err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !json.Valid(data) {
		t.Fatalf("canonical file %s = (%q, %v)", path, data, err)
	}
	var value any
	if filepath.Base(path) == releaseStateFilename {
		var state ReleaseState
		if json.Unmarshal(data, &state) != nil {
			t.Fatalf("decode canonical file %s", path)
		}
		value = state
	} else {
		var fact ReleaseFact
		if json.Unmarshal(data, &fact) != nil {
			t.Fatalf("decode canonical file %s", path)
		}
		value = fact
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, data) {
		t.Fatalf("non-canonical file %s", path)
	}
	return exactFileState{info: info, data: data}
}

func assertSameFileAndBytes(t *testing.T, path string, before os.FileInfo, want []byte) {
	t.Helper()
	after, err := os.Lstat(path)
	data, readErr := os.ReadFile(path)
	if err != nil || readErr != nil || !os.SameFile(before, after) || !bytes.Equal(data, want) {
		t.Fatalf("immutable file %s changed: stat=%v read=%v", path, err, readErr)
	}
}

func withUnknownArtifactField(t *testing.T, request ReleaseRequest) ReleaseRequest {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(request.Artifact.Bytes, &object); err != nil {
		t.Fatal(err)
	}
	object["unknown"] = json.RawMessage(`true`)
	return withArtifactBytes(t, request, object)
}

func withTamperedSignature(t *testing.T, request ReleaseRequest) ReleaseRequest {
	t.Helper()
	var wire signedAuthorityArtifact
	if err := json.Unmarshal(request.Artifact.Bytes, &wire); err != nil {
		t.Fatal(err)
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(wire.SignatureBase64)
	if err != nil {
		t.Fatal(err)
	}
	signature[0] ^= 1
	wire.SignatureBase64 = base64.StdEncoding.EncodeToString(signature)
	return withArtifactBytes(t, request, wire)
}

func withArtifactBytes(t *testing.T, request ReleaseRequest, value any) ReleaseRequest {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	request.Artifact.Bytes = data
	request.Artifact.SHA256 = hex.EncodeToString(digest[:])
	return request
}

func withArtifactMetadataMismatch(request ReleaseRequest) ReleaseRequest {
	request.Artifact.Revision++
	return request
}

func withInvalidSource(request ReleaseRequest) ReleaseRequest {
	request.Source.SHA256 = "not-a-digest"
	return request
}
