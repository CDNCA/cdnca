package objectstore

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func openTemp(t *testing.T) *Store {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "objects"))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestPutGetUsesContentAddressedLayout(t *testing.T) {
	store := openTemp(t)
	content := []byte("site object")
	digest := digestOf(content)
	if err := store.Put(digest, content); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(store.Root(), "sha256", digest[:2], digest[2:4], digest)
	if store.Path(digest) != want {
		t.Fatalf("path = %s, want %s", store.Path(digest), want)
	}
	info, err := os.Stat(want)
	if err != nil || info.Mode().Perm() != 0o400 {
		t.Fatalf("object file = %v %v", info, err)
	}
	got, err := store.Get(digest)
	if err != nil || string(got) != string(content) {
		t.Fatalf("get = %q %v", got, err)
	}
	// Writing the same object again is a no-op success.
	if err := store.Put(digest, content); err != nil {
		t.Fatal(err)
	}
}

func TestPutRejectsContentThatIsNotTheDigest(t *testing.T) {
	store := openTemp(t)
	digest := digestOf([]byte("expected"))
	if err := store.Put(digest, []byte("other")); !errors.Is(err, ErrDigest) {
		t.Fatalf("err = %v", err)
	}
	if store.Has(digest) {
		t.Fatal("rejected object was stored")
	}
	for _, bad := range []string{"", "ABC", digest[:63], digest + "0", "../" + digest[3:]} {
		if err := store.Put(bad, nil); !errors.Is(err, ErrDigest) {
			t.Fatalf("Put(%q) err = %v", bad, err)
		}
	}
}

func TestGetDropsACorruptedObject(t *testing.T) {
	store := openTemp(t)
	content := []byte("bucket")
	digest := digestOf(content)
	if err := store.Put(digest, content); err != nil {
		t.Fatal(err)
	}
	path := store.Path(digest)
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(digest); !errors.Is(err, ErrDigest) {
		t.Fatalf("err = %v", err)
	}
	if store.Has(digest) {
		t.Fatal("corrupted object kept")
	}
	if _, err := store.Get(digest); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestMissingReportsAbsentAndCorruptedObjectsOnce(t *testing.T) {
	store := openTemp(t)
	present, absent, corrupt := []byte("a"), []byte("b"), []byte("c")
	for _, content := range [][]byte{present, corrupt} {
		if err := store.Put(digestOf(content), content); err != nil {
			t.Fatal(err)
		}
	}
	path := store.Path(digestOf(corrupt))
	_ = os.Chmod(path, 0o600)
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing, err := store.Missing([]string{digestOf(absent), digestOf(present), digestOf(corrupt), digestOf(absent)})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{digestOf(absent), digestOf(corrupt)}
	if !slices.Equal(missing, want) {
		t.Fatalf("missing = %v, want %v", missing, want)
	}
}

func TestCommitKeepsCurrentAndPreviousGenerationsAndCollectsTheRest(t *testing.T) {
	store := openTemp(t)
	put := func(value string) string {
		content := []byte(value)
		digest := digestOf(content)
		if err := store.Put(digest, content); err != nil {
			t.Fatal(err)
		}
		return digest
	}
	one, two, shared := put("one"), put("two"), put("shared")
	other := put("other owner")
	orphan := put("orphan")
	if err := store.Commit("artifactset", []string{other}); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit("scope-a", []string{one, shared}); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit("scope-a", []string{two, shared}); err != nil {
		t.Fatal(err)
	}
	removed, err := store.Collect()
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 || store.Has(orphan) || !store.Has(one) || !store.Has(two) || !store.Has(shared) || !store.Has(other) {
		t.Fatalf("after second generation removed=%d one=%v two=%v orphan=%v", removed, store.Has(one), store.Has(two), store.Has(orphan))
	}
	three := put("three")
	if err := store.Commit("scope-a", []string{three}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Collect(); err != nil {
		t.Fatal(err)
	}
	if store.Has(one) || !store.Has(two) || !store.Has(three) || !store.Has(shared) || !store.Has(other) {
		t.Fatalf("after third generation one=%v two=%v three=%v shared=%v", store.Has(one), store.Has(two), store.Has(three), store.Has(shared))
	}
	// Re-committing the same set (a redelivered release) keeps the previous one.
	if err := store.Commit("scope-a", []string{three}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Collect(); err != nil {
		t.Fatal(err)
	}
	if !store.Has(two) {
		t.Fatal("re-committing the current generation dropped the previous one")
	}
	// The references survive a restart.
	reopened, err := Open(store.Root())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Collect(); err != nil {
		t.Fatal(err)
	}
	if !reopened.Has(two) || !reopened.Has(three) || !reopened.Has(other) {
		t.Fatal("references were not persisted")
	}
}

func TestCommitRequiresEveryObject(t *testing.T) {
	store := openTemp(t)
	if err := store.Commit("scope-a", []string{digestOf([]byte("absent"))}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	if err := store.Commit("../escape", nil); !errors.Is(err, ErrOwner) {
		t.Fatalf("err = %v", err)
	}
}

func TestStagedObjectsSurviveCollection(t *testing.T) {
	store := openTemp(t)
	content := []byte("being fetched")
	digest := digestOf(content)
	release := store.Stage([]string{digest})
	if err := store.Put(digest, content); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Collect(); err != nil {
		t.Fatal(err)
	}
	if !store.Has(digest) {
		t.Fatal("staged object collected")
	}
	release()
	if _, err := store.Collect(); err != nil {
		t.Fatal(err)
	}
	if store.Has(digest) {
		t.Fatal("unstaged unreferenced object kept")
	}
}

func TestOpenRemovesInterruptedWrites(t *testing.T) {
	store := openTemp(t)
	temp := filepath.Join(store.Root(), "tmp", "put-123")
	if err := os.WriteFile(temp, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(store.Root()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(temp); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temp file = %v", err)
	}
}

func TestOpenRejectsUnsafeRoots(t *testing.T) {
	dir := t.TempDir()
	for _, root := range []string{"", "relative/objects", "/", dir + "/../x"} {
		if _, err := Open(root); err == nil {
			t.Fatalf("Open(%q) accepted", root)
		}
	}
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(link); err == nil {
		t.Fatal("symlink root accepted")
	}
}

func TestOpenSharedMakesObjectsGroupReadable(t *testing.T) {
	gid := os.Getgid()
	root := filepath.Join(t.TempDir(), "objects")
	store, err := OpenShared(root, gid)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("shared site object")
	digest := digestOf(content)
	if err := store.Put(digest, content); err != nil {
		t.Fatal(err)
	}
	for path, mode := range map[string]os.FileMode{
		root: 0o750, filepath.Join(root, "sha256"): 0o750,
		filepath.Dir(filepath.Dir(store.Path(digest))): 0o750, filepath.Dir(store.Path(digest)): 0o750,
		store.Path(digest): 0o440, filepath.Join(root, "refs"): 0o700, filepath.Join(root, "tmp"): 0o700,
	} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != mode {
			t.Fatalf("%s mode = %v %v, want %v", path, info.Mode().Perm(), err, mode)
		}
	}
	if _, err := OpenShared(root, -1); !errors.Is(err, ErrRoot) {
		t.Fatalf("OpenShared without a group = %v", err)
	}
}
