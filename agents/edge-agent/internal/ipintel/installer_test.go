package ipintel

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	format "github.com/cdnca/cdnca/libs/entitlement/ipintel"
)

var testNow = time.Date(2026, 10, 17, 8, 0, 0, 0, time.UTC)

// library builds a format v2 artifact (the bytes an artifact set item holds).
func library(t *testing.T, revision uint64, asn uint32) []byte {
	t.Helper()
	artifact, err := format.Build(format.BuildInput{Revision: revision, BuildID: buildID(revision),
		GeneratedAt: testNow.Add(-time.Hour), DataUpdatedAt: testNow.Add(-2 * time.Hour), StaleAfter: testNow.Add(30 * 24 * time.Hour),
		SourceRelease: "ipx-test", Notice: "test",
		Sources: []format.Source{{ID: "geo", Name: "test", URL: "https://example.invalid", License: "CC0-1.0", Ref: "1", Role: "asn"}},
		Facts: []format.Fact{{Prefix: netip.MustParsePrefix("1.0.1.0/24"), ASN: asn, Country: "CN"},
			{Prefix: netip.MustParsePrefix("240e::/20"), ASN: 4134, Country: "CN"}}})
	if err != nil {
		t.Fatal(err)
	}
	return artifact.Bytes
}

func buildID(revision uint64) string { return fmt.Sprintf("ipintel-20261017-%06d", revision) }

// expect is the set item naming library(revision).
func expect(revision uint64) Expected {
	return Expected{Revision: revision, BuildID: buildID(revision)}
}

func newInstaller(t *testing.T) (*Installer, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "ip-intel")
	installer, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	return installer, root
}

func install(t *testing.T, installer *Installer, content []byte, revision uint64) (State, func() error) {
	t.Helper()
	staged, err := installer.Prepare(content, expect(revision), testNow)
	if err != nil {
		t.Fatal(err)
	}
	undo, err := staged.Commit()
	if err != nil {
		t.Fatal(err)
	}
	state, err := installer.Current()
	if err != nil || state == nil {
		t.Fatalf("Current after commit = %+v, %v", state, err)
	}
	return *state, undo
}

func TestPrepareCommitSwitchesAndKeepsLKG(t *testing.T) {
	installer, root := newInstaller(t)
	if state, err := installer.Current(); err != nil || state != nil {
		t.Fatalf("empty: %+v %v", state, err)
	}
	first := library(t, 1, 4134)
	state, _ := install(t, installer, first, 1)
	if state.Revision != 1 || state.BuildID != buildID(1) || state.PreviousRevision != 0 || state.ArtifactSHA256 == "" {
		t.Fatalf("first state = %+v", state)
	}
	if active, _ := os.ReadFile(filepath.Join(root, CurrentFile)); !bytes.Equal(active, first) {
		t.Fatal("current.ipi is not the installed artifact")
	}
	second := library(t, 2, 4837)
	state, _ = install(t, installer, second, 2)
	if state.Revision != 2 || state.PreviousRevision != 1 {
		t.Fatalf("second state = %+v", state)
	}
	if previous, _ := os.ReadFile(filepath.Join(root, PreviousFile)); !bytes.Equal(previous, first) {
		t.Fatal("previous.ipi is not the replaced library")
	}
}

func TestAbortLeavesTheActiveLibrary(t *testing.T) {
	installer, root := newInstaller(t)
	install(t, installer, library(t, 1, 4134), 1)
	staged, err := installer.Prepare(library(t, 2, 4837), expect(2), testNow)
	if err != nil {
		t.Fatal(err)
	}
	staged.Abort()
	if state, _ := installer.Current(); state == nil || state.Revision != 1 {
		t.Fatalf("after abort = %+v", state)
	}
	entries, _ := os.ReadDir(root)
	for _, entry := range entries {
		if entry.Name() != CurrentFile && entry.Name() != StateFile {
			t.Fatalf("abort left %s behind", entry.Name())
		}
	}
}

func TestPrepareRejectsInvalidOrOlderContent(t *testing.T) {
	installer, _ := newInstaller(t)
	install(t, installer, library(t, 2, 4134), 2)
	// Open digests the table region (data_sha256); the whole file, metadata
	// included, is bound by the signed set item's sha256, which the set
	// executor checks before Prepare.
	corrupt := library(t, 3, 4134)
	corrupt[format.HeaderSize] ^= 0xff
	cases := map[string]struct {
		content  []byte
		expected Expected
	}{
		"corrupt":       {corrupt, expect(3)},
		"older":         {library(t, 1, 4134), expect(1)},
		"empty":         {nil, expect(3)},
		"other build":   {library(t, 3, 4134), Expected{Revision: 3, BuildID: "ipintel-other"}},
		"item revision": {library(t, 3, 4134), Expected{Revision: 4, BuildID: buildID(3)}},
	}
	for name, test := range cases {
		if _, err := installer.Prepare(test.content, test.expected, testNow); !errors.Is(err, ErrRejected) {
			t.Errorf("%s: Prepare error = %v, want ErrRejected", name, err)
		}
	}
	if state, _ := installer.Current(); state == nil || state.Revision != 2 {
		t.Fatalf("rejections changed the library: %+v", state)
	}
}

func TestSameLibraryIsANoOp(t *testing.T) {
	installer, _ := newInstaller(t)
	content := library(t, 1, 4134)
	install(t, installer, content, 1)
	state, _ := install(t, installer, content, 1)
	if state.Revision != 1 || state.PreviousRevision != 0 {
		t.Fatalf("redelivery changed state: %+v", state)
	}
}

func TestUndoRestoresThePreviousLibrary(t *testing.T) {
	installer, root := newInstaller(t)
	first := library(t, 1, 4134)
	install(t, installer, first, 1)
	_, undo := install(t, installer, library(t, 2, 4837), 2)
	if err := undo(); err != nil {
		t.Fatal(err)
	}
	if state, _ := installer.Current(); state == nil || state.Revision != 1 {
		t.Fatalf("after undo = %+v", state)
	}
	if active, _ := os.ReadFile(filepath.Join(root, CurrentFile)); !bytes.Equal(active, first) {
		t.Fatal("undo did not restore current.ipi")
	}
	// Undo of a first install removes the library again.
	empty, _ := newInstaller(t)
	_, undo = install(t, empty, first, 1)
	if err := undo(); err != nil {
		t.Fatal(err)
	}
	if state, err := empty.Current(); err != nil || state != nil {
		t.Fatalf("undo of first install = %+v, %v", state, err)
	}
}

func TestRemoveUninstalls(t *testing.T) {
	installer, root := newInstaller(t)
	install(t, installer, library(t, 1, 4134), 1)
	if err := installer.Remove(); err != nil {
		t.Fatal(err)
	}
	if state, err := installer.Current(); err != nil || state != nil {
		t.Fatalf("after remove = %+v, %v", state, err)
	}
	if _, err := os.Stat(filepath.Join(root, CurrentFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("current.ipi still present: %v", err)
	}
	if err := installer.Remove(); err != nil {
		t.Fatalf("second remove: %v", err)
	}
}

func TestDamagedLibraryIsNotReported(t *testing.T) {
	installer, root := newInstaller(t)
	install(t, installer, library(t, 1, 4134), 1)
	if err := os.WriteFile(filepath.Join(root, CurrentFile), []byte("damaged"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := installer.Current(); !errors.Is(err, ErrRejected) {
		t.Fatalf("damaged library error = %v", err)
	}
}

// Base and local libraries have their own revision sequences: switching to
// the other artifact is accepted whatever the revision (the control plane
// picked the one with newer data); within one artifact revisions only move
// forward; undo restores the other artifact's library.
func TestSwitchBetweenBaseAndLocalLibraries(t *testing.T) {
	installer, _ := newInstaller(t)
	install(t, installer, library(t, 5, 4134), 5)
	local := func(revision uint64) Expected {
		return Expected{ArtifactID: "ipintel/local", Revision: revision, BuildID: buildID(revision)}
	}
	staged, err := installer.Prepare(library(t, 1, 4837), local(1), testNow)
	if err != nil {
		t.Fatalf("switch to local revision 1 over base revision 5: %v", err)
	}
	undo, err := staged.Commit()
	if err != nil {
		t.Fatal(err)
	}
	state, _ := installer.Current()
	if state == nil || state.ArtifactID != "ipintel/local" || state.Revision != 1 || state.PreviousRevision != 5 {
		t.Fatalf("after switch: %+v", state)
	}
	if _, err := installer.Prepare(library(t, 1, 4134), local(1), testNow); !errors.Is(err, ErrRejected) {
		t.Fatalf("other bytes at the same local revision: %v", err)
	}
	if err := undo(); err != nil {
		t.Fatal(err)
	}
	if state, _ := installer.Current(); state == nil || artifactOf(state) != DefaultArtifactID || state.Revision != 5 {
		t.Fatalf("after undo: %+v", state)
	}
	// Local revision 9, then back to base at a lower revision than the local one.
	staged, err = installer.Prepare(library(t, 9, 4134), local(9), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := staged.Commit(); err != nil {
		t.Fatal(err)
	}
	staged, err = installer.Prepare(library(t, 6, 4134), Expected{ArtifactID: DefaultArtifactID, Revision: 6, BuildID: buildID(6)}, testNow)
	if err != nil {
		t.Fatalf("back to base revision 6 over local revision 9: %v", err)
	}
	staged.Abort()
}
