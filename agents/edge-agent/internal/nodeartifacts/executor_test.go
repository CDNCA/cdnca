package nodeartifacts

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/objectstore"
	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	"github.com/klauspost/compress/zstd"
)

const nodeID = "6f1c1b7e-2d0a-4d5e-9b51-0d3c9a7d2e11"

var now = time.Date(2026, 10, 18, 1, 0, 0, 0, time.UTC)

// fakeInstaller records commits; content "bad" is rejected at Prepare and
// "boom" fails at Commit.
type fakeInstaller struct {
	active  []byte
	removed int
}

type fakeStaged struct {
	installer *fakeInstaller
	content   []byte
}

func (installer *fakeInstaller) Prepare(_ artifactset.Item, content []byte, _ time.Time) (Staged, error) {
	if string(content) == "bad" {
		return nil, errors.New("not a library")
	}
	return &fakeStaged{installer: installer, content: content}, nil
}

func (installer *fakeInstaller) Remove() error {
	installer.active, installer.removed = nil, installer.removed+1
	return nil
}

func (staged *fakeStaged) Abort() {}
func (staged *fakeStaged) Commit() (func() error, error) {
	if string(staged.content) == "boom" {
		return nil, errors.New("activation failed")
	}
	previous := staged.installer.active
	staged.installer.active = staged.content
	return func() error { staged.installer.active = previous; return nil }, nil
}

type fixture struct {
	executor  *Executor
	store     *objectstore.Store
	installer *fakeInstaller
	root      string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	root := t.TempDir()
	store, err := objectstore.Open(filepath.Join(root, "objects"))
	if err != nil {
		t.Fatal(err)
	}
	installer := &fakeInstaller{}
	executor, err := New(Config{NodeID: nodeID, StateDir: filepath.Join(root, "artifact-set"), Objects: store,
		Installers: map[string]Installer{artifactset.MediaTypeIPIntel: installer}})
	if err != nil {
		t.Fatal(err)
	}
	return fixture{executor: executor, store: store, installer: installer, root: root}
}

// item compresses content, splits it into 4-byte segments and, when put,
// stores the segments.
func (f fixture) item(t *testing.T, version string, content []byte, put bool) artifactset.Item {
	t.Helper()
	encoder, _ := zstd.NewWriter(nil)
	compressed := encoder.EncodeAll(content, nil)
	revision, err := strconv.ParseUint(version, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	item := artifactset.Item{ArtifactID: "ipintel/base", Version: version, Revision: revision, MediaType: artifactset.MediaTypeIPIntel,
		SHA256: artifactset.Digest(content), Size: int64(len(content)), Compression: artifactset.CompressionZstd,
		CompressedSHA256: artifactset.Digest(compressed), CompressedSize: int64(len(compressed)),
		Encryption: artifactset.EncryptionNone}
	size := (len(compressed) + 2) / 3
	for _, segment := range artifactset.SplitSegments(compressed, size) {
		item.Segments = append(item.Segments, artifactset.Segment{SHA256: artifactset.Digest(segment), Size: int64(len(segment))})
		if put {
			if err := f.store.Put(artifactset.Digest(segment), segment); err != nil {
				t.Fatal(err)
			}
		}
	}
	return item
}

func set(revision uint64, items ...artifactset.Item) artifactset.Set {
	if items == nil {
		items = []artifactset.Item{}
	}
	return artifactset.Set{NodeID: nodeID, Revision: revision, Items: items}
}

func digestOf(revision uint64) string { return artifactset.Digest([]byte{byte(revision)}) }

func apply(t *testing.T, f fixture, desired artifactset.Set) artifactset.Receipt {
	t.Helper()
	receipt, err := f.executor.Apply(desired, digestOf(desired.Revision), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := artifactset.EncodeReceipt(receipt); err != nil {
		t.Fatalf("receipt is not valid: %v (%+v)", err, receipt)
	}
	return receipt
}

func TestApplySwitchesTheWholeSet(t *testing.T) {
	f := newFixture(t)
	receipt := apply(t, f, set(1, f.item(t, "1", []byte("library one"), true)))
	if receipt.Result != artifactset.ResultApplied || receipt.ActiveRevision != 1 || len(receipt.Items) != 1 ||
		receipt.Items[0].Result != artifactset.ResultApplied {
		t.Fatalf("receipt = %+v", receipt)
	}
	if !bytes.Equal(f.installer.active, []byte("library one")) {
		t.Fatalf("installed = %q", f.installer.active)
	}
	if active := f.executor.Active(); active == nil || active.Revision != 1 || !f.executor.HasItem(artifactset.MediaTypeIPIntel) {
		t.Fatalf("Active = %+v", active)
	}
	// The same set again is applied without touching the installer.
	f.installer.active = []byte("sentinel")
	if receipt := apply(t, f, set(1, f.item(t, "1", []byte("library one"), true))); receipt.Result != artifactset.ResultApplied {
		t.Fatalf("redelivery receipt = %+v", receipt)
	}
	if string(f.installer.active) != "sentinel" {
		t.Fatal("redelivery reinstalled the item")
	}
}

func TestMissingSegmentIsPendingAndKeepsLKG(t *testing.T) {
	f := newFixture(t)
	apply(t, f, set(1, f.item(t, "1", []byte("library one"), true)))
	receipt := apply(t, f, set(2, f.item(t, "2", []byte("library two"), false)))
	if receipt.Result != artifactset.ResultPending || receipt.ActiveRevision != 1 ||
		receipt.Items[0].Result != artifactset.ResultPending || receipt.Items[0].Reason != artifactset.ReasonObjectMissing {
		t.Fatalf("receipt = %+v", receipt)
	}
	if !bytes.Equal(f.installer.active, []byte("library one")) || f.executor.Active().Revision != 1 {
		t.Fatal("a pending set changed the active set")
	}
}

func TestTamperedSegmentIsRejectedAndKeepsLKG(t *testing.T) {
	f := newFixture(t)
	apply(t, f, set(1, f.item(t, "1", []byte("library one"), true)))
	item := f.item(t, "2", []byte("library two with more bytes"), true)
	// Objects are read-only files in an owner-writable directory.
	path := f.store.Path(item.Segments[1].SHA256)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	receipt := apply(t, f, set(2, item))
	if receipt.Result != artifactset.ResultRejected || receipt.ActiveRevision != 1 ||
		receipt.Items[0].Result != artifactset.ResultRejected || receipt.Items[0].Reason != artifactset.ReasonSegmentMismatch {
		t.Fatalf("receipt = %+v", receipt)
	}
	if !bytes.Equal(f.installer.active, []byte("library one")) || f.executor.Active().Revision != 1 {
		t.Fatal("a rejected set changed the active set")
	}
}

func TestContentMismatchAndInstallerRejection(t *testing.T) {
	f := newFixture(t)
	wrong := f.item(t, "1", []byte("library one"), true)
	wrong.SHA256 = artifactset.Digest([]byte("something else"))
	if receipt := apply(t, f, set(1, wrong)); receipt.Items[0].Reason != artifactset.ReasonContentMismatch {
		t.Fatalf("content mismatch receipt = %+v", receipt)
	}
	if receipt := apply(t, f, set(2, f.item(t, "2", []byte("bad"), true))); receipt.Items[0].Reason != artifactset.ReasonInstallRejected {
		t.Fatalf("install rejected receipt = %+v", receipt)
	}
	if receipt := apply(t, f, set(3, f.item(t, "3", []byte("boom"), true))); receipt.Result != artifactset.ResultRejected ||
		receipt.Items[0].Reason != artifactset.ReasonActivationFailed || receipt.ActiveRevision != 0 {
		t.Fatalf("activation failure receipt = %+v", receipt)
	}
	if f.executor.Active() != nil || f.installer.active != nil {
		t.Fatal("a failed set left something active")
	}
}

func TestAbsentItemIsUninstalled(t *testing.T) {
	f := newFixture(t)
	apply(t, f, set(1, f.item(t, "1", []byte("library one"), true)))
	receipt := apply(t, f, set(2))
	if receipt.Result != artifactset.ResultApplied || receipt.ActiveRevision != 2 || f.installer.removed != 1 ||
		f.executor.HasItem(artifactset.MediaTypeIPIntel) {
		t.Fatalf("receipt = %+v removed=%d", receipt, f.installer.removed)
	}
}

func TestOlderRevisionIsRefused(t *testing.T) {
	f := newFixture(t)
	apply(t, f, set(2, f.item(t, "2", []byte("library two"), true)))
	if _, err := f.executor.Apply(set(1), digestOf(1), now); !errors.Is(err, ErrStaleSet) {
		t.Fatalf("older set error = %v", err)
	}
	if _, err := f.executor.Apply(set(2), digestOf(9), now); !errors.Is(err, ErrStaleSet) {
		t.Fatalf("conflicting same-revision set error = %v", err)
	}
}

func TestStateSurvivesRestart(t *testing.T) {
	f := newFixture(t)
	apply(t, f, set(4, f.item(t, "4", []byte("library four"), true)))
	reopened, err := New(Config{NodeID: nodeID, StateDir: filepath.Join(f.root, "artifact-set"), Objects: f.store,
		Installers: map[string]Installer{artifactset.MediaTypeIPIntel: f.installer}})
	if err != nil {
		t.Fatal(err)
	}
	if active := reopened.Active(); active == nil || active.Revision != 4 || active.SetSHA256 != digestOf(4) {
		t.Fatalf("Active after restart = %+v", active)
	}
}

func TestWrongNodeIsRefused(t *testing.T) {
	f := newFixture(t)
	other := set(1)
	other.NodeID = "00000000-0000-4000-8000-000000000001"
	if _, err := f.executor.Apply(other, digestOf(1), now); !errors.Is(err, ErrWrongNode) {
		t.Fatalf("wrong node error = %v", err)
	}
}
