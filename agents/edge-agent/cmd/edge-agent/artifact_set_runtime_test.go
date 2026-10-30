package main

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/objectstore"
	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	format "github.com/cdnca/cdnca/libs/entitlement/ipintel"
	"github.com/klauspost/compress/zstd"
)

const runtimeTestNodeID = "8a9e4f0c-1d2b-4c3a-9e8f-7a6b5c4d3e2f"

// runtimeLibrary is a format v2 library and its set item (zstd, two segments).
func runtimeLibrary(t *testing.T, revision uint64) (artifactset.Item, [][]byte) {
	t.Helper()
	generated := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	artifact, err := format.Build(format.BuildInput{Revision: revision, BuildID: fmt.Sprintf("runtime-%04d", revision),
		GeneratedAt: generated, DataUpdatedAt: generated.Add(-time.Hour), StaleAfter: generated.Add(365 * 24 * time.Hour),
		Sources: []format.Source{{ID: "fixture", Name: "fixture", URL: "https://example.test", License: "CC0-1.0", Ref: "1", Role: "test"}},
		Facts:   []format.Fact{{Prefix: netip.MustParsePrefix(fmt.Sprintf("1.0.%d.0/24", revision)), Tags: format.TagCNTelecom, Country: "CN"}}})
	if err != nil {
		t.Fatal(err)
	}
	encoder, _ := zstd.NewWriter(nil)
	compressed := encoder.EncodeAll(artifact.Bytes, nil)
	_ = encoder.Close()
	segments := artifactset.SplitSegments(compressed, len(compressed)/2+1)
	item := artifactset.Item{ArtifactID: "ipintel/base", Version: artifact.Metadata.BuildID, Revision: revision,
		MediaType: artifactset.MediaTypeIPIntel, SHA256: artifactset.Digest(artifact.Bytes), Size: int64(len(artifact.Bytes)),
		Compression: artifactset.CompressionZstd, CompressedSHA256: artifactset.Digest(compressed),
		CompressedSize: int64(len(compressed)), Encryption: artifactset.EncryptionNone}
	for _, segment := range segments {
		item.Segments = append(item.Segments, artifactset.Segment{SHA256: artifactset.Digest(segment), Size: int64(len(segment))})
	}
	return item, segments
}

func newRuntimeFixture(t *testing.T) (*artifactSetRuntime, *objectstore.Store) {
	t.Helper()
	root := t.TempDir()
	objects, err := objectstore.Open(filepath.Join(root, objectStoreDir))
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := assembleArtifactSetRuntime(root, runtimeTestNodeID, objects, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return runtime, objects
}

// The object store is shared with site objects, whose fetches collect every
// object no owner references: received segments and the active set's
// segments must survive that, and an applied set releases the segments
// only older sets used.
func TestArtifactSetSegmentsSurviveSiteObjectCollection(t *testing.T) {
	runtime, objects := newRuntimeFixture(t)
	first, firstSegments := runtimeLibrary(t, 1)
	for index, segment := range firstSegments {
		if err := runtime.PutObject(first.Segments[index].SHA256, segment); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := objects.Collect(); err != nil {
		t.Fatal(err)
	}
	for _, segment := range first.Segments {
		if !objects.Has(segment.SHA256) {
			t.Fatalf("received segment %s was collected before its set arrived", segment.SHA256)
		}
	}
	receipt, err := runtime.Apply(artifactset.Set{NodeID: runtimeTestNodeID, Revision: 1, Items: []artifactset.Item{first}},
		artifactset.Digest([]byte("set one")), time.Now())
	if err != nil || receipt.Result != artifactset.ResultApplied {
		t.Fatalf("apply set 1: %+v %v", receipt, err)
	}
	if !runtime.IPIntelReady() {
		t.Fatal("library 1 is not ready after its set applied")
	}

	second, secondSegments := runtimeLibrary(t, 2)
	for index, segment := range secondSegments {
		if err := runtime.PutObject(second.Segments[index].SHA256, segment); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := objects.Collect(); err != nil {
		t.Fatal(err)
	}
	for _, segment := range append(append([]artifactset.Segment{}, first.Segments...), second.Segments...) {
		if !objects.Has(segment.SHA256) {
			t.Fatalf("segment %s was collected while referenced", segment.SHA256)
		}
	}
	receipt, err = runtime.Apply(artifactset.Set{NodeID: runtimeTestNodeID, Revision: 2, Items: []artifactset.Item{second}},
		artifactset.Digest([]byte("set two")), time.Now())
	if err != nil || receipt.Result != artifactset.ResultApplied {
		t.Fatalf("apply set 2: %+v %v", receipt, err)
	}
	// The applied set collects: set 2 is current, set 1 previous (LKG), nothing else.
	stray := artifactset.Digest([]byte("stray"))
	if err := objects.Put(stray, []byte("stray")); err != nil {
		t.Fatal(err)
	}
	third, thirdSegments := runtimeLibrary(t, 3)
	for index, segment := range thirdSegments {
		if err := runtime.PutObject(third.Segments[index].SHA256, segment); err != nil {
			t.Fatal(err)
		}
	}
	receipt, err = runtime.Apply(artifactset.Set{NodeID: runtimeTestNodeID, Revision: 3, Items: []artifactset.Item{third}},
		artifactset.Digest([]byte("set three")), time.Now())
	if err != nil || receipt.Result != artifactset.ResultApplied {
		t.Fatalf("apply set 3: %+v %v", receipt, err)
	}
	for _, segment := range first.Segments {
		if objects.Has(segment.SHA256) {
			t.Fatalf("segment %s of set 1 survived two newer sets", segment.SHA256)
		}
	}
	for _, segment := range append(append([]artifactset.Segment{}, second.Segments...), third.Segments...) {
		if !objects.Has(segment.SHA256) {
			t.Fatalf("segment %s of the current or previous set was collected", segment.SHA256)
		}
	}
	if objects.Has(stray) {
		t.Fatal("an unreferenced object survived the applied set's collection")
	}
	if _, err := os.Stat(filepath.Join(objects.Root(), "refs", artifactSetIncomingOwner+".json")); err != nil {
		t.Fatalf("incoming references: %v", err)
	}
}

// A library whose metadata does not match the set item is refused by the
// installer even though its digests match (Version = build_id, Revision).
func TestIPIntelInstallerChecksItemAgainstLibraryMetadata(t *testing.T) {
	runtime, _ := newRuntimeFixture(t)
	item, segments := runtimeLibrary(t, 1)
	for index, segment := range segments {
		if err := runtime.PutObject(item.Segments[index].SHA256, segment); err != nil {
			t.Fatal(err)
		}
	}
	for name, mutate := range map[string]func(*artifactset.Item){
		"revision": func(item *artifactset.Item) { item.Revision = 7 },
		"build id": func(item *artifactset.Item) { item.Version = "another-build" },
	} {
		changed := item
		mutate(&changed)
		receipt, err := runtime.Apply(artifactset.Set{NodeID: runtimeTestNodeID, Revision: 1, Items: []artifactset.Item{changed}},
			artifactset.Digest([]byte("set "+name)), time.Now())
		if err != nil || receipt.Result != artifactset.ResultRejected || receipt.Items[0].Reason != artifactset.ReasonInstallRejected {
			t.Fatalf("%s: %+v %v", name, receipt, err)
		}
	}
	if runtime.IPIntelReady() {
		t.Fatal("a mismatched library was installed")
	}
}
