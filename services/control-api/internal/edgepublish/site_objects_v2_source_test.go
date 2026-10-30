package edgepublish

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	"github.com/google/uuid"
)

// D13-c③: dynamic routing publications are built from the release directly
// (siteObjectsV2SourceFromBundle). The v8 split they were once derived from
// is deleted (dr-d13-c3b); the roots it produced are recorded below and the
// direct path must keep reproducing them.

// dynamicRoutingPublicationRoot builds bundle's dynamic routing publication
// from the direct source.
func dynamicRoutingPublicationRoot(t *testing.T, name string, bundle edgeconfig.Bundle, tenantID uuid.UUID) string {
	t.Helper()
	direct, err := siteObjectsV2SourceFromBundle(bundle)
	if err != nil {
		t.Fatalf("%s: direct source: %v", name, err)
	}
	got, _, err := buildDynamicRoutingPublication(direct, tenantID, nil, nil, nil)
	if err != nil {
		t.Fatalf("%s: direct: %v", name, err)
	}
	return got.RootSHA256
}

// The roots the v8 split path produced for the golden release before
// D13-c③ (recorded at d6fe23aca): the direct path must reproduce them.
func TestDynamicRoutingDirectSourceMatchesRecordedRoots(t *testing.T) {
	want := map[int]string{
		1:   "98c95ca573b5101372ee09025bb0becb9b4f54e801139ee82afdd5b14a211a0c",
		2:   "c0a21bdf701890549e41d14c1a5c7f85bb4973f46d872d61cc8f70c93f46e70d",
		30:  "2298453a5352bfdd69df82f533ccb84144a4294d35ad039373895f32058b6805",
		300: "e3aded08e3b7eaefa95b140160649a52463e3af7fc1f0485324047f89ed8dda8",
	}
	for count, root := range want {
		stateRoot := filepath.Join(t.TempDir(), "edge")
		bundle := goldenSiteRuntimeV2ReleaseWith(t, uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7e01"), 41, count, stateRoot, count)
		if got := dynamicRoutingPublicationRoot(t, fmt.Sprintf("golden-%d", count), bundle, goldenTenant); got != root {
			t.Fatalf("golden-%d: root %s, recorded %s", count, got, root)
		}
	}
}

// The direct source refuses what the split refused: an HTTP policy entry
// for a site without a binding, a bound site without an entry.
func TestSiteObjectsV2SourceRefusesInconsistentReleases(t *testing.T) {
	bundle := goldenSiteRuntimeV2ReleaseWith(t, uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7e01"), 41, 3,
		filepath.Join(t.TempDir(), "edge"), 3)
	missing := edgeconfig.Bundle{Files: map[string][]byte{}}
	for path, content := range bundle.Files {
		if path != siteRuntimeV2HTTPPolicyArtifactPath {
			missing.Files[path] = content
		}
	}
	if _, err := siteObjectsV2SourceFromBundle(missing); err == nil {
		t.Fatal("a bound site without its HTTP policy entry was accepted")
	}
	if _, err := siteObjectsV2SourceFromBundle(edgeconfig.Bundle{Files: map[string][]byte{}}); err == nil {
		t.Fatal("a release without its document was accepted")
	}
}

// Deleting or disabling a scope's last L4 listener leaves a stream runtime
// without streams in the document (bindSiteRuntimeV2Streams keeps it so the
// removal carries its tcp/udp lifecycle requirements); the publication is a
// scope without streams, not an invalid one.
func TestSiteObjectsV2SourceTreatsStreamlessRuntimeAsNoStreams(t *testing.T) {
	bundle := goldenSiteRuntimeV2ReleaseWith(t, uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7e01"), 41, 3,
		filepath.Join(t.TempDir(), "edge"), 3)
	var document siteRuntimeV2Document
	if err := json.Unmarshal(bundle.Files[siteobject.DocumentPath], &document); err != nil {
		t.Fatal(err)
	}
	document.Streams = &edgeconfig.StreamRuntime{TenantID: goldenTenant.String()}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	bundle.Files[siteobject.DocumentPath] = raw
	source, err := siteObjectsV2SourceFromBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if source.Streams != nil {
		t.Fatalf("streamless runtime kept: %+v", source.Streams)
	}
	if _, _, err := buildDynamicRoutingPublication(source, goldenTenant, nil, nil, nil); err != nil {
		t.Fatalf("last listener removal refused: %v", err)
	}
}
