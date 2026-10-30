package artifactsetdist

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	"github.com/cdnca/cdnca/libs/entitlement/ipintel"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/jackc/pgx/v5/pgxpool"
)

// testLibrary builds a real IP library whose data changed at dataUpdatedAt.
func testLibrary(t *testing.T, revision uint64, dataUpdatedAt time.Time) []byte {
	t.Helper()
	generated := dataUpdatedAt.Add(time.Hour)
	artifact, err := ipintel.Build(ipintel.BuildInput{Revision: revision, BuildID: strconv.FormatUint(revision, 10),
		GeneratedAt: generated, DataUpdatedAt: dataUpdatedAt, StaleAfter: generated.Add(30 * 24 * time.Hour),
		SourceRelease: "ipx-test", Notice: "test",
		Sources: []ipintel.Source{{ID: "geo", Name: "test", URL: "https://example.invalid", License: "CC0-1.0", Ref: "1", Role: "asn"}},
		Facts:   []ipintel.Fact{{Prefix: netip.MustParsePrefix("1.0.1.0/24"), ASN: uint32(revision), Country: "CN"}}})
	if err != nil {
		t.Fatal(err)
	}
	return artifact.Bytes
}

// Nodes run one IP library: the base or the plugin-built local one,
// whichever has newer data (ties: base); a local library that does not open
// falls back to the base; without the module (not listed) only the base.
func TestDesiredSelectsTheNewerIPLibrary(t *testing.T) {
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	source := &staticSource{}
	distributor, err := New(Config{Pool: new(pgxpool.Pool), Deployments: new(edgedeployment.Store), Source: source,
		Signer: testSigner{id: "edge-key", private: private}})
	if err != nil {
		t.Fatal(err)
	}
	day := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	use := func(base, local []byte) {
		source.artifacts, source.objects = nil, map[string][]byte{}
		if base != nil {
			artifact := ipIntelArtifact(1, base)
			source.artifacts = append(source.artifacts, artifact)
			source.objects[artifact.SHA256] = base
		}
		if local != nil {
			artifact := ipIntelArtifact(1, local)
			artifact.ArtifactID = IPIntelLocalArtifactID
			source.artifacts = append(source.artifacts, artifact)
			source.objects[artifact.SHA256] = local
		}
	}
	base := testLibrary(t, 1, day)
	for name, test := range map[string]struct {
		base, local []byte
		want        string
		reason      string
	}{
		"base only":    {base, nil, IPIntelArtifactID, "only_base"},
		"local only":   {nil, testLibrary(t, 1, day), IPIntelLocalArtifactID, "only_local"},
		"local newer":  {base, testLibrary(t, 1, day.Add(time.Hour)), IPIntelLocalArtifactID, "local_newer"},
		"base newer":   {base, testLibrary(t, 1, day.Add(-time.Hour)), IPIntelArtifactID, "base_newer_or_equal"},
		"tie":          {base, testLibrary(t, 2, day), IPIntelArtifactID, "base_newer_or_equal"},
		"local broken": {base, []byte("not a library"), IPIntelArtifactID, "local_unreadable"},
	} {
		use(test.base, test.local)
		desired, err := distributor.desired(t.Context())
		if err != nil || len(desired) != 1 || desired[0].item.ArtifactID != test.want ||
			desired[0].item.MediaType != artifactset.MediaTypeIPIntel || distributor.ipIntelChoice.Reason != test.reason {
			t.Fatalf("%s: desired %+v choice %+v %v", name, desired, distributor.ipIntelChoice, err)
		}
	}
	use(nil, nil)
	if desired, err := distributor.desired(t.Context()); err != nil || len(desired) != 0 {
		t.Fatalf("no library: %+v %v", desired, err)
	}
}
