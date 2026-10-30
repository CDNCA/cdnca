package artifactsetdist

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"strconv"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	"github.com/cdnca/cdnca/libs/entitlement/artifactcatalog"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/klauspost/compress/zstd"
	"google.golang.org/protobuf/proto"
)

type testSigner struct {
	id      string
	private ed25519.PrivateKey
}

func (signer testSigner) KeyID() string { return signer.id }
func (signer testSigner) PublicKey() ed25519.PublicKey {
	if signer.private == nil {
		return nil
	}
	return signer.private.Public().(ed25519.PublicKey)
}
func (signer testSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(signer.private, payload), nil
}

// staticSource is a control plane holding the given local artifacts and
// objects (artifactsync verified them on download; the distributor only
// checks that each artifact's bytes are the ones it names).
type staticSource struct {
	artifacts []LocalArtifact
	objects   map[string][]byte
	err       error
}

func (source *staticSource) LocalArtifacts(context.Context) ([]LocalArtifact, error) {
	return append([]LocalArtifact(nil), source.artifacts...), source.err
}

func (source *staticSource) Object(_ context.Context, sha string) ([]byte, error) {
	content, found := source.objects[sha]
	if !found {
		return nil, errors.New("object not found")
	}
	return content, nil
}

// set makes the source hold only the IP library revision with content.
func (source *staticSource) set(revision uint64, content []byte) {
	artifact := ipIntelArtifact(revision, content)
	source.artifacts, source.objects = []LocalArtifact{artifact}, map[string][]byte{artifact.SHA256: content}
}

// ipIntelArtifact is ipintel/base revision with content (build ID: the
// revision in decimal).
func ipIntelArtifact(revision uint64, content []byte) LocalArtifact {
	return LocalArtifact{ArtifactID: IPIntelArtifactID, Kind: artifactcatalog.KindIPIntel, Version: strconv.FormatUint(revision, 10),
		Revision: revision, SHA256: artifactset.Digest(content), Size: int64(len(content)), MediaType: artifactset.MediaTypeIPIntel,
		RequiresCapability: &artifactcatalog.Capability{Name: "IP_INTEL", MinVersion: 2}}
}

func randomBytes(t *testing.T, size int) []byte {
	t.Helper()
	data := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		t.Fatal(err)
	}
	return data
}

// The IP library item is the zstd of the artifact cut into segments the
// agent can rebuild and check; preparing the same library twice gives the
// same item (segment configurations are content addressed).
func TestPrepareIPIntelSegmentsTheCompressedLibrary(t *testing.T) {
	artifact := randomBytes(t, 9<<20) // incompressible: three segments
	local := ipIntelArtifact(7, artifact)
	local.Version = "ipintel-20261017-000007"
	entry, err := prepareItem(local, artifact, artifactset.MaxSegmentBytes)
	if err != nil {
		t.Fatal(err)
	}
	item := entry.item
	if item.ArtifactID != IPIntelArtifactID || item.Version != local.Version || item.Revision != 7 ||
		item.MediaType != artifactset.MediaTypeIPIntel ||
		item.SHA256 != artifactset.Digest(artifact) || item.Size != int64(len(artifact)) ||
		item.Compression != artifactset.CompressionZstd || len(item.Segments) != 3 || len(entry.segments) != 3 {
		t.Fatalf("item = %+v", item)
	}
	for index, segment := range entry.segments {
		if len(segment) > artifactset.MaxSegmentBytes || artifactset.Digest(segment) != item.Segments[index].SHA256 {
			t.Fatalf("segment %d does not match the item", index)
		}
	}
	compressed, err := item.Join(entry.segments)
	if err != nil {
		t.Fatal(err)
	}
	decoder, _ := zstd.NewReader(nil)
	content, err := decoder.DecodeAll(compressed, nil)
	decoder.Close()
	if err != nil || !item.CheckContent(content) || !bytes.Equal(content, artifact) {
		t.Fatalf("rebuilt content does not match: %v", err)
	}
	again, err := prepareItem(local, artifact, artifactset.MaxSegmentBytes)
	if err != nil || itemsDigest([]artifactset.Item{again.item}) != itemsDigest([]artifactset.Item{item}) {
		t.Fatalf("preparing the same library twice differs: %v", err)
	}
	if itemsDigest(nil) != itemsDigest([]artifactset.Item{}) || itemsDigest(nil) == itemsDigest([]artifactset.Item{item}) {
		t.Fatal("items digest does not tell the empty list from the library")
	}
}

func TestPrepareItemRefusesMismatchedOrOversizedBytes(t *testing.T) {
	content := []byte("CDNIPI01 artifact")
	other := ipIntelArtifact(3, []byte("other"))
	if _, err := prepareItem(other, content, artifactset.MaxSegmentBytes); err == nil {
		t.Fatal("bytes the artifact does not name were prepared")
	}
	large := randomBytes(t, artifactset.MaxSegmentsPerItem*artifactset.MaxSegmentBytes+1)
	if _, err := prepareItem(ipIntelArtifact(4, large), large, artifactset.MaxSegmentBytes); err == nil {
		t.Fatal("artifact over the set bounds was prepared")
	}
}

// Only ipintel/base goes to nodes; any failure to read a usable node
// artifact fails the sweep rather than issuing a set without it (which
// would uninstall it from every node).
func TestDesiredTakesNodeArtifactsAndFailsClosed(t *testing.T) {
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	source := &staticSource{}
	distributor, err := New(Config{Pool: new(pgxpool.Pool), Deployments: new(edgedeployment.Store), Source: source,
		Signer: testSigner{id: "edge-key", private: private}, SegmentBytes: 8})
	if err != nil {
		t.Fatal(err)
	}
	library := []byte("a small IP library, several segments")
	source.set(5, library)
	ruleset := LocalArtifact{ArtifactID: "ruleset/owasp", Kind: "ruleset", Version: "1", Revision: 1,
		SHA256: artifactset.Digest([]byte("rules")), Size: 5, MediaType: "application/vnd.cdnca.ruleset-item+json;version=1"}
	source.artifacts = append(source.artifacts, ruleset)
	desired, err := distributor.desired(t.Context())
	if err != nil || len(desired) != 1 || desired[0].item.ArtifactID != IPIntelArtifactID || len(desired[0].item.Segments) < 2 {
		t.Fatalf("desired = %+v, %v", desired, err)
	}
	source.objects = map[string][]byte{}
	if _, err := distributor.desired(t.Context()); err != nil {
		t.Fatalf("a cached item was read again: %v", err)
	}
	source.set(6, []byte("revision six"))
	delete(source.objects, source.artifacts[0].SHA256)
	if _, err := distributor.desired(t.Context()); err == nil {
		t.Fatal("a usable artifact whose bytes are missing was left out of the set")
	}
	source.err = errors.New("database unavailable")
	if _, err := distributor.desired(t.Context()); err == nil {
		t.Fatal("a source failure produced a desired set")
	}
}

// Only an authentic session snapshot declaring ARTIFACT_SET v1 is a target.
func TestDeclaresArtifactSetRequiresAnAuthenticSnapshot(t *testing.T) {
	snapshot := func(features ...*agentv1.Capability) ([]byte, []byte) {
		encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(&agentv1.AgentCapabilities{
			AgentVersion: "1.0.35", Features: features})
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(encoded)
		return encoded, digest[:]
	}
	set := &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_ARTIFACT_SET, ApiVersion: 1}
	other := &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_IP_INTEL, ApiVersion: 2}
	if encoded, digest := snapshot(other, set); !declaresArtifactSet(encoded, digest) {
		t.Fatal("ARTIFACT_SET v1 not a target")
	}
	if encoded, digest := snapshot(other); declaresArtifactSet(encoded, digest) {
		t.Fatal("node without ARTIFACT_SET is a target")
	}
	encoded, digest := snapshot(set)
	digest[0] ^= 0xff
	if declaresArtifactSet(encoded, digest) {
		t.Fatal("snapshot with a mismatched digest is a target")
	}
}

func TestNewRequiresItsDependencies(t *testing.T) {
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	valid := Config{Pool: new(pgxpool.Pool), Deployments: new(edgedeployment.Store), Source: &staticSource{},
		Signer: testSigner{id: "edge-key", private: private}}
	if _, err := New(valid); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Config){
		"pool":   func(config *Config) { config.Pool = nil },
		"store":  func(config *Config) { config.Deployments = nil },
		"source": func(config *Config) { config.Source = nil },
		"signer": func(config *Config) { config.Signer = testSigner{id: "edge-key"} },
		"key id": func(config *Config) { config.Signer = testSigner{private: private} },
	} {
		config := valid
		mutate(&config)
		if _, err := New(config); err == nil {
			t.Fatalf("%s: invalid configuration accepted", name)
		}
	}
}
