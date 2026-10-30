package artifactsetdist

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	"github.com/cdnca/cdnca/libs/entitlement/artifactcatalog"
	"github.com/cdnca/cdnca/libs/entitlement/ipintel"
	"github.com/cdnca/cdnca/libs/entitlement/enginemodule"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/artifactsync"
	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"
)

// IPIntelArtifactID is the set item of the license-delivered IP intelligence
// library (ADR 0007 section 4.4 ipintel/base); IPIntelLocalArtifactID the one
// this control plane builds with module.ipintel.dnspup. A set holds at most
// one of the two (selectIPIntel).
const (
	IPIntelArtifactID      = artifactcatalog.IPIntelBaseID
	IPIntelLocalArtifactID = artifactsync.IPIntelLocalID
)

// LocalArtifact is one artifact the control plane downloaded and may use now
// (artifactsync: active catalog entry, lease feature granted).
type LocalArtifact = artifactsync.LocalArtifact

// Source is the control plane's local artifact store (*artifactsync.Store).
// Usability is the source's decision; what of it goes to nodes is the
// distributor's (nodeArtifact).
type Source interface {
	LocalArtifacts(ctx context.Context) ([]LocalArtifact, error)
	// Object returns the stored bytes named by sha256 (lowercase hex).
	Object(ctx context.Context, sha256 string) ([]byte, error)
}

// prepared is one desired item with its segment bytes.
type prepared struct {
	item     artifactset.Item
	segments [][]byte
	// dataUpdatedAt of an IP library (zero otherwise or when unreadable).
	dataUpdatedAt time.Time
	// requiresVersion: the node capability version the entry requires
	// (engine modules: WAF_CRS_MODULE).
	requiresVersion uint32
	// sealed: an encrypted rule pack, sent only with the node's key wrap.
	sealed bool
}

// RulePackSource is the optional part of Source for rule packs
// (*artifactsync.Store): the pack versions published sites mount, the
// current versions of the enabled official system packs (system/crs-tuning,
// the mark-only intel packs: node-wide, no site mount, ADR 0011 §6.1) and
// each node's wrapped content keys of the sealed ones (WrapNodeKeys).
type RulePackSource interface {
	MountedRulePacks(ctx context.Context) ([]artifactsync.MountedRulePack, error)
	SystemRulePacks(ctx context.Context) ([]artifactsync.MountedRulePack, error)
	NodeKeyWraps(ctx context.Context, nodeID uuid.UUID) ([]artifactsync.NodeKeyWrap, error)
}

// RulePackArtifactID names a mounted pack's set item by its object digest:
// two versions of one pack mounted by different sites are two items.
func RulePackArtifactID(sha256 string) string { return "rule_pack/" + sha256 }

// mountedRulePackItem is the set item of a mounted pack (version: the pack
// version; revision 1: the digest identifies the content).
func mountedRulePackItem(pack artifactsync.MountedRulePack, segmentBytes int) (prepared, error) {
	entry, err := prepareItem(LocalArtifact{ArtifactID: RulePackArtifactID(pack.SHA256), Version: pack.Version, Revision: 1,
		SHA256: pack.SHA256, Size: int64(len(pack.Content)), MediaType: artifactset.MediaTypeRulePack}, pack.Content, segmentBytes)
	entry.sealed = pack.Sealed
	return entry, err
}

// nodeArtifact reports whether a local artifact belongs in node artifact
// sets (LocalArtifacts also lists control-side kinds: ruleset, crs_profile):
// the IP library, base (license) or local (module.ipintel.dnspup;
// LocalArtifacts lists it only while the lease grants the module; desired
// keeps one of the two, selectIPIntel), and engine modules (B3).
func nodeArtifact(artifact LocalArtifact) bool {
	switch {
	case artifact.ArtifactID == IPIntelArtifactID || artifact.ArtifactID == IPIntelLocalArtifactID:
		return artifact.Kind == artifactcatalog.KindIPIntel && artifact.MediaType == artifactset.MediaTypeIPIntel
	case artifact.Kind == artifactcatalog.KindCRSProfile:
		// CRS profile packs (system/crs-<level>); not the CRS rule text, not
		// the application exclusion packs (crs_profile/app-*: they travel with
		// the release, edgeconfig.ListenerCRSAppPath).
		return artifact.MediaType == artifactcatalog.MediaTypeCRSProfilePack &&
			!strings.HasPrefix(artifact.ArtifactID, artifactcatalog.KindCRSProfile+"/app-")
	case artifact.Kind == artifactcatalog.KindEngineModule:
		_, _, ok := enginemodule.ParseArtifactID(artifact.ArtifactID)
		return ok && artifact.MediaType == artifactset.MediaTypeEngineModule && artifact.RequiresCapability != nil &&
			artifact.RequiresCapability.Name == artifactcatalog.EngineModuleCapability
	default:
		return false
	}
}

// IPIntelChoice is the IP library nodes should run and why.
type IPIntelChoice struct {
	ArtifactID    string
	DataUpdatedAt time.Time
	// Reason: only_base, only_local, local_newer, base_newer_or_equal,
	// local_unreadable (the local library could not be opened: base used).
	Reason string
}

// selectIPIntel picks one IP library (ADR 0007 section 4.4, user decision
// 2026-10-17): the one whose data_updated_at is newer; on a tie the base
// library. A local library that cannot be opened falls back to the base.
func selectIPIntel(base, local *prepared) (*prepared, IPIntelChoice) {
	switch {
	case base == nil && local == nil:
		return nil, IPIntelChoice{}
	case local == nil:
		return base, IPIntelChoice{ArtifactID: IPIntelArtifactID, DataUpdatedAt: base.dataUpdatedAt, Reason: "only_base"}
	case local.dataUpdatedAt.IsZero() && base != nil:
		return base, IPIntelChoice{ArtifactID: IPIntelArtifactID, DataUpdatedAt: base.dataUpdatedAt, Reason: "local_unreadable"}
	case base == nil:
		return local, IPIntelChoice{ArtifactID: IPIntelLocalArtifactID, DataUpdatedAt: local.dataUpdatedAt, Reason: "only_local"}
	case local.dataUpdatedAt.After(base.dataUpdatedAt):
		return local, IPIntelChoice{ArtifactID: IPIntelLocalArtifactID, DataUpdatedAt: local.dataUpdatedAt, Reason: "local_newer"}
	default:
		return base, IPIntelChoice{ArtifactID: IPIntelArtifactID, DataUpdatedAt: base.dataUpdatedAt, Reason: "base_newer_or_equal"}
	}
}

// libraryDataUpdatedAt reads data_updated_at of an IP library (zero when it
// does not open: the node would reject it too).
func libraryDataUpdatedAt(content []byte) time.Time {
	table, err := ipintel.Open(content)
	if err != nil {
		return time.Time{}
	}
	at, err := time.Parse(time.RFC3339, table.Metadata.DataUpdatedAt)
	if err != nil {
		return time.Time{}
	}
	return at.UTC()
}

// nodeItems is the item list one node should run (sorted, as desired is):
// every item but engine modules, and the engine module built for the
// node's OpenResty version and architecture when the node declares
// WAF_CRS_MODULE at the version the entry requires (one per component).
// A sealed rule pack goes only to a node holding its key wrap (wraps:
// sealed sha256 -> wrap), with the wrap.
func nodeItems(desired []prepared, capabilities *agentv1.AgentCapabilities, wraps map[string]artifactsync.NodeKeyWrap) []artifactset.Item {
	engineVersion := uint32(0)
	for _, feature := range capabilities.GetFeatures() {
		if feature.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_WAF_CRS_MODULE {
			engineVersion = max(engineVersion, feature.GetApiVersion())
		}
	}
	platform := enginemodule.Platform{OpenRestyVersion: capabilities.GetOpenrestyVersion(), Architecture: capabilities.GetArchitecture()}
	items := make([]artifactset.Item, 0, len(desired))
	for _, entry := range desired {
		if entry.item.MediaType == artifactset.MediaTypeEngineModule {
			_, built, ok := enginemodule.ParseArtifactID(entry.item.ArtifactID)
			if !ok || built != platform || capabilities.GetOperatingSystem() != "linux" ||
				entry.requiresVersion < 1 || engineVersion < entry.requiresVersion {
				continue
			}
		}
		item := entry.item
		if entry.sealed {
			wrap, found := wraps[item.SHA256]
			if !found {
				continue
			}
			item.KeyWrap = &artifactset.KeyWrap{RecipientKeyID: wrap.RecipientKeyID, WrappedKey: wrap.WrappedKey}
		}
		items = append(items, item)
	}
	return items
}

// prepareItem turns a local artifact and its bytes into a set item: zstd of
// the content, cut into segments of at most segmentBytes. The bytes must be
// the ones the artifact names (the node checks the content again and its
// installer the metadata against Version / Revision).
func prepareItem(artifact LocalArtifact, content []byte, segmentBytes int) (prepared, error) {
	if artifactset.Digest(content) != artifact.SHA256 || int64(len(content)) != artifact.Size {
		return prepared{}, fmt.Errorf("local artifact %s revision %d does not match its stored bytes",
			artifact.ArtifactID, artifact.Revision)
	}
	encoder, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedBestCompression), zstd.WithEncoderConcurrency(1))
	if err != nil {
		return prepared{}, err
	}
	compressed := encoder.EncodeAll(content, nil)
	_ = encoder.Close()
	segments := artifactset.SplitSegments(compressed, segmentBytes)
	item := artifactset.Item{ArtifactID: artifact.ArtifactID, Version: artifact.Version, Revision: artifact.Revision,
		MediaType: artifact.MediaType, SHA256: artifact.SHA256, Size: artifact.Size,
		Compression: artifactset.CompressionZstd, CompressedSHA256: artifactset.Digest(compressed),
		CompressedSize: int64(len(compressed)), Encryption: artifactset.EncryptionNone}
	for _, segment := range segments {
		item.Segments = append(item.Segments, artifactset.Segment{SHA256: artifactset.Digest(segment), Size: int64(len(segment))})
	}
	if len(item.Segments) > artifactset.MaxSegmentsPerItem || item.Size > artifactset.MaxItemBytes {
		return prepared{}, fmt.Errorf("local artifact %s revision %d (%d bytes, %d compressed) exceeds the node artifact set bounds",
			artifact.ArtifactID, artifact.Revision, item.Size, item.CompressedSize)
	}
	if _, err := item.Join(segments); err != nil {
		return prepared{}, fmt.Errorf("local artifact %s revision %d: %w", artifact.ArtifactID, artifact.Revision, err)
	}
	result := prepared{item: item, segments: segments}
	if artifact.MediaType == artifactset.MediaTypeIPIntel {
		result.dataUpdatedAt = libraryDataUpdatedAt(content)
	}
	if artifact.RequiresCapability != nil {
		result.requiresVersion = uint32(artifact.RequiresCapability.MinVersion)
	}
	return result, nil
}

// itemsDigest identifies a desired item list (sorted by artifact ID).
func itemsDigest(items []artifactset.Item) string {
	if items == nil {
		items = []artifactset.Item{}
	}
	encoded, _ := json.Marshal(items)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
