// Package siteobject is the site object delivery format of dynamic routing
// (ADR 0009 §8.3, site_runtime 9): a publication is one signed v2 root, a
// bucket list of site objects and a scope object, all content addressed by
// the SHA-256 of their plaintext. Only the root is signed; buckets, sites,
// the scope and files are reached through digests (root_v2.go).
package siteobject

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

const (
	KeySchema = "cdnca.edge.site-object-key/v1"

	// KeyMediaType is the per-node HPKE artifact carrying KeyDocument.
	KeyMediaType = "application/vnd.cdnca.edge-site-object-key+json;version=1"

	// TargetSitesPerBucket sizes bucket_count; MaxBuckets bounds it.
	TargetSitesPerBucket = 256
	MaxBuckets           = 4096
	// MaxSites is the per-scope site bound of the format (MaxBuckets *
	// TargetSitesPerBucket). Other bounds (the canonical snapshot, the node)
	// are lower in practice.
	MaxSites = MaxBuckets * TargetSitesPerBucket
	// MaxBucketEntries tolerates hash skew far above the target.
	MaxBucketEntries = 4096
	// MaxRootBytes and MaxObjectBytes bound one plaintext.
	MaxRootBytes   = 1 << 20
	MaxObjectBytes = 8 << 20
	// MaxRootIndexBytes bounds the root index: the root plus every bucket,
	// which a node must hold whole before it can fetch a single site. It is
	// the node's one-document bound (edgeconfig.MaxConfigurationBundleFileBytes);
	// site, scope and file objects are fetched by digest and do not count.
	// Measured: 5,000 sites 0.70 MiB, 50,000 sites 6.97 MiB, about 115,000
	// sites reach it (ADR 0009 §8.3).
	MaxRootIndexBytes = edgeconfig.MaxConfigurationBundleFileBytes
	// MaxScopeFiles and MaxSiteFiles bound file references.
	MaxScopeFiles = 4096
	MaxSiteFiles  = 16
)

var (
	ErrInvalid = errors.New("site object: invalid")
	ErrMissing = errors.New("site object: missing")

	uuidPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Capability is one required capability, as the v2 document names it.
type Capability struct {
	Name       string `json:"name"`
	APIVersion uint32 `json:"api_version"`
}

// Bucket lists the sites whose BucketIndex is Index, by site_id.
type Bucket struct {
	Schema               string        `json:"schema"`
	ConfigurationScopeID string        `json:"configuration_scope_id"`
	BucketCount          int           `json:"bucket_count"`
	Index                int           `json:"index"`
	Sites                []BucketEntry `json:"sites"`
}

type BucketEntry struct {
	SiteID   string `json:"site_id"`
	Revision int64  `json:"revision"`
	SHA256   string `json:"sha256"`
}

// FileRef is a release file carried as a file object (raw bytes).
type FileRef struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// SiteTelemetry is what the site's telemetry entries carry besides what the
// runtime entry, the root and the scope determine. Capture applies to every
// listener of the site.
type SiteTelemetry struct {
	PackageSubscriptionID string           `json:"package_subscription_id,omitempty"`
	Capture               TelemetryCapture `json:"capture"`
}

type TelemetryCapture struct {
	Revision                   uint64   `json:"revision,omitempty"`
	EvidenceDigest             string   `json:"evidence_digest,omitempty"`
	Enabled                    bool     `json:"enabled"`
	Methods                    []string `json:"methods"`
	URIPrefixes                []string `json:"uri_prefixes"`
	RequestHeaderAllowlist     []string `json:"request_header_allowlist"`
	ResponseHeaderAllowlist    []string `json:"response_header_allowlist"`
	RequestBodyFieldAllowlist  []string `json:"request_body_field_allowlist"`
	ResponseBodyFieldAllowlist []string `json:"response_body_field_allowlist"`
	MaxValueBytes              int      `json:"max_value_bytes"`
	MaxBodyBytes               int      `json:"max_body_bytes"`
	MaxEventBytes              int      `json:"max_event_bytes"`
}

// KeyDocument is the plaintext of a node's HPKE key artifact: the content
// key of KeyEpoch for the publication whose root digest is RootSHA256.
type KeyDocument struct {
	Schema               string `json:"schema"`
	ConfigurationScopeID string `json:"configuration_scope_id"`
	ConfigVersionID      string `json:"config_version_id"`
	RootSHA256           string `json:"root_sha256"`
	KeyEpoch             int64  `json:"key_epoch"`
	ContentKey           []byte `json:"content_key"`
	// TrafficStopStreams (L4_TRAFFIC_STOP v1, per node: only a node that
	// declares it gets the field) are the scope's L4 forwards withdrawn
	// because their package went over its monthly traffic: the node closes
	// their open sessions instead of draining them. Sorted, unique; omitted
	// when none.
	TrafficStopStreams []string `json:"traffic_stop_streams,omitempty"`
	// L4WithheldStreams (L4_STREAM_SELECTION v1, per node: only a node that
	// declares it gets the field) are the root's L4 forwards this node does
	// not serve: none of their line groups has it. The node leaves them out
	// of its L4 runtime. Sorted, unique; omitted when none.
	L4WithheldStreams []string `json:"l4_withheld_streams,omitempty"`
	// NodeRegion (NODE_REGION v1, per node: only a node that declares it
	// gets the field) is the code of the node's region in the region catalog
	// (region_catalog.code, lower-case ASCII; omitted when the node has
	// none). The node picks region error pages and region origin routes by
	// it; the node has no region setting of its own.
	NodeRegion string `json:"node_region,omitempty"`
	// NodeStorage (NODE_STORAGE v1, per node: only a node that declares it
	// gets the field) is the node's cache directory, cache limit and log
	// directory set on the console; omitted when none is set.
	NodeStorage *NodeStorage `json:"node_storage,omitempty"`
}

// NodeRegionAPIVersion is the CAPABILITY_NAME_NODE_REGION version an Agent
// declares and control needs to write KeyDocument.NodeRegion.
const NodeRegionAPIVersion uint32 = 1

// NodeRegionPattern is a region catalog code (region_catalog.code, 528).
var NodeRegionPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// MaxTrafficStopStreams bounds KeyDocument.TrafficStopStreams.
const MaxTrafficStopStreams = 4096

// L4StreamSelectionAPIVersion is the CAPABILITY_NAME_L4_STREAM_SELECTION
// version an Agent declares and control needs to write L4WithheldStreams.
const L4StreamSelectionAPIVersion uint32 = 1

// MaxL4WithheldStreams bounds KeyDocument.L4WithheldStreams (a scope's v2
// release carries at most 1000 forwards, edgeconfig.normalize).
const MaxL4WithheldStreams = 1000

// Encode is the object encoding: encoding/json of the struct, compact, no
// HTML escaping, no trailing newline. A decoder only needs the digest; the
// strict parsers below also require that re-encoding gives the same bytes.
func Encode(value any) ([]byte, error) {
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, fmt.Errorf("%w: encode: %v", ErrInvalid, err)
	}
	return bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), nil
}

// Digest is the hex SHA-256 an object is addressed by.
func Digest(plaintext []byte) string {
	sum := sha256.Sum256(plaintext)
	return hex.EncodeToString(sum[:])
}

func decodeStrict(raw []byte, limit int, target any) error {
	if len(raw) == 0 || len(raw) > limit {
		return fmt.Errorf("%w: size", ErrInvalid)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return fmt.Errorf("%w: JSON", ErrInvalid)
	}
	encoded, err := Encode(target)
	if err != nil || !bytes.Equal(encoded, raw) {
		return fmt.Errorf("%w: not in object encoding", ErrInvalid)
	}
	return nil
}

// BucketIndex is the first 4 bytes of SHA-256(site_id) big endian, mod
// bucketCount (a power of two, so doubling it splits each bucket in two).
func BucketIndex(siteID string, bucketCount int) int {
	sum := sha256.Sum256([]byte(siteID))
	return int(binary.BigEndian.Uint32(sum[:4]) % uint32(bucketCount))
}

// BucketCount is the smallest power of two with at most
// TargetSitesPerBucket sites per bucket on average, at least 1.
func BucketCount(sites int) (int, error) {
	if sites < 0 || sites > MaxSites {
		return 0, fmt.Errorf("%w: %d sites exceed the per-scope bound %d", ErrInvalid, sites, MaxSites)
	}
	count := 1
	for count*TargetSitesPerBucket < sites {
		count *= 2
	}
	return count, nil
}

func validBucketCount(count int) bool {
	return count >= 1 && count <= MaxBuckets && count&(count-1) == 0
}

func validRootCapabilitiesAt(values []Capability, version uint32) bool {
	if len(values) == 0 || len(values) > 64 {
		return false
	}
	siteRuntime := false
	for index, value := range values {
		if value.Name == "" || value.APIVersion == 0 || index > 0 && values[index-1].Name >= value.Name {
			return false
		}
		if value.Name == "site_runtime" {
			siteRuntime = value.APIVersion == version
		}
	}
	return siteRuntime
}

// rootCapabilitiesAt is document's required capabilities (site_runtime at
// most edgeconfig.MaxDocumentSiteRuntimeVersion) with site_runtime raised to
// version.
func rootCapabilitiesAt(document []Capability, version uint32) ([]Capability, error) {
	result := make([]Capability, len(document))
	found := false
	for index, value := range document {
		if value.Name == "" || value.APIVersion == 0 || index > 0 && document[index-1].Name >= value.Name {
			return nil, fmt.Errorf("%w: document capabilities", ErrInvalid)
		}
		result[index] = value
		if value.Name == "site_runtime" {
			if value.APIVersion > edgeconfig.MaxDocumentSiteRuntimeVersion {
				return nil, fmt.Errorf("%w: the v2 document already declares site_runtime %d", ErrInvalid, value.APIVersion)
			}
			result[index].APIVersion = version
			found = true
		}
	}
	if !found {
		return nil, fmt.Errorf("%w: document capabilities lack site_runtime", ErrInvalid)
	}
	return result, nil
}

func parseBucket(raw []byte, schema string) (Bucket, error) {
	var bucket Bucket
	if err := decodeStrict(raw, MaxObjectBytes, &bucket); err != nil {
		return Bucket{}, err
	}
	if bucket.Schema != schema || !uuidPattern.MatchString(bucket.ConfigurationScopeID) ||
		!validBucketCount(bucket.BucketCount) || bucket.Index < 0 || bucket.Index >= bucket.BucketCount ||
		bucket.Sites == nil || len(bucket.Sites) > MaxBucketEntries {
		return Bucket{}, fmt.Errorf("%w: bucket", ErrInvalid)
	}
	for index, entry := range bucket.Sites {
		if !uuidPattern.MatchString(entry.SiteID) || entry.Revision < 1 || entry.Revision > maxSafeInteger ||
			!digestPattern.MatchString(entry.SHA256) || index > 0 && bucket.Sites[index-1].SiteID >= entry.SiteID ||
			BucketIndex(entry.SiteID, bucket.BucketCount) != bucket.Index {
			return Bucket{}, fmt.Errorf("%w: bucket entry", ErrInvalid)
		}
	}
	return bucket, nil
}

func validFileRefs(files []FileRef) bool {
	for index, file := range files {
		if file.Path == "" || !digestPattern.MatchString(file.SHA256) || index > 0 && files[index-1].Path >= file.Path {
			return false
		}
	}
	return true
}

func ParseKeyDocument(raw []byte) (KeyDocument, error) {
	var document KeyDocument
	if err := decodeStrict(raw, 4096+MaxTrafficStopStreams*40+MaxL4WithheldStreams*40, &document); err != nil {
		return KeyDocument{}, err
	}
	if !validStreamIDList(document.TrafficStopStreams, MaxTrafficStopStreams) {
		return KeyDocument{}, fmt.Errorf("%w: key document traffic stop streams", ErrInvalid)
	}
	if !validStreamIDList(document.L4WithheldStreams, MaxL4WithheldStreams) {
		return KeyDocument{}, fmt.Errorf("%w: key document L4 withheld streams", ErrInvalid)
	}
	if document.NodeRegion != "" && !NodeRegionPattern.MatchString(document.NodeRegion) {
		return KeyDocument{}, fmt.Errorf("%w: key document node region", ErrInvalid)
	}
	if storage := document.NodeStorage; storage != nil && (storage.IsZero() || !storage.Validate()) {
		return KeyDocument{}, fmt.Errorf("%w: key document node storage", ErrInvalid)
	}
	if document.Schema != KeySchema || !uuidPattern.MatchString(document.ConfigurationScopeID) ||
		!uuidPattern.MatchString(document.ConfigVersionID) || !digestPattern.MatchString(document.RootSHA256) ||
		document.KeyEpoch < 1 || document.KeyEpoch > maxSafeInteger || len(document.ContentKey) != ContentKeySize {
		return KeyDocument{}, fmt.Errorf("%w: key document", ErrInvalid)
	}
	return document, nil
}

// validStreamIDList: nil, or 1..limit canonical UUIDs in ascending order
// (an empty list is omitted, never encoded).
func validStreamIDList(ids []string, limit int) bool {
	if ids != nil && len(ids) == 0 || len(ids) > limit {
		return false
	}
	for index, id := range ids {
		if !uuidPattern.MatchString(id) || index > 0 && ids[index-1] >= id {
			return false
		}
	}
	return true
}
