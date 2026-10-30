package siteobject

import (
	"bytes"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// Dynamic routing delivery (site_runtime 9, ADR 0009 section 8.1): the same
// signed root, buckets, scope, encryption and FetchSiteObjects as site
// runtime v8, but the bucket entries address cdnca.edge.site/v2 objects
// (libs/edgeconfig/edgesite) that the node activates as they are, without
// rebuilding a bundle. The scope object lists the scope's CRS rule text and
// profile packs; the objects a site reads at request time (CC policies, HTTP
// policy entries, error page bodies, client CAs, ...) are members of the
// publication fetched by the digests the site object names.
const (
	RootSchemaV2   = "cdnca.edge.site-root/v2"
	BucketSchemaV2 = "cdnca.edge.site-bucket/v2"
	ScopeSchemaV2  = "cdnca.edge.site-scope/v2"

	RootMediaTypeV2 = "application/vnd.cdnca.edge-site-root+json;version=2"

	// DynamicRoutingSiteRuntimeVersion mirrors
	// edgeconfig.DynamicRoutingSiteRuntimeVersion (this package cannot
	// import the constant's users).
	DynamicRoutingSiteRuntimeVersion uint32 = 9

	// ScopeFilePrefixV2 is the release directory the v2 scope carries files
	// from (CRS rule text and CRS profile packs).
	ScopeFilePrefixV2 = "security/modsecurity/"
)

// RootV2 is the signed root of a dynamic routing publication.
// DocumentSHA256 binds it to the canonical v2 document control keeps as the
// config version's snapshot; the node does not rebuild the document.
type RootV2 struct {
	Schema               string       `json:"schema"`
	ConfigurationScopeID string       `json:"configuration_scope_id"`
	ConfigVersionID      string       `json:"config_version_id"`
	SourceRevision       int64        `json:"source_revision"`
	KeyEpoch             int64        `json:"key_epoch"`
	RequiredCapabilities []Capability `json:"required_capabilities"`
	DocumentSHA256       string       `json:"document_sha256"`
	ScopeSHA256          string       `json:"scope_sha256"`
	BucketCount          int          `json:"bucket_count"`
	Buckets              []string     `json:"buckets"`
}

// ScopeV2 lists the scope's files (CRS rule text, CRS profile packs) and the
// digests of every object the sites reference (Objects, sorted), so a node
// fetches exactly the publication's members.
type ScopeV2 struct {
	Schema               string    `json:"schema"`
	ConfigurationScopeID string    `json:"configuration_scope_id"`
	Files                []FileRef `json:"files"`
	Objects              []string  `json:"objects"`
	// System is the platform system configuration the v2 document carries
	// (nginx base and DDoS protection); a node serving several scopes runs
	// the highest revision (edgeconfig.SelectSiteRuntimeSystem).
	System *edgeconfig.SiteRuntimeSystem `json:"system,omitempty"`
	// Streams are the scope's L4 forwards (v2 streams only; D13-c0): a node
	// serving several scopes merges them into its L4 runtime.
	Streams *edgeconfig.StreamRuntime `json:"streams,omitempty"`
	// NodePages are the scope's node pages (global no_host / unknown_site
	// error pages, D13-b2; the slot pages and their region / node overrides,
	// errpage-3). The bodies are members of Objects. Sorted by NodePageKey,
	// unique.
	NodePages []NodePageV2 `json:"node_pages,omitempty"`
	// InstallationID is the control installation the scope's telemetry is
	// reported for (the v8 scope's telemetry.installation_id; the node's
	// independent connections metrics name it, D13-b2). "" = none.
	InstallationID string `json:"installation_id,omitempty"`
}

// Node page categories (errorpage no_host / unknown_site).
const (
	NodePageNoHost      = "no_host"
	NodePageUnknownSite = "unknown_site"
)

// Slot node pages (errpage-3, CAPABILITY_NAME_ERROR_PAGE_SLOTS v1): the
// platform's bound error page slots for responses the node gives itself.
// A scope carrying one needs ErrorPageSlotsCapability.
const (
	NodePageBlacklist       = "blacklist"        // listed ban 403 (cdnca_banlist)
	NodePageHTTP403         = "http_403"         // edge 403 of a non-WAF block (ACL, IP lists, region, Referer/UA)
	NodePageTrafficExceeded = "traffic_exceeded" // site traffic cap 509 (site without its own notice)
	NodePagePackageExpired  = "package_expired"  // site whose package ended (no origin request)
	NodePageNodeIPAccess    = "node_ip_access"   // Host is an IP address no site serves
	NodePageConnectionLimit = "connection_limit" // connection / QPS / bandwidth refusal 503

	ErrorPageSlotsCapability        = "error_page_slots"
	ErrorPageSlotsAPIVersion uint32 = 1
)

// SlotNodePageStatus is the status a slot node page answers with.
var SlotNodePageStatus = map[string]int{
	NodePageBlacklist: 403, NodePageHTTP403: 403, NodePageTrafficExceeded: 509, NodePagePackageExpired: 403,
	NodePageNodeIPAccess: 403, NodePageConnectionLimit: 503,
}

// NodePageV2 is one node page: its status (no_host 400; unknown_site 403,
// 404, 410 or 421; a slot page SlotNodePageStatus), media type, the CSP
// source of an HTML theme page's <style> and the body object's digest.
// Region / NodeID (errpage-3 E3, scope overrides; at most one, lower-case)
// restrict it to the nodes of that region or that node: a node takes, per
// category, its own page, else its region's, else the one without either.
type NodePageV2 struct {
	Category  string `json:"category"`
	Status    int    `json:"status"`
	MIMEType  string `json:"mime_type"`
	StyleHash string `json:"style_hash,omitempty"`
	SHA256    string `json:"sha256"`
	Region    string `json:"region,omitempty"`
	NodeID    string `json:"node_id,omitempty"`
}

var (
	styleHashPattern  = regexp.MustCompile(`^sha256-[A-Za-z0-9+/]{43}=$`)
	nodeRegionPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
)

// NodePageKey orders node pages: category, then node, then region.
func NodePageKey(page NodePageV2) string {
	return page.Category + "\x00" + page.NodeID + "\x00" + page.Region
}

// NodePagesNeedSlots reports whether pages need ErrorPageSlotsCapability.
func NodePagesNeedSlots(pages []NodePageV2) bool {
	for _, page := range pages {
		if _, slot := SlotNodePageStatus[page.Category]; slot || page.Region != "" || page.NodeID != "" {
			return true
		}
	}
	return false
}

// validNodePages checks pages against the scope's objects (sorted digests).
func validNodePages(pages []NodePageV2, objects []string) bool {
	for index, page := range pages {
		slotStatus, slot := SlotNodePageStatus[page.Category]
		statusOK := page.Category == NodePageNoHost && page.Status == 400 ||
			page.Category == NodePageUnknownSite && slices.Contains([]int{403, 404, 410, 421}, page.Status) ||
			slot && page.Status == slotStatus
		if !statusOK || index > 0 && NodePageKey(pages[index-1]) >= NodePageKey(page) ||
			page.Region != "" && (page.NodeID != "" || !nodeRegionPattern.MatchString(page.Region)) ||
			page.NodeID != "" && !uuidPattern.MatchString(page.NodeID) ||
			!slices.Contains([]string{"application/json", "text/html", "text/plain"}, page.MIMEType) ||
			page.StyleHash != "" && (page.MIMEType != "text/html" || !styleHashPattern.MatchString(page.StyleHash)) {
			return false
		}
		if _, found := slices.BinarySearch(objects, page.SHA256); !found {
			return false
		}
	}
	return true
}

// SiteV2 is one encoded cdnca.edge.site/v2 object.
type SiteV2 struct {
	SiteID    string
	Revision  int64
	Plaintext []byte
}

type BuildV2Input struct {
	ConfigurationScopeID string
	ConfigVersionID      string
	SourceRevision       int64
	KeyEpoch             int64
	// RequiredCapabilities are the release's: the v2 document's with
	// site_runtime raised to 9 (RootCapabilitiesV2), name order.
	RequiredCapabilities []Capability
	DocumentSHA256       string
	Sites                []SiteV2
	// Referenced: the objects the sites read, by digest.
	Referenced map[string][]byte
	// ScopeFiles: release path -> content, every path under ScopeFilePrefixV2.
	ScopeFiles map[string][]byte
	// System: the document's platform system configuration (nil = none).
	System *edgeconfig.SiteRuntimeSystem
	// Streams: the document's L4 forwards (nil = none).
	Streams *edgeconfig.StreamRuntime
	// NodePages: the scope's node pages, bodies in Referenced.
	NodePages []NodePageV2
	// InstallationID: the scope's telemetry installation ("" = none).
	InstallationID string
}

// BuildV2 builds a dynamic routing publication: the root to sign and every
// object it references once, ordered by digest.
func BuildV2(input BuildV2Input) (Publication, RootV2, error) {
	if !uuidPattern.MatchString(input.ConfigurationScopeID) || !uuidPattern.MatchString(input.ConfigVersionID) ||
		input.SourceRevision < 1 || input.SourceRevision > maxSafeInteger || input.KeyEpoch < 1 ||
		!digestPattern.MatchString(input.DocumentSHA256) {
		return Publication{}, RootV2{}, fmt.Errorf("%w: v2 build input", ErrInvalid)
	}
	if !validRootCapabilitiesAt(input.RequiredCapabilities, DynamicRoutingSiteRuntimeVersion) {
		return Publication{}, RootV2{}, fmt.Errorf("%w: v2 capabilities", ErrInvalid)
	}
	capabilities := append([]Capability(nil), input.RequiredCapabilities...)
	objects := map[string]Object{}
	add := func(kind ObjectKind, plaintext []byte) (string, error) {
		if len(plaintext) == 0 || len(plaintext) > MaxObjectBytes {
			return "", fmt.Errorf("%w: %s object of %d bytes", ErrInvalid, kind, len(plaintext))
		}
		digest := Digest(plaintext)
		if _, present := objects[digest]; !present {
			objects[digest] = Object{SHA256: digest, Kind: kind, Plaintext: bytes.Clone(plaintext)}
		}
		return digest, nil
	}
	for digest, content := range input.Referenced {
		if got, err := add(KindFile, content); err != nil || got != digest {
			return Publication{}, RootV2{}, fmt.Errorf("%w: referenced object %s", ErrInvalid, digest)
		}
	}
	if input.System != nil {
		if err := input.System.Validate(); err != nil {
			return Publication{}, RootV2{}, fmt.Errorf("%w: v2 system: %v", ErrInvalid, err)
		}
	}
	if err := validateStreamsV2(input.ConfigVersionID, input.SourceRevision, input.Streams); err != nil {
		return Publication{}, RootV2{}, err
	}
	scope := ScopeV2{Schema: ScopeSchemaV2, ConfigurationScopeID: input.ConfigurationScopeID, Files: []FileRef{},
		Objects: make([]string, 0, len(input.Referenced)), System: input.System, Streams: input.Streams,
		InstallationID: input.InstallationID}
	if input.InstallationID != "" && !uuidPattern.MatchString(input.InstallationID) {
		return Publication{}, RootV2{}, fmt.Errorf("%w: v2 installation", ErrInvalid)
	}
	for digest := range input.Referenced {
		scope.Objects = append(scope.Objects, digest)
	}
	sort.Strings(scope.Objects)
	if NodePagesNeedSlots(input.NodePages) && !hasCapability(capabilities, ErrorPageSlotsCapability, ErrorPageSlotsAPIVersion) {
		return Publication{}, RootV2{}, fmt.Errorf("%w: v2 slot node pages need %s", ErrInvalid, ErrorPageSlotsCapability)
	}
	if len(input.NodePages) > 0 {
		scope.NodePages = append([]NodePageV2(nil), input.NodePages...)
		sort.Slice(scope.NodePages, func(i, j int) bool { return NodePageKey(scope.NodePages[i]) < NodePageKey(scope.NodePages[j]) })
		if !validNodePages(scope.NodePages, scope.Objects) {
			return Publication{}, RootV2{}, fmt.Errorf("%w: v2 node pages", ErrInvalid)
		}
	}
	for path, content := range input.ScopeFiles {
		if !strings.HasPrefix(path, ScopeFilePrefixV2) {
			return Publication{}, RootV2{}, fmt.Errorf("%w: v2 scope file %s", ErrInvalid, path)
		}
		digest, err := add(KindFile, content)
		if err != nil {
			return Publication{}, RootV2{}, err
		}
		scope.Files = append(scope.Files, FileRef{Path: path, SHA256: digest})
	}
	sort.Slice(scope.Files, func(i, j int) bool { return scope.Files[i].Path < scope.Files[j].Path })
	if len(scope.Files) > MaxScopeFiles {
		return Publication{}, RootV2{}, fmt.Errorf("%w: %d v2 scope files", ErrInvalid, len(scope.Files))
	}
	scopeBytes, err := Encode(scope)
	if err != nil {
		return Publication{}, RootV2{}, err
	}
	scopeDigest, err := add(KindScope, scopeBytes)
	if err != nil {
		return Publication{}, RootV2{}, err
	}
	bucketCount, err := BucketCount(len(input.Sites))
	if err != nil {
		return Publication{}, RootV2{}, err
	}
	buckets := make([]Bucket, bucketCount)
	for index := range buckets {
		buckets[index] = Bucket{Schema: BucketSchemaV2, ConfigurationScopeID: input.ConfigurationScopeID,
			BucketCount: bucketCount, Index: index, Sites: []BucketEntry{}}
	}
	sites := append([]SiteV2(nil), input.Sites...)
	sort.Slice(sites, func(i, j int) bool { return sites[i].SiteID < sites[j].SiteID })
	for index, site := range sites {
		if !uuidPattern.MatchString(site.SiteID) || site.Revision < 1 || index > 0 && sites[index-1].SiteID == site.SiteID {
			return Publication{}, RootV2{}, fmt.Errorf("%w: v2 site %s", ErrInvalid, site.SiteID)
		}
		digest, err := add(KindSite, site.Plaintext)
		if err != nil {
			return Publication{}, RootV2{}, err
		}
		bucket := &buckets[BucketIndex(site.SiteID, bucketCount)]
		bucket.Sites = append(bucket.Sites, BucketEntry{SiteID: site.SiteID, Revision: site.Revision, SHA256: digest})
	}
	root := RootV2{
		Schema: RootSchemaV2, ConfigurationScopeID: input.ConfigurationScopeID, ConfigVersionID: input.ConfigVersionID,
		SourceRevision: input.SourceRevision, KeyEpoch: input.KeyEpoch, RequiredCapabilities: capabilities,
		DocumentSHA256: input.DocumentSHA256, ScopeSHA256: scopeDigest, BucketCount: bucketCount,
		Buckets: make([]string, bucketCount),
	}
	indexBytes := 0
	for index := range buckets {
		raw, err := Encode(buckets[index])
		if err != nil {
			return Publication{}, RootV2{}, err
		}
		indexBytes += len(raw)
		if root.Buckets[index], err = add(KindBucket, raw); err != nil {
			return Publication{}, RootV2{}, err
		}
	}
	rootBytes, err := Encode(root)
	if err != nil {
		return Publication{}, RootV2{}, err
	}
	if len(rootBytes) > MaxRootBytes || indexBytes+len(rootBytes) > MaxRootIndexBytes {
		return Publication{}, RootV2{}, fmt.Errorf("%w: v2 root index of %d bytes", ErrInvalid, indexBytes+len(rootBytes))
	}
	publication := Publication{RootBytes: rootBytes, RootSHA256: Digest(rootBytes), Objects: make([]Object, 0, len(objects))}
	for _, object := range objects {
		publication.Objects = append(publication.Objects, object)
	}
	sort.Slice(publication.Objects, func(i, j int) bool { return publication.Objects[i].SHA256 < publication.Objects[j].SHA256 })
	return publication, root, nil
}

// ParseRootV2 validates a v2 root's own fields (not its signature).
func ParseRootV2(raw []byte) (RootV2, error) {
	var root RootV2
	if err := decodeStrict(raw, MaxRootBytes, &root); err != nil {
		return RootV2{}, err
	}
	if root.Schema != RootSchemaV2 || !uuidPattern.MatchString(root.ConfigurationScopeID) ||
		!uuidPattern.MatchString(root.ConfigVersionID) || root.SourceRevision < 1 || root.SourceRevision > maxSafeInteger ||
		root.KeyEpoch < 1 || root.KeyEpoch > maxSafeInteger || !digestPattern.MatchString(root.DocumentSHA256) ||
		!digestPattern.MatchString(root.ScopeSHA256) || !validBucketCount(root.BucketCount) ||
		len(root.Buckets) != root.BucketCount ||
		!validRootCapabilitiesAt(root.RequiredCapabilities, DynamicRoutingSiteRuntimeVersion) {
		return RootV2{}, fmt.Errorf("%w: v2 root", ErrInvalid)
	}
	for _, digest := range root.Buckets {
		if !digestPattern.MatchString(digest) {
			return RootV2{}, fmt.Errorf("%w: v2 root bucket digest", ErrInvalid)
		}
	}
	return root, nil
}

// ParseBucketV2 is ParseBucket for a v2 root's buckets.
func ParseBucketV2(raw []byte) (Bucket, error) {
	return parseBucket(raw, BucketSchemaV2)
}

func ParseScopeV2(raw []byte) (ScopeV2, error) {
	var scope ScopeV2
	if err := decodeStrict(raw, MaxObjectBytes, &scope); err != nil {
		return ScopeV2{}, err
	}
	if scope.Schema != ScopeSchemaV2 || !uuidPattern.MatchString(scope.ConfigurationScopeID) || scope.Files == nil ||
		len(scope.Files) > MaxScopeFiles || !validFileRefs(scope.Files) || scope.Objects == nil {
		return ScopeV2{}, fmt.Errorf("%w: v2 scope", ErrInvalid)
	}
	for index, digest := range scope.Objects {
		if !digestPattern.MatchString(digest) || index > 0 && scope.Objects[index-1] >= digest {
			return ScopeV2{}, fmt.Errorf("%w: v2 scope object", ErrInvalid)
		}
	}
	for _, file := range scope.Files {
		if !strings.HasPrefix(file.Path, ScopeFilePrefixV2) {
			return ScopeV2{}, fmt.Errorf("%w: v2 scope file %s", ErrInvalid, file.Path)
		}
	}
	if scope.System != nil {
		if err := scope.System.Validate(); err != nil {
			return ScopeV2{}, fmt.Errorf("%w: v2 scope system: %v", ErrInvalid, err)
		}
	}
	if scope.Streams != nil && len(scope.Streams.StreamsV2) == 0 {
		return ScopeV2{}, fmt.Errorf("%w: v2 scope streams", ErrInvalid)
	}
	if scope.InstallationID != "" && !uuidPattern.MatchString(scope.InstallationID) {
		return ScopeV2{}, fmt.Errorf("%w: v2 scope installation", ErrInvalid)
	}
	if scope.NodePages != nil && (len(scope.NodePages) == 0 || !validNodePages(scope.NodePages, scope.Objects)) {
		return ScopeV2{}, fmt.Errorf("%w: v2 scope node pages", ErrInvalid)
	}
	return scope, nil
}

// validateStreamsV2 checks a scope's L4 forwards as the v2 document's L4
// artifact is rendered (ports shared with websites are the node's to
// check, across scopes): at least one stream.
func validateStreamsV2(versionID string, revision int64, streams *edgeconfig.StreamRuntime) error {
	if streams == nil {
		return nil
	}
	if len(streams.StreamsV2) == 0 {
		return fmt.Errorf("%w: v2 streams: empty", ErrInvalid)
	}
	if _, _, err := edgeconfig.RenderSharedStreamFragment(versionID, uint64(revision), *streams, 0, nil); err != nil {
		return fmt.Errorf("%w: v2 streams: %v", ErrInvalid, err)
	}
	return nil
}

// RootCapabilitiesV2 is document's required capabilities with site_runtime
// raised to DynamicRoutingSiteRuntimeVersion.
func RootCapabilitiesV2(document []Capability) ([]Capability, error) {
	return rootCapabilitiesAt(document, DynamicRoutingSiteRuntimeVersion)
}

func hasCapability(values []Capability, name string, version uint32) bool {
	for _, value := range values {
		if value.Name == name && value.APIVersion >= version {
			return true
		}
	}
	return false
}

// maxSafeInteger bounds revisions and epochs (JSON numbers stay exact).
const maxSafeInteger = int64(1<<53 - 1)

// DocumentPath is the site runtime v2 document's path in the release bundle.
const DocumentPath = "site-runtime.v2.json"

// ObjectKind is advisory (control stores it for diagnostics); objects are
// identified by digest alone.
type ObjectKind string

const (
	KindScope  ObjectKind = "scope"
	KindBucket ObjectKind = "bucket"
	KindSite   ObjectKind = "site"
	KindFile   ObjectKind = "file"
)

type Object struct {
	SHA256    string
	Kind      ObjectKind
	Plaintext []byte
}

// Publication is a built release: the root plaintext (to sign) and every
// object it references, once each, ordered by digest.
type Publication struct {
	RootBytes  []byte
	RootSHA256 string
	Objects    []Object
}

// SiteDigests returns the site objects a bucket references.
func (bucket Bucket) SiteDigests() []string {
	result := make([]string, len(bucket.Sites))
	for index, entry := range bucket.Sites {
		result[index] = entry.SHA256
	}
	return result
}

// FileDigests returns the file objects a site or scope references.
func FileDigests(files []FileRef) []string {
	result := make([]string, len(files))
	for index, file := range files {
		result[index] = file.SHA256
	}
	return result
}
