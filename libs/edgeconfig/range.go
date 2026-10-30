package edgeconfig

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

const (
	RangeCacheSchemaVersion = "cdnca.edge.range-cache/v1"
	RangeCacheLuaPath       = "/usr/local/share/cdnca/?.lua"

	RangeCacheMaxPolicyBytes          = 256 << 10
	RangeCacheMaxPolicyVersion        = 1<<53 - 1
	RangeCacheMaxSites                = 64
	RangeCacheMinSliceBytes     int64 = 64 << 10
	RangeCacheMaxSliceBytes     int64 = 16 << 20
	RangeCacheMaxCacheBytes     int64 = 1 << 40
	RangeCacheMaxCacheSeconds         = 7 * 24 * 60 * 60
	RangeCacheMinHeaderBytes          = 1024
	RangeCacheMaxHeaderBytes          = 64 << 10
	RangeCacheMaxRanges               = 16
	RangeCacheMaxRangeSpanBytes       = 64 << 20

	rangeCacheMaxAggregateBytes int64 = 16 << 40
)

var ErrInvalidRangeCachePolicy = errors.New("invalid Range cache policy")

type RangeCachePolicy struct {
	SchemaVersion          string `json:"schema_version"`
	PolicyVersion          uint64 `json:"policy_version"`
	SliceBytes             int64  `json:"slice_bytes"`
	CacheMaxBytes          int64  `json:"cache_max_bytes"`
	CacheInactiveSeconds   uint32 `json:"cache_inactive_seconds"`
	CacheValidSeconds      uint32 `json:"cache_valid_seconds"`
	MaxRangeHeaderBytes    uint32 `json:"max_range_header_bytes"`
	MaxIfRangeHeaderBytes  uint32 `json:"max_if_range_header_bytes"`
	MaxResponseHeaderBytes uint32 `json:"max_response_header_bytes"`
}

type RangeCacheDocument struct {
	SchemaVersion          string `json:"schema_version"`
	PolicyVersion          uint64 `json:"policy_version"`
	TenantID               string `json:"tenant_id"`
	SiteID                 string `json:"site_id"`
	Domain                 string `json:"domain"`
	ListenPort             uint16 `json:"listen_port"`
	URLAuthPolicyID        string `json:"url_auth_policy_id,omitempty"`
	SliceBytes             int64  `json:"slice_bytes"`
	CacheMaxBytes          int64  `json:"cache_max_bytes"`
	CacheInactiveSeconds   uint32 `json:"cache_inactive_seconds"`
	CacheValidSeconds      uint32 `json:"cache_valid_seconds"`
	MaxRangeHeaderBytes    uint32 `json:"max_range_header_bytes"`
	MaxIfRangeHeaderBytes  uint32 `json:"max_if_range_header_bytes"`
	MaxResponseHeaderBytes uint32 `json:"max_response_header_bytes"`
}

func NormalizeRangeCachePolicy(input RangeCachePolicy) (RangeCachePolicy, error) {
	if input.SchemaVersion != RangeCacheSchemaVersion {
		return RangeCachePolicy{}, invalidRangeCache("schema_version must be %q", RangeCacheSchemaVersion)
	}
	if input.PolicyVersion == 0 || input.PolicyVersion > RangeCacheMaxPolicyVersion {
		return RangeCachePolicy{}, invalidRangeCache("policy_version is out of range")
	}
	if input.SliceBytes < RangeCacheMinSliceBytes || input.SliceBytes > RangeCacheMaxSliceBytes || input.SliceBytes%4096 != 0 {
		return RangeCachePolicy{}, invalidRangeCache("slice_bytes is out of range")
	}
	if input.CacheMaxBytes < input.SliceBytes || input.CacheMaxBytes > RangeCacheMaxCacheBytes {
		return RangeCachePolicy{}, invalidRangeCache("cache_max_bytes is out of range")
	}
	if input.CacheInactiveSeconds == 0 || input.CacheInactiveSeconds > RangeCacheMaxCacheSeconds ||
		input.CacheValidSeconds == 0 || input.CacheValidSeconds > RangeCacheMaxCacheSeconds {
		return RangeCachePolicy{}, invalidRangeCache("cache duration is out of range")
	}
	for _, value := range []uint32{input.MaxRangeHeaderBytes, input.MaxIfRangeHeaderBytes, input.MaxResponseHeaderBytes} {
		if value < RangeCacheMinHeaderBytes || value > RangeCacheMaxHeaderBytes || value&(value-1) != 0 {
			return RangeCachePolicy{}, invalidRangeCache("header bound is not a supported power of two")
		}
	}
	return input, nil
}

func CanonicalRangeCachePolicy(input RangeCacheDocument) ([]byte, error) {
	normalized, err := normalizeRangeCacheDocument(input)
	if err != nil {
		return nil, err
	}
	content, err := json.Marshal(normalized)
	if err != nil {
		return nil, fmt.Errorf("marshal canonical Range cache policy: %w", err)
	}
	return append(content, '\n'), nil
}

func DecodeRangeCachePolicy(content []byte) (RangeCacheDocument, error) {
	if len(content) == 0 || len(content) > RangeCacheMaxPolicyBytes {
		return RangeCacheDocument{}, invalidRangeCache("policy size is invalid")
	}
	if err := RejectDuplicateJSONKeys(content); err != nil {
		return RangeCacheDocument{}, invalidRangeCache("policy JSON is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var document RangeCacheDocument
	if err := decoder.Decode(&document); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return RangeCacheDocument{}, invalidRangeCache("policy JSON is invalid")
	}
	return normalizeRangeCacheDocument(document)
}

func ValidateRangeCacheBundle(bundle Bundle) error {
	nginx := bundle.Files["nginx.conf"]
	hasRangeRuntime := bytes.Contains(nginx, []byte(`require("range.guard")`)) ||
		bytes.Contains(nginx, []byte(`/shared/range/`))
	policyCount := 0
	var parsedNginx *nginxDocument
	var httpBlock int
	var cachePaths map[string][]nginxDirective
	luaPackagePathOK := false
	for path, content := range bundle.Files {
		if !strings.HasPrefix(path, "range/") {
			continue
		}
		if !validRangeCachePolicyPath(path) {
			return fmt.Errorf("%w: unexpected Range cache file %q", ErrInvalidBundle, path)
		}
		document, err := DecodeRangeCachePolicy(content)
		if err != nil {
			return fmt.Errorf("%w: invalid Range cache policy", ErrInvalidBundle)
		}
		canonical, err := CanonicalRangeCachePolicy(document)
		if err != nil || !bytes.Equal(canonical, content) {
			return fmt.Errorf("%w: Range cache policy is not canonical", ErrInvalidBundle)
		}
		if parsedNginx == nil {
			var ok bool
			parsedNginx, ok = parseNginxDirectives(string(nginx))
			if !ok || parsedNginx.hasInclude {
				return fmt.Errorf("%w: Range cache Nginx configuration is invalid", ErrInvalidBundle)
			}
			httpBlock, ok = uniqueUnquotedNginxBlock(parsedNginx, 0, []string{"http"})
			if !ok {
				return fmt.Errorf("%w: Range cache Nginx HTTP block is invalid", ErrInvalidBundle)
			}
			cachePaths, ok = indexNginxCachePaths(parsedNginx, httpBlock)
			if !ok {
				return fmt.Errorf("%w: Range cache path configuration is invalid", ErrInvalidBundle)
			}
			luaPackagePathOK = rangeCacheLuaPackagePathBound(parsedNginx, httpBlock)
		}
		siteNumber, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(path, "range/site_"), ".json"))
		publicServer, ok := uniquePublicNginxServer(parsedNginx, httpBlock, document.Domain, document.ListenPort)
		if !ok {
			return fmt.Errorf("%w: Range cache policy is not bound to a public server", ErrInvalidBundle)
		}
		publicLocation, ok := uniqueUnquotedNginxBlock(parsedNginx, publicServer, []string{"location", "/"})
		generatedSite, generatedOK := rangeCacheGeneratedSiteBinding(parsedNginx, httpBlock, publicServer)
		urlAuthRequired, urlAuthOK := rangeCacheURLAuthBindingRequired(parsedNginx, httpBlock, document)
		if !ok || !generatedOK || generatedSite != siteNumber ||
			!urlAuthOK || !validateRangeCacheLuaHooks(parsedNginx, publicLocation, document, urlAuthRequired) {
			return fmt.Errorf("%w: Range cache policy is not bound to the public location", ErrInvalidBundle)
		}
		cacheKeys := parsedNginx.directNamed(publicLocation, "proxy_cache_key")
		bindingSuffix := fmt.Sprintf("|policy=%d|tenant=%s|site=%s|range=$range_cache_effective_range|scheme=$scheme|host=$host|port=$server_port|request=$request_uri",
			document.PolicyVersion, document.TenantID, document.SiteID)
		if len(cacheKeys) != 1 || len(cacheKeys[0].fields) != 2 || !strings.HasPrefix(cacheKeys[0].fields[1], "v=") ||
			!strings.HasSuffix(cacheKeys[0].fields[1], bindingSuffix) {
			return fmt.Errorf("%w: Range cache policy is not bound to the generated location", ErrInvalidBundle)
		}
		configVersion := strings.TrimSuffix(strings.TrimPrefix(cacheKeys[0].fields[1], "v="), bindingSuffix)
		manifest := CachePolicyManifest{TenantID: document.TenantID, ConfigVersionID: configVersion}
		listener := CacheListenerPolicy{SiteID: document.SiteID, Domain: document.Domain, ListenPort: document.ListenPort}
		rangeZone, rangeOK := nginxRangeCacheContract(parsedNginx, httpBlock, publicLocation, cachePaths, manifest, listener)
		rangePathBindingOK := false
		if rangeOK {
			directives := cachePaths[rangeZone]
			rangePathBindingOK = len(directives) == 1 &&
				directives[0].fields[4] == "inactive="+strconv.FormatUint(uint64(document.CacheInactiveSeconds), 10)+"s" &&
				directives[0].fields[5] == "max_size="+strconv.FormatInt(document.CacheMaxBytes, 10)
		}
		if configVersion == "" || strings.Contains(configVersion, "|") || !rangePathBindingOK ||
			!hasExactDirectNginxDirectives(parsedNginx, publicLocation,
				[]string{"proxy_pass", fmt.Sprintf("http://site_%04d", siteNumber)}) ||
			!hasExactDirectNginxDirectives(parsedNginx, publicLocation,
				[]string{"slice", strconv.FormatInt(document.SliceBytes, 10)},
				[]string{"proxy_cache_valid", "200", "206", strconv.FormatUint(uint64(document.CacheValidSeconds), 10) + "s"},
				[]string{"proxy_cache_valid", "any", "0s"}) {
			return fmt.Errorf("%w: Range cache policy is not bound to the generated site", ErrInvalidBundle)
		}
		policyCount++
	}
	if policyCount == 0 && !hasRangeRuntime {
		return nil
	}
	rangePathCount := 0
	for zone := range cachePaths {
		if strings.HasPrefix(zone, "range_cache_") {
			rangePathCount++
		}
	}
	if policyCount == 0 || policyCount > RangeCacheMaxSites || rangePathCount != policyCount ||
		!luaPackagePathOK {
		return fmt.Errorf("%w: Range cache runtime is incomplete", ErrInvalidBundle)
	}
	return nil
}

func rangeCacheLuaPackagePathBound(document *nginxDocument, httpBlock int) bool {
	directives := document.directNamed(httpBlock, "lua_package_path")
	if len(directives) != 1 || directives[0].nameQuoted || len(directives[0].fields) != 2 ||
		len(directives[0].fieldQuoted) != 2 || !directives[0].fieldQuoted[1] {
		return false
	}
	entries := strings.Split(directives[0].fields[1], ";")
	for len(entries) > 0 && entries[len(entries)-1] == "" {
		entries = entries[:len(entries)-1]
	}
	foundExact := false
	for _, entry := range entries {
		if entry == "" {
			return false
		}
		if entry == RangeCacheLuaPath {
			foundExact = true
		}
	}
	return foundExact
}

func rangeCacheURLAuthBindingRequired(document *nginxDocument, httpBlock int, policy RangeCacheDocument) (bool, bool) {
	if policy.URLAuthPolicyID == "" {
		return false, true
	}
	pids := document.directNamed(0, "pid")
	const pidSuffix = "/shared/nginx.pid"
	if len(pids) != 1 || pids[0].nameQuoted || len(pids[0].fields) != 2 ||
		!strings.HasSuffix(pids[0].fields[1], pidSuffix) {
		return false, false
	}
	stateRoot := strings.TrimSuffix(pids[0].fields[1], pidSuffix)
	if !safeAbsolutePath(stateRoot) {
		return false, false
	}
	expectedPolicyPath := stateRoot + "/urlauth/policies/" + policy.URLAuthPolicyID + "/current.json"
	initBlocks := document.blockNamed(httpBlock, "init_by_lua_block")
	if len(initBlocks) == 0 {
		return false, false
	}
	if len(initBlocks) != 1 {
		return false, false
	}
	body, exists := document.opaqueBodies[initBlocks[0].blockID]
	if !exists {
		return false, false
	}
	body, _, split := splitChallengeInitTail(strings.TrimSpace(body))
	if !split {
		return false, false
	}
	const marker = `require("url_auth").init({`
	if !strings.Contains(body, marker) {
		return false, false
	}
	if strings.Count(body, marker) != 1 {
		return false, false
	}
	start := strings.Index(body, marker)
	lineStart := strings.LastIndexByte(body[:start], '\n') + 1
	if strings.TrimSpace(body[lineStart:start]) != "" {
		return false, false
	}
	const prefix = marker + "\n      state_dict = \"cdnca_url_auth_state\",\n      bindings = {\n"
	section := body[start:]
	const closing = "\n      },\n    })"
	if !strings.HasPrefix(section, prefix) || !strings.HasSuffix(section, closing) {
		return false, false
	}
	entries := strings.TrimSuffix(strings.TrimPrefix(section, prefix), closing)
	if entries == "" {
		return false, false
	}
	found := 0
	for _, line := range strings.Split(entries, "\n") {
		const entryPrefix = `        { tenant_id = "`
		const tenantSeparator = `", site_id = "`
		const siteSeparator = `", listen_port = `
		const portSeparator = `, policy_path = "`
		if !strings.HasPrefix(line, entryPrefix) || !strings.HasSuffix(line, `" },`) {
			return false, false
		}
		value := strings.TrimSuffix(strings.TrimPrefix(line, entryPrefix), `" },`)
		tenantEnd := strings.Index(value, tenantSeparator)
		if tenantEnd <= 0 {
			return false, false
		}
		tenant := value[:tenantEnd]
		remainder := value[tenantEnd+len(tenantSeparator):]
		siteEnd := strings.Index(remainder, siteSeparator)
		if siteEnd <= 0 {
			return false, false
		}
		site := remainder[:siteEnd]
		remainder = remainder[siteEnd+len(siteSeparator):]
		portEnd := strings.Index(remainder, portSeparator)
		if portEnd <= 0 {
			return false, false
		}
		portText := remainder[:portEnd]
		port, portErr := strconv.ParseUint(portText, 10, 16)
		path := remainder[portEnd+len(portSeparator):]
		if !uuidPattern.MatchString(tenant) || !uuidPattern.MatchString(site) || portErr != nil || port == 0 ||
			portText != strconv.FormatUint(port, 10) || !safeAbsolutePath(path) ||
			strings.ContainsAny(path, "\"\r\n") {
			return false, false
		}
		if tenant == policy.TenantID && site == policy.SiteID && uint16(port) == policy.ListenPort {
			if path != expectedPolicyPath {
				return false, false
			}
			found++
		}
	}
	return found == 1, found == 1
}

func rangeCacheGeneratedSiteBinding(document *nginxDocument, httpBlock, targetServer int) (int, bool) {
	publicServers := make([]int, 0)
	for _, directive := range document.blockNamed(httpBlock, "server") {
		if directive.nameQuoted || !equalNginxFields(directive.fields, []string{"server"}) {
			return 0, false
		}
		if _, ok := uniqueUnquotedNginxBlock(document, directive.blockID, []string{"location", "/"}); ok {
			publicServers = append(publicServers, directive.blockID)
		}
	}

	upstreams := make(map[int]struct{}, len(publicServers))
	for _, directive := range document.blockNamed(httpBlock, "upstream") {
		if len(directive.fields) < 2 || !strings.HasPrefix(directive.fields[1], "site_") {
			continue
		}
		if directive.nameQuoted || len(directive.fields) != 2 ||
			!validRangeCachePolicyPath("range/"+directive.fields[1]+".json") {
			return 0, false
		}
		servers := document.directNamed(directive.blockID, "server")
		if len(servers) == 0 || len(document.blockNamed(directive.blockID, "server")) != 0 {
			return 0, false
		}
		for _, server := range servers {
			if server.nameQuoted || server.multiline || len(server.fields) != 4 ||
				len(server.fieldQuoted) != len(server.fields) {
				return 0, false
			}
			for _, quoted := range server.fieldQuoted {
				if quoted {
					return 0, false
				}
			}
			host, portValue, err := net.SplitHostPort(server.fields[1])
			if err != nil {
				return 0, false
			}
			host, err = normalizeOriginHost(host)
			port, portErr := strconv.ParseUint(portValue, 10, 16)
			weightValue := strings.TrimPrefix(server.fields[2], "weight=")
			weight, weightErr := strconv.ParseUint(weightValue, 10, 8)
			if err != nil || portErr != nil || port == 0 ||
				portValue != strconv.FormatUint(port, 10) ||
				server.fields[1] != originEndpoint(Origin{Host: host, Port: uint16(port)}) ||
				weightErr != nil || weight == 0 || weight > 100 ||
				server.fields[2] != "weight="+strconv.FormatUint(weight, 10) ||
				server.fields[3] != "max_fails=0" {
				return 0, false
			}
		}
		siteNumber, _ := strconv.Atoi(strings.TrimPrefix(directive.fields[1], "site_"))
		if _, exists := upstreams[siteNumber]; exists {
			return 0, false
		}
		upstreams[siteNumber] = struct{}{}
	}
	if len(upstreams) != len(publicServers) {
		return 0, false
	}

	targetSite := 0
	for index, server := range publicServers {
		siteNumber := index + 1
		if _, exists := upstreams[siteNumber]; !exists {
			return 0, false
		}
		references := make(map[int]struct{}, 1)
		blocks := []int{server}
		for len(blocks) != 0 {
			block := blocks[len(blocks)-1]
			blocks = blocks[:len(blocks)-1]
			for _, directive := range document.directNamed(block, "proxy_pass") {
				if directive.nameQuoted || len(directive.fields) != 2 ||
					!strings.HasPrefix(directive.fields[1], "http://site_") {
					continue
				}
				upstream := strings.TrimPrefix(directive.fields[1], "http://")
				if !validRangeCachePolicyPath("range/" + upstream + ".json") {
					return 0, false
				}
				reference, _ := strconv.Atoi(strings.TrimPrefix(upstream, "site_"))
				references[reference] = struct{}{}
			}
			for _, directives := range document.blockNames[block] {
				for _, directive := range directives {
					blocks = append(blocks, directive.blockID)
				}
			}
		}
		if len(references) != 1 {
			return 0, false
		}
		if _, exists := references[siteNumber]; !exists {
			return 0, false
		}
		if server == targetServer {
			targetSite = siteNumber
		}
	}
	return targetSite, targetSite != 0
}

func validateRangeCacheLuaHooks(document *nginxDocument, location int, policy RangeCacheDocument, urlAuthRequired bool) bool {
	body := func(name string) (string, bool) {
		directives := document.blockNamed(location, name)
		if len(directives) != 1 || directives[0].nameQuoted ||
			!equalNginxFields(directives[0].fields, []string{name}) {
			return "", false
		}
		content, ok := document.opaqueBodies[directives[0].blockID]
		return strings.TrimSpace(content), ok
	}
	access, accessOK := body("access_by_lua_block")
	header, headerOK := body("header_filter_by_lua_block")
	filter, filterOK := body("body_filter_by_lua_block")
	if !accessOK || !headerOK || !filterOK {
		return false
	}
	expectedAccess := fmt.Sprintf(`require("range.guard").access({ max_range_bytes = %d, max_if_range_bytes = %d, max_ranges = %d, max_range_span_bytes = %d })`,
		policy.MaxRangeHeaderBytes, policy.MaxIfRangeHeaderBytes, RangeCacheMaxRanges, RangeCacheMaxRangeSpanBytes)
	var combined strings.Builder
	renderURLAuthAccess(&combined, normalizedSpec{TenantID: policy.TenantID},
		Site{ID: policy.SiteID, ListenPort: policy.ListenPort})
	fmt.Fprintf(&combined, "        %s\n", expectedAccess)
	validAccess := access == expectedAccess
	if urlAuthRequired {
		validAccess = access == strings.TrimSpace(combined.String())
	}
	return validAccess &&
		header == fmt.Sprintf(`require("range.guard").header_filter({ max_header_bytes = %d })`, policy.MaxResponseHeaderBytes) &&
		filter == `require("range.guard").body_filter()`
}

func normalizeRangeCacheDocument(input RangeCacheDocument) (RangeCacheDocument, error) {
	policy, err := NormalizeRangeCachePolicy(RangeCachePolicy{
		SchemaVersion: input.SchemaVersion, PolicyVersion: input.PolicyVersion,
		SliceBytes: input.SliceBytes, CacheMaxBytes: input.CacheMaxBytes,
		CacheInactiveSeconds: input.CacheInactiveSeconds, CacheValidSeconds: input.CacheValidSeconds,
		MaxRangeHeaderBytes: input.MaxRangeHeaderBytes, MaxIfRangeHeaderBytes: input.MaxIfRangeHeaderBytes,
		MaxResponseHeaderBytes: input.MaxResponseHeaderBytes,
	})
	if err != nil {
		return RangeCacheDocument{}, err
	}
	domain, err := normalizeSiteDomainName(input.Domain)
	if err != nil || !uuidPattern.MatchString(input.TenantID) || !uuidPattern.MatchString(input.SiteID) || input.ListenPort == 0 ||
		(input.URLAuthPolicyID != "" && !uuidPattern.MatchString(input.URLAuthPolicyID)) {
		return RangeCacheDocument{}, invalidRangeCache("tenant, site, domain, or listener binding is invalid")
	}
	return RangeCacheDocument{
		SchemaVersion: policy.SchemaVersion, PolicyVersion: policy.PolicyVersion,
		TenantID: input.TenantID, SiteID: input.SiteID, Domain: domain, ListenPort: input.ListenPort,
		URLAuthPolicyID: input.URLAuthPolicyID,
		SliceBytes:      policy.SliceBytes, CacheMaxBytes: policy.CacheMaxBytes,
		CacheInactiveSeconds: policy.CacheInactiveSeconds, CacheValidSeconds: policy.CacheValidSeconds,
		MaxRangeHeaderBytes: policy.MaxRangeHeaderBytes, MaxIfRangeHeaderBytes: policy.MaxIfRangeHeaderBytes,
		MaxResponseHeaderBytes: policy.MaxResponseHeaderBytes,
	}, nil
}

func rangeCacheDocument(spec normalizedSpec, site Site) RangeCacheDocument {
	policy := *site.RangeCache
	document := RangeCacheDocument{
		SchemaVersion: policy.SchemaVersion, PolicyVersion: policy.PolicyVersion,
		TenantID: spec.TenantID, SiteID: site.ID, Domain: site.Domain, ListenPort: site.ListenPort,
		SliceBytes: policy.SliceBytes, CacheMaxBytes: policy.CacheMaxBytes,
		CacheInactiveSeconds: policy.CacheInactiveSeconds, CacheValidSeconds: policy.CacheValidSeconds,
		MaxRangeHeaderBytes: policy.MaxRangeHeaderBytes, MaxIfRangeHeaderBytes: policy.MaxIfRangeHeaderBytes,
		MaxResponseHeaderBytes: policy.MaxResponseHeaderBytes,
	}
	if site.URLAuth != nil {
		document.URLAuthPolicyID = site.URLAuth.PolicyID
	}
	return document
}

func rangeCachePolicyPath(siteIndex int) string {
	return fmt.Sprintf("range/site_%04d.json", siteIndex+1)
}

func validRangeCachePolicyPath(path string) bool {
	const prefix, suffix = "range/site_", ".json"
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		return false
	}
	index := strings.TrimSuffix(strings.TrimPrefix(path, prefix), suffix)
	if len(index) != 4 {
		return false
	}
	value, err := strconv.Atoi(index)
	return err == nil && value > 0 && value <= 1000 && fmt.Sprintf("%04d", value) == index
}

func hasRangeCache(sites []Site) bool {
	for _, site := range sites {
		if site.RangeCache != nil {
			return true
		}
	}
	return false
}

func rangeCacheRequestBufferBytes(sites []Site) uint32 {
	var maximum uint32
	for _, site := range sites {
		if site.RangeCache == nil {
			continue
		}
		value := max(site.RangeCache.MaxRangeHeaderBytes, site.RangeCache.MaxIfRangeHeaderBytes) + 512
		maximum = max(maximum, value)
	}
	return maximum
}

func rangeCacheIdentity(spec normalizedSpec, site Site) string {
	return RangeCacheIdentity(spec.TenantID, site.ID, site.Domain, site.ListenPort)
}

// RangeCacheIdentity names the per-listener Range slice cache directory
// (<state>/shared/range/<identity>). It is independent of the config version,
// so slices written by earlier versions of the same listener share the area.
func RangeCacheIdentity(tenantID, siteID, domain string, listenPort uint16) string {
	digest := sha256.Sum256([]byte(tenantID + "\x00" + siteID + "\x00" + domain + "\x00" + strconv.Itoa(int(listenPort))))
	return hex.EncodeToString(digest[:8])
}

func invalidRangeCache(format string, values ...any) error {
	return errors.Join(ErrInvalidRangeCachePolicy, fmt.Errorf(format, values...))
}
