package rangecache

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

func CompileJSON(raw []byte, paths RuntimePaths) (Artifact, error) {
	if len(raw) == 0 || len(raw) > MaxPolicyBytes {
		return Artifact{}, invalid("policy size must be between 1 and %d bytes", MaxPolicyBytes)
	}
	if err := validateRuntimePaths(paths); err != nil {
		return Artifact{}, err
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return Artifact{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var input Policy
	if err := decoder.Decode(&input); err != nil {
		return Artifact{}, invalid("decode policy: %v", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return Artifact{}, err
	}
	policy, err := normalizePolicy(input)
	if err != nil {
		return Artifact{}, err
	}
	canonical, err := json.Marshal(policy)
	if err != nil {
		return Artifact{}, fmt.Errorf("marshal canonical range cache policy: %w", err)
	}
	canonical = append(canonical, '\n')
	nginx := compileNginx(policy, paths)
	digestInput := make([]byte, 0, len(canonical)+len(nginx))
	digestInput = append(digestInput, canonical...)
	digestInput = append(digestInput, nginx...)
	return Artifact{
		PolicyVersion: policy.PolicyVersion, CanonicalPolicy: canonical, Nginx: nginx,
		Digest: sha256.Sum256(digestInput),
	}, nil
}

func normalizePolicy(input Policy) (Policy, error) {
	if input.SchemaVersion != SchemaVersion {
		return Policy{}, invalid("schema_version must be %q", SchemaVersion)
	}
	if input.PolicyVersion == 0 || input.PolicyVersion > MaxPolicyVersion {
		return Policy{}, invalid("policy_version must be between 1 and %d", MaxPolicyVersion)
	}
	if input.SliceBytes < MinSliceBytes || input.SliceBytes > MaxSliceBytes || input.SliceBytes%4096 != 0 {
		return Policy{}, invalid("slice_bytes must be a 4096-byte multiple between %d and %d", MinSliceBytes, MaxSliceBytes)
	}
	if input.CacheMaxBytes < input.SliceBytes || input.CacheMaxBytes > MaxCacheBytes {
		return Policy{}, invalid("cache_max_bytes must be between slice_bytes and %d", MaxCacheBytes)
	}
	if input.CacheInactiveSeconds == 0 || input.CacheInactiveSeconds > MaxCacheSeconds {
		return Policy{}, invalid("cache_inactive_seconds must be between 1 and %d", MaxCacheSeconds)
	}
	if input.CacheValidSeconds == 0 || input.CacheValidSeconds > MaxCacheSeconds {
		return Policy{}, invalid("cache_valid_seconds must be between 1 and %d", MaxCacheSeconds)
	}
	for field, value := range map[string]uint32{
		"max_range_header_bytes":    input.MaxRangeHeaderBytes,
		"max_if_range_header_bytes": input.MaxIfRangeHeaderBytes,
		"max_response_header_bytes": input.MaxResponseHeaderBytes,
	} {
		if value < MinHeaderBytes || value > MaxHeaderBytes || value&(value-1) != 0 {
			return Policy{}, invalid("%s must be a power of two between %d and %d", field, MinHeaderBytes, MaxHeaderBytes)
		}
	}
	if len(input.Sites) == 0 || len(input.Sites) > MaxSites {
		return Policy{}, invalid("site count must be between 1 and %d", MaxSites)
	}

	result := input
	result.Sites = make([]Site, len(input.Sites))
	bindings := make(map[string]string)
	identifiers := make(map[string]struct{})
	for index, site := range input.Sites {
		normalized, err := normalizeSite(site)
		if err != nil {
			return Policy{}, invalid("site %d: %v", index, err)
		}
		if _, exists := identifiers[normalized.SiteID]; exists {
			return Policy{}, invalid("duplicate site_id %q", normalized.SiteID)
		}
		identifiers[normalized.SiteID] = struct{}{}
		for _, host := range normalized.Hosts {
			key := listener(normalized.ListenAddress, normalized.ListenPort) + "\x00" + host
			if previous, exists := bindings[key]; exists {
				return Policy{}, invalid("host %q on listener %s is shared by sites %q and %q", host, listener(normalized.ListenAddress, normalized.ListenPort), previous, normalized.SiteID)
			}
			bindings[key] = normalized.SiteID
		}
		result.Sites[index] = normalized
	}
	sort.Slice(result.Sites, func(i, j int) bool { return siteKey(result.Sites[i]) < siteKey(result.Sites[j]) })
	return result, nil
}

func normalizeSite(input Site) (Site, error) {
	if !validIdentifier(input.SiteID) {
		return Site{}, errors.New("site_id is invalid")
	}
	address, err := netip.ParseAddr(input.ListenAddress)
	if err != nil || address.Is4In6() || input.ListenPort == 0 {
		return Site{}, errors.New("listen address or port is invalid")
	}
	origin, err := normalizeHost(input.OriginHost, true)
	if err != nil || input.OriginPort == 0 {
		return Site{}, errors.New("origin host or port is invalid")
	}
	if len(input.Hosts) == 0 || len(input.Hosts) > MaxHostsPerSite {
		return Site{}, fmt.Errorf("host count must be between 1 and %d", MaxHostsPerSite)
	}
	hosts := make([]string, 0, len(input.Hosts))
	seen := make(map[string]struct{}, len(input.Hosts))
	for _, value := range input.Hosts {
		host, err := normalizeHost(value, false)
		if err != nil {
			return Site{}, fmt.Errorf("host %q: %w", value, err)
		}
		if _, exists := seen[host]; exists {
			return Site{}, fmt.Errorf("duplicate host %q", host)
		}
		seen[host] = struct{}{}
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	return Site{
		SiteID: input.SiteID, ListenAddress: address.String(), ListenPort: input.ListenPort,
		Hosts: hosts, OriginHost: origin, OriginPort: input.OriginPort,
	}, nil
}

func compileNginx(policy Policy, paths RuntimePaths) []byte {
	var output bytes.Buffer
	fmt.Fprintf(&output, "# generated by cdnca edge-agent rangecache schema=%s version=%d\n", SchemaVersion, policy.PolicyVersion)
	output.WriteString("worker_processes auto;\n")
	fmt.Fprintf(&output, "pid %s;\n", nginxQuote(filepath.Join(paths.StateRoot, "range-cache.pid")))
	fmt.Fprintf(&output, "error_log %s notice;\n", nginxQuote(filepath.Join(paths.StateRoot, "error.log")))
	output.WriteString("events { worker_connections 4096; }\nhttp {\n")
	output.WriteString("  access_log off;\n  server_tokens off;\n  gzip off;\n")
	fmt.Fprintf(&output, "  lua_package_path %s;\n", nginxQuote(filepath.Join(paths.LuaRoot, "?.lua")+";;"))
	requestBufferBytes := max(policy.MaxRangeHeaderBytes, policy.MaxIfRangeHeaderBytes) + 512
	fmt.Fprintf(&output, "  client_header_buffer_size 1024;\n")
	fmt.Fprintf(&output, "  large_client_header_buffers 4 %d;\n", requestBufferBytes)
	fmt.Fprintf(&output, "  proxy_buffer_size %d;\n", policy.MaxResponseHeaderBytes)
	fmt.Fprintf(&output, "  proxy_buffers 8 %d;\n", policy.MaxResponseHeaderBytes)
	fmt.Fprintf(&output, "  proxy_cache_path %s levels=1:2 keys_zone=range_cache:16m inactive=%ds max_size=%d use_temp_path=off;\n",
		nginxQuote(filepath.Join(paths.StateRoot, "cache")), policy.CacheInactiveSeconds, policy.CacheMaxBytes)
	fmt.Fprintf(&output, "  proxy_temp_path %s;\n", nginxQuote(filepath.Join(paths.StateRoot, "proxy_temp")))
	output.WriteString("  map $request_method $range_cache_method_bypass { default 1; GET 0; HEAD 0; }\n")
	output.WriteString("  map $upstream_http_content_encoding $range_cache_encoded { default 1; \"\" 0; identity 0; }\n")
	output.WriteString("  map $upstream_http_content_length $range_cache_unknown_length { default 0; \"\" 1; }\n")
	output.WriteString("  map $upstream_http_vary $range_cache_vary { default 1; \"\" 0; }\n")
	output.WriteString("  map $http_range $range_cache_effective_range { volatile; default $slice_range; ~, $http_range; }\n")

	for index, site := range policy.Sites {
		fmt.Fprintf(&output, "  upstream range_origin_%03d { server %s; keepalive 8; }\n", index, originAddress(site.OriginHost, site.OriginPort))
	}
	listeners := make(map[string]struct{})
	for _, site := range policy.Sites {
		key := listener(site.ListenAddress, site.ListenPort)
		if _, exists := listeners[key]; exists {
			continue
		}
		listeners[key] = struct{}{}
		output.WriteString("  server {\n")
		fmt.Fprintf(&output, "    listen %s default_server;\n", key)
		output.WriteString("    server_name \"\";\n    return 421;\n  }\n")
	}
	for index, site := range policy.Sites {
		output.WriteString("  server {\n")
		fmt.Fprintf(&output, "    # site_id=%s\n", site.SiteID)
		fmt.Fprintf(&output, "    listen %s;\n", listener(site.ListenAddress, site.ListenPort))
		fmt.Fprintf(&output, "    server_name %s;\n", strings.Join(site.Hosts, " "))
		fmt.Fprintf(&output, "    set $range_cache_policy_version %d;\n", policy.PolicyVersion)
		output.WriteString("    location = /_cdnca/range-healthz { default_type text/plain; return 200 \"ok:$range_cache_policy_version\\n\"; }\n")
		output.WriteString("    location / {\n")
		output.WriteString("      set $range_cache_guard_no_store 0;\n")
		output.WriteString("      access_by_lua_block { require(\"guard\").access({ max_range_bytes = ")
		fmt.Fprintf(&output, "%d, max_if_range_bytes = %d, max_ranges = %d, max_range_span_bytes = %d }) }\n",
			policy.MaxRangeHeaderBytes, policy.MaxIfRangeHeaderBytes, MaxRanges, MaxRangeSpanBytes)
		output.WriteString("      header_filter_by_lua_block { require(\"guard\").header_filter({ max_header_bytes = ")
		fmt.Fprintf(&output, "%d }) }\n", policy.MaxResponseHeaderBytes)
		output.WriteString("      body_filter_by_lua_block { require(\"guard\").body_filter() }\n")
		fmt.Fprintf(&output, "      max_ranges %d;\n      slice ", MaxRanges)
		fmt.Fprintf(&output, "%d;\n", policy.SliceBytes)
		output.WriteString("      proxy_http_version 1.1;\n      proxy_set_header Connection \"\";\n      proxy_set_header Host $host;\n")
		output.WriteString("      proxy_set_header Range $range_cache_effective_range;\n      proxy_set_header If-Range \"\";\n      proxy_set_header Accept-Encoding \"\";\n")
		output.WriteString("      proxy_cache range_cache;\n")
		fmt.Fprintf(&output, "      proxy_cache_key \"v=%d|range=$range_cache_effective_range|scheme=$scheme|host=$host|port=$server_port|request=$request_uri\";\n", policy.PolicyVersion)
		output.WriteString("      proxy_cache_methods GET HEAD;\n      proxy_cache_convert_head on;\n      proxy_cache_lock on;\n      proxy_cache_lock_timeout 5s;\n      proxy_cache_lock_age 5s;\n")
		output.WriteString("      proxy_cache_bypass $range_cache_method_bypass $http_authorization $http_cookie $http_upgrade;\n")
		output.WriteString("      proxy_no_cache $range_cache_method_bypass $http_authorization $http_cookie $http_upgrade;\n")
		output.WriteString("      proxy_no_cache $range_cache_encoded $range_cache_unknown_length $range_cache_vary;\n")
		output.WriteString("      proxy_no_cache $range_cache_guard_no_store $upstream_http_set_cookie;\n")
		fmt.Fprintf(&output, "      proxy_cache_valid 200 206 %ds;\n", policy.CacheValidSeconds)
		output.WriteString("      proxy_cache_valid any 0s;\n      proxy_cache_revalidate on;\n      proxy_force_ranges on;\n")
		output.WriteString("      proxy_hide_header X-CDNCA-Range-Cache;\n      proxy_hide_header X-CDNCA-Range-Config-Version;\n")
		output.WriteString("      add_header X-CDNCA-Range-Cache $upstream_cache_status always;\n")
		fmt.Fprintf(&output, "      add_header X-CDNCA-Range-Config-Version %d always;\n", policy.PolicyVersion)
		fmt.Fprintf(&output, "      proxy_pass http://range_origin_%03d;\n", index)
		output.WriteString("    }\n  }\n")
	}
	output.WriteString("}\n")
	return append([]byte(nil), output.Bytes()...)
}

func validateRuntimePaths(paths RuntimePaths) error {
	for field, value := range map[string]string{"state_root": paths.StateRoot, "lua_root": paths.LuaRoot} {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value || value == string(filepath.Separator) || strings.ContainsAny(value, "\x00\r\n\"'$;{}") {
			return invalid("%s must be a clean absolute non-root path", field)
		}
	}
	return nil
}

func normalizeHost(value string, allowIP bool) (string, error) {
	if len(value) == 0 || len(value) > MaxHostBytes || strings.ContainsAny(value, ":/\\%\x00\r\n\t ") {
		return "", errors.New("must be a bounded hostname without a port or escape")
	}
	if address, err := netip.ParseAddr(value); err == nil {
		if !allowIP || address.Is4In6() {
			return "", errors.New("IP address is not allowed")
		}
		return address.String(), nil
	}
	value = strings.ToLower(strings.TrimSuffix(value, "."))
	if value == "" {
		return "", errors.New("hostname is empty")
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("hostname contains an invalid label")
		}
		for index := range label {
			character := label[index]
			if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' {
				continue
			}
			return "", errors.New("hostname contains an invalid character")
		}
	}
	return value, nil
}

func validIdentifier(value string) bool {
	if len(value) == 0 || len(value) > MaxIdentifierBytes {
		return false
	}
	for index := range value {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || strings.ContainsRune("._:-", rune(character)) {
			continue
		}
		return false
	}
	return true
}

func siteKey(site Site) string {
	return listener(site.ListenAddress, site.ListenPort) + "\x00" + strings.Join(site.Hosts, "\x00") + "\x00" + site.SiteID
}

func listener(host string, port uint16) string {
	if address, err := netip.ParseAddr(host); err == nil && address.Is6() {
		return "[" + host + "]:" + strconv.Itoa(int(port))
	}
	return host + ":" + strconv.Itoa(int(port))
}

func originAddress(host string, port uint16) string {
	return listener(host, port)
}

func nginxQuote(value string) string { return `"` + value + `"` }

func uintString(value uint64) string { return strconv.FormatUint(value, 10) }

func errorf(format string, values ...any) error { return fmt.Errorf(format, values...) }

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return invalid("policy contains trailing JSON")
		}
		return invalid("decode trailing JSON: %v", err)
	}
	return nil
}

type jsonFrame struct {
	object    bool
	expectKey bool
	keys      map[string]struct{}
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	stack := make([]jsonFrame, 0, 8)
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return invalid("decode policy tokens: %v", err)
		}
		switch value := token.(type) {
		case json.Delim:
			switch value {
			case '{':
				stack = append(stack, jsonFrame{object: true, expectKey: true, keys: make(map[string]struct{})})
			case '[':
				stack = append(stack, jsonFrame{})
			case '}', ']':
				if len(stack) > 0 {
					stack = stack[:len(stack)-1]
					markValueConsumed(stack)
				}
			}
		case string:
			if len(stack) > 0 && stack[len(stack)-1].object && stack[len(stack)-1].expectKey {
				current := &stack[len(stack)-1]
				if _, exists := current.keys[value]; exists {
					return invalid("duplicate JSON key %q", value)
				}
				current.keys[value] = struct{}{}
				current.expectKey = false
			} else {
				markValueConsumed(stack)
			}
		default:
			markValueConsumed(stack)
		}
	}
}

func markValueConsumed(stack []jsonFrame) {
	if len(stack) > 0 && stack[len(stack)-1].object && !stack[len(stack)-1].expectKey {
		stack[len(stack)-1].expectKey = true
	}
}
