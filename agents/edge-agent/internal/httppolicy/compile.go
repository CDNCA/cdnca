package httppolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	pathpkg "path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

var commonForbiddenHeaders = map[string]struct{}{
	"connection": {}, "content-length": {}, "host": {}, "keep-alive": {},
	"proxy-authenticate": {}, "proxy-authorization": {}, "proxy-connection": {},
	"te": {}, "trailer": {}, "transfer-encoding": {}, "upgrade": {},
}

var requestForbiddenHeaders = map[string]struct{}{
	"cookie": {}, "forwarded": {}, "origin": {}, "x-forwarded-for": {},
	"x-forwarded-host": {}, "x-forwarded-proto": {}, "x-real-ip": {},
	"access-control-request-headers": {}, "access-control-request-method": {},
}

// Response headers the node's later header_filter slots own (Alt-Svc, HSTS,
// cache status; docs/edge/dynroute-filters.md §2): a policy cannot overwrite
// or delete them.
var responseForbiddenHeaders = map[string]struct{}{
	"location": {}, "refresh": {}, "vary": {},
	"alt-svc": {}, "strict-transport-security": {}, "x-cdn-cache": {},
}

func CompileJSON(raw []byte) (Artifact, error) {
	if len(raw) == 0 || len(raw) > MaxPolicyBytes {
		return Artifact{}, invalid("policy size must be between 1 and %d bytes", MaxPolicyBytes)
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return Artifact{}, err
	}
	if err := requireFields(raw); err != nil {
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
		return Artifact{}, fmt.Errorf("marshal canonical HTTP policy: %w", err)
	}
	canonical = append(canonical, '\n')
	return Artifact{
		PolicyVersion: policy.PolicyVersion,
		Canonical:     canonical,
		Digest:        sha256.Sum256(canonical),
	}, nil
}

func normalizePolicy(input Policy) (Policy, error) {
	if input.SchemaVersion != SchemaVersion {
		return Policy{}, invalid("schema_version must be %q", SchemaVersion)
	}
	if input.PolicyVersion == 0 || input.PolicyVersion > MaxPolicyVersion {
		return Policy{}, invalid("policy_version must be between 1 and %d", MaxPolicyVersion)
	}
	if len(input.Sites) == 0 || len(input.Sites) > MaxSites {
		return Policy{}, invalid("site count must be between 1 and %d", MaxSites)
	}
	result := Policy{SchemaVersion: SchemaVersion, PolicyVersion: input.PolicyVersion, Sites: make([]SitePolicy, len(input.Sites))}
	seen := make(map[string]struct{}, len(input.Sites))
	for index, site := range input.Sites {
		normalized, err := normalizeSite(site)
		if err != nil {
			return Policy{}, invalid("site %d: %v", index, err)
		}
		if _, exists := seen[normalized.SiteID]; exists {
			return Policy{}, invalid("duplicate site_id %q", normalized.SiteID)
		}
		seen[normalized.SiteID] = struct{}{}
		result.Sites[index] = normalized
	}
	sort.Slice(result.Sites, func(i, j int) bool { return result.Sites[i].SiteID < result.Sites[j].SiteID })
	return result, nil
}

func normalizeSite(input SitePolicy) (SitePolicy, error) {
	if !validIdentifier(input.SiteID) {
		return SitePolicy{}, errors.New("site_id is invalid")
	}
	if input.MaxUploadBytes < 1 || input.MaxUploadBytes > MaxUploadBytes {
		return SitePolicy{}, fmt.Errorf("max_upload_bytes must be between 1 and %d", MaxUploadBytes)
	}
	request, err := normalizeHeaderActions(input.RequestHeaders, true)
	if err != nil {
		return SitePolicy{}, fmt.Errorf("request_headers: %w", err)
	}
	response, err := normalizeHeaderActions(input.ResponseHeaders, false)
	if err != nil {
		return SitePolicy{}, fmt.Errorf("response_headers: %w", err)
	}
	rewrites, err := normalizeRewrites(input.Rewrites)
	if err != nil {
		return SitePolicy{}, fmt.Errorf("rewrites: %w", err)
	}
	allowedHosts, err := normalizeAuthorities(input.RedirectAllowedHosts)
	if err != nil {
		return SitePolicy{}, fmt.Errorf("redirect_allowed_hosts: %w", err)
	}
	redirects, err := normalizeRedirects(input.Redirects, allowedHosts)
	if err != nil {
		return SitePolicy{}, fmt.Errorf("redirects: %w", err)
	}
	cors, err := normalizeCORS(input.CORS)
	if err != nil {
		return SitePolicy{}, fmt.Errorf("cors: %w", err)
	}
	refererCheck, err := normalizeRefererCheck(input.RefererCheck)
	if err != nil {
		return SitePolicy{}, fmt.Errorf("referer_check: %w", err)
	}
	return SitePolicy{
		SiteID: input.SiteID, MaxUploadBytes: input.MaxUploadBytes,
		RequestHeaders: request, ResponseHeaders: response, Rewrites: rewrites,
		RedirectAllowedHosts: allowedHosts, Redirects: redirects, CORS: cors, RefererCheck: refererCheck,
	}, nil
}

func normalizeHeaderActions(input []HeaderAction, request bool) ([]HeaderAction, error) {
	if input == nil || len(input) > MaxHeaderActions {
		return nil, fmt.Errorf("must be an array with at most %d actions", MaxHeaderActions)
	}
	result := make([]HeaderAction, len(input))
	seen := make(map[string]struct{}, len(input))
	for index, action := range input {
		name := strings.ToLower(action.Name)
		if !validToken(name) || len(name) > 128 {
			return nil, fmt.Errorf("action %d has an invalid header name", index)
		}
		if _, blocked := commonForbiddenHeaders[name]; blocked || strings.HasPrefix(name, "x-cdnca-") {
			return nil, fmt.Errorf("action %d targets reserved header %q", index, action.Name)
		}
		if request {
			if _, blocked := requestForbiddenHeaders[name]; blocked || strings.HasPrefix(name, "access-control-") {
				return nil, fmt.Errorf("action %d targets request identity or CORS header %q", index, action.Name)
			}
		} else if _, blocked := responseForbiddenHeaders[name]; blocked || strings.HasPrefix(name, "access-control-") {
			return nil, fmt.Errorf("action %d targets response control header %q", index, action.Name)
		}
		if _, exists := seen[name]; exists {
			return nil, fmt.Errorf("duplicate action for case-insensitive header %q", action.Name)
		}
		seen[name] = struct{}{}
		values := make([]string, len(action.Values))
		copy(values, action.Values)
		switch action.Kind {
		case HeaderDelete:
			if action.Values == nil || len(action.Values) != 0 {
				return nil, fmt.Errorf("delete action %d requires an empty values array", index)
			}
		case HeaderAdd, HeaderSet:
			if len(values) == 0 || len(values) > MaxHeaderValues {
				return nil, fmt.Errorf("action %d values must contain between 1 and %d fields", index, MaxHeaderValues)
			}
			for valueIndex, value := range values {
				if err := validateHeaderValue(value); err != nil {
					return nil, fmt.Errorf("action %d value %d: %w", index, valueIndex, err)
				}
				if !edgeconfig.ValidHeaderValueVariables(value) {
					return nil, fmt.Errorf("action %d value %d references an unknown variable", index, valueIndex)
				}
			}
		default:
			return nil, fmt.Errorf("action %d has unknown kind %q", index, action.Kind)
		}
		if action.AllowDuplicate && action.Kind != HeaderAdd {
			return nil, fmt.Errorf("action %d: allow_duplicate needs an add action", index)
		}
		result[index] = HeaderAction{Kind: action.Kind, Name: name, Values: values, AllowDuplicate: action.AllowDuplicate}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func validateHeaderValue(value string) error {
	if len(value) == 0 || len(value) > MaxHeaderBytes {
		return fmt.Errorf("length must be between 1 and %d bytes", MaxHeaderBytes)
	}
	for index := range value {
		if value[index] < 0x20 || value[index] > 0x7e {
			return errors.New("contains a control or non-ASCII byte")
		}
	}
	return nil
}

func normalizeRewrites(input []RewriteRule) ([]RewriteRule, error) {
	if input == nil || len(input) > MaxRules {
		return nil, fmt.Errorf("must be an array with at most %d rules", MaxRules)
	}
	result := make([]RewriteRule, len(input))
	seen := make(map[string]struct{}, len(input))
	for index, rule := range input {
		if !validIdentifier(rule.RuleID) {
			return nil, fmt.Errorf("rule %d has invalid rule_id", index)
		}
		if _, exists := seen[rule.RuleID]; exists {
			return nil, fmt.Errorf("duplicate rule_id %q", rule.RuleID)
		}
		seen[rule.RuleID] = struct{}{}
		conditions, err := edgeconfig.NormalizeRuleConditions(rule.Conditions)
		if err != nil {
			return nil, fmt.Errorf("rule %q has invalid conditions", rule.RuleID)
		}
		rule.Conditions = conditions
		if rule.MatchKind == MatchRegex {
			groups, err := normalizeRegexPattern(rule.MatchPath)
			if err != nil {
				return nil, fmt.Errorf("rule %q: %w", rule.RuleID, err)
			}
			if err := validateRegexTarget(rule.TargetPath, groups); err != nil {
				return nil, fmt.Errorf("rule %q target_path: %w", rule.RuleID, err)
			}
			result[index] = rule
			continue
		}
		matchPath, targetPath, err := normalizePathPair(rule.MatchKind, rule.MatchPath, rule.TargetPath)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", rule.RuleID, err)
		}
		if matchPath == targetPath {
			return nil, fmt.Errorf("rule %q rewrites a path to itself", rule.RuleID)
		}
		rule.MatchPath, rule.TargetPath = matchPath, targetPath
		result[index] = rule
	}
	sortRules(result, func(value RewriteRule) (uint32, string) { return value.Priority, value.RuleID })
	return result, nil
}

func normalizeRedirects(input []RedirectRule, allowed []string) ([]RedirectRule, error) {
	if input == nil || len(input) > MaxRules {
		return nil, fmt.Errorf("must be an array with at most %d rules", MaxRules)
	}
	allow := make(map[string]struct{}, len(allowed))
	for _, authority := range allowed {
		allow[authority] = struct{}{}
	}
	result := make([]RedirectRule, len(input))
	seen := make(map[string]struct{}, len(input))
	for index, rule := range input {
		if !validIdentifier(rule.RuleID) {
			return nil, fmt.Errorf("rule %d has invalid rule_id", index)
		}
		if _, exists := seen[rule.RuleID]; exists {
			return nil, fmt.Errorf("duplicate rule_id %q", rule.RuleID)
		}
		seen[rule.RuleID] = struct{}{}
		if rule.Status != 301 && rule.Status != 302 && rule.Status != 307 && rule.Status != 308 {
			return nil, fmt.Errorf("rule %q has unsupported redirect status", rule.RuleID)
		}
		conditions, err := edgeconfig.NormalizeRuleConditions(rule.Conditions)
		if err != nil {
			return nil, fmt.Errorf("rule %q has invalid conditions", rule.RuleID)
		}
		rule.Conditions = conditions
		match, groups, targetKind := rule.MatchPath, 0, MatchExact
		switch {
		case rule.MatchKind == MatchRegex:
			if rule.PreservePath {
				return nil, fmt.Errorf("rule %q: preserve_path needs a prefix rule", rule.RuleID)
			}
			if groups, err = normalizeRegexPattern(rule.MatchPath); err != nil {
				return nil, fmt.Errorf("rule %q: %w", rule.RuleID, err)
			}
			targetKind = MatchRegex
		default:
			if match, err = normalizeMatchPath(rule.MatchKind, rule.MatchPath); err != nil {
				return nil, fmt.Errorf("rule %q: %w", rule.RuleID, err)
			}
			if rule.PreservePath {
				if rule.MatchKind != MatchPrefix {
					return nil, fmt.Errorf("rule %q: preserve_path needs a prefix rule", rule.RuleID)
				}
				targetKind = MatchPrefix
			}
		}
		target, authority, err := normalizeRedirectTarget(rule.TargetURL, targetKind, groups)
		if err != nil {
			return nil, fmt.Errorf("rule %q target_url: %w", rule.RuleID, err)
		}
		if _, exists := allow[authority]; !exists {
			return nil, fmt.Errorf("rule %q target authority %q is not allowlisted", rule.RuleID, authority)
		}
		rule.MatchPath, rule.TargetURL = match, target
		result[index] = rule
	}
	sortRules(result, func(value RedirectRule) (uint32, string) { return value.Priority, value.RuleID })
	return result, nil
}

func sortRules[T any](values []T, key func(T) (uint32, string)) {
	sort.Slice(values, func(i, j int) bool {
		leftPriority, leftID := key(values[i])
		rightPriority, rightID := key(values[j])
		return leftPriority < rightPriority || leftPriority == rightPriority && leftID < rightID
	})
}

func normalizePathPair(kind MatchKind, match, target string) (string, string, error) {
	match, err := normalizeMatchPath(kind, match)
	if err != nil {
		return "", "", err
	}
	target, err = normalizeMatchPath(kind, target)
	if err != nil {
		return "", "", fmt.Errorf("target_path: %w", err)
	}
	return match, target, nil
}

func normalizeMatchPath(kind MatchKind, value string) (string, error) {
	if kind != MatchExact && kind != MatchPrefix {
		return "", fmt.Errorf("unsupported match_kind %q", kind)
	}
	if len(value) == 0 || len(value) > MaxPathBytes || value[0] != '/' || !isASCII(value) ||
		strings.ContainsAny(value, "\\%?#") || strings.Contains(value, "//") {
		return "", errors.New("path must be bounded, absolute, unencoded, and free of query, fragment, or backslash")
	}
	cleanInput := value
	if kind == MatchPrefix && value != "/" {
		if !strings.HasSuffix(value, "/") {
			return "", errors.New("prefix path must end with slash")
		}
		cleanInput = strings.TrimSuffix(value, "/")
	}
	if pathpkg.Clean(cleanInput) != cleanInput {
		return "", errors.New("path contains empty, dot, or traversal segments")
	}
	return value, nil
}

func normalizeAuthorities(input []string) ([]string, error) {
	if input == nil || len(input) > MaxOrigins {
		return nil, fmt.Errorf("must be an array with at most %d authorities", MaxOrigins)
	}
	result := make([]string, 0, len(input))
	seen := make(map[string]struct{}, len(input))
	for index, value := range input {
		authority, err := normalizeAuthority(value)
		if err != nil {
			return nil, fmt.Errorf("authority %d: %w", index, err)
		}
		if _, exists := seen[authority]; exists {
			return nil, fmt.Errorf("duplicate authority %q", authority)
		}
		seen[authority] = struct{}{}
		result = append(result, authority)
	}
	sort.Strings(result)
	return result, nil
}

func normalizeAuthority(value string) (string, error) {
	if value == "" || len(value) > 512 || strings.ContainsAny(value, "\x00\r\n\t /\\?#@") {
		return "", errors.New("authority is empty or contains an unsafe character")
	}
	parsed, err := url.Parse("http://" + value)
	if err != nil || parsed.User != nil || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("authority is invalid")
	}
	return canonicalAuthority(parsed.Hostname(), parsed.Port())
}

func canonicalAuthority(host, port string) (string, error) {
	if host == "" {
		return "", errors.New("host is required")
	}
	host = strings.ToLower(host)
	if address, err := netip.ParseAddr(host); err == nil {
		if address.Is4In6() || address.Zone() != "" {
			return "", errors.New("mapped or zoned IP is not allowed")
		}
		host = address.String()
	} else if err := validateHostname(host); err != nil {
		return "", err
	}
	if port != "" {
		value, err := strconv.ParseUint(port, 10, 16)
		if err != nil || value == 0 {
			return "", errors.New("port is invalid")
		}
		return net.JoinHostPort(host, strconv.FormatUint(value, 10)), nil
	}
	if strings.Contains(host, ":") {
		return "[" + host + "]", nil
	}
	return host, nil
}

func validateHostname(host string) error {
	if len(host) > 253 || strings.HasSuffix(host, ".") {
		return errors.New("hostname length or trailing dot is invalid")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("hostname contains an invalid label")
		}
		for index := range label {
			character := label[index]
			if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' {
				continue
			}
			return errors.New("hostname contains an invalid character")
		}
	}
	return nil
}

// normalizeRegexPattern checks an anchored ("^/") RE2 pattern and returns
// its number of capture groups (at most 9).
func normalizeRegexPattern(pattern string) (int, error) {
	if len(pattern) < 2 || len(pattern) > MaxRegexBytes || !strings.HasPrefix(pattern, "^/") || !isASCII(pattern) ||
		strings.IndexFunc(pattern, func(character rune) bool { return character < 0x20 || character == 0x7f }) >= 0 {
		return 0, errors.New("regex must be printable ASCII, anchored at \"^/\" and at most 512 bytes")
	}
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return 0, fmt.Errorf("regex is not RE2: %w", err)
	}
	if compiled.NumSubexp() > 9 {
		return 0, errors.New("regex has more than 9 capture groups")
	}
	return compiled.NumSubexp(), nil
}

// validateRegexTarget checks a regex rule's target path: an absolute,
// unencoded path without dot segments, "$" only as $1..$groups.
func validateRegexTarget(target string, groups int) error {
	if len(target) == 0 || len(target) > MaxPathBytes || target[0] != '/' || !isASCII(target) ||
		strings.ContainsAny(target, "\\%?#") || strings.Contains(target, "//") ||
		strings.IndexFunc(target, func(character rune) bool { return character < 0x20 || character == 0x7f }) >= 0 {
		return errors.New("target must be bounded, absolute, unencoded, and free of query, fragment, or backslash")
	}
	for index := 0; index < len(target); index++ {
		if target[index] == '$' && (index+1 >= len(target) || target[index+1] < '1' || int(target[index+1]-'0') > groups) {
			return errors.New("target names a capture group the regex does not have")
		}
	}
	for _, segment := range strings.Split(target, "/") {
		if segment == "." || segment == ".." {
			return errors.New("target contains dot segments")
		}
	}
	return nil
}

func normalizeRedirectURL(value string) (string, string, error) {
	return normalizeRedirectTarget(value, MatchExact, 0)
}

// normalizeRedirectTarget is normalizeRedirectURL with the path checked as
// pathKind: exact (fixed), prefix (a directory) or regex (a template).
func normalizeRedirectTarget(value string, pathKind MatchKind, groups int) (string, string, error) {
	if value == "" || len(value) > 4096 || !isASCII(value) || strings.ContainsAny(value, "\x00\r\n\t\\") {
		return "", "", errors.New("URL is empty, too long, or unsafe")
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Opaque != "" || parsed.User != nil || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" {
		return "", "", errors.New("URL must be absolute without userinfo, query, fragment, or encoding")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", "", errors.New("URL scheme must be http or https")
	}
	authority, err := canonicalAuthority(parsed.Hostname(), parsed.Port())
	if err != nil {
		return "", "", err
	}
	path := parsed.Path
	if path == "" {
		path = "/"
	}
	if pathKind == MatchRegex {
		if err := validateRegexTarget(path, groups); err != nil {
			return "", "", fmt.Errorf("URL path: %w", err)
		}
	} else if _, err := normalizeMatchPath(pathKind, path); err != nil {
		return "", "", fmt.Errorf("URL path: %w", err)
	}
	return scheme + "://" + authority + path, authority, nil
}

// normalizeRefererCheck mirrors the control plane: sorted lower-case domains
// (host or "*.example.com"), disjoint lists, something restricted, sorted
// extensions without the dot.
func normalizeRefererCheck(input *RefererCheckPolicy) (*RefererCheckPolicy, error) {
	if input == nil {
		return nil, nil
	}
	allowed, err := normalizeRefererDomains(input.AllowedDomains)
	if err != nil {
		return nil, fmt.Errorf("allowed_domains: %w", err)
	}
	denied, err := normalizeRefererDomains(input.DeniedDomains)
	if err != nil {
		return nil, fmt.Errorf("denied_domains: %w", err)
	}
	for _, domain := range denied {
		if contains(allowed, domain) {
			return nil, fmt.Errorf("domain %q is both allowed and denied", domain)
		}
	}
	if !input.AllowSameDomain && len(allowed) == 0 && len(denied) == 0 {
		return nil, errors.New("a referer check must restrict something")
	}
	if input.Extensions == nil || len(input.Extensions) > MaxRefererExtensions {
		return nil, fmt.Errorf("extensions must be an array with at most %d items", MaxRefererExtensions)
	}
	extensions := append([]string{}, input.Extensions...)
	sort.Strings(extensions)
	for index, extension := range extensions {
		if len(extension) < 1 || len(extension) > 16 || strings.Trim(extension, "abcdefghijklmnopqrstuvwxyz0123456789") != "" ||
			index > 0 && extensions[index-1] == extension {
			return nil, fmt.Errorf("extension %q is invalid or duplicate", extension)
		}
	}
	return &RefererCheckPolicy{
		AllowEmpty: input.AllowEmpty, AllowSameDomain: input.AllowSameDomain,
		AllowedDomains: allowed, DeniedDomains: denied, CheckOrigin: input.CheckOrigin, Extensions: extensions,
	}, nil
}

func normalizeRefererDomains(input []string) ([]string, error) {
	if input == nil || len(input) > MaxRefererDomains {
		return nil, fmt.Errorf("must be an array with at most %d domains", MaxRefererDomains)
	}
	result := append([]string{}, input...)
	sort.Strings(result)
	for index, domain := range result {
		host := strings.TrimPrefix(domain, "*.")
		if domain != strings.ToLower(domain) || validateHostname(host) != nil || host != domain && !strings.Contains(host, ".") ||
			index > 0 && result[index-1] == domain {
			return nil, fmt.Errorf("domain %q is invalid or duplicate", domain)
		}
	}
	return result, nil
}

func normalizeCORS(input *CORSPolicy) (*CORSPolicy, error) {
	if input == nil {
		return nil, nil
	}
	origins, err := normalizeOrigins(input.AllowedOrigins)
	if err != nil {
		return nil, err
	}
	methods, err := normalizeTokens(input.AllowedMethods, true, false)
	if err != nil || len(methods) == 0 {
		return nil, errors.New("allowed_methods must contain uppercase HTTP tokens")
	}
	headers, err := normalizeTokens(input.AllowedHeaders, false, true)
	if err != nil {
		return nil, fmt.Errorf("allowed_headers: %w", err)
	}
	exposed, err := normalizeTokens(input.ExposedHeaders, false, true)
	if err != nil {
		return nil, fmt.Errorf("exposed_headers: %w", err)
	}
	if input.MaxAgeSeconds > 86400 {
		return nil, errors.New("max_age_seconds must not exceed 86400")
	}
	if input.AllowCredentials && (contains(origins, "*") || contains(headers, "*") || contains(exposed, "*")) {
		return nil, errors.New("credentials cannot be combined with wildcard origin or headers")
	}
	return &CORSPolicy{
		AllowedOrigins: origins, AllowedMethods: methods, AllowedHeaders: headers,
		ExposedHeaders: exposed, AllowCredentials: input.AllowCredentials,
		MaxAgeSeconds: input.MaxAgeSeconds,
	}, nil
}

func normalizeOrigins(input []string) ([]string, error) {
	if input == nil || len(input) == 0 || len(input) > MaxOrigins {
		return nil, fmt.Errorf("allowed_origins must contain between 1 and %d origins", MaxOrigins)
	}
	result := make([]string, 0, len(input))
	seen := make(map[string]struct{}, len(input))
	for index, value := range input {
		origin := value
		if value == "*" {
			if len(input) != 1 {
				return nil, errors.New("wildcard origin must be the only origin")
			}
		} else {
			parsed, err := url.Parse(value)
			if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" || parsed.Host == "" {
				return nil, fmt.Errorf("origin %d is not an origin tuple", index)
			}
			scheme := strings.ToLower(parsed.Scheme)
			if scheme != "http" && scheme != "https" {
				return nil, fmt.Errorf("origin %d scheme must be http or https", index)
			}
			authority, err := canonicalAuthority(parsed.Hostname(), parsed.Port())
			if err != nil {
				return nil, fmt.Errorf("origin %d: %w", index, err)
			}
			origin = scheme + "://" + authority
		}
		if _, exists := seen[origin]; exists {
			return nil, fmt.Errorf("duplicate origin %q", origin)
		}
		seen[origin] = struct{}{}
		result = append(result, origin)
	}
	sort.Strings(result)
	return result, nil
}

func normalizeTokens(input []string, upper, wildcard bool) ([]string, error) {
	if input == nil || len(input) > MaxOrigins {
		return nil, fmt.Errorf("must be an array with at most %d values", MaxOrigins)
	}
	result := make([]string, 0, len(input))
	seen := make(map[string]struct{}, len(input))
	for _, value := range input {
		if value == "*" && wildcard {
			if len(input) != 1 {
				return nil, errors.New("wildcard must be the only value")
			}
		} else if !validToken(value) {
			return nil, fmt.Errorf("invalid token %q", value)
		}
		if upper {
			value = strings.ToUpper(value)
		} else {
			value = strings.ToLower(value)
		}
		if _, exists := seen[value]; exists {
			return nil, fmt.Errorf("duplicate token %q", value)
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result, nil
}

func validIdentifier(value string) bool {
	if len(value) == 0 || len(value) > 128 {
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

func validToken(value string) bool {
	if value == "" {
		return false
	}
	for index := range value {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(character)) {
			continue
		}
		return false
	}
	return true
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func isASCII(value string) bool {
	for index := range value {
		if value[index] > 0x7f {
			return false
		}
	}
	return true
}

func requireFields(raw []byte) error {
	var policy map[string]json.RawMessage
	if err := json.Unmarshal(raw, &policy); err != nil {
		return invalid("decode policy object: %v", err)
	}
	if err := requireObject(policy, "policy", "schema_version", "policy_version", "sites"); err != nil {
		return err
	}
	var sites []map[string]json.RawMessage
	if err := json.Unmarshal(policy["sites"], &sites); err != nil {
		return invalid("sites must be an array")
	}
	for index, site := range sites {
		label := fmt.Sprintf("site %d", index)
		if err := requireObject(site, label, "site_id", "max_upload_bytes", "request_headers", "response_headers", "rewrites", "redirect_allowed_hosts", "redirects", "cors", "referer_check"); err != nil {
			return err
		}
		for _, field := range []string{"request_headers", "response_headers"} {
			var actions []map[string]json.RawMessage
			if err := json.Unmarshal(site[field], &actions); err != nil {
				return invalid("%s %s must be an array", label, field)
			}
			for actionIndex, action := range actions {
				if err := requireObject(action, fmt.Sprintf("%s %s action %d", label, field, actionIndex), "kind", "name", "values"); err != nil {
					return err
				}
			}
		}
		var rewrites []map[string]json.RawMessage
		if err := json.Unmarshal(site["rewrites"], &rewrites); err != nil {
			return invalid("%s rewrites must be an array", label)
		}
		for ruleIndex, rule := range rewrites {
			if err := requireObject(rule, fmt.Sprintf("%s rewrite %d", label, ruleIndex), "rule_id", "priority", "match_kind", "match_path", "target_path", "preserve_query", "preserve_cookie"); err != nil {
				return err
			}
		}
		var redirects []map[string]json.RawMessage
		if err := json.Unmarshal(site["redirects"], &redirects); err != nil {
			return invalid("%s redirects must be an array", label)
		}
		for ruleIndex, rule := range redirects {
			if err := requireObject(rule, fmt.Sprintf("%s redirect %d", label, ruleIndex), "rule_id", "priority", "match_kind", "match_path", "status", "target_url", "preserve_query", "preserve_path"); err != nil {
				return err
			}
		}
		if !bytes.Equal(bytes.TrimSpace(site["referer_check"]), []byte("null")) {
			var check map[string]json.RawMessage
			if err := json.Unmarshal(site["referer_check"], &check); err != nil {
				return invalid("%s referer_check must be an object or null", label)
			}
			if err := requireObject(check, label+" referer_check", "allow_empty", "allow_same_domain", "allowed_domains", "denied_domains", "check_origin", "extensions"); err != nil {
				return err
			}
		}
		if !bytes.Equal(bytes.TrimSpace(site["cors"]), []byte("null")) {
			var cors map[string]json.RawMessage
			if err := json.Unmarshal(site["cors"], &cors); err != nil {
				return invalid("%s cors must be an object or null", label)
			}
			if err := requireObject(cors, label+" cors", "allowed_origins", "allowed_methods", "allowed_headers", "exposed_headers", "allow_credentials", "max_age_seconds"); err != nil {
				return err
			}
		}
	}
	return nil
}

func requireObject(object map[string]json.RawMessage, label string, fields ...string) error {
	if object == nil {
		return invalid("%s must be an object", label)
	}
	for _, field := range fields {
		if _, exists := object[field]; !exists {
			return invalid("%s required field %q is missing", label, field)
		}
	}
	return nil
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return invalid("decode tokens: %v", err)
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			keys := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return invalid("decode object key: %v", err)
				}
				key, ok := keyToken.(string)
				if !ok {
					return invalid("object key is not a string")
				}
				if _, exists := keys[key]; exists {
					return invalid("duplicate JSON key %q", key)
				}
				keys[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return invalid("unexpected JSON delimiter %q", delimiter)
		}
	}
	if err := walk(); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return invalid("policy contains trailing JSON")
		}
		return invalid("decode trailing JSON: %v", err)
	}
	return nil
}

func invalid(format string, values ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidPolicy, fmt.Sprintf(format, values...))
}
