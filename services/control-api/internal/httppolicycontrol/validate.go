package httppolicycontrol

import (
	"crypto/sha256"
	"encoding/json"
	"net"
	"net/netip"
	"net/url"
	pathpkg "path"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
)

var metadataPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

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

func normalizeConfig(input Config) (Config, error) {
	if input.MaxUploadBytes < 1 || input.MaxUploadBytes > MaxUploadBytes {
		return Config{}, ErrValidation
	}
	requestHeaders, err := normalizeHeaderActions(input.RequestHeaders, true)
	if err != nil {
		return Config{}, ErrValidation
	}
	responseHeaders, err := normalizeHeaderActions(input.ResponseHeaders, false)
	if err != nil {
		return Config{}, ErrValidation
	}
	rewrites, err := normalizeRewrites(input.Rewrites)
	if err != nil {
		return Config{}, ErrValidation
	}
	allowedHosts, err := normalizeAuthorities(input.RedirectAllowedHosts)
	if err != nil {
		return Config{}, ErrValidation
	}
	redirects, err := normalizeRedirects(input.Redirects, allowedHosts)
	if err != nil {
		return Config{}, ErrValidation
	}
	cors, err := normalizeCORS(input.CORS)
	if err != nil {
		return Config{}, ErrValidation
	}
	refererCheck, err := normalizeRefererCheck(input.RefererCheck)
	if err != nil {
		return Config{}, ErrValidation
	}
	if err := validateRuleConflicts(rewrites, redirects); err != nil {
		return Config{}, ErrValidation
	}
	if err := validateRewriteGraph(rewrites); err != nil {
		return Config{}, ErrValidation
	}
	result := Config{
		MaxUploadBytes: input.MaxUploadBytes, RequestHeaders: requestHeaders,
		ResponseHeaders: responseHeaders, Rewrites: rewrites,
		RedirectAllowedHosts: allowedHosts, Redirects: redirects, CORS: cors, RefererCheck: refererCheck,
	}
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded) > MaxPolicyBytes {
		return Config{}, ErrValidation
	}
	return result, nil
}

func normalizeHeaderActions(input []HeaderAction, request bool) ([]HeaderAction, error) {
	if input == nil || len(input) > MaxHeaderActions {
		return nil, ErrValidation
	}
	result := make([]HeaderAction, len(input))
	seen := make(map[string]struct{}, len(input))
	for index, action := range input {
		name := strings.ToLower(action.Name)
		if name != action.Name && strings.TrimSpace(action.Name) != action.Name {
			return nil, ErrValidation
		}
		if !validToken(name) || len(name) > 128 {
			return nil, ErrValidation
		}
		if _, blocked := commonForbiddenHeaders[name]; blocked || strings.HasPrefix(name, "x-cdnca-") {
			return nil, ErrValidation
		}
		if request {
			if _, blocked := requestForbiddenHeaders[name]; blocked || strings.HasPrefix(name, "access-control-") {
				return nil, ErrValidation
			}
		} else if _, blocked := responseForbiddenHeaders[name]; blocked || strings.HasPrefix(name, "access-control-") {
			return nil, ErrValidation
		}
		if _, exists := seen[name]; exists {
			return nil, ErrValidation
		}
		seen[name] = struct{}{}
		values := append([]string{}, action.Values...)
		switch action.Kind {
		case HeaderDelete:
			if action.Values == nil || len(action.Values) != 0 {
				return nil, ErrValidation
			}
		case HeaderAdd, HeaderSet:
			if len(values) < 1 || len(values) > MaxHeaderValues {
				return nil, ErrValidation
			}
			for _, value := range values {
				if !validHeaderValue(value) || !edgeconfig.ValidHeaderValueVariables(value) {
					return nil, ErrValidation
				}
			}
		default:
			return nil, ErrValidation
		}
		if action.AllowDuplicate && action.Kind != HeaderAdd {
			return nil, ErrValidation
		}
		result[index] = HeaderAction{Kind: action.Kind, Name: name, Values: values, AllowDuplicate: action.AllowDuplicate}
	}
	sort.Slice(result, func(left, right int) bool { return result[left].Name < result[right].Name })
	return result, nil
}

func validHeaderValue(value string) bool {
	if len(value) < 1 || len(value) > MaxHeaderBytes || !utf8.ValidString(value) {
		return false
	}
	for index := range value {
		if value[index] < 0x20 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func normalizeRewrites(input []RewriteRule) ([]RewriteRule, error) {
	if input == nil || len(input) > MaxRules {
		return nil, ErrValidation
	}
	result := make([]RewriteRule, len(input))
	seen := make(map[string]struct{}, len(input))
	for index, rule := range input {
		if !validIdentifier(rule.RuleID) {
			return nil, ErrValidation
		}
		if _, exists := seen[rule.RuleID]; exists {
			return nil, ErrValidation
		}
		seen[rule.RuleID] = struct{}{}
		conditions, err := edgeconfig.NormalizeRuleConditions(rule.Conditions)
		if err != nil {
			return nil, ErrValidation
		}
		rule.Conditions = conditions
		if rule.MatchKind == MatchRegex {
			groups, err := normalizeRegexPattern(rule.MatchPath)
			if err != nil || validateRegexTarget(rule.TargetPath, groups) != nil {
				return nil, ErrValidation
			}
			result[index] = rule
			continue
		}
		matchPath, err := normalizeMatchPath(rule.MatchKind, rule.MatchPath)
		if err != nil {
			return nil, err
		}
		targetPath, err := normalizeMatchPath(rule.MatchKind, rule.TargetPath)
		if err != nil || matchPath == targetPath {
			return nil, ErrValidation
		}
		rule.MatchPath = matchPath
		rule.TargetPath = targetPath
		result[index] = rule
	}
	sort.Slice(result, func(left, right int) bool {
		return result[left].Priority < result[right].Priority ||
			result[left].Priority == result[right].Priority && result[left].RuleID < result[right].RuleID
	})
	return result, nil
}

func normalizeRedirects(input []RedirectRule, allowedHosts []string) ([]RedirectRule, error) {
	if input == nil || len(input) > MaxRules {
		return nil, ErrValidation
	}
	allowed := make(map[string]struct{}, len(allowedHosts))
	for _, authority := range allowedHosts {
		allowed[authority] = struct{}{}
	}
	result := make([]RedirectRule, len(input))
	seen := make(map[string]struct{}, len(input))
	for index, rule := range input {
		if !validIdentifier(rule.RuleID) {
			return nil, ErrValidation
		}
		if _, exists := seen[rule.RuleID]; exists {
			return nil, ErrValidation
		}
		seen[rule.RuleID] = struct{}{}
		if rule.Status != 301 && rule.Status != 302 && rule.Status != 307 && rule.Status != 308 {
			return nil, ErrValidation
		}
		conditions, err := edgeconfig.NormalizeRuleConditions(rule.Conditions)
		if err != nil {
			return nil, ErrValidation
		}
		rule.Conditions = conditions
		matchPath, groups := rule.MatchPath, 0
		if rule.MatchKind == MatchRegex {
			if groups, err = normalizeRegexPattern(rule.MatchPath); err != nil {
				return nil, err
			}
		} else if matchPath, err = normalizeMatchPath(rule.MatchKind, rule.MatchPath); err != nil {
			return nil, err
		}
		// The target path is fixed, a directory the kept suffix is appended
		// to (preserve_path, prefix rules only), or a regex template.
		targetKind := MatchExact
		switch {
		case rule.MatchKind == MatchRegex:
			if rule.PreservePath {
				return nil, ErrValidation
			}
			targetKind = MatchRegex
		case rule.PreservePath:
			if rule.MatchKind != MatchPrefix {
				return nil, ErrValidation
			}
			targetKind = MatchPrefix
		}
		targetURL, authority, err := normalizeRedirectTarget(rule.TargetURL, targetKind, groups)
		if err != nil {
			return nil, err
		}
		if _, exists := allowed[authority]; !exists {
			return nil, ErrValidation
		}
		rule.MatchPath = matchPath
		rule.TargetURL = targetURL
		result[index] = rule
	}
	sort.Slice(result, func(left, right int) bool {
		return result[left].Priority < result[right].Priority ||
			result[left].Priority == result[right].Priority && result[left].RuleID < result[right].RuleID
	})
	return result, nil
}

func validateRuleConflicts(rewrites []RewriteRule, redirects []RedirectRule) error {
	// A rule with conditions matches only some requests of its path: it
	// never conflicts, the first of priority, rule_id wins (migration 490).
	type match struct {
		id          string
		priority    uint32
		kind        string
		path        string
		conditional bool
	}
	matches := make([]match, 0, len(rewrites)+len(redirects))
	seenIDs := make(map[string]struct{}, len(rewrites)+len(redirects))
	for _, rule := range rewrites {
		seenIDs[rule.RuleID] = struct{}{}
		matches = append(matches, match{rule.RuleID, rule.Priority, rule.MatchKind, rule.MatchPath, rule.Conditions != nil})
	}
	for _, rule := range redirects {
		if _, exists := seenIDs[rule.RuleID]; exists {
			return ErrValidation
		}
		seenIDs[rule.RuleID] = struct{}{}
		matches = append(matches, match{rule.RuleID, rule.Priority, rule.MatchKind, rule.MatchPath, rule.Conditions != nil})
	}
	for left := 0; left < len(matches); left++ {
		for right := left + 1; right < len(matches); right++ {
			if matches[left].priority == matches[right].priority && !matches[left].conditional &&
				!matches[right].conditional && patternsOverlap(
				matches[left].kind, matches[left].path, matches[right].kind, matches[right].path,
			) {
				return ErrValidation
			}
		}
	}
	return nil
}

func validateRewriteGraph(rules []RewriteRule) error {
	edges := make([][]int, len(rules))
	for sourceIndex, source := range rules {
		for targetIndex, target := range rules {
			if rewriteOutputMayMatch(source, target) {
				edges[sourceIndex] = append(edges[sourceIndex], targetIndex)
			}
		}
	}
	state := make([]uint8, len(rules))
	depth := make([]int, len(rules))
	var visit func(int) (int, error)
	visit = func(index int) (int, error) {
		if state[index] == 1 {
			return 0, ErrValidation
		}
		if state[index] == 2 {
			return depth[index], nil
		}
		state[index] = 1
		longest := 1
		for _, next := range edges[index] {
			child, err := visit(next)
			if err != nil {
				return 0, err
			}
			if child+1 > longest {
				longest = child + 1
			}
		}
		if longest > MaxRewriteHops {
			return 0, ErrValidation
		}
		state[index] = 2
		depth[index] = longest
		return longest, nil
	}
	for index := range rules {
		if _, err := visit(index); err != nil {
			return err
		}
	}
	return nil
}

func rewriteOutputMayMatch(source, target RewriteRule) bool {
	if source.MatchKind == MatchRegex || target.MatchKind == MatchRegex {
		// Chains through regex rules are bounded at run time (the engine's
		// visited set and MaxRewriteHops answer 508), not here.
		return false
	}
	if source.MatchKind == MatchExact {
		return pathMatches(target.MatchKind, target.MatchPath, source.TargetPath)
	}
	return patternsOverlap(MatchPrefix, source.TargetPath, target.MatchKind, target.MatchPath)
}

func patternsOverlap(leftKind, leftPath, rightKind, rightPath string) bool {
	if leftKind == MatchRegex || rightKind == MatchRegex {
		// Whether two patterns can match one path is not decided statically:
		// a regex rule needs a priority of its own.
		return true
	}
	if leftKind == MatchExact {
		return pathMatches(rightKind, rightPath, leftPath)
	}
	if rightKind == MatchExact {
		return pathMatches(leftKind, leftPath, rightPath)
	}
	if leftPath == "/" || rightPath == "/" {
		return true
	}
	return strings.HasPrefix(leftPath, rightPath) || strings.HasPrefix(rightPath, leftPath)
}

// normalizeRegexPattern checks a regex match pattern and returns its number
// of capture groups. The pattern is anchored at the path start ("^/"),
// printable ASCII, and RE2 (no backreferences or lookaround), which the
// node's PCRE runs with the same meaning under its match limit.
func normalizeRegexPattern(pattern string) (int, error) {
	if len(pattern) < 2 || len(pattern) > MaxRegexBytes || !strings.HasPrefix(pattern, "^/") ||
		!isASCII(pattern) || hasControl(pattern) {
		return 0, ErrValidation
	}
	compiled, err := regexp.Compile(pattern)
	if err != nil || compiled.NumSubexp() > 9 {
		return 0, ErrValidation
	}
	return compiled.NumSubexp(), nil
}

// validateRegexTarget checks a regex rule's target path: absolute, the
// path rules of normalizeMatchPath, and "$" only as $1..$groups.
func validateRegexTarget(target string, groups int) error {
	if len(target) < 1 || len(target) > MaxPathBytes || target[0] != '/' || !isASCII(target) ||
		strings.ContainsAny(target, "\\%?#") || strings.Contains(target, "//") || hasControl(target) {
		return ErrValidation
	}
	for index := 0; index < len(target); index++ {
		if target[index] != '$' {
			continue
		}
		if index+1 >= len(target) || target[index+1] < '1' || int(target[index+1]-'0') > groups {
			return ErrValidation
		}
	}
	for _, segment := range strings.Split(target, "/") {
		if segment == "." || segment == ".." {
			return ErrValidation
		}
	}
	return nil
}

func pathMatches(kind, pattern, candidate string) bool {
	if kind == MatchExact {
		return pattern == candidate
	}
	return pattern == "/" || strings.HasPrefix(candidate, pattern)
}

func normalizeMatchPath(kind, value string) (string, error) {
	if kind != MatchExact && kind != MatchPrefix {
		return "", ErrValidation
	}
	if len(value) < 1 || len(value) > MaxPathBytes || value[0] != '/' || !isASCII(value) ||
		strings.ContainsAny(value, "\\%?#") || strings.Contains(value, "//") || hasControl(value) {
		return "", ErrValidation
	}
	cleanInput := value
	if kind == MatchPrefix && value != "/" {
		if !strings.HasSuffix(value, "/") {
			return "", ErrValidation
		}
		cleanInput = strings.TrimSuffix(value, "/")
	}
	if pathpkg.Clean(cleanInput) != cleanInput {
		return "", ErrValidation
	}
	return value, nil
}

func normalizeAuthorities(input []string) ([]string, error) {
	if input == nil || len(input) > MaxOrigins {
		return nil, ErrValidation
	}
	result := make([]string, 0, len(input))
	seen := make(map[string]struct{}, len(input))
	for _, value := range input {
		authority, err := normalizeAuthority(value)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[authority]; exists {
			return nil, ErrValidation
		}
		seen[authority] = struct{}{}
		result = append(result, authority)
	}
	sort.Strings(result)
	return result, nil
}

func normalizeAuthority(value string) (string, error) {
	if value == "" || len(value) > 512 || strings.ContainsAny(value, "\x00\r\n\t /\\?#@") {
		return "", ErrValidation
	}
	parsed, err := url.Parse("http://" + value)
	if err != nil || parsed.User != nil || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", ErrValidation
	}
	return canonicalAuthority(parsed.Hostname(), parsed.Port())
}

func canonicalAuthority(host, port string) (string, error) {
	if host == "" {
		return "", ErrValidation
	}
	host = strings.ToLower(host)
	if address, err := netip.ParseAddr(host); err == nil {
		if address.Is4In6() || address.Zone() != "" {
			return "", ErrValidation
		}
		host = address.String()
	} else if !validHostname(host) {
		return "", ErrValidation
	}
	if port != "" {
		value, err := strconv.ParseUint(port, 10, 16)
		if err != nil || value == 0 {
			return "", ErrValidation
		}
		return net.JoinHostPort(host, strconv.FormatUint(value, 10)), nil
	}
	if strings.Contains(host, ":") {
		return "[" + host + "]", nil
	}
	return host, nil
}

func validHostname(host string) bool {
	if len(host) > 253 || strings.HasSuffix(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for index := range label {
			character := label[index]
			if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func normalizeRedirectURL(value string) (string, string, error) {
	return normalizeRedirectTarget(value, MatchExact, 0)
}

// normalizeRedirectTarget is normalizeRedirectURL whose path is checked as
// pathKind: exact (a fixed path), prefix (a directory, "/"-terminated) or
// regex (a template naming at most groups capture groups).
func normalizeRedirectTarget(value, pathKind string, groups int) (string, string, error) {
	if value == "" || len(value) > 4096 || !isASCII(value) || strings.ContainsAny(value, "\x00\r\n\t\\") {
		return "", "", ErrValidation
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Opaque != "" || parsed.User != nil || parsed.Host == "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" {
		return "", "", ErrValidation
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", "", ErrValidation
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
			return "", "", err
		}
	} else if path, err = normalizeMatchPath(pathKind, path); err != nil {
		return "", "", err
	}
	return scheme + "://" + authority + path, authority, nil
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
		return nil, ErrValidation
	}
	headers, err := normalizeTokens(input.AllowedHeaders, false, true)
	if err != nil {
		return nil, err
	}
	exposed, err := normalizeTokens(input.ExposedHeaders, false, true)
	if err != nil {
		return nil, err
	}
	if input.MaxAgeSeconds > 86400 || input.AllowCredentials &&
		(contains(origins, "*") || contains(headers, "*") || contains(exposed, "*")) {
		return nil, ErrValidation
	}
	return &CORSPolicy{
		AllowedOrigins: origins, AllowedMethods: methods, AllowedHeaders: headers,
		ExposedHeaders: exposed, AllowCredentials: input.AllowCredentials,
		MaxAgeSeconds: input.MaxAgeSeconds,
	}, nil
}

// normalizeRefererCheck canonicalizes hotlink protection: domains lower case
// and sorted ("*.example.com" matches any subdomain, not example.com itself),
// extensions lower case without the dot. A check must restrict something.
func normalizeRefererCheck(input *RefererCheckPolicy) (*RefererCheckPolicy, error) {
	if input == nil {
		return nil, nil
	}
	allowed, err := normalizeRefererDomains(input.AllowedDomains)
	if err != nil {
		return nil, err
	}
	denied, err := normalizeRefererDomains(input.DeniedDomains)
	if err != nil {
		return nil, err
	}
	for _, domain := range denied {
		if contains(allowed, domain) {
			return nil, ErrValidation
		}
	}
	if !input.AllowSameDomain && len(allowed) == 0 && len(denied) == 0 {
		return nil, ErrValidation
	}
	if input.Extensions == nil || len(input.Extensions) > MaxRefererExtensions {
		return nil, ErrValidation
	}
	extensions := make([]string, 0, len(input.Extensions))
	for _, value := range input.Extensions {
		extension := strings.ToLower(strings.TrimPrefix(value, "."))
		if !refererExtensionPattern.MatchString(extension) || contains(extensions, extension) {
			return nil, ErrValidation
		}
		extensions = append(extensions, extension)
	}
	sort.Strings(extensions)
	return &RefererCheckPolicy{
		AllowEmpty: input.AllowEmpty, AllowSameDomain: input.AllowSameDomain,
		AllowedDomains: allowed, DeniedDomains: denied, CheckOrigin: input.CheckOrigin, Extensions: extensions,
	}, nil
}

var refererExtensionPattern = regexp.MustCompile(`^[a-z0-9]{1,16}$`)

func normalizeRefererDomains(input []string) ([]string, error) {
	if input == nil || len(input) > MaxRefererDomains {
		return nil, ErrValidation
	}
	result := make([]string, 0, len(input))
	for _, value := range input {
		domain := strings.ToLower(strings.TrimSpace(value))
		host := strings.TrimPrefix(domain, "*.")
		if !validHostname(host) || !strings.Contains(host, ".") && domain != host || contains(result, domain) {
			return nil, ErrValidation
		}
		result = append(result, domain)
	}
	sort.Strings(result)
	return result, nil
}

func cloneRefererCheck(input *RefererCheckPolicy) *RefererCheckPolicy {
	if input == nil {
		return nil
	}
	result := *input
	result.AllowedDomains = append([]string{}, input.AllowedDomains...)
	result.DeniedDomains = append([]string{}, input.DeniedDomains...)
	result.Extensions = append([]string{}, input.Extensions...)
	return &result
}

func normalizeOrigins(input []string) ([]string, error) {
	if input == nil || len(input) < 1 || len(input) > MaxOrigins {
		return nil, ErrValidation
	}
	result := make([]string, 0, len(input))
	seen := make(map[string]struct{}, len(input))
	for _, value := range input {
		origin := value
		if value == "*" {
			if len(input) != 1 {
				return nil, ErrValidation
			}
		} else {
			parsed, err := url.Parse(value)
			if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
				parsed.Path != "" || parsed.Host == "" {
				return nil, ErrValidation
			}
			scheme := strings.ToLower(parsed.Scheme)
			if scheme != "http" && scheme != "https" {
				return nil, ErrValidation
			}
			authority, err := canonicalAuthority(parsed.Hostname(), parsed.Port())
			if err != nil {
				return nil, err
			}
			origin = scheme + "://" + authority
		}
		if _, exists := seen[origin]; exists {
			return nil, ErrValidation
		}
		seen[origin] = struct{}{}
		result = append(result, origin)
	}
	sort.Strings(result)
	return result, nil
}

func normalizeTokens(input []string, upper, wildcard bool) ([]string, error) {
	if input == nil || len(input) > MaxOrigins {
		return nil, ErrValidation
	}
	result := make([]string, 0, len(input))
	seen := make(map[string]struct{}, len(input))
	for _, value := range input {
		if value == "*" && wildcard {
			if len(input) != 1 {
				return nil, ErrValidation
			}
		} else if !validToken(value) {
			return nil, ErrValidation
		}
		if upper {
			value = strings.ToUpper(value)
		} else {
			value = strings.ToLower(value)
		}
		if _, exists := seen[value]; exists {
			return nil, ErrValidation
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result, nil
}

func validIdentifier(value string) bool {
	if len(value) < 1 || len(value) > 128 {
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

func hasControl(value string) bool {
	return strings.IndexFunc(value, func(character rune) bool { return character < 0x20 || character == 0x7f }) >= 0
}

func isASCII(value string) bool {
	return utf8.ValidString(value) && strings.IndexFunc(value, func(character rune) bool { return character > 0x7f }) < 0
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func validWriteMetadata(metadata WriteMetadata) bool {
	return metadataPattern.MatchString(metadata.IdempotencyKey) &&
		metadataPattern.MatchString(metadata.RequestID) && metadataPattern.MatchString(metadata.TraceID)
}

func validActor(actor Actor) bool {
	return actor.UserID != uuid.Nil && actor.ScopeID != uuid.Nil &&
		(actor.ScopeKind == "platform" || actor.ScopeKind == "tenant")
}

func digestRequest(value any) ([32]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func configFromPolicy(policy Policy) Config {
	return Config{
		MaxUploadBytes:       policy.MaxUploadBytes,
		RequestHeaders:       append([]HeaderAction{}, policy.RequestHeaders...),
		ResponseHeaders:      append([]HeaderAction{}, policy.ResponseHeaders...),
		Rewrites:             append([]RewriteRule{}, policy.Rewrites...),
		RedirectAllowedHosts: append([]string{}, policy.RedirectAllowedHosts...),
		Redirects:            append([]RedirectRule{}, policy.Redirects...),
		CORS:                 cloneCORS(policy.CORS),
		RefererCheck:         cloneRefererCheck(policy.RefererCheck),
	}
}

func applyConfig(policy *Policy, config Config) {
	policy.MaxUploadBytes = config.MaxUploadBytes
	policy.RequestHeaders = append([]HeaderAction{}, config.RequestHeaders...)
	policy.ResponseHeaders = append([]HeaderAction{}, config.ResponseHeaders...)
	policy.Rewrites = append([]RewriteRule{}, config.Rewrites...)
	policy.RedirectAllowedHosts = append([]string{}, config.RedirectAllowedHosts...)
	policy.Redirects = append([]RedirectRule{}, config.Redirects...)
	policy.CORS = cloneCORS(config.CORS)
	policy.RefererCheck = cloneRefererCheck(config.RefererCheck)
}

func cloneCORS(input *CORSPolicy) *CORSPolicy {
	if input == nil {
		return nil
	}
	result := *input
	result.AllowedOrigins = append([]string{}, input.AllowedOrigins...)
	result.AllowedMethods = append([]string{}, input.AllowedMethods...)
	result.AllowedHeaders = append([]string{}, input.AllowedHeaders...)
	result.ExposedHeaders = append([]string{}, input.ExposedHeaders...)
	return &result
}

func edgeSite(policy Policy) EdgeSitePolicy {
	return EdgeSitePolicy{
		SiteID: policy.SiteID.String(), MaxUploadBytes: policy.MaxUploadBytes,
		RequestHeaders:       append([]HeaderAction{}, policy.RequestHeaders...),
		ResponseHeaders:      append([]HeaderAction{}, policy.ResponseHeaders...),
		Rewrites:             append([]RewriteRule{}, policy.Rewrites...),
		RedirectAllowedHosts: append([]string{}, policy.RedirectAllowedHosts...),
		Redirects:            append([]RedirectRule{}, policy.Redirects...), CORS: cloneCORS(policy.CORS),
		RefererCheck: cloneRefererCheck(policy.RefererCheck),
	}
}

func canonicalSnapshot(version uint64, policies []Policy) (EdgeSnapshot, []byte, [32]byte, error) {
	if version < 1 || version > MaxPolicyVersion || len(policies) < 1 || len(policies) > MaxSites {
		return EdgeSnapshot{}, nil, [32]byte{}, ErrConflict
	}
	seenSites := make(map[uuid.UUID]struct{}, len(policies))
	for _, policy := range policies {
		if policy.SiteID == uuid.Nil || !policy.Enabled || policy.Deleted {
			return EdgeSnapshot{}, nil, [32]byte{}, ErrConflict
		}
		if _, exists := seenSites[policy.SiteID]; exists {
			return EdgeSnapshot{}, nil, [32]byte{}, ErrConflict
		}
		seenSites[policy.SiteID] = struct{}{}
		config := configFromPolicy(policy)
		normalized, err := normalizeConfig(config)
		if err != nil || !reflect.DeepEqual(config, normalized) {
			return EdgeSnapshot{}, nil, [32]byte{}, ErrConflict
		}
	}
	sort.Slice(policies, func(left, right int) bool { return policies[left].SiteID.String() < policies[right].SiteID.String() })
	snapshot := EdgeSnapshot{SchemaVersion: EdgeSchemaVersion, PolicyVersion: version, Sites: make([]EdgeSitePolicy, len(policies))}
	for index, policy := range policies {
		snapshot.Sites[index] = edgeSite(policy)
	}
	canonical, err := json.Marshal(snapshot)
	if err != nil {
		return EdgeSnapshot{}, nil, [32]byte{}, err
	}
	canonical = append(canonical, '\n')
	if len(canonical) > MaxPolicyBytes {
		return EdgeSnapshot{}, nil, [32]byte{}, ErrConflict
	}
	return snapshot, canonical, sha256.Sum256(canonical), nil
}

func strictUUID(raw string) (uuid.UUID, error) {
	if raw != strings.ToLower(raw) || len(raw) != 36 {
		return uuid.Nil, ErrInvalidInput
	}
	value, err := uuid.Parse(raw)
	if err != nil || value.String() != raw {
		return uuid.Nil, ErrInvalidInput
	}
	return value, nil
}
