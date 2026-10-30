package cachecontrol

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
)

const (
	maxRules      = 100
	maxRuleValues = 32
	// maxTargets / maxTotalTargetBytes: one operation's targets (ge-cache:
	// raised from 16; every hop carries the same limits).
	maxTargets          = 500
	maxTotalTargetBytes = 256 << 10
	maxNodes            = 1000
	maxOperationItems   = 100000
	maxTargetBytes      = 16 << 10
	maxPathBytes        = 8 << 10
	minTTLSeconds       = 1
	maxTTLSeconds       = 365 * 24 * 60 * 60
	minDiskQuotaBytes   = 64 << 20
	maxDiskQuotaBytes   = int64(16) << 40
	maxRetries          = 10
	maxClaimBatch       = 100
)

var (
	idempotencyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	extensionPattern   = regexp.MustCompile(`^\.[a-z0-9][a-z0-9_+-]{0,15}$`)
	queryNamePattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.~-]{0,127}$`)
	headerNamePattern  = regexp.MustCompile(`^[!#$%&'*+.^_` + "`" + `|~0-9A-Za-z-]{1,128}$`)
	stableCodePattern  = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,127}$`)
)

var forbiddenVaryHeaders = map[string]struct{}{
	"authorization":       {},
	"cookie":              {},
	"proxy-authorization": {},
	"set-cookie":          {},
}

func (rule Rule) MarshalJSON() ([]byte, error) {
	if rule.Action == "" {
		return json.Marshal(struct {
			Order        int      `json:"order"`
			Extensions   []string `json:"extensions,omitempty"`
			PathPrefix   string   `json:"path_prefix,omitempty"`
			StatusCodes  []int    `json:"status_codes,omitempty"`
			TTLSeconds   int64    `json:"ttl_seconds"`
			PathRegex    string   `json:"path_regex,omitempty"`
			ContentTypes []string `json:"content_types,omitempty"`
		}{rule.Order, rule.Extensions, rule.PathPrefix, rule.StatusCodes, rule.TTLSeconds, rule.PathRegex, rule.ContentTypes})
	}
	return json.Marshal(struct {
		Order             int        `json:"order"`
		Extensions        []string   `json:"extensions,omitempty"`
		PathPrefix        string     `json:"path_prefix,omitempty"`
		StatusCodes       []int      `json:"status_codes,omitempty"`
		Action            RuleAction `json:"action"`
		TTLSeconds        int64      `json:"ttl_seconds"`
		BrowserTTLSeconds int64      `json:"browser_ttl_seconds"`
		PathRegex         string     `json:"path_regex,omitempty"`
		ContentTypes      []string   `json:"content_types,omitempty"`
		edgeconfig.CacheRuleExtras
	}{
		rule.Order, rule.Extensions, rule.PathPrefix, rule.StatusCodes,
		rule.Action, rule.TTLSeconds, rule.BrowserTTLSeconds, rule.PathRegex, rule.ContentTypes,
		rule.CacheRuleExtras,
	})
}

func (rule *Rule) UnmarshalJSON(data []byte) error {
	decoded, err := decodeRuleJSON(data, false)
	if err != nil {
		return err
	}
	*rule = decoded
	return nil
}

func decodeRuleJSON(data []byte, strictV2 bool) (Rule, error) {
	fields, err := decodeJSONObject(data)
	if err != nil {
		return Rule{}, err
	}
	if strictV2 {
		if err := validateJSONObjectFields(fields, map[string]bool{
			"order": true, "extensions": false, "path_prefix": false, "status_codes": false,
			"action": true, "ttl_seconds": true, "browser_ttl_seconds": true,
			"path_regex": false, "content_types": false,
			"path_exact": false, "ignore_query": false, "slice_bytes": false, "force_cache": false,
			"ignore_vary": false, "no_cache": false,
		}); err != nil {
			return Rule{}, err
		}
	}
	type wire Rule
	var decoded wire
	if err := json.Unmarshal(data, &decoded); err != nil {
		return Rule{}, ErrInvalidInput
	}
	result := Rule(decoded)
	_, result.actionExplicit = fields["action"]
	_, result.browserTTLExplicit = fields["browser_ttl_seconds"]
	return result, nil
}

func (document PolicyDocument) MarshalJSON() ([]byte, error) {
	type wire struct {
		SchemaVersion  *int       `json:"schema_version,omitempty"`
		Mode           PolicyMode `json:"mode"`
		Rules          []Rule     `json:"rules"`
		QueryMode      QueryMode  `json:"query_mode"`
		QueryNames     []string   `json:"query_names"`
		VaryHeaders    []string   `json:"vary_headers"`
		DiskQuotaBytes int64      `json:"disk_quota_bytes"`
		PolicyExtensions
	}
	var schemaVersion *int
	if document.SchemaVersion != 0 && document.SchemaVersion != PolicySchemaV1 {
		value := document.SchemaVersion
		schemaVersion = &value
	}
	return json.Marshal(wire{
		SchemaVersion: schemaVersion, Mode: document.Mode, Rules: document.Rules,
		QueryMode: document.QueryMode, QueryNames: document.QueryNames,
		VaryHeaders: document.VaryHeaders, DiskQuotaBytes: document.DiskQuotaBytes,
		PolicyExtensions: document.Extensions,
	})
}

func (document *PolicyDocument) UnmarshalJSON(data []byte) error {
	fields, err := decodeJSONObject(data)
	if err != nil {
		return err
	}
	schemaRaw, schemaExplicit := fields["schema_version"]
	strictV2 := false
	if schemaExplicit {
		if bytes.Equal(bytes.TrimSpace(schemaRaw), []byte("null")) {
			return ErrInvalidInput
		}
		var schemaVersion int
		if err := json.Unmarshal(schemaRaw, &schemaVersion); err != nil {
			return ErrInvalidInput
		}
		strictV2 = schemaVersion == PolicySchemaV2
	}
	if strictV2 {
		if err := validateJSONObjectFields(fields, map[string]bool{
			"schema_version": true, "mode": true, "rules": true, "query_mode": true,
			"query_names": true, "vary_headers": true, "disk_quota_bytes": true,
			"stale_if_error": false, "background_update": false, "min_object_bytes": false,
			"max_object_bytes": false, "slice_bytes": false,
		}); err != nil {
			return err
		}
	}
	type wire struct {
		SchemaVersion  int             `json:"schema_version"`
		Mode           PolicyMode      `json:"mode"`
		Rules          json.RawMessage `json:"rules"`
		QueryMode      QueryMode       `json:"query_mode"`
		QueryNames     []string        `json:"query_names"`
		VaryHeaders    []string        `json:"vary_headers"`
		DiskQuotaBytes int64           `json:"disk_quota_bytes"`
		PolicyExtensions
	}
	var decoded wire
	if err := json.Unmarshal(data, &decoded); err != nil {
		return ErrInvalidInput
	}
	var rules []Rule
	if len(decoded.Rules) > 0 && !bytes.Equal(bytes.TrimSpace(decoded.Rules), []byte("null")) {
		var rawRules []json.RawMessage
		if err := json.Unmarshal(decoded.Rules, &rawRules); err != nil {
			return ErrInvalidInput
		}
		rules = make([]Rule, len(rawRules))
		for index, raw := range rawRules {
			rule, err := decodeRuleJSON(raw, strictV2)
			if err != nil {
				return err
			}
			rules[index] = rule
		}
	}
	*document = PolicyDocument{
		SchemaVersion: decoded.SchemaVersion, Mode: decoded.Mode, Rules: rules,
		QueryMode: decoded.QueryMode, QueryNames: decoded.QueryNames,
		VaryHeaders: decoded.VaryHeaders, DiskQuotaBytes: decoded.DiskQuotaBytes,
		Extensions: decoded.PolicyExtensions, schemaVersionExplicit: schemaExplicit,
	}
	return nil
}

func DecodeStoredPolicyDocument(
	schemaVersion int,
	mode PolicyMode,
	rules json.RawMessage,
	queryMode QueryMode,
	queryNames, varyHeaders []string,
	diskQuotaBytes int64,
	extensions ...json.RawMessage,
) (PolicyDocument, error) {
	if schemaVersion != PolicySchemaV1 && schemaVersion != PolicySchemaV2 ||
		len(rules) == 0 || bytes.Equal(bytes.TrimSpace(rules), []byte("null")) {
		return PolicyDocument{}, ErrInvalidInput
	}
	var schema *int
	if schemaVersion == PolicySchemaV2 {
		value := schemaVersion
		schema = &value
	}
	wire, err := json.Marshal(struct {
		SchemaVersion  *int            `json:"schema_version,omitempty"`
		Mode           PolicyMode      `json:"mode"`
		Rules          json.RawMessage `json:"rules"`
		QueryMode      QueryMode       `json:"query_mode"`
		QueryNames     []string        `json:"query_names"`
		VaryHeaders    []string        `json:"vary_headers"`
		DiskQuotaBytes int64           `json:"disk_quota_bytes"`
	}{schema, mode, rules, queryMode, queryNames, varyHeaders, diskQuotaBytes})
	if err != nil {
		return PolicyDocument{}, ErrInvalidInput
	}
	var document PolicyDocument
	if err := json.Unmarshal(wire, &document); err != nil {
		return PolicyDocument{}, ErrInvalidInput
	}
	if len(extensions) > 1 {
		return PolicyDocument{}, ErrInvalidInput
	}
	if len(extensions) == 1 && len(extensions[0]) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(extensions[0]))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&document.Extensions); err != nil {
			return PolicyDocument{}, ErrInvalidInput
		}
	}
	return normalizePolicy(document)
}

// StoredExtensions is the extensions column value of a document.
func (document PolicyDocument) StoredExtensions() []byte {
	encoded, err := json.Marshal(document.Extensions)
	if err != nil {
		return []byte("{}")
	}
	return encoded
}

// validExtensions applies edgeconfig's bounds (site runtime v2 only).
func validExtensions(mode PolicyMode, extensions PolicyExtensions) bool {
	return edgeconfig.ValidateCachePolicyExtensions(edgeconfig.CachePolicyDocument{
		Mode: edgeconfig.CacheMode(mode), StaleIfError: extensions.StaleIfError,
		BackgroundUpdate: extensions.BackgroundUpdate, MinObjectBytes: extensions.MinObjectBytes,
		MaxObjectBytes: extensions.MaxObjectBytes, SliceBytes: extensions.SliceBytes,
	}) == nil
}

func decodeJSONObject(data []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, ErrInvalidInput
	}
	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err := decoder.Token()
		name, ok := token.(string)
		if err != nil || !ok {
			return nil, ErrInvalidInput
		}
		if _, duplicate := fields[name]; duplicate {
			return nil, ErrInvalidInput
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return nil, ErrInvalidInput
		}
		fields[name] = raw
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, ErrInvalidInput
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, ErrInvalidInput
	}
	return fields, nil
}

func validateJSONObjectFields(fields map[string]json.RawMessage, allowed map[string]bool) error {
	for name, raw := range fields {
		if _, ok := allowed[name]; !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return ErrInvalidInput
		}
	}
	for name, required := range allowed {
		if _, ok := fields[name]; required && !ok {
			return ErrInvalidInput
		}
	}
	return nil
}

type siteDescriptor struct {
	TenantID uuid.UUID
	Domain   string
	// Domains are the site's active names (primary, aliases, "*."
	// wildcards) as the edge serves them; empty means Domain alone.
	Domains    []string
	HTTPPorts  []string
	HTTPSPorts []string
}

// servesHost reports whether the concrete host is a name the site serves:
// equal to one of its names, or under a "*." name (any depth, not the bare
// suffix), as nginx server_name routes it.
func (site siteDescriptor) servesHost(host string) bool {
	names := site.Domains
	if len(names) == 0 {
		names = []string{site.Domain}
	}
	return SiteServesHost(names, host)
}

// SiteServesHost is servesHost over a site's active names: the cache
// operation target-site resolver (fix-cachedlg) matches URLs to sites by the
// same rule a create checks them against.
func SiteServesHost(names []string, host string) bool {
	for _, name := range names {
		if suffix, wildcard := strings.CutPrefix(name, "*."); wildcard {
			if strings.HasSuffix(host, "."+suffix) {
				return true
			}
		} else if name == host {
			return true
		}
	}
	return false
}

// servesWildcard reports whether a purge of "*.<suffix>" stays within the
// site: the site serves "*.<suffix>" itself, a wildcard covering every host
// under suffix, or names under suffix (it clears only those). It matches the
// node's check (cachetask siteServesWildcard, dyncache servesWildcard).
func (site siteDescriptor) servesWildcard(suffix string) bool {
	names := site.Domains
	if len(names) == 0 {
		names = []string{site.Domain}
	}
	return SiteServesWildcard(names, suffix)
}

// SiteServesWildcard is servesWildcard over a site's active names.
func SiteServesWildcard(names []string, suffix string) bool {
	for _, name := range names {
		if name == "*."+suffix || strings.HasSuffix(name, "."+suffix) {
			return true
		}
		if parent, wildcard := strings.CutPrefix(name, "*."); wildcard && strings.HasSuffix(suffix, "."+parent) {
			return true
		}
	}
	return false
}

// NormalizePolicyDocument applies the same rules PublishPolicy does, so a
// caller can reject a document before it starts a write (marketsupply).
func NormalizePolicyDocument(input PolicyDocument) (PolicyDocument, error) {
	return normalizePolicy(input)
}

func normalizePolicy(input PolicyDocument) (PolicyDocument, error) {
	schemaVersion := input.SchemaVersion
	if schemaVersion == 0 {
		schemaVersion = PolicySchemaV1
	}
	if schemaVersion != PolicySchemaV1 && schemaVersion != PolicySchemaV2 ||
		input.schemaVersionExplicit && schemaVersion != PolicySchemaV2 {
		return PolicyDocument{}, ErrInvalidInput
	}
	result := PolicyDocument{
		SchemaVersion:  schemaVersion,
		Mode:           input.Mode,
		QueryMode:      input.QueryMode,
		DiskQuotaBytes: input.DiskQuotaBytes,
		Extensions:     input.Extensions,
	}
	if !validExtensions(input.Mode, input.Extensions) {
		return PolicyDocument{}, ErrInvalidInput
	}
	if input.Mode != PolicyDisabled && input.Mode != PolicyFollowOrigin && input.Mode != PolicyOverride {
		return PolicyDocument{}, ErrInvalidInput
	}
	if len(input.Rules) > maxRules {
		return PolicyDocument{}, ErrInvalidInput
	}
	switch input.Mode {
	case PolicyDisabled:
		if len(input.Rules) != 0 || input.DiskQuotaBytes != 0 {
			return PolicyDocument{}, ErrInvalidInput
		}
	case PolicyFollowOrigin:
		if len(input.Rules) != 0 || !validDiskQuota(input.DiskQuotaBytes) {
			return PolicyDocument{}, ErrInvalidInput
		}
	case PolicyOverride:
		if len(input.Rules) == 0 || !validDiskQuota(input.DiskQuotaBytes) {
			return PolicyDocument{}, ErrInvalidInput
		}
	}

	result.Rules = make([]Rule, len(input.Rules))
	for index, raw := range input.Rules {
		rule, err := normalizeRule(raw, index+1, schemaVersion, input.schemaVersionExplicit)
		if err != nil {
			return PolicyDocument{}, err
		}
		result.Rules[index] = rule
	}
	conditional := 0
	for _, rule := range result.Rules {
		if rule.PathRegex != "" || len(rule.ContentTypes) != 0 {
			conditional++
		}
	}
	if conditional > edgeconfig.MaxCacheConditionalRules {
		return PolicyDocument{}, ErrInvalidInput
	}
	if schemaVersion == PolicySchemaV1 {
		for left := range result.Rules {
			for right := left + 1; right < len(result.Rules); right++ {
				if rulesOverlap(result.Rules[left], result.Rules[right]) {
					return PolicyDocument{}, ErrInvalidInput
				}
			}
		}
	}

	queryNames, err := normalizeUniqueNames(input.QueryNames, 64, queryNamePattern, false)
	if err != nil {
		return PolicyDocument{}, err
	}
	switch input.QueryMode {
	case QueryPreserve, QueryIgnore:
		if len(queryNames) != 0 {
			return PolicyDocument{}, ErrInvalidInput
		}
	case QueryInclude, QueryExclude:
		if len(queryNames) == 0 {
			return PolicyDocument{}, ErrInvalidInput
		}
	default:
		return PolicyDocument{}, ErrInvalidInput
	}
	result.QueryNames = queryNames

	vary, err := normalizeUniqueNames(input.VaryHeaders, 16, headerNamePattern, true)
	if err != nil {
		return PolicyDocument{}, err
	}
	for _, name := range vary {
		if name == "*" {
			return PolicyDocument{}, ErrInvalidInput
		}
		if _, forbidden := forbiddenVaryHeaders[name]; forbidden {
			return PolicyDocument{}, ErrInvalidInput
		}
	}
	result.VaryHeaders = vary
	return result, nil
}

func normalizeRule(input Rule, expectedOrder, schemaVersion int, explicitV2 bool) (Rule, error) {
	if input.Order != expectedOrder || len(input.Extensions) > maxRuleValues || len(input.StatusCodes) > maxRuleValues {
		return Rule{}, ErrInvalidInput
	}
	switch schemaVersion {
	case PolicySchemaV1:
		if input.Action != "" || input.BrowserTTLSeconds != 0 || input.actionExplicit || input.browserTTLExplicit ||
			input.CacheRuleExtras.Used() ||
			input.TTLSeconds < minTTLSeconds || input.TTLSeconds > maxTTLSeconds {
			return Rule{}, ErrInvalidInput
		}
	case PolicySchemaV2:
		if explicitV2 && (!input.actionExplicit || !input.browserTTLExplicit) {
			return Rule{}, ErrInvalidInput
		}
		if input.Action == RuleActionCache {
			if input.TTLSeconds < minTTLSeconds || input.TTLSeconds > maxTTLSeconds ||
				input.BrowserTTLSeconds < 0 || input.BrowserTTLSeconds > input.TTLSeconds {
				return Rule{}, ErrInvalidInput
			}
		} else if input.Action != RuleActionNoCache || input.TTLSeconds != 0 || input.BrowserTTLSeconds != 0 {
			return Rule{}, ErrInvalidInput
		}
	default:
		return Rule{}, ErrInvalidInput
	}
	extensions := make([]string, 0, len(input.Extensions))
	seenExtensions := make(map[string]struct{}, len(input.Extensions))
	for _, raw := range input.Extensions {
		value := strings.ToLower(strings.TrimSpace(raw))
		if value != raw && value != strings.ToLower(raw) || !strings.HasPrefix(value, ".") {
			return Rule{}, ErrInvalidInput
		}
		if !extensionPattern.MatchString(value) {
			return Rule{}, ErrInvalidInput
		}
		if _, exists := seenExtensions[value]; exists {
			return Rule{}, ErrInvalidInput
		}
		seenExtensions[value] = struct{}{}
		extensions = append(extensions, value)
	}
	sort.Strings(extensions)

	statuses := append([]int(nil), input.StatusCodes...)
	sort.Ints(statuses)
	for index, status := range statuses {
		if status < 100 || status > 599 || index > 0 && statuses[index-1] == status {
			return Rule{}, ErrInvalidInput
		}
	}

	pathPrefix := input.PathPrefix
	if pathPrefix != "" {
		var err error
		pathPrefix, err = normalizeDirectoryPath(pathPrefix)
		if err != nil {
			return Rule{}, err
		}
	}
	if input.PathRegex != "" && edgeconfig.ValidateCachePathRegex(input.PathRegex) != nil {
		return Rule{}, ErrInvalidInput
	}
	var contentTypes []string
	if input.ContentTypes != nil {
		var err error
		if contentTypes, err = edgeconfig.NormalizeCacheContentTypes(input.ContentTypes); err != nil {
			return Rule{}, ErrInvalidInput
		}
	}
	extras := input.CacheRuleExtras.Clone()
	for index := range extras.NoCache {
		extras.NoCache[index].Name = strings.ToLower(extras.NoCache[index].Name)
	}
	if edgeconfig.ValidateCacheRuleExtras(extras, pathPrefix, edgeconfig.CacheRuleAction(input.Action)) != nil {
		return Rule{}, ErrInvalidInput
	}
	return Rule{
		Order: expectedOrder, Extensions: extensions, PathPrefix: pathPrefix,
		StatusCodes: statuses, Action: input.Action, TTLSeconds: input.TTLSeconds,
		BrowserTTLSeconds: input.BrowserTTLSeconds, PathRegex: input.PathRegex, ContentTypes: contentTypes,
		CacheRuleExtras: extras,
	}, nil
}

func validDiskQuota(value int64) bool {
	return value >= minDiskQuotaBytes && value <= maxDiskQuotaBytes
}

func normalizeUniqueNames(values []string, maximum int, pattern *regexp.Regexp, lower bool) ([]string, error) {
	if len(values) > maximum {
		return nil, ErrInvalidInput
	}
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, raw := range values {
		value := raw
		if lower {
			value = strings.ToLower(value)
		}
		if strings.TrimSpace(raw) != raw || !pattern.MatchString(value) {
			return nil, ErrInvalidInput
		}
		if _, exists := seen[value]; exists {
			return nil, ErrInvalidInput
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result, nil
}

// rulesOverlap (schema v1: rules may not overlap). A rule with a path_regex
// or content_types is exempt: whether it matches is only known per request
// or response, and the first matching rule wins as in schema v2.
func rulesOverlap(left, right Rule) bool {
	if left.PathRegex != "" || right.PathRegex != "" || len(left.ContentTypes) != 0 || len(right.ContentTypes) != 0 {
		return false
	}
	return stringSetsOverlap(left.Extensions, right.Extensions) &&
		pathPrefixesOverlap(left.PathPrefix, right.PathPrefix) &&
		intSetsOverlap(left.StatusCodes, right.StatusCodes)
}

func stringSetsOverlap(left, right []string) bool {
	if len(left) == 0 || len(right) == 0 {
		return true
	}
	for _, value := range left {
		if _, found := slices.BinarySearch(right, value); found {
			return true
		}
	}
	return false
}

func intSetsOverlap(left, right []int) bool {
	if len(left) == 0 || len(right) == 0 {
		return true
	}
	for _, value := range left {
		if _, found := slices.BinarySearch(right, value); found {
			return true
		}
	}
	return false
}

func pathPrefixesOverlap(left, right string) bool {
	return left == "" || right == "" || strings.HasPrefix(left, right) || strings.HasPrefix(right, left)
}

func MatchRule(policy PolicyDocument, facts RequestFacts) *Rule {
	extension := strings.ToLower(path.Ext(facts.Path))
	for index := range policy.Rules {
		rule := &policy.Rules[index]
		if len(rule.Extensions) > 0 {
			if _, found := slices.BinarySearch(rule.Extensions, extension); !found {
				continue
			}
		}
		if rule.PathPrefix != "" && !strings.HasPrefix(facts.Path, rule.PathPrefix) ||
			rule.PathExact != "" && facts.Path != rule.PathExact {
			continue
		}
		if rule.PathRegex != "" {
			if pattern, err := edgeconfig.CompileCachePathRegex(rule.PathRegex); err != nil || !pattern.MatchString(facts.Path) {
				continue
			}
		}
		if !edgeconfig.CacheContentTypeMatches(rule.ContentTypes, edgeconfig.CacheMediaType(facts.ContentType)) {
			continue
		}
		if len(rule.StatusCodes) > 0 {
			if _, found := slices.BinarySearch(rule.StatusCodes, facts.StatusCode); !found {
				continue
			}
		}
		return rule
	}
	return nil
}

// TargetError says why one target of a create was refused (ADD-10): the
// 1-based ordinal and a stable reason. It is an ErrInvalidInput.
type TargetError struct {
	Ordinal int
	Reason  string
}

const (
	TargetReasonInvalidURL         = "target_url_invalid"
	TargetReasonHostNotServed      = "target_host_not_served"
	TargetReasonListenerNotEnabled = "target_listener_not_enabled"
	TargetReasonPathInvalid        = "target_path_invalid"
	TargetReasonDuplicate          = "canonical_target_duplicate"
	TargetReasonTooLarge           = "targets_too_large"
)

func (err *TargetError) Error() string {
	return fmt.Sprintf("cache operation target %d: %s", err.Ordinal, err.Reason)
}

func (err *TargetError) Unwrap() error { return ErrInvalidInput }

func targetError(ordinal int, reason string) error {
	return &TargetError{Ordinal: ordinal, Reason: reason}
}

// normalizeTargets: a purge (Q4, user 10-25) may name a "*." wildcard host
// the site serves (see servesWildcard); a prewarm names concrete hosts only.
func normalizeTargets(rawTargets []string, action Action, targetType TargetType, site siteDescriptor) ([]Target, error) {
	if targetType == TargetWholeSite {
		if len(rawTargets) != 0 {
			return nil, ErrInvalidInput
		}
		return []Target{{Ordinal: 1, CanonicalURL: "/", CanonicalPath: "/"}}, nil
	}
	if targetType != TargetExactURL && targetType != TargetDirectoryPrefix ||
		len(rawTargets) == 0 || len(rawTargets) > maxTargets {
		return nil, ErrInvalidInput
	}
	result := make([]Target, 0, len(rawTargets))
	seen := make(map[string]struct{}, len(rawTargets))
	totalBytes := 0
	for index, raw := range rawTargets {
		target, err := normalizeTargetURL(raw, targetType == TargetDirectoryPrefix, site, action == ActionPurge)
		if err != nil {
			var reason *targetReason
			if errors.As(err, &reason) {
				return nil, targetError(index+1, reason.reason)
			}
			return nil, err
		}
		totalBytes += len(target.CanonicalURL)
		if totalBytes > maxTotalTargetBytes {
			return nil, targetError(index+1, TargetReasonTooLarge)
		}
		if _, exists := seen[target.CanonicalURL]; exists {
			return nil, targetError(index+1, TargetReasonDuplicate)
		}
		seen[target.CanonicalURL] = struct{}{}
		target.Ordinal = len(result) + 1
		result = append(result, target)
	}
	return result, nil
}

// targetReason is normalizeTargetURL's refusal with its stable reason;
// normalizeTargets adds the ordinal.
type targetReason struct{ reason string }

func (err *targetReason) Error() string { return err.reason }
func (err *targetReason) Unwrap() error { return ErrInvalidInput }

var (
	errTargetURL      = &targetReason{TargetReasonInvalidURL}
	errTargetHost     = &targetReason{TargetReasonHostNotServed}
	errTargetListener = &targetReason{TargetReasonListenerNotEnabled}
	errTargetPath     = &targetReason{TargetReasonPathInvalid}
)

func normalizeTargetURL(raw string, prefix bool, site siteDescriptor, allowWildcard bool) (Target, error) {
	if raw == "" || len(raw) > maxTargetBytes || strings.TrimSpace(raw) != raw ||
		!asciiPrintable(raw) || strings.Contains(raw, "\\") {
		return Target{}, errTargetURL
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.User != nil || parsed.Fragment != "" || parsed.Opaque != "" ||
		parsed.Host == "" || strings.Contains(raw, "#") {
		return Target{}, errTargetURL
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return Target{}, errTargetURL
	}
	hostname := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if strings.Contains(hostname, "*") {
		// Only a leading "*." label, and only for a purge of names the site
		// serves; the node clears every host under the suffix it keys.
		suffix, wildcard := strings.CutPrefix(hostname, "*.")
		if !allowWildcard || !wildcard || strings.Contains(suffix, "*") {
			return Target{}, ErrWildcardTargetHost
		}
		if !strings.Contains(suffix, ".") || !site.servesWildcard(suffix) {
			return Target{}, errTargetHost
		}
	} else if !site.servesHost(hostname) {
		return Target{}, errTargetHost
	}
	port, err := effectivePort(parsed, scheme)
	if err != nil {
		return Target{}, errTargetURL
	}
	if !siteAllowsPort(site, scheme, port) {
		return Target{}, errTargetListener
	}
	requestPath := parsed.Path
	if requestPath == "" {
		requestPath = "/"
	}
	escapedPath := strings.ToLower(parsed.EscapedPath())
	if len(requestPath) > maxPathBytes || strings.Contains(escapedPath, "%2f") ||
		strings.Contains(escapedPath, "%5c") || !validCanonicalPath(requestPath) {
		return Target{}, errTargetPath
	}
	if prefix {
		if parsed.RawQuery != "" || parsed.ForceQuery {
			return Target{}, errTargetPath
		}
		requestPath, err = normalizeDirectoryPath(requestPath)
		if err != nil {
			return Target{}, errTargetPath
		}
	}
	if !asciiPrintable(parsed.RawQuery) {
		return Target{}, errTargetURL
	}
	// The URL keeps its own host (an alias or a name under a wildcard): the
	// node prewarms under it.
	host := hostname
	if !(scheme == "http" && port == 80 || scheme == "https" && port == 443) {
		host = net.JoinHostPort(hostname, strconv.Itoa(port))
	}
	canonical := (&url.URL{
		Scheme: scheme, Host: host, Path: requestPath,
		RawQuery: parsed.RawQuery, ForceQuery: parsed.ForceQuery,
	}).String()
	return Target{CanonicalURL: canonical, CanonicalPath: requestPath}, nil
}

func effectivePort(parsed *url.URL, scheme string) (int, error) {
	if raw := parsed.Port(); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 65535 {
			return 0, ErrInvalidInput
		}
		return value, nil
	}
	if scheme == "http" {
		return 80, nil
	}
	return 443, nil
}

func siteAllowsPort(site siteDescriptor, scheme string, port int) bool {
	values := site.HTTPPorts
	if scheme == "https" {
		values = site.HTTPSPorts
	}
	want := strconv.Itoa(port)
	return slices.Contains(values, want)
}

func normalizeDirectoryPath(value string) (string, error) {
	if !validCanonicalPath(value) {
		return "", ErrInvalidInput
	}
	if value != "/" && !strings.HasSuffix(value, "/") {
		value += "/"
	}
	return value, nil
}

func validCanonicalPath(value string) bool {
	if value == "" || value[0] != '/' || len(value) > maxPathBytes ||
		strings.Contains(value, "//") || !utf8.ValidString(value) {
		return false
	}
	cleaned := path.Clean(value)
	if value != "/" && strings.HasSuffix(value, "/") {
		cleaned += "/"
	}
	if cleaned != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.IsSpace(character) ||
			character == '|' || character == '?' || character == '#' || character == '\\' {
			return false
		}
	}
	return true
}

func asciiPrintable(value string) bool {
	for _, character := range value {
		if character > unicode.MaxASCII || unicode.IsControl(character) || unicode.IsSpace(character) {
			return false
		}
	}
	return true
}

func validActor(actor Actor) bool {
	return actor.UserID != uuid.Nil && actor.ScopeID != uuid.Nil && actor.ActorScopeID != uuid.Nil
}

func validWriteMetadata(key, requestID string) bool {
	return idempotencyPattern.MatchString(key) && validSafeText(requestID, 128)
}

func validSafeText(value string, maximum int) bool {
	if value == "" || len([]rune(value)) > maximum || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || character == '\u2028' || character == '\u2029' {
			return false
		}
	}
	return true
}

func validStableCode(value string) bool {
	return stableCodePattern.MatchString(value)
}

func digestJSON(value any) ([sha256.Size]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return [sha256.Size]byte{}, ErrInvalidInput
	}
	return sha256.Sum256(encoded), nil
}

func validateCreateOperation(actor Actor, request CreateOperationRequest) error {
	if !validActor(actor) || request.SiteID == uuid.Nil ||
		(request.Action != ActionPurge && request.Action != ActionPrewarm) ||
		(request.TargetType != TargetExactURL && request.TargetType != TargetDirectoryPrefix && request.TargetType != TargetWholeSite) ||
		request.Action == ActionPrewarm && request.TargetType != TargetExactURL ||
		len(request.NodeIDs) > maxNodes || request.MaxRetries > maxRetries ||
		!validWriteMetadata(request.IdempotencyKey, request.RequestID) {
		return ErrInvalidInput
	}
	seen := make(map[uuid.UUID]struct{}, len(request.NodeIDs))
	for _, nodeID := range request.NodeIDs {
		if nodeID == uuid.Nil {
			return ErrInvalidInput
		}
		if _, exists := seen[nodeID]; exists {
			return ErrInvalidInput
		}
		seen[nodeID] = struct{}{}
	}
	return nil
}

func validateClaim(request ClaimRequest) error {
	if request.ScopeID == uuid.Nil || !validSafeText(request.WorkerID, 128) ||
		len(request.OnlineNodeIDs) == 0 || len(request.OnlineNodeIDs) > maxNodes ||
		request.Limit < 1 || request.Limit > maxClaimBatch ||
		request.LeaseDuration < time.Second || request.LeaseDuration > time.Hour ||
		!validSafeText(request.RequestID, 128) {
		return ErrInvalidInput
	}
	seen := make(map[uuid.UUID]struct{}, len(request.OnlineNodeIDs))
	for _, nodeID := range request.OnlineNodeIDs {
		if nodeID == uuid.Nil {
			return ErrInvalidInput
		}
		if _, exists := seen[nodeID]; exists {
			return ErrInvalidInput
		}
		seen[nodeID] = struct{}{}
	}
	return nil
}

func normalizeReport(request ReportRequest) ([]TargetResult, [sha256.Size]byte, error) {
	if request.ScopeID == uuid.Nil || request.OperationID == uuid.Nil || request.NodeID == uuid.Nil ||
		request.LeaseID == uuid.Nil || request.Attempt == 0 || request.Attempt > maxRetries+1 ||
		request.Sequence == 0 || request.Sequence > uint64(^uint64(0)>>1) ||
		!validSafeText(request.WorkerID, 128) || !validSafeText(request.RequestID, 128) ||
		len(request.Results) == 0 || len(request.Results) > maxTargets {
		return nil, [sha256.Size]byte{}, ErrInvalidInput
	}
	results := append([]TargetResult(nil), request.Results...)
	sort.Slice(results, func(i, j int) bool { return results[i].TargetOrdinal < results[j].TargetOrdinal })
	for index, result := range results {
		if result.TargetOrdinal < 1 || result.TargetOrdinal > maxTargets ||
			index > 0 && results[index-1].TargetOrdinal == result.TargetOrdinal ||
			(result.State != ItemSucceeded && result.State != ItemFailed && result.State != ItemCancelled) ||
			(result.State == ItemSucceeded && result.ErrorCode != "") ||
			(result.State == ItemFailed && !validStableCode(result.ErrorCode)) ||
			(result.State == ItemCancelled && result.ErrorCode != codeCancelled) {
			return nil, [sha256.Size]byte{}, ErrInvalidInput
		}
	}
	digest, err := digestJSON(struct {
		Attempt  uint32         `json:"attempt"`
		Sequence uint64         `json:"sequence"`
		Results  []TargetResult `json:"results"`
	}{request.Attempt, request.Sequence, results})
	return results, digest, err
}
