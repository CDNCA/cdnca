package waf

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var ErrInvalidPolicy = errors.New("invalid WAF policy")

func CompileJSON(raw []byte) ([]byte, *CompiledPolicy, error) {
	if len(raw) == 0 || len(raw) > MaxPolicyBytes {
		return nil, nil, invalid("policy size must be between 1 and %d bytes", MaxPolicyBytes)
	}
	if err := rejectInvalidJSONUnicode(raw); err != nil {
		return nil, nil, err
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return nil, nil, err
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var input Policy
	if err := decoder.Decode(&input); err != nil {
		return nil, nil, invalid("decode: %v", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, nil, err
	}
	if err := requireRulesArray(raw); err != nil {
		return nil, nil, err
	}
	compiled, err := compile(input)
	if err != nil {
		if errors.Is(err, ErrInvalidPolicy) {
			return nil, nil, err
		}
		return nil, nil, invalid("%v", err)
	}
	canonical, err := json.Marshal(compiled)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal canonical WAF policy: %w", err)
	}
	canonical = append(canonical, '\n')
	if len(canonical) > MaxPolicyBytes {
		return nil, nil, invalid("canonical policy exceeds %d bytes", MaxPolicyBytes)
	}
	return canonical, compiled, nil
}

func requireRulesArray(raw []byte) error {
	var shape struct {
		Rules json.RawMessage `json:"rules"`
	}
	if err := json.Unmarshal(raw, &shape); err != nil {
		return invalid("decode rules: %v", err)
	}
	if rules := bytes.TrimSpace(shape.Rules); len(rules) == 0 || bytes.Equal(rules, []byte("null")) {
		return invalid("rules must be an array")
	}
	return nil
}

func compile(input Policy) (*CompiledPolicy, error) {
	if input.SchemaVersion != SchemaVersionV1 && input.SchemaVersion != SchemaVersionV2 {
		return nil, invalid("schema_version is unsupported")
	}
	if input.SchemaVersion == SchemaVersionV1 &&
		(input.ClientSource != nil || len(input.TrustedCrawlers) != 0 || input.UnknownGeoAction != "") {
		return nil, invalid("schema v1 cannot carry client source or trusted crawler policy")
	}
	if input.PolicyVersion == 0 {
		return nil, invalid("policy_version must be positive")
	}
	if input.PolicyVersion > MaxPolicyVersion {
		return nil, invalid("policy_version exceeds cross-runtime integer limit %d", MaxPolicyVersion)
	}
	if len(input.Rules) > MaxRules {
		return nil, invalid("rule count exceeds %d", MaxRules)
	}

	result := &CompiledPolicy{
		SchemaVersion: input.SchemaVersion,
		PolicyVersion: input.PolicyVersion,
		Rules:         make([]CompiledRule, 0, len(input.Rules)),
		valid:         true,
	}
	if input.SchemaVersion == SchemaVersionV2 {
		var err error
		result.ClientSource, err = compileClientSource(input.ClientSource)
		if err != nil {
			return nil, err
		}
		result.TrustedCrawlers, err = compileTrustedCrawlers(input.TrustedCrawlers)
		if err != nil {
			return nil, err
		}
	}
	geo, err := compileGeo(input.Geo)
	if err != nil {
		return nil, err
	}
	result.Geo = geo
	ids := make(map[string]struct{}, len(input.Rules))
	hasCountryRule := false
	for index, rule := range input.Rules {
		compiled, err := compileRule(rule)
		if err != nil {
			return nil, invalid("rule %d: %v", index, err)
		}
		if _, exists := ids[compiled.RuleID]; exists {
			return nil, invalid("duplicate rule_id %q", compiled.RuleID)
		}
		ids[compiled.RuleID] = struct{}{}
		result.Rules = append(result.Rules, compiled)
		hasCountryRule = hasCountryRule || compiled.Match.Country != nil
	}
	for _, rule := range result.Rules {
		if rule.Match.Country != nil && len(result.Geo) == 0 {
			return nil, errors.New("country match requires an authoritative geo table")
		}
	}
	if input.SchemaVersion == SchemaVersionV2 {
		if hasCountryRule && input.UnknownGeoAction != GeoUnknownAllow && input.UnknownGeoAction != GeoUnknownBlock {
			return nil, errors.New("country match requires an explicit unknown geo action")
		}
		if !hasCountryRule && input.UnknownGeoAction != "" {
			return nil, errors.New("unknown geo action requires a country matcher")
		}
		result.UnknownGeoAction = input.UnknownGeoAction
	}
	sort.Slice(result.Rules, func(i, j int) bool {
		if result.Rules[i].Priority != result.Rules[j].Priority {
			return result.Rules[i].Priority < result.Rules[j].Priority
		}
		return result.Rules[i].RuleID < result.Rules[j].RuleID
	})
	return result, nil
}

func compileClientSource(input *ClientSourcePolicy) (*CompiledClientSourcePolicy, error) {
	if input == nil {
		return nil, nil
	}
	if input.Header != "x-forwarded-for" || input.MaxHops < 1 || input.MaxHops > MaxProxyHops {
		return nil, errors.New("client source policy is invalid")
	}
	proxies, err := compileTrustedCIDRs(input.TrustedProxyCIDRs, MaxTrustedProxies)
	if err != nil {
		return nil, fmt.Errorf("trusted proxy CIDRs: %w", err)
	}
	return &CompiledClientSourcePolicy{Header: input.Header, MaxHops: input.MaxHops, TrustedProxyCIDRs: proxies}, nil
}

func compileTrustedCrawlers(input []TrustedCrawler) ([]CompiledTrustedCrawler, error) {
	if len(input) > MaxTrustedCrawlers {
		return nil, errors.New("trusted crawler count exceeds limit")
	}
	result := make([]CompiledTrustedCrawler, len(input))
	for index, crawler := range input {
		networks, err := compileTrustedCIDRs(crawler.Networks, MaxCrawlerNetworks)
		if err != nil {
			return nil, fmt.Errorf("trusted crawler %d networks: %w", index, err)
		}
		if len(crawler.UserAgentPrefixes) == 0 || len(crawler.UserAgentPrefixes) > MaxCrawlerUserAgents {
			return nil, fmt.Errorf("trusted crawler %d user-agent prefix count is invalid", index)
		}
		prefixes := slices.Clone(crawler.UserAgentPrefixes)
		sort.Strings(prefixes)
		for prefixIndex, prefix := range prefixes {
			if len(prefix) == 0 || len(prefix) > MaxValueBytes || !isASCII(prefix) || hasControl(prefix) ||
				strings.TrimSpace(prefix) != prefix || prefixIndex > 0 && prefix == prefixes[prefixIndex-1] {
				return nil, fmt.Errorf("trusted crawler %d user-agent prefix is invalid", index)
			}
		}
		result[index] = CompiledTrustedCrawler{Networks: networks, UserAgentPrefixes: prefixes}
	}
	return result, nil
}

func compileTrustedCIDRs(input []string, maximum int) ([]CompiledCIDR, error) {
	if len(input) == 0 || len(input) > maximum {
		return nil, errors.New("CIDR count is invalid")
	}
	parsed := make([]netip.Prefix, 0, len(input))
	result := make([]CompiledCIDR, 0, len(input))
	for _, value := range input {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix != prefix.Masked() || prefix.Addr().Is4In6() || prefix.Bits() == 0 ||
			prefix.Addr().IsUnspecified() || prefix.Addr().IsMulticast() || prefix.Addr().IsLoopback() ||
			prefix.Addr().IsLinkLocalUnicast() || prefix.Addr().IsLinkLocalMulticast() {
			return nil, errors.New("CIDR is unsafe")
		}
		for _, previous := range parsed {
			if previous.Addr().BitLen() == prefix.Addr().BitLen() &&
				(previous.Contains(prefix.Addr()) || prefix.Contains(previous.Addr())) {
				return nil, errors.New("CIDRs overlap")
			}
		}
		compiled, err := compileCIDR(value)
		if err != nil {
			return nil, err
		}
		parsed = append(parsed, prefix)
		result = append(result, *compiled)
	}
	sort.Slice(result, func(left, right int) bool {
		if result[left].Family != result[right].Family {
			return result[left].Family < result[right].Family
		}
		if compared := slices.Compare(result[left].Network, result[right].Network); compared != 0 {
			return compared < 0
		}
		return result[left].PrefixLength < result[right].PrefixLength
	})
	return result, nil
}

func compileRule(input Rule) (CompiledRule, error) {
	if err := validateIdentifier(input.RuleID); err != nil {
		return CompiledRule{}, fmt.Errorf("rule_id: %w", err)
	}
	switch input.Action {
	case ActionAllow, ActionBlock, ActionLog:
	default:
		return CompiledRule{}, fmt.Errorf("unsupported action %q", input.Action)
	}
	switch input.Flow {
	case FlowContinue, FlowStop:
	default:
		return CompiledRule{}, fmt.Errorf("unsupported flow %q", input.Flow)
	}
	match, err := compileMatch(input.Match)
	if err != nil {
		return CompiledRule{}, err
	}
	if (input.Comment != nil || input.ExpiresAt != nil) && input.Match.SourceCIDR == "" {
		return CompiledRule{}, errors.New("comment and expires_at require source_cidr")
	}
	comment := ""
	if input.Comment != nil {
		comment = *input.Comment
		if len(comment) == 0 || len(comment) > MaxCommentBytes || !utf8.ValidString(comment) || hasControl(comment) || strings.TrimSpace(comment) == "" {
			return CompiledRule{}, fmt.Errorf("comment must be non-empty UTF-8 within %d bytes and contain no control characters", MaxCommentBytes)
		}
	}
	expiresAtUnix := int64(0)
	if input.ExpiresAt != nil {
		expiresAtUnix, err = parseCanonicalExpiry(*input.ExpiresAt)
		if err != nil {
			return CompiledRule{}, err
		}
	}
	return CompiledRule{
		RuleID: input.RuleID, Priority: input.Priority, Action: input.Action, Flow: input.Flow,
		Comment: comment, ExpiresAtUnix: expiresAtUnix, Match: match,
	}, nil
}

func parseCanonicalExpiry(value string) (int64, error) {
	const canonicalLayout = "2006-01-02T15:04:05Z"
	if len(value) != len(canonicalLayout) {
		return 0, errors.New("expires_at must be canonical RFC3339 UTC with second precision")
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Format(canonicalLayout) != value {
		return 0, errors.New("expires_at must be canonical RFC3339 UTC with second precision")
	}
	seconds := parsed.Unix()
	if seconds <= 0 || seconds > MaxPolicyVersion {
		return 0, errors.New("expires_at is outside the cross-runtime integer range")
	}
	return seconds, nil
}

func compileMatch(input Match) (CompiledMatch, error) {
	if input.Host == "" && input.Port == 0 && input.Method == "" && input.Path == nil && input.Query == nil && input.Header == nil &&
		input.UserAgent == nil && input.SourceCIDR == "" && input.Country == nil {
		return CompiledMatch{}, errors.New("match must contain at least one condition")
	}
	result := CompiledMatch{Port: input.Port}
	var err error
	if input.Host != "" {
		result.Host, err = normalizeHost(input.Host)
		if err != nil {
			return CompiledMatch{}, fmt.Errorf("host: %w", err)
		}
	}
	if input.Method != "" {
		result.Method = strings.ToUpper(input.Method)
		if len(result.Method) > MaxMethodBytes || !isToken(result.Method) || result.Method != input.Method {
			return CompiledMatch{}, errors.New("method must be an uppercase HTTP token")
		}
	}
	if input.Path != nil {
		value, err := validatePath(*input.Path)
		if err != nil {
			return CompiledMatch{}, err
		}
		result.Path = &value
	}
	if input.Query != nil {
		value, err := validateValueMatch("query", *input.Query, false)
		if err != nil {
			return CompiledMatch{}, err
		}
		result.Query = &value
	}
	if input.Header != nil {
		value, err := validateValueMatch("header", *input.Header, true)
		if err != nil {
			return CompiledMatch{}, err
		}
		value.Name = strings.ToLower(value.Name)
		result.Header = &value
	}
	if input.UserAgent != nil {
		value, err := validateUserAgentMatch(*input.UserAgent)
		if err != nil {
			return CompiledMatch{}, err
		}
		result.UserAgent = &value
	}
	if input.SourceCIDR != "" {
		result.SourceCIDR, err = compileCIDR(input.SourceCIDR)
		if err != nil {
			return CompiledMatch{}, err
		}
	}
	if input.Country != nil {
		country, err := compileCountryMatch(*input.Country)
		if err != nil {
			return CompiledMatch{}, err
		}
		result.Country = &country
	}
	return result, nil
}

func compileCountryMatch(input CountryMatch) (CountryMatch, error) {
	if input.Operator != CountryIn && input.Operator != CountryNotIn || len(input.Values) == 0 || len(input.Values) > 64 {
		return CountryMatch{}, errors.New("country matcher is invalid")
	}
	values := slices.Clone(input.Values)
	sort.Strings(values)
	for index, value := range values {
		if !validCountry(value) || index > 0 && value == values[index-1] {
			return CountryMatch{}, errors.New("country matcher is invalid")
		}
	}
	return CountryMatch{Operator: input.Operator, Values: values}, nil
}

func compileGeo(input []GeoRange) ([]CompiledGeoRange, error) {
	if len(input) > MaxGeoRanges {
		return nil, errors.New("geo range count exceeds limit")
	}
	result := make([]CompiledGeoRange, 0, len(input))
	prefixes := make([]netip.Prefix, 0, len(input))
	for _, item := range input {
		prefix, err := netip.ParsePrefix(item.CIDR)
		if err != nil || prefix != prefix.Masked() || !validCountry(item.Country) {
			return nil, errors.New("geo range is invalid")
		}
		for _, previous := range prefixes {
			if previous.Addr().BitLen() == prefix.Addr().BitLen() &&
				(previous.Contains(prefix.Addr()) || prefix.Contains(previous.Addr())) {
				return nil, errors.New("geo ranges overlap")
			}
		}
		compiled, err := compileCIDR(item.CIDR)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, prefix)
		result = append(result, CompiledGeoRange{CIDR: *compiled, Country: item.Country})
	}
	sort.Slice(result, func(i, j int) bool {
		left, right := result[i].CIDR, result[j].CIDR
		if left.Family != right.Family {
			return left.Family < right.Family
		}
		for index := range left.Network {
			if left.Network[index] != right.Network[index] {
				return left.Network[index] < right.Network[index]
			}
		}
		return left.PrefixLength < right.PrefixLength
	})
	return result, nil
}

func validCountry(value string) bool {
	return len(value) == 2 && value[0] >= 'A' && value[0] <= 'Z' && value[1] >= 'A' && value[1] <= 'Z'
}

func validateIdentifier(value string) error {
	if len(value) == 0 || len(value) > MaxRuleIDBytes {
		return fmt.Errorf("length must be between 1 and %d bytes", MaxRuleIDBytes)
	}
	for index := range value {
		character := value[index]
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '.' || character == '_' || character == ':' || character == '-' {
			continue
		}
		return errors.New("contains an unsupported character")
	}
	return nil
}

func normalizeHost(value string) (string, error) {
	if len(value) == 0 || len(value) > MaxHostBytes || !isASCII(value) || hasControl(value) {
		return "", errors.New("must be a bounded ASCII hostname")
	}
	if strings.ContainsAny(value, ":/\\%") {
		return "", errors.New("must not contain a port, address literal, slash, or escape")
	}
	value = strings.ToLower(strings.TrimSuffix(value, "."))
	if value == "" || len(value) > MaxHostBytes {
		return "", errors.New("hostname is empty")
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("contains an invalid DNS label")
		}
		for index := range label {
			character := label[index]
			if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-' {
				continue
			}
			return "", errors.New("contains an invalid DNS label")
		}
	}
	return value, nil
}

func validatePath(input PathMatch) (PathMatch, error) {
	if input.Kind != PathExact && input.Kind != PathPrefix && input.Kind != PathRawPrefix {
		return PathMatch{}, fmt.Errorf("path kind %q is unsupported", input.Kind)
	}
	value := input.Value
	if len(value) == 0 || len(value) > MaxPathBytes || !utf8.ValidString(value) || hasControl(value) {
		return PathMatch{}, errors.New("path must be valid UTF-8 within the configured limit")
	}
	if value[0] != '/' || strings.ContainsAny(value, "\\%?#") || strings.Contains(value, "//") || path.Clean(value) != value {
		return PathMatch{}, errors.New("path must be canonical and contain no traversal, escape, query, fragment, or backslash")
	}
	return input, nil
}

func validateValueMatch(kind string, input ValueMatch, header bool) (ValueMatch, error) {
	if len(input.Name) == 0 || len(input.Name) > MaxNameBytes || !utf8.ValidString(input.Name) || hasControl(input.Name) {
		return ValueMatch{}, fmt.Errorf("%s name is invalid", kind)
	}
	if header && (!isASCII(input.Name) || !isToken(input.Name)) {
		return ValueMatch{}, errors.New("header name must be an RFC token")
	}
	if !header && strings.ContainsAny(input.Name, "&=#") {
		return ValueMatch{}, errors.New("query name contains a reserved separator")
	}
	switch input.Operator {
	case OperatorExists:
		if input.Value != "" {
			return ValueMatch{}, fmt.Errorf("%s exists matcher must not have a value", kind)
		}
	case OperatorExact:
		if len(input.Value) > MaxValueBytes || !utf8.ValidString(input.Value) || hasControl(input.Value) {
			return ValueMatch{}, fmt.Errorf("%s exact value is invalid", kind)
		}
	default:
		return ValueMatch{}, fmt.Errorf("%s operator %q is unsupported", kind, input.Operator)
	}
	return input, nil
}

func validateUserAgentMatch(input UserAgentMatch) (UserAgentMatch, error) {
	switch input.Operator {
	case OperatorExists:
		if input.Value != "" {
			return UserAgentMatch{}, errors.New("user-agent exists matcher must not have a value")
		}
	case OperatorExact:
		if input.Value == "" || len(input.Value) > MaxUserAgentBytes || !utf8.ValidString(input.Value) || hasControl(input.Value) {
			return UserAgentMatch{}, errors.New("user-agent exact value is invalid")
		}
	default:
		return UserAgentMatch{}, fmt.Errorf("user-agent operator %q is unsupported", input.Operator)
	}
	return input, nil
}

func compileCIDR(value string) (*CompiledCIDR, error) {
	if len(value) > MaxValueBytes || !isASCII(value) || hasControl(value) || strings.Contains(value, "%") {
		return nil, errors.New("source_cidr is invalid")
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return nil, fmt.Errorf("source_cidr: %w", err)
	}
	if prefix.Addr().Is4In6() {
		return nil, errors.New("source_cidr must not use an IPv4-mapped IPv6 address")
	}
	addressText, bitsText, found := strings.Cut(value, "/")
	if !found || addressText != prefix.Addr().String() || bitsText != strconv.Itoa(prefix.Bits()) {
		return nil, errors.New("source_cidr address and prefix must use canonical text")
	}
	prefix = prefix.Masked()
	address := prefix.Addr()
	if address.Is4() {
		bytes := address.As4()
		return &CompiledCIDR{Family: 4, Network: numericBytes(bytes[:]), PrefixLength: uint8(prefix.Bits())}, nil
	}
	bytes := address.As16()
	return &CompiledCIDR{Family: 6, Network: numericBytes(bytes[:]), PrefixLength: uint8(prefix.Bits())}, nil
}

func numericBytes(value []byte) []uint16 {
	result := make([]uint16, len(value))
	for index, element := range value {
		result[index] = uint16(element)
	}
	return result
}

func hasControl(value string) bool {
	for _, character := range value {
		if unicode.IsControl(character) {
			return true
		}
	}
	return false
}

func isASCII(value string) bool {
	for index := range value {
		if value[index] > unicode.MaxASCII {
			return false
		}
	}
	return true
}

func isToken(value string) bool {
	if value == "" {
		return false
	}
	const separators = "()<>@,;:\\\"/[]?={} \t"
	for index := range value {
		character := value[index]
		if character < 0x21 || character > 0x7e || strings.ContainsRune(separators, rune(character)) {
			return false
		}
	}
	return true
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return invalid("multiple JSON values are not allowed")
		}
		return invalid("trailing JSON: %v", err)
	}
	return nil
}

func rejectInvalidJSONUnicode(raw []byte) error {
	if !utf8.Valid(raw) {
		return invalid("policy contains invalid UTF-8")
	}
	for index := 0; index < len(raw); index++ {
		if raw[index] != '"' {
			continue
		}
		for index++; index < len(raw) && raw[index] != '"'; index++ {
			if raw[index] != '\\' {
				continue
			}
			index++
			if index >= len(raw) || raw[index] != 'u' {
				continue
			}
			if index+5 > len(raw) {
				return invalid("policy contains an invalid Unicode escape")
			}
			codeUnit, ok := parseJSONCodeUnit(raw[index+1 : index+5])
			if !ok {
				return invalid("policy contains an invalid Unicode escape")
			}
			index += 4
			switch {
			case codeUnit >= 0xd800 && codeUnit <= 0xdbff:
				if index+6 >= len(raw) || raw[index+1] != '\\' || raw[index+2] != 'u' {
					return invalid("policy contains an unpaired UTF-16 surrogate")
				}
				low, ok := parseJSONCodeUnit(raw[index+3 : index+7])
				if !ok || low < 0xdc00 || low > 0xdfff {
					return invalid("policy contains an unpaired UTF-16 surrogate")
				}
				index += 6
			case codeUnit >= 0xdc00 && codeUnit <= 0xdfff:
				return invalid("policy contains an unpaired UTF-16 surrogate")
			}
		}
	}
	return nil
}

func parseJSONCodeUnit(raw []byte) (uint16, bool) {
	if len(raw) != 4 {
		return 0, false
	}
	var result uint16
	for _, value := range raw {
		result <<= 4
		switch {
		case value >= '0' && value <= '9':
			result += uint16(value - '0')
		case value >= 'a' && value <= 'f':
			result += uint16(value-'a') + 10
		case value >= 'A' && value <= 'F':
			result += uint16(value-'A') + 10
		default:
			return 0, false
		}
	}
	return result, true
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

func invalid(format string, values ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidPolicy, fmt.Sprintf(format, values...))
}
