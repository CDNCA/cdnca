package cc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

func CompileJSON(raw []byte) ([]byte, *CompiledPolicy, error) {
	if len(raw) == 0 || len(raw) > MaxPolicyBytes {
		return nil, nil, invalid("policy size must be between 1 and %d bytes", MaxPolicyBytes)
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
	compiled, err := compile(input)
	if err != nil {
		return nil, nil, err
	}
	canonical, err := json.Marshal(compiled)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal canonical CC policy: %w", err)
	}
	canonical = append(canonical, '\n')
	if len(canonical) > MaxPolicyBytes {
		return nil, nil, invalid("canonical policy exceeds %d bytes", MaxPolicyBytes)
	}
	return canonical, compiled, nil
}

func compile(input Policy) (*CompiledPolicy, error) {
	if input.SchemaVersion != SchemaVersion {
		return nil, invalid("schema_version must be %q", SchemaVersion)
	}
	if input.PolicyVersion == 0 || input.PolicyVersion > MaxPolicyVersion {
		return nil, invalid("policy_version must be between 1 and %d", MaxPolicyVersion)
	}
	if len(input.Rules) > MaxRules {
		return nil, invalid("rule count exceeds %d", MaxRules)
	}
	trusted, err := compileCIDRs("trusted_proxies", input.TrustedProxies, MaxProxyCIDRs)
	if err != nil {
		return nil, err
	}
	allowlist, err := compileCIDRs("allowlist", input.Allowlist, MaxAllowlistCIDRs)
	if err != nil {
		return nil, err
	}
	result := &CompiledPolicy{
		SchemaVersion: input.SchemaVersion, PolicyVersion: input.PolicyVersion,
		TrustedProxies: trusted, Allowlist: allowlist, Rules: make([]Rule, 0, len(input.Rules)),
	}
	ids := make(map[string]struct{}, len(input.Rules))
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
	}
	sort.Slice(result.Rules, func(i, j int) bool {
		if result.Rules[i].Priority != result.Rules[j].Priority {
			return result.Rules[i].Priority < result.Rules[j].Priority
		}
		return result.Rules[i].RuleID < result.Rules[j].RuleID
	})
	return result, nil
}

func compileRule(input Rule) (Rule, error) {
	if err := validateIdentifier(input.RuleID); err != nil {
		return Rule{}, fmt.Errorf("rule_id: %w", err)
	}
	if err := validateIdentifier(input.TenantID); err != nil {
		return Rule{}, fmt.Errorf("tenant_id: %w", err)
	}
	if err := validateIdentifier(input.SiteID); err != nil {
		return Rule{}, fmt.Errorf("site_id: %w", err)
	}
	match, err := compileMatch(input.Match)
	if err != nil {
		return Rule{}, err
	}
	switch input.Dimension {
	case DimensionClientIP, DimensionPath, DimensionSite:
	default:
		return Rule{}, fmt.Errorf("unsupported dimension %q", input.Dimension)
	}
	if err := validateLimit(input.Limit); err != nil {
		return Rule{}, err
	}
	if err := validateAction(input.Action, input.Dimension); err != nil {
		return Rule{}, err
	}
	input.Match = match
	return input, nil
}

func compileMatch(input Match) (Match, error) {
	result := Match{Port: input.Port}
	var err error
	if input.Host != "" {
		result.Host, err = normalizeHost(input.Host)
		if err != nil {
			return Match{}, fmt.Errorf("host: %w", err)
		}
	}
	if input.Method != "" {
		if len(input.Method) > MaxMethodBytes || input.Method != strings.ToUpper(input.Method) || !isHTTPToken(input.Method) {
			return Match{}, errors.New("method must be an uppercase HTTP token")
		}
		result.Method = input.Method
	}
	if input.Path != nil {
		path, err := validatePath(*input.Path)
		if err != nil {
			return Match{}, err
		}
		result.Path = &path
	}
	return result, nil
}

func validateLimit(input Limit) error {
	switch input.Algorithm {
	case AlgorithmFixedWindow:
		if input.Requests == 0 || input.Requests > MaxRequests {
			return fmt.Errorf("fixed_window requests must be between 1 and %d", MaxRequests)
		}
		if input.WindowSeconds == 0 || input.WindowSeconds > MaxWindowSeconds {
			return fmt.Errorf("fixed_window window_seconds must be between 1 and %d", MaxWindowSeconds)
		}
		if input.RatePerSecond != 0 || input.Burst != 0 {
			return errors.New("fixed_window must not set leaky bucket fields")
		}
	case AlgorithmLeakyBucket:
		if input.RatePerSecond == 0 || input.RatePerSecond > MaxRatePerSecond {
			return fmt.Errorf("leaky_bucket rate_per_second must be between 1 and %d", MaxRatePerSecond)
		}
		if input.Burst == 0 || input.Burst > MaxBurst {
			return fmt.Errorf("leaky_bucket burst must be between 1 and %d", MaxBurst)
		}
		if input.Requests != 0 || input.WindowSeconds != 0 {
			return errors.New("leaky_bucket must not set fixed window fields")
		}
	default:
		return fmt.Errorf("unsupported limit algorithm %q", input.Algorithm)
	}
	return nil
}

func validateAction(input Action, dimension Dimension) error {
	switch input.Kind {
	case ActionLog, ActionReject429:
		if input.BanSeconds != 0 {
			return errors.New("non-ban action must not set ban_seconds")
		}
	case ActionTemporaryBan:
		if dimension != DimensionClientIP {
			return errors.New("temporary_ban requires the client_ip dimension")
		}
		if input.BanSeconds == 0 || input.BanSeconds > MaxBanSeconds {
			return fmt.Errorf("temporary ban_seconds must be between 1 and %d", MaxBanSeconds)
		}
	default:
		return fmt.Errorf("unsupported action %q", input.Kind)
	}
	return nil
}

func compileCIDRs(field string, values []string, maximum int) ([]CompiledCIDR, error) {
	if len(values) > maximum {
		return nil, invalid("%s count exceeds %d", field, maximum)
	}
	result := make([]CompiledCIDR, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		if len(value) == 0 || len(value) > MaxCIDRBytes || !isASCII(value) || hasControl(value) || strings.Contains(value, "%") {
			return nil, invalid("%s entry %d is invalid", field, index)
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Addr().Is4In6() {
			return nil, invalid("%s entry %d is not a supported CIDR", field, index)
		}
		prefix = prefix.Masked()
		canonical := prefix.String()
		if _, exists := seen[canonical]; exists {
			return nil, invalid("%s contains duplicate CIDR %q", field, canonical)
		}
		seen[canonical] = struct{}{}
		result = append(result, compiledCIDR(prefix))
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].prefix().String() < result[j].prefix().String()
	})
	return result, nil
}

func compiledCIDR(prefix netip.Prefix) CompiledCIDR {
	address := prefix.Addr()
	if address.Is4() {
		value := address.As4()
		return CompiledCIDR{Family: 4, Network: []uint16{uint16(value[0]), uint16(value[1]), uint16(value[2]), uint16(value[3])}, PrefixLength: uint8(prefix.Bits())}
	}
	value := address.As16()
	network := make([]uint16, len(value))
	for index := range value {
		network[index] = uint16(value[index])
	}
	return CompiledCIDR{Family: 6, Network: network, PrefixLength: uint8(prefix.Bits())}
}

func validateIdentifier(value string) error {
	if len(value) == 0 || len(value) > MaxIdentifierBytes {
		return fmt.Errorf("length must be between 1 and %d bytes", MaxIdentifierBytes)
	}
	for index := range value {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || strings.ContainsRune("._:-", rune(character)) {
			continue
		}
		return errors.New("contains an unsupported character")
	}
	return nil
}

func normalizeHost(value string) (string, error) {
	if len(value) == 0 || len(value) > MaxHostBytes || !isASCII(value) || hasControl(value) || strings.ContainsAny(value, ":/\\%") {
		return "", errors.New("must be a bounded ASCII hostname without a port or escape")
	}
	value = strings.ToLower(strings.TrimSuffix(value, "."))
	if value == "" {
		return "", errors.New("hostname is empty")
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("contains an invalid DNS label")
		}
		for index := range label {
			character := label[index]
			if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' {
				continue
			}
			return "", errors.New("contains an invalid DNS label")
		}
	}
	return value, nil
}

func validatePath(input PathMatch) (PathMatch, error) {
	if input.Kind != PathExact && input.Kind != PathPrefix {
		return PathMatch{}, fmt.Errorf("path kind %q is unsupported", input.Kind)
	}
	if len(input.Value) == 0 || len(input.Value) > MaxPathBytes || !utf8.ValidString(input.Value) || hasControl(input.Value) ||
		input.Value[0] != '/' || strings.ContainsAny(input.Value, "\\%?#") || strings.Contains(input.Value, "//") {
		return PathMatch{}, errors.New("path must be canonical UTF-8 without escapes, query, fragment, or backslash")
	}
	for _, segment := range strings.Split(input.Value, "/") {
		if segment == "." || segment == ".." {
			return PathMatch{}, errors.New("path must not contain traversal segments")
		}
	}
	return input, nil
}

func isHTTPToken(value string) bool {
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
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return invalid("multiple JSON values are not allowed")
		}
		return invalid("trailing JSON: %v", err)
	}
	return nil
}

func invalid(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidPolicy, fmt.Sprintf(format, arguments...))
}
