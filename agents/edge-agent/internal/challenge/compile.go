package challenge

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	pathpkg "path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"unicode"

	"golang.org/x/sys/unix"
)

var requiredPolicyFields = []string{
	"schema_version", "policy_version", "algorithm", "cookie_name", "trusted_proxies", "bypass_routes", "current_key", "rules",
}

var requiredRuleFields = []string{
	"rule_id", "priority", "tenant_id", "site_id", "host", "mode", "min_delay_seconds",
	"challenge_ttl_seconds", "pass_ttl_seconds", "clock_skew_seconds", "attempts_per_nonce",
	"failure_window_seconds", "max_failures_per_window", "ip_binding", "bind_user_agent",
}

func CompileJSON(raw []byte) ([]byte, *CompiledPolicy, error) {
	if len(raw) == 0 || len(raw) > MaxPolicyBytes {
		return nil, nil, invalid("policy size must be between 1 and %d bytes", MaxPolicyBytes)
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return nil, nil, err
	}
	if err := requireFields(raw); err != nil {
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
		return nil, nil, fmt.Errorf("marshal canonical challenge policy: %w", err)
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
	if input.Algorithm != AlgorithmHMACSHA256 {
		return nil, invalid("algorithm must be %q", AlgorithmHMACSHA256)
	}
	if err := validateCookieName(input.CookieName); err != nil {
		return nil, invalid("cookie_name: %v", err)
	}
	if len(input.Rules) == 0 || len(input.Rules) > MaxRules {
		return nil, invalid("rules must contain between 1 and %d entries", MaxRules)
	}
	trusted, err := compileCIDRs(input.TrustedProxies)
	if err != nil {
		return nil, err
	}
	bypassRoutes, err := compileBypassRoutes(input.BypassRoutes)
	if err != nil {
		return nil, err
	}
	current, err := compileKey("current_key", input.CurrentKey)
	if err != nil {
		return nil, err
	}
	var previous *CompiledKey
	if input.PreviousKey != nil {
		value, err := compileKey("previous_key", *input.PreviousKey)
		if err != nil {
			return nil, err
		}
		if value.KeyID == current.KeyID || value.KeyFile == current.KeyFile || value.KeySHA256 == current.KeySHA256 {
			return nil, invalid("previous_key must use a distinct id, file, and secret")
		}
		previous = &value
	}
	rules := make([]Rule, 0, len(input.Rules))
	ids := make(map[string]struct{}, len(input.Rules))
	scopes := make(map[string]struct{}, len(input.Rules))
	for index, rule := range input.Rules {
		compiled, err := compileRule(rule)
		if err != nil {
			return nil, invalid("rule %d: %v", index, err)
		}
		if _, exists := ids[compiled.RuleID]; exists {
			return nil, invalid("duplicate rule_id %q", compiled.RuleID)
		}
		ids[compiled.RuleID] = struct{}{}
		scope := compiled.TenantID + "\x00" + compiled.SiteID + "\x00" + compiled.Host
		if _, exists := scopes[scope]; exists {
			return nil, invalid("duplicate tenant/site/host challenge scope")
		}
		scopes[scope] = struct{}{}
		rules = append(rules, compiled)
	}
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Priority != rules[j].Priority {
			return rules[i].Priority < rules[j].Priority
		}
		return rules[i].RuleID < rules[j].RuleID
	})
	return &CompiledPolicy{
		SchemaVersion: input.SchemaVersion, PolicyVersion: input.PolicyVersion, Algorithm: input.Algorithm,
		CookieName: input.CookieName, TrustedProxies: trusted, BypassRoutes: bypassRoutes,
		CurrentKey: current, PreviousKey: previous, Rules: rules,
	}, nil
}

func compileRule(input Rule) (Rule, error) {
	for name, value := range map[string]string{
		"rule_id": input.RuleID, "tenant_id": input.TenantID, "site_id": input.SiteID,
	} {
		if err := validateIdentifier(value, MaxIdentifierBytes); err != nil {
			return Rule{}, fmt.Errorf("%s: %w", name, err)
		}
	}
	host, err := normalizeHost(input.Host)
	if err != nil {
		return Rule{}, fmt.Errorf("host: %w", err)
	}
	input.Host = host
	switch input.Mode {
	case ModeDelay:
		if input.MinDelaySeconds < MinDelaySeconds || input.MinDelaySeconds > MaxDelaySeconds {
			return Rule{}, fmt.Errorf("delay min_delay_seconds must be between %d and %d", MinDelaySeconds, MaxDelaySeconds)
		}
	case ModeClick, ModeSlider, ModeCaptcha, ModeExternal:
		if input.MinDelaySeconds != 0 {
			return Rule{}, fmt.Errorf("%s min_delay_seconds must be zero", input.Mode)
		}
	default:
		return Rule{}, fmt.Errorf("unsupported mode %q", input.Mode)
	}
	if input.Mode == ModeExternal {
		if input.ExternalProvider == nil ||
			(input.ExternalProvider.Provider != ProviderTencent && input.ExternalProvider.Provider != ProviderGeetestV4) ||
			validateIdentifier(input.ExternalProvider.AppID, MaxIdentifierBytes) != nil {
			return Rule{}, fmt.Errorf("external_provider must bind a supported provider and app_id")
		}
	} else if input.ExternalProvider != nil {
		return Rule{}, fmt.Errorf("external_provider is only valid for external mode")
	}
	if input.ChallengeTTLSeconds < MinChallengeTTLSeconds || input.ChallengeTTLSeconds > MaxChallengeTTLSeconds ||
		input.ChallengeTTLSeconds <= input.MinDelaySeconds+input.ClockSkewSeconds {
		return Rule{}, fmt.Errorf("challenge_ttl_seconds must be within bounds and exceed delay plus clock skew")
	}
	if input.PassTTLSeconds == 0 || input.PassTTLSeconds > MaxPassTTLSeconds {
		return Rule{}, fmt.Errorf("pass_ttl_seconds must be between 1 and %d", MaxPassTTLSeconds)
	}
	if input.ClockSkewSeconds > MaxClockSkewSeconds {
		return Rule{}, fmt.Errorf("clock_skew_seconds must not exceed %d", MaxClockSkewSeconds)
	}
	if input.AttemptsPerNonce != RequiredAttemptsPerNonce {
		return Rule{}, fmt.Errorf("attempts_per_nonce must be %d", RequiredAttemptsPerNonce)
	}
	if input.FailureWindowSeconds == 0 || input.FailureWindowSeconds > MaxFailureWindowSeconds {
		return Rule{}, fmt.Errorf("failure_window_seconds must be between 1 and %d", MaxFailureWindowSeconds)
	}
	if input.MaxFailuresPerWindow == 0 || input.MaxFailuresPerWindow > MaxFailuresPerWindow {
		return Rule{}, fmt.Errorf("max_failures_per_window must be between 1 and %d", MaxFailuresPerWindow)
	}
	if input.IPBinding != IPBindingNone && input.IPBinding != IPBindingExact {
		return Rule{}, fmt.Errorf("unsupported ip_binding %q", input.IPBinding)
	}
	return input, nil
}

func compileBypassRoutes(values []BypassRoute) ([]BypassRoute, error) {
	if values == nil || len(values) > MaxBypassRoutes {
		return nil, invalid("bypass_routes must contain at most %d entries", MaxBypassRoutes)
	}
	result := append([]BypassRoute{}, values...)
	seen := make(map[string]struct{}, len(result))
	for index, route := range result {
		if route.Kind != BypassExact && route.Kind != BypassPrefix {
			return nil, invalid("bypass_routes entry %d has unsupported kind %q", index, route.Kind)
		}
		if !validBypassPath(route.Path, route.Kind) {
			return nil, invalid("bypass_routes entry %d has invalid path", index)
		}
		if _, exists := seen[route.Path]; exists {
			return nil, invalid("bypass_routes contains duplicate path %q", route.Path)
		}
		seen[route.Path] = struct{}{}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Path != result[j].Path {
			return result[i].Path < result[j].Path
		}
		return result[i].Kind < result[j].Kind
	})
	return result, nil
}

func validBypassPath(value string, kind BypassKind) bool {
	if len(value) == 0 || len(value) > MaxBypassPathBytes || !isASCII(value) || hasControl(value) ||
		value[0] != '/' || strings.HasPrefix(value, "//") || strings.ContainsAny(value, "\\?#%") {
		return false
	}
	if kind == BypassPrefix {
		if value == "/" || !strings.HasSuffix(value, "/") {
			return false
		}
		return pathpkg.Clean(strings.TrimSuffix(value, "/")) == strings.TrimSuffix(value, "/")
	}
	return pathpkg.Clean(value) == value
}

func compileKey(field string, input KeyRef) (CompiledKey, error) {
	if err := validateIdentifier(input.KeyID, MaxKeyIDBytes); err != nil {
		return CompiledKey{}, invalid("%s key_id: %v", field, err)
	}
	secret, err := readSecureKey(input.KeyFile)
	if err != nil {
		return CompiledKey{}, invalid("%s key_file is not a private independent key file: %v", field, err)
	}
	digest := sha256.Sum256(secret)
	return CompiledKey{KeyID: input.KeyID, KeyFile: input.KeyFile, KeySHA256: hex.EncodeToString(digest[:])}, nil
}

func readSecureKey(path string) ([]byte, error) {
	if len(path) == 0 || len(path) > MaxKeyFilePathBytes || !filepath.IsAbs(path) || filepath.Clean(path) != path ||
		path == string(filepath.Separator) || hasControl(path) {
		return nil, errors.New("invalid absolute path")
	}
	rootFD, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("inspect ancestor failed")
	}
	root := os.NewFile(uintptr(rootFD), string(filepath.Separator))
	if root == nil {
		_ = unix.Close(rootFD)
		return nil, errors.New("inspect ancestor failed")
	}
	components := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	return readSecureKeyAt(root, components)
}

func readSecureKeyAt(directory *os.File, components []string) ([]byte, error) {
	defer func() { _ = directory.Close() }()
	for _, component := range components[:len(components)-1] {
		fd, err := unix.Openat(int(directory.Fd()), component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			if errors.Is(err, unix.ELOOP) {
				return nil, errors.New("ancestor directory must not be a symlink")
			}
			return nil, errors.New("inspect ancestor failed")
		}
		next := os.NewFile(uintptr(fd), component)
		if next == nil {
			_ = unix.Close(fd)
			return nil, errors.New("inspect ancestor failed")
		}
		_ = directory.Close()
		directory = next
	}
	parent, err := directory.Stat()
	if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || parent.Mode().Perm() != 0o700 {
		return nil, errors.New("parent directory mode must be 0700")
	}
	fd, err := unix.Openat(int(directory.Fd()), components[len(components)-1], unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("open failed")
	}
	file := os.NewFile(uintptr(fd), components[len(components)-1])
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open failed")
	}
	defer file.Close()
	info, err := file.Stat()
	stat, ok := infoSys(info)
	if err != nil || !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || stat.Nlink != 1 {
		return nil, errors.New("key must be a 0600 regular single-linked file")
	}
	secret, err := io.ReadAll(io.LimitReader(file, MaxKeyBytes+1))
	if err != nil || len(secret) < MinKeyBytes || len(secret) > MaxKeyBytes {
		return nil, fmt.Errorf("key length must be between %d and %d bytes", MinKeyBytes, MaxKeyBytes)
	}
	return secret, nil
}

func infoSys(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return stat, ok
}

func compileCIDRs(values []string) ([]CompiledCIDR, error) {
	if values == nil || len(values) > MaxProxyCIDRs {
		return nil, invalid("trusted_proxies must contain at most %d entries", MaxProxyCIDRs)
	}
	result := make([]CompiledCIDR, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		if len(value) == 0 || len(value) > MaxCIDRBytes || !isASCII(value) || hasControl(value) || strings.Contains(value, "%") {
			return nil, invalid("trusted_proxies entry %d is invalid", index)
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Addr().Is4In6() {
			return nil, invalid("trusted_proxies entry %d is not a supported CIDR", index)
		}
		prefix = prefix.Masked()
		canonical := prefix.String()
		if _, exists := seen[canonical]; exists {
			return nil, invalid("trusted_proxies contains duplicate CIDR %q", canonical)
		}
		seen[canonical] = struct{}{}
		result = append(result, compiledCIDR(prefix))
	}
	sort.Slice(result, func(i, j int) bool { return result[i].prefix().String() < result[j].prefix().String() })
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

func normalizeHost(value string) (string, error) {
	if len(value) == 0 || len(value) > MaxHostBytes || !isASCII(value) || hasControl(value) || strings.ContainsAny(value, ":/\\%") {
		return "", errors.New("must be a bounded ASCII hostname without port or escape")
	}
	value = strings.ToLower(strings.TrimSuffix(value, "."))
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

func validateCookieName(value string) error {
	if len(value) <= len("__Host-") || len(value) > MaxCookieNameBytes || !strings.HasPrefix(value, "__Host-") {
		return fmt.Errorf("must use the __Host- prefix and contain at most %d bytes", MaxCookieNameBytes)
	}
	for index := range value {
		character := value[index]
		if character <= 0x20 || character >= 0x7f || strings.ContainsRune("()<>@,;:\\\"/[]?={} ", rune(character)) {
			return errors.New("contains an invalid cookie-name character")
		}
	}
	return nil
}

func validateIdentifier(value string, maximum int) error {
	if len(value) == 0 || len(value) > maximum {
		return fmt.Errorf("length must be between 1 and %d bytes", maximum)
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
			if _, err := decoder.Token(); err != nil {
				return invalid("decode object close: %v", err)
			}
			return nil
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			if _, err := decoder.Token(); err != nil {
				return invalid("decode array close: %v", err)
			}
			return nil
		default:
			return invalid("unexpected JSON delimiter %q", delimiter)
		}
	}
	if err := walk(); err != nil {
		return err
	}
	if token, err := decoder.Token(); err != io.EOF {
		return invalid("unexpected trailing JSON token %v: %v", token, err)
	}
	return nil
}

func requireFields(raw []byte) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return invalid("decode policy object: %v", err)
	}
	for _, field := range requiredPolicyFields {
		if _, exists := object[field]; !exists {
			return invalid("required field %q is missing", field)
		}
	}
	for _, keyField := range []string{"current_key", "previous_key"} {
		rawKey, exists := object[keyField]
		if !exists || bytes.Equal(rawKey, []byte("null")) {
			continue
		}
		var key map[string]json.RawMessage
		if err := json.Unmarshal(rawKey, &key); err != nil {
			return invalid("%s is invalid", keyField)
		}
		for _, field := range []string{"key_id", "key_file"} {
			if _, exists := key[field]; !exists {
				return invalid("%s required field %q is missing", keyField, field)
			}
		}
	}
	var rules []map[string]json.RawMessage
	if err := json.Unmarshal(object["rules"], &rules); err != nil {
		return invalid("rules is invalid")
	}
	for index, rule := range rules {
		for _, field := range requiredRuleFields {
			if _, exists := rule[field]; !exists {
				return invalid("rule %d required field %q is missing", index, field)
			}
		}
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return invalid("policy contains trailing JSON")
		}
		return invalid("decode trailing data: %v", err)
	}
	return nil
}

func invalid(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidPolicy, fmt.Sprintf(format, arguments...))
}
