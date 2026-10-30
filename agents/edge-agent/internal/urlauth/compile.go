package urlauth

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
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"unicode"
)

var requiredPolicyFields = []string{
	"schema_version", "policy_version", "tenant_id", "site_id", "algorithm",
	"signature_parameter", "expiration_parameter", "key_id_parameter", "bind_client_ip",
	"max_clock_skew_seconds", "max_validity_seconds", "max_signature_uses",
	"excluded_query_parameters", "trusted_proxies", "current_key",
}

func CompileJSON(raw []byte) ([]byte, *CompiledPolicy, error) {
	if len(raw) == 0 || len(raw) > MaxPolicyBytes {
		return nil, nil, invalid("policy size must be between 1 and %d bytes", MaxPolicyBytes)
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return nil, nil, err
	}
	if err := requireTopLevelFields(raw, requiredPolicyFields); err != nil {
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
		return nil, nil, fmt.Errorf("marshal canonical URL auth policy: %w", err)
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
	if err := validateIdentifier(input.TenantID); err != nil {
		return nil, invalid("tenant_id: %v", err)
	}
	if err := validateIdentifier(input.SiteID); err != nil {
		return nil, invalid("site_id: %v", err)
	}
	if input.Algorithm != AlgorithmHMACSHA256 {
		return nil, invalid("algorithm must be %q", AlgorithmHMACSHA256)
	}
	parameters := []string{input.SignatureParameter, input.ExpirationParameter, input.KeyIDParameter}
	seenParameters := make(map[string]struct{}, len(parameters)+len(input.ExcludedQueryParameters))
	for _, parameter := range parameters {
		if err := validateParameterName(parameter); err != nil {
			return nil, invalid("authentication parameter: %v", err)
		}
		if _, exists := seenParameters[parameter]; exists {
			return nil, invalid("authentication parameter names must be distinct")
		}
		seenParameters[parameter] = struct{}{}
	}
	if input.MaxClockSkewSeconds > MaxClockSkewSeconds {
		return nil, invalid("max_clock_skew_seconds must not exceed %d", MaxClockSkewSeconds)
	}
	if input.MaxValiditySeconds == 0 || input.MaxValiditySeconds > MaxValiditySeconds {
		return nil, invalid("max_validity_seconds must be between 1 and %d", MaxValiditySeconds)
	}
	if input.MaxSignatureUses > MaxSignatureUses {
		return nil, invalid("max_signature_uses must not exceed %d", MaxSignatureUses)
	}
	if input.ExcludedQueryParameters == nil || len(input.ExcludedQueryParameters) > MaxExcludedParams {
		return nil, invalid("excluded_query_parameters must contain at most %d entries", MaxExcludedParams)
	}
	excluded := append(make([]string, 0, len(input.ExcludedQueryParameters)), input.ExcludedQueryParameters...)
	for index, parameter := range excluded {
		if err := validateParameterName(parameter); err != nil {
			return nil, invalid("excluded_query_parameters entry %d: %v", index, err)
		}
		if _, exists := seenParameters[parameter]; exists {
			return nil, invalid("duplicate or authentication query parameter %q in exclusions", parameter)
		}
		seenParameters[parameter] = struct{}{}
	}
	sort.Strings(excluded)
	trusted, err := compileCIDRs(input.TrustedProxies)
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
	return &CompiledPolicy{
		SchemaVersion: input.SchemaVersion, PolicyVersion: input.PolicyVersion,
		TenantID: input.TenantID, SiteID: input.SiteID, Algorithm: input.Algorithm,
		SignatureParameter: input.SignatureParameter, ExpirationParameter: input.ExpirationParameter,
		KeyIDParameter: input.KeyIDParameter, BindClientIP: input.BindClientIP,
		MaxClockSkewSeconds: input.MaxClockSkewSeconds, MaxValiditySeconds: input.MaxValiditySeconds,
		MaxSignatureUses: input.MaxSignatureUses, ExcludedQueryParameters: excluded,
		TrustedProxies: trusted, CurrentKey: current, PreviousKey: previous,
	}, nil
}

func compileKey(field string, input KeyRef) (CompiledKey, error) {
	if err := validateKeyID(input.KeyID); err != nil {
		return CompiledKey{}, invalid("%s key_id: %v", field, err)
	}
	secret, err := readSecureKey(input.KeyFile)
	if err != nil {
		return CompiledKey{}, invalid("%s key_file is not a private regular key file: %v", field, err)
	}
	digest := sha256.Sum256(secret)
	return CompiledKey{KeyID: input.KeyID, KeyFile: input.KeyFile, KeySHA256: hex.EncodeToString(digest[:])}, nil
}

func readSecureKey(path string) ([]byte, error) {
	if len(path) == 0 || len(path) > MaxKeyFilePathBytes || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) || hasControl(path) {
		return nil, errors.New("invalid absolute path")
	}
	for directory := filepath.Dir(path); ; directory = filepath.Dir(directory) {
		info, err := os.Lstat(directory)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return nil, errors.New("inspect ancestor failed")
			}
		} else if info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("ancestor directory must not be a symlink")
		}
		if parent := filepath.Dir(directory); parent == directory {
			break
		}
	}
	parentInfo, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || parentInfo.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("parent directory permissions must be private")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("open failed")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return nil, errors.New("mode must be 0600")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return nil, errors.New("key file must have exactly one link")
	}
	secret, err := io.ReadAll(io.LimitReader(file, MaxKeyBytes+1))
	if err != nil || len(secret) < MinKeyBytes || len(secret) > MaxKeyBytes {
		return nil, fmt.Errorf("key length must be between %d and %d bytes", MinKeyBytes, MaxKeyBytes)
	}
	return secret, nil
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

func validateKeyID(value string) error {
	if len(value) == 0 || len(value) > MaxKeyIDBytes {
		return fmt.Errorf("length must be between 1 and %d bytes", MaxKeyIDBytes)
	}
	return validateIdentifier(value)
}

func validateParameterName(value string) error {
	if len(value) == 0 || len(value) > MaxParameterBytes || !isASCII(value) {
		return fmt.Errorf("must be between 1 and %d ASCII bytes", MaxParameterBytes)
	}
	for index := range value {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || strings.ContainsRune("_.~-", rune(character)) {
			continue
		}
		return errors.New("contains a character outside the URL parameter allowlist")
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
	if token, err := decoder.Token(); err != io.EOF {
		return invalid("unexpected trailing JSON token %v: %v", token, err)
	}
	return nil
}

func requireTopLevelFields(raw []byte, fields []string) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return invalid("decode policy object: %v", err)
	}
	for _, field := range fields {
		if _, exists := object[field]; !exists {
			return invalid("required field %q is missing", field)
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
