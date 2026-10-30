package urlauth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type queryPair struct {
	name  string
	value string
}

func LoadCompiledJSON(raw []byte) (*CompiledPolicy, error) {
	if len(raw) == 0 || len(raw) > MaxPolicyBytes {
		return nil, invalid("compiled policy size is invalid")
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var policy CompiledPolicy
	if err := decoder.Decode(&policy); err != nil {
		return nil, invalid("decode compiled policy: %v", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, err
	}
	if err := validateCompiledPolicy(&policy); err != nil {
		return nil, err
	}
	return &policy, nil
}

func SignTargetAt(policy *CompiledPolicy, method, target, keyID, clientIP string, expiresAt, now time.Time) (string, error) {
	if err := validateCompiledPolicy(policy); err != nil {
		return "", err
	}
	if expiresAt.Unix() <= now.Unix() || expiresAt.Unix() > now.Unix()+int64(policy.MaxValiditySeconds) {
		return "", errors.New("expiration must be in the configured future validity window")
	}
	pairs, path, err := parseTarget(target)
	if err != nil {
		return "", err
	}
	for _, pair := range pairs {
		if pair.name == policy.SignatureParameter || pair.name == policy.ExpirationParameter || pair.name == policy.KeyIDParameter {
			return "", errors.New("target must not already contain URL authentication parameters")
		}
	}
	key := &policy.CurrentKey
	if keyID != "" && keyID != key.KeyID {
		if policy.PreviousKey == nil || keyID != policy.PreviousKey.KeyID {
			return "", errors.New("unknown key id")
		}
		key = policy.PreviousKey
	}
	secret, err := loadCompiledKey(*key)
	if err != nil {
		return "", err
	}
	canonicalIP, err := canonicalClientIP(policy.BindClientIP, clientIP)
	if err != nil {
		return "", err
	}
	expiration := strconv.FormatInt(expiresAt.Unix(), 10)
	canonical, err := buildCanonical(policy, method, path, pairs, expiration, key.KeyID, canonicalIP)
	if err != nil {
		return "", err
	}
	digest := hmac.New(sha256.New, secret)
	_, _ = digest.Write([]byte(canonical))
	signature := hex.EncodeToString(digest.Sum(nil))
	pairs = append(pairs,
		queryPair{name: policy.ExpirationParameter, value: expiration},
		queryPair{name: policy.KeyIDParameter, value: key.KeyID},
		queryPair{name: policy.SignatureParameter, value: signature},
	)
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].name != pairs[j].name {
			return pairs[i].name < pairs[j].name
		}
		return pairs[i].value < pairs[j].value
	})
	return path + "?" + encodePairs(pairs), nil
}

func buildCanonical(policy *CompiledPolicy, method, path string, pairs []queryPair, expiration, keyID, clientIP string) (string, error) {
	if method == "" || method != strings.ToUpper(method) || len(method) > 32 {
		return "", errors.New("method must be an uppercase HTTP token")
	}
	for index := range method {
		character := method[index]
		if character < 0x21 || character > 0x7e || strings.ContainsRune("()<>@,;:\\\"/[]?={} \t", rune(character)) {
			return "", errors.New("method must be an uppercase HTTP token")
		}
	}
	if err := validateRequestPath(path); err != nil {
		return "", err
	}
	excluded := make(map[string]struct{}, len(policy.ExcludedQueryParameters)+3)
	for _, name := range policy.ExcludedQueryParameters {
		excluded[name] = struct{}{}
	}
	excluded[policy.SignatureParameter] = struct{}{}
	excluded[policy.ExpirationParameter] = struct{}{}
	excluded[policy.KeyIDParameter] = struct{}{}
	canonicalPairs := make([]queryPair, 0, len(pairs))
	for _, pair := range pairs {
		if _, skip := excluded[pair.name]; !skip {
			canonicalPairs = append(canonicalPairs, pair)
		}
	}
	sort.Slice(canonicalPairs, func(i, j int) bool {
		if canonicalPairs[i].name != canonicalPairs[j].name {
			return canonicalPairs[i].name < canonicalPairs[j].name
		}
		return canonicalPairs[i].value < canonicalPairs[j].value
	})
	return "CDNCA-URL-AUTH/1\n" +
		"tenant_id=" + percentEncode(policy.TenantID) + "\n" +
		"site_id=" + percentEncode(policy.SiteID) + "\n" +
		"method=" + method + "\n" +
		"path=" + percentEncode(path) + "\n" +
		"query=" + encodePairs(canonicalPairs) + "\n" +
		"expires=" + expiration + "\n" +
		"key_id=" + percentEncode(keyID) + "\n" +
		"client_ip=" + percentEncode(clientIP) + "\n", nil
}

func parseTarget(target string) ([]queryPair, string, error) {
	if len(target) == 0 || len(target) > MaxURIBytes || strings.Contains(target, "#") || containsControlBytes(target) {
		return nil, "", errors.New("target URI is invalid or too long")
	}
	path, rawQuery, hasQuery := strings.Cut(target, "?")
	if err := validateRequestPath(path); err != nil {
		return nil, "", err
	}
	if !hasQuery {
		return []queryPair{}, path, nil
	}
	pairs, err := parseRawQuery(rawQuery)
	return pairs, path, err
}

func parseRawQuery(raw string) ([]queryPair, error) {
	if len(raw) == 0 || len(raw) > MaxQueryBytes {
		return nil, errors.New("query string is empty or too long")
	}
	parts := strings.Split(raw, "&")
	if len(parts) > MaxQueryParameters {
		return nil, errors.New("too many query parameters")
	}
	pairs := make([]queryPair, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		if part == "" {
			return nil, errors.New("empty query parameter")
		}
		rawName, rawValue, _ := strings.Cut(part, "=")
		name, err := url.QueryUnescape(rawName)
		if err != nil || validateParameterName(name) != nil {
			return nil, errors.New("invalid query parameter name")
		}
		value, err := url.QueryUnescape(rawValue)
		if err != nil || len(value) > MaxQueryValueBytes || containsControlBytes(value) {
			return nil, errors.New("invalid query parameter value")
		}
		if _, exists := seen[name]; exists {
			return nil, fmt.Errorf("duplicate query parameter %q", name)
		}
		seen[name] = struct{}{}
		pairs = append(pairs, queryPair{name: name, value: value})
	}
	return pairs, nil
}

func validateRequestPath(path string) error {
	if len(path) == 0 || len(path) > MaxPathBytes || path[0] != '/' || !isASCII(path) || containsControlBytes(path) || strings.ContainsAny(path, "\\%?#") || strings.Contains(path, "//") {
		return errors.New("path must be a canonical unescaped ASCII absolute path")
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." {
			return errors.New("path must not contain traversal segments")
		}
	}
	return nil
}

func canonicalClientIP(required bool, value string) (string, error) {
	if !required {
		if value != "" {
			return "", errors.New("client IP was supplied for an unbound policy")
		}
		return "", nil
	}
	address, err := netip.ParseAddr(value)
	if err != nil || address.Zone() != "" || address.Is4In6() {
		return "", errors.New("client IP is invalid")
	}
	if address.Is4() {
		return "4:" + address.String(), nil
	}
	bytes := address.As16()
	return "6:" + hex.EncodeToString(bytes[:]), nil
}

func loadCompiledKey(key CompiledKey) ([]byte, error) {
	secret, err := readSecureKey(key.KeyFile)
	if err != nil {
		return nil, errors.New("signing key is unavailable")
	}
	digest := sha256.Sum256(secret)
	expected, err := hex.DecodeString(key.KeySHA256)
	if err != nil || len(expected) != sha256.Size || !hmac.Equal(digest[:], expected) {
		return nil, errors.New("signing key digest mismatch")
	}
	return secret, nil
}

func validateCompiledPolicy(policy *CompiledPolicy) error {
	if policy == nil || policy.SchemaVersion != SchemaVersion || policy.PolicyVersion == 0 || policy.PolicyVersion > MaxPolicyVersion ||
		policy.Algorithm != AlgorithmHMACSHA256 || validateIdentifier(policy.TenantID) != nil || validateIdentifier(policy.SiteID) != nil {
		return invalid("compiled policy envelope is invalid")
	}
	parameters := []string{policy.SignatureParameter, policy.ExpirationParameter, policy.KeyIDParameter}
	seen := make(map[string]struct{}, len(parameters)+len(policy.ExcludedQueryParameters))
	for _, parameter := range parameters {
		if validateParameterName(parameter) != nil {
			return invalid("compiled authentication parameter is invalid")
		}
		if _, exists := seen[parameter]; exists {
			return invalid("compiled authentication parameters are not distinct")
		}
		seen[parameter] = struct{}{}
	}
	if policy.MaxClockSkewSeconds > MaxClockSkewSeconds || policy.MaxValiditySeconds == 0 || policy.MaxValiditySeconds > MaxValiditySeconds || policy.MaxSignatureUses > MaxSignatureUses {
		return invalid("compiled time or replay bounds are invalid")
	}
	if policy.ExcludedQueryParameters == nil || len(policy.ExcludedQueryParameters) > MaxExcludedParams {
		return invalid("compiled exclusions are invalid")
	}
	previous := ""
	for _, parameter := range policy.ExcludedQueryParameters {
		if validateParameterName(parameter) != nil || parameter <= previous {
			return invalid("compiled exclusions are not strictly sorted")
		}
		if _, exists := seen[parameter]; exists {
			return invalid("compiled exclusion collides with another parameter")
		}
		seen[parameter] = struct{}{}
		previous = parameter
	}
	if len(policy.TrustedProxies) > MaxProxyCIDRs {
		return invalid("compiled trusted proxy list is too large")
	}
	previousCIDR := ""
	for _, cidr := range policy.TrustedProxies {
		if (cidr.Family != 4 && cidr.Family != 6) || len(cidr.Network) != map[uint8]int{4: 4, 6: 16}[cidr.Family] || int(cidr.PrefixLength) > map[uint8]int{4: 32, 6: 128}[cidr.Family] {
			return invalid("compiled trusted proxy CIDR is invalid")
		}
		for _, value := range cidr.Network {
			if value > 255 {
				return invalid("compiled trusted proxy byte is invalid")
			}
		}
		name := cidr.prefix().String()
		if name <= previousCIDR || cidr.prefix() != cidr.prefix().Masked() {
			return invalid("compiled trusted proxies are not canonical")
		}
		previousCIDR = name
	}
	if err := validateCompiledKey(policy.CurrentKey); err != nil {
		return err
	}
	if policy.PreviousKey != nil {
		if err := validateCompiledKey(*policy.PreviousKey); err != nil {
			return err
		}
		if policy.PreviousKey.KeyID == policy.CurrentKey.KeyID || policy.PreviousKey.KeyFile == policy.CurrentKey.KeyFile || policy.PreviousKey.KeySHA256 == policy.CurrentKey.KeySHA256 {
			return invalid("compiled previous key is not distinct")
		}
	}
	return nil
}

func validateCompiledKey(key CompiledKey) error {
	if validateKeyID(key.KeyID) != nil || len(key.KeySHA256) != sha256.Size*2 {
		return invalid("compiled key metadata is invalid")
	}
	if _, err := hex.DecodeString(key.KeySHA256); err != nil || key.KeySHA256 != strings.ToLower(key.KeySHA256) {
		return invalid("compiled key digest is invalid")
	}
	secret, err := readSecureKey(key.KeyFile)
	if err != nil {
		return invalid("compiled key file is unavailable")
	}
	digest := sha256.Sum256(secret)
	expected, err := hex.DecodeString(key.KeySHA256)
	if err != nil || !hmac.Equal(digest[:], expected) {
		return invalid("compiled key digest does not match key file")
	}
	return nil
}

func encodePairs(pairs []queryPair) string {
	encoded := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		encoded = append(encoded, percentEncode(pair.name)+"="+percentEncode(pair.value))
	}
	return strings.Join(encoded, "&")
}

func percentEncode(value string) string {
	const hexadecimal = "0123456789ABCDEF"
	var result strings.Builder
	for index := range value {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || strings.ContainsRune("-._~", rune(character)) {
			result.WriteByte(character)
			continue
		}
		result.WriteByte('%')
		result.WriteByte(hexadecimal[character>>4])
		result.WriteByte(hexadecimal[character&0x0f])
	}
	return result.String()
}

func containsControlBytes(value string) bool {
	for index := range value {
		if value[index] < 0x20 || value[index] == 0x7f {
			return true
		}
	}
	return false
}
