package originauthcontrol

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	maxCursorBytes  = 512
	maxSafeRevision = int64(1<<53 - 1)
)

var (
	metadataPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	idempotencyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	scopePattern       = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])$`)
	bucketPattern      = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{1,61}[a-z0-9])$`)
	cosBucketPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*-[0-9]+$`)
)

type pageCursor struct {
	CreatedAt time.Time `json:"created_at"`
	ID        uuid.UUID `json:"id"`
}

func validActor(actor Actor) bool {
	return actor.UserID != uuid.Nil && actor.ScopeID != uuid.Nil &&
		(actor.ScopeKind == "platform" || actor.ScopeKind == "tenant")
}

func validateTarget(actor Actor, target uuid.UUID) error {
	if !validActor(actor) || target == uuid.Nil {
		return ErrInvalidInput
	}
	return nil
}

func validWriteMetadata(metadata WriteMetadata) bool {
	return idempotencyPattern.MatchString(metadata.IdempotencyKey) &&
		metadataPattern.MatchString(metadata.RequestID) && metadataPattern.MatchString(metadata.TraceID)
}

func validateCredentialInput(provider, name string, secret CredentialSecret, now time.Time) error {
	if provider != ProviderS3 && provider != ProviderOSS && provider != ProviderCOS {
		return ErrValidation
	}
	if !validText(name, 1, 128) || strings.TrimSpace(name) != name ||
		!validSecret(secret.AccessKeyID, 256) || !validSecret(secret.SecretAccessKey, 512) ||
		(secret.SessionToken != "" && !validSecret(secret.SessionToken, 4096)) {
		return ErrValidation
	}
	notBefore, expiresAt := storeTime(secret.NotBefore), storeTime(secret.ExpiresAt)
	if secret.NotBefore.Location() == nil || secret.ExpiresAt.Location() == nil ||
		notBefore.Before(now.Add(-24*time.Hour)) || notBefore.After(now.Add(30*24*time.Hour)) ||
		!expiresAt.After(notBefore) || !expiresAt.After(now) || expiresAt.After(now.Add(370*24*time.Hour)) {
		return ErrValidation
	}
	return nil
}

func validateRuleConfig(config *RuleConfig, egressPolicies map[string]map[string]struct{}) error {
	if config == nil || config.SignatureTTLSeconds < 1 || config.SignatureTTLSeconds > 3600 ||
		!scopePattern.MatchString(config.Region) || !scopePattern.MatchString(config.Service) {
		return ErrValidation
	}
	endpoint, host, err := normalizeEndpoint(config.Endpoint)
	if err != nil {
		return err
	}
	prefix, err := normalizePathPrefix(config.PathPrefix)
	if err != nil {
		return err
	}
	config.Endpoint, config.PathPrefix = endpoint, prefix
	config.Region, config.Service = strings.ToLower(config.Region), strings.ToLower(config.Service)
	config.Bucket = strings.ToLower(config.Bucket)
	switch config.Provider {
	case ProviderS3:
		if config.Algorithm != AlgorithmS3 || config.Service != "s3" || config.Bucket != "" {
			return ErrValidation
		}
		if officialS3Host(host, config.Region) {
			if config.EgressPolicyReference != "" {
				return ErrValidation
			}
		} else if !egressAllows(egressPolicies, config.EgressPolicyReference, host) {
			return ErrValidation
		}
	case ProviderOSS:
		if config.Algorithm != AlgorithmOSS || config.Service != "oss" ||
			!knownOfficialRegion(ProviderOSS, config.Region) || !validBucket(config.Bucket) ||
			host != config.Bucket+".oss-"+config.Region+".aliyuncs.com" || config.EgressPolicyReference != "" {
			return ErrValidation
		}
	case ProviderCOS:
		suffix := ".cos." + config.Region + ".myqcloud.com"
		prefix := strings.TrimSuffix(host, suffix)
		if config.Algorithm != AlgorithmCOS || config.Service != "cos" || config.Bucket != "" ||
			!knownOfficialRegion(ProviderCOS, config.Region) || !strings.HasSuffix(host, suffix) ||
			!cosBucketPattern.MatchString(prefix) || config.EgressPolicyReference != "" {
			return ErrValidation
		}
	default:
		return ErrValidation
	}
	if config.CurrentCredential.CredentialID == uuid.Nil || config.CurrentCredential.Revision < 1 ||
		config.CurrentCredential.Revision > maxSafeRevision {
		return ErrValidation
	}
	if config.PreviousCredential == nil {
		if config.ActivateCurrentAt != nil {
			return ErrValidation
		}
	} else if config.PreviousCredential.CredentialID == uuid.Nil || config.PreviousCredential.Revision < 1 ||
		config.PreviousCredential.Revision > maxSafeRevision || config.ActivateCurrentAt == nil ||
		*config.PreviousCredential == config.CurrentCredential {
		return ErrValidation
	}
	return nil
}

func normalizeEndpoint(raw string) (string, string, error) {
	if raw == "" || raw != strings.ToLower(raw) || len(raw) > 512 || hasControl(raw) {
		return "", "", ErrValidation
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.RawQuery != "" ||
		parsed.Fragment != "" || parsed.Path != "" || parsed.RawPath != "" {
		return "", "", ErrValidation
	}
	host := parsed.Hostname()
	if parsed.Port() != "" && parsed.Port() != "443" || !validDomain(host) || net.ParseIP(host) != nil ||
		host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") ||
		strings.HasSuffix(host, ".internal") || host == "metadata.google.internal" {
		return "", "", ErrValidation
	}
	return "https://" + host, host, nil
}

func normalizePathPrefix(raw string) (string, error) {
	if len(raw) < 1 || len(raw) > 2048 || raw[0] != '/' || raw[len(raw)-1] != '/' ||
		hasControl(raw) || strings.ContainsAny(raw, `?#\%`) || strings.Contains(raw, "//") || path.Clean(raw) != strings.TrimSuffix(raw, "/") {
		if raw != "/" {
			return "", ErrValidation
		}
	}
	if raw == "/" {
		return raw, nil
	}
	for _, segment := range strings.Split(strings.Trim(raw, "/"), "/") {
		if segment == "" || segment == "." || segment == ".." {
			return "", ErrValidation
		}
	}
	return raw, nil
}

func officialS3Host(host, region string) bool {
	suffix := ".s3." + region + ".amazonaws.com"
	if !strings.HasSuffix(host, suffix) {
		return false
	}
	return validBucket(strings.TrimSuffix(host, suffix))
}

func egressAllows(policies map[string]map[string]struct{}, reference, host string) bool {
	if !metadataPattern.MatchString(reference) {
		return false
	}
	hosts, found := policies[reference]
	if !found {
		return false
	}
	_, found = hosts[host]
	return found
}

func normalizeEgressPolicies(input map[string][]string) (map[string]map[string]struct{}, error) {
	result := make(map[string]map[string]struct{}, len(input))
	for reference, hosts := range input {
		if !metadataPattern.MatchString(reference) || len(hosts) == 0 || len(hosts) > 256 {
			return nil, ErrInvalidInput
		}
		allowed := make(map[string]struct{}, len(hosts))
		for _, raw := range hosts {
			if raw != strings.ToLower(raw) || !validDomain(raw) || net.ParseIP(raw) != nil ||
				raw == "localhost" || strings.HasSuffix(raw, ".localhost") || strings.HasSuffix(raw, ".local") ||
				strings.HasSuffix(raw, ".internal") {
				return nil, ErrInvalidInput
			}
			allowed[raw] = struct{}{}
		}
		result[reference] = allowed
	}
	return result, nil
}

func validBucket(value string) bool {
	return len(value) >= 3 && len(value) <= 63 && bucketPattern.MatchString(value) &&
		!strings.Contains(value, "..") && net.ParseIP(value) == nil
}

func validDomain(value string) bool {
	if value == "" || len(value) > 253 || value != strings.ToLower(value) || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func knownOfficialRegion(provider, region string) bool {
	regions := map[string][]string{
		ProviderOSS: {
			"cn-hangzhou", "cn-shanghai", "cn-nanjing", "cn-fuzhou", "cn-wuhan-lr", "cn-qingdao",
			"cn-beijing", "cn-zhangjiakou", "cn-huhehaote", "cn-wulanchabu", "cn-shenzhen", "cn-heyuan",
			"cn-guangzhou", "cn-chengdu", "cn-hongkong", "cn-zhongwei", "cn-beijing-finance-1",
			"cn-hangzhou-finance", "cn-shanghai-finance-1", "cn-shenzhen-finance-1", "cn-north-2-gov-1",
			"us-west-1", "us-east-1", "ap-northeast-1", "ap-northeast-2", "ap-southeast-1",
			"ap-southeast-3", "ap-southeast-5", "ap-southeast-6", "ap-southeast-7", "ap-southeast-8",
			"eu-central-1", "eu-west-1", "eu-west-2", "me-east-1",
		},
		ProviderCOS: {
			"ap-beijing-1", "ap-beijing", "ap-nanjing", "ap-shanghai", "ap-guangzhou", "ap-chengdu",
			"ap-chongqing", "ap-shenzhen-fsi", "ap-shanghai-fsi", "ap-beijing-fsi", "ap-hongkong",
			"ap-singapore", "ap-mumbai", "ap-jakarta", "ap-seoul", "ap-bangkok", "ap-tokyo",
			"na-siliconvalley", "na-ashburn", "na-toronto", "eu-frankfurt", "eu-moscow", "sa-saopaulo",
		},
	}
	for _, candidate := range regions[provider] {
		if candidate == region {
			return true
		}
	}
	return false
}

func validSecret(value string, maximum int) bool {
	return len(value) > 0 && len(value) <= maximum && strings.TrimSpace(value) == value && !hasControl(value)
}

func validText(value string, minimum, maximum int) bool {
	if !utf8.ValidString(value) || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return false
	}
	length := utf8.RuneCountInString(value)
	return length >= minimum && length <= maximum
}

func hasControl(value string) bool {
	return strings.IndexFunc(value, func(character rune) bool {
		return unicode.IsControl(character) || character == '\u2028' || character == '\u2029'
	}) >= 0
}

func storeTime(value time.Time) time.Time {
	return value.UTC().Truncate(time.Microsecond)
}

func digestRequest(value any) ([32]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func encodeCursor(cursor pageCursor) (string, error) {
	encoded, err := json.Marshal(cursor)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

func decodeCursor(encoded string) (*pageCursor, error) {
	if encoded == "" {
		return nil, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) > maxCursorBytes {
		return nil, ErrInvalidInput
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var cursor pageCursor
	if err := decoder.Decode(&cursor); err != nil || cursor.CreatedAt.IsZero() || cursor.ID == uuid.Nil {
		return nil, ErrInvalidInput
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, ErrInvalidInput
	}
	return &cursor, nil
}
