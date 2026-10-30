package originauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

func CompileJSON(raw []byte) ([]byte, *CompiledPolicy, error) {
	if len(raw) == 0 || len(raw) > MaxPolicyBytes {
		return nil, nil, reject("POLICY_SIZE_INVALID")
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return nil, nil, reject("POLICY_INVALID")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var input Policy
	if err := decoder.Decode(&input); err != nil {
		return nil, nil, reject("POLICY_INVALID")
	}
	if err := requireEOF(decoder); err != nil {
		return nil, nil, reject("POLICY_INVALID")
	}
	compiled, err := compile(input)
	if err != nil {
		return nil, nil, err
	}
	canonical, err := json.Marshal(compiled)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal origin auth policy: %w", err)
	}
	canonical = append(canonical, '\n')
	return canonical, compiled, nil
}

func compile(input Policy) (*CompiledPolicy, error) {
	if input.SchemaVersion != SchemaVersion || input.PolicyVersion == 0 || input.PolicyVersion > 1<<53-1 || len(input.Rules) == 0 || len(input.Rules) > MaxRules {
		return nil, reject("POLICY_INVALID")
	}
	rules := make([]CompiledRule, 0, len(input.Rules))
	seen := make(map[string]struct{}, len(input.Rules))
	for _, rule := range input.Rules {
		compiled, err := compileRule(rule)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[compiled.RuleID]; exists {
			return nil, reject("POLICY_SCOPE_AMBIGUOUS")
		}
		seen[compiled.RuleID] = struct{}{}
		rules = append(rules, compiled)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].RuleID < rules[j].RuleID })
	return &CompiledPolicy{SchemaVersion: SchemaVersion, PolicyVersion: input.PolicyVersion, Rules: rules}, nil
}

func compileRule(input Rule) (CompiledRule, error) {
	if !validIdentifier(input.RuleID, 128) || input.SignatureTTLSeconds < 1 || input.SignatureTTLSeconds > 3600 {
		return CompiledRule{}, reject("RULE_INVALID")
	}
	endpoint, err := normalizeEndpoint(input.Endpoint)
	if err != nil {
		return CompiledRule{}, err
	}
	pathPrefix, err := canonicalPath(input.PathPrefix)
	if err != nil || !strings.HasSuffix(pathPrefix, "/") {
		return CompiledRule{}, reject("PATH_PREFIX_INVALID")
	}
	region := strings.ToLower(input.Region)
	service := strings.ToLower(input.Service)
	if !validScopeName(region) || !validScopeName(service) {
		return CompiledRule{}, reject("SIGNING_SCOPE_UNKNOWN")
	}
	bucket := strings.ToLower(input.Bucket)
	switch input.Provider {
	case ProviderS3:
		if input.Algorithm != AlgorithmS3 || bucket != "" {
			return CompiledRule{}, reject("ALGORITHM_UNKNOWN")
		}
	case ProviderOSS:
		if input.Algorithm != AlgorithmOSS || service != "oss" || !validBucket(bucket) {
			return CompiledRule{}, reject("ALGORITHM_UNKNOWN")
		}
		if !knownOfficialRegion(ProviderOSS, region) {
			return CompiledRule{}, reject("SIGNING_SCOPE_UNKNOWN")
		}
		if endpoint.Host != bucket+".oss-"+region+".aliyuncs.com" {
			return CompiledRule{}, reject("ENDPOINT_NOT_ALLOWED")
		}
	case ProviderCOS:
		if input.Algorithm != AlgorithmCOS || service != "cos" || bucket != "" {
			return CompiledRule{}, reject("ALGORITHM_UNKNOWN")
		}
		if !knownOfficialRegion(ProviderCOS, region) {
			return CompiledRule{}, reject("SIGNING_SCOPE_UNKNOWN")
		}
		if !strings.HasSuffix(endpoint.Host, ".cos."+region+".myqcloud.com") {
			return CompiledRule{}, reject("ENDPOINT_NOT_ALLOWED")
		}
	default:
		return CompiledRule{}, reject("PROVIDER_UNKNOWN")
	}
	current, err := compileKey(input.Provider, input.CurrentKey)
	if err != nil {
		return CompiledRule{}, err
	}
	var previous *CompiledKey
	if input.PreviousKey != nil {
		if input.ActivateCurrentAtUnix <= 0 {
			return CompiledRule{}, reject("ROTATION_INVALID")
		}
		value, err := compileKey(input.Provider, *input.PreviousKey)
		if err != nil {
			return CompiledRule{}, err
		}
		if value.KeyID == current.KeyID || value.SecretFile == current.SecretFile || value.SHA256 == current.SHA256 {
			return CompiledRule{}, reject("ROTATION_INVALID")
		}
		previous = &value
	} else if input.ActivateCurrentAtUnix != 0 {
		return CompiledRule{}, reject("ROTATION_INVALID")
	}
	return CompiledRule{
		RuleID: input.RuleID, Provider: input.Provider, Algorithm: input.Algorithm, Endpoint: endpoint,
		Bucket: bucket, PathPrefix: pathPrefix, Region: region, Service: service,
		SignatureTTLSeconds: input.SignatureTTLSeconds, CurrentKey: current, PreviousKey: previous,
		ActivateCurrentAtUnix: input.ActivateCurrentAtUnix,
	}, nil
}

func knownOfficialRegion(provider, region string) bool {
	switch provider {
	case ProviderOSS:
		switch region {
		case "cn-hangzhou", "cn-shanghai", "cn-nanjing", "cn-fuzhou", "cn-wuhan-lr", "cn-qingdao",
			"cn-beijing", "cn-zhangjiakou", "cn-huhehaote", "cn-wulanchabu", "cn-shenzhen", "cn-heyuan",
			"cn-guangzhou", "cn-chengdu", "cn-hongkong", "cn-zhongwei", "cn-beijing-finance-1",
			"cn-hangzhou-finance", "cn-shanghai-finance-1", "cn-shenzhen-finance-1", "cn-north-2-gov-1",
			"us-west-1", "us-east-1", "ap-northeast-1", "ap-northeast-2", "ap-southeast-1",
			"ap-southeast-3", "ap-southeast-5", "ap-southeast-6", "ap-southeast-7", "ap-southeast-8",
			"eu-central-1", "eu-west-1", "eu-west-2", "me-east-1":
			return true
		}
	case ProviderCOS:
		switch region {
		case "ap-beijing-1", "ap-beijing", "ap-nanjing", "ap-shanghai", "ap-guangzhou", "ap-chengdu",
			"ap-chongqing", "ap-shenzhen-fsi", "ap-shanghai-fsi", "ap-beijing-fsi", "ap-hongkong",
			"ap-singapore", "ap-mumbai", "ap-jakarta", "ap-seoul", "ap-bangkok", "ap-tokyo",
			"na-siliconvalley", "na-ashburn", "na-toronto", "eu-frankfurt", "eu-moscow", "sa-saopaulo":
			return true
		}
	}
	return false
}

func normalizeEndpoint(raw string) (Endpoint, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" || parsed.RawPath != "" {
		return Endpoint{}, reject("ENDPOINT_NOT_ALLOWED")
	}
	host := strings.ToLower(parsed.Hostname())
	if !validDomain(host) || net.ParseIP(host) != nil || host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") {
		return Endpoint{}, reject("ENDPOINT_NOT_ALLOWED")
	}
	port := uint16(443)
	if parsed.Port() != "" {
		value, err := strconv.ParseUint(parsed.Port(), 10, 16)
		if err != nil || value != 443 {
			return Endpoint{}, reject("ENDPOINT_NOT_ALLOWED")
		}
	}
	return Endpoint{Scheme: "https", Host: host, Port: port}, nil
}

func validIdentifier(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || strings.ContainsRune("._:-", character) {
			continue
		}
		return false
	}
	return true
}

func validScopeName(value string) bool {
	if len(value) == 0 || len(value) > 64 || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func validBucket(value string) bool { return len(value) >= 3 && len(value) <= 63 && validDomain(value) }

func validDomain(value string) bool {
	if len(value) == 0 || len(value) > 253 || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
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

func hasControl(value string) bool {
	for _, character := range value {
		if unicode.IsControl(character) {
			return true
		}
	}
	return false
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var stack []map[string]struct{}
	var expectingKey []bool
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		switch value := token.(type) {
		case json.Delim:
			switch value {
			case '{':
				stack = append(stack, make(map[string]struct{}))
				expectingKey = append(expectingKey, true)
			case '}':
				stack = stack[:len(stack)-1]
				expectingKey = expectingKey[:len(expectingKey)-1]
				if len(expectingKey) > 0 {
					expectingKey[len(expectingKey)-1] = true
				}
			case '[':
				stack = append(stack, nil)
				expectingKey = append(expectingKey, false)
			case ']':
				stack = stack[:len(stack)-1]
				expectingKey = expectingKey[:len(expectingKey)-1]
				if len(expectingKey) > 0 && stack[len(stack)-1] != nil {
					expectingKey[len(expectingKey)-1] = true
				}
			}
		case string:
			if len(stack) > 0 && stack[len(stack)-1] != nil && expectingKey[len(expectingKey)-1] {
				if _, exists := stack[len(stack)-1][value]; exists {
					return fmt.Errorf("duplicate key")
				}
				stack[len(stack)-1][value] = struct{}{}
				expectingKey[len(expectingKey)-1] = false
			} else if len(stack) > 0 && stack[len(stack)-1] != nil {
				expectingKey[len(expectingKey)-1] = true
			}
		default:
			if len(stack) > 0 && stack[len(stack)-1] != nil && !expectingKey[len(expectingKey)-1] {
				expectingKey[len(expectingKey)-1] = true
			}
		}
	}
}
