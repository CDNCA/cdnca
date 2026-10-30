package originauthcontrol

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestRuleProviderEndpointAndSSRFBoundaries(t *testing.T) {
	credential := CredentialReference{CredentialID: uuid.New(), Revision: 2}
	base := RuleConfig{
		Provider: ProviderS3, Algorithm: AlgorithmS3,
		Endpoint: "https://bucket.s3.us-east-1.amazonaws.com", PathPrefix: "/objects/",
		Region: "us-east-1", Service: "s3", SignatureTTLSeconds: 300,
		CurrentCredential: credential,
	}
	policies, err := normalizeEgressPolicies(map[string][]string{
		"egress-minio-prod": {"objects.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		mutate    func(*RuleConfig)
		wantError bool
	}{
		"AWS exact": {func(*RuleConfig) {}, false},
		"AWS region mismatch": {func(value *RuleConfig) {
			value.Endpoint = "https://bucket.s3.us-west-2.amazonaws.com"
		}, true},
		"AWS bucket too long": {func(value *RuleConfig) {
			value.Endpoint = "https://" + strings.Repeat("a", 64) + ".s3.us-east-1.amazonaws.com"
		}, true},
		"HTTP":             {func(value *RuleConfig) { value.Endpoint = "http://objects.example.com" }, true},
		"IP":               {func(value *RuleConfig) { value.Endpoint = "https://127.0.0.1" }, true},
		"localhost":        {func(value *RuleConfig) { value.Endpoint = "https://localhost" }, true},
		"dot local":        {func(value *RuleConfig) { value.Endpoint = "https://objects.local" }, true},
		"userinfo":         {func(value *RuleConfig) { value.Endpoint = "https://user@objects.example.com" }, true},
		"query":            {func(value *RuleConfig) { value.Endpoint = "https://objects.example.com?x=1" }, true},
		"fragment":         {func(value *RuleConfig) { value.Endpoint = "https://objects.example.com#x" }, true},
		"non 443":          {func(value *RuleConfig) { value.Endpoint = "https://objects.example.com:8443" }, true},
		"custom no policy": {func(value *RuleConfig) { value.Endpoint = "https://objects.example.com" }, true},
		"custom wrong policy": {func(value *RuleConfig) {
			value.Endpoint = "https://objects.example.com"
			value.EgressPolicyReference = "wrong"
		}, true},
		"custom exact allowlist": {func(value *RuleConfig) {
			value.Endpoint = "https://objects.example.com"
			value.EgressPolicyReference = "egress-minio-prod"
		}, false},
	} {
		t.Run(name, func(t *testing.T) {
			input := base
			test.mutate(&input)
			err := validateRuleConfig(&input, policies)
			if test.wantError && !errors.Is(err, ErrValidation) {
				t.Fatalf("validateRuleConfig() error = %v", err)
			}
			if !test.wantError && err != nil {
				t.Fatalf("validateRuleConfig() error = %v", err)
			}
		})
	}
}

func TestOfficialOSSAndCOSBindings(t *testing.T) {
	credential := CredentialReference{CredentialID: uuid.New(), Revision: 2}
	valid := []RuleConfig{
		{
			Provider: ProviderOSS, Algorithm: AlgorithmOSS,
			Endpoint: "https://private-bucket.oss-cn-hangzhou.aliyuncs.com", Bucket: "private-bucket",
			PathPrefix: "/", Region: "cn-hangzhou", Service: "oss", SignatureTTLSeconds: 60,
			CurrentCredential: credential,
		},
		{
			Provider: ProviderCOS, Algorithm: AlgorithmCOS,
			Endpoint: "https://private-bucket-1250000000.cos.ap-guangzhou.myqcloud.com", Bucket: "",
			PathPrefix: "/assets/", Region: "ap-guangzhou", Service: "cos", SignatureTTLSeconds: 60,
			CurrentCredential: credential,
		},
	}
	for _, input := range valid {
		if err := validateRuleConfig(&input, nil); err != nil {
			t.Fatalf("valid %s config error = %v", input.Provider, err)
		}
	}
	invalidOSS := valid[0]
	invalidOSS.Endpoint = "https://private-bucket.oss-cn-shanghai.aliyuncs.com"
	if err := validateRuleConfig(&invalidOSS, nil); !errors.Is(err, ErrValidation) {
		t.Fatalf("OSS region mismatch error = %v", err)
	}
	invalidCOS := valid[1]
	invalidCOS.Endpoint = "https://private-bucket.cos.ap-guangzhou.myqcloud.com"
	if err := validateRuleConfig(&invalidCOS, nil); !errors.Is(err, ErrValidation) {
		t.Fatalf("COS APPID omission error = %v", err)
	}
}

func TestPathPrefixIsCanonicalAndBounded(t *testing.T) {
	for _, value := range []string{"assets/", "/assets", "/a//b/", "/a/../b/", "/a/%2f/", "/a/?x/", "/a\\b/"} {
		if _, err := normalizePathPrefix(value); !errors.Is(err, ErrValidation) {
			t.Fatalf("normalizePathPrefix(%q) error = %v", value, err)
		}
	}
	for _, value := range []string{"/", "/assets/", "/a-b_c./"} {
		if normalized, err := normalizePathPrefix(value); err != nil || normalized != value {
			t.Fatalf("normalizePathPrefix(%q) = %q, %v", value, normalized, err)
		}
	}
}
