package originauth

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func testSecretDirectory(t *testing.T) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "credentials")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func writeTestCredential(t *testing.T, directory, name, provider, accessKey, secretKey, token string, notBefore, expiresAt int64) string {
	t.Helper()
	credential := Credential{
		SchemaVersion: CredentialVersion, Provider: provider, AccessKeyID: accessKey,
		SecretAccessKey: secretKey, SessionToken: token, NotBeforeUnix: notBefore, ExpiresAtUnix: expiresAt,
	}
	raw, err := json.Marshal(credential)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func testRule(provider, credentialPath string) Rule {
	rule := Rule{
		RuleID: "rule-" + provider, Provider: provider, PathPrefix: "/", Region: "us-east-1",
		Service: provider, SignatureTTLSeconds: 600,
		CurrentKey: KeyRef{KeyID: "current", SecretFile: credentialPath},
	}
	switch provider {
	case ProviderS3:
		rule.Algorithm = AlgorithmS3
		rule.Endpoint = "https://examplebucket.s3.us-east-1.amazonaws.com"
		rule.Service = "s3"
	case ProviderOSS:
		rule.Algorithm = AlgorithmOSS
		rule.Endpoint = "https://bucket.oss-cn-hangzhou.aliyuncs.com"
		rule.Bucket = "bucket"
		rule.Region = "cn-hangzhou"
		rule.Service = "oss"
	case ProviderCOS:
		rule.Algorithm = AlgorithmCOS
		rule.Endpoint = "https://testbucket-125000000.cos.ap-guangzhou.myqcloud.com"
		rule.Region = "ap-guangzhou"
		rule.Service = "cos"
	}
	return rule
}

func compileTestPolicy(t *testing.T, version uint64, rules ...Rule) ([]byte, *CompiledPolicy) {
	t.Helper()
	raw, err := json.Marshal(Policy{SchemaVersion: SchemaVersion, PolicyVersion: version, Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	canonical, policy, err := CompileJSON(raw)
	if err != nil {
		t.Fatalf("CompileJSON: %v", err)
	}
	return canonical, policy
}

func rejectionCode(t *testing.T, err error) string {
	t.Helper()
	var rejection *Rejection
	if !errors.As(err, &rejection) {
		t.Fatalf("error %v is not a rejection", err)
	}
	return rejection.Code
}
