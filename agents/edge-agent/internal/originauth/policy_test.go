package originauth

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompileJSONIsDeterministicAndSecretFree(t *testing.T) {
	directory := testSecretDirectory(t)
	s3Path := writeTestCredential(t, directory, "s3.json", ProviderS3, "S3_TEST_ACCESS", "S3_TEST_SECRET", "S3_TEST_TOKEN", 0, 4102444800)
	ossPath := writeTestCredential(t, directory, "oss.json", ProviderOSS, "OSS_TEST_ACCESS", "OSS_TEST_SECRET", "", 0, 4102444800)

	first, firstPolicy := compileTestPolicy(t, 7, testRule(ProviderS3, s3Path), testRule(ProviderOSS, ossPath))
	second, secondPolicy := compileTestPolicy(t, 7, testRule(ProviderOSS, ossPath), testRule(ProviderS3, s3Path))
	if !bytes.Equal(first, second) {
		t.Fatalf("canonical policy depends on input rule order:\n%s\n%s", first, second)
	}
	if first[len(first)-1] != '\n' || firstPolicy.Rules[0].RuleID != "rule-oss" || secondPolicy.Rules[1].RuleID != "rule-s3" {
		t.Fatalf("compiled rules are not sorted: %#v", firstPolicy.Rules)
	}
	for _, secret := range []string{"S3_TEST_ACCESS", "S3_TEST_SECRET", "S3_TEST_TOKEN", "OSS_TEST_ACCESS", "OSS_TEST_SECRET"} {
		if bytes.Contains(first, []byte(secret)) {
			t.Fatalf("compiled policy contains credential material %q", secret)
		}
	}
	if !bytes.Contains(first, []byte(s3Path)) || !bytes.Contains(first, []byte(`"sha256":"`)) {
		t.Fatalf("compiled policy did not retain a bound secret reference: %s", first)
	}
}

func TestRejectDuplicateJSONKeys(t *testing.T) {
	valid := []string{
		`{"a":1,"b":{"a":2},"c":[{"a":3},{"a":4}]}`,
		`[{"a":"value"},[1,2,{"b":true}]]`,
	}
	for _, raw := range valid {
		if err := rejectDuplicateJSONKeys([]byte(raw)); err != nil {
			t.Fatalf("valid JSON rejected %s: %v", raw, err)
		}
	}
	invalid := []string{
		`{"a":1,"a":2}`,
		`{"a":{"b":1,"b":2}}`,
		`{"a":[{"b":1,"b":2}]}`,
		`[{"a":1},{"a":2,"a":3}]`,
	}
	for _, raw := range invalid {
		if err := rejectDuplicateJSONKeys([]byte(raw)); err == nil {
			t.Fatalf("duplicate JSON key accepted: %s", raw)
		}
	}
}

func TestCompileJSONRejectsAmbiguousEnvelope(t *testing.T) {
	cases := []string{
		`{"schema_version":"x","schema_version":"y","policy_version":1,"rules":[]}`,
		`{"schema_version":"x","policy_version":1,"rules":[],"unknown":true}`,
		`{"schema_version":"x","policy_version":1,"rules":[]} {}`,
		`null`,
		`[]`,
	}
	for _, raw := range cases {
		if _, _, err := CompileJSON([]byte(raw)); err == nil {
			t.Fatalf("ambiguous envelope accepted: %s", raw)
		}
	}
}

func TestCompileJSONRejectsInvalidRules(t *testing.T) {
	directory := testSecretDirectory(t)
	path := writeTestCredential(t, directory, "oss.json", ProviderOSS, "ak", "sk", "", 0, 4102444800)

	tests := map[string]func(*Rule){
		"unknown provider":     func(rule *Rule) { rule.Provider = "swift" },
		"unknown algorithm":    func(rule *Rule) { rule.Algorithm = "oss-v1" },
		"insecure endpoint":    func(rule *Rule) { rule.Endpoint = "http://bucket.oss-cn-hangzhou.aliyuncs.com" },
		"endpoint path":        func(rule *Rule) { rule.Endpoint += "/bucket" },
		"endpoint userinfo":    func(rule *Rule) { rule.Endpoint = "https://user@bucket.oss-cn-hangzhou.aliyuncs.com" },
		"bucket host mismatch": func(rule *Rule) { rule.Bucket = "other" },
		"region host mismatch": func(rule *Rule) { rule.Region = "cn-beijing" },
		"unknown region": func(rule *Rule) {
			rule.Region = "moon-1"
			rule.Endpoint = "https://bucket.oss-moon-1.aliyuncs.com"
		},
		"unknown service":      func(rule *Rule) { rule.Service = "object-storage" },
		"encoded slash prefix": func(rule *Rule) { rule.PathPrefix = "/private%2fchild/" },
		"dot prefix":           func(rule *Rule) { rule.PathPrefix = "/private/../child/" },
		"prefix without slash": func(rule *Rule) { rule.PathPrefix = "/private" },
		"excessive ttl":        func(rule *Rule) { rule.SignatureTTLSeconds = 3601 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			rule := testRule(ProviderOSS, path)
			mutate(&rule)
			raw, err := json.Marshal(Policy{SchemaVersion: SchemaVersion, PolicyVersion: 1, Rules: []Rule{rule}})
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := CompileJSON(raw); err == nil {
				t.Fatal("invalid rule accepted")
			}
		})
	}
}

func TestCredentialFileSecurity(t *testing.T) {
	validDirectory := testSecretDirectory(t)
	validPath := writeTestCredential(t, validDirectory, "valid.json", ProviderS3, "ak", "sk", "token", 0, 4102444800)
	if _, _, err := CompileJSON(mustPolicyJSON(t, testRule(ProviderS3, validPath))); err != nil {
		t.Fatalf("secure credential rejected: %v", err)
	}

	t.Run("permissive file", func(t *testing.T) {
		path := writeTestCredential(t, validDirectory, "permissive.json", ProviderS3, "ak", "sk", "", 0, 4102444800)
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		assertPolicyRejected(t, testRule(ProviderS3, path), "SECRET_FILE_UNSAFE")
	})

	t.Run("permissive parent", func(t *testing.T) {
		directory := testSecretDirectory(t)
		path := writeTestCredential(t, directory, "credential.json", ProviderS3, "ak", "sk", "", 0, 4102444800)
		if err := os.Chmod(directory, 0o755); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(directory, 0o700) })
		assertPolicyRejected(t, testRule(ProviderS3, path), "SECRET_FILE_UNSAFE")
	})

	t.Run("symlink", func(t *testing.T) {
		link := filepath.Join(validDirectory, "link.json")
		if err := os.Symlink(validPath, link); err != nil {
			t.Fatal(err)
		}
		assertPolicyRejected(t, testRule(ProviderS3, link), "SECRET_FILE_UNAVAILABLE")
	})

	t.Run("hardlink", func(t *testing.T) {
		path := writeTestCredential(t, validDirectory, "hard-source.json", ProviderS3, "ak", "sk", "", 0, 4102444800)
		if err := os.Link(path, filepath.Join(validDirectory, "hard-copy.json")); err != nil {
			t.Fatal(err)
		}
		assertPolicyRejected(t, testRule(ProviderS3, path), "SECRET_FILE_UNSAFE")
	})

	t.Run("relative", func(t *testing.T) {
		rule := testRule(ProviderS3, "credential.json")
		assertPolicyRejected(t, rule, "SECRET_FILE_UNSAFE")
	})
}

func TestCredentialJSONIsStrict(t *testing.T) {
	directory := testSecretDirectory(t)
	cases := map[string]string{
		"duplicate": `{"schema_version":"cdnca.edge.originauth.credential/v1","provider":"s3","provider":"oss","access_key_id":"ak","secret_access_key":"sk","session_token":"","not_before_unix":0,"expires_at_unix":9}`,
		"unknown":   `{"schema_version":"cdnca.edge.originauth.credential/v1","provider":"s3","access_key_id":"ak","secret_access_key":"sk","session_token":"","not_before_unix":0,"expires_at_unix":9,"extra":true}`,
		"trailing":  `{"schema_version":"cdnca.edge.originauth.credential/v1","provider":"s3","access_key_id":"ak","secret_access_key":"sk","session_token":"","not_before_unix":0,"expires_at_unix":9} {}`,
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(directory, name+".json")
			if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
				t.Fatal(err)
			}
			assertPolicyRejected(t, testRule(ProviderS3, path), "CREDENTIAL_INVALID")
		})
	}
}

func mustPolicyJSON(t *testing.T, rules ...Rule) []byte {
	t.Helper()
	raw, err := json.Marshal(Policy{SchemaVersion: SchemaVersion, PolicyVersion: 1, Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func assertPolicyRejected(t *testing.T, rule Rule, code string) {
	t.Helper()
	_, _, err := CompileJSON(mustPolicyJSON(t, rule))
	if err == nil || rejectionCode(t, err) != code {
		t.Fatalf("CompileJSON error = %v, want %s", err, code)
	}
}

func TestCompileJSONBounds(t *testing.T) {
	if _, _, err := CompileJSON(nil); rejectionCode(t, err) != "POLICY_SIZE_INVALID" {
		t.Fatalf("empty policy error = %v", err)
	}
	tooLarge := bytes.Repeat([]byte{' '}, MaxPolicyBytes+1)
	if _, _, err := CompileJSON(tooLarge); rejectionCode(t, err) != "POLICY_SIZE_INVALID" {
		t.Fatalf("large policy error = %v", err)
	}
	if strings.Contains((&Rejection{Code: "POLICY_INVALID"}).Error(), "secret") {
		t.Fatal("rejection included secret material")
	}
}
