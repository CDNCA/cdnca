package urlauth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCompileJSONIsDeterministicAndDoesNotEmbedSecrets(t *testing.T) {
	keys := makeKeys(t)
	first := validPolicy(keys)
	first.ExcludedQueryParameters = []string{"utm_source", "cache_bust"}
	first.TrustedProxies = []string{"2001:db8:10::/48", "10.0.0.0/8"}
	second := first
	second.ExcludedQueryParameters = []string{"cache_bust", "utm_source"}
	second.TrustedProxies = []string{"10.0.0.1/8", "2001:db8:10::1/48"}

	canonicalFirst, compiled, err := CompileJSON(marshalPolicy(t, first))
	if err != nil {
		t.Fatal(err)
	}
	canonicalSecond, _, err := CompileJSON(marshalPolicy(t, second))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canonicalFirst, canonicalSecond) {
		t.Fatalf("canonical outputs differ:\n%s\n%s", canonicalFirst, canonicalSecond)
	}
	if bytes.Contains(canonicalFirst, keys.currentSecret) || bytes.Contains(canonicalFirst, keys.previousSecret) {
		t.Fatal("canonical policy embeds a key secret")
	}
	if got := compiled.ExcludedQueryParameters; len(got) != 2 || got[0] != "cache_bust" || got[1] != "utm_source" {
		t.Fatalf("excluded params = %#v", got)
	}
	if compiled.CurrentKey.KeySHA256 != sha256Hex(keys.currentSecret) {
		t.Fatalf("current key digest = %q", compiled.CurrentKey.KeySHA256)
	}
}

func TestCompileJSONRejectsUnsafePolicies(t *testing.T) {
	keys := makeKeys(t)
	tests := []struct {
		name   string
		mutate func(*Policy)
	}{
		{name: "algorithm downgrade", mutate: func(policy *Policy) { policy.Algorithm = "md5" }},
		{name: "clock skew", mutate: func(policy *Policy) { policy.MaxClockSkewSeconds = MaxClockSkewSeconds + 1 }},
		{name: "validity", mutate: func(policy *Policy) { policy.MaxValiditySeconds = 0 }},
		{name: "replay uses", mutate: func(policy *Policy) { policy.MaxSignatureUses = MaxSignatureUses + 1 }},
		{name: "parameter collision", mutate: func(policy *Policy) { policy.KeyIDParameter = policy.SignatureParameter }},
		{name: "excluded auth parameter", mutate: func(policy *Policy) { policy.ExcludedQueryParameters = []string{"sig"} }},
		{name: "duplicate CIDR", mutate: func(policy *Policy) { policy.TrustedProxies = []string{"10.0.0.0/8", "10.1.2.3/8"} }},
		{name: "same rotation id", mutate: func(policy *Policy) { policy.PreviousKey.KeyID = policy.CurrentKey.KeyID }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := validPolicy(keys)
			test.mutate(&policy)
			if _, _, err := CompileJSON(marshalPolicy(t, policy)); !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	raw := marshalPolicy(t, validPolicy(keys))
	duplicate := bytes.Replace(raw, []byte(`"algorithm":"hmac-sha256"`), []byte(`"algorithm":"hmac-sha256","algorithm":"md5"`), 1)
	if _, _, err := CompileJSON(duplicate); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("duplicate JSON key error = %v", err)
	}
	unknown := bytes.Replace(raw, []byte(`"site_id":"site-a"`), []byte(`"site_id":"site-a","future":true`), 1)
	if _, _, err := CompileJSON(unknown); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("unknown field error = %v", err)
	}
	missing := bytes.Replace(raw, []byte(`"bind_client_ip":false,`), nil, 1)
	if _, _, err := CompileJSON(missing); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("missing field error = %v", err)
	}
}

func TestCompileJSONRequiresPrivateKeyFiles(t *testing.T) {
	keys := makeKeys(t)
	policy := validPolicy(keys)
	if err := os.Chmod(keys.currentPath, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, _, err := CompileJSON(marshalPolicy(t, policy)); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("permissive key error = %v", err)
	}
	if err := os.Chmod(keys.currentPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(keys.currentPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, _, err := CompileJSON(marshalPolicy(t, policy)); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("permissive parent error = %v", err)
	}
	if err := os.Chmod(filepath.Dir(keys.currentPath), 0o700); err != nil {
		t.Fatal(err)
	}
	hardlink := filepath.Join(filepath.Dir(keys.currentPath), "hardlink.key")
	if err := os.Link(keys.currentPath, hardlink); err != nil {
		t.Fatal(err)
	}
	if _, _, err := CompileJSON(marshalPolicy(t, policy)); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("hard-linked key error = %v", err)
	}
	if err := os.Remove(hardlink); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(keys.currentPath), "link.key")
	if err := os.Symlink(keys.currentPath, link); err != nil {
		t.Fatal(err)
	}
	policy.CurrentKey.KeyFile = link
	if _, _, err := CompileJSON(marshalPolicy(t, policy)); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("symlink key error = %v", err)
	}
}

func TestCompileJSONRejectsSymlinkKeyAncestors(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	realDirectory := filepath.Join(root, "real", "keys")
	if err := os.MkdirAll(realDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	keys := testKeys{
		currentPath:    filepath.Join(realDirectory, "current.key"),
		previousPath:   filepath.Join(realDirectory, "previous.key"),
		currentSecret:  []byte("current-url-auth-secret-32-bytes!!"),
		previousSecret: []byte("previous-url-auth-secret-32-byte!"),
	}
	if err := os.WriteFile(keys.currentPath, keys.currentSecret, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keys.previousPath, keys.previousSecret, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := CompileJSON(marshalPolicy(t, validPolicy(keys))); err != nil {
		t.Fatalf("direct resolved key path error = %v", err)
	}

	link := filepath.Join(root, "linked")
	if err := os.Symlink(filepath.Join(root, "real"), link); err != nil {
		t.Fatal(err)
	}
	policy := validPolicy(keys)
	policy.CurrentKey.KeyFile = filepath.Join(link, "keys", "current.key")
	if _, _, err := CompileJSON(marshalPolicy(t, policy)); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("symlink ancestor error = %v", err)
	}

	if _, err := readSecureKey(filepath.Join(realDirectory, "missing.key")); err == nil || err.Error() != "open failed" {
		t.Fatalf("missing key error = %v", err)
	}
}

func TestCompiledPolicyRejectsKeyReplacement(t *testing.T) {
	keys := makeKeys(t)
	canonical, _, err := CompileJSON(marshalPolicy(t, validPolicy(keys)))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keys.currentPath, []byte("replacement-url-auth-secret-32-byte!"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCompiledJSON(canonical); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("replacement key error = %v", err)
	}
}

func TestSignTargetCanonicalizesQueryAndBindsSecurityFields(t *testing.T) {
	keys := makeKeys(t)
	policyInput := validPolicy(keys)
	policyInput.BindClientIP = true
	_, policy, err := CompileJSON(marshalPolicy(t, policyInput))
	if err != nil {
		t.Fatal(err)
	}
	loadedSecret, err := loadCompiledKey(policy.CurrentKey)
	if err != nil || !bytes.Equal(loadedSecret, keys.currentSecret) {
		t.Fatalf("loaded current key differs: error = %v", err)
	}
	now := time.Unix(1_700_000_000, 0)
	expires := now.Add(30 * time.Second)
	originalPairs, originalPath, err := parseTarget("/asset?b=two&a=one&utm_source=alpha")
	if err != nil {
		t.Fatal(err)
	}
	testClientIP, err := canonicalClientIP(true, "2001:db8::1")
	if err != nil {
		t.Fatal(err)
	}
	originalCanonical, err := buildCanonical(policy, "GET", originalPath, originalPairs, "1700000030", "current", testClientIP)
	if err != nil {
		t.Fatal(err)
	}
	originalDigest := hmac.New(sha256.New, keys.currentSecret)
	_, _ = originalDigest.Write([]byte(originalCanonical))
	originalSignature := hex.EncodeToString(originalDigest.Sum(nil))
	signed, err := SignTargetAt(policy, "GET", "/asset?b=two&a=one&utm_source=alpha", "", "2001:db8::1", expires, now)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(signed, "/asset?a=one&b=two&exp=1700000030&kid=current&sig=") || !strings.HasSuffix(signed, "&utm_source=alpha") {
		t.Fatalf("signed target = %q", signed)
	}

	pairs, path, err := parseTarget(signed)
	if err != nil {
		t.Fatal(err)
	}
	values := make(map[string]string, len(pairs))
	for _, pair := range pairs {
		values[pair.name] = pair.value
	}
	canonical, err := buildCanonical(policy, "GET", path, pairs, values[policy.ExpirationParameter], values[policy.KeyIDParameter], testClientIP)
	if err != nil {
		t.Fatal(err)
	}
	digest := hmac.New(sha256.New, keys.currentSecret)
	_, _ = digest.Write([]byte(canonical))
	expectedSignature := hex.EncodeToString(digest.Sum(nil))
	if !hmac.Equal([]byte(values[policy.SignatureParameter]), []byte(expectedSignature)) {
		t.Fatalf("signature = %q, want %q; canonical = %q", values[policy.SignatureParameter], expectedSignature, canonical)
	}
	if expectedSignature != originalSignature {
		t.Fatal("canonical signature changed after query reordering")
	}
	if strings.Contains(canonical, "utm_source") || !strings.Contains(canonical, "query=a=one&b=two") || !strings.Contains(canonical, "method=GET") || !strings.Contains(canonical, "path=%2Fasset") {
		t.Fatalf("canonical request = %q", canonical)
	}
}

func TestSigningRejectsAmbiguousOrUnboundedRequests(t *testing.T) {
	keys := makeKeys(t)
	_, policy, err := CompileJSON(marshalPolicy(t, validPolicy(keys)))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	for _, target := range []string{
		"/asset?a=1&a=2",
		"/asset?%61=1&a=2",
		"/asset?bad=%0A",
		"/encoded%2Fpath?a=1",
		"/asset?sig=existing",
		"/asset?" + strings.Repeat("a", MaxQueryBytes+1),
	} {
		if _, err := SignTargetAt(policy, "GET", target, "", "", now.Add(time.Minute), now); err == nil {
			t.Fatalf("target %q was accepted", target)
		}
	}
	if _, err := SignTargetAt(policy, "GET", "/asset", "missing", "", now.Add(time.Minute), now); err == nil {
		t.Fatal("unknown key was accepted")
	}
	if _, err := SignTargetAt(policy, "GET", "/asset", "", "", now.Add(time.Duration(policy.MaxValiditySeconds+1)*time.Second), now); err == nil {
		t.Fatal("unbounded expiration was accepted")
	}
}

type testKeys struct {
	currentPath    string
	previousPath   string
	currentSecret  []byte
	previousSecret []byte
}

func makeKeys(t *testing.T) testKeys {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	current := []byte("current-url-auth-secret-32-bytes!!")
	previous := []byte("previous-url-auth-secret-32-byte!")
	currentPath := filepath.Join(directory, "current.key")
	previousPath := filepath.Join(directory, "previous.key")
	if err := os.WriteFile(currentPath, current, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(previousPath, previous, 0o600); err != nil {
		t.Fatal(err)
	}
	return testKeys{currentPath: currentPath, previousPath: previousPath, currentSecret: current, previousSecret: previous}
}

func validPolicy(keys testKeys) Policy {
	return Policy{
		SchemaVersion: SchemaVersion, PolicyVersion: 1, TenantID: "tenant-a", SiteID: "site-a",
		Algorithm: AlgorithmHMACSHA256, SignatureParameter: "sig", ExpirationParameter: "exp", KeyIDParameter: "kid",
		MaxClockSkewSeconds: 2, MaxValiditySeconds: 300, MaxSignatureUses: 0,
		ExcludedQueryParameters: []string{"utm_source"}, TrustedProxies: []string{},
		CurrentKey:  KeyRef{KeyID: "current", KeyFile: keys.currentPath},
		PreviousKey: &KeyRef{KeyID: "previous", KeyFile: keys.previousPath},
	}
}

func marshalPolicy(t *testing.T, policy Policy) []byte {
	t.Helper()
	raw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func sha256Hex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
