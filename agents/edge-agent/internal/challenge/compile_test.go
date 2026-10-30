package challenge

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompileJSONIsDeterministicAndDoesNotEmbedSecrets(t *testing.T) {
	keys := makeKeys(t)
	first := validPolicy(keys)
	first.TrustedProxies = []string{"2001:db8:10::1/48", "10.20.30.40/8"}
	first.BypassRoutes = []BypassRoute{{Kind: BypassPrefix, Path: "/api/"}, {Kind: BypassExact, Path: "/healthz"}}
	first.Rules = []Rule{captchaRule(), clickRule(), sliderRule(), delayRule()}
	second := first
	second.TrustedProxies = []string{"10.0.0.0/8", "2001:db8:10::/48"}
	second.BypassRoutes = []BypassRoute{{Kind: BypassExact, Path: "/healthz"}, {Kind: BypassPrefix, Path: "/api/"}}

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
		t.Fatal("canonical challenge policy contains secret bytes")
	}
	if compiled.CurrentKey.KeySHA256 != sha256Hex(keys.currentSecret) || compiled.PreviousKey.KeySHA256 != sha256Hex(keys.previousSecret) {
		t.Fatal("compiled key fingerprints do not match owner-only files")
	}
	if compiled.Rules[0].RuleID != "delay" || compiled.Rules[1].RuleID != "click" ||
		compiled.Rules[2].RuleID != "slider" || compiled.Rules[3].RuleID != "captcha" || compiled.Rules[0].Host != "edge-a.test" {
		t.Fatalf("compiled rules are not normalized and sorted: %#v", compiled.Rules)
	}
	if len(compiled.BypassRoutes) != 2 || compiled.BypassRoutes[0].Path != "/api/" || compiled.BypassRoutes[1].Path != "/healthz" {
		t.Fatalf("compiled bypass routes are not deterministic: %#v", compiled.BypassRoutes)
	}
	if compiled.TrustedProxies[0].prefix().String() != "10.0.0.0/8" {
		t.Fatalf("trusted proxy was not canonicalized: %#v", compiled.TrustedProxies)
	}
}

func TestCompileJSONPreservesEmptyBypassRoutesAsArray(t *testing.T) {
	keys := makeKeys(t)
	policy := validPolicy(keys)
	policy.BypassRoutes = []BypassRoute{}

	canonical, compiled, err := CompileJSON(marshalPolicy(t, policy))
	if err != nil {
		t.Fatal(err)
	}
	if compiled.BypassRoutes == nil || !bytes.Contains(canonical, []byte(`"bypass_routes":[]`)) {
		t.Fatalf("empty bypass routes lost array shape: %s", canonical)
	}
}

func TestCompileJSONRejectsUnsafePolicy(t *testing.T) {
	keys := makeKeys(t)
	tests := []struct {
		name   string
		mutate func(*Policy)
	}{
		{name: "schema", mutate: func(policy *Policy) { policy.SchemaVersion = "cdnca.edge.challenge/v2" }},
		{name: "version", mutate: func(policy *Policy) { policy.PolicyVersion = MaxPolicyVersion + 1 }},
		{name: "algorithm", mutate: func(policy *Policy) { policy.Algorithm = "sha1" }},
		{name: "cookie prefix", mutate: func(policy *Policy) { policy.CookieName = "cdnca_pass" }},
		{name: "empty rules", mutate: func(policy *Policy) { policy.Rules = nil }},
		{name: "duplicate id", mutate: func(policy *Policy) { policy.Rules = append(policy.Rules, policy.Rules[0]) }},
		{name: "duplicate scope", mutate: func(policy *Policy) {
			rule := clickRule()
			rule.RuleID = "other"
			rule.Host = policy.Rules[0].Host
			rule.SiteID = policy.Rules[0].SiteID
			policy.Rules = append(policy.Rules, rule)
		}},
		{name: "control id", mutate: func(policy *Policy) { policy.Rules[0].TenantID = "tenant\nother" }},
		{name: "invalid host", mutate: func(policy *Policy) { policy.Rules[0].Host = "edge.test:443" }},
		{name: "delay too short", mutate: func(policy *Policy) { policy.Rules[0].MinDelaySeconds = 4 }},
		{name: "click delay", mutate: func(policy *Policy) { policy.Rules[0] = clickRule(); policy.Rules[0].MinDelaySeconds = 1 }},
		{name: "slider delay", mutate: func(policy *Policy) { policy.Rules[0] = sliderRule(); policy.Rules[0].MinDelaySeconds = 1 }},
		{name: "captcha delay", mutate: func(policy *Policy) { policy.Rules[0] = captchaRule(); policy.Rules[0].MinDelaySeconds = 1 }},
		{name: "challenge ttl", mutate: func(policy *Policy) { policy.Rules[0].ChallengeTTLSeconds = policy.Rules[0].MinDelaySeconds }},
		{name: "pass ttl", mutate: func(policy *Policy) { policy.Rules[0].PassTTLSeconds = MaxPassTTLSeconds + 1 }},
		{name: "clock skew", mutate: func(policy *Policy) { policy.Rules[0].ClockSkewSeconds = MaxClockSkewSeconds + 1 }},
		{name: "nonce attempts", mutate: func(policy *Policy) { policy.Rules[0].AttemptsPerNonce = 2 }},
		{name: "failure window", mutate: func(policy *Policy) { policy.Rules[0].FailureWindowSeconds = 0 }},
		{name: "failure count", mutate: func(policy *Policy) { policy.Rules[0].MaxFailuresPerWindow = MaxFailuresPerWindow + 1 }},
		{name: "IP binding", mutate: func(policy *Policy) { policy.Rules[0].IPBinding = "subnet" }},
		{name: "bad CIDR", mutate: func(policy *Policy) { policy.TrustedProxies = []string{"192.0.2.999/24"} }},
		{name: "duplicate CIDR", mutate: func(policy *Policy) { policy.TrustedProxies = []string{"10.0.0.1/8", "10.2.3.4/8"} }},
		{name: "same key id", mutate: func(policy *Policy) { policy.PreviousKey.KeyID = policy.CurrentKey.KeyID }},
		{name: "relative bypass", mutate: func(policy *Policy) { policy.BypassRoutes = []BypassRoute{{Kind: BypassExact, Path: "api"}} }},
		{name: "query bypass", mutate: func(policy *Policy) { policy.BypassRoutes = []BypassRoute{{Kind: BypassExact, Path: "/api?all=1"}} }},
		{name: "root prefix bypass", mutate: func(policy *Policy) { policy.BypassRoutes = []BypassRoute{{Kind: BypassPrefix, Path: "/"}} }},
		{name: "duplicate bypass", mutate: func(policy *Policy) {
			policy.BypassRoutes = []BypassRoute{{Kind: BypassExact, Path: "/healthz"}, {Kind: BypassExact, Path: "/healthz"}}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := validPolicy(keys)
			test.mutate(&policy)
			if _, _, err := CompileJSON(marshalPolicy(t, policy)); !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("CompileJSON() error = %v", err)
			}
		})
	}
}

func TestCompileJSONRejectsAmbiguousOrMissingJSON(t *testing.T) {
	keys := makeKeys(t)
	raw := marshalPolicy(t, validPolicy(keys))
	for _, candidate := range [][]byte{
		bytes.Replace(raw, []byte(`"algorithm":"hmac-sha256"`), []byte(`"algorithm":"hmac-sha256","algorithm":"sha1"`), 1),
		bytes.Replace(raw, []byte(`"cookie_name":"__Host-cdnca_challenge"`), []byte(`"cookie_name":"__Host-cdnca_challenge","future":true`), 1),
		bytes.Replace(raw, []byte(`"bind_user_agent":true`), nil, 1),
		append(append([]byte(nil), raw...), []byte(`{}`)...),
	} {
		if _, _, err := CompileJSON(candidate); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatalf("ambiguous JSON error = %v; input=%s", err, candidate)
		}
	}
}

func TestCompileJSONRequiresIndependentOwnerOnlyKeyFiles(t *testing.T) {
	keys := makeKeys(t)
	policy := validPolicy(keys)
	if err := os.Chmod(filepath.Dir(keys.currentPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := CompileJSON(marshalPolicy(t, policy)); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("public key directory error = %v", err)
	}
	if err := os.Chmod(filepath.Dir(keys.currentPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keys.currentPath, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, _, err := CompileJSON(marshalPolicy(t, policy)); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("permissive key error = %v", err)
	}
	if err := os.Chmod(keys.currentPath, 0o600); err != nil {
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
	policy = validPolicy(keys)
	hardlink := filepath.Join(filepath.Dir(keys.currentPath), "hardlink.key")
	if err := os.Link(keys.currentPath, hardlink); err != nil {
		t.Fatal(err)
	}
	if _, _, err := CompileJSON(marshalPolicy(t, policy)); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("multiply-linked key error = %v", err)
	}
}

func TestCompileJSONRejectsSymlinkKeyAncestorsAndNonCleanPaths(t *testing.T) {
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
		currentSecret:  []byte("current-challenge-hmac-key-material-001"),
		previousSecret: []byte("previous-challenge-hmac-key-material-02"),
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

	nonClean := filepath.Dir(keys.currentPath) + string(filepath.Separator) + "." + string(filepath.Separator) + filepath.Base(keys.currentPath)
	if _, err := readSecureKey(nonClean); err == nil || err.Error() != "invalid absolute path" {
		t.Fatalf("non-clean key path error = %v", err)
	}
	if _, err := readSecureKey(filepath.Join(realDirectory, "missing.key")); err == nil || err.Error() != "open failed" {
		t.Fatalf("missing key error = %v", err)
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
	current := []byte("current-challenge-hmac-key-material-001")
	previous := []byte("previous-challenge-hmac-key-material-02")
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
		SchemaVersion: SchemaVersion, PolicyVersion: 1, Algorithm: AlgorithmHMACSHA256,
		CookieName: "__Host-cdnca_challenge", TrustedProxies: []string{},
		BypassRoutes: []BypassRoute{
			{Kind: BypassPrefix, Path: "/.well-known/acme-challenge/"},
			{Kind: BypassPrefix, Path: "/api/"},
			{Kind: BypassExact, Path: "/healthz"},
		},
		CurrentKey:  KeyRef{KeyID: "key-2", KeyFile: keys.currentPath},
		PreviousKey: &KeyRef{KeyID: "key-1", KeyFile: keys.previousPath},
		Rules:       []Rule{delayRule(), clickRule()},
	}
}

func sliderRule() Rule {
	return Rule{
		RuleID: "slider", Priority: 30, TenantID: "tenant-a", SiteID: "site-c", Host: "edge-c.test", Mode: ModeSlider,
		MinDelaySeconds: 0, ChallengeTTLSeconds: 20, PassTTLSeconds: 30, ClockSkewSeconds: 1,
		AttemptsPerNonce: 1, FailureWindowSeconds: 60, MaxFailuresPerWindow: 5,
		IPBinding: IPBindingExact, BindUserAgent: true,
	}
}

func captchaRule() Rule {
	return Rule{
		RuleID: "captcha", Priority: 40, TenantID: "tenant-a", SiteID: "site-d", Host: "edge-d.test", Mode: ModeCaptcha,
		MinDelaySeconds: 0, ChallengeTTLSeconds: 20, PassTTLSeconds: 30, ClockSkewSeconds: 1,
		AttemptsPerNonce: 1, FailureWindowSeconds: 60, MaxFailuresPerWindow: 5,
		IPBinding: IPBindingExact, BindUserAgent: true,
	}
}

func delayRule() Rule {
	return Rule{
		RuleID: "delay", Priority: 10, TenantID: "tenant-a", SiteID: "site-a", Host: "EDGE-A.TEST.", Mode: ModeDelay,
		MinDelaySeconds: 5, ChallengeTTLSeconds: 20, PassTTLSeconds: 30, ClockSkewSeconds: 1,
		AttemptsPerNonce: 1, FailureWindowSeconds: 60, MaxFailuresPerWindow: 5,
		IPBinding: IPBindingExact, BindUserAgent: true,
	}
}

func clickRule() Rule {
	return Rule{
		RuleID: "click", Priority: 20, TenantID: "tenant-a", SiteID: "site-b", Host: "edge-b.test", Mode: ModeClick,
		MinDelaySeconds: 0, ChallengeTTLSeconds: 20, PassTTLSeconds: 30, ClockSkewSeconds: 1,
		AttemptsPerNonce: 1, FailureWindowSeconds: 60, MaxFailuresPerWindow: 5,
		IPBinding: IPBindingExact, BindUserAgent: true,
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

func TestKeyFixturesAreLongEnough(t *testing.T) {
	keys := makeKeys(t)
	if len(keys.currentSecret) < MinKeyBytes || len(keys.previousSecret) < MinKeyBytes || strings.Contains(string(keys.currentSecret), "\n") {
		t.Fatal("test key fixture is invalid")
	}
}
