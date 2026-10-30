package edgeconfig

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
)

const (
	ccV2BundleTenantID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	ccV2BundleSiteID   = "11111111-1111-4111-8111-111111111111"
	ccV2BundleVersion  = "018f1000-0000-7000-8000-000000000090"
)

func ccV2BundleFiles(bundle Bundle) map[string][]byte {
	files := make(map[string][]byte, len(bundle.Files))
	for path, content := range bundle.Files {
		files[path] = bytes.Clone(content)
	}
	return files
}

func ccV2BundleWithServerLua(t *testing.T, bundle Bundle, block string) Bundle {
	t.Helper()
	files := ccV2BundleFiles(bundle)
	marker := []byte("    server_name cc.example.test;\n")
	markerAt := bytes.Index(files["nginx.conf"], marker)
	if markerAt < 0 {
		t.Fatal("public CC test server was not found")
	}
	insertAt := markerAt + len(marker)
	nginx := make([]byte, 0, len(files["nginx.conf"])+len(block))
	nginx = append(nginx, files["nginx.conf"][:insertAt]...)
	nginx = append(nginx, block...)
	nginx = append(nginx, files["nginx.conf"][insertAt:]...)
	files["nginx.conf"] = nginx
	return ccV2ResealBundle(t, files)
}

func ccV2ResealBundle(t *testing.T, files map[string][]byte) Bundle {
	t.Helper()
	bundle, err := newBundle(files)
	if err != nil {
		t.Fatalf("newBundle() error = %v", err)
	}
	return bundle
}

func ccV2BundlePolicy(t *testing.T, bundle Bundle) CCV2Policy {
	t.Helper()
	policy, err := DecodeCCV2Policy(bundle.Files[ccV2CompiledPath(ccV2BundleSiteID)])
	if err != nil {
		t.Fatalf("DecodeCCV2Policy() error = %v", err)
	}
	policy.TrustedProxies = append([]string{}, policy.TrustedProxies...)
	policy.Allowlist = append([]string{}, policy.Allowlist...)
	policy.Rules = append([]CCV2Rule(nil), policy.Rules...)
	return policy
}

func ccV2BundleRegistry(t *testing.T, bundle Bundle) CCV2Registry {
	t.Helper()
	registry, err := DecodeCCV2RegistryFromNginx(bundle.Files["nginx.conf"])
	if err != nil {
		t.Fatalf("DecodeCCV2RegistryFromNginx() error = %v", err)
	}
	return registry
}

func ccV2BundleSetRegistryCompiledDigest(t *testing.T, files map[string][]byte, digest string) {
	t.Helper()
	registry, err := DecodeCCV2RegistryFromNginx(files["nginx.conf"])
	if err != nil {
		t.Fatal(err)
	}
	previous, err := CanonicalCCV2Registry(registry)
	if err != nil {
		t.Fatal(err)
	}
	for index := range registry.Entries {
		registry.Entries[index].CompiledSHA256 = digest
	}
	next, err := CanonicalCCV2Registry(registry)
	if err != nil {
		t.Fatal(err)
	}
	nginx := bytes.Replace(files["nginx.conf"], previous, next, 1)
	if bytes.Equal(nginx, files["nginx.conf"]) {
		t.Fatal("registry digest mutation did not change nginx")
	}
	files["nginx.conf"] = nginx
}

func ccV2AssertInvalidBundle(t *testing.T, candidate Bundle, checkWire bool) {
	t.Helper()
	before := ccV2BundleDocumentJSON(t, candidate)
	err := ValidateBundle(candidate)
	if after := ccV2BundleDocumentJSON(t, candidate); !bytes.Equal(after, before) {
		t.Fatal("ValidateBundle modified the invalid input")
	}
	if !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("ValidateBundle() error = %v, want ErrInvalidBundle", err)
	}
	if !checkWire {
		return
	}
	if _, err := MarshalBundle(candidate); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("MarshalBundle() error = %v, want ErrInvalidBundle", err)
	}
	var document BundleDocument
	if err := json.Unmarshal(before, &document); err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalBundle(wire); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("UnmarshalBundle(manual document) error = %v, want ErrInvalidBundle", err)
	}
}

func ccV2BundleDocumentJSON(t *testing.T, bundle Bundle) []byte {
	t.Helper()
	content, err := json.Marshal(BundleDocument{
		Version: bundleDocumentVersion, Manifest: bundle.Manifest,
		ManifestSHA256: bundle.ManifestSHA256, Files: bundle.Files,
	})
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func ccV2Digest(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}
