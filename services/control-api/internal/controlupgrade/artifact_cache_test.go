package controlupgrade

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

const testArtifactBaseURL = "https://cdnca.com/downloads/edge-agent/upgrades/sha256"

func artifactDigest(payload []byte) (string, string) {
	sum := sha256.Sum256(payload)
	return base64.RawURLEncoding.EncodeToString(sum[:]), hex.EncodeToString(sum[:])
}

func newTestArtifactCache(t *testing.T, server *httptest.Server) (*ArtifactCache, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "sha256")
	cache, err := NewArtifactCache(root, testArtifactBaseURL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	return cache, root
}

func TestArtifactCacheStoresVerifiedArtifactOnceAndServesControlURL(t *testing.T) {
	payload := bytes.Repeat([]byte("edge-agent-bundle"), 64)
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		_, _ = w.Write(payload)
	}))
	defer server.Close()
	cache, root := newTestArtifactCache(t, server)
	digest, name := artifactDigest(payload)

	for range 2 {
		got, err := cache.Ensure(t.Context(), server.URL+"/artifacts/forward.bundle", digest, int64(len(payload)))
		if err != nil || got != testArtifactBaseURL+"/"+name {
			t.Fatalf("Ensure() = (%q, %v)", got, err)
		}
	}
	if requests != 1 {
		t.Fatalf("license origin requests = %d, want 1 (cached)", requests)
	}
	stored, err := os.ReadFile(filepath.Join(root, name))
	if err != nil || !bytes.Equal(stored, payload) {
		t.Fatalf("cached artifact = (%d bytes, %v)", len(stored), err)
	}
	info, _ := os.Stat(filepath.Join(root, name))
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("cached artifact mode = %v, want 0644 for the console web server", info.Mode().Perm())
	}
}

// Once cached, an artifact keeps being served while the license origin is down.
func TestArtifactCacheServesCachedArtifactWhileLicenseOriginIsDown(t *testing.T) {
	payload := []byte("rollback-bundle")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(payload)
	}))
	cache, _ := newTestArtifactCache(t, server)
	digest, name := artifactDigest(payload)
	if _, err := cache.Ensure(t.Context(), server.URL+"/a", digest, int64(len(payload))); err != nil {
		t.Fatal(err)
	}
	server.Close()
	got, err := cache.Ensure(t.Context(), server.URL+"/a", digest, int64(len(payload)))
	if err != nil || got != testArtifactBaseURL+"/"+name {
		t.Fatalf("Ensure() after license outage = (%q, %v)", got, err)
	}
}

func TestArtifactCacheRejectsBytesThatDoNotMatchTheSignedManifest(t *testing.T) {
	payload := []byte("signed-bytes")
	for name, test := range map[string]struct {
		body []byte
		size int64
		want error
	}{
		"digest mismatch": {body: []byte("tampered!!!!"), size: int64(len(payload)), want: ErrArtifactInvalid},
		"short body":      {body: payload[:4], size: int64(len(payload)), want: ErrArtifactInvalid},
		"long body":       {body: append(append([]byte(nil), payload...), 'x'), size: int64(len(payload)), want: ErrArtifactInvalid},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write(test.body)
			}))
			defer server.Close()
			cache, root := newTestArtifactCache(t, server)
			digest, _ := artifactDigest(payload)
			if _, err := cache.Ensure(t.Context(), server.URL+"/a", digest, test.size); !errors.Is(err, test.want) {
				t.Fatalf("Ensure() error = %v, want %v", err, test.want)
			}
			entries, _ := os.ReadDir(root)
			if len(entries) != 0 {
				t.Fatalf("rejected artifact left %d cache entries", len(entries))
			}
		})
	}
}

func TestArtifactCacheReportsUnavailableLicenseOrigin(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	cache, _ := newTestArtifactCache(t, server)
	digest, _ := artifactDigest([]byte("x"))
	if _, err := cache.Ensure(t.Context(), server.URL+"/a", digest, 1); !errors.Is(err, ErrArtifactUnavailable) {
		t.Fatalf("Ensure() error = %v, want ErrArtifactUnavailable", err)
	}
}

func TestNewArtifactCacheRejectsUnsafeConfiguration(t *testing.T) {
	root := filepath.Join(t.TempDir(), "sha256")
	for name, test := range map[string]struct{ root, base string }{
		"relative root":     {root: "downloads", base: testArtifactBaseURL},
		"filesystem root":   {root: "/", base: testArtifactBaseURL},
		"plain HTTP":        {root: root, base: "http://cdnca.com/downloads"},
		"trailing slash":    {root: root, base: testArtifactBaseURL + "/"},
		"query":             {root: root, base: testArtifactBaseURL + "?x=1"},
		"uppercase host":    {root: root, base: "https://CDNCA.com/downloads"},
		"embedded userinfo": {root: root, base: "https://user@cdnca.com/downloads"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewArtifactCache(test.root, test.base, http.DefaultClient); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("NewArtifactCache() error = %v", err)
			}
		})
	}
	if _, err := NewArtifactCache(root, "https://203.0.113.9:8443/downloads/edge-agent/upgrades/sha256",
		http.DefaultClient); err != nil {
		t.Fatalf("IP literal control origin rejected: %v", err)
	}
	if info, err := os.Stat(root); err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("cache root = (%v, %v), want 0755 directory", info, err)
	}
}
