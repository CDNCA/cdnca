package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/controlplaneupgrade"
	"github.com/cdnca/cdnca/services/control-api/internal/controlplaneupgradehttp"
	"github.com/google/uuid"
)

func TestOPS06HTTPPlanSourceFetchesBoundedExactReplay(t *testing.T) {
	installationID := uuid.NewString()
	bundle := []byte(`{"signed":"plan"}`)
	digest := fmt.Sprintf("%x", sha256.Sum256(bundle))
	etag := `"4:` + digest + `"`
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.URL.Path != controlplaneupgradehttp.SystemdPlanSourcePath ||
			request.Header.Get("Authorization") != "Bearer internal-token-32-bytes-long-value" {
			http.Error(response, "denied", http.StatusUnauthorized)
			return
		}
		response.Header().Set("ETag", etag)
		response.Header().Set(controlplaneupgradehttp.SystemdPlanInstallationHeader, installationID)
		response.Header().Set(controlplaneupgradehttp.SystemdPlanOperationHeader, controlplaneupgrade.SystemdControlUpgradeOperation)
		if request.Header.Get("If-None-Match") == etag {
			response.WriteHeader(http.StatusNotModified)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write(bundle)
	}))
	defer server.Close()
	source, err := NewHTTPPlanSource(HTTPPlanSourceConfig{URL: server.URL + controlplaneupgradehttp.SystemdPlanSourcePath,
		InstallationID: installationID, Operation: controlplaneupgrade.SystemdControlUpgradeOperation,
		Token: "internal-token-32-bytes-long-value", HTTPClient: server.Client(), Timeout: time.Second, MaxBodyBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	first, err := source.Fetch(t.Context())
	if err != nil || string(first.Bundle) != string(bundle) || first.ETag != etag || first.Revision != 4 || first.Digest != digest || first.Replayed {
		t.Fatalf("first Fetch() = (%#v, %v)", first, err)
	}
	second, err := source.Fetch(t.Context())
	if err != nil || string(second.Bundle) != string(bundle) || !second.Replayed || requests.Load() != 2 {
		t.Fatalf("second Fetch() = (%#v, %v), requests=%d", second, err, requests.Load())
	}
	first.Bundle[0] ^= 0xff
	third, err := source.Fetch(t.Context())
	if err != nil || string(third.Bundle) != string(bundle) {
		t.Fatalf("cached plan was not cloned: (%q, %v)", third.Bundle, err)
	}
}

func TestOPS06HTTPPlanSourceRejectsTimeoutOversizeRedirectAndCrossBinding(t *testing.T) {
	installationID := uuid.NewString()
	for _, raw := range []string{"http://control.example/v1/internal/control-upgrade/plan",
		"https://user@control.example/v1/internal/control-upgrade/plan",
		"https://127.0.0.1/v1/internal/control-upgrade/plan",
		"https://control.example/v1/internal/control-upgrade/plan?other=1"} {
		if _, err := NewHTTPPlanSource(HTTPPlanSourceConfig{URL: raw, InstallationID: installationID,
			Operation: controlplaneupgrade.SystemdControlUpgradeOperation, Token: "internal-token-32-bytes-long-value"}); !errors.Is(err, ErrHTTPPlanSourceInvalid) {
			t.Errorf("URL %q error = %v", raw, err)
		}
	}

	t.Run("timeout", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) { <-request.Context().Done() }))
		defer server.Close()
		source := newHTTPPlanSourceForTest(t, server, installationID, 1024, 20*time.Millisecond)
		if _, err := source.Fetch(context.Background()); !errors.Is(err, ErrHTTPPlanSourceUnavailable) {
			t.Fatalf("timeout error = %v", err)
		}
	})

	t.Run("oversize", func(t *testing.T) {
		server := httptest.NewTLSServer(boundPlanResponse(installationID, strings.Repeat("x", 1025), 1))
		defer server.Close()
		source := newHTTPPlanSourceForTest(t, server, installationID, 1024, time.Second)
		if _, err := source.Fetch(t.Context()); !errors.Is(err, ErrHTTPPlanSourceInvalid) {
			t.Fatalf("oversize error = %v", err)
		}
	})

	t.Run("redirect", func(t *testing.T) {
		var targetCalls atomic.Int32
		target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { targetCalls.Add(1) }))
		defer target.Close()
		redirect := httptest.NewTLSServer(http.RedirectHandler(target.URL+controlplaneupgradehttp.SystemdPlanSourcePath, http.StatusFound))
		defer redirect.Close()
		source := newHTTPPlanSourceForTest(t, redirect, installationID, 1024, time.Second)
		if _, err := source.Fetch(t.Context()); !errors.Is(err, ErrHTTPPlanSourceUnavailable) || targetCalls.Load() != 0 {
			t.Fatalf("redirect error=%v target calls=%d", err, targetCalls.Load())
		}
	})

	t.Run("cross binding", func(t *testing.T) {
		server := httptest.NewTLSServer(boundPlanResponse(uuid.NewString(), `{"signed":"plan"}`, 1))
		defer server.Close()
		source := newHTTPPlanSourceForTest(t, server, installationID, 1024, time.Second)
		if _, err := source.Fetch(t.Context()); !errors.Is(err, ErrHTTPPlanSourceConflict) {
			t.Fatalf("cross-binding error = %v", err)
		}
	})
}

func newHTTPPlanSourceForTest(t *testing.T, server *httptest.Server, installationID string, maximum int64,
	timeout time.Duration) *HTTPPlanSource {
	t.Helper()
	source, err := NewHTTPPlanSource(HTTPPlanSourceConfig{URL: server.URL + controlplaneupgradehttp.SystemdPlanSourcePath,
		InstallationID: installationID, Operation: controlplaneupgrade.SystemdControlUpgradeOperation,
		Token: "internal-token-32-bytes-long-value", HTTPClient: server.Client(), Timeout: timeout, MaxBodyBytes: maximum})
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func boundPlanResponse(installationID, body string, revision uint64) http.Handler {
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(body)))
	return http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("ETag", fmt.Sprintf(`"%d:%s"`, revision, digest))
		response.Header().Set(controlplaneupgradehttp.SystemdPlanInstallationHeader, installationID)
		response.Header().Set(controlplaneupgradehttp.SystemdPlanOperationHeader, controlplaneupgrade.SystemdControlUpgradeOperation)
		_, _ = response.Write([]byte(body))
	})
}
