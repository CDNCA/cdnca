package httpapi

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWithRefusalLogLogsSubPackageErrors(t *testing.T) {
	var buf bytes.Buffer
	s := &Server{logger: slog.New(slog.NewTextHandler(&buf, nil))}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/x/{id}", func(w http.ResponseWriter, r *http.Request) {
		writeJSONStatus(w, http.StatusForbidden, map[string]any{"error": map[string]string{"code": "cc_forbidden", "message": "no access"}})
	})
	mux.HandleFunc("GET /v1/y", func(w http.ResponseWriter, r *http.Request) {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "bad_input"})
	})
	mux.HandleFunc("GET /v1/z", func(w http.ResponseWriter, r *http.Request) {
		s.writeAPIError(w, r, http.StatusConflict, "dup", "already there")
	})
	mux.HandleFunc("GET /v1/ok", func(w http.ResponseWriter, r *http.Request) { writeJSONStatus(w, 200, map[string]string{}) })
	h := s.withRefusalLog(mux)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/v1/x/secret-id", strings.NewReader("{}")))
	if rec.Code != 403 || !strings.Contains(rec.Body.String(), "cc_forbidden") {
		t.Fatalf("response changed: %d %s", rec.Code, rec.Body.String())
	}
	got := buf.String()
	for _, want := range []string{"request refused", "status=403", "code=cc_forbidden", `reason="no access"`, `route="POST /v1/x/{id}"`} {
		if !strings.Contains(got, want) {
			t.Fatalf("log missing %q: %s", want, got)
		}
	}
	if strings.Contains(got, "secret-id") {
		t.Fatalf("log leaked path value: %s", got)
	}

	buf.Reset()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/v1/y", nil))
	if !strings.Contains(buf.String(), "code=bad_input") {
		t.Fatalf("string-shaped error not logged: %s", buf.String())
	}

	buf.Reset()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/v1/z", nil))
	if n := strings.Count(buf.String(), "request refused"); n != 1 {
		t.Fatalf("writeAPIError refusal logged %d times: %s", n, buf.String())
	}

	buf.Reset()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/v1/ok", nil))
	if buf.Len() != 0 {
		t.Fatalf("2xx logged: %s", buf.String())
	}
}
