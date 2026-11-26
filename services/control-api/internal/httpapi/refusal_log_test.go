package httpapi

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/accountregistration"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/refusalreason"
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

// Problem 28: a refused built-in CAPTCHA logs its internal reason while the
// response keeps the generic code and never carries the reason.
func TestRefusalLogCarriesRecordedCaptchaReason(t *testing.T) {
	var buf bytes.Buffer
	s := &Server{logger: slog.New(slog.NewTextHandler(&buf, nil))}
	mux := http.NewServeMux()
	// A sub-package writing its own body (accountregistrationchallengehttp).
	mux.HandleFunc("POST /v1/auth/registration-challenges", func(w http.ResponseWriter, r *http.Request) {
		refusalreason.Record(r.Context(), refusalreason.Of(refusalreason.Wrap(errors.New("human invalid"), "captcha_binding_mismatch")))
		writeJSONStatus(w, http.StatusUnprocessableEntity, map[string]any{"error": map[string]string{"code": "account_registration_human_invalid", "request_id": "r1"}})
	})
	mux.HandleFunc("POST /v1/auth/register", func(w http.ResponseWriter, r *http.Request) {
		s.writeBuiltInRegistrationError(w, r, refusalreason.Wrap(accountregistration.ErrCaptchaInvalid, identity.CaptchaReasonExpired))
	})
	mux.HandleFunc("POST /v1/auth/login", func(w http.ResponseWriter, r *http.Request) {
		s.writeLoginSecurityError(w, r, fmt.Errorf("reserve login attempt: %w",
			refusalreason.Wrap(identity.ErrLoginCaptchaInvalid, identity.CaptchaReasonConsumed)))
	})
	h := s.withRefusalLog(mux)
	for _, test := range []struct{ path, code, reason string }{
		{"/v1/auth/registration-challenges", "account_registration_human_invalid", "captcha_binding_mismatch"},
		{"/v1/auth/register", "account_registration_captcha_invalid", "captcha_expired"},
		{"/v1/auth/login", "login_captcha_invalid", "captcha_consumed"},
	} {
		buf.Reset()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("POST", test.path, strings.NewReader("{}")))
		if !strings.Contains(rec.Body.String(), `"code":"`+test.code+`"`) || strings.Contains(rec.Body.String(), test.reason) ||
			strings.Contains(rec.Body.String(), "reason") {
			t.Fatalf("%s response: %d %s", test.path, rec.Code, rec.Body.String())
		}
		got := buf.String()
		if strings.Count(got, "request refused") != 1 || !strings.Contains(got, "code="+test.code) ||
			!strings.Contains(got, "reason="+test.reason) {
			t.Fatalf("%s log: %s", test.path, got)
		}
	}
}
