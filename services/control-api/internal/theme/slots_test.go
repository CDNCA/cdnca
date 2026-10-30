package theme

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// Console theme activations name a slot (migration 466): no body is both
// consoles as before, {"slot":"admin"|"user"|"all"} names one.
func TestActivationSlotFromBody(t *testing.T) {
	service := &fakeHTTPService{}
	handler := newTestHandler(t, service, "platform")
	sha := strings.Repeat("c", 64)
	path := "/v1/admin/themes/packages/" + sha + "/activate"
	headers := map[string]string{"Authorization": "Bearer token", "If-Match": `"3"`}
	for body, want := range map[string]string{"": SlotAll, `{"slot":"all"}`: SlotAll, `{"slot":"admin"}`: SlotAdmin, `{"slot":"user"}`: SlotUser} {
		service.slot = ""
		recorder := serve(handler, http.MethodPost, path, body, headers)
		if recorder.Code != http.StatusOK || service.slot != want {
			t.Fatalf("body %q: %d slot %q, want %q", body, recorder.Code, service.slot, want)
		}
	}
	for _, body := range []string{`{"slot":"site"}`, `{"slot":"ADMIN"}`, `{"slot":"user","x":1}`, `{"slots":["user"]}`, `[]`, `x`} {
		service.slot = "untouched"
		if recorder := serve(handler, http.MethodPost, path, body, headers); recorder.Code != http.StatusBadRequest || service.slot != "untouched" {
			t.Fatalf("body %q: %d slot %q", body, recorder.Code, service.slot)
		}
	}
}

// Only official themes may restyle the admin console: built in, the
// operator's own uploads and copies, or the io.cdnca market namespace.
func TestOfficialConsoleTheme(t *testing.T) {
	for id, want := range map[string]bool{
		"default": true, "official.tech": true, "custom.mine": true,
		"market.io.cdnca.tech": true, "market.io.cdnca.x.y": true,
		"market.acme.blue": false, "market.io.cdnc.blue": false, "market.io.cdnca-fake.x": false, "market.iocdnca.x": false,
	} {
		if got := OfficialConsoleTheme(id); got != want {
			t.Errorf("%s: %v, want %v", id, got, want)
		}
	}
}

func TestAdminSlotOfficialOnlyIsForbidden(t *testing.T) {
	if !errors.Is(ErrAdminSlotOfficialOnly, ErrAdminSlotOfficialOnly) || failureReason(ErrAdminSlotOfficialOnly) != "admin_slot_official_only" {
		t.Fatal("refusal reason")
	}
}

// The sign-in page style is public, CSS only, and its images are served
// with a sandboxing CSP.
func TestAuthStyleRoutes(t *testing.T) {
	handler := newTestHandler(t, &fakeHTTPService{}, "platform")
	style := serve(handler, http.MethodGet, AuthStylePath, "", nil)
	if style.Code != http.StatusOK || style.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("auth style = %d %v", style.Code, style.Header())
	}
	var body AuthStyle
	if err := json.Unmarshal(style.Body.Bytes(), &body); err != nil || body.CSS == "" || !strings.HasPrefix(body.Images["bg"], AuthStylePath+"/assets/") {
		t.Fatalf("auth style body %s: %v", style.Body, err)
	}
	if recorder := serve(handler, http.MethodPost, AuthStylePath, "{}", nil); recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST auth style = %d", recorder.Code)
	}
	image := serve(handler, http.MethodGet, AuthStylePath+"/assets/"+strings.Repeat("e", 64), "", nil)
	if image.Code != http.StatusOK || !strings.Contains(image.Header().Get("Content-Security-Policy"), "sandbox") ||
		image.Header().Get("Content-Type") != "image/png" {
		t.Fatalf("auth style image = %d %v", image.Code, image.Header())
	}
	if recorder := serve(handler, http.MethodGet, AuthStylePath+"/assets/"+strings.Repeat("f", 64), "", nil); recorder.Code != http.StatusNotFound {
		t.Fatalf("unknown auth style image = %d", recorder.Code)
	}
	if recorder := serve(handler, http.MethodGet, AuthStylePath+"/assets/../x", "", nil); recorder.Code != http.StatusNotFound {
		t.Fatalf("climbing auth style image = %d", recorder.Code)
	}
}
