package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/announcementhttp"
)

func TestAnnouncementRoutesAreDisabledByDefault(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/v1/admin/announcements", nil)
	response := httptest.NewRecorder()
	New(nil, nil, Config{}).Handler().ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("disabled announcement route status = %d, want 404", response.Code)
	}
	if response.Header().Get("X-Request-ID") == "" {
		t.Fatal("disabled announcement route omitted X-Request-ID")
	}
}

func TestAnnouncementHandlerFactoryFailsClosed(t *testing.T) {
	for _, test := range []struct {
		name    string
		factory AnnouncementHandlerFactory
	}{
		{name: "error", factory: func(announcementhttp.AuthenticateFunc) (http.Handler, error) {
			return nil, errors.New("factory failed")
		}},
		{name: "nil handler", factory: func(announcementhttp.AuthenticateFunc) (http.Handler, error) {
			return nil, nil
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), AnnouncementHandlerFactory: test.factory})
			if api.InitializationError() == nil {
				t.Fatal("announcement factory failure was not retained")
			}
		})
	}
}

func TestAnnouncementRoutesForwardOnlyExactOwnedMethodAndPath(t *testing.T) {
	type route struct{ method, path string }
	routes := []route{
		{http.MethodGet, "/v1/admin/announcements"},
		{http.MethodPost, "/v1/admin/announcements"},
		{http.MethodGet, "/v1/admin/announcements/global"},
		{http.MethodPost, "/v1/admin/announcements/global"},
		{http.MethodGet, "/v1/admin/announcements/global/audience-directory"},
		{http.MethodGet, "/v1/admin/announcements/global/33333333-3333-4333-8333-333333333333"},
		{http.MethodGet, "/v1/admin/announcements/global/33333333-3333-4333-8333-333333333333/audience/count"},
		{http.MethodPatch, "/v1/admin/announcements/global/33333333-3333-4333-8333-333333333333"},
		{http.MethodPost, "/v1/admin/announcements/global/33333333-3333-4333-8333-333333333333/publish"},
		{http.MethodPost, "/v1/admin/announcements/global/33333333-3333-4333-8333-333333333333/withdraw"},
		{http.MethodPost, "/v1/admin/announcements/global/33333333-3333-4333-8333-333333333333/archive"},
		{http.MethodPost, "/v1/admin/announcements/global/33333333-3333-4333-8333-333333333333/restore"},
		{http.MethodGet, "/v1/admin/announcements/audience-directory"},
		{http.MethodGet, "/v1/admin/announcements/11111111-1111-4111-8111-111111111111"},
		{http.MethodGet, "/v1/admin/announcements/11111111-1111-4111-8111-111111111111/audience/count"},
		{http.MethodPatch, "/v1/admin/announcements/11111111-1111-4111-8111-111111111111"},
		{http.MethodPost, "/v1/admin/announcements/11111111-1111-4111-8111-111111111111/schedule"},
		{http.MethodPost, "/v1/admin/announcements/11111111-1111-4111-8111-111111111111/publish"},
		{http.MethodPost, "/v1/admin/announcements/11111111-1111-4111-8111-111111111111/revise"},
		{http.MethodPost, "/v1/admin/announcements/11111111-1111-4111-8111-111111111111/withdraw"},
		{http.MethodPost, "/v1/admin/announcements/11111111-1111-4111-8111-111111111111/archive"},
		{http.MethodPost, "/v1/admin/announcements/11111111-1111-4111-8111-111111111111/restore"},
		{http.MethodGet, "/v1/account/messages"},
		{http.MethodPost, "/v1/account/messages/22222222-2222-4222-8222-222222222222/delivered"},
		{http.MethodPost, "/v1/account/messages/22222222-2222-4222-8222-222222222222/read"},
	}
	var authenticate announcementhttp.AuthenticateFunc
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), AnnouncementHandlerFactory: func(candidate announcementhttp.AuthenticateFunc) (http.Handler, error) {
		authenticate = candidate
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if request.Header.Get("X-Request-ID") != "normalized-request" {
				t.Errorf("forwarded request ID = %q", request.Header.Get("X-Request-ID"))
			}
			if strings.Contains(request.URL.Path, "/announcements/") && request.URL.Path != "/v1/admin/announcements/global" && !strings.HasSuffix(request.URL.Path, "/audience-directory") && request.PathValue("id") == "" {
				t.Error("announcement path value was not preserved")
			}
			if strings.Contains(request.URL.Path, "/messages/") && request.PathValue("event_id") == "" {
				t.Error("message path value was not preserved")
			}
			if request.Body != nil {
				body, err := io.ReadAll(request.Body)
				if err != nil || string(body) != "payload" {
					t.Errorf("forwarded body = %q, err=%v", body, err)
				}
			}
			response.WriteHeader(http.StatusNoContent)
		}), nil
	}})
	if err := api.InitializationError(); err != nil {
		t.Fatal(err)
	}
	if authenticate == nil {
		t.Fatal("announcement authenticator was not injected")
	}
	invalid := httptest.NewRequest(http.MethodGet, "/", nil)
	invalid.Header.Set("Authorization", "CdncaKey workload-credential")
	if _, err := authenticate(invalid); err == nil {
		t.Fatal("announcement authenticator accepted CdncaKey")
	}

	handler := api.Handler()
	for _, route := range routes {
		request := httptest.NewRequest(route.method, route.path, strings.NewReader("payload"))
		request.Header.Set("X-Request-ID", "normalized-request")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNoContent {
			t.Errorf("%s %s status = %d", route.method, route.path, response.Code)
		}
		if response.Header().Get("X-Request-ID") != "normalized-request" {
			t.Errorf("%s %s response request ID = %q", route.method, route.path, response.Header().Get("X-Request-ID"))
		}
	}

	for _, adjacent := range []string{
		"/v1/admin/announcements-extra",
		"/v1/admin/announcements/11111111-1111-4111-8111-111111111111/history",
		"/v1/account/messages-extra",
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, adjacent, nil))
		if response.Code != http.StatusNotFound {
			t.Errorf("adjacent route %s status = %d, want 404", adjacent, response.Code)
		}
	}
}

func TestAnnouncementRoutesRejectOversizedCursorBeforeForwarding(t *testing.T) {
	forwarded := false
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), AnnouncementHandlerFactory: func(announcementhttp.AuthenticateFunc) (http.Handler, error) {
		return http.HandlerFunc(func(http.ResponseWriter, *http.Request) { forwarded = true }), nil
	}})
	request := httptest.NewRequest(http.MethodGet, "/v1/account/messages?cursor="+strings.Repeat("a", 513), nil)
	response := httptest.NewRecorder()
	api.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("oversized cursor status = %d, want 400", response.Code)
	}
	if forwarded {
		t.Fatal("oversized cursor reached announcement handler")
	}
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil || body.Error.Code != "validation_error" {
		t.Fatalf("oversized cursor error = %+v, decode err=%v", body, err)
	}
}
