package brandassethttp

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/brandasset"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

type fakeBrandAssetService struct {
	public brandasset.PublicAsset
}

func (f fakeBrandAssetService) Get(context.Context, brandasset.Actor, brandasset.Slot) (brandasset.Asset, error) {
	return brandasset.Asset{}, brandasset.ErrNotFound
}
func (f fakeBrandAssetService) List(context.Context, brandasset.Actor) ([]brandasset.Asset, error) {
	return nil, nil
}
func (f fakeBrandAssetService) Upload(context.Context, brandasset.Actor, brandasset.UploadRequest) (brandasset.Asset, error) {
	return brandasset.Asset{}, brandasset.ErrUnavailable
}
func (f fakeBrandAssetService) OpenPublic(context.Context, brandasset.Slot) (brandasset.PublicAsset, error) {
	return f.public, nil
}

func TestPublicBrandAssetIsReadableWithoutSession(t *testing.T) {
	body := []byte("png-bytes")
	h, err := New(fakeBrandAssetService{public: brandasset.PublicAsset{Asset: brandasset.Asset{
		Schema: brandasset.Schema(), Slot: brandasset.SlotLogo, Revision: 2, MIMEType: "image/png", SizeBytes: int64(len(body)), SHA256: "abc123",
		UpdatedAt: time.Unix(10, 0),
	}, Body: io.NopCloser(bytes.NewReader(body))}}, func(*http.Request, string) (identity.AuthenticatedSession, error) {
		return identity.AuthenticatedSession{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/brand-assets/logo", nil)
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusOK || res.Header().Get("Content-Type") != "image/png" || res.Header().Get("ETag") != `"abc123"` || res.Body.String() != string(body) {
		t.Fatalf("public response = status %d headers=%v body=%q", res.Code, res.Header(), res.Body.String())
	}
}

func TestPublicBrandAssetHonorsNotModified(t *testing.T) {
	h, err := New(fakeBrandAssetService{public: brandasset.PublicAsset{Asset: brandasset.Asset{
		Slot: brandasset.SlotFavicon, Revision: 1, MIMEType: "image/png", SizeBytes: 1, SHA256: "deadbeef",
	}, Body: io.NopCloser(bytes.NewReader([]byte{1}))}}, func(*http.Request, string) (identity.AuthenticatedSession, error) {
		return identity.AuthenticatedSession{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/brand-assets/favicon", nil)
	req.Header.Set("If-None-Match", `"deadbeef"`)
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusNotModified {
		t.Fatalf("status = %d, want 304", res.Code)
	}
}

func TestPublicBrandAssetAllowsNumericCacheBuster(t *testing.T) {
	body := []byte("png-bytes")
	h, err := New(fakeBrandAssetService{public: brandasset.PublicAsset{Asset: brandasset.Asset{
		Slot: brandasset.SlotFavicon, MIMEType: "image/png", SizeBytes: int64(len(body)), SHA256: "abc123",
	}, Body: io.NopCloser(bytes.NewReader(body))}}, func(*http.Request, string) (identity.AuthenticatedSession, error) {
		return identity.AuthenticatedSession{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/brand-assets/favicon?v=1788244903194", nil)
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusOK || res.Body.String() != string(body) {
		t.Fatalf("public cache-busted response = status %d body %q", res.Code, res.Body.String())
	}
}

func TestPublicBrandAssetRejectsUnexpectedQuery(t *testing.T) {
	for _, rawQuery := range []string{"v=", "v=1&v=2", "cache=1", "v=1.0", "v=%31"} {
		t.Run(rawQuery, func(t *testing.T) {
			h, err := New(fakeBrandAssetService{}, func(*http.Request, string) (identity.AuthenticatedSession, error) {
				return identity.AuthenticatedSession{}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodGet, "/v1/brand-assets/favicon?"+rawQuery, nil)
			res := httptest.NewRecorder()
			h.ServeHTTP(res, req)
			if res.Code != http.StatusMethodNotAllowed {
				t.Fatalf("status = %d, want 405", res.Code)
			}
		})
	}
}

func TestPublicBrandAssetRejectsUnsupportedRoute(t *testing.T) {
	h, err := New(fakeBrandAssetService{}, func(*http.Request, string) (identity.AuthenticatedSession, error) {
		return identity.AuthenticatedSession{SessionID: uuid.New()}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/brand-assets/logo/extra", nil)
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", res.Code)
	}
}

func TestHandlerDistinguishesTenantDenialFromInvalidSession(t *testing.T) {
	tenantID := uuid.New()
	validTenant := identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant", TenantID: &tenantID}}
	for _, tc := range []struct {
		name    string
		session identity.AuthenticatedSession
		status  int
	}{
		{"authenticated tenant", validTenant, http.StatusForbidden},
		{"missing session", identity.AuthenticatedSession{Principal: validTenant.Principal}, http.StatusUnauthorized},
		{"missing identity", identity.AuthenticatedSession{SessionID: uuid.New()}, http.StatusUnauthorized},
	} {
		for _, method := range []string{http.MethodGet, http.MethodPut} {
			t.Run(tc.name+"/"+method, func(t *testing.T) {
				handler, err := New(fakeBrandAssetService{}, func(*http.Request, string) (identity.AuthenticatedSession, error) { return tc.session, nil })
				if err != nil {
					t.Fatal(err)
				}
				request := httptest.NewRequest(method, baseRoute, nil)
				request.Header.Set("Authorization", "Bearer test-session")
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				if response.Code != tc.status {
					t.Fatalf("status=%d want=%d body=%s", response.Code, tc.status, response.Body.String())
				}
			})
		}
	}
}
