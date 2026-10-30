package errorpagecontrol

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// GET /v1/error-pages/assets/{id}/content returns the body
// of a ready asset (错误页面 editing); PUT stays the upload.
func TestHandlerAssetContentRead(t *testing.T) {
	t.Parallel()
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform"}
	handler, err := NewHandler(&fakeHTTPDomain{asset: Asset{ID: uuid.New(), Status: StatusReady}}, fixedAuthenticator{actor: actor})
	if err != nil {
		t.Fatal(err)
	}
	path := "http://control.test/v1/error-pages/assets/" + uuid.NewString() + "/content"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"content":"\u003ch1\u003ex\u003c/h1\u003e"`) {
		t.Fatalf("code=%d body=%s", response.Code, response.Body.String())
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path+"?x=1", nil))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("unknown query code=%d", response.Code)
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, nil))
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST code=%d", response.Code)
	}
}
