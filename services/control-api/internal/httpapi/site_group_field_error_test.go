package httpapi

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/cdnca/cdnca/services/control-api/internal/sitegroup"
)

// fix-fielderr-be4: writeSiteGroupError keeps details.field of a located refusal.
func TestSiteGroupErrorKeepsLocatedField(t *testing.T) {
	server := &Server{}
	recorder := httptest.NewRecorder()
	server.writeSiteGroupError(recorder, httptest.NewRequest(http.MethodPost, "/v1/site-groups", nil),
		fmt.Errorf("create: %w", fielderr.New(sitegroup.ErrInvalidInput, "name", fielderr.TooLong)))
	assertFieldError(t, recorder, "name", fielderr.TooLong)

	recorder = httptest.NewRecorder()
	server.writeSiteGroupError(recorder, httptest.NewRequest(http.MethodPost, "/v1/site-groups", nil), sitegroup.ErrInvalidInput)
	if recorder.Code != http.StatusBadRequest || decodeFieldError(t, recorder).Error.Details != nil {
		t.Fatalf("unlocated: %d %s", recorder.Code, recorder.Body.String())
	}
}
