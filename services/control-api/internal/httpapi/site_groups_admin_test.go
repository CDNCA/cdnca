package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSiteGroupRemarkBody(t *testing.T) {
	for _, raw := range []string{"null", "123", `{}`, `[]`} {
		if _, err := siteGroupRemark(json.RawMessage(raw)); err == nil {
			t.Fatalf("accepted invalid remark %s", raw)
		}
	}
	if value, err := siteGroupRemark(nil); err != nil || value != nil {
		t.Fatalf("omission: %v %v", value, err)
	}
	for _, raw := range []string{`""`, `"first\nsecond"`} {
		value, err := siteGroupRemark(json.RawMessage(raw))
		if err != nil || value == nil {
			t.Fatalf("explicit string: %v %v", value, err)
		}
	}
}

func TestSiteGroupAdminHandlers(t *testing.T) {
	api := New(nil, nil, Config{})
	for _, handler := range []http.HandlerFunc{api.handleListAdminSiteGroups, api.handleGetSiteGroup} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		handler(w, r)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("missing service status %d", w.Code)
		}
	}
	for _, authorization := range []string{"", "Bearer", "Bearer one two", "Basic opaque"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", authorization)
		if _, ok := api.siteGroupActor(w, r); ok || w.Code != http.StatusUnauthorized {
			t.Fatalf("invalid credential status %d", w.Code)
		}
	}
}
