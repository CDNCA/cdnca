package analytics

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRealtimeQueryVersionPreservesCachedLegacyClients(t *testing.T) {
	from := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)
	store := &realtimeStoreFixture{result: validRealtimeResult(from, to)}
	service, _ := NewService(store)
	handler, _ := NewHandler(service, func(*http.Request) (Actor, error) {
		return Actor{ScopeKind: "platform", Permissions: []string{"platform.admin"}}, nil
	}, HandlerConfig{})
	path := "/v1/admin/analytics/site-realtime?from=" + from.Format(time.RFC3339) + "&to=" + to.Format(time.RFC3339)
	for _, version := range []string{"", "&query_version=2"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path+version, nil))
		var response struct {
			Data map[string]json.RawMessage `json:"data"`
			Meta map[string]json.RawMessage `json:"meta"`
		}
		if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &response) != nil {
			t.Fatalf("version %q: status=%d body=%s", version, recorder.Code, recorder.Body.String())
		}
		var points []map[string]json.RawMessage
		var evidence map[string]json.RawMessage
		if json.Unmarshal(response.Data["series"], &points) != nil || len(points) != 1 || json.Unmarshal(response.Data["evidence"], &evidence) != nil {
			t.Fatal("invalid series/evidence")
		}
		if version == "" {
			if len(response.Data) != 5 || len(points[0]) != 5 || len(evidence) != 7 || len(response.Meta) != 4 {
				t.Fatalf("legacy exact keys changed: %s", recorder.Body.String())
			}
		} else if len(response.Data) != 6 || len(points[0]) != 13 || len(evidence) != 10 || string(response.Meta["query_version"]) != "2" {
			t.Fatalf("minute contract: %s", recorder.Body.String())
		}
	}
	for _, suffix := range []string{"&query_version=", "&query_version=1", "&query_version=5", "&query_version=2&query_version=2"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path+suffix, nil))
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("unsupported version %q: %d", suffix, recorder.Code)
		}
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/admin/analytics/site-realtime?from=2026-09-25T10:17:00Z&to=2026-09-25T10:47:00Z", nil))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("legacy minute query accepted: %d", recorder.Code)
	}
}
