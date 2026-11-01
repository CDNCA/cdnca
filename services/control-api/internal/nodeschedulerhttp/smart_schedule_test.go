package nodeschedulerhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type smartFakeService struct {
	*fakeService
	put       nodescheduler.SmartScheduleSettings
	putCalled bool
	requestID string
	window    int
}

func (service *smartFakeService) GetSmartSchedule(_ context.Context, _ nodescheduler.Actor, _ uuid.UUID,
	_ nodescheduler.SmartScheduleReader) (nodescheduler.SmartSchedule, error) {
	settings := nodescheduler.DefaultSmartScheduleSettings()
	if service.putCalled {
		settings = service.put
	}
	return nodescheduler.SmartSchedule{SmartScheduleSettings: settings, Lines: []any{},
		ProbeSource: map[string]bool{"dnspup": false, "peer_nodes": true}, Revision: 2}, nil
}

func (service *smartFakeService) PutSmartSchedule(_ context.Context, _ nodescheduler.Actor, _ uuid.UUID,
	settings nodescheduler.SmartScheduleSettings, requestID string) (nodescheduler.SmartScheduleSettings, int64, error) {
	if settings.TopN > 20 {
		return nodescheduler.SmartScheduleSettings{}, 0, nodescheduler.ErrInvalidInput
	}
	settings.Fallback = "carrier_then_default"
	service.put, service.putCalled, service.requestID = settings, true, requestID
	return settings, 2, nil
}

func (service *smartFakeService) LatencyMatrix(_ context.Context, _ nodescheduler.Actor, _ uuid.UUID, window int,
	_ nodescheduler.SmartScheduleReader) (any, error) {
	service.window = window
	return map[string]any{"rows": []any{}}, nil
}

type nopSmartReader struct{}

func (nopSmartReader) Lines(context.Context, pgx.Tx, uuid.UUID, uuid.UUID, int64) (any, error) {
	return nil, nil
}
func (nopSmartReader) ProbeSource(context.Context, pgx.Tx) (any, error) { return nil, nil }
func (nopSmartReader) Matrix(context.Context, pgx.Tx, uuid.UUID, uuid.UUID, int) (any, error) {
	return nil, nil
}
func (nopSmartReader) ProvinceLines(context.Context, pgx.Tx, uuid.UUID, uuid.UUID) (bool, error) {
	return false, nil
}

func TestSmartScheduleRoutes(t *testing.T) {
	service := &smartFakeService{fakeService: &fakeService{}}
	handler, err := NewHandler(service, &staticAuthenticator{actor: nodescheduler.Actor{UserID: uuid.New(),
		ScopeID: uuid.New(), ScopeKind: "tenant"}})
	if err != nil {
		t.Fatal(err)
	}
	groupID := uuid.NewString()
	// Without a reader the routes are unavailable.
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/node-line-groups/"+groupID+"/smart-schedule", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("no reader = %d", recorder.Code)
	}
	handler.WithSmartSchedule(nopSmartReader{})

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/node-line-groups/"+groupID+"/smart-schedule", nil))
	var view map[string]any
	if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &view) != nil || view["enabled"] != false ||
		view["top_n"] != float64(3) || view["fallback"] != "carrier_then_default" || recorder.Header().Get("ETag") != `"2"` {
		t.Fatalf("GET = %d %s", recorder.Code, recorder.Body.String())
	}

	put := func(body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPut, "/v1/node-line-groups/"+groupID+"/smart-schedule", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", "smart-1")
		request.Header.Set("X-Request-ID", "smart-req-1")
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder
	}
	full := `{"enabled":true,"top_n":5,"granularity":"province_carrier","latency_window_minutes":30,"max_load_percent":70}`
	if recorder := put(full); recorder.Code != http.StatusOK || !service.put.Enabled || service.put.TopN != 5 ||
		service.put.Granularity != "province_carrier" || service.requestID != "smart-req-1" {
		t.Fatalf("PUT = %d %s %+v", recorder.Code, recorder.Body.String(), service.put)
	}
	for _, body := range []string{
		`{"enabled":true}`, // every field is required
		`{"enabled":true,"top_n":5,"granularity":"carrier","latency_window_minutes":30,"max_load_percent":70,"x":1}`,
		`{"enabled":true,"top_n":21,"granularity":"carrier","latency_window_minutes":30,"max_load_percent":70}`,
	} {
		if recorder := put(body); recorder.Code != http.StatusBadRequest {
			t.Fatalf("PUT %s = %d", body, recorder.Code)
		}
	}

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/node-line-groups/"+groupID+"/latency-matrix?window=30", nil))
	if recorder.Code != http.StatusOK || service.window != 30 || !strings.Contains(recorder.Body.String(), `"rows":[]`) {
		t.Fatalf("matrix = %d %s", recorder.Code, recorder.Body.String())
	}
	for _, query := range []string{"?window=0", "?window=61", "?window=a", "?window=5&window=6"} {
		recorder = httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/node-line-groups/"+groupID+"/latency-matrix"+query, nil))
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("matrix %s = %d", query, recorder.Code)
		}
	}
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodDelete, "/v1/node-line-groups/"+groupID+"/smart-schedule", nil))
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE = %d", recorder.Code)
	}
}
