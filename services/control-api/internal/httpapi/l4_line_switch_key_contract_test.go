package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/l4lineswitch"
	"github.com/cdnca/cdnca/services/control-api/internal/l4lineswitchhttp"
	"github.com/google/uuid"
)

type l4LineSwitchKeyProbe struct {
	l4lineswitchhttp.Service
	key   string
	calls int
}

func (probe *l4LineSwitchKeyProbe) Start(_ context.Context, request l4lineswitch.StartRequest) (l4lineswitch.Switch, error) {
	probe.key, probe.calls = request.IdempotencyKey, probe.calls+1
	return l4lineswitch.Switch{ID: uuid.New(), ConfigurationScopeID: request.ConfigurationScopeID}, nil
}

func TestL4LineSwitchIdempotencyKeyHTTPBounds(t *testing.T) {
	scopeID, requestID := uuid.New(), uuid.New()
	body := `{"expected_source_revision":1,"from":{"id":"` + uuid.NewString() + `","revision":1,"sha256":"` + strings.Repeat("31", 32) +
		`"},"to":{"id":"` + uuid.NewString() + `","revision":2,"sha256":"` + strings.Repeat("72", 32) +
		`"},"health":{"activation_timeout_ms":60000,"observation_window_ms":30000,"required_consecutive_successes":3},` +
		`"drain":{"health_timeout_ms":30000,"max_drain_ms":600000},"max_attempts":3,"deadline":"2026-09-27T04:00:00Z"}`
	for _, test := range []struct {
		name string
		keys []string
		want int
	}{
		{name: "minimum", keys: []string{"a"}, want: http.StatusCreated},
		{name: "maximum", keys: []string{"a" + strings.Repeat("-", 127)}, want: http.StatusCreated},
		{name: "missing", want: http.StatusBadRequest},
		{name: "empty", keys: []string{""}, want: http.StatusBadRequest},
		{name: "over maximum", keys: []string{strings.Repeat("a", 129)}, want: http.StatusBadRequest},
		{name: "invalid first character", keys: []string{"-a"}, want: http.StatusBadRequest},
		{name: "duplicate", keys: []string{"first", "second"}, want: http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			probe := &l4LineSwitchKeyProbe{}
			handler, err := l4lineswitchhttp.NewHandler(probe, l4lineswitchhttp.AuthenticatorFunc(func(*http.Request) (l4lineswitch.Actor, error) {
				return l4lineswitch.Actor{ScopeKind: "tenant", ScopeID: scopeID, UserID: uuid.New()}, nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "/v1/tenant-scopes/"+scopeID.String()+"/l4-line-switches", strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("X-Request-ID", requestID.String())
			request.Header.Set("Traceparent", "00-11111111111111111111111111111111-2222222222222222-01")
			for _, key := range test.keys {
				request.Header.Add("Idempotency-Key", key)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status=%d want=%d body=%s", response.Code, test.want, response.Body.String())
			}
			if test.want == http.StatusCreated {
				if probe.calls != 1 || probe.key != test.keys[0] {
					t.Fatalf("service calls=%d key=%q", probe.calls, probe.key)
				}
				return
			}
			var body errorEnvelope
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || probe.calls != 0 ||
				body.Error.Code != "l4_line_switch_invalid_request" || body.Error.RequestID != requestID.String() {
				t.Fatalf("service calls=%d body=%s error=%v", probe.calls, response.Body.String(), err)
			}
		})
	}
}
