package marketsubscribehttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestLicenseAdvisoryClientExchange(t *testing.T) {
	installation, advisory := uuid.New(), uuid.New()
	var bodies []map[string]any
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != activationPath || r.Method != http.MethodPost || r.Header.Get("X-Request-ID") == "" {
			t.Errorf("request %s %s", r.Method, r.URL.Path)
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		bodies = append(bodies, body)
		switch body["schema"] {
		case advisorySyncSchema:
			auth := uuid.NewString()
			row := map[string]any{"advisory_id": advisory, "plugin_id": "acme.waf", "plugin_version": "1.4.0",
				"affected_versions": "<1.4.2", "fixed_version": "1.4.2", "severity": "high", "action": "disable",
				"title_zh_cn": "规则绕过", "body_zh_cn": "升级", "authorization_id": auth, "disabled_by_advisory": true,
				"published_at": "2026-10-16T00:00:00Z", "delivered_at": "2026-10-16T00:01:00Z"}
			second := map[string]any{}
			for k, v := range row {
				second[k] = v
			}
			second["authorization_id"], second["plugin_version"] = uuid.NewString(), "1.3.0"
			_ = json.NewEncoder(w).Encode(map[string]any{"schema": advisorySyncSchema, "installation_id": installation,
				"advisories": []any{row, second}})
		case advisoryAckSchema:
			_ = json.NewEncoder(w).Encode(map[string]any{"advisory_id": body["advisory_id"], "acknowledged_at": "2026-10-16T01:00:00Z"})
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()
	client, err := NewLicenseAdvisoryClient(server.URL+"/", server.Client(), installation)
	if err != nil {
		t.Fatal(err)
	}
	items, err := client.Delivered(context.Background())
	if err != nil || len(items) != 1 || items[0].ID != advisory || items[0].Title != "规则绕过" || items[0].Action != "disable" ||
		!items[0].PublishedAt.Equal(time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("delivered (one row per advisory): %+v %v", items, err)
	}
	if err := client.Acknowledge(context.Background(), advisory); err != nil {
		t.Fatal(err)
	}
	if len(bodies) != 2 || bodies[0]["installation_id"] != installation.String() || bodies[1]["advisory_id"] != advisory.String() {
		t.Fatalf("bodies %v", bodies)
	}
	if _, err := NewLicenseAdvisoryClient("http://plain.example", server.Client(), installation); err == nil {
		t.Fatal("plain http accepted")
	}
}

func TestLicenseAdvisoryClientOlderLicenseService(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"code":"invalid_request"}`))
	}))
	defer server.Close()
	client, _ := NewLicenseAdvisoryClient(server.URL, server.Client(), uuid.New())
	if _, err := client.Delivered(context.Background()); !errors.Is(err, ErrAdvisoryUnsupported) {
		t.Fatalf("older license service: %v", err)
	}
}

type fakeUpstream struct {
	delivered []Advisory
	acked     []uuid.UUID
	ackErr    error
}

func (f *fakeUpstream) Delivered(context.Context) ([]Advisory, error) { return f.delivered, nil }
func (f *fakeUpstream) Acknowledge(_ context.Context, id uuid.UUID) error {
	if f.ackErr != nil {
		return f.ackErr
	}
	f.acked = append(f.acked, id)
	return nil
}

type fakeAdvisoryStorage struct {
	replaced []Advisory
	pending  []uuid.UUID
	reported []uuid.UUID
}

func (f *fakeAdvisoryStorage) ReplaceDelivered(_ context.Context, d []Advisory) error {
	f.replaced = d
	return nil
}
func (f *fakeAdvisoryStorage) UnreportedPlatformAcks(context.Context) ([]uuid.UUID, error) {
	return f.pending, nil
}
func (f *fakeAdvisoryStorage) MarkReported(_ context.Context, id uuid.UUID) error {
	f.reported = append(f.reported, id)
	return nil
}

func TestAdvisorySyncPullsThenReports(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	upstream := &fakeUpstream{delivered: []Advisory{{ID: a}}, ackErr: errors.New("down")}
	store := &fakeAdvisoryStorage{pending: []uuid.UUID{a, b}}
	sync := NewAdvisorySync(upstream, store, time.Minute, nil)
	if err := sync.Once(context.Background()); err == nil || len(store.replaced) != 1 || len(store.reported) != 0 {
		t.Fatalf("ack failure must leave acks unreported: err=%v reported=%v", err, store.reported)
	}
	upstream.ackErr = nil
	if err := sync.Report(context.Background()); err != nil || len(upstream.acked) != 2 || len(store.reported) != 2 ||
		store.reported[0] != a || store.reported[1] != b {
		t.Fatalf("report: %v acked=%v reported=%v", err, upstream.acked, store.reported)
	}
}
