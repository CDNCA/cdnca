package poolmon

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/dbpoolmon"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

type fixedView Snapshot

func (v fixedView) Snapshot() Snapshot { return Snapshot(v) }

func TestHandlerServesSnapshotToMaintenanceReaders(t *testing.T) {
	at := time.Date(2026, 11, 5, 12, 0, 30, 0, time.UTC)
	cur := Sample{At: at, MaxConns: 20, InUse: 19, ResidentConns: 2, RequestCapacity: 18, Queued: 4, AvgWaitMS: 250,
		Reasons: []string{dbpoolmon.ReasonSaturated}}
	view := fixedView{Instance: "ctl-a", IntervalSeconds: 10, Thresholds: dbpoolmon.CurrentThresholds(), Current: &cur,
		Series: []Sample{cur}, Residents: []database.Resident{{Name: "market_security_listen", InPool: true, Since: at}},
		Firing: true, FiringSince: &at, FiringReasons: []string{dbpoolmon.ReasonSaturated}, Notified: true, LastNotifiedAt: &at}
	tenant := uuid.New()
	sessions := map[string]identity.Principal{
		"reader":   {ScopeKind: "platform", Permissions: []string{"control.upgrades.read"}},
		"admin":    {ScopeKind: "platform", Permissions: []string{"platform.admin"}},
		"operator": {ScopeKind: "platform", Permissions: []string{"nodes.manage"}},
		"tenant":   {ScopeKind: "tenant", TenantID: &tenant, Permissions: []string{"control.upgrades.read"}},
	}
	h := NewHandler(view, func(_ *http.Request, raw string) (identity.AuthenticatedSession, error) {
		principal, ok := sessions[raw]
		if !ok {
			return identity.AuthenticatedSession{}, errors.New("bad token")
		}
		return identity.AuthenticatedSession{SessionID: uuid.New(), Principal: principal}, nil
	})
	call := func(method, path, token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		req.Header.Set("X-Request-ID", "req-1")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	for token, want := range map[string]int{"reader": 200, "admin": 200, "operator": 403, "tenant": 403, "nope": 401, "": 401} {
		if rec := call(http.MethodGet, Route, token); rec.Code != want {
			t.Errorf("%q: status %d, want %d", token, rec.Code, want)
		}
	}
	if rec := call(http.MethodPost, Route, "reader"); rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "GET" {
		t.Fatalf("POST = %d", rec.Code)
	}
	rec := call(http.MethodGet, Route, "nope")
	var failure struct {
		Error struct {
			Code      string `json:"code"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &failure); err != nil || failure.Error.Code != "authentication_required" ||
		failure.Error.RequestID != "req-1" || rec.Header().Get("X-Request-ID") != "req-1" {
		t.Fatalf("401 body %s", rec.Body)
	}
	rec = call(http.MethodGet, Route, "reader")
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("snapshot must not be cached")
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"instance", "interval_seconds", "thresholds", "current", "series", "residents", "firing",
		"firing_since", "firing_reasons", "notified", "last_notified_at", "pending_notifications"} {
		if _, ok := body[key]; !ok {
			t.Errorf("response lacks %q: %s", key, rec.Body)
		}
	}
	current := body["current"].(map[string]any)
	if current["resident_conns"] != 2.0 || current["request_capacity"] != 18.0 || current["in_use"] != 19.0 {
		t.Fatalf("current = %v", current)
	}
}
