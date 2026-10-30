package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/installationlock"
)

func TestInstallationLockGate(t *testing.T) {
	t.Cleanup(func() { installationlock.Set(installationlock.Lock{}) })
	server := &Server{}
	reached := 0
	handler := server.withRequestID(server.withInstallationLock(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached++
		w.WriteHeader(http.StatusNoContent)
	})))
	serve := func(method, path string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(method, path, nil))
		return recorder
	}
	if got := serve(http.MethodPost, "/v1/sites").Code; got != http.StatusNoContent {
		t.Fatalf("unlocked write = %d", got)
	}
	until := time.Unix(1_900_000_000, 0).UTC()
	installationlock.Set(installationlock.Lock{Locked: true, Reason: installationlock.ReasonBanned, BanID: "ban-1",
		ReasonCode: "abuse", ReasonText: "滥用", Until: &until})
	for _, write := range [][2]string{{"POST", "/v1/sites"}, {"PATCH", "/v1/nodes/1"}, {"DELETE", "/v1/streams/1"},
		{"PUT", "/v1/dns-settings"}, {"POST", "/v1/admin/billing/adjustments"}, {"POST", "/v1/account/api-keys"}} {
		recorder := serve(write[0], write[1])
		if recorder.Code != http.StatusLocked {
			t.Fatalf("%s %s = %d, want 423", write[0], write[1], recorder.Code)
		}
		var body struct {
			Error struct {
				Code       string     `json:"code"`
				Reason     string     `json:"reason"`
				ReasonText string     `json:"reason_text"`
				Until      *time.Time `json:"until"`
			} `json:"error"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil || body.Error.Code != "installation_locked" ||
			body.Error.Reason != installationlock.ReasonBanned || body.Error.ReasonText != "滥用" ||
			body.Error.Until == nil || !body.Error.Until.Equal(until) {
			t.Fatalf("423 body = %s (%v)", recorder.Body.String(), err)
		}
	}
	reached = 0
	for _, allowed := range [][2]string{{"GET", "/v1/sites"}, {"HEAD", "/v1/sites"}, {"POST", "/v1/auth/login"},
		{"POST", "/v1/auth/logout"}, {"POST", "/v1/auth/refresh"}, {"POST", "/v1/account/password"},
		{"POST", "/v1/account/mfa/totp"}, {"POST", "/v1/installation-lock/check"}} {
		if got := serve(allowed[0], allowed[1]).Code; got != http.StatusNoContent {
			t.Fatalf("%s %s = %d while locked, want allowed", allowed[0], allowed[1], got)
		}
	}
	if reached != 8 {
		t.Fatalf("allowed requests reached %d", reached)
	}
	installationlock.Set(installationlock.Lock{})
	if got := serve(http.MethodPost, "/v1/sites").Code; got != http.StatusNoContent {
		t.Fatalf("unlocked again write = %d", got)
	}
}
