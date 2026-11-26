package controlplaneupgradehttp

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/controlplaneupgrade"
	"github.com/cdnca/cdnca/services/control-api/internal/controlupgrade"
	"github.com/google/uuid"
)

// nativeWithLicense wires a real LicenseClient to a fake license service.
func nativeWithLicense(t *testing.T, license http.HandlerFunc) *NativeHandler {
	t.Helper()
	handler, _, _, _ := nativeFixture(t)
	server := httptest.NewTLSServer(license)
	t.Cleanup(server.Close)
	client, err := controlupgrade.NewLicenseClient(server.URL, server.Client(), uuid.MustParse(handler.config.InstallationID),
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize)), handler.config.Now)
	if err != nil {
		t.Fatal(err)
	}
	handler.config.License = client
	return handler
}

func TestNativeUpgradeOptionsPassThrough(t *testing.T) {
	var installation string
	handler := nativeWithLicense(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/activation/v1/installations/"+installation+"/upgrade-options:list" {
			t.Fatalf("license path %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"schema":"cdnca.upgrade.options/v1","installation_id":"`+installation+`","component":"control-api",`+
			`"current_version":"1.4.0","current_schema_head":290,"target_mode":"follow_channel","items":[`+
			`{"artifact_id":"00000000-0000-4000-8000-0000000000c1","version":"1.5.0","release_notes":"notes","published_at":1,"operation":"upgrade","control_schema_head":291,"channel_target":true,"pinned":false,"selectable":true,"reason":""}]}`+"\n")
	})
	installation = handler.config.InstallationID
	response := httptest.NewRecorder()
	handler.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, nativePlanPath+"/options", nil))
	var body NativeUpgradeOptions
	var keys map[string]json.RawMessage
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &body) != nil ||
		json.Unmarshal(response.Body.Bytes(), &keys) != nil || len(body.Options.Items) != 1 || body.Options.Items[0].Version != "1.5.0" {
		t.Fatalf("options = %d %s", response.Code, response.Body.String())
	}
	if _, ok := keys["supported"]; ok || len(keys) != 3 {
		t.Fatalf("options keys = %s", response.Body.String())
	}
}

// the options request names the runner-verified
// installed build, and without it the page gets an unconfirmed head instead of a License value.
func TestNativeUpgradeOptionsReportsInstalledArtifact(t *testing.T) {
	var installation, sent string
	handler := nativeWithLicense(t, func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			CurrentArtifactSHA256 string `json:"current_artifact_sha256"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		sent = body.CurrentArtifactSHA256
		head := "697"
		if sent == strings.Repeat("52", 32) {
			head = "692"
		}
		_, _ = io.WriteString(w, `{"schema":"cdnca.upgrade.options/v1","installation_id":"`+installation+`","component":"control-api",`+
			`"current_version":"1.4.0","current_schema_head":`+head+`,"target_mode":"follow_channel","items":[]}`+"\n")
	})
	installation = handler.config.InstallationID
	options := func() string {
		t.Helper()
		response := httptest.NewRecorder()
		handler.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, nativePlanPath+"/options", nil))
		if response.Code != http.StatusOK {
			t.Fatalf("options = %d %s", response.Code, response.Body.String())
		}
		return response.Body.String()
	}
	if body := options(); sent != strings.Repeat("52", 32) || !strings.Contains(body, `"current_schema_head":692,"target_mode"`) {
		t.Fatalf("installed build options = %s (sent %q)", body, sent)
	}
	for name, status := range map[string]func(*controlplaneupgrade.NativeStandaloneStatus){
		"runner status unreadable": nil,
		"current release unverified": func(status *controlplaneupgrade.NativeStandaloneStatus) {
			*status = controlplaneupgrade.NativeStandaloneStatus{Reason: controlplaneupgrade.NativeReasonCurrentReleaseUnverified,
				InstallationID: status.InstallationID, ProtocolVersion: 2, ArtifactFormat: controlplaneupgrade.NativeManifestSchema}
		},
		"runner reports another version": func(status *controlplaneupgrade.NativeStandaloneStatus) { status.CurrentVersion = "1.3.9" },
	} {
		t.Run(name, func(t *testing.T) {
			base := controlplaneupgrade.NativeStandaloneStatus{InstallationID: handler.config.InstallationID, ProtocolVersion: 2,
				ArtifactFormat: controlplaneupgrade.NativeManifestSchema, CurrentVersion: "1.4.0", CurrentArtifactSHA256: strings.Repeat("52", 32)}
			handler.readStatus = func(string, string, time.Time) (controlplaneupgrade.NativeStandaloneStatus, error) {
				if status == nil {
					return controlplaneupgrade.NativeStandaloneStatus{}, errors.New("status file missing")
				}
				current := base
				status(&current)
				return current, nil
			}
			sent = "unset"
			if body := options(); sent != "" ||
				!strings.Contains(body, `"current_schema_head":null,"current_schema_head_reason":"current_artifact_unverified"`) {
				t.Fatalf("unverified options = %s (sent %q)", body, sent)
			}
		})
	}
}

// A license service that cannot list versions is an error, not a fallback
// to the channel latest.
func TestNativeUpgradeOptionsWithoutLicenseListIsUnavailable(t *testing.T) {
	for name, status := range map[string]int{"no route": http.StatusNotFound, "method refused": http.StatusMethodNotAllowed} {
		t.Run(name, func(t *testing.T) {
			handler := nativeWithLicense(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) })
			response := httptest.NewRecorder()
			handler.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, nativePlanPath+"/options", nil))
			if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "upgrade_options_unavailable") {
				t.Fatalf("options without license list = %d %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestNativeIssueForwardsRequestedArtifact(t *testing.T) {
	requested := "00000000-0000-4000-8000-0000000000c1"
	var forwarded string
	handler := nativeWithLicense(t, func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			RequestedArtifactID string `json:"requested_artifact_id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		forwarded = body.RequestedArtifactID
		w.WriteHeader(http.StatusConflict)
		_, _ = io.WriteString(w, `{"code":"upgrade_target_blocked","reason_code":"schema_downgrade","request_id":"x"}`+"\n")
	})
	issue := func(body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, nativePlanPath+"/issue", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", "issue-1")
		response := httptest.NewRecorder()
		handler.Handler().ServeHTTP(response, request)
		return response
	}
	response := issue(`{"requested_artifact_id":"` + requested + `"}`)
	var blocked struct {
		Error struct {
			Code   string `json:"code"`
			Reason string `json:"reason_code"`
		} `json:"error"`
	}
	if response.Code != http.StatusConflict || json.Unmarshal(response.Body.Bytes(), &blocked) != nil ||
		blocked.Error.Code != "upgrade_target_blocked" || blocked.Error.Reason != "schema_downgrade" || forwarded != requested {
		t.Fatalf("blocked issue = %d %s forwarded=%q", response.Code, response.Body.String(), forwarded)
	}
	forwarded = "unset"
	if response := issue(`{}`); response.Code != http.StatusConflict || forwarded != "" {
		t.Fatalf("latest issue = %d forwarded=%q", response.Code, forwarded)
	}
	for _, body := range []string{`{"requested_artifact_id":"not-a-uuid"}`, `{"target":"1.5.0"}`, ``} {
		if response := issue(body); response.Code != http.StatusBadRequest {
			t.Fatalf("issue %q = %d %s", body, response.Code, response.Body.String())
		}
	}
}

// 73 实测：授权端拒签计划包（父授权为 reinstall）时页面只显示「发布失败」。
// A License 4xx business refusal keeps its code; only 5xx / unreachable is 503.
func TestNativeIssuePassesLicenseRefusalThrough(t *testing.T) {
	for name, test := range map[string]struct {
		status      int
		body        string
		wantStatus  int
		wantCode    string
		wantReason  string
		unreachable bool
	}{
		"same_version":       {http.StatusConflict, `{"code":"upgrade_target_blocked","reason_code":"same_version","request_id":"x"}`, http.StatusConflict, "upgrade_target_blocked", "same_version", false},
		"bundle_unavailable": {http.StatusConflict, `{"code":"upgrade_plan_artifact_bundle_unavailable","request_id":"x"}`, http.StatusConflict, "upgrade_plan_artifact_bundle_unavailable", "", false},
		"banned":             {http.StatusForbidden, `{"code":"installation_banned","request_id":"x"}`, http.StatusConflict, "installation_banned", "", false},
		"license_5xx":        {http.StatusServiceUnavailable, `{"code":"signer_unavailable","request_id":"x"}`, http.StatusServiceUnavailable, "control_upgrade_state_unavailable", "", false},
		"license_500":        {http.StatusInternalServerError, `{"code":"internal_error","request_id":"x"}`, http.StatusServiceUnavailable, "control_upgrade_state_unavailable", "", false},
		"unreachable":        {0, "", http.StatusServiceUnavailable, "control_upgrade_state_unavailable", "", true},
	} {
		t.Run(name, func(t *testing.T) {
			handler := nativeWithLicense(t, func(w http.ResponseWriter, r *http.Request) {
				if test.unreachable {
					// Drop the connection: the client sees a transport error, as on a timeout.
					conn, _, _ := w.(http.Hijacker).Hijack()
					_ = conn.Close()
					return
				}
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, test.body+"\n")
			})
			request := httptest.NewRequest(http.MethodPost, nativePlanPath+"/issue", strings.NewReader(`{}`))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Idempotency-Key", "issue-1")
			response := httptest.NewRecorder()
			handler.Handler().ServeHTTP(response, request)
			var envelope struct {
				Error struct {
					Code   string `json:"code"`
					Reason string `json:"reason_code"`
				} `json:"error"`
			}
			if response.Code != test.wantStatus || json.Unmarshal(response.Body.Bytes(), &envelope) != nil ||
				envelope.Error.Code != test.wantCode || envelope.Error.Reason != test.wantReason {
				t.Fatalf("issue = %d %s", response.Code, response.Body.String())
			}
		})
	}
}
