package controlbackuphttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/nativebackup"
	"github.com/google/uuid"
)

type harness struct {
	t       *testing.T
	layout  nativebackup.Layout
	handler *Handler
	audits  []string
	perms   []string
	scope   string
}

func newHarness(t *testing.T) *harness {
	h := &harness{t: t, layout: nativebackup.Layout{Root: t.TempDir()}, perms: []string{readPermission, managePermission}, scope: "platform"}
	if _, err := nativebackup.LoadOrCreateKeys(h.layout); err != nil {
		t.Fatal(err)
	}
	unit := h.layout.Path("/etc/systemd/system/cdnca-control-backup.path")
	_ = os.MkdirAll(filepath.Dir(unit), 0o755)
	_ = os.WriteFile(unit, []byte("[Path]\n"), 0o644)
	handler, err := NewHandler(Dependencies{Layout: h.layout,
		Authenticate: func(_ context.Context, token string) (identity.AuthenticatedSession, error) {
			if token != "good" {
				return identity.AuthenticatedSession{}, errors.New("bad")
			}
			return identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{UserID: uuid.New(), ScopeID: uuid.New(),
				ScopeKind: h.scope, Username: "admin", Permissions: h.perms}}, nil
		},
		Audit: func(_ context.Context, _ identity.AuthenticatedSession, action, _, _ string, payload map[string]any) error {
			encoded, _ := json.Marshal(payload)
			h.audits = append(h.audits, action+" "+string(encoded))
			return nil
		},
		Probe:   func(context.Context, nativebackup.Target) error { return errors.New("dial: password=leaked refused") },
		HostKey: func(context.Context, string, int) (string, error) { return "SHA256:" + strings.Repeat("Q", 43), nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	h.handler = handler
	return h
}

func (h *harness) do(method, path, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	request.Header.Set("Authorization", "Bearer good")
	recorder := httptest.NewRecorder()
	h.handler.ServeHTTP(recorder, request)
	return recorder
}

func TestStatusRequiresPlatformReadPermission(t *testing.T) {
	h := newHarness(t)
	request := httptest.NewRequest(http.MethodGet, Prefix, nil)
	recorder := httptest.NewRecorder()
	h.handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous = %d", recorder.Code)
	}
	h.scope = "tenant"
	if got := h.do(http.MethodGet, Prefix, ""); got.Code != http.StatusForbidden {
		t.Fatalf("tenant = %d", got.Code)
	}
	h.scope = "platform"
	got := h.do(http.MethodGet, Prefix, "")
	if got.Code != http.StatusOK || !strings.Contains(got.Body.String(), `"keys_ready":true`) || !strings.Contains(got.Body.String(), `"agent_installed":true`) {
		t.Fatalf("status = %d %s", got.Code, got.Body)
	}
	// The default schedule is off: no next run.
	if !strings.Contains(got.Body.String(), `"next_run_at":null`) {
		t.Fatalf("next_run_at missing: %s", got.Body)
	}
}

func TestBackupRequestIsQueuedAuditedAndNeedsManage(t *testing.T) {
	h := newHarness(t)
	h.perms = []string{readPermission}
	if got := h.do(http.MethodPost, Prefix+"/backups", "{}"); got.Code != http.StatusForbidden {
		t.Fatalf("read-only = %d", got.Code)
	}
	h.perms = []string{readPermission, managePermission}
	got := h.do(http.MethodPost, Prefix+"/backups", "{}")
	if got.Code != http.StatusAccepted {
		t.Fatalf("submit = %d %s", got.Code, got.Body)
	}
	if len(h.audits) != 1 || !strings.HasPrefix(h.audits[0], "control_backup.backup_request") {
		t.Fatalf("audits = %v", h.audits)
	}
	if again := h.do(http.MethodPost, Prefix+"/backups", "{}"); again.Code != http.StatusConflict {
		t.Fatalf("second = %d", again.Code)
	}
	entries, _ := os.ReadDir(h.layout.Path(nativebackup.AgentRoot + "/requests"))
	if len(entries) != 1 {
		t.Fatalf("requests = %d", len(entries))
	}
}

func (h *harness) revision() string {
	h.t.Helper()
	var status struct {
		Data struct {
			Settings struct {
				Revision string `json:"revision"`
			} `json:"settings"`
		} `json:"data"`
	}
	got := h.do(http.MethodGet, Prefix, "")
	if err := json.Unmarshal(got.Body.Bytes(), &status); err != nil || status.Data.Settings.Revision == "" {
		h.t.Fatalf("status = %s %v", got.Body, err)
	}
	return status.Data.Settings.Revision
}

func withRevision(revision, body string) string {
	return `{"expected_revision":"` + revision + `",` + strings.TrimPrefix(strings.TrimSpace(body), "{")
}

func TestSettingsKeepSecretsAndNeverReturnThem(t *testing.T) {
	h := newHarness(t)
	body := `{"schedule":{"enabled":true,"weekdays":[1,3],"hour":3,"minute":30},"keep_local":5,"keep_remote":10,
	  "targets":[{"name":"offsite","kind":"s3","enabled":true,"endpoint":"https://s3.example.com","region":"us-east-1",
	  "bucket":"cdnca-backups","prefix":"ctl/","access_key":"AKIAEXAMPLE","secret_key":"very-secret-value"}]}`
	got := h.do(http.MethodPut, Prefix+"/settings", withRevision(h.revision(), body))
	if got.Code != http.StatusOK || strings.Contains(got.Body.String(), "very-secret-value") || strings.Contains(got.Body.String(), "AKIAEXAMPLE") {
		t.Fatalf("put = %d %s", got.Code, got.Body)
	}
	// Re-saving the edited target (stored_name) without secrets keeps the stored ones.
	kept := strings.Replace(strings.Replace(body, `"AKIAEXAMPLE"`, `""`, 1), `"very-secret-value"`, `""`, 1)
	kept = strings.Replace(kept, `{"name":"offsite"`, `{"stored_name":"offsite","name":"offsite"`, 1)
	if stale := h.do(http.MethodPut, Prefix+"/settings", withRevision("stale", kept)); stale.Code != http.StatusConflict ||
		!strings.Contains(stale.Body.String(), "control_backup_revision_conflict") {
		t.Fatalf("stale revision = %d %s", stale.Code, stale.Body)
	}
	got = h.do(http.MethodPut, Prefix+"/settings", withRevision(h.revision(), kept))
	if got.Code != http.StatusOK {
		t.Fatalf("second put = %d %s", got.Code, got.Body)
	}
	settings, _ := nativebackup.LoadSettings(h.layout)
	if settings.Targets[0].SecretKey != "very-secret-value" {
		t.Fatal("secret must be kept when the field is left empty")
	}
	for _, audit := range h.audits {
		if strings.Contains(audit, "secret") && strings.Contains(audit, "very") {
			t.Fatalf("audit leaks a secret: %s", audit)
		}
	}
	probe := h.do(http.MethodPost, Prefix+"/targets/probe", `{"expected_revision":"`+h.revision()+`","target":{"stored_name":"offsite","name":"offsite",
	  "kind":"s3","enabled":true,"endpoint":"https://s3.example.com","region":"us-east-1","bucket":"cdnca-backups","prefix":"ctl/"}}`)
	if probe.Code != http.StatusOK || strings.Contains(probe.Body.String(), "leaked") || !strings.Contains(probe.Body.String(), `"ok":false`) {
		t.Fatalf("probe = %s", probe.Body)
	}
	if bad := h.do(http.MethodPut, Prefix+"/settings", withRevision(h.revision(), `{"schedule":{"hour":30},"keep_local":5,"keep_remote":5,"targets":[]}`)); bad.Code != http.StatusBadRequest {
		t.Fatalf("invalid = %d", bad.Code)
	}
}

func TestMigrationNeedsTypedConfirmationAndNeverStoresCredentialInRun(t *testing.T) {
	h := newHarness(t)
	target := `"host":"203.0.113.9","port":22,"user":"root","host_key_sha256":"SHA256:` + strings.Repeat("Q", 43) + `","password":"ssh-pass-123"`
	if got := h.do(http.MethodPost, Prefix+"/migrations", `{`+target+`,"confirm":"wrong"}`); got.Code != http.StatusBadRequest {
		t.Fatalf("unconfirmed = %d", got.Code)
	}
	if got := h.do(http.MethodPost, Prefix+"/migrations", `{`+target+`,"confirm":"203.0.113.9"}`); got.Code != http.StatusConflict {
		t.Fatalf("missing dependency installer must be refused, got %d", got.Code)
	}
	script := h.layout.Path(nativebackup.DependenciesScript)
	_ = os.MkdirAll(filepath.Dir(script), 0o755)
	_ = os.WriteFile(script, []byte("#!/bin/bash\n"), 0o700)
	got := h.do(http.MethodPost, Prefix+"/migrations", `{`+target+`,"confirm":"203.0.113.9"}`)
	if got.Code != http.StatusAccepted || strings.Contains(got.Body.String(), "ssh-pass-123") {
		t.Fatalf("migrate = %d %s", got.Code, got.Body)
	}
	for _, audit := range h.audits {
		if strings.Contains(audit, "ssh-pass-123") {
			t.Fatal("audit leaks the SSH password")
		}
	}
	runs, _ := os.ReadDir(h.layout.Path(nativebackup.AgentRoot + "/runs"))
	for _, entry := range runs {
		data, _ := os.ReadFile(h.layout.Path(nativebackup.AgentRoot + "/runs/" + entry.Name()))
		if strings.Contains(string(data), "ssh-pass-123") {
			t.Fatal("run record leaks the SSH password")
		}
	}
	if bad := h.do(http.MethodPost, Prefix+"/migrations", `{`+target+`,"env":"docker","confirm":"203.0.113.9"}`); bad.Code != http.StatusBadRequest {
		t.Fatalf("unknown target environment must be refused, got %d", bad.Code)
	}
	// fix-btenv: the chosen target environment travels with the request and is audited.
	fresh := newHarness(t)
	freshScript := fresh.layout.Path(nativebackup.DependenciesScript)
	_ = os.MkdirAll(filepath.Dir(freshScript), 0o755)
	_ = os.WriteFile(freshScript, []byte("#!/bin/bash\n"), 0o700)
	if bt := fresh.do(http.MethodPost, Prefix+"/migrations", `{`+target+`,"env":"bt","confirm":"203.0.113.9"}`); bt.Code != http.StatusAccepted {
		t.Fatalf("bt target = %d %s", bt.Code, bt.Body)
	}
	if !strings.Contains(strings.Join(fresh.audits, "\n"), `"target_env":"bt"`) {
		t.Fatalf("audit must record the target environment: %v", fresh.audits)
	}
	if key := h.do(http.MethodPost, Prefix+"/host-key", `{"host":"203.0.113.9","port":22}`); !strings.Contains(key.Body.String(), "SHA256:") {
		t.Fatalf("host key = %s", key.Body)
	}
}

func TestRestoreCommandsAndRecoveryKit(t *testing.T) {
	h := newHarness(t)
	keys, _ := nativebackup.LoadKeys(h.layout)
	// Publish a minimal valid bundle through the real writer.
	clock := time.Date(2026, 10, 17, 1, 0, 0, 0, time.UTC)
	now := func() time.Time { clock = clock.Add(time.Second); return clock }
	id := nativebackup.NewBackupID(now())
	writer, err := nativebackup.NewBundleWriter(h.layout.Path(nativebackup.BackupRoot), id, []string{keys.Recipient()}, now)
	if err != nil {
		t.Fatal(err)
	}
	frozen := now()
	for _, name := range nativebackup.ComponentOrder {
		if err := writer.Add(name, func(output io.Writer) (map[string]string, error) {
			_, err := output.Write([]byte("data"))
			return nil, err
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := writer.Publish(nativebackup.Manifest{Schema: nativebackup.ManifestSchema, BackupID: id, Reason: "manual", CreatedAt: now(),
		FreezeMode: nativebackup.FreezeBackup, FrozenAt: frozen, ToolVersion: "1",
		Control: nativebackup.ControlFacts{InstallationID: "x", Version: "1.0.35", SchemaVersion: 302}}, keys); err != nil {
		t.Fatal(err)
	}
	got := h.do(http.MethodGet, Prefix+"/backups/"+id+"/restore-commands", "")
	if got.Code != http.StatusOK || !strings.Contains(got.Body.String(), keys.Fingerprint()) || !strings.Contains(got.Body.String(), "native-backup restore") {
		t.Fatalf("commands = %d %s", got.Code, got.Body)
	}
	if weak := h.do(http.MethodPost, Prefix+"/recovery-kit", `{"passphrase":"short"}`); weak.Code != http.StatusBadRequest {
		t.Fatalf("weak = %d", weak.Code)
	}
	kit := h.do(http.MethodPost, Prefix+"/recovery-kit", `{"passphrase":"correct horse battery staple"}`)
	if kit.Code != http.StatusOK || strings.Contains(kit.Body.String(), keys.Identity.String()) {
		t.Fatalf("kit = %d", kit.Code)
	}
	if _, _, err := nativebackup.OpenRecoveryKit(kit.Body.Bytes(), "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	if del := h.do(http.MethodDelete, Prefix+"/backups/"+id, `{"confirm":"nope"}`); del.Code != http.StatusBadRequest {
		t.Fatalf("unconfirmed delete = %d", del.Code)
	}
	if del := h.do(http.MethodDelete, Prefix+"/backups/"+id, `{"confirm":"`+id+`"}`); del.Code != http.StatusAccepted {
		t.Fatalf("delete = %d %s", del.Code, del.Body)
	}
}
