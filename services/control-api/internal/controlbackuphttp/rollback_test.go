package controlbackuphttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/nativebackup"
	"github.com/google/uuid"
)

// fix-migrollback acceptance: stop, rollback, new-master guard, frozen console.

var rollbackTarget = nativebackup.MigrationTarget{Host: "203.0.113.9", Port: 22, User: "root",
	HostKeySHA256: "SHA256:" + strings.Repeat("A", 43), Password: "x"}

type rollbackRig struct {
	*harness
	clock     time.Time
	reachable bool
	dns       map[string][]string
	password  string
	userID    uuid.UUID
}

func newRollbackRig(t *testing.T) *rollbackRig {
	rig := &rollbackRig{harness: newHarness(t), clock: time.Date(2026, 10, 28, 3, 0, 0, 0, time.UTC), password: "correct horse", userID: uuid.New(),
		dns: map[string][]string{}}
	dependencies := rig.handler.dependencies
	dependencies.Now = func() time.Time { return rig.clock }
	dependencies.Authenticate = func(_ context.Context, token string) (identity.AuthenticatedSession, error) {
		if token != "good" {
			return identity.AuthenticatedSession{}, errors.New("bad")
		}
		return identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{UserID: rig.userID, ScopeID: uuid.New(),
			ScopeKind: rig.scope, Username: "admin", Permissions: rig.perms}}, nil
	}
	dependencies.VerifyPassword = func(_ context.Context, username, password, _ string) (identity.Principal, error) {
		if username != "admin" || password != rig.password {
			return identity.Principal{}, identity.ErrInvalidCredentials
		}
		return identity.Principal{UserID: rig.userID, ScopeKind: "platform", Username: "admin", Permissions: rig.perms}, nil
	}
	dependencies.ProbeNewMaster = func(context.Context, string, string) error {
		if rig.reachable {
			return nil
		}
		return errors.New("unreachable")
	}
	dependencies.LookupHost = func(_ context.Context, host string) ([]string, error) {
		if addresses, ok := rig.dns[host]; ok {
			return addresses, nil
		}
		return nil, errors.New("nxdomain")
	}
	dependencies.Facts = func(context.Context) nativebackup.ControlFacts {
		return nativebackup.ControlFacts{ControlDomain: "cdnca.com", GatewayEndpoint: "gateway.cdnca.com:443"}
	}
	handler, err := NewHandler(dependencies)
	if err != nil {
		t.Fatal(err)
	}
	rig.handler = handler
	return rig
}

// migration records a migrate run that reached phase in state.
func (rig *rollbackRig) migration(phase string, state nativebackup.RunState) nativebackup.Run {
	rig.t.Helper()
	run, err := nativebackup.SubmitRequest(rig.layout, nativebackup.Request{Kind: nativebackup.RequestMigrate, Migration: &rollbackTarget}, rig.clock)
	if err != nil {
		rig.t.Fatal(err)
	}
	// The agent consumes the request; drop it so later submissions are not queued twice.
	entries, _ := os.ReadDir(rig.layout.Path(nativebackup.AgentRoot + "/requests"))
	for _, entry := range entries {
		_ = os.Remove(rig.layout.Path(nativebackup.AgentRoot + "/requests/" + entry.Name()))
	}
	run.State, run.Phase, run.BackupID = state, phase, "20261028T030000Z-abcdef12"
	encoded, _ := json.MarshalIndent(run, "", "  ")
	if err := os.WriteFile(rig.layout.Path(nativebackup.AgentRoot+"/runs/"+run.ID+".json"), encoded, 0o600); err != nil {
		rig.t.Fatal(err)
	}
	return run
}

func (rig *rollbackRig) hold() {
	rig.t.Helper()
	record := `{"schema":"cdnca.control-native-freeze/v1","mode":"hold","id":"m1","acquired_at":"2026-10-28T03:00:00Z","units":[` +
		`{"name":"cdnca-native-control-upgrade-runner.service","was_loaded":true,"was_active":true,"was_enabled":true},` +
		`{"name":"cdnca-agent-gateway.service","was_loaded":true,"was_active":true,"was_enabled":true},` +
		`{"name":"cdnca-control-api.service","was_loaded":true,"was_active":true,"was_enabled":true}]}`
	if err := os.MkdirAll(rig.layout.Path(nativebackup.AgentRoot), 0o700); err != nil {
		rig.t.Fatal(err)
	}
	if err := os.WriteFile(rig.layout.Path(nativebackup.AgentRoot+"/freeze.json"), []byte(record), 0o600); err != nil {
		rig.t.Fatal(err)
	}
}

func errorCode(t *testing.T, recorder *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(recorder.Body.Bytes(), &body)
	return body.Error.Code
}

func TestStopRunningMigrationWritesMarkerAndAudit(t *testing.T) {
	rig := newRollbackRig(t)
	run := rig.migration(nativebackup.PhaseTransfer, nativebackup.RunRunning)
	got := rig.do(http.MethodPost, Prefix+"/runs/"+run.ID+"/stop", "")
	if got.Code != http.StatusAccepted || !strings.Contains(got.Body.String(), `"abort":false`) {
		t.Fatalf("stop = %d %s", got.Code, got.Body.String())
	}
	if _, err := os.Stat(rig.layout.Path(nativebackup.AgentRoot + "/runs/" + run.ID + ".stop")); err != nil {
		t.Fatalf("stop marker: %v", err)
	}
	if last := rig.audits[len(rig.audits)-1]; !strings.HasPrefix(last, "control_backup.migrate_stop ") || !strings.Contains(last, `"phase":"transfer"`) {
		t.Fatalf("audit = %v", rig.audits)
	}
}

func TestStopDuringRestoreIsAnAbort(t *testing.T) {
	rig := newRollbackRig(t)
	run := rig.migration(nativebackup.PhaseRestore, nativebackup.RunRunning)
	got := rig.do(http.MethodPost, Prefix+"/runs/"+run.ID+"/stop", "")
	if got.Code != http.StatusAccepted || !strings.Contains(got.Body.String(), `"abort":true`) {
		t.Fatalf("stop = %d %s", got.Code, got.Body.String())
	}
}

func TestStopRefusedForFinishedRunAndReader(t *testing.T) {
	rig := newRollbackRig(t)
	run := rig.migration(nativebackup.PhaseDone, nativebackup.RunSucceeded)
	if got := rig.do(http.MethodPost, Prefix+"/runs/"+run.ID+"/stop", ""); got.Code != http.StatusConflict || errorCode(t, got) != "control_backup_not_stoppable" {
		t.Fatalf("stop finished = %d %s", got.Code, got.Body.String())
	}
	rig.perms = []string{readPermission}
	if got := rig.do(http.MethodPost, Prefix+"/runs/"+run.ID+"/stop", ""); got.Code != http.StatusForbidden {
		t.Fatalf("reader stop = %d", got.Code)
	}
}

func TestRollbackNeedsHoldConfirmationAndPassword(t *testing.T) {
	rig := newRollbackRig(t)
	body := `{"password":"correct horse","confirm":"rollback"}`
	if got := rig.do(http.MethodPost, Prefix+"/rollback", body); got.Code != http.StatusConflict || errorCode(t, got) != "control_backup_not_held" {
		t.Fatalf("not held = %d %s", got.Code, got.Body.String())
	}
	rig.hold()
	if got := rig.do(http.MethodPost, Prefix+"/rollback", `{"password":"correct horse","confirm":"yes"}`); errorCode(t, got) != "confirmation_mismatch" {
		t.Fatalf("confirm = %s", got.Body.String())
	}
	if got := rig.do(http.MethodPost, Prefix+"/rollback", `{"password":"wrong","confirm":"rollback"}`); got.Code != http.StatusForbidden ||
		errorCode(t, got) != "control_backup_password_invalid" {
		t.Fatalf("wrong password = %d %s", got.Code, got.Body.String())
	}
	if last := rig.audits[len(rig.audits)-1]; !strings.Contains(last, `"result":"denied"`) || strings.Contains(last, "wrong") {
		t.Fatalf("denied audit = %s", last)
	}
	got := rig.do(http.MethodPost, Prefix+"/rollback", body)
	if got.Code != http.StatusAccepted {
		t.Fatalf("rollback = %d %s", got.Code, got.Body.String())
	}
	last := rig.audits[len(rig.audits)-1]
	if !strings.HasPrefix(last, "control_backup.rollback_request ") || strings.Contains(last, "correct horse") {
		t.Fatalf("audit = %s", last)
	}
}

func TestRollbackPasswordAttemptsAreLimited(t *testing.T) {
	rig := newRollbackRig(t)
	rig.hold()
	for range rollbackAttempts {
		rig.do(http.MethodPost, Prefix+"/rollback", `{"password":"wrong","confirm":"rollback"}`)
	}
	if got := rig.do(http.MethodPost, Prefix+"/rollback", `{"password":"correct horse","confirm":"rollback"}`); got.Code != http.StatusTooManyRequests {
		t.Fatalf("limited = %d", got.Code)
	}
	rig.clock = rig.clock.Add(rollbackWindow + time.Second) // injected clock: the window passes
	if got := rig.do(http.MethodPost, Prefix+"/rollback", `{"password":"correct horse","confirm":"rollback"}`); got.Code != http.StatusAccepted {
		t.Fatalf("after window = %d %s", got.Code, got.Body.String())
	}
}

func TestRollbackRefusedWhileNewMasterServesUntilConfirmed(t *testing.T) {
	rig := newRollbackRig(t)
	rig.migration(nativebackup.PhaseDone, nativebackup.RunSucceeded)
	rig.hold()
	rig.reachable = true
	got := rig.do(http.MethodPost, Prefix+"/rollback", `{"password":"correct horse","confirm":"rollback"}`)
	if got.Code != http.StatusConflict || errorCode(t, got) != "control_backup_new_master_serving" ||
		!strings.Contains(got.Body.String(), `"serving":true`) || !strings.Contains(got.Body.String(), "clean-target") {
		t.Fatalf("serving = %d %s", got.Code, got.Body.String())
	}
	got = rig.do(http.MethodPost, Prefix+"/rollback", `{"password":"correct horse","confirm":"rollback","confirm_new_master_stopped":true}`)
	if got.Code != http.StatusAccepted {
		t.Fatalf("confirmed = %d %s", got.Code, got.Body.String())
	}
	if last := rig.audits[len(rig.audits)-1]; !strings.Contains(last, `"new_master_serving":true`) || !strings.Contains(last, `"confirm_new_master_stopped":true`) {
		t.Fatalf("audit = %s", last)
	}
}

func TestNewMasterDetection(t *testing.T) {
	cases := []struct {
		name               string
		phase              string
		state              nativebackup.RunState
		reachable          bool
		dns                []string
		restored, serving  bool
		dnsPointsToNewHost bool
	}{
		{"stopped before restore, target up", nativebackup.PhaseTransfer, nativebackup.RunStopped, true, nil, false, false, false},
		{"aborted in restore, target up", nativebackup.PhaseRestore, nativebackup.RunStopped, true, nil, true, true, false},
		{"verify failed, unreachable, DNS moved", nativebackup.PhaseVerify, nativebackup.RunFailed, false, []string{"203.0.113.9"}, true, true, true},
		{"done, unreachable, DNS not moved", nativebackup.PhaseDone, nativebackup.RunSucceeded, false, []string{"198.51.100.1"}, true, false, false},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			rig := newRollbackRig(t)
			rig.migration(item.phase, item.state)
			rig.reachable = item.reachable
			if item.dns != nil {
				rig.dns["cdnca.com"] = item.dns
			}
			view := rig.handler.newMaster(context.Background())
			if view.Host != rollbackTarget.Host || view.Restored != item.restored || view.Serving != item.serving ||
				view.DNSPointsToNew != item.dnsPointsToNewHost || view.ControlDomain != "cdnca.com" || view.GatewayEndpoint != "gateway.cdnca.com:443" {
				t.Fatalf("view = %+v", view)
			}
			if item.restored != (view.CleanCommand != "") {
				t.Fatalf("clean command only after a restore started: %+v", view)
			}
		})
	}
}

func TestSubmitStillRefusedWhileHeldExceptRollback(t *testing.T) {
	rig := newRollbackRig(t)
	rig.hold()
	if got := rig.do(http.MethodPost, Prefix+"/backups", ""); errorCode(t, got) != "control_backup_host_held" {
		t.Fatalf("backup while held = %s", got.Body.String())
	}
}

func newFrozenRig(t *testing.T) (*rollbackRig, *FrozenConsole) {
	rig := newRollbackRig(t)
	console, err := NewFrozenConsole(rig.handler.dependencies, nil)
	if err != nil {
		t.Fatal(err)
	}
	return rig, console
}

func frozenDo(console *FrozenConsole, method, path, token, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	recorder := httptest.NewRecorder()
	console.ServeHTTP(recorder, request)
	return recorder
}

func TestFrozenConsoleSignsInAndServesOnlyMigrationRoutes(t *testing.T) {
	rig, console := newFrozenRig(t)
	rig.hold()
	run := rig.migration(nativebackup.PhaseVerify, nativebackup.RunFailed)
	if got := frozenDo(console, http.MethodPost, FrozenSessionPath, "", `{"username":"admin","password":"bad"}`); got.Code != http.StatusUnauthorized {
		t.Fatalf("bad sign-in = %d", got.Code)
	}
	signed := frozenDo(console, http.MethodPost, FrozenSessionPath, "", `{"username":"Admin ","password":"correct horse"}`)
	var session struct {
		Data struct {
			AccessToken string `json:"access_token"`
			CanManage   bool   `json:"can_manage"`
		} `json:"data"`
	}
	if signed.Code != http.StatusOK || json.Unmarshal(signed.Body.Bytes(), &session) != nil || session.Data.AccessToken == "" || !session.Data.CanManage {
		t.Fatalf("sign-in = %d %s", signed.Code, signed.Body.String())
	}
	token := session.Data.AccessToken
	if got := frozenDo(console, http.MethodGet, Prefix, token, ""); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), `"mode":"hold"`) {
		t.Fatalf("status = %d %s", got.Code, got.Body.String())
	}
	if got := frozenDo(console, http.MethodGet, Prefix+"/runs/"+run.ID, token, ""); got.Code != http.StatusOK {
		t.Fatalf("run log = %d", got.Code)
	}
	if got := frozenDo(console, http.MethodGet, Prefix+"/new-master", token, ""); got.Code != http.StatusOK {
		t.Fatalf("new master = %d", got.Code)
	}
	if got := frozenDo(console, http.MethodPost, Prefix+"/rollback", token, `{"password":"correct horse","confirm":"rollback"}`); got.Code != http.StatusAccepted {
		t.Fatalf("rollback = %d %s", got.Code, got.Body.String())
	}
	for _, refused := range [][2]string{{http.MethodPut, Prefix + "/settings"}, {http.MethodPost, Prefix + "/migrations"}, {http.MethodPost, Prefix + "/backups"}} {
		if got := frozenDo(console, refused[0], refused[1], token, "{}"); got.Code != http.StatusConflict {
			t.Fatalf("%s %s = %d while held", refused[0], refused[1], got.Code)
		}
	}
	for _, other := range []string{"/v1/sites", "/v1/auth/me", "/health/ready"} {
		if got := frozenDo(console, http.MethodGet, other, token, ""); got.Code != http.StatusServiceUnavailable || errorCode(t, got) != HoldErrorCode {
			t.Fatalf("GET %s = %d %s", other, got.Code, got.Body.String())
		}
	}
	if got := frozenDo(console, http.MethodGet, Prefix, "frozen.forged", ""); got.Code != http.StatusUnauthorized {
		t.Fatalf("forged token = %d", got.Code)
	}
	rig.clock = rig.clock.Add(frozenSessionTTL) // injected clock: the session expires
	if got := frozenDo(console, http.MethodGet, Prefix, token, ""); got.Code != http.StatusUnauthorized {
		t.Fatalf("expired session = %d", got.Code)
	}
}

func TestFrozenConsoleRefusesTenantAndReader(t *testing.T) {
	rig, console := newFrozenRig(t)
	rig.perms = []string{readPermission}
	signed := frozenDo(console, http.MethodPost, FrozenSessionPath, "", `{"username":"admin","password":"correct horse"}`)
	if signed.Code != http.StatusOK || !strings.Contains(signed.Body.String(), `"can_manage":false`) {
		t.Fatalf("reader sign-in = %d %s", signed.Code, signed.Body.String())
	}
	rig.perms = []string{}
	if got := frozenDo(console, http.MethodPost, FrozenSessionPath, "", `{"username":"admin","password":"correct horse"}`); got.Code != http.StatusUnauthorized {
		t.Fatalf("no permission sign-in = %d", got.Code)
	}
}
