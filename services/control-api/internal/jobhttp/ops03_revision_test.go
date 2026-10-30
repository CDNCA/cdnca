package jobhttp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestOPS03HTTPCommandsRequireStrongJobRevision(t *testing.T) {
	taskID := uuid.MustParse("40000000-0000-4000-8000-000000000099")
	tenantID := uuid.MustParse("30000000-0000-4000-8000-000000000099")
	scopeID := uuid.MustParse("20000000-0000-4000-8000-000000000099")
	reader := &fixtureReader{
		jobs:         []Job{fixtureJob(taskID, tenantID, StateQueued, fixtureNow)},
		scopeTenants: map[uuid.UUID]uuid.UUID{scopeID: tenantID},
	}
	handler := fixtureHandler(t, reader, func(*http.Request) (Principal, error) {
		principal := tenantPrincipal(scopeID)
		principal.Permissions[PermissionManage] = struct{}{}
		return principal, nil
	}, HandlerConfig{})

	missing := commandRequest("/v1/jobs/"+taskID.String()+"/cancel", "ops03-missing-revision")
	missing.Header.Del("If-Match")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, missing)
	if response.Code != http.StatusBadRequest || reader.commandCalls != 0 {
		t.Fatalf("missing If-Match status=%d calls=%d body=%s", response.Code, reader.commandCalls, response.Body.String())
	}

	for _, invalid := range []string{"1", `W/"1"`, `""`, `"01"`, `"1","2"`} {
		request := commandRequest("/v1/jobs/"+taskID.String()+"/cancel", "ops03-invalid-revision")
		request.Header.Set("If-Match", invalid)
		response = httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest || reader.commandCalls != 0 {
			t.Fatalf("If-Match %q status=%d calls=%d body=%s", invalid, response.Code, reader.commandCalls, response.Body.String())
		}
	}

	request := commandRequest("/v1/jobs/"+taskID.String()+"/cancel", "ops03-valid-revision")
	request.Header.Set("If-Match", `"1"`)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || reader.commandCalls != 1 {
		t.Fatalf("strong If-Match status=%d calls=%d body=%s", response.Code, reader.commandCalls, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"revision":`) {
		t.Fatalf("command response omitted job revision: %s", response.Body.String())
	}
}

func TestOPS03CommandDigestBindsExpectedRevision(t *testing.T) {
	principal := tenantPrincipal(uuid.MustParse("20000000-0000-4000-8000-000000000098"))
	taskID := uuid.MustParse("40000000-0000-4000-8000-000000000098")
	first := commandDigestWithRevision(principal, AudienceTenant, taskID, CommandCancel, "1")
	second := commandDigestWithRevision(principal, AudienceTenant, taskID, CommandCancel, "2")
	if first == second {
		t.Fatal("job command digest did not bind expected revision")
	}
}
