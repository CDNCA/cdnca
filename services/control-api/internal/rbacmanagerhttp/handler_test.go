package rbacmanagerhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/rbacmanager"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type fakeCommands struct {
	mu            sync.Mutex
	actor         rbacmanager.Actor
	create        rbacmanager.CreateRoleRequest
	createRole    rbacmanager.Role
	createErr     error
	renameErr     error
	publishErr    error
	deactivateErr error
	assignErr     error
	revokeErr     error
}

func (commands *fakeCommands) CreateRole(
	_ context.Context,
	actor rbacmanager.Actor,
	request rbacmanager.CreateRoleRequest,
) (rbacmanager.Role, error) {
	commands.mu.Lock()
	defer commands.mu.Unlock()
	commands.actor, commands.create = actor, request
	if commands.createErr != nil {
		return rbacmanager.Role{}, commands.createErr
	}
	result := commands.createRole
	if result.ID == uuid.Nil {
		result = coreRole(actor.ScopeID)
	}
	return result, nil
}

func (commands *fakeCommands) RenameRole(
	_ context.Context,
	actor rbacmanager.Actor,
	request rbacmanager.RenameRoleRequest,
) (rbacmanager.Role, error) {
	if commands.renameErr != nil {
		return rbacmanager.Role{}, commands.renameErr
	}
	result := coreRole(actor.ScopeID)
	result.ID, result.Name, result.CurrentRevision = request.RoleID, request.Name, request.ExpectedRevision+1
	return result, nil
}

func (commands *fakeCommands) PublishRevision(
	_ context.Context,
	actor rbacmanager.Actor,
	request rbacmanager.PublishRevisionRequest,
) (rbacmanager.Role, error) {
	if commands.publishErr != nil {
		return rbacmanager.Role{}, commands.publishErr
	}
	result := coreRole(actor.ScopeID)
	result.ID, result.CurrentRevision = request.RoleID, request.ExpectedRevision+1
	result.Permissions = append([]string(nil), request.Permissions...)
	return result, nil
}

func (commands *fakeCommands) DeactivateRole(
	_ context.Context,
	actor rbacmanager.Actor,
	request rbacmanager.DeactivateRoleRequest,
) (rbacmanager.Role, error) {
	if commands.deactivateErr != nil {
		return rbacmanager.Role{}, commands.deactivateErr
	}
	result := coreRole(actor.ScopeID)
	now := time.Date(2026, 7, 23, 3, 0, 0, 0, time.UTC)
	result.ID, result.CurrentRevision, result.DeactivatedAt = request.RoleID, request.ExpectedRevision, &now
	return result, nil
}

func (commands *fakeCommands) AssignRole(
	_ context.Context,
	actor rbacmanager.Actor,
	request rbacmanager.AssignRoleRequest,
) (rbacmanager.Grant, error) {
	if commands.assignErr != nil {
		return rbacmanager.Grant{}, commands.assignErr
	}
	return rbacmanager.Grant{ID: uuid.New(), TenantID: uuid.New(), TenantScopeID: actor.ScopeID,
		RoleID: request.RoleID, RoleRevision: request.ExpectedRoleRevision,
		SubjectUserID: request.SubjectUserID, GrantedByUserID: actor.UserID,
		GrantedAt: time.Date(2026, 7, 23, 3, 0, 0, 0, time.UTC)}, nil
}

func (commands *fakeCommands) RevokeGrant(
	_ context.Context,
	actor rbacmanager.Actor,
	request rbacmanager.RevokeGrantRequest,
) (rbacmanager.Revocation, error) {
	if commands.revokeErr != nil {
		return rbacmanager.Revocation{}, commands.revokeErr
	}
	return rbacmanager.Revocation{ID: uuid.New(), GrantID: request.GrantID,
		RevokedByUserID: actor.UserID, RevokedAt: time.Date(2026, 7, 23, 3, 0, 0, 0, time.UTC)}, nil
}

type fakeReader struct {
	mu            sync.Mutex
	rolePages     []RolePageFacts
	roleQueries   []RolePageQuery
	role          RoleView
	permissions   []PermissionView
	grantPages    []GrantPageFacts
	err           error
	waitForCancel bool
}

func (reader *fakeReader) ListRoles(
	ctx context.Context,
	_ rbacmanager.Actor,
	query RolePageQuery,
) (RolePageFacts, error) {
	if reader.waitForCancel {
		<-ctx.Done()
		return RolePageFacts{}, ctx.Err()
	}
	reader.mu.Lock()
	defer reader.mu.Unlock()
	reader.roleQueries = append(reader.roleQueries, query)
	if reader.err != nil {
		return RolePageFacts{}, reader.err
	}
	if len(reader.rolePages) == 0 {
		version := int64(0)
		return RolePageFacts{Items: []RoleView{}, SnapshotVersion: &version}, nil
	}
	result := reader.rolePages[0]
	reader.rolePages = reader.rolePages[1:]
	return result, nil
}

func (reader *fakeReader) GetRole(
	context.Context,
	rbacmanager.Actor,
	uuid.UUID,
) (RoleView, error) {
	if reader.err != nil {
		return RoleView{}, reader.err
	}
	return reader.role, nil
}

func (reader *fakeReader) PermissionCatalog(
	context.Context,
	rbacmanager.Actor,
) ([]PermissionView, error) {
	if reader.err != nil {
		return nil, reader.err
	}
	return reader.permissions, nil
}

func (reader *fakeReader) ListGrants(
	context.Context,
	rbacmanager.Actor,
	GrantPageQuery,
) (GrantPageFacts, error) {
	if reader.err != nil {
		return GrantPageFacts{}, reader.err
	}
	if len(reader.grantPages) == 0 {
		version := int64(0)
		return GrantPageFacts{Items: []GrantView{}, SnapshotVersion: &version}, nil
	}
	result := reader.grantPages[0]
	reader.grantPages = reader.grantPages[1:]
	return result, nil
}

func TestNewServiceFailsClosedWithoutTransactionStepUpVerifier(t *testing.T) {
	t.Parallel()
	if _, err := NewService(&pgxpool.Pool{}, nil, ServiceConfig{CursorKey: bytes.Repeat([]byte{1}, 32)}); !errors.Is(err, ErrStepUpUnavailable) {
		t.Fatalf("NewService(nil verifier) error = %v", err)
	}
}

func TestStepUpBindingDigestIncludesEveryAuthorizationFact(t *testing.T) {
	t.Parallel()
	base := rbacmanager.StepUpCheck{Actor: rbacmanager.Actor{
		UserID: uuid.New(), ScopeID: uuid.New(), SessionID: uuid.New(), ScopeKind: "tenant",
		IdentityDomain: rbacmanager.CustomerControlIdentityDomain,
	}, TenantID: uuid.New(), Audience: "custom-rbac", Action: "identity.custom_role.assign",
		RoleID: uuid.New(), SubjectUserID: uuid.New(), ExpectedRevision: 7,
		Permissions: []string{"identity.users.manage"}, MutationDigest: bytes.Repeat([]byte{0x42}, 32),
		RequestID: "binding-request", TraceID: strings.Repeat("a", 32)}
	want, err := stepUpBindingDigest(base)
	if err != nil {
		t.Fatal(err)
	}
	mutations := []struct {
		name   string
		mutate func(*rbacmanager.StepUpCheck)
	}{
		{"tenant", func(value *rbacmanager.StepUpCheck) { value.TenantID = uuid.New() }},
		{"actor", func(value *rbacmanager.StepUpCheck) { value.Actor.UserID = uuid.New() }},
		{"scope", func(value *rbacmanager.StepUpCheck) { value.Actor.ScopeID = uuid.New() }},
		{"session", func(value *rbacmanager.StepUpCheck) { value.Actor.SessionID = uuid.New() }},
		{"role", func(value *rbacmanager.StepUpCheck) { value.RoleID = uuid.New() }},
		{"grant", func(value *rbacmanager.StepUpCheck) { value.GrantID = uuid.New() }},
		{"subject", func(value *rbacmanager.StepUpCheck) { value.SubjectUserID = uuid.New() }},
		{"expected_revision", func(value *rbacmanager.StepUpCheck) { value.ExpectedRevision++ }},
		{"action", func(value *rbacmanager.StepUpCheck) { value.Action = "identity.custom_role.revoke" }},
		{"mutation", func(value *rbacmanager.StepUpCheck) { value.MutationDigest[0] ^= 0xff }},
		{"request", func(value *rbacmanager.StepUpCheck) { value.RequestID = "binding-request-other" }},
		{"trace", func(value *rbacmanager.StepUpCheck) { value.TraceID = strings.Repeat("b", 32) }},
		{"permissions", func(value *rbacmanager.StepUpCheck) { value.Permissions = []string{"certificates.manage"} }},
	}
	for _, test := range mutations {
			t.Run(test.name, func(t *testing.T) {
				changed := base
				changed.Permissions = append([]string(nil), base.Permissions...)
				changed.MutationDigest = append([]byte(nil), base.MutationDigest...)
			test.mutate(&changed)
			got, err := stepUpBindingDigest(changed)
			if err != nil {
				t.Fatal(err)
			}
			if got == want {
				t.Fatalf("%s was omitted from step-up binding", test.name)
			}
		})
	}
}

func TestHandlerDerivesActorAndRejectsScopeClaimsAndOperatorIdentity(t *testing.T) {
	t.Parallel()
	commands := &fakeCommands{}
	handler := testHandler(t, commands, &fakeReader{})

	request := commandRequest(http.MethodPost, "/v1/custom-rbac/roles",
		`{"name":"reader","permissions":["sites.read"]}`)
	request.Header.Set("Authorization", "tenant")
	request.Header.Set("X-Step-Up-Proof", strings.Repeat("A", 43))
	response := perform(handler, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", response.Code, response.Body.String())
	}
	commands.mu.Lock()
	actor, mutation := commands.actor, commands.create.Mutation
	commands.mu.Unlock()
	want := tenantSession()
	if actor.UserID != want.UserID || actor.ScopeID != want.ScopeID || actor.SessionID != want.SessionID ||
		actor.ScopeKind != "tenant" || actor.IdentityDomain != rbacmanager.CustomerControlIdentityDomain {
		t.Fatalf("derived actor = %#v", actor)
	}
	if mutation.StepUp.Token != strings.Repeat("A", 43) || mutation.RequestID != "request-1" ||
		mutation.TraceID != strings.Repeat("1", 32) {
		t.Fatalf("mutation metadata = %#v", mutation)
	}
	for _, forbidden := range []string{"tenant_id", "tenant_scope_id", "step_up_proof", "request_digest", "permissions_digest"} {
		if strings.Contains(response.Body.String(), forbidden) {
			t.Fatalf("response leaked %q: %s", forbidden, response.Body.String())
		}
	}

	for _, auth := range []string{"platform", "operator"} {
		request := commandRequest(http.MethodPost, "/v1/custom-rbac/roles",
			`{"name":"reader","permissions":["sites.read"]}`)
		request.Header.Set("Authorization", auth)
		response := perform(handler, request)
		assertAPIError(t, response, http.StatusForbidden, "custom_rbac_permission_denied")
	}

	request = commandRequest(http.MethodPost, "/v1/custom-rbac/roles",
		`{"name":"reader","permissions":["sites.read"],"tenant_id":"`+uuid.NewString()+`"}`)
	request.Header.Set("Authorization", "tenant")
	response = perform(handler, request)
	assertAPIError(t, response, http.StatusBadRequest, "custom_rbac_validation_error")
}

func TestHandlerStrictInputAndMethodBoundaries(t *testing.T) {
	t.Parallel()
	handler := testHandler(t, &fakeCommands{}, &fakeReader{})
	tests := []struct {
		name    string
		request *http.Request
		status  int
		code    string
	}{
		{name: "unknown json", request: commandRequest(http.MethodPost, "/v1/custom-rbac/roles",
			`{"name":"reader","permissions":["sites.read"],"unknown":true}`), status: 400, code: "custom_rbac_validation_error"},
		{name: "trailing json", request: commandRequest(http.MethodPost, "/v1/custom-rbac/roles",
			`{"name":"reader","permissions":["sites.read"]}{}`), status: 400, code: "custom_rbac_validation_error"},
		{name: "wrong media", request: commandRequest(http.MethodPost, "/v1/custom-rbac/roles",
			`{"name":"reader","permissions":["sites.read"]}`), status: 400, code: "custom_rbac_validation_error"},
		{name: "query override", request: commandRequest(http.MethodPost, "/v1/custom-rbac/roles?tenant_id="+uuid.NewString(),
			`{"name":"reader","permissions":["sites.read"]}`), status: 400, code: "custom_rbac_validation_error"},
		{name: "client step up claim", request: commandRequest(http.MethodPost, "/v1/custom-rbac/roles",
			`{"name":"reader","permissions":["sites.read"]}`), status: 400, code: "custom_rbac_validation_error"},
		{name: "missing idempotency", request: commandRequest(http.MethodPost, "/v1/custom-rbac/roles",
			`{"name":"reader","permissions":["sites.read"]}`), status: 400, code: "custom_rbac_validation_error"},
		{name: "bad if match", request: commandRequest(http.MethodPost, "/v1/custom-rbac/roles/"+uuid.NewString()+"/publish",
			`{"permissions":["sites.read"]}`), status: 400, code: "custom_rbac_validation_error"},
		{name: "duplicate query", request: httptest.NewRequest(http.MethodGet,
			"/v1/custom-rbac/roles?limit=1&limit=2", nil), status: 400, code: "custom_rbac_validation_error"},
		{name: "permission catalog query", request: httptest.NewRequest(http.MethodGet,
			"/v1/custom-rbac/permissions?unknown=1", nil), status: 400, code: "custom_rbac_validation_error"},
		{name: "method", request: httptest.NewRequest(http.MethodDelete,
			"/v1/custom-rbac/roles", nil), status: 405, code: "custom_rbac_method_not_allowed"},
	}
	for index := range tests {
		test := &tests[index]
		t.Run(test.name, func(t *testing.T) {
			test.request.Header.Set("Authorization", "tenant")
			switch test.name {
			case "wrong media":
				test.request.Header.Set("Content-Type", "text/plain")
			case "client step up claim":
				test.request.Header.Set("X-Step-Up-Verified", "true")
			case "missing idempotency":
				test.request.Header.Del("Idempotency-Key")
			case "bad if match":
				test.request.Header.Set("If-Match", "1")
			}
			response := perform(handler, test.request)
			assertAPIError(t, response, test.status, test.code)
		})
	}

	request := commandRequest(http.MethodPost, "/v1/custom-rbac/roles", strings.Repeat("x", 2048))
	request.Header.Set("Authorization", "tenant")
	response := perform(handler, request)
	assertAPIError(t, response, http.StatusRequestEntityTooLarge, "custom_rbac_payload_too_large")
}

func TestPublicErrorMappingsAreStable(t *testing.T) {
	t.Parallel()
	tests := []struct {
		err    error
		status int
		code   string
	}{
		{rbacmanager.ErrPermissionNotAllowed, 422, "custom_rbac_permission_not_delegable"},
		{rbacmanager.ErrPermissionEscalation, 403, "custom_rbac_permission_escalation"},
		{rbacmanager.ErrSystemRoleImmutable, 409, "custom_rbac_system_role_immutable"},
		{rbacmanager.ErrTenantBoundary, 404, "custom_rbac_not_found"},
		{rbacmanager.ErrSelfAssignment, 403, "custom_rbac_self_assignment_denied"},
		{rbacmanager.ErrStepUpRequired, 428, "custom_rbac_step_up_required"},
		{rbacmanager.ErrRevisionConflict, 409, "custom_rbac_revision_conflict"},
		{rbacmanager.ErrIdempotencyConflict, 409, "custom_rbac_idempotency_conflict"},
		{rbacmanager.ErrNameConflict, 409, "custom_rbac_name_conflict"},
		{context.Canceled, 408, "custom_rbac_request_cancelled"},
		{context.DeadlineExceeded, 504, "custom_rbac_request_timeout"},
		{errors.New("SELECT secret FROM proof"), 503, "custom_rbac_store_unavailable"},
	}
	for _, test := range tests {
		status, code, _ := publicError(fmt.Errorf("wrapped: %w", test.err))
		if status != test.status || code != test.code {
			t.Errorf("publicError(%v)=(%d,%q), want (%d,%q)", test.err, status, code, test.status, test.code)
		}
	}
}

func TestRoleCursorIsSnapshotAndFilterBoundAndRejectsTampering(t *testing.T) {
	t.Parallel()
	snapshot := time.Date(2026, 7, 23, 4, 0, 0, 0, time.UTC)
	snapshotVersion := int64(3)
	ids := []uuid.UUID{uuid.MustParse("00000000-0000-7000-8000-000000000003"),
		uuid.MustParse("00000000-0000-7000-8000-000000000002"),
		uuid.MustParse("00000000-0000-7000-8000-000000000001")}
	reader := &fakeReader{rolePages: []RolePageFacts{
		{SnapshotVersion: &snapshotVersion, Items: []RoleView{
			roleView(ids[0], snapshot, 3), roleView(ids[1], snapshot.Add(-time.Second), 2),
			roleView(ids[2], snapshot.Add(-2*time.Second), 1),
		}},
		{SnapshotVersion: &snapshotVersion, Items: []RoleView{roleView(ids[2], snapshot.Add(-2*time.Second), 1)}},
	}}
	service, err := newService(&fakeCommands{}, reader, ServiceConfig{CursorKey: bytes.Repeat([]byte{4}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.ListRoles(t.Context(), tenantSession(), RoleListInput{PageInput: PageInput{Limit: 2}})
	if err != nil || len(first.Data) != 2 || first.Page.NextCursor == "" {
		t.Fatalf("first page=%#v err=%v", first, err)
	}
	second, err := service.ListRoles(t.Context(), tenantSession(), RoleListInput{
		PageInput: PageInput{Limit: 2, Cursor: first.Page.NextCursor},
	})
	if err != nil || len(second.Data) != 1 || second.Data[0].ID != ids[2] {
		t.Fatalf("second page=%#v err=%v", second, err)
	}
	reader.mu.Lock()
	secondQuery := reader.roleQueries[1]
	reader.mu.Unlock()
	if secondQuery.SnapshotVersion == nil || *secondQuery.SnapshotVersion != snapshotVersion ||
		secondQuery.AfterVersion == nil || *secondQuery.AfterVersion != 2 ||
		secondQuery.AfterID == nil || *secondQuery.AfterID != ids[1] {
		t.Fatalf("second query lost snapshot boundary: %#v", secondQuery)
	}

	tampered := tamperCursor(first.Page.NextCursor)
	if _, err := service.ListRoles(t.Context(), tenantSession(), RoleListInput{
		PageInput: PageInput{Limit: 2, Cursor: tampered},
	}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("tampered cursor error=%v", err)
	}
	if _, err := service.ListRoles(t.Context(), tenantSession(), RoleListInput{
		PageInput: PageInput{Limit: 2, Cursor: first.Page.NextCursor}, IncludeDeactivated: true,
	}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("filter-replayed cursor error=%v", err)
	}
	other := tenantSession()
	other.ScopeID = uuid.New()
	if _, err := service.ListRoles(t.Context(), other, RoleListInput{
		PageInput: PageInput{Limit: 2, Cursor: first.Page.NextCursor},
	}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("cross-scope cursor error=%v", err)
	}
}

func TestCancellationStoreFaultAndSensitiveValuesAreNotReturned(t *testing.T) {
	t.Parallel()
	commands := &fakeCommands{}
	cancelHandler := testHandlerWithConfig(t, commands, &fakeReader{waitForCancel: true}, HandlerConfig{
		QueryTimeout: time.Millisecond, CommandTimeout: time.Second,
		MaxRequestBytes: 1024, MaxResponseBytes: 4096,
	})
	request := httptest.NewRequest(http.MethodGet, "/v1/custom-rbac/roles", nil)
	request.Header.Set("Authorization", "tenant")
	response := perform(cancelHandler, request)
	assertAPIError(t, response, http.StatusGatewayTimeout, "custom_rbac_request_timeout")

	secret := "proof-secret-should-never-leak"
	var logs bytes.Buffer
	faultHandler := testHandlerWithConfig(t, commands, &fakeReader{err: errors.New("SELECT request_digest " + secret)}, HandlerConfig{
		QueryTimeout: time.Second, CommandTimeout: time.Second,
		MaxRequestBytes: 1024, MaxResponseBytes: 4096,
		Logger: slog.New(slog.NewTextHandler(&logs, nil)),
	})
	request = httptest.NewRequest(http.MethodGet, "/v1/custom-rbac/roles", nil)
	request.Header.Set("Authorization", "tenant")
	response = perform(faultHandler, request)
	assertAPIError(t, response, http.StatusServiceUnavailable, "custom_rbac_store_unavailable")
	combined := response.Body.String() + logs.String()
	for _, forbidden := range []string{secret, "SELECT", "request_digest", "step_up_proof_id", "permissions_digest"} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("HTTP/log output leaked %q: %s", forbidden, combined)
		}
	}
}

func testHandler(t *testing.T, commands Commands, reader ReadStore) *Handler {
	t.Helper()
	return testHandlerWithConfig(t, commands, reader, HandlerConfig{
		CommandTimeout: time.Second, QueryTimeout: time.Second,
		MaxRequestBytes: 1024, MaxResponseBytes: 4096,
	})
}

func testHandlerWithConfig(t *testing.T, commands Commands, reader ReadStore, config HandlerConfig) *Handler {
	t.Helper()
	service, err := newService(commands, reader, ServiceConfig{CursorKey: bytes.Repeat([]byte{9}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(service, func(request *http.Request) (AuthenticatedSession, error) {
		switch request.Header.Get("Authorization") {
		case "tenant":
			return tenantSession(), nil
		case "platform":
			value := tenantSession()
			value.ScopeKind = "platform"
			return value, nil
		case "operator":
			value := tenantSession()
			value.IdentityDomain = rbacmanager.PlatformOperatorIdentityDomain
			return value, nil
		default:
			return AuthenticatedSession{}, errors.New("not authenticated")
		}
	}, config)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func tenantSession() AuthenticatedSession {
	return AuthenticatedSession{
		UserID:    uuid.MustParse("10000000-0000-7000-8000-000000000001"),
		ScopeID:   uuid.MustParse("20000000-0000-7000-8000-000000000001"),
		SessionID: uuid.MustParse("30000000-0000-7000-8000-000000000001"),
		ScopeKind: "tenant", IdentityDomain: rbacmanager.CustomerControlIdentityDomain,
	}
}

func coreRole(scopeID uuid.UUID) rbacmanager.Role {
	return rbacmanager.Role{ID: uuid.New(), TenantID: uuid.New(), TenantScopeID: scopeID,
		Name: "reader", CurrentRevision: 1, Permissions: []string{"sites.read"},
		CreatedAt: time.Date(2026, 7, 23, 2, 0, 0, 0, time.UTC)}
}

func roleView(id uuid.UUID, createdAt time.Time, stateVersion int64) RoleView {
	return RoleView{ID: id, Name: "reader", CurrentRevision: 1,
		Permissions: []string{"sites.read"}, CreatedAt: createdAt, StateVersion: stateVersion}
}

func commandRequest(method, target, body string) *http.Request {
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "operation-1")
	request.Header.Set("X-Request-ID", "request-1")
	request.Header.Set("Traceparent", "00-"+strings.Repeat("1", 32)+"-"+strings.Repeat("2", 16)+"-01")
	return request
}

func perform(handler http.Handler, request *http.Request) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func assertAPIError(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status=%d want=%d body=%s", response.Code, status, response.Body.String())
	}
	var envelope errorEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode error response: %v body=%s", err, response.Body.String())
	}
	if envelope.Error.Code != code || envelope.Error.RequestID == "" {
		t.Fatalf("error=%#v want code=%q", envelope.Error, code)
	}
}

func tamperCursor(value string) string {
	replacement := byte('A')
	if value[len(value)-1] == replacement {
		replacement = 'B'
	}
	return value[:len(value)-1] + string(replacement)
}
