package observabilityloghttp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/observabilitylog"
	"github.com/google/uuid"
)

type fakeDomain09 struct {
	actor        observabilitylog.Actor
	query        observabilitylog.Query
	frontend     observabilitylog.FrontendInput
	page         observabilitylog.Page
	artifact     observabilitylog.ExportArtifact
	err          error
	listCalls    int
	exportCalls  int
	recordCalls  int
	boundary     observabilitylog.AuditBoundary
	captureCalls int
}

func (domain *fakeDomain09) CaptureAuditBoundary(_ context.Context, actor observabilitylog.Actor, target uuid.UUID) (observabilitylog.AuditBoundary, error) {
	domain.captureCalls++
	domain.actor = actor
	domain.query.TargetScopeID = &target
	return domain.boundary, domain.err
}

func (domain *fakeDomain09) List(_ context.Context, actor observabilitylog.Actor, query observabilitylog.Query) (observabilitylog.Page, error) {
	domain.listCalls++
	domain.actor, domain.query = actor, query
	return domain.page, domain.err
}

func (domain *fakeDomain09) Export(_ context.Context, actor observabilitylog.Actor, query observabilitylog.Query) (observabilitylog.ExportArtifact, error) {
	domain.exportCalls++
	domain.actor, domain.query = actor, query
	return domain.artifact, domain.err
}

func (domain *fakeDomain09) RecordFrontend(_ context.Context, actor observabilitylog.Actor, input observabilitylog.FrontendInput) error {
	domain.recordCalls++
	domain.actor, domain.frontend = actor, input
	return domain.err
}

func TestOBS09HandlerTenantSessionScopeAndStrictFrontend(t *testing.T) {
	scopeID, userID, sessionID := uuid.New(), uuid.New(), uuid.New()
	domain := &fakeDomain09{page: observabilitylog.Page{Items: []observabilitylog.Fact{{
		ID: "event-1", ScopeID: scopeID, Kind: observabilitylog.KindLogin, Action: "auth.login",
		ReasonCode: "credentials_accepted", ResultCode: "success", SourceIP: "192.0.2.1",
		GeoCode: "unknown", OccurredAt: time.Date(2026, 8, 7, 9, 0, 0, 0, time.UTC),
	}}, SnapshotAt: time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)}}
	handler := tenantHandler09(t, domain, scopeID, userID, sessionID)

	request := request09(http.MethodGet, "/v1/observability/logs?kind=login&limit=20", "")
	request.Header.Set("X-Request-ID", "request-1")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || domain.listCalls != 1 || domain.actor.ScopeID != scopeID ||
		domain.actor.UserID != userID || domain.actor.SessionID != sessionID || domain.actor.RequestID != "request-1" ||
		domain.actor.SourceIP != "192.0.2.20" || domain.query.TargetScopeID != nil {
		t.Fatalf("list code=%d actor=%#v query=%#v calls=%d", response.Code, domain.actor, domain.query, domain.listCalls)
	}

	for _, body := range []string{
		`{"event_code":"render_error","route":"/home","reason_code":"component_failed","result_code":"failure","release":"2026.08.07","source_ip":"203.0.113.9"}`,
		`{"event_code":"render_error","route":"/home","reason_code":"component_failed","result_code":"failure","release":"2026.08.07","actor_id":"forged"}`,
		`{"event_code":"render_error","route":"/home","reason_code":"component_failed","result_code":"failure","release":"2026.08.07","request_id":"forged"}`,
	} {
		response = httptest.NewRecorder()
		handler.ServeHTTP(response, request09(http.MethodPost, "/v1/observability/frontend-events", body))
		if response.Code != http.StatusBadRequest || domain.recordCalls != 0 {
			t.Fatalf("unknown frontend identity field code=%d body=%s calls=%d", response.Code, response.Body.String(), domain.recordCalls)
		}
	}

	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request09(http.MethodPost, "/v1/observability/frontend-events",
		`{"event_code":"render_error","route":"/home","reason_code":"component_failed","result_code":"failure","release":"2026.08.07"}`))
	if response.Code != http.StatusAccepted || domain.recordCalls != 1 || domain.actor.ScopeID != scopeID ||
		domain.actor.UserID != userID || domain.actor.SessionID != sessionID || domain.actor.SourceIP != "192.0.2.20" ||
		domain.frontend.EventCode != "render_error" {
		t.Fatalf("frontend code=%d actor=%#v input=%#v calls=%d", response.Code, domain.actor, domain.frontend, domain.recordCalls)
	}
}

func TestOBS09HandlerParsesAccountLogParityFilters(t *testing.T) {
	platformScopeID, targetScopeID, userID, sessionID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	domain := &fakeDomain09{}
	handler := handler09(t, domain, platformSession09(platformScopeID, uuid.New(), sessionID, true))
	request := request09(http.MethodGet, "/v1/observability/logs?target_scope_id="+targetScopeID.String()+"&actor_user_id="+userID.String()+"&kind=operation&result=success&action_verb=update&resource_type=site&resource_id=site-1&change=revision&source_ip=192.0.2.1&from=2026-08-01T00%3A00%3A00Z&to=2026-08-02T00%3A00%3A00Z&limit=10", "")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || domain.listCalls != 1 || domain.query.ActionVerb != "update" ||
		domain.query.ResourceType != "site" || domain.query.ResourceID != "site-1" || domain.query.Change != "revision" ||
		domain.query.TargetScopeID == nil || *domain.query.TargetScopeID != targetScopeID ||
		domain.query.AuditActorUserID == nil || *domain.query.AuditActorUserID != userID ||
		len(domain.query.Kinds) != 1 || domain.query.Kinds[0] != observabilitylog.KindOperation ||
		len(domain.query.ResultCodes) != 1 || domain.query.ResultCodes[0] != "success" || domain.query.Limit != 10 {
		t.Fatalf("code=%d calls=%d query=%#v body=%s", response.Code, domain.listCalls, domain.query, response.Body.String())
	}
}

func TestOBS09HandlerParsesDisplayUserFilter(t *testing.T) {
	targetScopeID := uuid.New()
	domain := &fakeDomain09{}
	handler := handler09(t, domain, platformSession09(uuid.New(), uuid.New(), uuid.New(), true))
	request := request09(http.MethodGet, "/v1/observability/logs?target_scope_id="+targetScopeID.String()+"&kind=login&actor_user_display_id=1", "")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || domain.query.ActorUserDisplayID != "1" || domain.listCalls != 1 {
		t.Fatalf("code=%d query=%#v calls=%d body=%s", response.Code, domain.query, domain.listCalls, response.Body.String())
	}
}

func TestOBS09HandlerRejectsCrossScopeBeforeDomainCall(t *testing.T) {
	tenantScope, platformScope, targetScope := uuid.New(), uuid.New(), uuid.New()
	tests := []struct {
		name        string
		session     identity.AuthenticatedSession
		path        string
		wantStatus  int
		wantTarget  uuid.UUID
		wantInvoked bool
	}{
		{name: "tenant explicit target", session: tenantSession09(tenantScope, uuid.New(), uuid.New()), path: "/v1/observability/logs?target_scope_id=" + targetScope.String(), wantStatus: http.StatusForbidden},
		// 平台作用域未指定目标时读取自身作用域。
		{name: "platform missing target", session: platformSession09(platformScope, uuid.New(), uuid.New(), true), path: "/v1/observability/logs", wantStatus: http.StatusOK, wantTarget: platformScope, wantInvoked: true},
		{name: "platform missing permission", session: platformSession09(platformScope, uuid.New(), uuid.New(), false), path: "/v1/observability/logs?target_scope_id=" + targetScope.String(), wantStatus: http.StatusForbidden},
		{name: "platform explicit target", session: platformSession09(platformScope, uuid.New(), uuid.New(), true), path: "/v1/observability/logs?target_scope_id=" + targetScope.String(), wantStatus: http.StatusOK, wantTarget: targetScope, wantInvoked: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			domain := &fakeDomain09{}
			handler := handler09(t, domain, test.session)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request09(http.MethodGet, test.path, ""))
			if response.Code != test.wantStatus || (domain.listCalls == 1) != test.wantInvoked {
				t.Fatalf("code=%d body=%s calls=%d", response.Code, response.Body.String(), domain.listCalls)
			}
			// 未指定目标时请求里没有 target_scope_id，作用域由 actor 自身补齐。
			got := domain.actor.ScopeID
			if domain.query.TargetScopeID != nil {
				got = *domain.query.TargetScopeID
			}
			if test.wantInvoked && got != test.wantTarget {
				t.Fatalf("target=%v want=%s", got, test.wantTarget)
			}
		})
	}
}

func TestOBS09HandlerPlatformFrontendUsesExplicitTarget(t *testing.T) {
	platformScope, targetScope := uuid.New(), uuid.New()
	domain := &fakeDomain09{}
	handler := handler09(t, domain, platformSession09(platformScope, uuid.New(), uuid.New(), true))
	body := `{"event_code":"api_error","route":"/sys/log","reason_code":"dependency_unavailable","result_code":"failure","release":"2026.08.07"}`

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request09(http.MethodPost, "/v1/observability/frontend-events", body))
	if response.Code != http.StatusBadRequest || domain.recordCalls != 0 {
		t.Fatalf("missing target code=%d calls=%d", response.Code, domain.recordCalls)
	}

	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request09(http.MethodPost, "/v1/observability/frontend-events?target_scope_id="+targetScope.String(), body))
	if response.Code != http.StatusAccepted || domain.recordCalls != 1 || domain.actor.ScopeID != targetScope ||
		domain.actor.ScopeKind != observabilitylog.ScopePlatform || domain.actor.SourceIP != "192.0.2.20" {
		t.Fatalf("explicit target code=%d actor=%#v calls=%d", response.Code, domain.actor, domain.recordCalls)
	}
}

func TestOBS09HandlerRejectsNonSessionCredential(t *testing.T) {
	domain := &fakeDomain09{}
	handler := tenantHandler09(t, domain, uuid.New(), uuid.New(), uuid.New())
	request := httptest.NewRequest(http.MethodGet, "/v1/observability/logs", nil)
	request.Header.Set("Authorization", "ApiKey must-not-be-accepted")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || domain.listCalls != 0 || strings.Contains(response.Body.String(), "must-not-be-accepted") {
		t.Fatalf("code=%d calls=%d body=%s", response.Code, domain.listCalls, response.Body.String())
	}
}

func TestOBS09HandlerValidatesExportBeforeWriting(t *testing.T) {
	scopeID := uuid.New()
	validContent := []byte("event_id\r\nevent-1\r\n")
	validDigest := sha256.Sum256(validContent)
	tests := []struct {
		name       string
		artifact   observabilitylog.ExportArtifact
		domainErr  error
		wantStatus int
		wantBody   string
	}{
		{name: "valid", artifact: observabilitylog.ExportArtifact{Content: validContent, SHA256: hex.EncodeToString(validDigest[:])}, wantStatus: http.StatusOK, wantBody: string(validContent)},
		{name: "uppercase digest", artifact: observabilitylog.ExportArtifact{Content: validContent, SHA256: strings.Repeat("A", 64)}, wantStatus: http.StatusServiceUnavailable},
		{name: "digest mismatch", artifact: observabilitylog.ExportArtifact{Content: validContent, SHA256: strings.Repeat("a", 64)}, wantStatus: http.StatusServiceUnavailable},
		{name: "oversize", artifact: observabilitylog.ExportArtifact{Content: make([]byte, (8<<20)+1), SHA256: strings.Repeat("a", 64)}, wantStatus: http.StatusServiceUnavailable},
		{name: "dependency secret", domainErr: errors.New("postgres password=do-not-return"), wantStatus: http.StatusServiceUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			domain := &fakeDomain09{artifact: test.artifact, err: test.domainErr}
			handler := tenantHandler09(t, domain, scopeID, uuid.New(), uuid.New())
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request09(http.MethodGet, "/v1/observability/logs/export?kind=login", ""))
			if response.Code != test.wantStatus || strings.Contains(response.Body.String(), "do-not-return") {
				t.Fatalf("code=%d headers=%v body_bytes=%d", response.Code, response.Header(), response.Body.Len())
			}
			if test.wantStatus == http.StatusOK {
				if response.Body.String() != test.wantBody || response.Header().Get("Content-Disposition") != `attachment; filename="observability-logs.csv"` ||
					response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("X-Content-Type-Options") != "nosniff" ||
					response.Header().Get("X-Content-SHA256") != hex.EncodeToString(validDigest[:]) {
					t.Fatalf("valid export headers=%v body=%q", response.Header(), response.Body.String())
				}
			} else if response.Header().Get("Content-Disposition") != "" || response.Header().Get("X-Content-SHA256") != "" ||
				strings.Contains(response.Body.String(), "event-1") {
				t.Fatalf("invalid artifact was partially exposed: headers=%v body=%q", response.Header(), response.Body.String())
			}
		})
	}
}

func TestOBS09HandlerOpaqueAuditBoundaryAndExactActorQuery(t *testing.T) {
	targetScopeID, authorityID, sessionID, browserActorID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	domain := &fakeDomain09{boundary: observabilitylog.AuditBoundary{Token: "opaque.signed.boundary"}}
	handler := handler09(t, domain, platformSession09(uuid.New(), authorityID, sessionID, true))

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request09(http.MethodGet, "/v1/observability/logs?target_scope_id="+targetScopeID.String()+"&audit_boundary=capture", ""))
	if response.Code != http.StatusOK || domain.captureCalls != 1 || domain.listCalls != 0 ||
		!strings.Contains(response.Body.String(), `"audit_boundary":"opaque.signed.boundary"`) ||
		strings.Contains(response.Body.String(), "stream_position") || strings.Contains(response.Body.String(), "payload") {
		t.Fatalf("capture code=%d calls=(%d,%d) body=%s", response.Code, domain.captureCalls, domain.listCalls, response.Body.String())
	}

	response = httptest.NewRecorder()
	path := "/v1/observability/logs?target_scope_id=" + targetScopeID.String() + "&kind=operation&actor_user_id=" + browserActorID.String() + "&after_audit_boundary=opaque.signed.boundary&limit=100"
	handler.ServeHTTP(response, request09(http.MethodGet, path, ""))
	if response.Code != http.StatusOK || domain.listCalls != 1 || domain.query.AuditActorUserID == nil ||
		*domain.query.AuditActorUserID != browserActorID || domain.query.AfterAuditBoundary != "opaque.signed.boundary" {
		t.Fatalf("after code=%d query=%#v calls=%d body=%s", response.Code, domain.query, domain.listCalls, response.Body.String())
	}
}

func TestOBS09HandlerRejectsUnsafeAuditBoundaryParametersBeforeDomain(t *testing.T) {
	targetScopeID, actorID := uuid.New(), uuid.New()
	tests := map[string]string{
		"capture filter":     "/v1/observability/logs?target_scope_id=" + targetScopeID.String() + "&audit_boundary=capture&kind=operation",
		"tenant capture":     "/v1/observability/logs?audit_boundary=capture",
		"duplicate boundary": "/v1/observability/logs?target_scope_id=" + targetScopeID.String() + "&audit_boundary=capture&audit_boundary=capture",
		"duplicate actor":    "/v1/observability/logs?target_scope_id=" + targetScopeID.String() + "&kind=operation&actor_user_id=" + actorID.String() + "&actor_user_id=" + actorID.String() + "&after_audit_boundary=token",
		"oversized boundary": "/v1/observability/logs?target_scope_id=" + targetScopeID.String() + "&kind=operation&actor_user_id=" + actorID.String() + "&after_audit_boundary=" + strings.Repeat("a", 4097),
		"mixed notification": "/v1/observability/logs?target_scope_id=" + targetScopeID.String() + "&kind=operation,notification&actor_user_id=" + actorID.String() + "&after_audit_boundary=token",
		"unknown":            "/v1/observability/logs?target_scope_id=" + targetScopeID.String() + "&audit_boundary=capture&stream_position=1",
	}
	for name, path := range tests {
		t.Run(name, func(t *testing.T) {
			domain := &fakeDomain09{}
			session := platformSession09(uuid.New(), uuid.New(), uuid.New(), true)
			if name == "tenant capture" {
				session = tenantSession09(targetScopeID, uuid.New(), uuid.New())
			}
			handler := handler09(t, domain, session)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request09(http.MethodGet, path, ""))
			if response.Code != http.StatusBadRequest && response.Code != http.StatusForbidden || domain.captureCalls != 0 || domain.listCalls != 0 {
				t.Fatalf("code=%d capture=%d list=%d body=%s", response.Code, domain.captureCalls, domain.listCalls, response.Body.String())
			}
		})
	}
}

func tenantHandler09(t *testing.T, domain observabilitylog.Domain, scopeID, userID, sessionID uuid.UUID) *Handler {
	t.Helper()
	return handler09(t, domain, tenantSession09(scopeID, userID, sessionID))
}

func handler09(t *testing.T, domain observabilitylog.Domain, session identity.AuthenticatedSession) *Handler {
	t.Helper()
	handler, err := NewHandler(Dependencies{Domain: domain, AuthenticateSession: func(_ context.Context, token string) (identity.AuthenticatedSession, error) {
		if token != "session-token" {
			return identity.AuthenticatedSession{}, identity.ErrInvalidSession
		}
		return session, nil
	}, ResolveClientIP: func(*http.Request) string { return "192.0.2.20" }})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func tenantSession09(scopeID, userID, sessionID uuid.UUID) identity.AuthenticatedSession {
	tenantID := scopeID
	return identity.AuthenticatedSession{SessionID: sessionID, Principal: identity.Principal{UserID: userID, ScopeID: scopeID,
		ScopeKind: observabilitylog.ScopeTenant, TenantID: &tenantID, Permissions: []string{"identity.self.read"}}}
}

func platformSession09(scopeID, userID, sessionID uuid.UUID, admin bool) identity.AuthenticatedSession {
	var permissions []string
	if admin {
		permissions = []string{"platform.admin"}
	}
	return identity.AuthenticatedSession{SessionID: sessionID, Principal: identity.Principal{UserID: userID, ScopeID: scopeID,
		ScopeKind: observabilitylog.ScopePlatform, Permissions: permissions}}
}

func request09(method, target, body string) *http.Request {
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer session-token")
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	return request
}
