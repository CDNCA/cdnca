package auditloghttp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/auditlog"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

type fakeReader struct {
	filters []auditlog.Filter
	locale  audit.Locale
	rows    int
}

func (reader *fakeReader) List(_ context.Context, filter auditlog.Filter, locale audit.Locale, _ *time.Location) (auditlog.Page, error) {
	reader.filters, reader.locale = append(reader.filters, filter), locale
	return auditlog.Page{Items: []audit.Rendered{{ID: "x", Summary: "s"}}}, nil
}

func (reader *fakeReader) Export(_ context.Context, filter auditlog.Filter, locale audit.Locale, _ *time.Location, out io.Writer) (int, error) {
	reader.filters, reader.locale = append(reader.filters, filter), locale
	_, err := io.WriteString(out, "时间\n")
	return reader.rows, err
}

var (
	platformScope = uuid.MustParse("00000000-0000-7000-8000-000000000001")
	tenantScope   = uuid.MustParse("00000000-0000-7000-8000-000000000002")
	otherScope    = uuid.MustParse("00000000-0000-7000-8000-000000000003")
	userID        = uuid.MustParse("00000000-0000-7000-8000-000000000009")
)

func newHandler(t *testing.T, reader *fakeReader, principal identity.Principal, events *[]audit.Event, auditErr error) *Handler {
	t.Helper()
	handler, err := NewHandler(Dependencies{Reader: reader,
		Authenticate: func(_ context.Context, token string) (identity.AuthenticatedSession, error) {
			if token != "good" {
				return identity.AuthenticatedSession{}, errors.New("bad token")
			}
			return identity.AuthenticatedSession{SessionID: uuid.New(), Principal: principal}, nil
		},
		Audit: func(_ context.Context, event audit.Event) error {
			*events = append(*events, event)
			return auditErr
		}, DefaultLocation: time.UTC})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func get(handler http.Handler, target string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, target, nil)
	request.Header.Set("Authorization", "Bearer good")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func platformAdmin() identity.Principal {
	return identity.Principal{UserID: userID, ScopeID: platformScope, ScopeKind: "platform", Permissions: []string{"platform.admin"}}
}

func tenantUser() identity.Principal {
	return identity.Principal{UserID: userID, ScopeID: tenantScope, ScopeKind: "tenant", Permissions: []string{"identity.self.read"}}
}

func TestTenantSeesOnlyOwnScope(t *testing.T) {
	reader := &fakeReader{}
	var events []audit.Event
	handler := newHandler(t, reader, tenantUser(), &events, nil)
	if recorder := get(handler, "/v1/audit-logs?category=site&lang=en"); recorder.Code != http.StatusOK {
		t.Fatalf("status %d: %s", recorder.Code, recorder.Body)
	}
	filter := reader.filters[0]
	if len(filter.ScopeIDs) != 1 || filter.ScopeIDs[0] != tenantScope || filter.Category != "site" || reader.locale != audit.LocaleEN {
		t.Fatalf("filter = %+v locale %s", filter, reader.locale)
	}
	if recorder := get(handler, "/v1/audit-logs?scope_id="+otherScope.String()); recorder.Code != http.StatusBadRequest {
		t.Fatalf("tenant reading another scope: status %d", recorder.Code)
	}
}

func TestPlatformAdminFiltersAnyScope(t *testing.T) {
	reader := &fakeReader{}
	var events []audit.Event
	handler := newHandler(t, reader, platformAdmin(), &events, nil)
	if recorder := get(handler, "/v1/audit-logs?category=all"); recorder.Code != http.StatusOK || len(reader.filters[0].ScopeIDs) != 0 ||
		reader.filters[0].Category != "" {
		t.Fatalf("all scopes: %d %+v", recorder.Code, reader.filters)
	}
	if recorder := get(handler, "/v1/audit-logs?scope_id="+otherScope.String()); recorder.Code != http.StatusOK ||
		reader.filters[1].ScopeIDs[0] != otherScope {
		t.Fatalf("one scope: %d %+v", recorder.Code, reader.filters)
	}
	for _, query := range []string{"category=nope", "result=maybe", "source_ip=1.2.3", "since=yesterday", "tz=Mars/Base"} {
		if recorder := get(handler, "/v1/audit-logs?"+query); recorder.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d", query, recorder.Code)
		}
	}
}

func TestPermissionAndAuthentication(t *testing.T) {
	var events []audit.Event
	noPermission := tenantUser()
	noPermission.Permissions = nil
	if recorder := get(newHandler(t, &fakeReader{}, noPermission, &events, nil), "/v1/audit-logs"); recorder.Code != http.StatusForbidden {
		t.Fatalf("no permission: %d", recorder.Code)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/audit-logs", nil)
	recorder := httptest.NewRecorder()
	newHandler(t, &fakeReader{}, platformAdmin(), &events, nil).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d", recorder.Code)
	}
}

func TestExportIsAuditedBeforeReturning(t *testing.T) {
	reader := &fakeReader{rows: 3}
	var events []audit.Event
	recorder := get(newHandler(t, reader, tenantUser(), &events, nil), "/v1/audit-logs/export?category=finance")
	if recorder.Code != http.StatusOK || !strings.HasPrefix(recorder.Body.String(), "\ufeff时间") ||
		!strings.HasPrefix(recorder.Header().Get("Content-Type"), "text/csv") {
		t.Fatalf("export: %d %q", recorder.Code, recorder.Body)
	}
	if len(events) != 1 || events[0].Action != ExportAction || events[0].ScopeID != tenantScope ||
		events[0].ResourceID != tenantScope.String() || events[0].Payload["rows"] != 3 || events[0].Payload["category"] != "finance" {
		t.Fatalf("export audit = %+v", events)
	}
	if _, ok := audit.Lookup(ExportAction); !ok {
		t.Fatal("export action is not catalogued")
	}

	// No audit, no file.
	events = nil
	recorder = get(newHandler(t, reader, tenantUser(), &events, errors.New("db down")), "/v1/audit-logs/export")
	if recorder.Code != http.StatusServiceUnavailable || strings.Contains(recorder.Body.String(), "时间") {
		t.Fatalf("export without audit: %d %q", recorder.Code, recorder.Body)
	}
}

func TestCategoriesListEveryCategory(t *testing.T) {
	var events []audit.Event
	recorder := get(newHandler(t, &fakeReader{}, tenantUser(), &events, nil), "/v1/audit-logs/categories")
	var body struct {
		Items []categoryView `json:"items"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil || len(body.Items) != len(audit.Categories()) {
		t.Fatalf("categories: %d %v %s", recorder.Code, err, recorder.Body)
	}
	if body.Items[0].Label != "管理员操作" || body.Items[0].DefaultDays != 365 || body.Items[0].Actions == 0 {
		t.Fatalf("first category = %+v", body.Items[0])
	}
}
