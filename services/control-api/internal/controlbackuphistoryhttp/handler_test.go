package controlbackuphistoryhttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/controlbackuphistory"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

type historyReaderStub struct {
	page  controlbackuphistory.Page
	err   error
	query controlbackuphistory.Query
}

func (stub *historyReaderStub) List(_ context.Context, query controlbackuphistory.Query) (controlbackuphistory.Page, error) {
	stub.query = query
	return stub.page, stub.err
}

func TestHandlerAuthCapabilityAndQueryBoundaries(t *testing.T) {
	platform := identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform", Permissions: []string{"platform.admin"}}}
	reader := &historyReaderStub{page: controlbackuphistory.Page{Schema: "cdnca.control-backup-history/v1", Items: []controlbackuphistory.Record{}, SnapshotAt: time.Now().UTC()}}
	handler, err := NewHandler(Dependencies{Reader: reader, AuthenticateSession: func(context.Context, string) (identity.AuthenticatedSession, error) { return platform, nil }})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, path string
		session    identity.AuthenticatedSession
		want       int
	}{
		{name: "anonymous", path: "/v1/admin/system-backup-runs", want: http.StatusUnauthorized},
		{name: "tenant denied", path: "/v1/admin/system-backup-runs", session: identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant", Permissions: []string{"platform.admin"}}}, want: http.StatusForbidden},
		{name: "invalid limit", path: "/v1/admin/system-backup-runs?limit=two", session: platform, want: http.StatusBadRequest},
		{name: "valid filters", path: "/v1/admin/system-backup-runs?backup_id=run-1&state=unknown&limit=30&from=2026-09-01T00:00:00Z&to=2026-09-28T00:00:00Z", session: platform, want: http.StatusOK},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			current := test.session
			if current.SessionID == uuid.Nil {
				handler.authenticate = func(context.Context, string) (identity.AuthenticatedSession, error) {
					return identity.AuthenticatedSession{}, context.Canceled
				}
			} else {
				handler.authenticate = func(context.Context, string) (identity.AuthenticatedSession, error) { return current, nil }
			}
			request := httptest.NewRequest(http.MethodGet, test.path, nil)
			if test.name != "anonymous" {
				request.Header.Set("Authorization", "Bearer token")
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
	if reader.query.Limit != 30 || reader.query.BackupID != "run-1" || reader.query.State != "unknown" {
		t.Fatalf("query=%+v", reader.query)
	}
}

func TestHandlerReturnsUnavailableWithoutReaderAndReaderErrors(t *testing.T) {
	platform := identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform", Permissions: []string{"platform.admin"}}}
	auth := func(context.Context, string) (identity.AuthenticatedSession, error) { return platform, nil }
	for _, test := range []struct {
		name   string
		reader controlbackuphistory.Reader
		err    error
		want   int
	}{
		{name: "missing capability", reader: nil, want: http.StatusServiceUnavailable},
		{name: "no backup runner bound", reader: controlbackuphistory.Unconfigured{Now: time.Now}, want: http.StatusOK},
		{name: "reader unavailable", reader: &historyReaderStub{err: controlbackuphistory.ErrUnavailable}, want: http.StatusServiceUnavailable},
		{name: "reader invalid cursor", reader: &historyReaderStub{err: controlbackuphistory.ErrInvalidCursor}, want: http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler, err := NewHandler(Dependencies{Reader: test.reader, AuthenticateSession: auth})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodGet, "/v1/admin/system-backup-runs", nil)
			request.Header.Set("Authorization", "Bearer token")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.want || strings.Contains(response.Body.String(), "secret") {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestParseQueryObservedBackupHistoryLimits(t *testing.T) {
	for _, limit := range []int{10, 30, 100, 300} {
		query, err := parseQuery(url.Values{"limit": {strconv.Itoa(limit)}})
		if err != nil || query.Limit != limit {
			t.Errorf("limit=%d: query=%+v err=%v", limit, query, err)
		}
	}
	for _, limit := range []string{"-1", "0", "20", "50", "301", "030", "300.0"} {
		if _, err := parseQuery(url.Values{"limit": {limit}}); err != controlbackuphistory.ErrInvalidInput {
			t.Errorf("limit=%s: err=%v, want invalid input", limit, err)
		}
	}
}
