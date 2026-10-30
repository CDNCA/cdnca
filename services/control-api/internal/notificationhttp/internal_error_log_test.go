package notificationhttp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/notificationcontrol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

type failingSubscriptionService struct {
	stubService
	err error
}

func (s *failingSubscriptionService) GetSubscription(context.Context, notificationcontrol.Actor, string) (notificationcontrol.Subscription, error) {
	return notificationcontrol.Subscription{}, s.err
}

// notif-sub（A8）：未分类错误仍只回 internal_error，但要记一条脱敏日志：
// 错误类型链、SQLSTATE、约束名和 request_id；不带令牌、SQL 文本或报错原文。
func TestHandlerLogsUnclassifiedErrorWithoutSecrets(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	session := identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{
		UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant",
	}}
	pgErr := &pgconn.PgError{Code: "40P01", ConstraintName: "auth_sessions_pkey",
		Message: "deadlock detected secret-detail", Detail: "Process 1 waits for ShareLock secret-detail"}
	service := &failingSubscriptionService{err: fmt.Errorf("get notification subscription: %w", pgErr)}
	handler, err := New(service, func(*http.Request) (identity.AuthenticatedSession, error) { return session, nil })
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/account/notification-subscriptions/ticket.replied", nil)
	request.Header.Set("Authorization", "Bearer secret-access-token")
	request.Header.Set("X-Request-ID", "notif-sub-log-1")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), `"internal_error"`) {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	line := logs.String()
	for _, want := range []string{`"sqlstate":"40P01"`, `"constraint":"auth_sessions_pkey"`, `"request_id":"notif-sub-log-1"`,
		`*pgconn.PgError`, `"route":"GET /v1/account/notification-subscriptions/{event_type}"`} {
		if !strings.Contains(line, want) {
			t.Fatalf("log missing %s: %s", want, line)
		}
	}
	for _, leaked := range []string{"secret-access-token", "secret-detail", "Bearer"} {
		if strings.Contains(line, leaked) || strings.Contains(response.Body.String(), leaked) {
			t.Fatalf("leaked %q: log=%s body=%s", leaked, line, response.Body.String())
		}
	}

	// 分类错误（404 等）不记错误日志。
	logs.Reset()
	service.err = fmt.Errorf("get: %w", notificationcontrol.ErrNotFound)
	handler.ServeHTTP(httptest.NewRecorder(), request)
	if logs.Len() != 0 {
		t.Fatalf("classified error logged: %s", logs.String())
	}

	// 非 PG 错误也要留下类型，便于区分。
	service.err = errors.Join(errors.New("first"), context.DeadlineExceeded)
	handler.ServeHTTP(httptest.NewRecorder(), request)
	if !strings.Contains(logs.String(), `"context_deadline":true`) {
		t.Fatalf("deadline not flagged: %s", logs.String())
	}
}
