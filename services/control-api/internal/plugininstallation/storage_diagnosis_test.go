package plugininstallation

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

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// 首次恢复 500 时日志没有阶段、SQLSTATE、约束名，无法定因。存储边界保留安全的错误分类，
// handler 只把白名单字段写进日志（不含 SQL 参数、消息正文、幂等键）。

func TestPostgresErrorKeepsSafeClassification(t *testing.T) {
	cause := &pgconn.PgError{Code: "23505", ConstraintName: "plugin_installation_receipts_pkey",
		Message: "duplicate key value violates unique constraint", Detail: "Key (idempotency_key)=(secret-key) already exists."}
	err := postgresError(context.Background(), fmt.Errorf("insert receipt: %w", cause))
	if !errors.Is(err, ErrStorageUnavailable) {
		t.Fatalf("storage failure must stay ErrStorageUnavailable: %v", err)
	}
	class := StorageFailureOf(err)
	if class.SQLState != "23505" || class.Constraint != "plugin_installation_receipts_pkey" {
		t.Fatalf("classification=%+v", class)
	}
	if strings.Contains(err.Error(), "secret-key") || strings.Contains(err.Error(), "duplicate key") {
		t.Fatalf("error text must not carry the database message or detail: %q", err.Error())
	}
	if got := StorageFailureOf(postgresError(context.Background(), errors.New("dial tcp: refused"))); got.SQLState != "" {
		t.Fatalf("a non-PostgreSQL cause has no SQLSTATE: %+v", got)
	}
}

func TestHandlerLogsStorageClassAndCommitStage(t *testing.T) {
	tenantID, authorizationID := uuid.New(), uuid.New()
	cause := &pgconn.PgError{Code: "42501", Message: "permission denied for table plugin_installation_receipts"}
	domain := &handlerTestDomain{err: StageError("resume.apply", postgresError(context.Background(), cause))}
	handler := newHandlerForTest(t, tenantID, domain)
	var logs bytes.Buffer
	handler.logger = slog.New(slog.NewJSONHandler(&logs, nil))
	request := authenticatedHandlerRequest(http.MethodPost,
		"/v1/tenant-scopes/"+tenantID.String()+"/plugin-installations/"+authorizationID.String()+"/resume", bytes.NewBufferString(`{}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("If-Match", `"7"`)
	request.Header.Set("Idempotency-Key", "plugin-resume-diagnosis")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	assertHandlerError(t, response, http.StatusInternalServerError, "internal_error")
	for _, want := range []string{`"stage":"resume.apply"`, `"error_class":"storage"`, `"sqlstate":"42501"`, `"committed":false`} {
		if !strings.Contains(logs.String(), want) {
			t.Fatalf("log missing %s: %s", want, logs.String())
		}
	}
	if strings.Contains(logs.String(), "permission denied for table") || strings.Contains(logs.String(), "plugin-resume-diagnosis") {
		t.Fatalf("log leaked database message or idempotency key: %s", logs.String())
	}

	// 写入已提交、上报失败：结果未知，标 committed=true。
	logs.Reset()
	domain.err = StageError("resume.report", fmt.Errorf("%w: report license lifecycle", ErrResultUnknown))
	response = httptest.NewRecorder()
	request = authenticatedHandlerRequest(http.MethodPost,
		"/v1/tenant-scopes/"+tenantID.String()+"/plugin-installations/"+authorizationID.String()+"/resume", bytes.NewBufferString(`{}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("If-Match", `"7"`)
	request.Header.Set("Idempotency-Key", "plugin-resume-diagnosis")
	handler.ServeHTTP(response, request)
	assertHandlerError(t, response, http.StatusServiceUnavailable, "plugin_installation_result_unknown")
	if !strings.Contains(logs.String(), `"stage":"resume.report"`) || !strings.Contains(logs.String(), `"committed":true`) {
		t.Fatalf("report-stage log=%s", logs.String())
	}
}

func TestProductionResumeTagsStages(t *testing.T) {
	domain, repository, resolver, actor := productionResumeFixture(StatusDisabled, PausedByInstallation)
	head := repository.head
	resolver.reportErr = errors.New("license unreachable")
	_, err := domain.Mutate(context.Background(), actor, resumeRequest(actor, head))
	if !errors.Is(err, ErrResultUnknown) || StageOf(err) != "resume.report" {
		t.Fatalf("report failure err=%v stage=%q", err, StageOf(err))
	}
}
