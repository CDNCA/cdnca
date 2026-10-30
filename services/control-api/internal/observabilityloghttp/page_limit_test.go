package observabilityloghttp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/observabilitylog"
	"github.com/google/uuid"
)

type pageLimitRepository struct {
	observabilitylog.Repository
	pages   [][]observabilitylog.Fact
	queries []observabilitylog.StoreQuery
}

func (repository *pageLimitRepository) ListFacts(_ context.Context, query observabilitylog.StoreQuery) ([]observabilitylog.Fact, error) {
	repository.queries = append(repository.queries, query)
	return repository.pages[len(repository.queries)-1], nil
}

func TestLogPageLimitHTTPWithService(t *testing.T) {
	now := time.Date(2026, 9, 28, 9, 0, 0, 0, time.UTC)
	scopeID, userID := uuid.New(), uuid.New()
	for _, total := range []int{0, 299, 300, 301} {
		t.Run(fmt.Sprintf("%d facts", total), func(t *testing.T) {
			rows := make([]observabilitylog.Fact, total)
			for index := range rows {
				rows[index] = observabilitylog.Fact{ID: fmt.Sprintf("event-%03d", total-index), ScopeID: scopeID,
					Kind: observabilitylog.KindOperation, ActorUserID: &userID, Action: "site.update",
					ReasonCode: "site.update", ResultCode: "success", SourceIP: "unknown", GeoCode: "unknown",
					OccurredAt: now.Add(-time.Minute), TotalCount: int64(total)}
			}
			repository := &pageLimitRepository{pages: [][]observabilitylog.Fact{rows}}
			if total > 300 {
				repository.pages = append(repository.pages, rows[300:])
			}
			service, err := observabilitylog.NewService(repository, []byte("0123456789abcdef0123456789abcdef"), func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			handler := tenantHandler09(t, service, scopeID, userID, uuid.New())
			cursor := ""
			seen := 0
			for pageNumber := range repository.pages {
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request09(http.MethodGet, "/v1/observability/logs?kind=operation&limit=300&cursor="+url.QueryEscape(cursor), ""))
				if response.Code != http.StatusOK {
					t.Fatalf("page %d status=%d body=%s", pageNumber, response.Code, response.Body.String())
				}
				var page observabilitylog.Page
				if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil {
					t.Fatal(err)
				}
				query := repository.queries[pageNumber]
				if query.Limit != 301 || query.ScopeID != scopeID || query.ActorUserID == nil || *query.ActorUserID != userID ||
					len(page.Items) != min(300, total-seen) || page.TotalCount != int64(total) || !page.SnapshotAt.Equal(now) {
					t.Fatalf("page %d count=%d total=%d query=%+v", pageNumber, len(page.Items), page.TotalCount, query)
				}
				if seen == 0 {
					if query.BeforeID != "" || !query.BeforeTime.IsZero() {
						t.Fatalf("first page has cursor boundary: %+v", query)
					}
				} else if query.BeforeID != rows[seen-1].ID || !query.BeforeTime.Equal(rows[seen-1].OccurredAt) {
					t.Fatalf("cursor skipped or repeated the boundary: %+v", query)
				}
				for _, row := range page.Items {
					if row.ID != rows[seen].ID {
						t.Fatalf("item %d=%q, want %q", seen, row.ID, rows[seen].ID)
					}
					seen++
				}
				if (page.NextCursor != "") != (seen < total) {
					t.Fatalf("seen=%d total=%d cursor=%q", seen, total, page.NextCursor)
				}
				cursor = page.NextCursor
			}
			if seen != total || len(repository.queries) != len(repository.pages) {
				t.Fatalf("seen=%d total=%d calls=%d", seen, total, len(repository.queries))
			}
		})
	}
}

func TestLogPageLimitHTTPRejectsOversizeBeforeRepository(t *testing.T) {
	for _, limit := range []string{"301", "1000", "-1", "300.5", "999999999999999999999999999999"} {
		t.Run(limit, func(t *testing.T) {
			repository := &pageLimitRepository{}
			service, err := observabilitylog.NewService(repository, []byte("0123456789abcdef0123456789abcdef"), time.Now)
			if err != nil {
				t.Fatal(err)
			}
			handler := tenantHandler09(t, service, uuid.New(), uuid.New(), uuid.New())
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request09(http.MethodGet, "/v1/observability/logs?limit="+limit, ""))
			if response.Code != http.StatusBadRequest || len(repository.queries) != 0 ||
				!strings.Contains(response.Body.String(), `"code":"observability_logs_invalid_request"`) {
				t.Fatalf("limit=%s status=%d queries=%d body=%s", limit, response.Code, len(repository.queries), response.Body.String())
			}
		})
	}
}

// A18：游标失效与普通参数错误分开返回稳定码，前端才能只清游标重查第一页。
func TestA18InvalidCursorHasStableRecoverableCode(t *testing.T) {
	repository := &pageLimitRepository{}
	service, err := observabilitylog.NewService(repository, []byte("0123456789abcdef0123456789abcdef"), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	handler := tenantHandler09(t, service, uuid.New(), uuid.New(), uuid.New())
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request09(http.MethodGet, "/v1/observability/logs?kind=login&cursor=tampered.cursor", ""))
	if response.Code != http.StatusBadRequest || len(repository.queries) != 0 ||
		!strings.Contains(response.Body.String(), `"code":"observability_logs_cursor_expired"`) {
		t.Fatalf("status=%d queries=%d body=%s", response.Code, len(repository.queries), response.Body.String())
	}
}
