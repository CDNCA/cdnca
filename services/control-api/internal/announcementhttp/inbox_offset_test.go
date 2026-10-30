package announcementhttp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/announcement"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

// tp-b7：消息查询按页码分页。offset 只接受规范的非负整数、不超过上限，且不能和游标一起用；
// 这些都在读库之前拒绝（Store 没有连接池，读库就会 panic）。
func TestInboxOffsetIsValidatedBeforeTheStore(t *testing.T) {
	tenant := identity.Principal{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant", Permissions: []string{"announcements.read"}}
	handler, err := New(&announcement.Store{}, AuthenticateFunc(func(*http.Request) (SessionEnvelope, error) {
		return SessionEnvelope{Principal: tenant, SessionID: uuid.New()}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{"offset=-1", "offset=abc", "offset=01", "offset=%2B5", "offset=10001", "offset=20&cursor=abc", "offset=1&offset=2"} {
		request := httptest.NewRequest(http.MethodGet, "/v1/account/messages?"+query, nil)
		writer := httptest.NewRecorder()
		handler.Handler().ServeHTTP(writer, request)
		if writer.Code != http.StatusBadRequest || !strings.Contains(writer.Body.String(), `"code":"validation_error"`) {
			t.Fatalf("%s: status = %d %s", query, writer.Code, writer.Body.String())
		}
	}
}
