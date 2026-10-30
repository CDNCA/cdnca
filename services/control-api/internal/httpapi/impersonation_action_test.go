package httpapi

import (
	"net/http/httptest"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/impersonation"
)

// 代登录打开"API 密钥"页不能 401；只读列表可用，产生秘密的写操作仍被拒。
func TestImpersonationAPIKeyReadIsNotSensitive(t *testing.T) {
	for _, c := range []struct {
		method, path string
		sensitive   bool
	}{
		{"GET", "/v1/account/api-keys", false},
		{"GET", "/v1/account/api-keys/compatibility", false},
		{"POST", "/v1/account/api-keys", true},
		{"POST", "/v1/account/api-keys/k1/rotate", true},
	} {
		action := impersonationRequestAction(httptest.NewRequest(c.method, c.path, nil))
		if got := impersonation.SensitiveAction(action); got != c.sensitive {
			t.Errorf("%s %s -> %s sensitive=%v, want %v", c.method, c.path, action, got, c.sensitive)
		}
	}
}
