package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fix-smallfu：grant_all_scopes 只被轮换（简单版"重置密钥"）接受；激活、吊销带上它一律 400。
func TestAPIKeyMutationBodyGrantAllScopesOnlyWhereAllowed(t *testing.T) {
	decode := func(body string, allow bool) (*httptest.ResponseRecorder, []string, bool, bool) {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/v1/account/api-keys/x/rotate", strings.NewReader(body))
		allowlist, grantAll, ok := decodeAPIKeyMutationBodyWith(recorder, request, allow)
		return recorder, allowlist, grantAll, ok
	}
	if _, allowlist, grantAll, ok := decode(`{"ip_allowlist":["192.0.2.0/24"],"grant_all_scopes":true}`, true); !ok || !grantAll || len(allowlist) != 1 {
		t.Fatalf("rotate grant_all_scopes = (%v, %v, %v)", allowlist, grantAll, ok)
	}
	if _, _, grantAll, ok := decode(`{"ip_allowlist":[]}`, true); !ok || grantAll {
		t.Fatalf("rotate without flag = (%v, %v)", grantAll, ok)
	}
	if _, _, _, ok := decode(`{"ip_allowlist":[],"grant_all_scopes":false}`, false); !ok {
		t.Fatal("explicit false must stay accepted for non-rotate operations")
	}
	recorder, _, _, ok := decode(`{"ip_allowlist":[],"grant_all_scopes":true}`, false)
	if ok || recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "invalid_request") {
		t.Fatalf("non-rotate grant_all_scopes = ok=%v status=%d body=%s", ok, recorder.Code, recorder.Body.String())
	}
}
