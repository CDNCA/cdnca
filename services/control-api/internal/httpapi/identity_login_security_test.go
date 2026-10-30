package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

func TestLoginSecurityTargetRejectsAmbiguousQuery(t *testing.T) {
	userID, scopeID := uuid.NewString(), uuid.NewString()
	for _, query := range []string{"", "tenant_scope_id=", "tenant_scope_id=" + scopeID + "&tenant_scope_id=" + scopeID, "tenant_scope_id=" + scopeID + "&include=user_metadata", "tenant_scope_id=" + strings.ToUpper(scopeID)} {
		request := httptest.NewRequest("GET", "/?"+query, nil)
		request.SetPathValue("id", userID)
		if _, _, ok := loginSecurityIDs(request); ok {
			t.Fatalf("accepted %s", query)
		}
	}
	request := httptest.NewRequest("GET", "/?tenant_scope_id="+scopeID, nil)
	request.SetPathValue("id", userID)
	if _, _, ok := loginSecurityIDs(request); !ok {
		t.Fatal("valid canonical target rejected")
	}
}

func TestLoginSecurityRequirementResponseHasOnlyChannelAndScope(t *testing.T) {
	s := new(Server)
	scopeID := uuid.New()
	r := httptest.NewRequest("POST", "/v1/auth/login", nil)
	w := httptest.NewRecorder()
	if !s.writeLoginSecurityError(w, r, &identity.LoginVerificationRequired{Channel: "email", ScopeID: scopeID}) {
		t.Fatal("not mapped")
	}
	var body struct {
		Error struct {
			Code   string            `json:"code"`
			Params map[string]string `json:"params"`
		} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusUnauthorized || body.Error.Code != "login_verification_required" || len(body.Error.Params) != 2 || body.Error.Params["channel"] != "email" || body.Error.Params["scope_id"] != scopeID.String() {
		t.Fatalf("response=%s", w.Body.String())
	}
	if len(w.Result().Cookies()) != 0 {
		t.Fatal("requirement response created a cookie")
	}
}
