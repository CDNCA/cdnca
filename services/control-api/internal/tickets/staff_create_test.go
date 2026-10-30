package tickets

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

// fix-ticket2 ①: staff open a ticket for a chosen user. Input is checked
// before any database work; the route exists only on the admin surface.
func TestStaffCreateRejectsInvalidInputBeforeTheDatabase(t *testing.T) {
	service := &Service{}
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), SessionID: uuid.New()}
	valid := StaffCreateInput{UserID: uuid.NewString(), Category: "billing", Subject: "余额", Body: "请核对"}
	for name, input := range map[string]StaffCreateInput{
		"no user":      {Category: "billing", Subject: "x", Body: "y"},
		"bad user":     {UserID: "u", Category: "billing", Subject: "x", Body: "y"},
		"category":     {UserID: valid.UserID, Category: "nope", Subject: "x", Body: "y"},
		"priority":     {UserID: valid.UserID, Category: "billing", Priority: "p0", Subject: "x", Body: "y"},
		"subject":      {UserID: valid.UserID, Category: "billing", Subject: " ", Body: "y"},
		"body":         {UserID: valid.UserID, Category: "billing", Subject: "x", Body: "\n"},
		"bad assignee": {UserID: valid.UserID, Category: "billing", Subject: "x", Body: "y", AssigneeUserID: "z"},
	} {
		if _, err := service.StaffCreate(context.Background(), actor, "k1", "r1", input); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s: err = %v, want ErrInvalidInput", name, err)
		}
	}
	if !slices.Contains(Patterns, "POST /v1/admin/tickets") || slices.Contains(Patterns, "GET /v1/reseller/tickets") {
		t.Fatalf("patterns = %v", Patterns)
	}
}

// The admin surface needs a platform session with tickets.manage; tenant and
// reader sessions are refused before the service runs.
func TestStaffCreateRouteAuthorization(t *testing.T) {
	sessions := map[string]identity.AuthenticatedSession{
		"tenant": {SessionID: uuid.New(), Principal: identity.Principal{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"}},
		"other":  {SessionID: uuid.New(), Principal: identity.Principal{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform", Permissions: []string{"sites.read"}}},
		"staff":  {SessionID: uuid.New(), Principal: identity.Principal{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform", Permissions: []string{PermissionManage}}},
	}
	handler, err := NewHandler(&Service{}, func(_ context.Context, token string) (identity.AuthenticatedSession, error) {
		return sessions[token], nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for token, want := range map[string]int{"tenant": http.StatusForbidden, "other": http.StatusForbidden, "staff": http.StatusBadRequest} {
		request := httptest.NewRequest(http.MethodPost, "/v1/admin/tickets", strings.NewReader(`{"user_id":"x"}`))
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", "staff-create-1")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != want {
			t.Errorf("%s: status %d body %s, want %d", token, response.Code, response.Body.String(), want)
		}
	}
}
