package identity

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestTenantScopeDisplayIDMarshalsAsString(t *testing.T) {
	encoded, err := json.Marshal(TenantScope{
		ScopeID: uuid.New(), TenantID: uuid.New(), TenantName: "Alpha Tenant", Status: "active", DisplayID: "12",
	})
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(encoded, &payload); err != nil {
		t.Fatal(err)
	}
	if displayID, ok := payload["display_id"].(string); !ok || displayID != "12" {
		t.Fatalf("display_id = %#v, want decimal string %q", payload["display_id"], "12")
	}
}

func TestListTenantScopesRejectsInvalidActorsAndBounds(t *testing.T) {
	service := &Service{}
	validActor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform"}
	longSearch := strings.Repeat("租", 129)

	tests := []struct {
		name  string
		actor Actor
		input ListTenantScopesInput
	}{
		{name: "missing user", actor: Actor{ScopeID: validActor.ScopeID, ScopeKind: "platform"}, input: ListTenantScopesInput{Page: 1, Limit: 50}},
		{name: "tenant actor", actor: Actor{UserID: validActor.UserID, ScopeID: validActor.ScopeID, ScopeKind: "tenant"}, input: ListTenantScopesInput{Page: 1, Limit: 50}},
		{name: "page below one", actor: validActor, input: ListTenantScopesInput{Page: 0, Limit: 50}},
		{name: "page above maximum", actor: validActor, input: ListTenantScopesInput{Page: 1_000_001, Limit: 50}},
		{name: "limit below one", actor: validActor, input: ListTenantScopesInput{Page: 1, Limit: 0}},
		{name: "limit above maximum", actor: validActor, input: ListTenantScopesInput{Page: 1, Limit: 101}},
		{name: "search above rune limit", actor: validActor, input: ListTenantScopesInput{Page: 1, Limit: 50, Search: longSearch}},
		{name: "parent not a UUID", actor: validActor, input: ListTenantScopesInput{Page: 1, Limit: 50, Parent: "reseller"}},
		{name: "parent nil UUID", actor: validActor, input: ListTenantScopesInput{Page: 1, Limit: 50, Parent: uuid.Nil.String()}},
		{name: "parent upper case UUID", actor: validActor, input: ListTenantScopesInput{Page: 1, Limit: 50, Parent: strings.ToUpper(uuid.NewString())}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := service.ListTenantScopes(context.Background(), test.actor, test.input)
			if !errors.Is(err, ErrInvalidUserInput) {
				t.Fatalf("ListTenantScopes() error = %v, want ErrInvalidUserInput", err)
			}
		})
	}
}

func TestListTenantScopesRequiresConfiguredStoreForValidInput(t *testing.T) {
	service := &Service{}
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform"}
	_, err := service.ListTenantScopes(context.Background(), actor, ListTenantScopesInput{Page: 1, Limit: 50})
	if err == nil || !strings.Contains(err.Error(), "identity store is unavailable") {
		t.Fatalf("ListTenantScopes() error = %v, want unavailable store error", err)
	}
}
