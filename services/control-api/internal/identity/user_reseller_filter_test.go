package identity

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// RS-06b：用户列表按类型/所属代理商筛选的入参校验（不连库，校验在 store 之前拒绝）。
func TestListUsersRejectsInvalidResellerFilters(t *testing.T) {
	service := &Service{}
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform"}
	for name, input := range map[string]ListUsersInput{
		"unknown type":         {Page: 1, Limit: 20, Type: "agent"},
		"type upper case":      {Page: 1, Limit: 20, Type: "Reseller"},
		"parent not a UUID":    {Page: 1, Limit: 20, Parent: "platform"},
		"parent nil UUID":      {Page: 1, Limit: 20, Parent: uuid.Nil.String()},
		"parent upper case":    {Page: 1, Limit: 20, Parent: strings.ToUpper(uuid.NewString())},
		"parent with type mix": {Page: 1, Limit: 20, Type: "customer", Parent: "None"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := service.ListUsers(context.Background(), actor, input); !errors.Is(err, ErrInvalidUserInput) {
				t.Fatalf("ListUsers() error = %v, want ErrInvalidUserInput", err)
			}
		})
	}
}

func TestUserTypeFilterValues(t *testing.T) {
	for _, value := range []string{"", "reseller", "customer", "direct"} {
		if !validUserTypeFilter(value) {
			t.Fatalf("validUserTypeFilter(%q) = false", value)
		}
	}
	for _, value := range []string{"normal", "all", " reseller"} {
		if validUserTypeFilter(value) {
			t.Fatalf("validUserTypeFilter(%q) = true", value)
		}
	}
}

// reseller 投影只在 include=reseller 时出现；出现时四个字段都在（null 不省略）。
func TestManagedUserResellerProjectionShape(t *testing.T) {
	encoded, err := json.Marshal(ManagedUser{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), `"reseller"`) {
		t.Fatalf("reseller projection must be omitted by default: %s", encoded)
	}
	parent := uuid.New()
	name := "代理商甲"
	encoded, err = json.Marshal(ManagedUser{Reseller: &UserReseller{ParentScopeID: &parent, ParentName: &name}})
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Reseller map[string]any `json:"reseller"`
	}
	if err := json.Unmarshal(encoded, &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Reseller) != 4 || payload.Reseller["is_reseller"] != false || payload.Reseller["status"] != nil ||
		payload.Reseller["parent_scope_id"] != parent.String() || payload.Reseller["parent_name"] != name {
		t.Fatalf("reseller projection = %#v", payload.Reseller)
	}
}
