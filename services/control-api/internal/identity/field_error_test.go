package identity

import (
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/google/uuid"
)

func assertUserField(t *testing.T, err error, field, reason string) {
	t.Helper()
	located, ok := fielderr.As(err)
	if !errors.Is(err, ErrInvalidUserInput) || !ok || located.Field != field || located.Reason != reason {
		t.Fatalf("error = %v, want %s/%s", err, field, reason)
	}
}

// fix-fielderr-be: user and user group refusals name the request field
// (createManagedUserRequest / updateManagedUserRequest / profile JSON names).
func TestUserRefusalsLocateField(t *testing.T) {
	service := &Service{}
	admin := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform"}
	text := func(value string) *string { return &value }
	create := func(change func(*CreateUserInput)) error {
		input := CreateUserInput{Username: "alice", Password: "Abcdefg1!", Role: UserRoleOwner,
			Fields: UserFields{DisplayName: "Alice"}, IdempotencyKey: "key-1", RequestID: "request-1"}
		change(&input)
		_, err := service.CreateUser(t.Context(), admin, input)
		return err
	}
	for name, check := range map[string]struct {
		change        func(*CreateUserInput)
		field, reason string
	}{
		"short username": {func(i *CreateUserInput) { i.Username = "ab" }, "username", fielderr.TooShort},
		"bad username":   {func(i *CreateUserInput) { i.Username = "a b c" }, "username", fielderr.InvalidFormat},
		"empty username": {func(i *CreateUserInput) { i.Username = " " }, "username", fielderr.Required},
		"role":           {func(i *CreateUserInput) { i.Role = "root" }, "role", fielderr.Invalid},
		"long remark":    {func(i *CreateUserInput) { i.Remark = text(strings.Repeat("x", 513)) }, "remark", fielderr.TooLong},
		"qq":             {func(i *CreateUserInput) { i.QQ = text("1\n2") }, "qq", fielderr.InvalidFormat},
		"display name":   {func(i *CreateUserInput) { i.Fields.DisplayName = " " }, "display_name", fielderr.Required},
		"long display":   {func(i *CreateUserInput) { i.Fields.DisplayName = strings.Repeat("名", 129) }, "display_name", fielderr.TooLong},
		"email":          {func(i *CreateUserInput) { i.Fields.Email = "not-an-email" }, "email", fielderr.InvalidFormat},
		"phone":          {func(i *CreateUserInput) { i.Fields.Phone = "12" }, "phone", fielderr.InvalidFormat},
	} {
		t.Run(name, func(t *testing.T) { assertUserField(t, create(check.change), check.field, check.reason) })
	}
	t.Run("update status", func(t *testing.T) {
		_, err := service.UpdateUser(t.Context(), admin, UpdateUserInput{ID: uuid.New(), ExpectedRevision: 1,
			Status: "gone", Role: UserRoleOwner, Fields: UserFields{DisplayName: "a"}, IdempotencyKey: "key-1", RequestID: "request-1"})
		assertUserField(t, err, "status", fielderr.Invalid)
	})
	t.Run("group name", func(t *testing.T) {
		_, err := service.CreateUserGroup(t.Context(), admin, CreateUserGroupInput{Name: " ", IdempotencyKey: "key-1", RequestID: "request-1"})
		assertUserField(t, err, "name", fielderr.Required)
		_, err = service.UpdateUserGroup(t.Context(), admin, UpdateUserGroupInput{ID: uuid.New(), ExpectedRevision: 1,
			Name: strings.Repeat("x", 129), IdempotencyKey: "key-1", RequestID: "request-1"})
		assertUserField(t, err, "name", fielderr.TooLong)
	})
}

// fix-fielderr-be3: the account password change names current_password
// (POST /v1/account/password changeAccountPasswordRequest).
func TestChangePasswordLocatesField(t *testing.T) {
	service := &Service{}
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"}
	err := service.ChangePassword(t.Context(), actor, ChangePasswordInput{NewPassword: "Abcdef12!x", RequestID: "r"})
	assertUserField(t, err, "current_password", fielderr.Required)
	err = service.ChangePassword(t.Context(), actor, ChangePasswordInput{CurrentPassword: strings.Repeat("x", 1025), NewPassword: "Abcdef12!x", RequestID: "r"})
	assertUserField(t, err, "current_password", fielderr.TooLong)
}
