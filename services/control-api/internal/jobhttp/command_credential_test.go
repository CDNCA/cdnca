package jobhttp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type fakeCommandAPIKeyAuthorizer struct {
	grant      commandAPIKeyGrant
	err        error
	calls      int
	raw        string
	target     uuid.UUID
	permission string
}

func (fake *fakeCommandAPIKeyAuthorizer) authorizeAPIKey(
	_ context.Context, _ pgx.Tx, raw string, targetScopeID uuid.UUID, permission string,
) (commandAPIKeyGrant, error) {
	fake.calls++
	fake.raw, fake.target, fake.permission = raw, targetScopeID, permission
	return fake.grant, fake.err
}

// API-JOBS-02：认证后到命令事务之间密钥被吊销或缩权，事务内复核必须拒绝。
func TestAuthorizeCommandAPIKeyRechecksCredentialInTransaction(t *testing.T) {
	scopeID := uuid.MustParse("20000000-0000-4000-8000-000000000062")
	userID := uuid.MustParse("30000000-0000-4000-8000-000000000062")
	keyID := uuid.MustParse("50000000-0000-4000-8000-000000000062")
	const raw = "cdnca_key_example.secret-example"
	base := Principal{UserID: userID, ScopeID: scopeID, ScopeKind: ScopeTenant,
		Permissions: map[string]struct{}{PermissionManage: {}}}
	withKey := base.WithAPIKeyCredential(keyID, raw)
	granted := commandAPIKeyGrant{keyID: keyID, userID: userID, authenticationScopeID: scopeID, targetScopeID: scopeID}
	input := func(principal Principal, audience Audience) CommandInput {
		return CommandInput{Principal: principal, Audience: audience, Operation: CommandCancel}
	}
	foreign := granted
	foreign.keyID = uuid.MustParse("50000000-0000-4000-8000-000000000063")
	otherUser := granted
	otherUser.userID = uuid.MustParse("30000000-0000-4000-8000-000000000063")
	otherTarget := granted
	otherTarget.targetScopeID = uuid.MustParse("20000000-0000-4000-8000-000000000063")

	for _, test := range []struct {
		name       string
		input      CommandInput
		authorizer *fakeCommandAPIKeyAuthorizer
		noIAM      bool
		want       error
		wantCalls  int
	}{
		{name: "bearer session skips API key recheck", input: input(base, AudienceTenant),
			authorizer: &fakeCommandAPIKeyAuthorizer{err: errors.New("must not be called")}},
		{name: "valid key passes", input: input(withKey, AudienceTenant),
			authorizer: &fakeCommandAPIKeyAuthorizer{grant: granted}, wantCalls: 1},
		{name: "revoked key is denied", input: input(withKey, AudienceTenant),
			authorizer: &fakeCommandAPIKeyAuthorizer{err: iamlock.ErrInvalidCredential}, want: ErrPermissionDenied, wantCalls: 1},
		{name: "narrowed key is denied", input: input(withKey, AudienceTenant),
			authorizer: &fakeCommandAPIKeyAuthorizer{err: iamlock.ErrPermissionDenied}, want: ErrPermissionDenied, wantCalls: 1},
		{name: "invalid input is denied", input: input(withKey, AudienceTenant),
			authorizer: &fakeCommandAPIKeyAuthorizer{err: iamlock.ErrInvalidInput}, want: ErrPermissionDenied, wantCalls: 1},
		{name: "IAM unavailable fails closed", input: input(withKey, AudienceTenant),
			authorizer: &fakeCommandAPIKeyAuthorizer{err: fmt.Errorf("%w: test", iamlock.ErrUnavailable)}, want: ErrStoreUnavailable, wantCalls: 1},
		{name: "lock order violation fails closed", input: input(withKey, AudienceTenant),
			authorizer: &fakeCommandAPIKeyAuthorizer{err: iamlock.ErrLockOrder}, want: ErrStoreUnavailable, wantCalls: 1},
		{name: "rechecked key id differs", input: input(withKey, AudienceTenant),
			authorizer: &fakeCommandAPIKeyAuthorizer{grant: foreign}, want: ErrPermissionDenied, wantCalls: 1},
		{name: "rechecked user differs", input: input(withKey, AudienceTenant),
			authorizer: &fakeCommandAPIKeyAuthorizer{grant: otherUser}, want: ErrPermissionDenied, wantCalls: 1},
		{name: "rechecked target differs", input: input(withKey, AudienceTenant),
			authorizer: &fakeCommandAPIKeyAuthorizer{grant: otherTarget}, want: ErrPermissionDenied, wantCalls: 1},
		{name: "API key on platform audience", input: input(withKey, AudiencePlatform),
			authorizer: &fakeCommandAPIKeyAuthorizer{grant: granted}, want: ErrScopeForbidden},
		{name: "API key without configured IAM fails closed", input: input(withKey, AudienceTenant),
			noIAM: true, want: ErrStoreUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			var authorizer commandAPIKeyAuthorizer = test.authorizer
			if test.noIAM {
				authorizer = nil
			}
			err := authorizeCommandAPIKey(t.Context(), nil, authorizer, test.input)
			if test.want == nil && err != nil || test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("err=%v, want %v", err, test.want)
			}
			if test.authorizer != nil && test.authorizer.calls != test.wantCalls {
				t.Fatalf("authorizer calls=%d, want %d", test.authorizer.calls, test.wantCalls)
			}
			if test.wantCalls > 0 && (test.authorizer.raw != raw || test.authorizer.target != scopeID ||
				test.authorizer.permission != PermissionManage) {
				t.Fatalf("authorizer args raw=%q target=%s permission=%q", test.authorizer.raw,
					test.authorizer.target, test.authorizer.permission)
			}
		})
	}
}

func TestPrincipalAPIKeyCredentialIsNotPrinted(t *testing.T) {
	const raw = "cdnca_key_example.secret-must-not-print"
	principal := Principal{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: ScopeTenant}.
		WithAPIKeyCredential(uuid.New(), raw)
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if printed := fmt.Sprintf(format, principal); strings.Contains(printed, "secret-must-not-print") {
			t.Fatalf("%s printed raw credential: %s", format, printed)
		}
	}
}
