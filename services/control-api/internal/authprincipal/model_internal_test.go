package authprincipal

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCredentialReferenceV1RejectsInvalidPrivateState(t *testing.T) {
	issuedAt := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	notAfter := issuedAt.Add(time.Hour)

	for name, reference := range map[string]CredentialReferenceV1{
		"unknown kind": {
			kind: "unknown", id: uuid.New(), generation: 1,
			issuedAt: issuedAt, notAfter: notAfter,
		},
		"session generation": {
			kind: CredentialKindSession, id: uuid.New(), generation: 1,
			issuedAt: issuedAt, notAfter: notAfter,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if reference.IsValid() {
				t.Fatalf("tampered credential is valid: %#v", reference)
			}
		})
	}
}

func TestAuthorizedScopeV1(t *testing.T) {
	userID, scopeID, tenantID, otherTenantID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	credentialID := uuid.New()
	subject, err := NewSubjectV1(
		userID, scopeID, &tenantID, ScopeKindTenant, IdentityDomainCustomerControl,
	)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := newAPIKey(
		credentialID, 7, time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC), time.Time{},
	)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := newAuthenticatedPrincipalV1(subject, credential)
	if err != nil {
		t.Fatal(err)
	}

	scope, err := newAuthorizedScopeV1(principal, tenantID)
	if err != nil || !scope.IsValid() || scope.UserID() != userID || scope.ScopeID() != scopeID ||
		scope.TenantID() != tenantID || scope.CredentialKind() != CredentialKindAPIKey ||
		scope.CredentialID() != credentialID || scope.CredentialGeneration() != 7 {
		t.Fatalf("newAuthorizedScopeV1() = (%#v, %v)", scope, err)
	}
	encoded, err := json.Marshal(scope)
	if err != nil || string(encoded) != "{}" {
		t.Fatalf("json.Marshal(scope) = (%s, %v)", encoded, err)
	}
	formatted := fmt.Sprintf("%#v", scope)
	if !strings.Contains(formatted, "redacted") || strings.Contains(formatted, credentialID.String()) {
		t.Fatalf("scope formatting was not redacted: %q", formatted)
	}

	for name, test := range map[string]func() (AuthorizedScopeV1, error){
		"cross tenant": func() (AuthorizedScopeV1, error) {
			return newAuthorizedScopeV1(principal, otherTenantID)
		},
		"zero tenant": func() (AuthorizedScopeV1, error) {
			return newAuthorizedScopeV1(principal, uuid.Nil)
		},
		"invalid principal": func() (AuthorizedScopeV1, error) {
			return newAuthorizedScopeV1(AuthenticatedPrincipalV1{}, tenantID)
		},
	} {
		t.Run(name, func(t *testing.T) {
			value, err := test()
			if !errors.Is(err, ErrInvalidPrincipal) || value.IsValid() {
				t.Fatalf("invalid authorized scope = (%#v, %v)", value, err)
			}
		})
	}
	if (AuthorizedScopeV1{}).IsValid() {
		t.Fatal("zero authorized scope is valid")
	}
}
