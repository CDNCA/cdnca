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

func TestSubjectV1(t *testing.T) {
	userID, scopeID, tenantID := uuid.New(), uuid.New(), uuid.New()
	tenant, err := NewSubjectV1(
		userID, scopeID, &tenantID, ScopeKindTenant,
		IdentityDomainCustomerControl,
	)
	if err != nil || !tenant.IsValid() {
		t.Fatalf("NewSubjectV1(tenant) = (%#v, %v)", tenant, err)
	}
	wantTenantID := tenantID
	tenantID = uuid.New()
	gotTenantID, ok := tenant.TenantID()
	if !ok || gotTenantID != wantTenantID || tenant.UserID() != userID || tenant.ScopeID() != scopeID ||
		tenant.ScopeKind() != ScopeKindTenant ||
		tenant.IdentityDomain() != IdentityDomainCustomerControl {
		t.Fatalf("tenant subject accessors returned unexpected values")
	}

	platform, err := NewSubjectV1(
		userID, scopeID, nil, ScopeKindPlatform,
		IdentityDomainCustomerControl,
	)
	if err != nil || !platform.IsValid() {
		t.Fatalf("NewSubjectV1(platform) = (%#v, %v)", platform, err)
	}
	if _, ok := platform.TenantID(); ok {
		t.Fatal("platform subject has tenant")
	}

	invalidTenant := uuid.Nil
	for name, test := range map[string]func() (SubjectV1, error){
		"zero user": func() (SubjectV1, error) {
			return NewSubjectV1(uuid.Nil, scopeID, &wantTenantID, ScopeKindTenant, IdentityDomainCustomerControl)
		},
		"zero scope": func() (SubjectV1, error) {
			return NewSubjectV1(userID, uuid.Nil, &wantTenantID, ScopeKindTenant, IdentityDomainCustomerControl)
		},
		"tenant without tenant": func() (SubjectV1, error) {
			return NewSubjectV1(userID, scopeID, nil, ScopeKindTenant, IdentityDomainCustomerControl)
		},
		"zero tenant": func() (SubjectV1, error) {
			return NewSubjectV1(userID, scopeID, &invalidTenant, ScopeKindTenant, IdentityDomainCustomerControl)
		},
		"platform with tenant": func() (SubjectV1, error) {
			return NewSubjectV1(userID, scopeID, &wantTenantID, ScopeKindPlatform, IdentityDomainCustomerControl)
		},
		"unknown scope": func() (SubjectV1, error) {
			return NewSubjectV1(userID, scopeID, nil, "unknown", IdentityDomainCustomerControl)
		},
		"unknown domain": func() (SubjectV1, error) {
			return NewSubjectV1(userID, scopeID, nil, ScopeKindPlatform, "unknown")
		},
	} {
		t.Run(name, func(t *testing.T) {
			value, err := test()
			if !errors.Is(err, ErrInvalidPrincipal) || value.IsValid() {
				t.Fatalf("invalid subject = (%#v, %v)", value, err)
			}
		})
	}
	if (SubjectV1{}).IsValid() {
		t.Fatal("zero subject is valid")
	}
}

func TestCredentialReferenceV1(t *testing.T) {
	id := uuid.New()
	issuedAt := time.Date(2026, 7, 23, 10, 0, 0, 0, time.FixedZone("test", 8*60*60))
	notAfter := issuedAt.Add(time.Hour)

	session, err := newSession(id, issuedAt, notAfter)
	if err != nil || !session.IsValid() || session.Kind() != CredentialKindSession ||
		session.ID() != id || session.Generation() != 0 ||
		!session.IssuedAt().Equal(issuedAt) || !session.NotAfter().Equal(notAfter) {
		t.Fatalf("newSession() = (%#v, %v)", session, err)
	}
	key, err := newAPIKey(id, 3, issuedAt, time.Time{})
	if err != nil || !key.IsValid() || key.Kind() != CredentialKindAPIKey ||
		key.ID() != id || key.Generation() != 3 || !key.NotAfter().IsZero() {
		t.Fatalf("newAPIKey() = (%#v, %v)", key, err)
	}
	expiringKey, err := newAPIKey(id, 1, issuedAt, notAfter)
	if err != nil || !expiringKey.IsValid() {
		t.Fatalf("newAPIKey(expiring) = (%#v, %v)", expiringKey, err)
	}

	for name, test := range map[string]func() (CredentialReferenceV1, error){
		"session zero id": func() (CredentialReferenceV1, error) {
			return newSession(uuid.Nil, issuedAt, notAfter)
		},
		"session zero issued": func() (CredentialReferenceV1, error) {
			return newSession(id, time.Time{}, notAfter)
		},
		"session zero expiry": func() (CredentialReferenceV1, error) {
			return newSession(id, issuedAt, time.Time{})
		},
		"session equal expiry": func() (CredentialReferenceV1, error) {
			return newSession(id, issuedAt, issuedAt)
		},
		"session reversed expiry": func() (CredentialReferenceV1, error) {
			return newSession(id, issuedAt, issuedAt.Add(-time.Second))
		},
		"api key zero id": func() (CredentialReferenceV1, error) {
			return newAPIKey(uuid.Nil, 1, issuedAt, time.Time{})
		},
		"api key zero generation": func() (CredentialReferenceV1, error) {
			return newAPIKey(id, 0, issuedAt, time.Time{})
		},
		"api key negative generation": func() (CredentialReferenceV1, error) {
			return newAPIKey(id, -1, issuedAt, time.Time{})
		},
		"api key zero issued": func() (CredentialReferenceV1, error) {
			return newAPIKey(id, 1, time.Time{}, time.Time{})
		},
		"api key equal expiry": func() (CredentialReferenceV1, error) {
			return newAPIKey(id, 1, issuedAt, issuedAt)
		},
	} {
		t.Run(name, func(t *testing.T) {
			value, err := test()
			if !errors.Is(err, ErrInvalidPrincipal) || value.IsValid() {
				t.Fatalf("invalid credential = (%#v, %v)", value, err)
			}
		})
	}
	if (CredentialReferenceV1{}).IsValid() {
		t.Fatal("zero credential is valid")
	}
}

func TestCredentialFormattingAndJSONAreRedacted(t *testing.T) {
	id := uuid.New()
	issuedAt := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	reference, err := newAPIKey(id, 42, issuedAt, issuedAt.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for _, formatted := range []string{
		fmt.Sprint(reference), fmt.Sprintf("%+v", reference), fmt.Sprintf("%#v", reference),
	} {
		if !strings.Contains(formatted, "redacted") || strings.Contains(formatted, id.String()) ||
			strings.Contains(formatted, issuedAt.Format(time.RFC3339)) {
			t.Fatalf("credential formatting was not redacted: %q", formatted)
		}
	}
	encoded, err := json.Marshal(reference)
	if err != nil || string(encoded) != "{}" {
		t.Fatalf("json.Marshal(credential) = (%s, %v)", encoded, err)
	}
	var decoded CredentialReferenceV1
	if err := json.Unmarshal([]byte(`{"kind":"api_key","id":"`+id.String()+`","generation":42}`), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.IsValid() {
		t.Fatal("JSON created a valid credential reference")
	}
}

func TestAuthenticatedPrincipalV1(t *testing.T) {
	userID, scopeID, tenantID, credentialID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	subject, err := NewSubjectV1(
		userID, scopeID, &tenantID, ScopeKindTenant,
		IdentityDomainCustomerControl,
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
	if err != nil || !principal.IsValid() {
		t.Fatalf("newAuthenticatedPrincipalV1() = (%#v, %v)", principal, err)
	}
	if principal.Subject().UserID() != userID || principal.Credential().ID() != credentialID {
		t.Fatal("principal accessors returned unexpected values")
	}

	encoded, err := json.Marshal(principal)
	if err != nil || string(encoded) != "{}" {
		t.Fatalf("json.Marshal(principal) = (%s, %v)", encoded, err)
	}
	formatted := fmt.Sprintf("%#v", principal)
	if !strings.Contains(formatted, "redacted") || strings.Contains(formatted, credentialID.String()) {
		t.Fatalf("principal formatting was not redacted: %q", formatted)
	}

	if (AuthenticatedPrincipalV1{}).IsValid() {
		t.Fatal("zero principal is valid")
	}
	if value, err := newAuthenticatedPrincipalV1(SubjectV1{}, credential); !errors.Is(err, ErrInvalidPrincipal) || value.IsValid() {
		t.Fatalf("invalid principal = (%#v, %v)", value, err)
	}
}

func TestValidPermission(t *testing.T) {
	valid := []string{"a", "sites.manage", "identity_verification.self-manage", "a_b.c-d"}
	for _, permission := range valid {
		if !ValidPermission(permission) {
			t.Fatalf("ValidPermission(%q) = false", permission)
		}
	}
	invalid := []string{"", "Sites.manage", " sites.manage", "sites.manage ", ".sites", "sites/manage", strings.Repeat("a", 129)}
	for _, permission := range invalid {
		if ValidPermission(permission) {
			t.Fatalf("ValidPermission(%q) = true", permission)
		}
	}
}

func TestScopeLockNameV1(t *testing.T) {
	scopeID := uuid.New()
	name, err := ScopeLockNameV1(scopeID)
	if err != nil || name != "iam-authz:v1:"+scopeID.String() {
		t.Fatalf("ScopeLockNameV1() = (%q, %v)", name, err)
	}
	if name, err := ScopeLockNameV1(uuid.Nil); name != "" || !errors.Is(err, ErrInvalidPrincipal) {
		t.Fatalf("ScopeLockNameV1(nil) = (%q, %v)", name, err)
	}
}
