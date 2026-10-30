package impersonation

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestAuthorizationCodeIsOpaqueDeterministicAndKeyBound(t *testing.T) {
	grantID := uuid.New()
	key := []byte("0123456789abcdef0123456789abcdef")
	code := authorizationCode(grantID, key)
	if code == "" || strings.Contains(code, grantID.String()) {
		t.Fatalf("authorization code is not opaque: %q", code)
	}
	if repeated := authorizationCode(grantID, key); repeated != code {
		t.Fatalf("authorization code changed across idempotent reconstruction")
	}
	parsed, err := parseAuthorizationCode(code, key)
	if err != nil || parsed != grantID {
		t.Fatalf("parseAuthorizationCode() = (%s, %v), want %s", parsed, err, grantID)
	}
	if _, err := parseAuthorizationCode(code, []byte("abcdef0123456789abcdef0123456789")); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("parseAuthorizationCode(wrong key) error = %v", err)
	}
	tampered := code[:len(code)-1] + "A"
	if tampered == code {
		tampered = code[:len(code)-1] + "B"
	}
	if _, err := parseAuthorizationCode(tampered, key); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("parseAuthorizationCode(tampered) error = %v", err)
	}
}

func TestValidatePrimaryActorRejectsNestedSession(t *testing.T) {
	actor := Actor{
		UserID: uuid.New(), ScopeID: uuid.New(), PrimaryAuthSessionID: uuid.New(),
		ScopeKind: "platform", SessionKind: SessionKindPrimary,
	}
	if err := validatePrimaryActor(actor); err != nil {
		t.Fatalf("validatePrimaryActor(primary) error = %v", err)
	}
	nested := actor
	nested.SessionKind = SessionKindImpersonation
	grantID := uuid.New()
	nested.ImpersonationGrantID = &grantID
	if err := validatePrimaryActor(nested); !errors.Is(err, ErrNested) {
		t.Fatalf("nested session error = %v", err)
	}
	// RS-07: a tenant (reseller) session passes the shape check; whether it
	// is an active reseller is decided in the transaction.
	tenantActor := actor
	tenantActor.ScopeKind = "tenant"
	if err := validatePrimaryActor(tenantActor); err != nil {
		t.Fatalf("tenant actor error = %v", err)
	}
	otherActor := actor
	otherActor.ScopeKind = "license"
	if err := validatePrimaryActor(otherActor); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("other scope kind error = %v", err)
	}
}

// TestResellerMayOnlyTargetOwnCustomers (ADR 0018 RS-07, user decision
// 10-24 Q4): an active reseller holding reseller.customers.manage may switch
// to its own customers only; a suspended reseller, a plain tenant, or a
// reseller without the permission may not switch at all.
func TestResellerMayOnlyTargetOwnCustomers(t *testing.T) {
	resellerScope, otherReseller := uuid.New(), uuid.New()
	reseller := actorState{scopeID: resellerScope, scopeKind: "tenant", activeReseller: true, userStatus: "active",
		membershipStatus: "active", permissions: []string{ResellerPermission}}
	if !reseller.canImpersonate() {
		t.Fatal("active reseller with reseller.customers.manage cannot switch")
	}
	if !reseller.mayTarget(targetState{scopeKind: "tenant", parentScopeID: resellerScope}) {
		t.Fatal("reseller denied its own customer")
	}
	for name, target := range map[string]targetState{
		"another reseller's customer": {scopeKind: "tenant", parentScopeID: otherReseller},
		"a platform customer":         {scopeKind: "tenant"},
	} {
		if reseller.mayTarget(target) {
			t.Errorf("reseller may switch to %s", name)
		}
	}
	for name, state := range map[string]actorState{
		"suspended reseller":     {scopeKind: "tenant", userStatus: "active", membershipStatus: "active", permissions: []string{ResellerPermission}},
		"reseller without perm":  {scopeKind: "tenant", activeReseller: true, userStatus: "active", membershipStatus: "active", permissions: []string{ManagePermission}},
		"platform without perm":  {scopeKind: "platform", userStatus: "active", membershipStatus: "active", permissions: []string{ResellerPermission}},
		"disabled reseller user": {scopeKind: "tenant", activeReseller: true, userStatus: "disabled", membershipStatus: "active", permissions: []string{ResellerPermission}},
	} {
		if state.canImpersonate() {
			t.Errorf("%s may switch", name)
		}
	}
	platform := actorState{scopeKind: "platform", userStatus: "active", membershipStatus: "active", permissions: []string{ManagePermission}}
	if !platform.canImpersonate() || !platform.mayTarget(targetState{scopeKind: "tenant", parentScopeID: otherReseller}) {
		t.Fatal("platform administrator lost switching to any tenant")
	}
}

func TestSensitiveActionPolicy(t *testing.T) {
	for _, action := range []string{
		"identity.password.change",
		"identity.mfa.enroll",
		"api_key.self.create",
		"api_key.self.update",
		"api_key.self.rotate",
		"billing.recharge",
		"billing.adjustment.create",
		"traffic_package.refund",
		"identity.roles.update",
		"audit.event.delete",
		actionCreate,
	} {
		if !SensitiveAction(action) {
			t.Errorf("SensitiveAction(%q) = false", action)
		}
	}
	for _, action := range []string{"sites.read", "sites.update", "api_key.self.revoke", "audit.read"} {
		if SensitiveAction(action) {
			t.Errorf("SensitiveAction(%q) = true", action)
		}
	}
}

func TestPermissionsDigestIsOrderIndependentAndChangeSensitive(t *testing.T) {
	first := permissionsDigest([]string{"sites.manage", "sites.read", "sites.read"})
	second := permissionsDigest([]string{"sites.read", "sites.manage"})
	if first != second {
		t.Fatal("equivalent permission sets produced different digests")
	}
	if first == permissionsDigest([]string{"sites.read"}) {
		t.Fatal("permission change did not change digest")
	}
}

func TestTargetCannotCarryCrossDomainAdministration(t *testing.T) {
	if !safeTargetPermissions([]string{"sites.read", "identity.self.read"}) {
		t.Fatal("ordinary tenant permissions were rejected")
	}
	for _, permission := range []string{"platform.admin", ManagePermission} {
		if safeTargetPermissions([]string{"sites.read", permission}) {
			t.Fatalf("cross-domain permission %q was accepted", permission)
		}
	}
}
