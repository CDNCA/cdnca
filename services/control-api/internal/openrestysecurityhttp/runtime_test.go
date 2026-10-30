package openrestysecurityhttp

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/openrestysecurity"
	"github.com/google/uuid"
)

func TestActorFromPrincipalPreservesPermissionsAndStoreRejectsMissingAccessBeforeTransaction(t *testing.T) {
	scopeID := uuid.New()
	principal := identity.Principal{UserID: uuid.New(), ScopeID: scopeID, ScopeKind: openrestysecurity.ScopePlatform,
		Permissions: []string{"sites.read"}}
	actor, err := actorFromPrincipal(principal, openrestysecurity.CredentialSession, uuid.New(), "session-token")
	if err != nil {
		t.Fatalf("actorFromPrincipal() error = %v", err)
	}
	if !slices.Equal(actor.Permissions, []string{"sites.read"}) {
		t.Fatalf("actor permissions = %v", actor.Permissions)
	}
	principal.Permissions[0] = openrestysecurity.PermissionManage
	if !slices.Equal(actor.Permissions, []string{"sites.read"}) {
		t.Fatalf("actor permissions alias principal storage: %v", actor.Permissions)
	}

	// A zero-value store has no pool. These calls can return cleanly only when
	// the actor permission check happens before opening a transaction.
	var store openrestysecurity.Store
	if _, err := store.GetGlobal(context.Background(), openrestysecurity.ReadGlobalRequest{
		Actor: actor, TargetScopeID: scopeID,
	}); !errors.Is(err, openrestysecurity.ErrPermissionDenied) {
		t.Fatalf("GetGlobal() error = %v, want ErrPermissionDenied", err)
	}
	if _, err := store.PatchGlobal(context.Background(), openrestysecurity.PatchGlobalRequest{
		Actor: actor, TargetScopeID: scopeID,
	}); !errors.Is(err, openrestysecurity.ErrPermissionDenied) {
		t.Fatalf("PatchGlobal() error = %v, want ErrPermissionDenied", err)
	}
}

func TestActorFromPrincipalAllowsTenantForRuleGroups(t *testing.T) {
	scopeID := uuid.New()
	principal := identity.Principal{UserID: uuid.New(), ScopeID: scopeID, ScopeKind: openrestysecurity.ScopeTenant,
		TenantID: &scopeID, Permissions: []string{openrestysecurity.PermissionManage}}
	actor, err := actorFromPrincipal(principal, openrestysecurity.CredentialSession, uuid.New(), "session-token")
	if err != nil {
		t.Fatalf("actorFromPrincipal() error = %v", err)
	}
	if actor.ScopeKind != openrestysecurity.ScopeTenant {
		t.Fatalf("actor=%+v", actor)
	}
}
