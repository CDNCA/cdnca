package identity

import (
	"context"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/bridgeauth"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func testBridgeGrant(t *testing.T, kind string) *bridgeauth.Grant {
	t.Helper()
	grant, err := bridgeauth.NewGrant(uuid.New(), "cbb_AAAAAAAAAAAAAAAAAAAAAA", uuid.New(), kind, uuid.New(),
		func(context.Context, pgx.Tx) (bool, error) { return true, nil })
	if err != nil {
		t.Fatal(err)
	}
	return grant
}

// A bridge actor never passes the administrator check, even though its user
// (the key's creator) may be a platform administrator.
func TestBridgeActorNeverManagedUserAdmin(t *testing.T) {
	platform, err := NewBridgeActor(testBridgeGrant(t, bridgeauth.OwnerPlatform))
	if err != nil || !platform.Bridge() || platform.ScopeKind != "platform" || platform.SessionID != uuid.Nil {
		t.Fatalf("platform bridge actor %#v %v", platform, err)
	}
	if err := authorizeManagedUserActor(t.Context(), nil, platform); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("authorizeManagedUserActor(bridge) = %v", err)
	}
	if (Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform", SessionID: uuid.New()}).Bridge() {
		t.Fatal("session actor marked bridge")
	}
}

func TestBridgeActorPermissionSets(t *testing.T) {
	reseller, _ := NewBridgeActor(testBridgeGrant(t, bridgeauth.OwnerReseller))
	platform, _ := NewBridgeActor(testBridgeGrant(t, bridgeauth.OwnerPlatform))
	// Refused before any query: outside the fixed set or the wrong kind.
	for name, check := range map[string]struct {
		actor      Actor
		permission string
	}{
		"reseller users manage":    {reseller, PermissionUsersManage},
		"platform reseller manage": {platform, PermissionResellerCustomersManage},
		"platform admin":           {platform, "platform.admin"},
	} {
		if err := authorizeBridgeActor(t.Context(), nil, check.actor, check.permission); !errors.Is(err, ErrPermissionDenied) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := (&Service{}).CreateBridgeCustomer(t.Context(), Actor{UserID: uuid.New(), ScopeID: uuid.New(),
		ScopeKind: "platform", SessionID: uuid.New()}, CreateUserInput{}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("CreateBridgeCustomer(session) = %v", err)
	}
	if _, err := (&Service{}).SetBridgeCustomerStatus(t.Context(), Actor{UserID: uuid.New(), ScopeID: uuid.New(),
		ScopeKind: "platform", SessionID: uuid.New()}, ResellerCustomerStatusInput{}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("SetBridgeCustomerStatus(session) = %v", err)
	}
}
