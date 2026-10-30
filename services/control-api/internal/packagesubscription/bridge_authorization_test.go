package packagesubscription

import (
	"context"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/bridgeauth"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func bridgeGrant(t *testing.T, kind string) *bridgeauth.Grant {
	t.Helper()
	grant, err := bridgeauth.NewGrant(uuid.New(), "cbb_AAAAAAAAAAAAAAAAAAAAAA", uuid.New(), kind, uuid.New(),
		func(context.Context, pgx.Tx) (bool, error) { return true, nil })
	if err != nil {
		t.Fatal(err)
	}
	return grant
}

// A session actor (SessionID set, no grant) and a bridge actor (grant, no
// session) are each valid; a mix of both, or neither, is refused.
func TestActorEnvelopeSeparatesSessionAndBridge(t *testing.T) {
	session := Actor{UserID: uuid.New(), ScopeID: uuid.New(), SessionID: uuid.New(), ScopeKind: ScopeTenant}
	if !validActorEnvelope(session) || session.Bridge() {
		t.Fatal("session actor refused or marked bridge")
	}
	bridge, err := NewBridgeActor(bridgeGrant(t, bridgeauth.OwnerReseller))
	if err != nil || !validActorEnvelope(bridge) || !bridge.Bridge() || bridge.SessionID != uuid.Nil {
		t.Fatalf("bridge actor %#v %v", bridge, err)
	}
	mixed := bridge
	mixed.SessionID = uuid.New()
	if validActorEnvelope(mixed) {
		t.Fatal("bridge actor with a session accepted")
	}
	if validActorEnvelope(Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: ScopeTenant}) {
		t.Fatal("actor without session or grant accepted")
	}
	if _, err := NewBridgeActor(nil); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("nil grant: %v", err)
	}
}

func TestBridgeAuthorizationRefusesBeforeQuery(t *testing.T) {
	reseller, _ := NewBridgeActor(bridgeGrant(t, bridgeauth.OwnerReseller))
	platform, _ := NewBridgeActor(bridgeGrant(t, bridgeauth.OwnerPlatform))
	wrongKind := platform
	wrongKind.ScopeKind = ScopeTenant
	mixed := reseller
	mixed.SessionID = uuid.New()
	for name, check := range map[string]struct {
		actor  Actor
		target uuid.UUID
	}{
		"own scope":       {reseller, reseller.ScopeID},
		"no target":       {platform, uuid.Nil},
		"kind mismatch":   {wrongKind, uuid.New()},
		"session smuggle": {mixed, uuid.New()},
	} {
		if err := authorizeBridgeActor(t.Context(), nil, check.actor, check.target); !errors.Is(err, ErrPermissionDenied) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
