package cachecontrolhttp

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

func TestProductionDependenciesDeclareIdentityAndIAM(t *testing.T) {
	t.Parallel()
	typeOfDependencies := reflect.TypeOf(ProductionDependencies{})
	for _, field := range []string{"Identity", "IAM"} {
		if _, exists := typeOfDependencies.FieldByName(field); !exists {
			t.Fatalf("ProductionDependencies missing %s", field)
		}
	}
}

func TestStrictBearerTokenRejectsThe8192ByteBoundary(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		values  []string
		wantLen int
	}{
		{name: "8191 byte token", values: []string{"Bearer " + strings.Repeat("a", 8191)}, wantLen: 8191},
		{name: "8192 byte token", values: []string{"Bearer " + strings.Repeat("a", 8192)}},
		{name: "duplicate header", values: []string{"Bearer first", "Bearer second"}},
		{name: "non-exact scheme", values: []string{"bearer token"}},
		{name: "embedded space", values: []string{"Bearer first second"}},
		{name: "embedded tab", values: []string{"Bearer first\tsecond"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request, err := http.NewRequest(http.MethodGet, "/v1/cache-operations", nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, value := range test.values {
				request.Header.Add("Authorization", value)
			}
			token, err := strictBearerToken(request)
			if test.wantLen > 0 {
				if err != nil || len(token) != test.wantLen {
					t.Fatalf("strictBearerToken() = (%d bytes, %v), want %d bytes", len(token), err, test.wantLen)
				}
				return
			}
			if token != "" || !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("strictBearerToken() = (%d bytes, %v), want empty unauthenticated", len(token), err)
			}
		})
	}
}

func TestNewProductionHandlerFailsClosedWithoutDependencies(t *testing.T) {
	t.Parallel()
	authenticate := func(*http.Request) (identity.Principal, error) {
		return identity.Principal{}, errors.New("not authenticated")
	}

	if handler, err := NewProductionHandler(ProductionConfig{}, ProductionDependencies{Authenticate: authenticate}); handler != nil || !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("NewProductionHandler() = (%T, %v), want nil invalid request", handler, err)
	}
}

func TestRuntimeControlStoreRequiresExactActorScope(t *testing.T) {
	t.Parallel()
	userID := uuid.New()
	targetScopeID := uuid.New()
	authenticationScopeID := uuid.New()
	ctx := context.WithValue(context.Background(), runtimeSessionKey{}, runtimeSessionResult{
		session: runtimeSession{
			principal: identity.Principal{UserID: userID, ScopeID: authenticationScopeID},
			sessionID: uuid.New(),
			rawToken:  "formal-session-token",
		},
	})
	store := runtimeControlStore{inner: &fakeControl{}}

	for _, test := range []struct {
		name         string
		actorScopeID uuid.UUID
		wantAllowed  bool
	}{
		{name: "missing actor scope"},
		{name: "mismatched actor scope", actorScopeID: uuid.New()},
		{name: "exact actor scope", actorScopeID: authenticationScopeID, wantAllowed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			actor := cachecontrol.Actor{
				UserID: userID, ScopeID: targetScopeID, ActorScopeID: test.actorScopeID,
			}
			authorizedCtx, authorizedActor, err := store.authorize(ctx, actor)
			if test.wantAllowed {
				if err != nil || authorizedCtx == nil || authorizedActor != actor {
					t.Fatalf("authorize() = (%v, %+v, %v), want exact actor", authorizedCtx, authorizedActor, err)
				}
				return
			}
			if authorizedCtx != nil || authorizedActor != (cachecontrol.Actor{}) ||
				!errors.Is(err, cachecontrol.ErrPermissionDenied) {
				t.Fatalf("authorize() = (%v, %+v, %v), want permission denied", authorizedCtx, authorizedActor, err)
			}
		})
	}
}
