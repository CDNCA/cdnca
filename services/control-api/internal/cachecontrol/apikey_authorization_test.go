package cachecontrol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/google/uuid"
)

// fix-cacheflow3 §1: the task center may run a cache command with an API key;
// the store re-authorizes it in its transaction and audits the key as subject.
func TestWithAPIKeyAuthorizationBoundaryRedactionAndAuditRef(t *testing.T) {
	keyID := uuid.New()
	raw := "cdnca_test_" + strings.Repeat("k", 40)
	ctx, err := WithAPIKeyAuthorization(context.Background(), keyID, raw)
	if err != nil {
		t.Fatal(err)
	}
	if got := auditActorRef(ctx); got != "api_key:"+keyID.String() {
		t.Fatalf("actor ref = %q", got)
	}
	if got := auditActorRef(context.Background()); got != "" {
		t.Fatalf("no credential actor ref = %q", got)
	}
	sessionCtx, err := WithSessionAuthorization(context.Background(), "session-token")
	if err != nil || auditActorRef(sessionCtx) != "" {
		t.Fatalf("session actor ref = %q err=%v", auditActorRef(sessionCtx), err)
	}
	authorization, ok := ctx.Value(apiKeyAuthorizationContextKey{}).(apiKeyAuthorization)
	if !ok || authorization.rawKey != raw || authorization.keyID != keyID {
		t.Fatal("API key authorization was not stored in the private context value")
	}
	if got := fmt.Sprintf("%v %+v %#v", authorization, authorization, authorization); strings.Contains(got, raw) {
		t.Fatalf("formatted API key authorization leaked the key: %q", got)
	}
	if encoded, _ := json.Marshal(authorization); strings.Contains(string(encoded), raw) {
		t.Fatalf("JSON API key authorization leaked the key: %s", encoded)
	}
	for name, test := range map[string]struct {
		ctx   context.Context
		keyID uuid.UUID
		raw   string
	}{
		"nil context": {keyID: keyID, raw: raw},
		"nil key id":  {ctx: context.Background(), raw: raw},
		"empty key":   {ctx: context.Background(), keyID: keyID},
		"whitespace":  {ctx: context.Background(), keyID: keyID, raw: "a b"},
		"too long":    {ctx: context.Background(), keyID: keyID, raw: strings.Repeat("a", 8192)},
	} {
		if result, err := WithAPIKeyAuthorization(test.ctx, test.keyID, test.raw); !errors.Is(err, ErrInvalidInput) || result != nil {
			t.Errorf("%s: ctx=%v err=%v", name, result, err)
		}
	}
}

// An API key belongs to one tenant: it never authorizes a platform actor
// acting on a tenant scope, and is refused before any database call.
func TestAPIKeyAuthorizationRefusesPlatformActors(t *testing.T) {
	ctx, err := WithAPIKeyAuthorization(context.Background(), uuid.New(), "cdnca_test_key")
	if err != nil {
		t.Fatal(err)
	}
	store := &Store{authorizer: new(iamlock.Authorizer)}
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ActorScopeID: uuid.New()}
	if _, err := store.authorizeActor(ctx, nil, actor, "sites.manage"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("platform actor with API key: %v", err)
	}
}
