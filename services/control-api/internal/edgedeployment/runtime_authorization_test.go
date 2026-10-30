package edgedeployment_test

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/google/uuid"
)

func TestSessionActorFactoryKeepsCredentialSealed(t *testing.T) {
	userID, scopeID, sessionID := uuid.New(), uuid.New(), uuid.New()
	const rawToken = "signed-access-token"
	actor, err := edgedeployment.NewSessionActor(
		userID, scopeID, edgedeployment.ScopeKindPlatform, sessionID, rawToken,
	)
	if err != nil {
		t.Fatal(err)
	}
	if actor.UserID != userID || actor.ScopeID != scopeID ||
		actor.ScopeKind != edgedeployment.ScopeKindPlatform || actor.SessionID != sessionID {
		t.Fatalf("session actor metadata = %+v", actor)
	}
	encoded, err := json.Marshal(actor)
	if err != nil {
		t.Fatal(err)
	}
	for _, exposed := range []string{actor.String(), fmt.Sprintf("%v", actor), fmt.Sprintf("%#v", actor), string(encoded)} {
		if strings.Contains(exposed, rawToken) {
			t.Fatalf("session credential leaked through %q", exposed)
		}
	}
}

func TestSessionActorFormattingRedactsEveryVerbAndJSON(t *testing.T) {
	userID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	scopeID := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	sessionID := uuid.MustParse("33333333-3333-4333-8333-333333333333")
	const rawToken = "distinctive-signed-access-token"
	actor, err := edgedeployment.NewSessionActor(
		userID, scopeID, edgedeployment.ScopeKindPlatform, sessionID, rawToken,
	)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(actor)
	if err != nil {
		t.Fatal(err)
	}
	redacted := actor.String()
	type formattedOutput struct {
		name  string
		value string
	}
	outputs := make([]formattedOutput, 0, 12)
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
		formatted := fmt.Sprintf(format, actor)
		if formatted != redacted {
			t.Fatalf("%s formatted actor = %q, want %q", format, formatted, redacted)
		}
		outputs = append(outputs, formattedOutput{name: format, value: formatted})
	}
	typeFormat := "%T"
	typeOutput := fmt.Sprintf(typeFormat, actor)
	if typeOutput != "edgedeployment.Actor" {
		t.Fatalf("%%T formatted actor = %q", typeOutput)
	}
	pointerFormat := "%p"
	pointerOutput := fmt.Sprintf(pointerFormat, actor)
	if pointerOutput == "" {
		t.Fatal("pointer-formatted actor is empty")
	}
	pointerLeaks := []string{
		rawToken,
		hex.EncodeToString([]byte(rawToken)),
	}
	for _, leak := range pointerLeaks {
		if strings.Contains(pointerOutput, leak) {
			t.Fatalf("%%p leaked actor data %q through %q", leak, pointerOutput)
		}
	}
	if string(encoded) != `"`+redacted+`"` {
		t.Fatalf("JSON actor = %s, want redacted string", encoded)
	}
	outputs = append(outputs,
		formattedOutput{name: "%T", value: typeOutput},
		formattedOutput{name: "%p", value: pointerOutput},
		formattedOutput{name: "String", value: actor.String()},
		formattedOutput{name: "GoString", value: actor.GoString()},
		formattedOutput{name: "JSON", value: string(encoded)},
	)
	secrets := []string{rawToken}
	for _, output := range outputs {
		for _, secret := range secrets {
			if strings.Contains(output.value, secret) {
				t.Fatalf("%s leaked actor data through %q", output.name, output.value)
			}
		}
	}
}

func TestSessionActorFactoryRejectsUnusableCredentials(t *testing.T) {
	validUser, validScope, validSession := uuid.New(), uuid.New(), uuid.New()
	tests := []struct {
		name      string
		userID    uuid.UUID
		scopeID   uuid.UUID
		scopeKind string
		sessionID uuid.UUID
		token     string
	}{
		{name: "user", scopeID: validScope, scopeKind: edgedeployment.ScopeKindPlatform, sessionID: validSession, token: "token"},
		{name: "scope", userID: validUser, scopeKind: edgedeployment.ScopeKindPlatform, sessionID: validSession, token: "token"},
		{name: "scope kind", userID: validUser, scopeID: validScope, scopeKind: "customer", sessionID: validSession, token: "token"},
		{name: "session", userID: validUser, scopeID: validScope, scopeKind: edgedeployment.ScopeKindPlatform, token: "token"},
		{name: "empty token", userID: validUser, scopeID: validScope, scopeKind: edgedeployment.ScopeKindPlatform, sessionID: validSession},
		{name: "token whitespace", userID: validUser, scopeID: validScope, scopeKind: edgedeployment.ScopeKindPlatform, sessionID: validSession, token: "bad token"},
		{name: "token too large", userID: validUser, scopeID: validScope, scopeKind: edgedeployment.ScopeKindPlatform, sessionID: validSession, token: strings.Repeat("x", 8193)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := edgedeployment.NewSessionActor(
				test.userID, test.scopeID, test.scopeKind, test.sessionID, test.token,
			); err == nil {
				t.Fatal("invalid session actor was accepted")
			}
		})
	}
}

func TestIAMStoreRequiresConcreteDependencies(t *testing.T) {
	if _, err := edgedeployment.NewIAMStore(nil, nil); err == nil {
		t.Fatal("IAM store accepted missing pool and authorizer")
	}
}

func TestProtectedOperationsRejectNilAndZeroStoresWithoutPanic(t *testing.T) {
	actor, err := edgedeployment.NewSessionActor(
		uuid.New(), uuid.New(), edgedeployment.ScopeKindPlatform, uuid.New(), "signed-access-token",
	)
	if err != nil {
		t.Fatal(err)
	}
	scopeID, rolloutID := uuid.New(), uuid.New()
	command := edgedeployment.RolloutCommandRequest{
		Actor: actor, ConfigurationScopeID: scopeID, RolloutID: rolloutID,
		ExpectedRevision: 1, IdempotencyKey: "uninitialized-store", RequestID: uuid.NewString(),
	}
	operations := []struct {
		name string
		run  func(*edgedeployment.Store) error
	}{
		{name: "cancel", run: func(store *edgedeployment.Store) error {
			_, err := store.CancelRollout(t.Context(), command)
			return err
		}},
		{name: "retry", run: func(store *edgedeployment.Store) error {
			_, err := store.RetryRollout(t.Context(), command)
			return err
		}},
		{name: "get rollout", run: func(store *edgedeployment.Store) error {
			_, err := store.GetRollout(t.Context(), actor, scopeID, rolloutID)
			return err
		}},
		{name: "list rollouts", run: func(store *edgedeployment.Store) error {
			_, err := store.ListRollouts(t.Context(), actor, scopeID, edgedeployment.RolloutPageRequest{})
			return err
		}},
		{name: "list deployments", run: func(store *edgedeployment.Store) error {
			_, err := store.ListDeployments(t.Context(), actor, scopeID, rolloutID, edgedeployment.DeploymentPageRequest{})
			return err
		}},
	}
	stores := []struct {
		name  string
		store *edgedeployment.Store
	}{
		{name: "nil receiver"},
		{name: "zero store", store: &edgedeployment.Store{}},
	}
	for _, store := range stores {
		for _, operation := range operations {
			t.Run(store.name+"/"+operation.name, func(t *testing.T) {
				if err := operation.run(store.store); !errors.Is(err, edgedeployment.ErrUnavailable) {
					t.Fatalf("operation error = %v, want %v", err, edgedeployment.ErrUnavailable)
				}
			})
		}
	}
}
