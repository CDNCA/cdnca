package identity

import (
	"bytes"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestManagedPasswordResetRejectsInvalidInputsBeforeDependencies(t *testing.T) {
	valid := ResetManagedUserPasswordInput{
		ID: uuid.New(), TenantScopeID: uuid.New(), ExpectedRevision: 1,
		NewPassword: "replacement-password-long-enough", StepUpToken: "opaque-step-up-proof",
		IdempotencyKey: "reset-user-password", RequestID: "reset-user-password-request",
	}
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform", SessionID: uuid.New()}
	tests := map[string]func(*ResetManagedUserPasswordInput, *Actor){
		"missing session":      func(_ *ResetManagedUserPasswordInput, actor *Actor) { actor.SessionID = uuid.Nil },
		"tenant actor":         func(_ *ResetManagedUserPasswordInput, actor *Actor) { actor.ScopeKind = "tenant" },
		"missing target scope": func(input *ResetManagedUserPasswordInput, _ *Actor) { input.TenantScopeID = uuid.Nil },
		"missing revision":     func(input *ResetManagedUserPasswordInput, _ *Actor) { input.ExpectedRevision = 0 },
		"short password":       func(input *ResetManagedUserPasswordInput, _ *Actor) { input.NewPassword = "short-1" },
		"missing step up":      func(input *ResetManagedUserPasswordInput, _ *Actor) { input.StepUpToken = "" },
		"invalid idempotency":  func(input *ResetManagedUserPasswordInput, _ *Actor) { input.IdempotencyKey = "has spaces" },
		"missing request":      func(input *ResetManagedUserPasswordInput, _ *Actor) { input.RequestID = "" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input, candidate := valid, actor
			mutate(&input, &candidate)
			service := &Service{}
			if _, err := service.ResetManagedUserPassword(t.Context(), candidate, input); !errors.Is(err, ErrInvalidUserInput) {
				t.Fatalf("ResetManagedUserPassword() error = %v, want invalid input", err)
			}
		})
	}
}

func TestManagedPasswordResetBindingIsStableAndDoesNotContainSecrets(t *testing.T) {
	requestDigest := [32]byte{1, 2, 3, 4}
	secretHash := "$argon2id$v=19$m=65536,t=3,p=2$c2FsdA$ZGlnaWVzdA"
	first := managedPasswordResetBindingDigest(requestDigest, secretHash)
	second := managedPasswordResetBindingDigest(requestDigest, secretHash)
	if first != second || first == ([32]byte{}) {
		t.Fatalf("binding digest is not stable: %x / %x", first, second)
	}
	for _, secret := range [][]byte{[]byte(secretHash), []byte("replacement-password-long-enough")} {
		if bytes.Contains(first[:], secret) {
			t.Fatalf("binding digest contains secret %q", secret)
		}
	}
}
