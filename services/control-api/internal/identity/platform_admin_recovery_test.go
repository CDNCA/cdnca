package identity

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestPlatformAdministratorRecoveryInput(t *testing.T) {
	base := PlatformAdministratorRecoveryInput{UserID: uuid.New(), ScopeID: uuid.New(),
		ExpectedUsername: "recovery-before", ExpectedRevision: 1, NewUsername: "recovery-after",
		NewPassword: "fixture-recovery-password", RequestID: uuid.NewString()}
	for name, change := range map[string]func(*PlatformAdministratorRecoveryInput){
		"user":           func(in *PlatformAdministratorRecoveryInput) { in.UserID = uuid.Nil },
		"scope":          func(in *PlatformAdministratorRecoveryInput) { in.ScopeID = uuid.Nil },
		"request":        func(in *PlatformAdministratorRecoveryInput) { in.RequestID = "not-a-request" },
		"old name":       func(in *PlatformAdministratorRecoveryInput) { in.ExpectedUsername = "WrongCase" },
		"new name":       func(in *PlatformAdministratorRecoveryInput) { in.NewUsername = " bad-name" },
		"revision":       func(in *PlatformAdministratorRecoveryInput) { in.ExpectedRevision = 0 },
		"short password": func(in *PlatformAdministratorRecoveryInput) { in.NewPassword = "short" },
		"long password":  func(in *PlatformAdministratorRecoveryInput) { in.NewPassword = strings.Repeat("x", 1025) },
	} {
		t.Run(name, func(t *testing.T) {
			input := base
			change(&input)
			if _, err := NewStore(nil).RecoverPlatformAdministrator(t.Context(), input); !errors.Is(err, ErrPlatformRecoveryInput) {
				t.Fatalf("invalid input reached storage: %v", err)
			}
		})
	}
	if _, err := NewStore(nil).RecoverPlatformAdministrator(nil, base); !errors.Is(err, ErrPlatformRecoveryInput) {
		t.Fatal(err)
	}
	if _, _, err := NewStore(nil).PlatformAdministratorRecoveryStatus(context.Background(), uuid.Nil, base.ScopeID, base.RequestID); !errors.Is(err, ErrPlatformRecoveryInput) {
		t.Fatal(err)
	}
	if _, _, err := NewStore(nil).PlatformAdministratorRecoveryStatus(context.Background(), base.UserID, base.ScopeID, base.RequestID); !errors.Is(err, ErrPlatformRecoveryUnavailable) {
		t.Fatal(err)
	}
}
