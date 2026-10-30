package mfa

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestProofScopeShape(t *testing.T) {
	tenant := uuid.New()
	for _, c := range []struct {
		platform bool
		tenant   uuid.UUID
		want     bool
	}{{true, uuid.Nil, true}, {true, tenant, false}, {false, tenant, true}, {false, uuid.Nil, false}} {
		if got := validProofScope(c.platform, c.tenant); got != c.want {
			t.Errorf("validProofScope(%v,%v) = %v", c.platform, c.tenant, got)
		}
	}
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), SessionID: uuid.New()}
	token := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	ctx := RequestContext{RequestID: "r", TraceID: "t"}
	if err := validateConsumeStepUp(actor, ConsumeStepUpRequest{Token: token, PlatformScope: true, TenantID: tenant,
		Audience: "a", Action: "b", Context: ctx}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("platform proof with tenant: %v", err)
	}
	if err := validateConsumeStepUp(actor, ConsumeStepUpRequest{Token: token, Audience: "a", Action: "b",
		Context: ctx}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("tenant proof without tenant: %v", err)
	}
}

func TestPlatformProofRequiresPlatformSession(t *testing.T) {
	tenant := uuid.New()
	if err := validateProofScopeBinding(t.Context(), nil, principalState{scopeKind: "tenant", tenantID: &tenant},
		true, uuid.Nil); !errors.Is(err, ErrProofBinding) {
		t.Fatalf("tenant session platform proof: %v", err)
	}
	if err := validateProofScopeBinding(t.Context(), nil, principalState{scopeKind: "platform"}, true, uuid.Nil); err != nil {
		t.Fatalf("platform session platform proof: %v", err)
	}
}
