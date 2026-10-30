package sessioncredential

import (
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
)

func TestVerifierConfigured(t *testing.T) {
	var nilVerifier *Verifier
	if nilVerifier.Configured() {
		t.Fatal("nil Verifier reported configured")
	}
	if new(Verifier).Configured() {
		t.Fatal("zero Verifier reported configured")
	}
	verifierWithZeroTokens, err := NewVerifier(new(identity.TokenManager), time.Now)
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	if verifierWithZeroTokens.Configured() {
		t.Fatal("NewVerifier(new(identity.TokenManager), ...) reported configured")
	}
	tokens, err := identity.NewTokenManager(strings.Repeat("t", 32), time.Hour)
	if err != nil {
		t.Fatalf("identity.NewTokenManager() error = %v", err)
	}
	verifier, err := NewVerifier(tokens, time.Now)
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	if !verifier.Configured() {
		t.Fatal("NewVerifier() result reported unconfigured")
	}
}
