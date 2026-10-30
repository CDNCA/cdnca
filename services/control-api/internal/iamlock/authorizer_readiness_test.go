package iamlock

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
)

func TestAuthorizerConfigured(t *testing.T) {
	var nilAuthorizer *Authorizer
	if nilAuthorizer.Configured() {
		t.Fatal("nil Authorizer reported configured")
	}
	if new(Authorizer).Configured() {
		t.Fatal("zero Authorizer reported configured")
	}

	tokens, err := identity.NewTokenManager(strings.Repeat("t", 32), time.Hour)
	if err != nil {
		t.Fatalf("identity.NewTokenManager() error = %v", err)
	}
	sessions, err := sessioncredential.NewVerifier(tokens, time.Now)
	if err != nil {
		t.Fatalf("sessioncredential.NewVerifier() error = %v", err)
	}
	apiKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{'p'}, 32), time.Now)
	if err != nil {
		t.Fatalf("apikeycredential.NewVerifier() error = %v", err)
	}
	zeroSessionsAuthorizer, err := NewAuthorizer(new(sessioncredential.Verifier), apiKeys)
	if err != nil {
		t.Fatalf("NewAuthorizer() error = %v", err)
	}
	if zeroSessionsAuthorizer.Configured() {
		t.Fatal("NewAuthorizer(new(sessioncredential.Verifier), ...) reported configured")
	}
	sessionsWithZeroTokens, err := sessioncredential.NewVerifier(new(identity.TokenManager), time.Now)
	if err != nil {
		t.Fatalf("sessioncredential.NewVerifier() error = %v", err)
	}
	nestedZeroSessionsAuthorizer, err := NewAuthorizer(sessionsWithZeroTokens, apiKeys)
	if err != nil {
		t.Fatalf("NewAuthorizer() error = %v", err)
	}
	if nestedZeroSessionsAuthorizer.Configured() {
		t.Fatal("NewAuthorizer(NewVerifier(new(identity.TokenManager), ...), ...) reported configured")
	}
	zeroAPIKeysAuthorizer, err := NewAuthorizer(sessions, new(apikeycredential.Verifier))
	if err != nil {
		t.Fatalf("NewAuthorizer() error = %v", err)
	}
	if zeroAPIKeysAuthorizer.Configured() {
		t.Fatal("NewAuthorizer(..., new(apikeycredential.Verifier)) reported configured")
	}
	authorizer, err := NewAuthorizer(sessions, apiKeys)
	if err != nil {
		t.Fatalf("NewAuthorizer() error = %v", err)
	}
	if !authorizer.Configured() {
		t.Fatal("NewAuthorizer() result reported unconfigured")
	}
}

func TestInvalidCredentialClassificationContract(t *testing.T) {
	for name, err := range map[string]error{
		"sentinel": ErrInvalidCredential,
		"session":  mapSessionCredentialError(sessioncredential.ErrInvalidCredential),
		"API key":  mapAPIKeyCredentialError(apikeycredential.ErrInvalidCredential),
	} {
		t.Run(name, func(t *testing.T) {
			if !errors.Is(err, ErrInvalidCredential) || !errors.Is(err, ErrPermissionDenied) {
				t.Fatalf("classification=%v invalid=%t permission=%t", err,
					errors.Is(err, ErrInvalidCredential), errors.Is(err, ErrPermissionDenied))
			}
			if errors.Is(err, ErrUnavailable) {
				t.Fatalf("invalid credential classified unavailable: %v", err)
			}
		})
	}
	if errors.Is(ErrPermissionDenied, ErrInvalidCredential) {
		t.Fatal("plain permission denial classified as invalid credential")
	}

	for name, err := range map[string]error{
		"session": mapSessionCredentialError(sessioncredential.ErrUnavailable),
		"API key": mapAPIKeyCredentialError(apikeycredential.ErrUnavailable),
	} {
		t.Run(name+" dependency", func(t *testing.T) {
			if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrInvalidCredential) ||
				errors.Is(err, ErrPermissionDenied) {
				t.Fatalf("dependency classification=%v unavailable=%t invalid=%t permission=%t", err,
					errors.Is(err, ErrUnavailable), errors.Is(err, ErrInvalidCredential),
					errors.Is(err, ErrPermissionDenied))
			}
		})
	}
}
