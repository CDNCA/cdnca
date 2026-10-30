package accountrecovery

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestRecoveryContextBindsScopeTokenAndExpiry(t *testing.T) {
	key := bytes.Repeat([]byte{0x41}, 32)
	now := time.Date(2026, 7, 23, 3, 0, 0, 123000, time.UTC)
	claim := dispatchClaim{
		TenantID: uuid.New(), ScopeID: uuid.New(), ChallengeID: uuid.New(), ExpiresAt: now.Add(15 * time.Minute),
	}
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x52}, tokenBytes))
	encoded, err := issueRecoveryContext(key, claim, token)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := VerifyRecoveryContext(key, token, encoded, now)
	if err != nil || scope.TenantID != claim.TenantID || scope.ScopeID != claim.ScopeID {
		t.Fatalf("verified scope = (%+v, %v)", scope, err)
	}

	otherToken := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x53}, tokenBytes))
	if _, err := VerifyRecoveryContext(key, otherToken, encoded, now); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("cross-token error = %v", err)
	}
	if _, err := VerifyRecoveryContext(key, token, encoded, claim.ExpiresAt); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expired context error = %v", err)
	}

	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	for _, index := range []int{1, 17, 33, 49, 57, recoveryContextPayloadSize} {
		tampered := append([]byte(nil), raw...)
		tampered[index] ^= 0xff
		if _, err := VerifyRecoveryContext(key, token,
			base64.RawURLEncoding.EncodeToString(tampered), now); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("tamper at %d error = %v", index, err)
		}
	}
}

func TestRecoveryContextRejectsMalformedInputs(t *testing.T) {
	key := bytes.Repeat([]byte{0x41}, 32)
	now := time.Date(2026, 7, 23, 3, 0, 0, 0, time.UTC)
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x52}, tokenBytes))
	claim := dispatchClaim{
		TenantID: uuid.New(), ScopeID: uuid.New(), ChallengeID: uuid.New(), ExpiresAt: now.Add(time.Minute),
	}
	encoded, err := issueRecoveryContext(key, claim, token)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		key     []byte
		token   string
		context string
		now     time.Time
	}{
		{name: "short key", key: key[:31], token: token, context: encoded, now: now},
		{name: "invalid token", key: key, token: "not-a-token", context: encoded, now: now},
		{name: "invalid context", key: key, token: token, context: "not-a-context", now: now},
		{name: "zero time", key: key, token: token, context: encoded},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := VerifyRecoveryContext(test.key, test.token, test.context, test.now); !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestRecoveryContextSupportsPlatformScope(t *testing.T) {
	key := bytes.Repeat([]byte{0x41}, 32)
	now := time.Date(2026, 8, 12, 2, 0, 0, 0, time.UTC)
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x54}, tokenBytes))
	claim := dispatchClaim{ScopeID: uuid.New(), ChallengeID: uuid.New(), ExpiresAt: now.Add(time.Minute)}
	encoded, err := issueRecoveryContext(key, claim, token)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := VerifyRecoveryContext(key, token, encoded, now)
	if err != nil || scope.TenantID != uuid.Nil || scope.ScopeID != claim.ScopeID {
		t.Fatalf("platform recovery scope=%+v err=%v", scope, err)
	}
}
