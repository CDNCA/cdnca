package pluginwebhookcontrol

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestActorRequiresExplicitAuthenticatedAndTargetScopes(t *testing.T) {
	target := uuid.New()
	authenticated := uuid.New()
	user := uuid.New()
	for name, actor := range map[string]Actor{
		"zero user":           {ActorScopeID: authenticated, TargetScopeID: target},
		"zero actor scope":    {ActorUserID: user, TargetScopeID: target},
		"zero target scope":   {ActorUserID: user, ActorScopeID: authenticated},
		"tenant impersonates": {ActorUserID: user, ActorScopeID: uuid.New(), TargetScopeID: target, ScopeKind: ScopeTenant},
	} {
		t.Run(name, func(t *testing.T) {
			if err := actor.validate(); !errors.Is(err, ErrPermissionDenied) {
				t.Fatalf("validate() = %v, want permission denied", err)
			}
		})
	}
	if err := (Actor{ActorUserID: user, ActorScopeID: target, TargetScopeID: target, ScopeKind: ScopeTenant}).validate(); err != nil {
		t.Fatalf("tenant actor validate() = %v", err)
	}
	if err := (Actor{ActorUserID: user, ActorScopeID: authenticated, TargetScopeID: target, ScopeKind: ScopePlatform}).validate(); err != nil {
		t.Fatalf("platform actor validate() = %v", err)
	}
}

func TestSecretCipherUsesFrozenAADAndNeverFormatsPlaintext(t *testing.T) {
	key := WrappingKey{ID: "key/v1", Key: [32]byte{1, 2, 3}}
	keyring := fixedKeyring{active: key}
	cipher, err := newSecretCipher(keyring, fixedBytes(0x42))
	if err != nil {
		t.Fatal(err)
	}
	target, subscription, secretID := uuid.New(), uuid.New(), uuid.New()
	record, plaintext, err := cipher.encryptSecret(context.Background(), target, subscription, secretID, 7)
	if err != nil {
		t.Fatal(err)
	}
	defer plaintext.clear()
	if len(record.Nonce) != 12 || len(record.Ciphertext) != 48 || len(record.AADSHA256) != 32 {
		t.Fatalf("encrypted lengths = nonce %d ciphertext %d aad %d", len(record.Nonce), len(record.Ciphertext), len(record.AADSHA256))
	}
	plaintextBytes := plaintext.bytes()
	defer clearBytes(plaintextBytes)
	if got := base64.RawURLEncoding.EncodeToString(plaintextBytes); len(got) != 43 {
		t.Fatalf("encoded secret length = %d, want 43", len(got))
	}
	decrypted, err := cipher.decryptSecret(context.Background(), record, target, subscription, secretID, 7)
	if err != nil {
		t.Fatal(err)
	}
	defer decrypted.clear()
	decryptedBytes := decrypted.bytes()
	defer clearBytes(decryptedBytes)
	if string(decryptedBytes) != string(plaintextBytes) {
		t.Fatalf("decrypted secret mismatch")
	}
}

func TestCanonicalTargetValidation(t *testing.T) {
	validator := NewTargetValidator()
	for _, raw := range []string{
		"http://example.com/hook", "https://localhost/hook", "https://worker.localhost/hook", "https://127.0.0.1/hook",
		"https://xn--bcher-kva.example/hook", "https://example.com/a%2fb",
		"https://example.com/a/../b", "https://user@example.com/hook", "https://example.com/hook?q=1",
	} {
		if _, err := validator.Validate(raw); !errors.Is(err, ErrTargetForbidden) {
			t.Fatalf("Validate(%q) = %v, want forbidden", raw, err)
		}
	}
	got, err := validator.Validate("https://EXAMPLE.COM:443/a:b@c")
	if err != nil {
		t.Fatal(err)
	}
	if got.URL != "https://example.com/a:b@c" || got.Host != "example.com" || got.Path != "/a:b@c" {
		t.Fatalf("canonical target = %+v", got)
	}
}

func TestActorFormattingRedactsSession(t *testing.T) {
	actor, err := NewActor(uuid.New(), uuid.New(), uuid.New(), ScopePlatform, "raw-formal-session")
	if err != nil {
		t.Fatal(err)
	}
	for _, formatted := range []string{fmt.Sprint(actor), fmt.Sprintf("%+v", actor), fmt.Sprintf("%#v", actor), string(mustJSON(t, actor))} {
		if strings.Contains(formatted, "raw-formal-session") {
			t.Fatalf("Actor leaked session: %s", formatted)
		}
	}
}

func TestSecretReceiptFormattingRedactsPlaintext(t *testing.T) {
	const subscriptionSecret = "subscription-secret-must-not-format"
	const rotationSecret = "rotation-secret-must-not-format"
	values := []struct {
		name   string
		secret string
		value  any
	}{
		{"subscription receipt", subscriptionSecret, SubscriptionReceipt{Secret: subscriptionSecret}},
		{"rotation receipt", rotationSecret, RotationReceipt{Secret: rotationSecret}},
	}
	for _, value := range values {
		t.Run(value.name, func(t *testing.T) {
			formatted := []string{
				fmt.Sprint(value.value),
				fmt.Sprintf("%s", value.value),
				fmt.Sprintf("%q", value.value),
				fmt.Sprintf("%v", value.value),
				fmt.Sprintf("%+v", value.value),
				fmt.Sprintf("%#v", value.value),
			}
			for _, output := range formatted {
				if strings.Contains(output, value.secret) {
					t.Fatalf("formatted receipt leaked plaintext: %s", output)
				}
			}
		})
	}
}

func TestRequestDigestBindsActorAndRequestIdentity(t *testing.T) {
	target, actorScope, user := uuid.New(), uuid.New(), uuid.New()
	actor, err := NewActor(user, actorScope, target, ScopePlatform, "formal-session")
	if err != nil {
		t.Fatal(err)
	}
	type request struct {
		Revision uint64 `json:"revision"`
	}
	base, err := requestDigest(actor, opRotate, "rotate-1", request{Revision: 1})
	if err != nil {
		t.Fatal(err)
	}
	otherActor := actor
	otherActor.ActorUserID = uuid.New()
	other, err := requestDigest(otherActor, opRotate, "rotate-1", request{Revision: 1})
	if err != nil {
		t.Fatal(err)
	}
	changed, err := requestDigest(actor, opRotate, "rotate-1", request{Revision: 2})
	if err != nil {
		t.Fatal(err)
	}
	if base == other || base == changed {
		t.Fatal("request digest did not bind actor triple and revision")
	}
}

func TestWriteCommitErrorDistinguishesAmbiguousFromKnownRollback(t *testing.T) {
	if err := mapWriteCommitError(io.ErrUnexpectedEOF); !errors.Is(err, ErrResultUnknown) || errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("transport commit error = %v, want result unknown only", err)
	}
	if err := mapWriteCommitError(context.DeadlineExceeded); !errors.Is(err, ErrResultUnknown) {
		t.Fatalf("deadline commit error = %v, want result unknown", err)
	}
	for name, input := range map[string]error{
		"server rejected commit":    &pgconn.PgError{Code: "23505"},
		"serialization rolled back": &pgconn.PgError{Code: "40001"},
		"deadlock rolled back":      &pgconn.PgError{Code: "40P01"},
		"commit rolled back":        pgx.ErrTxCommitRollback,
	} {
		t.Run(name, func(t *testing.T) {
			if err := mapWriteCommitError(input); errors.Is(err, ErrResultUnknown) || !errors.Is(err, ErrStoreUnavailable) && name != "server rejected commit" {
				t.Fatalf("mapWriteCommitError() = %v, want known rollback/failure", err)
			}
		})
	}
}

func TestP8408MappingUsesStructuredDetailCodes(t *testing.T) {
	for name, test := range map[string]struct {
		detail string
		want   error
	}{
		"rate":        {detail: "plugin_webhook.rate_limited", want: ErrRateLimited},
		"quota":       {detail: "plugin_webhook.quota_exceeded", want: ErrQuotaExceeded},
		"entitlement": {detail: "plugin_webhook.entitlement_denied", want: ErrEntitlementDenied},
	} {
		t.Run(name, func(t *testing.T) {
			err := mapStoreError(&pgconn.PgError{Code: "P8408", Message: "invariant text must be ignored", Detail: test.detail})
			if !errors.Is(err, test.want) {
				t.Fatalf("mapStoreError() = %v, want %v", err, test.want)
			}
		})
	}
	invariant := mapStoreError(&pgconn.PgError{
		Code: "P8408", Message: "rate quota entitlement words are not a classification API",
		Detail: "plugin_webhook.invariant_violation",
	})
	if !errors.Is(invariant, ErrStoreUnavailable) || errors.Is(invariant, ErrRateLimited) ||
		errors.Is(invariant, ErrQuotaExceeded) || errors.Is(invariant, ErrEntitlementDenied) {
		t.Fatalf("invariant P8408 = %v, want fail-closed store unavailable", invariant)
	}
}

func TestBoundedRetryAfterUsesLargestRemainingWholeSecond(t *testing.T) {
	for name, test := range map[string]struct {
		seconds []int64
		want    time.Duration
	}{
		"empty":    {want: time.Second},
		"negative": {seconds: []int64{-1, 0}, want: time.Second},
		"largest":  {seconds: []int64{7, 19}, want: 19 * time.Second},
		"maximum":  {seconds: []int64{3601}, want: time.Hour},
	} {
		t.Run(name, func(t *testing.T) {
			if got := boundedRetryAfter(test.seconds...); got != test.want {
				t.Fatalf("boundedRetryAfter(%v) = %v, want %v", test.seconds, got, test.want)
			}
		})
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

type fixedKeyring struct{ active WrappingKey }

func (keyring fixedKeyring) Active(context.Context) (WrappingKey, error) { return keyring.active, nil }
func (keyring fixedKeyring) Lookup(_ context.Context, id string) ([32]byte, error) {
	if id != keyring.active.ID {
		return [32]byte{}, ErrSecretUnavailable
	}
	return keyring.active.Key, nil
}

func fixedBytes(value byte) func([]byte) error {
	return func(target []byte) error {
		for index := range target {
			target[index] = value
		}
		return nil
	}
}
