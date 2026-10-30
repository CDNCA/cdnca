//go:build integration

package pluginwebhookcontrol

import (
	"bytes"
	"encoding/base64"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestRuntimeSecretProviderHead084FencesSecretStates(t *testing.T) {
	fixture := newStoreIntegrationFixture(t)
	keyring := runtimeIntegrationKeyring()
	provider, err := NewRuntimeSecretProvider(fixture.pool, keyring)
	if err != nil {
		t.Fatal(err)
	}
	created, err := fixture.store.CreateSubscription(t.Context(), fixture.actor, CreateSubscriptionRequest{
		Name: "Runtime", TargetURL: "https://runtime.example.com/webhook", EventTypes: []string{EventTypeTest}, IdempotencyKey: "runtime-create-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	subscription, active := created.Value.Subscription.ID, created.Value.Subscription.ActiveSecretVersionID
	assertRuntimeSecret(t, provider, fixture.actor.TargetScopeID, subscription, active, created.Value.Secret)
	for name, ids := range map[string][3]uuid.UUID{
		"wrong tenant":       {uuid.New(), subscription, active},
		"wrong subscription": {fixture.actor.TargetScopeID, uuid.New(), active},
		"wrong version":      {fixture.actor.TargetScopeID, subscription, uuid.New()},
	} {
		t.Run(name, func(t *testing.T) {
			if secret, err := provider.Secret(t.Context(), ids[0], ids[1], ids[2]); secret != nil || !errors.Is(err, ErrSecretUnavailable) {
				t.Fatalf("Secret() = %x,%v", secret, err)
			}
		})
	}

	rotation, err := fixture.store.RotateSecret(t.Context(), fixture.actor, subscription, WriteRequest{IdempotencyKey: "runtime-rotate-1", Revision: 1})
	if err != nil {
		t.Fatal(err)
	}
	if secret, err := provider.Secret(t.Context(), fixture.actor.TargetScopeID, subscription, rotation.Value.RotationID); secret != nil || !errors.Is(err, ErrSecretUnavailable) {
		t.Fatalf("pending secret = %x,%v", secret, err)
	}
	if _, err = fixture.store.ActivateSecret(t.Context(), fixture.actor, subscription, rotation.Value.RotationID, WriteRequest{IdempotencyKey: "runtime-activate-1", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	if secret, err := provider.Secret(t.Context(), fixture.actor.TargetScopeID, subscription, active); secret != nil || !errors.Is(err, ErrSecretUnavailable) {
		t.Fatalf("retired secret = %x,%v", secret, err)
	}
	assertRuntimeSecret(t, provider, fixture.actor.TargetScopeID, subscription, rotation.Value.RotationID, rotation.Value.Secret)

	unavailable, err := NewRuntimeSecretProvider(fixture.pool, fixedKeyring{active: WrappingKey{ID: "other-key", Key: [32]byte{9}}})
	if err != nil {
		t.Fatal(err)
	}
	if secret, err := unavailable.Secret(t.Context(), fixture.actor.TargetScopeID, subscription, rotation.Value.RotationID); secret != nil || !errors.Is(err, ErrSecretUnavailable) {
		t.Fatalf("unavailable key = %x,%v", secret, err)
	}
	if _, err = fixture.store.RevokeSubscription(t.Context(), fixture.actor, subscription, WriteRequest{IdempotencyKey: "runtime-revoke-1", Revision: 2}); err != nil {
		t.Fatal(err)
	}
	if secret, err := provider.Secret(t.Context(), fixture.actor.TargetScopeID, subscription, rotation.Value.RotationID); secret != nil || !errors.Is(err, ErrSecretUnavailable) {
		t.Fatalf("revoked secret = %x,%v", secret, err)
	}

	fixture.pool.Close()
	if secret, err := provider.Secret(t.Context(), fixture.actor.TargetScopeID, subscription, rotation.Value.RotationID); secret != nil || !errors.Is(err, ErrSecretUnavailable) {
		t.Fatalf("closed pool = %x,%v", secret, err)
	}
}

func TestRuntimeSecretProviderLinearizesWithActivationAndRevoke(t *testing.T) {
	fixture := newStoreIntegrationFixture(t)
	provider, err := NewRuntimeSecretProvider(fixture.pool, runtimeIntegrationKeyring())
	if err != nil {
		t.Fatal(err)
	}
	created, err := fixture.store.CreateSubscription(t.Context(), fixture.actor, CreateSubscriptionRequest{
		Name: "Concurrent", TargetURL: "https://concurrent.example.com/webhook", EventTypes: []string{EventTypeTest}, IdempotencyKey: "concurrent-create-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	subscription, oldSecretID := created.Value.Subscription.ID, created.Value.Subscription.ActiveSecretVersionID
	rotation, err := fixture.store.RotateSecret(t.Context(), fixture.actor, subscription, WriteRequest{IdempotencyKey: "concurrent-rotate-1", Revision: 1})
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	var wait sync.WaitGroup
	var readSecret []byte
	var readErr, activateErr error
	wait.Add(2)
	go func() {
		defer wait.Done()
		<-start
		readSecret, readErr = provider.Secret(t.Context(), fixture.actor.TargetScopeID, subscription, oldSecretID)
	}()
	go func() {
		defer wait.Done()
		<-start
		_, activateErr = fixture.store.ActivateSecret(t.Context(), fixture.actor, subscription, rotation.Value.RotationID, WriteRequest{IdempotencyKey: "concurrent-activate-1", Revision: 1})
	}()
	close(start)
	wait.Wait()
	if activateErr != nil || readErr != nil && !errors.Is(readErr, ErrSecretUnavailable) {
		t.Fatalf("activation race = read %v activate %v", readErr, activateErr)
	}
	clearBytes(readSecret)
	if secret, err := provider.Secret(t.Context(), fixture.actor.TargetScopeID, subscription, oldSecretID); secret != nil || !errors.Is(err, ErrSecretUnavailable) {
		t.Fatalf("old secret after activation = %x,%v", secret, err)
	}
	assertRuntimeSecret(t, provider, fixture.actor.TargetScopeID, subscription, rotation.Value.RotationID, rotation.Value.Secret)

	start = make(chan struct{})
	readSecret, readErr = nil, nil
	var revokeErr error
	wait.Add(2)
	go func() {
		defer wait.Done()
		<-start
		readSecret, readErr = provider.Secret(t.Context(), fixture.actor.TargetScopeID, subscription, rotation.Value.RotationID)
	}()
	go func() {
		defer wait.Done()
		<-start
		_, revokeErr = fixture.store.RevokeSubscription(t.Context(), fixture.actor, subscription, WriteRequest{IdempotencyKey: "concurrent-revoke-1", Revision: 2})
	}()
	close(start)
	wait.Wait()
	if revokeErr != nil || readErr != nil && !errors.Is(readErr, ErrSecretUnavailable) {
		t.Fatalf("revoke race = read %v revoke %v", readErr, revokeErr)
	}
	clearBytes(readSecret)
	if secret, err := provider.Secret(t.Context(), fixture.actor.TargetScopeID, subscription, rotation.Value.RotationID); secret != nil || !errors.Is(err, ErrSecretUnavailable) {
		t.Fatalf("secret after revoke = %x,%v", secret, err)
	}
}

func TestRuntimeSecretProviderSecretTxHoldsFenceUntilCallerCommit(t *testing.T) {
	fixture := newStoreIntegrationFixture(t)
	provider, err := NewRuntimeSecretProvider(fixture.pool, runtimeIntegrationKeyring())
	if err != nil {
		t.Fatal(err)
	}
	created, err := fixture.store.CreateSubscription(t.Context(), fixture.actor, CreateSubscriptionRequest{
		Name: "Started fence", TargetURL: "https://started.example.com/webhook", EventTypes: []string{EventTypeTest}, IdempotencyKey: "started-fence-create-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	subscription, secretID := created.Value.Subscription.ID, created.Value.Subscription.ActiveSecretVersionID
	startTx, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer startTx.Rollback(t.Context())
	secret, err := provider.SecretTx(t.Context(), startTx, fixture.actor.TargetScopeID, subscription, secretID)
	if err != nil || len(secret) != 32 {
		t.Fatalf("SecretTx() = %x, %v", secret, err)
	}

	mutator, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer mutator.Rollback(t.Context())
	if _, err = mutator.Exec(t.Context(), `SET LOCAL lock_timeout='100ms'`); err != nil {
		t.Fatal(err)
	}
	var ignored uuid.UUID
	err = mutator.QueryRow(t.Context(), `SELECT id FROM plugin_webhook_subscriptions WHERE tenant_scope_id=$1 AND id=$2 FOR UPDATE`, fixture.actor.TargetScopeID, subscription).Scan(&ignored)
	var postgres *pgconn.PgError
	if !errors.As(err, &postgres) || postgres.Code != "55P03" {
		t.Fatalf("rotation/revoke fence error = %v, want lock timeout", err)
	}
	if err = mutator.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = startTx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	clearBytes(secret)

	if _, err = fixture.store.RevokeSubscription(t.Context(), fixture.actor, subscription, WriteRequest{IdempotencyKey: "started-fence-revoke-1", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	if secret, err = provider.Secret(t.Context(), fixture.actor.TargetScopeID, subscription, secretID); secret != nil || !errors.Is(err, ErrSecretUnavailable) {
		t.Fatalf("secret after revoke = %x, %v", secret, err)
	}
}

func runtimeIntegrationKeyring() fixedKeyring {
	return fixedKeyring{active: WrappingKey{ID: "plugin-webhook-kek-v1", Key: [32]byte{1, 2, 3, 4}}}
}

func assertRuntimeSecret(t *testing.T, provider *RuntimeSecretProvider, target, subscription, secretID uuid.UUID, encoded string) {
	t.Helper()
	want, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	got, err := provider.Secret(t.Context(), target, subscription, secretID)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("Secret() = %x,%v want %x", got, err, want)
	}
	clearBytes(got)
	clearBytes(want)
}
