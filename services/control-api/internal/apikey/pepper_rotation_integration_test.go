package apikey

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
)

func TestAPIKeyPepperRotationDualReadAndVersionBinding(t *testing.T) {
	fixture := newAPIKeyIntegrationFixture(t)
	ctx := context.Background()
	legacy := mustCreateSelfKey(t, fixture, "pepper-rotation-create")

	keyring, err := apikeycredential.NewPepperKeyring(apikeycredential.PepperKeyringConfig{
		ActiveVersion: "pepper-v2", Active: bytes.Repeat([]byte{0x24}, 32),
		PreviousVersion: LegacyPepperVersion, Previous: bytes.Repeat([]byte{0x42}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	rotatedService := NewServiceWithPepperKeyring(fixture.pool, keyring, fixture.clock.Now)
	if err := rotatedService.Ready(ctx); err != nil {
		t.Fatalf("rotated service readiness = %v", err)
	}
	if _, err := rotatedService.Authenticate(ctx, legacy.Key.KeyID+"."+legacy.Secret); err != nil {
		t.Fatalf("previous-version credential was not accepted during rotation: %v", err)
	}

	replay, err := rotatedService.CreateSelf(ctx, fixture.alice, CreateInput{
		Name: "pepper-rotation-create", Scopes: []string{"sites.read"},
		ExpiresAt: legacy.Key.ExpiresAt, IdempotencyKey: "pepper-rotation-create", RequestID: "pepper-rotation-replay",
	})
	if err != nil || replay.Key.ID != legacy.Key.ID || replay.Secret != legacy.Secret {
		t.Fatalf("cross-rotation idempotent replay = (%#v, %v)", replay, err)
	}

	current, err := rotatedService.CreateSelf(ctx, fixture.alice, CreateInput{
		Name: "pepper-v2-key", Scopes: []string{"sites.read"},
		IdempotencyKey: "pepper-v2-create", RequestID: "pepper-v2-create",
	})
	if err != nil {
		t.Fatal(err)
	}
	for id, wantVersion := range map[any]string{
		legacy.Key.ID:  LegacyPepperVersion,
		current.Key.ID: "pepper-v2",
	} {
		var got string
		if err := fixture.pool.QueryRow(ctx, `SELECT pepper_version FROM api_keys WHERE id=$1`, id).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != wantVersion {
			t.Fatalf("key %v pepper_version = %q, want %q", id, got, wantVersion)
		}
	}

	activeOnly, err := apikeycredential.NewPepperKeyring(apikeycredential.PepperKeyringConfig{
		ActiveVersion: "pepper-v2", Active: bytes.Repeat([]byte{0x24}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	activeService := NewServiceWithPepperKeyring(fixture.pool, activeOnly, fixture.clock.Now)
	if _, err := activeService.Authenticate(ctx, legacy.Key.KeyID+"."+legacy.Secret); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("retired pepper credential error = %v", err)
	}
	if _, err := activeService.Authenticate(ctx, current.Key.KeyID+"."+current.Secret); err != nil {
		t.Fatalf("active pepper credential error = %v", err)
	}

	if _, err := fixture.pool.Exec(ctx, `UPDATE api_keys
		SET secret_digest=decode(repeat('9a',32),'hex'), pepper_version='pepper-unknown',
			revision=revision+1, updated_at=updated_at+interval '1 second'
		WHERE id=$1`, current.Key.ID); err != nil {
		t.Fatalf("seed unknown pepper version: %v", err)
	}
	if _, err := rotatedService.Authenticate(ctx, current.Key.KeyID+"."+current.Secret); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("unknown pepper version error = %v", err)
	}
}
