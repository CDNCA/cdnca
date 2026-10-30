package edgepublish

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type runtimeSigner struct{}

func (*runtimeSigner) KeyID() string { return "edgepublish-runtime-test" }
func (*runtimeSigner) PublicKey() ed25519.PublicKey {
	return make(ed25519.PublicKey, ed25519.PublicKeySize)
}
func (*runtimeSigner) Sign(context.Context, []byte) ([]byte, error) {
	return make([]byte, ed25519.SignatureSize), nil
}

type runtimeEntitlement struct{}

func (runtimeEntitlement) AuthorizePublication(
	context.Context,
	pgx.Tx,
	EntitlementRequest,
) (EntitlementDecision, error) {
	return EntitlementDecision{}, nil
}

func TestRuntimeBindsRealPublisherAndOutboxStore(t *testing.T) {
	config, dependencies := validRuntimeConfigAndDependencies(t)
	runtime, err := NewRuntime(config, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	if !runtime.ConfiguredFor(dependencies.Pool, dependencies.IAM) ||
		runtime.Publisher() == nil || runtime.RolloutCommands() == nil {
		t.Fatalf("runtime is not fully bound: %+v", runtime)
	}
	if runtime.ConfiguredFor(new(pgxpool.Pool), dependencies.IAM) ||
		runtime.ConfiguredFor(dependencies.Pool, new(iamlock.Authorizer)) {
		t.Fatal("runtime accepted mismatched production dependencies")
	}
}

func TestRuntimeRejectsMissingTypedNilAndUnconfiguredDependencies(t *testing.T) {
	tests := map[string]func(*RuntimeConfig, *RuntimeDependencies){
		"pool_missing": func(_ *RuntimeConfig, value *RuntimeDependencies) { value.Pool = nil },
		"pool_zero":    func(_ *RuntimeConfig, value *RuntimeDependencies) { value.Pool = new(pgxpool.Pool) },
		"iam_missing":  func(_ *RuntimeConfig, value *RuntimeDependencies) { value.IAM = nil },
		"iam_zero":     func(_ *RuntimeConfig, value *RuntimeDependencies) { value.IAM = new(iamlock.Authorizer) },
		"signer_missing": func(_ *RuntimeConfig, value *RuntimeDependencies) {
			value.Signer = nil
		},
		"signer_typed_nil": func(_ *RuntimeConfig, value *RuntimeDependencies) {
			var signer *runtimeSigner
			value.Signer = signer
		},
		"clock_missing": func(config *RuntimeConfig, _ *RuntimeDependencies) {
			config.Publisher.Clock = nil
		},
		"entitlement_missing": func(config *RuntimeConfig, _ *RuntimeDependencies) {
			config.Publisher.EntitlementAuthorizer = nil
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			config, dependencies := validRuntimeConfigAndDependencies(t)
			mutate(&config, &dependencies)
			runtime, err := NewRuntime(config, dependencies)
			if runtime != nil || !errors.Is(err, ErrInvalidRuntimeConfig) {
				t.Fatalf("NewRuntime() = (%T, %v), want nil invalid runtime config", runtime, err)
			}
		})
	}
}

func TestRuntimeRejectsMissingTargetResolver(t *testing.T) {
	config, dependencies := validRuntimeConfigAndDependencies(t)
	config.Publisher.TargetResolver = nil
	runtime, err := NewRuntime(config, dependencies)
	if runtime != nil || !errors.Is(err, ErrInvalidRuntimeConfig) {
		t.Fatalf("missing target resolver = (%T, %v), want nil invalid runtime config", runtime, err)
	}
}

func validRuntimeConfigAndDependencies(t *testing.T) (RuntimeConfig, RuntimeDependencies) {
	t.Helper()
	poolConfig, err := pgxpool.ParseConfig("postgresql://runtime:runtime@127.0.0.1:1/runtime?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	poolConfig.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(context.Background(), poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	tokens, err := identity.NewTokenManager("edgepublish-runtime-token-secret", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := sessioncredential.NewVerifier(tokens, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	apiKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{0x61}, 32), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := iamlock.NewAuthorizer(sessions, apiKeys)
	if err != nil {
		t.Fatal(err)
	}
	publisher := DefaultConfig()
	publisher.EntitlementAuthorizer = runtimeEntitlement{}
	return RuntimeConfig{Publisher: publisher}, RuntimeDependencies{
		Pool: pool, Signer: &runtimeSigner{}, IAM: authorizer,
	}
}
