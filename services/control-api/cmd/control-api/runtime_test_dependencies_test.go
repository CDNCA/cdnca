package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/jackc/pgx/v5/pgxpool"
)

// runtimeTestDependencies are production-shaped dependencies that never
// connect: a lazy pool to an invalid host, a real identity service and IAM.
type runtimeTestDependencies struct {
	Pool     *pgxpool.Pool
	Identity *identity.Service
	IAM      *iamlock.Authorizer
}

func configuredRuntimeTestDependencies(t *testing.T) runtimeTestDependencies {
	t.Helper()
	config, err := pgxpool.ParseConfig("postgres://runtime-test.invalid/runtime")
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	tokens, err := identity.NewTokenManager(strings.Repeat("p", 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := sessioncredential.NewVerifier(tokens, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	apiKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{0x42}, 32), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := iamlock.NewAuthorizer(sessions, apiKeys)
	if err != nil {
		t.Fatal(err)
	}
	return runtimeTestDependencies{Pool: pool, Identity: identityService, IAM: authorizer}
}
