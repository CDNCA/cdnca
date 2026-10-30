package identity

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestServiceConfigured(t *testing.T) {
	var nilService *Service
	if nilService.Configured() {
		t.Fatal("nil Service reported configured")
	}
	if new(Service).Configured() {
		t.Fatal("zero Service reported configured")
	}

	tokens, err := NewTokenManager(strings.Repeat("t", 32), time.Hour)
	if err != nil {
		t.Fatalf("NewTokenManager() error = %v", err)
	}
	serviceWithoutPool, err := NewService(NewStore(nil), tokens, time.Hour)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	if serviceWithoutPool.Configured() {
		t.Fatal("NewService(NewStore(nil), ...) reported configured")
	}
	serviceWithZeroPool, err := NewService(NewStore(new(pgxpool.Pool)), tokens, time.Hour)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	if serviceWithZeroPool.Configured() {
		t.Fatal("NewService(NewStore(new(pgxpool.Pool)), ...) reported configured")
	}
	poolConfig, err := pgxpool.ParseConfig("postgresql://identity:identity@127.0.0.1:1/identity?sslmode=disable")
	if err != nil {
		t.Fatalf("pgxpool.ParseConfig() error = %v", err)
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), poolConfig)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig() error = %v", err)
	}
	t.Cleanup(pool.Close)
	serviceWithZeroTokens, err := NewService(NewStore(pool), new(TokenManager), time.Hour)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	if serviceWithZeroTokens.Configured() {
		t.Fatal("NewService(..., new(TokenManager), ...) reported configured")
	}
	service, err := NewService(NewStore(pool), tokens, time.Hour)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	if !service.Configured() {
		t.Fatal("NewService() result reported unconfigured")
	}
}

func TestTokenManagerConfigured(t *testing.T) {
	var nilManager *TokenManager
	if nilManager.Configured() {
		t.Fatal("nil TokenManager reported configured")
	}
	if new(TokenManager).Configured() {
		t.Fatal("zero TokenManager reported configured")
	}
	manager, err := NewTokenManager(strings.Repeat("t", 32), time.Hour)
	if err != nil {
		t.Fatalf("NewTokenManager() error = %v", err)
	}
	if !manager.Configured() {
		t.Fatal("NewTokenManager() result reported unconfigured")
	}
}
