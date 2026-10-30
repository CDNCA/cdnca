package gateway

import (
	"context"
	"testing"
	"time"
)

func TestSessionCoordinatorModeMustBeExplicit(t *testing.T) {
	if _, err := NewSessionCoordinator(context.Background(), SessionCoordinatorConfig{}); err == nil {
		t.Fatal("empty session coordinator mode was accepted")
	}
	coordinator, err := NewSessionCoordinator(context.Background(), SessionCoordinatorConfig{Mode: SessionCoordinatorModeStandalone})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := coordinator.(*MemorySessionCoordinator); !ok {
		t.Fatalf("standalone coordinator = %T, want memory coordinator", coordinator)
	}
	if _, err := NewSessionCoordinator(context.Background(), SessionCoordinatorConfig{Mode: SessionCoordinatorModeDistributed}); err == nil {
		t.Fatal("distributed mode without Redis was accepted")
	}
}

func TestRedisSessionCoordinatorConfigRejectsUnsafeLeaseTiming(t *testing.T) {
	valid := RedisSessionCoordinatorConfig{
		GatewayInstanceID:    "gateway-test",
		KeyPrefix:            "cdnca:test",
		LeaseTTL:             300 * time.Millisecond,
		RenewInterval:        75 * time.Millisecond,
		OperationTimeout:     50 * time.Millisecond,
		AcquireTimeout:       time.Second,
		AcquireRetryInterval: 10 * time.Millisecond,
	}
	if err := valid.validate(); err != nil {
		t.Fatalf("valid Redis session config: %v", err)
	}

	tests := []struct {
		name   string
		change func(*RedisSessionCoordinatorConfig)
	}{
		{name: "missing gateway", change: func(c *RedisSessionCoordinatorConfig) { c.GatewayInstanceID = "" }},
		{name: "unsafe prefix", change: func(c *RedisSessionCoordinatorConfig) { c.KeyPrefix = "cdnca:{shared}" }},
		{name: "short lease", change: func(c *RedisSessionCoordinatorConfig) { c.LeaseTTL = 2 * c.RenewInterval }},
		{name: "duration overflow", change: func(c *RedisSessionCoordinatorConfig) { c.RenewInterval = time.Duration(1<<63 - 1) }},
		{name: "slow operation", change: func(c *RedisSessionCoordinatorConfig) { c.OperationTimeout = 2 * c.RenewInterval }},
		{name: "slow acquire retry", change: func(c *RedisSessionCoordinatorConfig) { c.AcquireRetryInterval = c.AcquireTimeout }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.change(&config)
			if err := config.validate(); err == nil {
				t.Fatal("invalid Redis session config was accepted")
			}
		})
	}
}

func TestSessionTokensAreRandomAndOpaque(t *testing.T) {
	const count = 128
	tokens := make(map[string]struct{}, count)
	for range count {
		token, err := newSessionToken()
		if err != nil {
			t.Fatal(err)
		}
		if len(token) != 43 {
			t.Fatalf("token length = %d, want 43", len(token))
		}
		if _, exists := tokens[token]; exists {
			t.Fatal("generated a duplicate session token")
		}
		tokens[token] = struct{}{}
	}
}
