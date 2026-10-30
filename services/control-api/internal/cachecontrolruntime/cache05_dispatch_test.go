package cachecontrolruntime

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/google/uuid"
)

type cache05Clock struct {
	mu     sync.Mutex
	now    time.Time
	sleeps []time.Duration
}

func (clock *cache05Clock) current() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *cache05Clock) sleep(ctx context.Context, delay time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	clock.mu.Lock()
	clock.now = clock.now.Add(delay)
	clock.sleeps = append(clock.sleeps, delay)
	clock.mu.Unlock()
	return nil
}

func TestCACHE05DispatchLimiterAppliesTenantSiteAndNodeBuckets(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	tenantID, siteID, nodeID := uuid.New(), uuid.New(), uuid.New()
	cases := []struct {
		name      string
		configure func(*Config)
		first     cachecontrol.Claim
		second    cachecontrol.Claim
	}{
		{
			name: "tenant",
			configure: func(config *Config) {
				config.TenantDispatchRate, config.TenantDispatchBurst = 1, 1
			},
			first:  cache05Claim(tenantID, siteID, nodeID),
			second: cache05Claim(tenantID, uuid.New(), uuid.New()),
		},
		{
			name: "site",
			configure: func(config *Config) {
				config.SiteDispatchRate, config.SiteDispatchBurst = 1, 1
			},
			first:  cache05Claim(tenantID, siteID, nodeID),
			second: cache05Claim(tenantID, siteID, uuid.New()),
		},
		{
			name: "node",
			configure: func(config *Config) {
				config.NodeDispatchRate, config.NodeDispatchBurst = 1, 1
			},
			first:  cache05Claim(tenantID, siteID, nodeID),
			second: cache05Claim(tenantID, siteID, nodeID),
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			clock := &cache05Clock{now: base}
			config := DefaultConfig()
			config.Clock, config.DispatchSleep = clock.current, clock.sleep
			config.TenantDispatchRate, config.TenantDispatchBurst = 1000, 1000
			config.SiteDispatchRate, config.SiteDispatchBurst = 1000, 1000
			config.NodeDispatchRate, config.NodeDispatchBurst = 1000, 1000
			test.configure(&config)
			limiter, err := newDispatchLimiter(config)
			if err != nil {
				t.Fatalf("new limiter: %v", err)
			}
			if err := limiter.Wait(context.Background(), test.first); err != nil {
				t.Fatalf("first admission: %v", err)
			}
			if err := limiter.Wait(context.Background(), test.second); err != nil {
				t.Fatalf("second admission: %v", err)
			}
			if len(clock.sleeps) != 1 || clock.sleeps[0] != time.Second {
				t.Fatalf("%s waits = %v, want [1s]", test.name, clock.sleeps)
			}
		})
	}
}

func TestCACHE05DispatchLimiterBoundsIdentityRetention(t *testing.T) {
	t.Parallel()
	clock := &cache05Clock{now: time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)}
	config := DefaultConfig()
	config.Clock, config.DispatchSleep = clock.current, clock.sleep
	config.MaxDispatchLimiters = 3
	limiter, err := newDispatchLimiter(config)
	if err != nil {
		t.Fatalf("new limiter: %v", err)
	}
	for index := 0; index < 20; index++ {
		if err := limiter.Wait(context.Background(), cache05Claim(uuid.New(), uuid.New(), uuid.New())); err != nil {
			t.Fatalf("admission %d: %v", index, err)
		}
	}
	if got := limiter.Len(); got > config.MaxDispatchLimiters {
		t.Fatalf("retained limiters = %d, want <= %d", got, config.MaxDispatchLimiters)
	}
}

func TestCACHE05DispatchLimiterPreservesTenantBudgetAcrossIdentityEviction(t *testing.T) {
	t.Parallel()
	clock := &cache05Clock{now: time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)}
	config := DefaultConfig()
	config.Clock, config.DispatchSleep = clock.current, clock.sleep
	config.MaxDispatchLimiters = 3
	config.TenantDispatchRate, config.TenantDispatchBurst = 1, 2
	config.SiteDispatchRate, config.SiteDispatchBurst = 1000, 1000
	config.NodeDispatchRate, config.NodeDispatchBurst = 1000, 1000
	limiter, err := newDispatchLimiter(config)
	if err != nil {
		t.Fatalf("new limiter: %v", err)
	}
	tenantID := uuid.New()
	for index := 0; index < 3; index++ {
		claim := cache05Claim(tenantID, uuid.New(), uuid.New())
		if err := limiter.Wait(context.Background(), claim); err != nil {
			t.Fatalf("admission %d: %v", index, err)
		}
	}
	if len(clock.sleeps) != 1 || clock.sleeps[0] != time.Second {
		t.Fatalf("tenant waits = %v, want [1s]", clock.sleeps)
	}
	if got := limiter.Len(); got != config.MaxDispatchLimiters {
		t.Fatalf("retained limiters = %d, want %d", got, config.MaxDispatchLimiters)
	}
}

func cache05Claim(tenantID, siteID, nodeID uuid.UUID) cachecontrol.Claim {
	return cachecontrol.Claim{TenantID: tenantID, SiteID: siteID, NodeID: nodeID}
}
