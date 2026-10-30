package cachecontrolruntime

import (
	"context"
	"math"
	"sync"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/google/uuid"
)

type dispatchBucket struct {
	rate     float64
	burst    float64
	tokens   float64
	updated  time.Time
	lastUsed uint64
}

type dispatchLimiter struct {
	mu          sync.Mutex
	clock       func() time.Time
	sleep       func(context.Context, time.Duration) error
	maximum     int
	tick        uint64
	buckets     map[string]*dispatchBucket
	tenantRate  float64
	tenantBurst int
	siteRate    float64
	siteBurst   int
	nodeRate    float64
	nodeBurst   int
}

func newDispatchLimiter(config Config) (*dispatchLimiter, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	return &dispatchLimiter{
		clock: config.Clock, sleep: config.DispatchSleep, maximum: config.MaxDispatchLimiters,
		buckets:    make(map[string]*dispatchBucket),
		tenantRate: config.TenantDispatchRate, tenantBurst: config.TenantDispatchBurst,
		siteRate: config.SiteDispatchRate, siteBurst: config.SiteDispatchBurst,
		nodeRate: config.NodeDispatchRate, nodeBurst: config.NodeDispatchBurst,
	}, nil
}

func (limiter *dispatchLimiter) Wait(ctx context.Context, claim cachecontrol.Claim) error {
	if ctx == nil || claim.TenantID == uuid.Nil || claim.SiteID == uuid.Nil || claim.NodeID == uuid.Nil {
		return ErrInvalidConfig
	}
	keys := []struct {
		value string
		rate  float64
		burst int
	}{
		{"tenant:" + claim.TenantID.String(), limiter.tenantRate, limiter.tenantBurst},
		{"site:" + claim.TenantID.String() + ":" + claim.SiteID.String(), limiter.siteRate, limiter.siteBurst},
		{"node:" + claim.NodeID.String(), limiter.nodeRate, limiter.nodeBurst},
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		now := limiter.clock().UTC()
		limiter.mu.Lock()
		buckets := make([]*dispatchBucket, 0, len(keys))
		protected := make(map[string]struct{}, len(keys))
		wait := time.Duration(0)
		for _, key := range keys {
			bucket := limiter.bucket(key.value, key.rate, key.burst, now, protected)
			if bucket == nil {
				limiter.mu.Unlock()
				return ErrInvalidConfig
			}
			protected[key.value] = struct{}{}
			limiter.refill(bucket, now)
			buckets = append(buckets, bucket)
			if bucket.tokens < 1 {
				delay := time.Duration(math.Ceil((1 - bucket.tokens) / bucket.rate * float64(time.Second)))
				if delay > wait {
					wait = delay
				}
			}
		}
		if wait <= 0 {
			for _, bucket := range buckets {
				bucket.tokens--
				limiter.tick++
				bucket.lastUsed = limiter.tick
			}
			limiter.mu.Unlock()
			return nil
		}
		limiter.mu.Unlock()
		if err := limiter.sleep(ctx, wait); err != nil {
			return err
		}
	}
}

func (limiter *dispatchLimiter) Len() int {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	return len(limiter.buckets)
}

func (limiter *dispatchLimiter) bucket(
	key string,
	rate float64,
	burst int,
	now time.Time,
	protected map[string]struct{},
) *dispatchBucket {
	if existing := limiter.buckets[key]; existing != nil {
		return existing
	}
	for len(limiter.buckets) >= limiter.maximum {
		var oldestKey string
		var oldestTick uint64
		for candidateKey, candidate := range limiter.buckets {
			if _, keep := protected[candidateKey]; keep {
				continue
			}
			if oldestKey == "" || candidate.lastUsed < oldestTick {
				oldestKey, oldestTick = candidateKey, candidate.lastUsed
			}
		}
		if oldestKey == "" {
			return nil
		}
		delete(limiter.buckets, oldestKey)
	}
	limiter.tick++
	created := &dispatchBucket{
		rate: rate, burst: float64(burst), tokens: float64(burst), updated: now, lastUsed: limiter.tick,
	}
	limiter.buckets[key] = created
	return created
}

func (limiter *dispatchLimiter) refill(bucket *dispatchBucket, now time.Time) {
	if now.After(bucket.updated) {
		bucket.tokens += now.Sub(bucket.updated).Seconds() * bucket.rate
		if bucket.tokens > bucket.burst {
			bucket.tokens = bucket.burst
		}
		bucket.updated = now
	}
}
