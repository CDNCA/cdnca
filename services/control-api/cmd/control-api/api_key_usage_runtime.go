package main

import (
	"context"
	"sync"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikeyusage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type apiKeyUsageWorker interface {
	TryRecord(uuid.UUID, time.Time) bool
	Close(context.Context) error
}

type apiKeyUsageRuntime struct {
	worker          apiKeyUsageWorker
	shutdownTimeout time.Duration
	closeOnce       sync.Once
	closeErr        error
}

func newAPIKeyUsageRuntime(pool *pgxpool.Pool) (*apiKeyUsageRuntime, error) {
	config := apikeyusage.DefaultConfig()
	worker, err := apikeyusage.NewRuntime(pool, config)
	if err != nil {
		return nil, err
	}
	return &apiKeyUsageRuntime{worker: worker, shutdownTimeout: config.ShutdownTimeout}, nil
}

func (runtime *apiKeyUsageRuntime) TryRecord(keyID uuid.UUID, observedAt time.Time) bool {
	return runtime != nil && runtime.worker != nil && runtime.worker.TryRecord(keyID, observedAt)
}

func (runtime *apiKeyUsageRuntime) Close() error {
	if runtime == nil || runtime.worker == nil {
		return nil
	}
	runtime.closeOnce.Do(func() {
		timeout := runtime.shutdownTimeout
		if timeout <= 0 {
			timeout = apikeyusage.DefaultConfig().ShutdownTimeout
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		runtime.closeErr = runtime.worker.Close(ctx)
	})
	return runtime.closeErr
}
