package main

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
	"github.com/cdnca/cdnca/services/control-api/internal/analyticsreplicametrics"
)

const analyticsReplicaMetricsPath = "/metrics"

type analyticsReplicaMetricsProductionRuntime struct {
	core        *analyticsreplicametrics.Runtime
	closeSource func()
	closeOnce   sync.Once
}

func newAnalyticsReplicaHealthSource(config analyticslog.RuntimeConfig) (
	analyticsreplicametrics.HealthSource,
	func(),
	error,
) {
	clientTransport := newAnalyticsHTTPClient(config.HTTP.ConnectTimeout, config.HTTP.Handler.QueryTimeout)
	client, err := analyticslog.NewClient(config.HTTP.Client, clientTransport)
	if err != nil {
		clientTransport.CloseIdleConnections()
		return nil, nil, err
	}
	source, err := analyticslog.NewReplicaHealthSource(client, analyticslog.ReplicaHealthConfig{
		QueryTimeout: config.HTTP.Client.QueryTimeout, MaxTables: 128, Now: time.Now,
	})
	if err != nil {
		clientTransport.CloseIdleConnections()
		return nil, nil, err
	}
	return source, clientTransport.CloseIdleConnections, nil
}

func newAnalyticsReplicaMetricsProductionRuntime(source analyticsreplicametrics.HealthSource,
	closeSource func(),
) (*analyticsReplicaMetricsProductionRuntime, error) {
	if source == nil {
		return nil, nil
	}
	core, err := analyticsreplicametrics.New(analyticsreplicametrics.Config{
		PollInterval: 15 * time.Second, ReadTimeout: 5 * time.Second, MaxTables: 128,
		MaxStaleness: time.Minute, Now: time.Now,
	}, source)
	if err != nil {
		if closeSource != nil {
			closeSource()
		}
		return nil, err
	}
	return &analyticsReplicaMetricsProductionRuntime{core: core, closeSource: closeSource}, nil
}

func (runtime *analyticsReplicaMetricsProductionRuntime) Run(ctx context.Context) error {
	if runtime == nil || runtime.core == nil {
		return analyticsreplicametrics.ErrInvalidConfiguration
	}
	return runtime.core.Run(ctx)
}

func (runtime *analyticsReplicaMetricsProductionRuntime) Ready() error {
	if runtime == nil || runtime.core == nil {
		return analyticsreplicametrics.ErrInvalidConfiguration
	}
	return runtime.core.Ready()
}

func (runtime *analyticsReplicaMetricsProductionRuntime) Close() error {
	if runtime == nil {
		return nil
	}
	var err error
	if runtime.core != nil {
		err = runtime.core.Close()
	}
	runtime.closeOnce.Do(func() {
		if runtime.closeSource != nil {
			runtime.closeSource()
		}
	})
	return err
}

func withAnalyticsReplicaMetrics(next http.Handler,
	runtime *analyticsReplicaMetricsProductionRuntime,
) http.Handler {
	if runtime == nil || runtime.core == nil {
		return next
	}
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != analyticsReplicaMetricsPath {
			next.ServeHTTP(response, request)
			return
		}
		if request.Method != http.MethodGet {
			response.Header().Set("Allow", http.MethodGet)
			http.Error(response, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if request.URL.RawQuery != "" {
			http.Error(response, "invalid metrics request", http.StatusBadRequest)
			return
		}
		response.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		response.Header().Set("Cache-Control", "no-store")
		for _, gauge := range runtime.core.Snapshot().PrometheusGauges() {
			if _, err := fmt.Fprintf(response, "%s %d\n", gauge.Name, gauge.Value); err != nil {
				return
			}
		}
	})
}
