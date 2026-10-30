package main

import (
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticsconnectionshttp"
	"github.com/cdnca/cdnca/services/control-api/internal/config"
)

func TestOpenAnalyticsConnectionsDLQRuntimeDisabledHasZeroDependencies(t *testing.T) {
	t.Setenv("ANALYTICS_CONNECTIONS_RUNTIME_ENABLED", "false")
	factoryCalled := false
	runtime, err := openAnalyticsConnectionsDLQRuntime(config.Config{}, nil, nil, func(
		analyticsconnectionshttp.DeadLetterStore,
		analyticsconnectionshttp.AuthenticateFunc,
		analyticsconnectionshttp.DLQHandlerConfig,
	) (http.Handler, error) {
		factoryCalled = true
		return nil, errors.New("disabled DLQ runtime reached handler factory")
	})
	if err != nil || runtime != nil || factoryCalled {
		t.Fatalf("disabled DLQ runtime = (%v, %v), factory called=%t", runtime, err, factoryCalled)
	}
}

func TestOpenAnalyticsConnectionsDLQRuntimeFailsClosedWithoutDurableNATS(t *testing.T) {
	t.Setenv("ANALYTICS_CONNECTIONS_RUNTIME_ENABLED", "true")
	runtime, err := openAnalyticsConnectionsDLQRuntime(config.Config{}, &analyticsConnectionsProcessRuntime{}, nil, nil)
	if err == nil || runtime != nil {
		t.Fatalf("DLQ runtime without NATS = (%v, %v), want fail closed", runtime, err)
	}
}

func TestRunServerDLQRuntimeCompositionIsBoundedAndClosed(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	rendered := string(source)
	for _, required := range []string{
		"openAnalyticsConnectionsDLQRuntime",
		"AnalyticsConnectionsDLQHandler:",
		"analyticsConnectionsDLQRuntime.Close()",
	} {
		if !strings.Contains(rendered, required) {
			t.Errorf("runServer omitted DLQ composition %q", required)
		}
	}
	if strings.Contains(rendered, "analytics_connections_dlq_payload") {
		t.Fatal("DLQ composition appears to include raw payload")
	}
}

func TestAnalyticsConnectionsDLQRuntimeCloseIsIdempotent(t *testing.T) {
	runtime := &analyticsConnectionsDLQRuntime{}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
}
