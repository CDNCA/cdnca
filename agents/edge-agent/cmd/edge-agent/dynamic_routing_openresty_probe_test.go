package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewayclient"
)

// The heartbeat probe checks the
// dynamic routing OpenResty (master and its 204 /healthz), not a version.
func TestDynamicRoutingOpenRestyProbe(t *testing.T) {
	status := http.StatusNoContent
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/healthz" {
			http.NotFound(writer, request)
			return
		}
		writer.WriteHeader(status)
	}))
	defer server.Close()
	running := true
	probe := dynamicRoutingOpenRestyProbe(func() bool { return running }, server.URL+"/healthz", time.Second)

	if err := probe(context.Background(), "any-scope-version"); err != nil {
		t.Fatalf("serving OpenResty: %v", err)
	}
	status = http.StatusServiceUnavailable
	if err := probe(context.Background(), "v"); err == nil || errors.Is(err, gatewayclient.ErrOpenRestyStopped) {
		t.Fatalf("running but unhealthy OpenResty = %v, want a degraded error", err)
	}
	running = false
	if err := probe(context.Background(), "v"); !errors.Is(err, gatewayclient.ErrOpenRestyStopped) {
		t.Fatalf("stopped OpenResty = %v, want ErrOpenRestyStopped", err)
	}
	running = true
	server.Close()
	if err := probe(context.Background(), "v"); err == nil || errors.Is(err, gatewayclient.ErrOpenRestyStopped) {
		t.Fatalf("unanswered health = %v, want a degraded error", err)
	}
}
