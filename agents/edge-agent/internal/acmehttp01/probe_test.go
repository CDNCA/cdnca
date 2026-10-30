package acmehttp01

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPProbeChecksHostPathExactBodyAndCleanup404(t *testing.T) {
	token := token("p")
	expected := value(token)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Host != "a.example.test" || request.URL.Path != ChallengePathPrefix+token {
			http.Error(response, "not found", http.StatusNotFound)
			return
		}
		if request.Header.Get("X-Cleanup") == "1" {
			http.Error(response, "not found", http.StatusNotFound)
			return
		}
		response.Header().Set("Content-Type", "text/plain")
		_, _ = response.Write([]byte(expected))
	}))
	server.Start()
	defer server.Close()
	probe, err := newHTTPProbe(server.Listener.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := probe.Check(context.Background(), "a.example.test", token, &expected); err != nil {
		t.Fatalf("exact probe error = %v", err)
	}
	server.Config.Handler = http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		http.Error(response, "not found", http.StatusNotFound)
	})
	if err := probe.Check(context.Background(), "a.example.test", token, nil); err != nil {
		t.Fatalf("cleanup probe error = %v", err)
	}
	wrong := expected + "x"
	if err := probe.Check(context.Background(), "a.example.test", token, &wrong); err == nil {
		t.Fatal("probe accepted a non-exact response body")
	}
}
