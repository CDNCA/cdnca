package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

func acmeHTTP01EdgePublishEnvironment() []string {
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	return []string{
		"EDGE_PUBLISH_RUNTIME_ENABLED=true",
		"EDGE_PUBLISH_CURSOR_ACTIVE_KEY_ID=active",
		`EDGE_PUBLISH_CURSOR_KEYS_JSON={"active":"` + key + `"}`,
	}
}

// FX05①: HTTP-01 stays refused (nil runtime, the fail-closed provider) unless
// the ACME runtime and edge publication are both enabled; enabled, a broken
// signer or NATS fails startup instead of silently refusing.
func TestOpenACMEHTTP01NodeRuntimeGates(t *testing.T) {
	connect := func(string, ...nats.Option) (*nats.Conn, error) { return nil, errors.New("nats unavailable") }
	runtime, err := openACMEHTTP01NodeRuntime(t.Context(), config.Config{}, nil, acmeHTTP01EdgePublishEnvironment(), connect)
	if runtime != nil || err != nil {
		t.Fatalf("ACME disabled: %v %v", runtime, err)
	}
	cfg := config.Config{ACMERuntimeEnabled: true}
	runtime, err = openACMEHTTP01NodeRuntime(t.Context(), cfg, nil, nil, connect)
	if runtime != nil || err != nil {
		t.Fatalf("edge publication unconfigured: %v %v", runtime, err)
	}
	runtime, err = openACMEHTTP01NodeRuntime(t.Context(), cfg, nil, []string{"EDGE_PUBLISH_RUNTIME_ENABLED=false"}, connect)
	if runtime != nil || err != nil {
		t.Fatalf("edge publication disabled: %v %v", runtime, err)
	}
	t.Setenv("EDGE_PUBLISH_SIGNING_KEY_ID", "")
	_, err = openACMEHTTP01NodeRuntime(t.Context(), cfg, new(pgxpool.Pool), acmeHTTP01EdgePublishEnvironment(), connect)
	if err == nil || err.Error() != "load ACME HTTP-01 overlay signer" {
		t.Fatalf("missing signer: %v", err)
	}
}
