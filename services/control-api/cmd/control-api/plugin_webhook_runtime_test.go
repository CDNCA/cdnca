package main

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/pluginwebhookcontrol"
)

func TestPluginWebhookRuntimeConfigPreservesNATSTrustAndReconnect(t *testing.T) {
	source := config.PluginWebhookConfig{
		NATSURL: "tls://nats.example.test:4222", NATSName: "cdnca-plugin-webhook-test",
		NATSCredsFile: "/run/secrets/nats/runtime.creds", NATSCAFile: "/run/secrets/nats/ca.crt",
		NATSReconnectMin: 1500 * time.Millisecond, NATSReconnectMax: 2 * time.Second,
	}
	got := pluginWebhookRuntimeConfig(source, nil)
	if got.NATSURL != source.NATSURL || got.NATSName != source.NATSName ||
		got.NATSCredsFile != source.NATSCredsFile || got.NATSCAFile != source.NATSCAFile ||
		got.NATSReconnectMin != source.NATSReconnectMin || got.NATSReconnectMax != source.NATSReconnectMax {
		t.Fatalf("plugin webhook runtime NATS config = %#v", got)
	}
}

func TestPluginWebhookKeyringActiveLookupCancellationAndClear(t *testing.T) {
	raw := make([]byte, 32)
	want := [32]byte{}
	for index := range raw {
		raw[index] = byte(index + 1)
		want[index] = byte(index + 1)
	}
	keyring, err := newPluginWebhookKeyring("plugin-webhook/key-v1", raw)
	if err != nil {
		t.Fatalf("newPluginWebhookKeyring() error = %v", err)
	}
	clear(raw)

	active, err := keyring.Active(t.Context())
	if err != nil || active.ID != "plugin-webhook/key-v1" || active.Key != want {
		t.Fatalf("Active() = (%#v, %v)", active, err)
	}
	lookup, err := keyring.Lookup(t.Context(), active.ID)
	if err != nil || lookup != want {
		t.Fatalf("Lookup() = (%x, %v)", lookup, err)
	}
	if _, err := keyring.Lookup(t.Context(), "other-key"); !errors.Is(err, pluginwebhookcontrol.ErrSecretUnavailable) {
		t.Fatalf("Lookup(other-key) error = %v", err)
	}

	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := keyring.Active(canceled); !errors.Is(err, pluginwebhookcontrol.ErrSecretUnavailable) {
		t.Fatalf("Active(canceled) error = %v", err)
	}
	if _, err := keyring.Lookup(canceled, active.ID); !errors.Is(err, pluginwebhookcontrol.ErrSecretUnavailable) {
		t.Fatalf("Lookup(canceled) error = %v", err)
	}
	var nilContext context.Context
	if _, err := keyring.Active(nilContext); !errors.Is(err, pluginwebhookcontrol.ErrSecretUnavailable) {
		t.Fatalf("Active(nil context) error = %v", err)
	}

	keyring.clear()
	if keyring.id != "" || keyring.key != ([32]byte{}) {
		t.Fatalf("clear() retained key material: id=%q key=%x", keyring.id, keyring.key)
	}
	if _, err := keyring.Active(t.Context()); !errors.Is(err, pluginwebhookcontrol.ErrSecretUnavailable) {
		t.Fatalf("Active(cleared) error = %v", err)
	}
	if _, err := keyring.Lookup(t.Context(), active.ID); !errors.Is(err, pluginwebhookcontrol.ErrSecretUnavailable) {
		t.Fatalf("Lookup(cleared) error = %v", err)
	}
	keyring.clear()
	(*pluginWebhookKeyring)(nil).clear()
}

func TestPluginWebhookKeyringRejectsInvalidAndZeroKeys(t *testing.T) {
	nonzero := make([]byte, 32)
	nonzero[0] = 1
	for _, test := range []struct {
		name string
		id   string
		key  []byte
	}{
		{name: "missing id", key: nonzero},
		{name: "short key", id: "key-v1", key: make([]byte, 31)},
		{name: "zero key", id: "key-v1", key: make([]byte, 32)},
	} {
		t.Run(test.name, func(t *testing.T) {
			keyring, err := newPluginWebhookKeyring(test.id, test.key)
			if keyring != nil || !errors.Is(err, pluginwebhookcontrol.ErrSecretUnavailable) {
				t.Fatalf("newPluginWebhookKeyring() = (%#v, %v)", keyring, err)
			}
		})
	}
}

func TestPluginWebhookRuntimeDegradedDoesNotGateControlReadiness(t *testing.T) {
	parsed, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var runServer *ast.FuncDecl
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Name.Name == "runServer" {
			runServer = function
			break
		}
	}
	if runServer == nil || runServer.Body == nil {
		t.Fatal("runServer AST not found")
	}
	pluginDependencies := make(map[string]bool)
	readinessWrites := 0
	dependsOnPlugin := func(expression ast.Expr) bool {
		depends := false
		ast.Inspect(expression, func(node ast.Node) bool {
			if identifier, ok := node.(*ast.Ident); ok &&
				(identifier.Name == "pluginWebhookRuntime" || pluginDependencies[identifier.Name]) {
				depends = true
				return false
			}
			return true
		})
		return depends
	}
	requireReadinessCalls := 0
	pluginRequired := false
	ast.Inspect(runServer.Body, func(node ast.Node) bool {
		switch statement := node.(type) {
		case *ast.AssignStmt:
			pending := make(map[string]bool)
			for index, target := range statement.Lhs {
				identifier, ok := target.(*ast.Ident)
				if !ok {
					continue
				}
				rhsIndex := index
				if len(statement.Rhs) == 1 {
					rhsIndex = 0
				}
				if rhsIndex < len(statement.Rhs) {
					pending[identifier.Name] = dependsOnPlugin(statement.Rhs[rhsIndex])
					if identifier.Name == "readinessProbes" {
						readinessWrites++
					}
				}
			}
			for name, depends := range pending {
				pluginDependencies[name] = depends
			}
		case *ast.ValueSpec:
			pending := make(map[string]bool)
			for index, identifier := range statement.Names {
				valueIndex := index
				if len(statement.Values) == 1 {
					valueIndex = 0
				}
				if valueIndex < len(statement.Values) {
					pending[identifier.Name] = dependsOnPlugin(statement.Values[valueIndex])
					if identifier.Name == "readinessProbes" {
						readinessWrites++
					}
				}
			}
			for name, depends := range pending {
				pluginDependencies[name] = depends
			}
		case *ast.CallExpr:
			identifier, ok := statement.Fun.(*ast.Ident)
			if !ok || identifier.Name != "requireReadiness" {
				break
			}
			requireReadinessCalls++
			for _, argument := range statement.Args[1:] {
				pluginRequired = pluginRequired || dependsOnPlugin(argument)
			}
		}
		return true
	})
	if readinessWrites == 0 || requireReadinessCalls != 1 {
		t.Fatalf("unrecognized global readiness composition: writes=%d calls=%d", readinessWrites, requireReadinessCalls)
	}

	degradedPluginRuntime := &fakeReadinessProbe{err: errors.New("NATS unavailable")}
	if degradedPluginRuntime.Ready() == nil {
		t.Fatal("test requires a degraded plugin webhook runtime")
	}
	coreRuntime := &fakeReadinessProbe{}
	requiredProbes := []readinessProbe{coreRuntime}
	if pluginRequired {
		requiredProbes = append(requiredProbes, degradedPluginRuntime)
	}
	coreCalled := false
	handler := requireReadiness(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		coreCalled = true
		writer.WriteHeader(http.StatusNoContent)
	}), requiredProbes...)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
	if response.Code != http.StatusNoContent || !coreCalled {
		t.Fatalf("global composition gates core readiness on degraded plugin: plugin_required=%v status=%d called=%v",
			pluginRequired, response.Code, coreCalled)
	}
}
