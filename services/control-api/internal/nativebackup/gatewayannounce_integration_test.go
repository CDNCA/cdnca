package nativebackup

import (
	"context"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestAnnounceGatewayPublishesTheNewHostFirst runs the entry point update with
// the real psql against the migration 448 table shape (TEST_DATABASE_URL,
// PG_TOOLS_DIR as for TestPostgresComponentRoundTrip).
func TestAnnounceGatewayPublishesTheNewHostFirst(t *testing.T) {
	raw := os.Getenv("TEST_DATABASE_URL")
	tools := os.Getenv("PG_TOOLS_DIR")
	if raw == "" || tools == "" {
		t.Skip("TEST_DATABASE_URL and PG_TOOLS_DIR are required")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	env := []string{"PGHOST=" + parsed.Hostname(), "PGPORT=" + parsed.Port(), "PGUSER=" + parsed.User.Username()}
	target := DatabaseTarget{Name: "migrateip", ToolsDir: tools, Env: env}
	sql := func(database, statement string) string {
		t.Helper()
		command := exec.Command(target.tool("psql"), "-X", "-A", "-t", "-q", "-v", "ON_ERROR_STOP=1", "--dbname", database, "--command", statement)
		command.Env = append(os.Environ(), env...)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v %s", statement, err, output)
		}
		return strings.TrimSpace(string(output))
	}
	sql("postgres", "DROP DATABASE IF EXISTS migrateip WITH (FORCE)")
	sql("postgres", "CREATE DATABASE migrateip TEMPLATE template0")
	t.Cleanup(func() { sql("postgres", "DROP DATABASE IF EXISTS migrateip WITH (FORCE)") })
	migration, err := os.ReadFile(filepath.Join("..", "..", "migrations", "448_agent_gateway_settings.up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	// Only the entry point table of 448 is needed, plus node presence.
	start := strings.Index(string(migration), "CREATE TABLE agent_gateway_entrypoints")
	end := strings.Index(string(migration)[start:], ");") + start + 2
	sql("migrateip", string(migration)[start:end])
	sql("migrateip", "CREATE TABLE node_presence (node_id uuid PRIMARY KEY, status text NOT NULL, last_seen_at timestamptz)")
	sql("migrateip", "INSERT INTO agent_gateway_entrypoints(position,address,server_name,transport,tunnel_host) VALUES "+
		"(1,'cdn.example.com:443','gw.example.com','ws','cdn.example.com'),(2,'10.0.0.9:19444','10.0.0.9','grpc','')")

	layout := Layout{Root: t.TempDir()}
	if err := os.MkdirAll(layout.Path(ConfigDirectory), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(layout.Path(gatewayEnvFile), []byte(gatewayHostEnv), 0o600); err != nil {
		t.Fatal(err)
	}
	systemd := newFakeSystemd(t)
	host := &Host{Layout: layout, Exec: OSExecutor{}, Systemd: systemd, Database: target}
	result, err := AnnounceGateway(context.Background(), host, AnnounceRequest{Host: "198.51.100.7"}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Added || result.Address != "198.51.100.7:19444" {
		t.Fatalf("result %+v", result)
	}
	rows := sql("migrateip", "SELECT string_agg(position||'='||address||'/'||server_name||'/'||transport, ',' ORDER BY position) FROM agent_gateway_entrypoints")
	if rows != "1=198.51.100.7:19444/198.51.100.7/grpc,2=cdn.example.com:443/gw.example.com/ws,3=10.0.0.9:19444/10.0.0.9/grpc" {
		t.Fatalf("entry points %s", rows)
	}
	if !slices.Contains(systemd.calls, "stop cdnca-agent-gateway.service") || !slices.Contains(systemd.calls, "start cdnca-agent-gateway.service") {
		t.Fatalf("gateway not restarted: %v", systemd.calls)
	}
	// Again: nothing is added.
	again, err := AnnounceGateway(context.Background(), host, AnnounceRequest{Host: "198.51.100.7"}, time.Now)
	if err != nil || again.Added {
		t.Fatalf("second run %+v %v", again, err)
	}
	if count := sql("migrateip", "SELECT count(*) FROM agent_gateway_entrypoints"); count != "3" {
		t.Fatalf("count %s", count)
	}
}
