//go:build integration

package gatewayregistry

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func integrationPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if strings.TrimSpace(os.Getenv("TEST_DATABASE_URL")) == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	if pool := databasetest.ClonedMigratedPool(t, nil); pool != nil {
		return pool
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	admin, err := pgxpool.New(ctx, os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	schema := "gateway_registry_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := databasetest.CleanupContext()
		defer cleanupCancel()
		_, _ = admin.Exec(cleanupCtx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		admin.Close()
	})
	config, err := pgxpool.ParseConfig(os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return pool
}

func seedAdmin(t *testing.T, pool *pgxpool.Pool, now time.Time) Actor {
	t.Helper()
	ctx := t.Context()
	var scope uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL`).Scan(&scope); errors.Is(err, pgx.ErrNoRows) {
		scope = uuid.New()
		if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind,created_at) VALUES($1,'platform',$2)`, scope, now); err != nil {
			t.Fatal(err)
		}
	} else if err != nil {
		t.Fatal(err)
	}
	user := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,username,display_name,password_hash,status,created_at,updated_at)
  VALUES($1,$2,$2,'not-used','active',$3,$3)`, user, "gw-"+strings.ReplaceAll(user.String(), "-", "")[:20], now); err != nil {
		t.Fatal(err)
	}
	return Actor{UserID: user, ScopeID: scope, IP: "203.0.113.5"}
}

func TestGatewayBindingLifecycle(t *testing.T) {
	pool := integrationPool(t)
	now := time.Date(2026, 10, 22, 8, 0, 0, 0, time.UTC)
	signer := Signer{Client: testCA(t, "client CA"), Server: testCA(t, "root CA")}
	service, err := New(Config{Pool: pool, Signer: signer, RootCAPEM: "root", NodeCAPEM: "node",
		InstallationID: "00000000-0000-4000-8000-0000000000aa",
		Endpoints: RemoteEndpoints{ControlInternalAddress: "control.example.com:9446", ControlInternalServerName: "control.example.com",
			RedisURL: "rediss://gw@control.example.com:6380/0", NATSURL: "tls://control.example.com:4222", TelemetryNATSURL: "tls://control.example.com:4222"},
		Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	actor := seedAdmin(t, pool, now)
	created, err := service.Create(ctx, actor, CreateInput{Name: "gw-2", Host: "gw2.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Create(ctx, actor, CreateInput{Name: "GW-2", Host: "gw3.example.com"}); !errors.Is(err, ErrNameTaken) {
		t.Fatalf("duplicate name: %v", err)
	}
	var stored []byte
	if err := pool.QueryRow(ctx, `SELECT secret_sha256 FROM agent_gateway_binding_tokens WHERE gateway_id=$1`, created.Gateway.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stored), strings.Split(created.BindingToken, ".")[3]) || len(stored) != 32 {
		t.Fatal("token secret stored in clear")
	}

	_, clientKey, _ := ed25519.GenerateKey(rand.Reader)
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	request := BindRequest{Token: created.BindingToken, ClientCSR: csr(t, clientKey), ServerCSR: csr(t, serverKey),
		EnrollmentPort: 21443, AgentPort: 21444, Version: "1.0.35"}

	// Expired: refused, token kept unused.
	later := now
	now = now.Add(TokenTTL)
	if _, err := service.Bind(ctx, request, "198.51.100.1"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expired token: %v", err)
	}
	now = later
	result, err := service.Bind(ctx, request, "198.51.100.1")
	if err != nil {
		t.Fatal(err)
	}
	if result.WorkloadURISAN != WorkloadURIPrefix+created.Gateway.ID.String() || result.InstallationID != service.InstallationID() ||
		result.Endpoints.ControlInternalAddress == "" {
		t.Fatalf("bind result = %+v", result)
	}
	if _, err := service.Bind(ctx, request, "198.51.100.1"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("token reuse: %v", err)
	}

	block, _ := pem.Decode([]byte(result.ClientCertificatePEM))
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	serial, digest := leaf.SerialNumber.Text(16), sha256.Sum256(leaf.Raw)
	if disabled, err := service.AuthorizeGateway(ctx, created.Gateway.ID, serial, digest); err != nil || disabled {
		t.Fatalf("bound gateway refused: %v %v", disabled, err)
	}
	if _, err := service.AuthorizeGateway(ctx, uuid.New(), serial, digest); !errors.Is(err, ErrGatewayUnauthorized) {
		t.Fatalf("certificate under another gateway ID: %v", err)
	}
	if err := service.MarkReady(ctx, created.Gateway.ID, "1.0.35"); err != nil {
		t.Fatal(err)
	}
	if ips, err := service.AllowedSourceIPs(ctx); err != nil || len(ips) != 1 || ips[0].String() != "198.51.100.1" {
		t.Fatalf("allowed source IPs = %v, %v", ips, err)
	}

	// Settings (migration 448): Cloudflare preset, page edits, publication.
	settings, err := service.Settings(ctx)
	if err != nil || len(settings.TrustedProxies) != 22 || settings.TrustedProxies[0] != (TrustedProxy{CIDR: "173.245.48.0/20", Header: "CF-Connecting-IP"}) {
		t.Fatalf("preset settings = %+v, %v", settings, err)
	}
	edit := Settings{TrustedProxies: []TrustedProxy{{CIDR: "10.0.0.0/8", Header: "X-Real-IP"}},
		Entrypoints: []Entrypoint{{Address: "cdn.example.com:443", ServerName: "gw2.example.com", Transport: "ws", TunnelHost: "cdn.example.com"}}}
	loaded := SettingsETag(settings)
	saved, err := service.UpdateSettings(ctx, actor, loaded, edit)
	if err != nil {
		t.Fatal(err)
	}
	// G1: a form loaded before that save is refused and changes nothing.
	if _, err := service.UpdateSettings(ctx, actor, loaded, Settings{}); !errors.Is(err, ErrSettingsChanged) {
		t.Fatalf("stale If-Match = %v", err)
	}
	if again, err := service.Settings(ctx); err != nil || SettingsETag(again) != SettingsETag(saved) || len(again.TrustedProxies) != 1 {
		t.Fatalf("after stale save = %+v, %v", again, err)
	}
	published, err := service.Publish(ctx)
	if err != nil || len(published.TrustedProxies) != 1 || published.TrustedProxies[0].Header != "X-Real-Ip" || len(published.Endpoints) != 2 ||
		published.Endpoints[0] != (Entrypoint{Address: "gw2.example.com:21444", ServerName: "gw2.example.com", Transport: "grpc",
			EnrollmentAddress: "gw2.example.com:21443"}) ||
		published.Endpoints[1].Transport != "ws" || published.EndpointsVersion == "" {
		t.Fatalf("published = %+v, %v", published, err)
	}
	if _, err := service.SetAllowedIPs(ctx, actor, created.Gateway.ID, []string{"198.51.100.1", "2001:db8::7"}); err != nil {
		t.Fatal(err)
	}
	if ips, err := service.AllowedSourceIPs(ctx); err != nil || len(ips) != 2 {
		t.Fatalf("edited allowed IPs = %v, %v", ips, err)
	}
	if list, err := service.List(ctx); err != nil || len(list) != 1 || len(list[0].AllowedIPs) != 2 || list[0].SourceIP == nil || *list[0].SourceIP != "198.51.100.1" {
		t.Fatalf("list allowed IPs = %+v, %v", list, err)
	}
	var audits int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action IN ('system.gateway.settings','system.gateway.allowed_ips')`).Scan(&audits); err != nil || audits != 2 {
		t.Fatalf("settings audits = %d, %v", audits, err)
	}
	if _, err := service.SetAllowedIPs(ctx, actor, created.Gateway.ID, []string{"10.0.0.0/8"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("range accepted as allowed IP: %v", err)
	}

	// Renewal: same key only.
	if _, err := service.Renew(ctx, created.Gateway.ID, KindClient, csr(t, clientKey)); err != nil {
		t.Fatalf("renew same key: %v", err)
	}
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := service.Renew(ctx, created.Gateway.ID, KindClient, csr(t, otherKey)); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("renew with another key: %v", err)
	}

	if err := service.SetDisabled(ctx, actor, created.Gateway.ID, true); err != nil {
		t.Fatal(err)
	}
	// Disabled: served (marked disabled) for its connected nodes during the
	// grace period, off the endpoint list, refused afterwards (ADR 0013 §5.2).
	if disabled, err := service.AuthorizeGateway(ctx, created.Gateway.ID, serial, digest); err != nil || !disabled {
		t.Fatalf("disabled gateway within grace = %v, %v", disabled, err)
	}
	if ips, err := service.AllowedSourceIPs(ctx); err != nil || len(ips) != 2 {
		t.Fatalf("disabled gateway dropped from the allow list within grace: %v, %v", ips, err)
	}
	if published, err := service.Publish(ctx); err != nil || len(published.Endpoints) != 1 || published.Endpoints[0].Transport != "ws" {
		t.Fatalf("disabled gateway still published: %+v, %v", published, err)
	}
	now = now.Add(DisabledGrace)
	if _, err := service.AuthorizeGateway(ctx, created.Gateway.ID, serial, digest); !errors.Is(err, ErrGatewayUnauthorized) {
		t.Fatalf("disabled gateway accepted after grace: %v", err)
	}
	if ips, err := service.AllowedSourceIPs(ctx); err != nil || len(ips) != 0 {
		t.Fatalf("disabled gateway still allowed after grace: %v, %v", ips, err)
	}
	if err := service.SetDisabled(ctx, actor, created.Gateway.ID, false); err != nil {
		t.Fatal(err)
	}
	if disabled, err := service.AuthorizeGateway(ctx, created.Gateway.ID, serial, digest); err != nil || disabled {
		t.Fatalf("re-enabled gateway refused: %v %v", disabled, err)
	}
	var disabledAt *time.Time
	if err := pool.QueryRow(ctx, `SELECT disabled_at FROM agent_gateways WHERE id=$1`, created.Gateway.ID).Scan(&disabledAt); err != nil || disabledAt != nil {
		t.Fatalf("disabled_at after enable = %v, %v", disabledAt, err)
	}
	if err := service.Delete(ctx, actor, created.Gateway.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.AuthorizeGateway(ctx, created.Gateway.ID, serial, digest); !errors.Is(err, ErrGatewayUnauthorized) {
		t.Fatalf("deleted gateway accepted: %v", err)
	}
	var unrevoked int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_gateway_certificates WHERE gateway_id=$1 AND revoked_at IS NULL`, created.Gateway.ID).Scan(&unrevoked); err != nil || unrevoked != 0 {
		t.Fatalf("unrevoked after delete = %d, %v", unrevoked, err)
	}
	list, err := service.List(ctx)
	if err != nil || len(list) != 0 {
		t.Fatalf("list after delete = %v, %v", list, err)
	}
	// The name is free again once deleted.
	if _, err := service.Create(ctx, actor, CreateInput{Name: "gw-2", Host: "gw2.example.com"}); err != nil {
		t.Fatalf("reuse deleted name: %v", err)
	}
}

// K1: two online standalone Gateways, the co-located Gateway and one extra
// entry point; disabling both standalone Gateways leaves the local one first,
// so their nodes migrate back to it without a hand-added entry point.
func TestPublishPutsTheLocalGatewayAfterStandaloneGateways(t *testing.T) {
	pool := integrationPool(t)
	now := time.Date(2026, 10, 22, 8, 0, 0, 0, time.UTC)
	local := Entrypoint{Address: "control.example.com:9444", ServerName: "control.example.com", Transport: TransportGRPC,
		EnrollmentAddress: "control.example.com:9443"}
	service, err := New(Config{Pool: pool, Signer: Signer{Client: testCA(t, "client CA"), Server: testCA(t, "root CA")}, RootCAPEM: "root", NodeCAPEM: "node",
		InstallationID: "00000000-0000-4000-8000-0000000000aa",
		Endpoints: RemoteEndpoints{ControlInternalAddress: "control.example.com:9446", ControlInternalServerName: "control.example.com",
			RedisURL: "rediss://gw@control.example.com:6380/0", NATSURL: "tls://control.example.com:4222", TelemetryNATSURL: "tls://control.example.com:4222"},
		LocalGateway: local, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	actor := seedAdmin(t, pool, now)
	var ids []uuid.UUID
	for i, host := range []string{"gw-a.example.com", "gw-b.example.com"} {
		created, err := service.Create(ctx, actor, CreateInput{Name: host, Host: host})
		if err != nil {
			t.Fatal(err)
		}
		_, clientKey, _ := ed25519.GenerateKey(rand.Reader)
		serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		now = now.Add(time.Second) // bound_at orders the standalone Gateways
		if _, err := service.Bind(ctx, BindRequest{Token: created.BindingToken, ClientCSR: csr(t, clientKey), ServerCSR: csr(t, serverKey),
			EnrollmentPort: 21443, AgentPort: 21444, Version: "1.0.35"}, "198.51.100."+string(rune('1'+i))); err != nil {
			t.Fatal(err)
		}
		if err := service.MarkReady(ctx, created.Gateway.ID, "1.0.35"); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, created.Gateway.ID)
	}
	extra := Entrypoint{Address: "cdn.example.com:443", ServerName: "control.example.com", Transport: TransportWS, TunnelHost: "cdn.example.com"}
	// The local Gateway repeated by hand is published once, in its own place.
	current, err := service.Settings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.UpdateSettings(ctx, actor, SettingsETag(current), Settings{Entrypoints: []Entrypoint{{Address: local.Address, ServerName: local.ServerName, Transport: TransportGRPC}, extra}}); err != nil {
		t.Fatal(err)
	}
	addresses := func() []string {
		published, err := service.Publish(ctx)
		if err != nil {
			t.Fatal(err)
		}
		out := []string{}
		for _, e := range published.Endpoints {
			out = append(out, e.Address+"|"+e.EnrollmentAddress)
		}
		return out
	}
	want := []string{"gw-a.example.com:21444|gw-a.example.com:21443", "gw-b.example.com:21444|gw-b.example.com:21443",
		"control.example.com:9444|control.example.com:9443", "cdn.example.com:443|"}
	if got := addresses(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("published = %v, want %v", got, want)
	}
	before, _ := service.Publish(ctx)
	for _, id := range ids {
		if err := service.SetDisabled(ctx, actor, id, true); err != nil {
			t.Fatal(err)
		}
	}
	after, _ := service.Publish(ctx)
	if got := addresses(); strings.Join(got, ",") != strings.Join(want[2:], ",") || after.EndpointsVersion == before.EndpointsVersion {
		t.Fatalf("after disabling the standalone Gateways = %v (version %q→%q)", got, before.EndpointsVersion, after.EndpointsVersion)
	}
}
