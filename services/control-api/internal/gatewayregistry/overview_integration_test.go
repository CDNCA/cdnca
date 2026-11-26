//go:build integration

package gatewayregistry

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// seedConnectedNode adds a node whose current session came through
// instance (a standalone gateway_id or the co-located Gateway's instance ID).
func seedConnectedNode(t *testing.T, pool *pgxpool.Pool, actor Actor, instance, status string, lastSeen time.Time) {
	t.Helper()
	id := uuid.New()
	digest := make([]byte, 32)
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id)
			VALUES($1,$2,$3,'active',$4,(SELECT COALESCE(max(display_id),0)+1 FROM nodes))`, id, actor.ScopeID, "gw-"+id.String()[:8], actor.UserID); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO node_presence(
			node_id,status,session_epoch,heartbeat_sequence,event_id,request_id,payload_digest,occurred_at,projected_at,
			last_seen_at,confirmed_session_epoch,confirmed_heartbeat_sequence,confirmed_event_id,confirmed_request_id,
			confirmed_payload_digest,online_since,offline_since,openresty_state,firewall_state,
			filesystem_total_bytes,filesystem_available_bytes,cache_used_bytes,updated_at)
			VALUES($1,$2,2,1,$3,$4,$5,$6::timestamptz,$6,$6,2,1,$3,$4,$5,
			CASE WHEN $2::text='online' THEN $6::timestamptz END,CASE WHEN $2::text='offline' THEN $6::timestamptz END,'running','running',100,50,0,$6)`,
			id, status, uuid.New(), uuid.New(), digest, lastSeen); err != nil {
			return err
		}
		// An older session through another Gateway: only the current one counts.
		for epoch, via := range map[int]string{1: "11111111-1111-4111-8111-111111111111", 2: instance} {
			if _, err := tx.Exec(t.Context(), `INSERT INTO node_session_capabilities(node_id,session_epoch,certificate_id,
				certificate_sha256,artifact_key_id,selected_protocol_major,selected_protocol_minor,capabilities_snapshot,
				capabilities_sha256,facts_snapshot,facts_sha256,gateway_workload_identity,gateway_instance_id,registered_at)
				VALUES($1,$2,$3,$4,'x25519:test',1,0,'\x01',$4,'\x01',$4,'gw',$5,$6)`, id, epoch, uuid.New(), digest, via, lastSeen); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed node: %v", err)
	}
}

// connected nodes are counted by
// the Gateway of their current session; the co-located Gateway gets the rest.
func TestOverviewCountsConnectedNodesByGateway(t *testing.T) {
	pool := integrationPool(t)
	now := time.Date(2026, 11, 24, 8, 0, 0, 0, time.UTC)
	service, err := New(Config{Pool: pool, Signer: Signer{Client: testCA(t, "client CA"), Server: testCA(t, "root CA")}, RootCAPEM: "root", NodeCAPEM: "node",
		InstallationID: "00000000-0000-4000-8000-0000000000aa",
		Endpoints: RemoteEndpoints{ControlInternalAddress: "control.example.com:9446", ControlInternalServerName: "control.example.com",
			RedisURL: "rediss://gw@control.example.com:6380/0", NATSURL: "tls://control.example.com:4222", TelemetryNATSURL: "tls://control.example.com:4222"},
		LocalGateway: Entrypoint{Address: "control.example.com:9444", ServerName: "control.example.com", Transport: TransportGRPC,
			EnrollmentAddress: "control.example.com:9443"},
		Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	actor := seedAdmin(t, pool, now)
	created, err := service.Create(ctx, actor, CreateInput{Name: "gw-a", Host: "gw-a.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	_, clientKey, _ := ed25519.GenerateKey(rand.Reader)
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := service.Bind(ctx, BindRequest{Token: created.BindingToken, ClientCSR: csr(t, clientKey), ServerCSR: csr(t, serverKey),
		EnrollmentPort: 21443, AgentPort: 21444, Version: "1.0.35"}, "198.51.100.1"); err != nil {
		t.Fatal(err)
	}
	standalone := created.Gateway.ID.String()
	local := "6cfad302-0e27-44c0-b37f-3b4f5ad4c08b"
	seedConnectedNode(t, pool, actor, standalone, "online", now.Add(-10*time.Second))
	seedConnectedNode(t, pool, actor, standalone, "online", now.Add(-20*time.Second))
	seedConnectedNode(t, pool, actor, local, "online", now.Add(-5*time.Second))
	seedConnectedNode(t, pool, actor, local, "offline", now.Add(-5*time.Second)) // disconnected
	seedConnectedNode(t, pool, actor, local, "online", now.Add(-time.Minute))    // stale

	gateways, localGateway, err := service.Overview(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(gateways) != 1 || gateways[0].NodesOnline != 2 {
		t.Fatalf("standalone = %+v", gateways)
	}
	if localGateway.NodesOnline != 1 || localGateway.Status != "not_reported" || localGateway.Address != "control.example.com:9444" {
		t.Fatalf("local = %+v", localGateway)
	}
	service.ObserveLocalGateway(local, "1.0.35", now.Add(90*24*time.Hour))
	if _, localGateway, err = service.Overview(ctx); err != nil || localGateway.Status != "online" || localGateway.Version != "1.0.35" {
		t.Fatalf("local after a call = %+v %v", localGateway, err)
	}
}
