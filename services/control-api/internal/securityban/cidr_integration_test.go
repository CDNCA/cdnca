//go:build integration

package securityban_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"
	"time"

	contract "github.com/cdnca/cdnca/libs/edgeconfig/securityban"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/securityban"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
)

func declareCapabilities(t *testing.T, pool *pgxpool.Pool, nodeID uuid.UUID, epoch int64, features ...agentv1.CapabilityName) {
	t.Helper()
	capabilities := &agentv1.AgentCapabilities{AgentVersion: "1.0.35"}
	for _, feature := range features {
		capabilities.Features = append(capabilities.Features, &agentv1.Capability{Name: feature, ApiVersion: 1})
	}
	snapshot, err := proto.Marshal(capabilities)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(snapshot)
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO node_session_capabilities(node_id,session_epoch,certificate_id,
			certificate_sha256,artifact_key_id,selected_protocol_major,selected_protocol_minor,capabilities_snapshot,
			capabilities_sha256,facts_snapshot,facts_sha256,gateway_workload_identity,gateway_instance_id,registered_at)
			VALUES($1,$2,$3,$4,'x25519:test',1,0,$5,$4,'\x01',$4,'gw','gw-1',now())`, nodeID, epoch, uuid.New(), digest[:], snapshot)
		return err
	}); err != nil {
		t.Fatalf("declare capabilities: %v", err)
	}
}

// TestSecurityBanNetworks (fix-cidrban): a manual network ban is stored
// masked, listed and filtered as "<network>/<bits>"; a node without BAN_CIDR
// gets the addresses only, and the network (then its release) once its latest
// session declares BAN_CIDR.
func TestSecurityBanNetworks(t *testing.T) {
	pool := newPool(t)
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Second)
	a := seedTenant(t, pool, "sbn-"+uuid.NewString()[:6])
	node := seedNode(t, pool, a)
	declareCapabilities(t, pool, node, 1, agentv1.CapabilityName_CAPABILITY_NAME_WAF)

	service := securityban.NewService(securityban.NewStore(pool, func() time.Time { return now }))
	actor := securityban.Actor{UserID: a.owner, ScopeID: a.scope, ScopeKind: "tenant"}
	create := func(client, key string) (securityban.Entry, error) {
		return service.Create(ctx, actor, securityban.CreateRequest{SiteID: a.site, ClientIP: client, DurationSecond: 600,
			IdempotencyKey: key, RequestID: key})
	}
	network, err := create("203.0.113.77/24", "n1")
	if err != nil || network.ClientIP != "203.0.113.0/24" {
		t.Fatalf("network ban = %+v, %v", network, err)
	}
	if replay, err := create("203.0.113.77/24", "n1"); err != nil || replay.ID != network.ID {
		t.Fatalf("network replay = %+v, %v", replay, err)
	}
	if _, err := create("203.0.113.0/24", "n2"); err == nil {
		t.Fatal("second ban of the same network accepted")
	}
	if _, err := create("203.0.113.5", "n3"); err != nil {
		t.Fatalf("address inside the banned network: %v", err)
	}
	listed, err := service.List(ctx, actor, securityban.ListFilter{ClientIP: "203.0.113.0/24", Page: 1, Limit: 20})
	if err != nil || listed.Total != 1 || listed.Items[0].ClientIP != "203.0.113.0/24" {
		t.Fatalf("list by network = %+v, %v", listed, err)
	}

	public, private, _ := ed25519.GenerateKey(nil)
	carrier := &transport{}
	distributor, err := securityban.NewDistributor(securityban.DistributorConfig{Pool: pool, Transport: carrier, KeyID: "k",
		Sign:     func(_ context.Context, payload []byte) ([]byte, error) { return ed25519.Sign(private, payload), nil },
		Interval: time.Minute, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	trusted := func(string) (ed25519.PublicKey, bool) { return public, true }
	latest := func(node uuid.UUID) contract.List {
		t.Helper()
		for index := len(carrier.published) - 1; index >= 0; index-- {
			if carrier.published[index].nodeID == node.String() {
				list, err := contract.Open(carrier.published[index].encoded, node.String(), trusted)
				if err != nil {
					t.Fatal(err)
				}
				return list
			}
		}
		t.Fatalf("nothing published to %s", node)
		return contract.List{}
	}
	publish := func() {
		t.Helper()
		if err := distributor.PublishOnce(ctx); err != nil {
			t.Fatal(err)
		}
	}
	publish()
	if list := latest(node); len(list.Bans) != 1 || list.Bans[0].Client != "203.0.113.5" || list.HasNetworks() {
		t.Fatalf("node without BAN_CIDR bans = %+v", list.Bans)
	}
	// The node upgrades: its next session declares BAN_CIDR.
	declareCapabilities(t, pool, node, 2, agentv1.CapabilityName_CAPABILITY_NAME_WAF, agentv1.CapabilityName_CAPABILITY_NAME_BAN_CIDR)
	publish()
	if list := latest(node); len(list.Bans) != 2 || list.Bans[0].Client != "203.0.113.0/24" || list.Bans[1].Client != "203.0.113.5" {
		t.Fatalf("BAN_CIDR node bans = %+v", list.Bans)
	}
	if _, err := service.Release(ctx, actor, securityban.ReleaseRequest{EntryID: network.ID, RequestID: "n4"}); err != nil {
		t.Fatal(err)
	}
	publish()
	if list := latest(node); len(list.Bans) != 1 || len(list.Releases) != 1 || list.Releases[0].Client != "203.0.113.0/24" {
		t.Fatalf("BAN_CIDR node after release = %+v", list)
	}
}
