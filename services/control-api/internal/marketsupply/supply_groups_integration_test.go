//go:build integration

package marketsupply

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"github.com/cdnca/cdnca/libs/marketproto/nodeaction"
	"github.com/cdnca/cdnca/libs/marketproto/nodeload"
	"io"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	"github.com/cdnca/cdnca/libs/marketproto/grant"
	"github.com/cdnca/cdnca/libs/marketproto/spec"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/marketclient"
	"github.com/cdnca/cdnca/services/control-api/internal/marketprobe"
	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
)

type staticFeatures map[string]bool

func (f staticFeatures) ReadValidFeatures(context.Context, pgx.Tx) (map[string]bool, error) {
	return f, nil
}

// TestSupplyGroupsSingleAndMultiNode (ML-09 acceptance): a seller with only
// marketplace.sell composes a one-node and a three-node supply; both are
// hidden platform line groups the line group API and package resources do
// not list; the market pool inventory reports their nodes; the node plugin
// query returns the intersection of what the lease grants and every node
// has; a group in use by a market product cannot be deleted.
func TestSupplyGroupsSingleAndMultiNode(t *testing.T) {
	pool := marketSupplyPool(t)
	ctx := t.Context()
	platform := platformScope(t, pool)
	seller := seedSeller(t, pool, platform)

	full := capabilitySnapshot(t, map[agentv1.CapabilityName]uint32{
		agentv1.CapabilityName_CAPABILITY_NAME_MARKET_PROBE: 1, agentv1.CapabilityName_CAPABILITY_NAME_AUTO_DEFENSE: 1,
		agentv1.CapabilityName_CAPABILITY_NAME_CC: 6, agentv1.CapabilityName_CAPABILITY_NAME_IP_INTEL: 2,
		agentv1.CapabilityName_CAPABILITY_NAME_JA4: 1,
	})
	noJA4 := capabilitySnapshot(t, map[agentv1.CapabilityName]uint32{
		agentv1.CapabilityName_CAPABILITY_NAME_MARKET_PROBE: 1, agentv1.CapabilityName_CAPABILITY_NAME_AUTO_DEFENSE: 1,
		agentv1.CapabilityName_CAPABILITY_NAME_CC: 6, agentv1.CapabilityName_CAPABILITY_NAME_IP_INTEL: 2,
	})
	nodes := []uuid.UUID{
		seedSupplyNode(t, pool, platform, seller.UserID, "8.8.4.1", "CN", "电信", full, true),
		seedSupplyNode(t, pool, platform, seller.UserID, "8.8.4.2", "CN", "联通", full, true),
		seedSupplyNode(t, pool, platform, seller.UserID, "8.8.4.3", "HK", "BGP", noJA4, false),
	}
	groups := NewSupplyGroups(pool, nodescheduler.NewService(pool, time.Now),
		staticFeatures{"module.autodefense": true, "pack.cc.advanced": true})

	single, err := groups.Put(ctx, seller, SupplyGroupWrite{Name: "单节点", NodeIDs: nodes[:1], IdempotencyKey: "ml09-single", RequestID: "ml09-single"})
	if err != nil {
		t.Fatalf("single-node supply: %v", err)
	}
	multi, err := groups.Put(ctx, seller, SupplyGroupWrite{Name: "三节点", NodeIDs: nodes, IdempotencyKey: "ml09-multi", RequestID: "ml09-multi"})
	if err != nil {
		t.Fatalf("three-node supply: %v", err)
	}
	if len(single.Nodes) != 1 || len(multi.Nodes) != 3 || multi.Name != "三节点" || multi.Revision != 1 {
		t.Fatalf("groups %+v / %+v", single, multi)
	}
	// Replay returns the same group; another key with a different body is a new group.
	if again, err := groups.Put(ctx, seller, SupplyGroupWrite{Name: "单节点", NodeIDs: nodes[:1], IdempotencyKey: "ml09-single", RequestID: "x"}); err != nil || again.ID != single.ID {
		t.Fatalf("replay %+v %v", again, err)
	}
	var purpose string
	if err := pool.QueryRow(ctx, `SELECT purpose FROM node_line_groups WHERE id=$1 AND tenant_scope_id=$2`, multi.ID, platform).Scan(&purpose); err != nil || purpose != "market_supply" {
		t.Fatalf("stored purpose %q %v", purpose, err)
	}

	// Hidden from the line group API and from package resources.
	scheduler, admin := platformScheduler(t, pool, platform)
	listed, err := scheduler.List(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range listed {
		if g.GroupID == single.ID || g.GroupID == multi.ID {
			t.Fatalf("line group list shows a market supply group %s", g.GroupID)
		}
	}
	if _, err := scheduler.GetCurrent(ctx, admin, multi.ID); !errors.Is(err, nodescheduler.ErrNotFound) {
		t.Fatalf("line group API get: %v, want not found", err)
	}
	if _, err := scheduler.DeleteGroup(ctx, admin, multi.ID, 1, "ml09-del-general", "ml09-del-general"); !errors.Is(err, nodescheduler.ErrNotFound) {
		t.Fatalf("line group API delete: %v, want not found", err)
	}
	if _, err := scheduler.PutGroup(ctx, admin, nodescheduler.PutGroupRequest{GroupID: multi.ID, ExpectedRevision: 1, Name: "x",
		IdempotencyKey: "ml09-put-general", RequestID: "ml09-put-general"}); !errors.Is(err, nodescheduler.ErrNotFound) {
		t.Fatalf("line group API overwrite: %v, want not found", err)
	}

	// Pool inventory: the market sees the supply's join_market, probe-capable nodes.
	market := &inventoryMarket{offers: []marketclient.OwnOffer{{Status: "listed", Components: []struct {
		Kind        string `json:"kind"`
		NodePoolRef string `json:"node_pool_ref"`
	}{{Kind: "own_pool", NodePoolRef: single.ID.String()}, {Kind: "own_pool", NodePoolRef: multi.ID.String()}}}}}
	probe := marketprobe.New(pool, market, nil, marketprobe.Config{Plugins: groups}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := probe.SyncInventory(ctx); err != nil {
		t.Fatal(err)
	}
	if got := market.reports[single.ID.String()]; len(got) != 1 || got[0].NodeID != nodes[0].String() || got[0].Carrier != "telecom" {
		t.Fatalf("single inventory %+v", got)
	}
	if got := market.reports[multi.ID.String()]; len(got) != 3 {
		t.Fatalf("multi inventory %+v", got)
	}
	// Each node carries its own licensed plugins (free ones are not market
	// plugin codes; no rule pack applied yet), from the same facts as GroupPlugins.
	for _, node := range market.reports[multi.ID.String()] {
		if want := []string{"module.autodefense", "pack.cc.advanced"}; !slices.Equal(node.Plugins, want) {
			t.Fatalf("node %s plugins %v want %v", node.NodeID, node.Plugins, want)
		}
	}

	// Plugins: the lease grants autodefense + advanced CC (not the auto
	// mitigation or dnspup); JA4 and the IP library are free but node 3
	// lacks JA4 and has no applied IP library.
	codes := func(items []SupplyPlugin) []string {
		out := []string{}
		for _, item := range items {
			out = append(out, item.Code)
		}
		return out
	}
	singlePlugins, err := groups.GroupPlugins(ctx, seller, single.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := codes(singlePlugins), []string{"module.autodefense", "pack.cc.advanced", "ipintel", "ja4"}; !slices.Equal(got, want) {
		t.Fatalf("single plugins %v want %v", got, want)
	}
	multiPlugins, err := groups.GroupPlugins(ctx, seller, multi.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := codes(multiPlugins), []string{"module.autodefense", "pack.cc.advanced"}; !slices.Equal(got, want) {
		t.Fatalf("three-node plugins %v want %v", got, want)
	}
	if adhoc, err := groups.SupplyPlugins(ctx, platform, nodes[:2]); err != nil || !slices.Equal(codes(adhoc), []string{"module.autodefense", "pack.cc.advanced", "ipintel", "ja4"}) {
		t.Fatalf("ad hoc plugins %v %v", codes(adhoc), err)
	}

	// A rule pack bought on the plugin
	// market and applied on a node is a market plugin code of that node
	// (rule_pack:<pack id>, spec.ValidPlugin), reported with the inventory.
	packSHA := strings.Repeat("b", 64)
	// One transaction: rule_packs.current_version references the artifact (deferred FK, 349).
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO rule_packs(pack_id,layer,current_version,update_policy,created_at,updated_at)
			VALUES('dev/io.cdnca.examples/bad-bots','developer','1.0.0','auto',now(),now())`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO rule_pack_artifacts(pack_id,version,engine,engine_min_version,name,sha256,size_bytes,content,
			source,state,downloaded_at,created_by_user_id,created_at) VALUES('dev/io.cdnca.examples/bad-bots','1.0.0','waf_v2',1,'坏机器人',$1,2,
			'{}'::bytea,'market','downloaded',now(),$2,now())`, packSHA, seller.UserID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO node_artifact_applied_items(node_id,artifact_id,version,item_revision,media_type,sha256,set_revision,applied_at)
		VALUES($1,'rule_pack/bad-bots','1.0.0',1,$2,$3,1,now())`, nodes[0], artifactset.MediaTypeRulePack, packSHA); err != nil {
		t.Fatal(err)
	}
	perNode, err := groups.NodePluginCodes(ctx, nodes[:2])
	if err != nil {
		t.Fatal(err)
	}
	if got, want := perNode[nodes[0]], []string{"module.autodefense", "pack.cc.advanced", "rule_pack:dev/io.cdnca.examples/bad-bots"}; !slices.Equal(got, want) {
		t.Fatalf("node with the market rule pack: %v want %v", got, want)
	}
	if got, want := perNode[nodes[1]], []string{"module.autodefense", "pack.cc.advanced"}; !slices.Equal(got, want) {
		t.Fatalf("node without the market rule pack: %v want %v", got, want)
	}

	// Replace the three-node set with two nodes; the group keeps its id.
	two, err := groups.Put(ctx, seller, SupplyGroupWrite{GroupID: multi.ID, ExpectedRevision: 1, Name: "两节点", NodeIDs: nodes[:2],
		IdempotencyKey: "ml09-multi-2", RequestID: "ml09-multi-2"})
	if err != nil || two.ID != multi.ID || two.Revision != 2 || len(two.Nodes) != 2 {
		t.Fatalf("update %+v %v", two, err)
	}
	if _, err := groups.Put(ctx, seller, SupplyGroupWrite{GroupID: multi.ID, ExpectedRevision: 1, Name: "旧", NodeIDs: nodes[:1],
		IdempotencyKey: "ml09-multi-stale", RequestID: "s"}); !errors.Is(err, ErrSupplyConflict) {
		t.Fatalf("stale update: %v", err)
	}

	// Invalid selections.
	if _, err := groups.Put(ctx, seller, SupplyGroupWrite{Name: "空", IdempotencyKey: "ml09-empty", RequestID: "e"}); !errors.Is(err, ErrSupplyInvalid) {
		t.Fatalf("empty: %v", err)
	}
	if _, err := groups.Put(ctx, seller, SupplyGroupWrite{Name: "重复", NodeIDs: []uuid.UUID{nodes[0], nodes[0]}, IdempotencyKey: "ml09-dup", RequestID: "d"}); !errors.Is(err, ErrSupplyInvalid) {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := groups.Put(ctx, seller, SupplyGroupWrite{Name: "未知", NodeIDs: []uuid.UUID{uuid.New()}, IdempotencyKey: "ml09-unknown", RequestID: "u"}); !errors.Is(err, ErrSupplyNodeUnusable) {
		t.Fatalf("unknown node: %v", err)
	}

	// A member without marketplace.sell or platform.admin is refused.
	outsider := seedPlatformMember(t, pool, platform, "")
	if _, err := groups.Put(ctx, outsider, SupplyGroupWrite{Name: "越权", NodeIDs: nodes[:1], IdempotencyKey: "ml09-outsider", RequestID: "o"}); !errors.Is(err, ErrSupplyForbidden) {
		t.Fatalf("outsider: %v", err)
	}

	// In use by a market product: delete refused; unused: deleted.
	// The hidden product a market grant on the single-node pool creates.
	svc := newTestService(t, pool, time.Now)
	actor, err := svc.ensureActor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.ensureProduct(ctx, actor, "ml09-"+single.ID.String()[:8], single.ID, grant.Grant{
		Schema: grant.SchemaV2, SubscriptionPath: []uuid.UUID{uuid.New()}, NodePoolRef: single.ID.String(),
		LoadThresholds: spec.DefaultLoadFloor}); err != nil {
		t.Fatalf("market product on the supply group: %v", err)
	}
	if err := groups.Delete(ctx, seller, single.ID, 1, "ml09-del-single", "ml09-del-single"); !errors.Is(err, nodescheduler.ErrMarketSupplyInUse) {
		t.Fatalf("delete in use: %v", err)
	}
	// A market product without a normal
	// subscription does not oblige the seller to keep a node, so emptying
	// is an ordinary invalid selection; the refusals are in
	// TestKeepOneOnlineNodeWhileNormalSubscribers.
	if _, err := groups.Put(ctx, seller, SupplyGroupWrite{GroupID: single.ID, ExpectedRevision: 1, Name: "清空",
		IdempotencyKey: "ml18-empty", RequestID: "ml18-empty"}); !errors.Is(err, ErrSupplyInvalid) {
		t.Fatalf("emptying a supply without normal subscribers: %v", err)
	}
	if _, err := groups.Put(ctx, seller, SupplyGroupWrite{GroupID: multi.ID, ExpectedRevision: 2, Name: "空", IdempotencyKey: "ml18-empty-unused",
		RequestID: "e"}); !errors.Is(err, ErrSupplyInvalid) {
		t.Fatalf("emptying an unused supply stays invalid: %v", err)
	}
	if err := groups.Delete(ctx, seller, multi.ID, 2, "ml09-del-multi", "ml09-del-multi"); err != nil {
		t.Fatalf("delete unused: %v", err)
	}
	if _, err := groups.Get(ctx, seller, multi.ID); !errors.Is(err, ErrSupplyNotFound) {
		t.Fatalf("get deleted: %v", err)
	}
}

type inventoryMarket struct {
	offers  []marketclient.OwnOffer
	reports map[string][]marketclient.PoolNode
}

func (m *inventoryMarket) OwnOffers(context.Context) ([]marketclient.OwnOffer, error) {
	return m.offers, nil
}
func (m *inventoryMarket) ReportPoolNodes(_ context.Context, ref string, nodes []marketclient.PoolNode, _ *int) error {
	if m.reports == nil {
		m.reports = map[string][]marketclient.PoolNode{}
	}
	m.reports[ref] = nodes
	return nil
}
func (m *inventoryMarket) ReportNodeLoad(context.Context, marketclient.Identity, nodeload.Report) (marketclient.NodeLoadResult, error) {
	return marketclient.NodeLoadResult{}, nil
}

func (m *inventoryMarket) ReportNodeActions(context.Context, marketclient.Identity, nodeaction.Report) (marketclient.NodeActionResult, error) {
	return marketclient.NodeActionResult{}, nil
}

func (m *inventoryMarket) ProbeTasks(context.Context) ([]marketclient.ProbeTask, error) {
	return nil, nil
}
func (m *inventoryMarket) SubmitProbeResults(context.Context, []marketclient.ProbeResult) (int, error) {
	return 0, nil
}

func capabilitySnapshot(t *testing.T, features map[agentv1.CapabilityName]uint32) []byte {
	t.Helper()
	var caps agentv1.AgentCapabilities
	for name, version := range features {
		caps.Features = append(caps.Features, &agentv1.Capability{Name: name, ApiVersion: version})
	}
	raw, err := proto.Marshal(&caps)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// seedSupplyNode inserts an active platform node with a public IPv4, its IP
// location, session capabilities, join_market role and (ipLibrary) an
// applied IP library artifact.
func seedSupplyNode(t *testing.T, pool *pgxpool.Pool, platform, user uuid.UUID, ip, country, isp string, caps []byte, ipLibrary bool) uuid.UUID {
	t.Helper()
	node := uuid.New()
	exec(t, pool, `INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id,ipv4,management_settings)
		VALUES($1,$2,$3,'active',$4,(SELECT COALESCE(max(display_id),0)+1 FROM nodes),$5::inet,
		jsonb_set(jsonb_set('{"schema_version":1,"sort":100,"node_type":"L1","cache_directory":"","cache_limit_gb":0,"log_directory":"",
		"ip_location":{"country":"","province":"","city":"","isp":"","country_code":""},"secondary_ips":[]}'::jsonb,
		'{ip_location,country_code}',to_jsonb($6::text)),'{ip_location,isp}',to_jsonb($7::text)))`,
		node, platform, "ml09-"+node.String()[:8], user, ip, country, isp)
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO node_session_capabilities(node_id,session_epoch,certificate_id,certificate_sha256,
			artifact_key_id,selected_protocol_major,selected_protocol_minor,capabilities_snapshot,capabilities_sha256,
			facts_snapshot,facts_sha256,gateway_workload_identity,gateway_instance_id,registered_at)
			VALUES($1,1,$2,$3,'k',1,0,$4,$3,'\x00',$3,'gw','gw-1',now())`, node, uuid.New(), make([]byte, 32), caps); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO node_presence(
			node_id,status,session_epoch,heartbeat_sequence,event_id,request_id,payload_digest,occurred_at,projected_at,
			last_seen_at,confirmed_session_epoch,confirmed_heartbeat_sequence,confirmed_event_id,confirmed_request_id,
			confirmed_payload_digest,online_since,openresty_state,firewall_state,
			filesystem_total_bytes,filesystem_available_bytes,cache_used_bytes,market_probe_role,updated_at)
			VALUES($1,'online',1,1,$2,$3,$4,now(),now(),now(),1,1,$2,$3,$4,now(),'running','running',100,50,0,'join_market',now())`,
			node, uuid.New(), uuid.New(), make([]byte, 32)); err != nil {
			return err
		}
		if !ipLibrary {
			return nil
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO node_artifact_applied_items(node_id,artifact_id,version,item_revision,media_type,sha256,set_revision,applied_at)
			VALUES($1,'ipintel/base','1',1,$2,repeat('a',64),1,now())`, node, artifactset.MediaTypeIPIntel)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return node
}

func seedSeller(t *testing.T, pool *pgxpool.Pool, platform uuid.UUID) SupplyActor {
	t.Helper()
	return seedPlatformMember(t, pool, platform, "marketplace.sell")
}

// platformScheduler is the line group API as served (IAM sessions) with a
// platform.admin session.
func platformScheduler(t *testing.T, pool *pgxpool.Pool, platform uuid.UUID) (*nodescheduler.Service, nodescheduler.Actor) {
	t.Helper()
	now := time.Now().UTC()
	tokens, err := identity.NewTokenManager(strings.Repeat("m", 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := sessioncredential.NewVerifier(tokens, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	apiKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{0x31}, 32), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := iamlock.NewAuthorizer(sessions, apiKeys)
	if err != nil {
		t.Fatal(err)
	}
	service, err := nodescheduler.NewIAMService(pool, func() time.Time { return now }, authorizer, nil)
	if err != nil {
		t.Fatal(err)
	}
	member := seedPlatformMember(t, pool, platform, "platform.admin")
	session := uuid.New()
	refresh := sha256.Sum256([]byte(session.String()))
	exec(t, pool, `INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
		VALUES($1,$2,$3,$4,$5,$6,$7)`, session, uuid.New(), member.UserID, platform, refresh[:], now.Add(-time.Minute), now.Add(time.Hour))
	raw, _, err := tokens.Mint(member.UserID, platform, session)
	if err != nil {
		t.Fatal(err)
	}
	return service, nodescheduler.Actor{UserID: member.UserID, ScopeID: platform, ScopeKind: "platform",
		Credential: nodescheduler.Credential{Kind: nodescheduler.CredentialSession, Raw: raw}}
}

// seedPlatformMember creates an active platform member holding permission
// ("" = none) through its own role.
func seedPlatformMember(t *testing.T, pool *pgxpool.Pool, platform uuid.UUID, permission string) SupplyActor {
	t.Helper()
	user, role := uuid.New(), uuid.New()
	exec(t, pool, `INSERT INTO users(id,username,display_name,password_hash,created_at,updated_at)
		VALUES($1,$2,'ML09','unused',now(),now())`, user, "ml09-"+user.String()[:12])
	exec(t, pool, `INSERT INTO memberships(scope_id,user_id,created_at) VALUES($1,$2,now())`, platform, user)
	if permission != "" {
		exec(t, pool, `INSERT INTO roles(id,scope_id,name,description,system_role,created_at) VALUES($1,$2,$3,'ML09',true,now())`,
			role, platform, "ml09-"+role.String()[:12])
		exec(t, pool, `INSERT INTO role_permissions(role_id,permission_name) VALUES($1,$2)`, role, permission)
		exec(t, pool, `INSERT INTO role_assignments(scope_id,user_id,role_id,assigned_at) VALUES($1,$2,$3,now())`, platform, user, role)
	}
	return SupplyActor{UserID: user, ScopeID: platform}
}
