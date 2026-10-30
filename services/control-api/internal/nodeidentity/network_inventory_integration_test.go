//go:build integration

package nodeidentity

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/node"
	"github.com/cdnca/cdnca/services/control-api/internal/nodecertlifecycle"
	"github.com/cdnca/cdnca/services/control-api/internal/nodepresence"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestNetworkInventoryFormalRegistration(t *testing.T) {
	pool := openIdentityTestDatabase(t, true)
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	clock := &identityTestClock{value: now}
	service := newIdentityTestService(t, pool, newIdentityTestCA(t, now), clock)
	fixture := seedIdentityPlatformNode(t, pool, now, "pending", "initial_enrollment")
	authorize := validAuthorizeRequest(t, testCSR(t, false))
	authorize.EnrollmentToken, authorize.PeerIP = fixture.token, "203.0.113.125"
	auth, err := service.Authorize(context.Background(), authorize)
	if err != nil {
		t.Fatal(err)
	}
	completion, err := service.Complete(context.Background(), CompleteRequest{RequestID: uuid.NewString(), AuthorizationID: auth.ID, GatewayWorkloadIdentity: authorize.GatewayWorkloadIdentity, GatewayInstanceID: authorize.GatewayInstanceID})
	if err != nil {
		t.Fatal(err)
	}
	request := NetworkInventoryRequest{GetAuthorizationRequest: GetAuthorizationRequest{NodeID: fixture.nodeID, CertificateSerialNumber: completion.Certificate.SerialNumber, CertificateSHA256: certificateDERDigest(t, completion.Certificate), GatewayWorkloadIdentity: authorize.GatewayWorkloadIdentity, GatewayInstanceID: authorize.GatewayInstanceID}, PeerIP: "203.0.113.125", Inventory: &agentv1.ReportNodeNetworkInventoryV1Request{SchemaVersion: 1, Request: &commonv1.RequestMetadata{RequestId: uuid.NewString(), SentTime: timestamppb.New(now)}, Ipv4: &agentv1.NodeNetworkCandidateV1{Address: "203.0.113.125", InterfaceName: "ens17"}, Ipv6Reason: "no_default_route"}}
	result, err := service.ReportNetworkInventory(context.Background(), request)
	if err != nil || result.GetIpv4State() != "verified" || result.GetNodeId() != fixture.nodeID.String() {
		t.Fatalf("automatic inventory = %v, %v", result, err)
	}
	var address string
	if err := pool.QueryRow(context.Background(), `SELECT host(ipv4) FROM nodes WHERE id=$1`, fixture.nodeID).Scan(&address); err != nil || address != request.PeerIP {
		t.Fatalf("inventory address = %q, %v", address, err)
	}
}

func TestNetworkInventorySafetyContract(t *testing.T) {
	ctx := context.Background()
	pool := openIdentityTestDatabase(t, true)
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	clock := &identityTestClock{value: now}
	service := newIdentityTestService(t, pool, newIdentityTestCA(t, now), clock)
	inventory := nodepresence.NewInventory(pool, nil, time.Minute, clock.now, nil)
	enroll := func(tenant ...bool) (identityFixture, NetworkInventoryRequest) {
		var fixture identityFixture
		if len(tenant) != 0 && tenant[0] {
			fixture = seedIdentityNode(t, pool, now, "pending", "initial_enrollment")
		} else {
			fixture = seedIdentityPlatformNode(t, pool, now, "pending", "initial_enrollment")
		}
		request := validAuthorizeRequest(t, testCSR(t, false))
		request.RequestID = uuid.NewString()
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		request.ArtifactEncryptionPublicKey = key.PublicKey().Bytes()
		request.EnrollmentToken, request.PeerIP = fixture.token, "203.0.113.125"
		authorized, err := service.Authorize(ctx, request)
		if err != nil {
			t.Fatal(err)
		}
		completed, err := service.Complete(ctx, CompleteRequest{RequestID: uuid.NewString(), AuthorizationID: authorized.ID, GatewayWorkloadIdentity: request.GatewayWorkloadIdentity, GatewayInstanceID: request.GatewayInstanceID})
		if err != nil {
			t.Fatal(err)
		}
		return fixture, NetworkInventoryRequest{GetAuthorizationRequest: GetAuthorizationRequest{NodeID: fixture.nodeID, CertificateSerialNumber: completed.Certificate.SerialNumber, CertificateSHA256: certificateDERDigest(t, completed.Certificate), GatewayWorkloadIdentity: request.GatewayWorkloadIdentity, GatewayInstanceID: request.GatewayInstanceID}, PeerIP: "203.0.113.125", Inventory: &agentv1.ReportNodeNetworkInventoryV1Request{SchemaVersion: 1, Request: &commonv1.RequestMetadata{RequestId: uuid.NewString(), SentTime: timestamppb.New(now)}, Ipv4: &agentv1.NodeNetworkCandidateV1{Address: "203.0.113.125", InterfaceName: "ens17"}, Ipv6Reason: "no_default_route"}}
	}
	clone := func(request NetworkInventoryRequest) NetworkInventoryRequest {
		request.Inventory = proto.Clone(request.Inventory).(*agentv1.ReportNodeNetworkInventoryV1Request)
		request.Inventory.Request.RequestId = uuid.NewString()
		return request
	}
	facts := func(id uuid.UUID) [3]int64 {
		var values [3]int64
		if err := pool.QueryRow(ctx, `SELECT revision,(SELECT count(*) FROM node_network_inventory_reports WHERE node_id=$1),(SELECT count(*) FROM audit_events WHERE resource_id=$1::text AND action='node.network_inventory.report') FROM nodes WHERE id=$1`, id).Scan(&values[0], &values[1], &values[2]); err != nil {
			t.Fatal(err)
		}
		return values
	}
	t.Run("replay-public-read-and-manual-address-preservation", func(t *testing.T) {
		fixture, request := enroll()
		before, err := inventory.Get(ctx, fixture.scopeID, fixture.nodeID)
		if err != nil || before.NetworkInventory.IPv4State != "not_reported" || before.NetworkInventory.ReceivedAt != nil {
			t.Fatalf("before report: %v %v", before.NetworkInventory, err)
		}
		initial := facts(fixture.nodeID)
		result, err := service.ReportNetworkInventory(ctx, request)
		if err != nil || result.GetReplayed() || result.GetIpv4State() != "verified" {
			t.Fatalf("write: %v %v", result, err)
		}
		if got := facts(fixture.nodeID); got != [3]int64{initial[0] + 1, 1, 1} {
			t.Fatalf("first-write facts %v", got)
		}
		clock.set(now.Add(10 * time.Minute))
		replay, err := service.ReportNetworkInventory(ctx, request)
		clock.set(now)
		if err != nil || !replay.GetReplayed() || !replay.ReceivedTime.AsTime().Equal(result.ReceivedTime.AsTime()) {
			t.Fatalf("exact replay: %v %v", replay, err)
		}
		if got := facts(fixture.nodeID); got != [3]int64{initial[0] + 1, 1, 1} {
			t.Fatalf("replay duplicated facts: %v", got)
		}
		changed := clone(request)
		changed.Inventory.Request.RequestId = request.Inventory.Request.RequestId
		changed.Inventory.Ipv4.InterfaceName = "ens18"
		if _, err := service.ReportNetworkInventory(ctx, changed); !errors.Is(err, ErrIdempotencyConflict) {
			t.Fatalf("changed replay: %v", err)
		}
		if _, err := inventory.Get(ctx, uuid.New(), fixture.nodeID); !errors.Is(err, node.ErrNotFound) {
			t.Fatalf("cross scope read: %v", err)
		}
		if _, err := pool.Exec(ctx, `UPDATE nodes SET ipv4='203.0.113.126',revision=revision+1 WHERE id=$1`, fixture.nodeID); err != nil {
			t.Fatal(err)
		}
		read, err := inventory.Get(ctx, fixture.scopeID, fixture.nodeID)
		if err != nil || read.NetworkInventory.IPv4State != "address_conflict" || read.IPv4 == nil || *read.IPv4 != "203.0.113.126" {
			t.Fatalf("manual change falsely verified: %v %v", read, err)
		}
		list, err := inventory.List(ctx, nodepresence.InventoryListRequest{ScopeID: fixture.scopeID, Limit: 300})
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, item := range list.Items {
			if item.ID == fixture.nodeID {
				found = item.NetworkInventory.IPv4State == "address_conflict"
			}
		}
		if !found {
			t.Fatal("list did not project current address conflict")
		}
		result, err = service.ReportNetworkInventory(ctx, clone(request))
		if err != nil || result.GetIpv4State() != "address_conflict" {
			t.Fatalf("do not overwrite: %v %v", result, err)
		}
		if got := facts(fixture.nodeID); got != [3]int64{initial[0] + 2, 2, 2} {
			t.Fatalf("conflict changed revision: %v", got)
		}
		read, err = inventory.Get(ctx, fixture.scopeID, fixture.nodeID)
		if err != nil || read.IPv4 == nil || *read.IPv4 != "203.0.113.126" {
			t.Fatal("manual value overwritten")
		}
	})
	t.Run("pending-is-not-an-address-or-cross-family-proof", func(t *testing.T) {
		fixture, request := enroll()
		request.PeerIP = "203.0.113.23"
		request.Inventory.Ipv6Reason = ""
		request.Inventory.Ipv6 = &agentv1.NodeNetworkCandidateV1{Address: "2606:4700:4700::1111", InterfaceName: "ens17"}
		result, err := service.ReportNetworkInventory(ctx, request)
		if err != nil || result.GetIpv4State() != "peer_mismatch" || result.GetIpv6State() != "peer_mismatch" {
			t.Fatalf("pending: %v %v", result, err)
		}
		read, err := inventory.Get(ctx, fixture.scopeID, fixture.nodeID)
		if err != nil || read.IPv4 != nil || read.IPv6 != nil {
			t.Fatal("pending wrote an address")
		}
		if _, err := pool.Exec(ctx, `UPDATE nodes SET ipv4='203.0.113.24',revision=revision+1 WHERE id=$1`, fixture.nodeID); err != nil {
			t.Fatal(err)
		}
		verified := clone(request)
		verified.PeerIP = verified.Inventory.Ipv6.Address
		result, err = service.ReportNetworkInventory(ctx, verified)
		if err != nil || result.GetIpv6State() != "verified" || result.GetIpv4State() != "peer_mismatch" {
			t.Fatalf("IPv6 independent proof: %v %v", result, err)
		}
		read, err = inventory.Get(ctx, fixture.scopeID, fixture.nodeID)
		if err != nil || read.IPv4 == nil || *read.IPv4 != "203.0.113.24" || read.IPv6 == nil || *read.IPv6 != verified.PeerIP {
			t.Fatal("independent proof changed manual address")
		}
	})
	t.Run("authority-is-current-even-for-replay", func(t *testing.T) {
		fixture, request := enroll()
		request.Inventory.Ipv4.Address, request.PeerIP = "203.0.113.40", "203.0.113.40"
		if _, err := service.ReportNetworkInventory(ctx, request); err != nil {
			t.Fatal(err)
		}
		before := facts(fixture.nodeID)
		for _, mutate := range []func(*NetworkInventoryRequest){
			func(r *NetworkInventoryRequest) { r.NodeID = uuid.New() },
			func(r *NetworkInventoryRequest) { r.CertificateSerialNumber = "ffff" },
			func(r *NetworkInventoryRequest) { r.CertificateSHA256[0] ^= 1 },
			func(r *NetworkInventoryRequest) { r.GatewayWorkloadIdentity = "spiffe://cdnca/control/other" },
		} {
			rejected := clone(request)
			mutate(&rejected)
			if _, err := service.ReportNetworkInventory(ctx, rejected); err == nil {
				t.Fatal("unbound authority accepted")
			}
		}
		if _, err := pool.Exec(ctx, `UPDATE nodes SET admin_state='draining',revision=revision+1 WHERE id=$1`, fixture.nodeID); err != nil {
			t.Fatal(err)
		}
		if _, err := service.ReportNetworkInventory(ctx, request); !errors.Is(err, ErrNodeStateDenied) {
			t.Fatalf("draining replay: %v", err)
		}
		if _, err := pool.Exec(ctx, `UPDATE nodes SET admin_state='active',revision=revision+1 WHERE id=$1`, fixture.nodeID); err != nil {
			t.Fatal(err)
		}
		if err := service.Revoke(ctx, RevokeRequest{RequestID: uuid.NewString(), NodeID: fixture.nodeID, SerialNumber: request.CertificateSerialNumber, Reason: "inventory test revoke"}); err != nil {
			t.Fatal(err)
		}
		if _, err := service.ReportNetworkInventory(ctx, request); err == nil {
			t.Fatal("revoked replay accepted")
		}
		if _, err := service.ReportNetworkInventory(ctx, clone(request)); err == nil {
			t.Fatal("revoked new request accepted")
		}
		after := facts(fixture.nodeID)
		if after[1] != before[1] || after[2] != before[2] {
			t.Fatal("denial wrote report or audit")
		}
	})
	t.Run("expired-after-lock-wait", func(t *testing.T) {
		fixture, request := enroll()
		before := facts(fixture.nodeID)
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		var expiration time.Time
		if err := tx.QueryRow(ctx, `SELECT not_after FROM node_certificates WHERE node_id=$1 FOR UPDATE`, fixture.nodeID).Scan(&expiration); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { _, err := service.ReportNetworkInventory(ctx, request); done <- err }()
		deadline := time.Now().Add(3 * time.Second)
		for {
			var waiting bool
			if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'SELECT id FROM node_certificates WHERE node_id=%')`).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
			if waiting {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("report did not reach certificate lock")
			}
			time.Sleep(5 * time.Millisecond)
		}
		clock.set(expiration)
		defer clock.set(now)
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			if !errors.Is(err, ErrNodeStateDenied) {
				t.Fatalf("expired after lock: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("report did not finish")
		}
		if after := facts(fixture.nodeID); after != before {
			t.Fatal("expired request wrote facts")
		}
	})
	t.Run("tenant-identity-cannot-change-platform-inventory", func(t *testing.T) {
		fixture, request := enroll(true)
		before := facts(fixture.nodeID)
		if _, err := service.ReportNetworkInventory(ctx, request); !errors.Is(err, ErrNodeStateDenied) {
			t.Fatalf("tenant report accepted: %v", err)
		}
		if after := facts(fixture.nodeID); after != before {
			t.Fatal("tenant report wrote facts")
		}
	})
	t.Run("scheduled-bound-revocation-is-checked-on-replay", func(t *testing.T) {
		fixture, request := enroll()
		request.Inventory.Ipv4.Address, request.PeerIP = "203.0.113.60", "203.0.113.60"
		roleID := uuid.New()
		if _, err := pool.Exec(ctx, `INSERT INTO roles(id,scope_id,name,system_role) VALUES($1,$2,'platform_owner',true)`, roleID, fixture.scopeID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'nodes.manage'),($1,'node_ca.manage') ON CONFLICT DO NOTHING`, roleID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, fixture.scopeID, fixture.userID, roleID); err != nil {
			t.Fatal(err)
		}
		lifecycle, err := nodecertlifecycle.NewStore(pool, nodecertlifecycle.Config{Clock: clock.now, OverlapWindow: time.Minute, AuthorizationSnapshotTTL: time.Minute, MaxScheduledRevocation: time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		_, err = lifecycle.RevokeCertificate(ctx, nodecertlifecycle.Actor{UserID: fixture.userID, ScopeID: fixture.scopeID, ScopeKind: "platform"}, nodecertlifecycle.RevokeCertificateRequest{RequestID: uuid.New(), NodeID: fixture.nodeID, SerialNumber: request.CertificateSerialNumber, LeafDERSHA256: request.CertificateSHA256, EffectiveAt: now.Add(30 * time.Second), Reason: "scheduled network test", RequestTraceID: uuid.NewString()})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.ReportNetworkInventory(ctx, request); err != nil {
			t.Fatalf("valid before revocation: %v", err)
		}
		before := facts(fixture.nodeID)
		clock.set(now.Add(30 * time.Second))
		defer clock.set(now)
		if _, err := service.ReportNetworkInventory(ctx, request); !errors.Is(err, ErrNodeStateDenied) {
			t.Fatalf("effective revocation replay: %v", err)
		}
		if after := facts(fixture.nodeID); after != before {
			t.Fatal("revoked replay wrote facts")
		}
	})
	t.Run("concurrent-conflict-and-replay", func(t *testing.T) {
		_, first := enroll()
		_, second := enroll()
		first.Inventory.Ipv4.Address, first.PeerIP = "203.0.113.50", "203.0.113.50"
		second.Inventory.Ipv4.Address, second.PeerIP = first.PeerIP, first.PeerIP
		start := make(chan struct{})
		results := make(chan string, 2)
		var wait sync.WaitGroup
		for _, request := range []NetworkInventoryRequest{first, second} {
			wait.Add(1)
			go func(request NetworkInventoryRequest) {
				defer wait.Done()
				<-start
				result, err := service.ReportNetworkInventory(ctx, request)
				if err != nil {
					results <- err.Error()
				} else {
					results <- result.Ipv4State
				}
			}(request)
		}
		close(start)
		wait.Wait()
		close(results)
		counts := map[string]int{}
		for state := range results {
			counts[state]++
		}
		if counts["verified"] != 1 || counts["address_conflict"] != 1 {
			t.Fatalf("concurrent address decisions: %v", counts)
		}
		before := facts(first.NodeID)
		results = make(chan string, 8)
		for range 8 {
			wait.Add(1)
			go func() {
				defer wait.Done()
				result, err := service.ReportNetworkInventory(ctx, first)
				if err != nil {
					results <- err.Error()
				} else if !result.Replayed {
					results <- "not replay"
				}
			}()
		}
		wait.Wait()
		close(results)
		for err := range results {
			t.Error(err)
		}
		if after := facts(first.NodeID); after != before {
			t.Fatalf("parallel replay changed facts %v→%v", before, after)
		}
	})
	t.Run("invalid-payload-has-no-effects", func(t *testing.T) {
		fixture, request := enroll()
		before := facts(fixture.nodeID)
		for name, mutate := range map[string]func(*NetworkInventoryRequest){
			"schema":     func(r *NetworkInventoryRequest) { r.Inventory.SchemaVersion = 2 },
			"private":    func(r *NetworkInventoryRequest) { r.Inventory.Ipv4.Address = "10.0.0.1"; r.PeerIP = "10.0.0.1" },
			"CGNAT":      func(r *NetworkInventoryRequest) { r.Inventory.Ipv4.Address = "100.64.0.1"; r.PeerIP = "100.64.0.1" },
			"IPv6-in-v4": func(r *NetworkInventoryRequest) { r.Inventory.Ipv4.Address = "2606:4700::1111" },
			"unknown":    func(r *NetworkInventoryRequest) { r.Inventory.Ipv4.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01}) },
			"stale-new-write": func(r *NetworkInventoryRequest) {
				r.Inventory.Request.SentTime = timestamppb.New(now.Add(-6 * time.Minute))
			},
			"future": func(r *NetworkInventoryRequest) {
				r.Inventory.Request.SentTime = timestamppb.New(now.Add(2 * time.Minute))
			},
			"reason-and-candidate": func(r *NetworkInventoryRequest) { r.Inventory.Ipv4Reason = "unavailable" },
			"interface":            func(r *NetworkInventoryRequest) { r.Inventory.Ipv4.InterfaceName = "bad\nname" },
		} {
			t.Run(name, func(t *testing.T) {
				bad := clone(request)
				mutate(&bad)
				if _, err := service.ReportNetworkInventory(ctx, bad); !errors.Is(err, ErrInvalidInput) {
					t.Fatalf("invalid report: %v", err)
				}
			})
		}
		if after := facts(fixture.nodeID); after != before {
			t.Fatalf("invalid input changed facts %v→%v", before, after)
		}
	})
	t.Run("revoked-CA-cannot-replay", func(t *testing.T) {
		fixture, request := enroll()
		request.Inventory.Ipv4.Address, request.PeerIP = "203.0.113.70", "203.0.113.70"
		if _, err := service.ReportNetworkInventory(ctx, request); err != nil {
			t.Fatal(err)
		}
		var epochID uuid.UUID
		if err := pool.QueryRow(ctx, `SELECT ca_epoch_id FROM node_certificates WHERE node_id=$1`, fixture.nodeID).Scan(&epochID); err != nil {
			t.Fatal(err)
		}
		lifecycle, err := nodecertlifecycle.NewStore(pool, nodecertlifecycle.Config{Clock: clock.now, OverlapWindow: time.Minute, AuthorizationSnapshotTTL: time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		if err := lifecycle.RevokeCAEpoch(ctx, nodecertlifecycle.Actor{UserID: fixture.userID, ScopeID: fixture.scopeID, ScopeKind: "platform"}, nodecertlifecycle.RevokeCAEpochRequest{RequestID: uuid.New(), EpochID: epochID, Reason: "network inventory test", RequestTraceID: uuid.NewString()}); err != nil {
			t.Fatal(err)
		}
		before := facts(fixture.nodeID)
		if _, err := service.ReportNetworkInventory(ctx, request); !errors.Is(err, ErrNodeStateDenied) {
			t.Fatalf("revoked CA replay: %v", err)
		}
		if after := facts(fixture.nodeID); after != before {
			t.Fatal("CA-revoked replay wrote facts")
		}
	})
	// 271 的“有地址事实时拒绝回滚”在 TestNetworkInventoryMigration271 中按 271 发布头单独验证；
	// 发布头已超过 271（且 268 不可回滚），这里只验证事实表在发布头上保持 append-only。
	for _, statement := range []string{`UPDATE node_network_inventory_reports SET ipv4_state='unavailable'`, `DELETE FROM node_network_inventory_reports`, `TRUNCATE node_network_inventory_reports`} {
		if _, err := pool.Exec(ctx, statement); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Fatalf("immutable fact: %v", err)
		}
	}
}

func TestNetworkInventoryMigration271(t *testing.T) {
	// 只装载 1..271，模拟 271 发布头：空表可以回滚，有地址事实时 down 必须失败且不改账本。
	const head = 271
	pool := openIdentityTestDatabase(t, false)
	ctx := context.Background()
	if err := databasetest.MigrateThrough(ctx, pool, "up", head); err != nil {
		t.Fatal(err)
	}
	if identityMigrationVersion(t, pool) != head {
		t.Fatal("271 not applied")
	}
	if err := databasetest.MigrateThrough(ctx, pool, "down", head); err != nil {
		t.Fatal(err)
	}
	if identityMigrationVersion(t, pool) != 270 {
		t.Fatal("empty rollback failed")
	}
	assertIdentityTable(t, pool, "node_network_inventory_reports", false)
	if err := databasetest.MigrateThrough(ctx, pool, "up", head); err != nil {
		t.Fatal(err)
	}
	assertIdentityTable(t, pool, "node_network_inventory_reports", true)

	// 地址事实的外键链很长，这里只为验证回滚闸门，临时跳过外键插入一条最小事实。
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `SET session_replication_role = replica`); err != nil {
		conn.Release()
		t.Fatal(err)
	}
	_, insertErr := conn.Exec(ctx, `INSERT INTO node_network_inventory_reports(
		request_id,node_id,scope_id,certificate_id,request_digest,inventory_json,ipv4_state,ipv6_state,received_at
	) VALUES($1,$2,$3,$4,$5,'{}'::jsonb,'verified','no_default_route',now())`,
		uuid.New(), uuid.New(), uuid.New(), uuid.New(), make([]byte, 32))
	_, resetErr := conn.Exec(ctx, `SET session_replication_role = origin`)
	conn.Release()
	if insertErr != nil || resetErr != nil {
		t.Fatalf("seed address fact: insert=%v reset=%v", insertErr, resetErr)
	}
	if err := databasetest.MigrateThrough(ctx, pool, "down", head); err == nil || !strings.Contains(err.Error(), "cannot discard node address evidence") {
		t.Fatalf("down with facts: %v", err)
	}
	if identityMigrationVersion(t, pool) != head {
		t.Fatal("failed down modified ledger")
	}
	// The seed bypassed foreign keys; later migrations (284) re-validate them,
	// so remove it the same way before rolling forward to the release head.
	cleanup, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, replicaErr := cleanup.Exec(ctx, `SET session_replication_role = replica`)
	_, deleteErr := cleanup.Exec(ctx, `DELETE FROM node_network_inventory_reports`)
	_, originErr := cleanup.Exec(ctx, `SET session_replication_role = origin`)
	cleanup.Release()
	if replicaErr != nil || deleteErr != nil || originErr != nil {
		t.Fatalf("remove seed address fact: replica=%v delete=%v origin=%v", replicaErr, deleteErr, originErr)
	}
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		t.Fatal(err)
	}
}
