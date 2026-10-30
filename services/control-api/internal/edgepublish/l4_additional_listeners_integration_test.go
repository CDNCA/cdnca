//go:build integration

package edgepublish

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func CheckL4AdditionalListenerPublication(t *testing.T, mutations func(*pgxpool.Pool, uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID) []func() int64) {
	t.Helper()
	fixture := newL4V2ContractFixture(t)
	site := fixture.createSite(t, "additional-publication.example.com", 18081, false).Site
	steps := mutations(fixture.pool, fixture.scopeID, fixture.userID, fixture.subscriptionID, site.ID)
	var firstRevision int64
	for index, mutate := range steps {
		revision := mutate()
		if index == 0 {
			firstRevision = revision
		}
		// Every live stream requires tcp/udp v12 (506) and, on a package,
		// L4_PACKAGE_ATTRIBUTION (66); once none is live, the scope's v2 history
		// alone requires revocation support (loadL4V2LifecycleProtocols: v3 after
		// an additional listener).
		want := [][2]uint32{{12, 0}, {12, 12}, {12, 3}, {3, 3}, {3, 3}}[index]
		wantTCP, wantUDP := want[0], want[1]
		var compiled compiledSiteRuntimeL4
		func() {
			// Rolled back on every exit: a failed assertion must not leave the
			// connection checked out, or the fixture's pool close waits forever.
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			tx, err := fixture.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			compiled = fixture.compileSiteRuntimeL4(t, tx, revision)
		}()
		assertL4V2ContractProtocolVersions(t, compiled.Capabilities, wantTCP, wantUDP)
		assertL4AdditionalAttribution(t, compiled.Capabilities, index < 3)
		if index == 1 && (len(compiled.Streams) != 1 || len(compiled.Streams[0].AdditionalListeners) != 1) {
			t.Fatal("additional listener lost from projection")
		}
		if index >= 3 && len(compiled.Streams) != 0 {
			t.Fatal("disabled/deleted listener remains active")
		}
		node := *fixture
		node.nodeID = uuid.New()
		seedPublishNode(t, fixture.pool, fixture.scopeID, fixture.userID, node.nodeID)
		features := append(siteRuntimeV2NodeFeatures(), &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_ATOMIC_RELEASE, ApiVersion: 1}, &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_CONFIG_PRECHECK, ApiVersion: 1}, &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY, ApiVersion: 12}, &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_UDP_PROXY, ApiVersion: 12})
		if index > 0 {
			old := make([]*agentv1.Capability, len(features))
			copy(old, features)
			old[len(old)-2] = &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY, ApiVersion: 2}
			old[len(old)-1] = &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_UDP_PROXY, ApiVersion: 2}
			seedSiteRuntimeV2Capabilities(t, &node, "", old)
			if _, err := fixture.service.Publish(t.Context(), fixture.publishRequest(fmt.Sprintf("additional-old-%d", index), node.nodeID)); !errors.Is(err, ErrTargetIneligible) {
				t.Fatalf("old agent accepted stage %d: %v", index, err)
			}
			var commands int
			if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM edge_command_outbox WHERE node_id=$1`, node.nodeID).Scan(&commands); err != nil || commands != 0 {
				t.Fatalf("rejected old agent persisted command: %d %v", commands, err)
			}
			node.nodeID = uuid.New()
			seedPublishNode(t, fixture.pool, fixture.scopeID, fixture.userID, node.nodeID)
		}
		seedSiteRuntimeV2Capabilities(t, &node, "", features)
		var historyBefore, historyAfter []byte
		readHistory := func(target *[]byte) {
			t.Helper()
			if err := fixture.pool.QueryRow(t.Context(), `SELECT jsonb_build_object('intents',(SELECT jsonb_agg(to_jsonb(i) ORDER BY version) FROM l4_publish_intents i WHERE scope_id=$1),'receipts',(SELECT jsonb_agg(to_jsonb(w) ORDER BY id) FROM l4_write_requests w WHERE target_scope_id=$1))::text`, fixture.scopeID).Scan(target); err != nil {
				t.Fatal(err)
			}
		}
		readHistory(&historyBefore)
		request := fixture.publishRequest(fmt.Sprintf("additional-publish-%d", index), node.nodeID)
		result, err := fixture.service.Publish(t.Context(), request)
		if err != nil {
			t.Fatalf("stage %d publish: %v", index, err)
		}
		command := readL4V2ContractCommand(t, fixture, result.RolloutID)
		assertL4V2ContractProtocolVersions(t, command.RequiredCapabilities, wantTCP, wantUDP)
		assertL4AdditionalAttribution(t, command.RequiredCapabilities, index < 3)
		// The node takes the scope's streams from its scope object.
		scope := receivedV2Release(t, fixture, result, node.nodeID, fixture.nodeKeys[node.nodeID]).Scope
		if index == 1 && (scope.Streams == nil || len(scope.Streams.StreamsV2) != 1 ||
			!slices.Equal(scope.Streams.StreamsV2[0].AdditionalListeners, compiled.Streams[0].AdditionalListeners)) {
			t.Fatalf("published extras lost: %+v", scope.Streams)
		}
		if index >= 3 && scope.Streams != nil {
			t.Fatalf("removal retained L4 streams: %+v", scope.Streams)
		}
		replayed, err := fixture.service.Publish(t.Context(), request)
		if err != nil || !replayed.Replayed || replayed.ArtifactSHA256 != result.ArtifactSHA256 {
			t.Fatalf("publication replay changed artifact: %v", err)
		}
		readHistory(&historyAfter)
		if !bytes.Equal(historyBefore, historyAfter) {
			t.Fatal("publication mutated listener history")
		}
	}
	tx, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	bounded, err := loadL4V2LifecycleProtocols(t.Context(), tx, fixture.scopeID, firstRevision)
	if err != nil || !slices.Equal(bounded, []l4ProtocolCapability{{"tcp", 2}}) {
		t.Fatalf("future extras escaped revision: %v %v", bounded, err)
	}
	foreign, err := loadL4V2LifecycleProtocols(t.Context(), tx, fixture.platformScopeID, fixture.sourceRevision())
	if err != nil || len(foreign) != 0 {
		t.Fatalf("foreign scope inherited listener capabilities: %v %v", foreign, err)
	}
}

// assertL4AdditionalAttribution: the package forward's attribution
// requirement (L4_PACKAGE_ATTRIBUTION v1) is present exactly while it is live.
func assertL4AdditionalAttribution(t *testing.T, capabilities []*agentv1.Capability, live bool) {
	t.Helper()
	var version uint32
	for _, capability := range capabilities {
		if capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_L4_PACKAGE_ATTRIBUTION {
			version = capability.ApiVersion
		}
	}
	if live && version != 1 || !live && version != 0 {
		t.Fatalf("L4_PACKAGE_ATTRIBUTION requirement = %d, live=%v", version, live)
	}
}

func CheckL4AdditionalListenerHealthPort(t *testing.T, mutate func(*pgxpool.Pool, uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID, uint16)) {
	t.Helper()
	fixture := newL4V2ContractFixture(t)
	site := fixture.createSite(t, "additional-health.example.com", 18081, false).Site
	mutate(fixture.pool, fixture.scopeID, fixture.userID, fixture.subscriptionID, site.ID, fixture.service.config.HealthPort)
	if _, err := fixture.service.Publish(t.Context(), fixture.publishRequest("additional-health-conflict", fixture.nodeID)); err == nil {
		t.Fatal("publication accepted a health-port conflict")
	}
	assertPublishState(t, fixture.pool, 0, 0, 0, 0, 0)
}
