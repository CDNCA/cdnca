//go:build integration

package edgepublish

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CheckL4GuardRulesPublication saves a stream with geo guard rules, with
// client IP rules and without rules through save and checks the artifact
// and the required capabilities (tcp v12 for every live stream since the
// 1.0.35 baseline, l4StreamCapabilityVersion; IP_INTEL v2 only for geo).
func CheckL4GuardRulesPublication(t *testing.T, save func(pool *pgxpool.Pool, scopeID, userID, subscriptionID, siteID uuid.UUID, rules []edgeconfig.L4GuardRuleV2) int64) {
	fixture := newL4DrainLimitFixture(t)
	site := fixture.createSite(t, "l4-guard.example.com", 18083, false).Site
	compile := func(revision int64) ([]edgeconfig.L4GuardRuleV2, uint32, uint32) {
		t.Helper()
		tx, err := fixture.pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(t.Context())
		compiled := fixture.compileSiteRuntimeL4(t, tx, revision)
		bundle, capabilities := compiled.Bundle(), compiled.Capabilities
		var wire struct {
			Streams []edgeconfig.L4StreamRuntimeV2 `json:"streams"`
		}
		if err := json.Unmarshal(bundle.Files[edgeconfig.L4RuntimeV2ArtifactPath], &wire); err != nil || len(wire.Streams) != 1 {
			t.Fatalf("L4 artifact: %+v %v", wire, err)
		}
		tcp, intel := uint32(0), uint32(0)
		for _, capability := range capabilities {
			switch capability.Name.String() {
			case "CAPABILITY_NAME_TCP_PROXY":
				tcp = capability.ApiVersion
			case "CAPABILITY_NAME_IP_INTEL":
				intel = capability.ApiVersion
			}
		}
		return wire.Streams[0].GuardRules, tcp, intel
	}
	geo := []edgeconfig.L4GuardRuleV2{
		{ID: "66666666-6666-4666-8666-666666666661", Action: edgeconfig.L4GuardActionAllow,
			ClientIP: &edgeconfig.L4GuardClientIP{CIDRs: []string{"192.0.2.0/24"}}},
		{ID: "66666666-6666-4666-8666-666666666662", Action: edgeconfig.L4GuardActionBan, BanSeconds: 600, Threshold: 5, WindowSeconds: 60,
			Geo: []edgeconfig.WAFIPIntel{{Field: edgeconfig.WAFIPIntelTag, Values: []string{"idc:global"}}}},
	}
	if rules, tcp, intel := compile(save(fixture.pool, fixture.scopeID, fixture.userID, fixture.subscriptionID, site.ID, geo)); len(rules) != 2 ||
		rules[0].Action != edgeconfig.L4GuardActionAllow || rules[1].Threshold != 5 || tcp != 12 || intel != edgeconfig.IPIntelCapabilityVersion {
		t.Fatalf("geo guarded stream: tcp v%d ip_intel v%d rules=%+v", tcp, intel, rules)
	}
	for name, mutation := range map[string]string{
		"not an array": `'{}'`, "empty": `'[]'`, "no condition": `'[{"id":"66666666-6666-4666-8666-666666666663","action":"drop"}]'`,
		"ban without threshold": `'[{"id":"66666666-6666-4666-8666-666666666663","action":"ban","ban_seconds":5,"client_ip":{"cidrs":["192.0.2.0/24"]}}]'`,
	} {
		_, err := fixture.pool.Exec(t.Context(), `INSERT INTO l4_publish_intents(id,scope_id,stream_id,version,operation,
			desired_state,resource_revision,configuration_source_revision,runtime_spec,created_by_user_id,created_at)
			SELECT gen_random_uuid(),scope_id,stream_id,version+1000,operation,desired_state,resource_revision,
			       configuration_source_revision,jsonb_set(runtime_spec,'{guard_rules}',`+mutation+`::jsonb),created_by_user_id,now()
			FROM l4_publish_intents WHERE scope_id=$1 AND runtime_spec ? 'guard_rules' ORDER BY version DESC LIMIT 1`, fixture.scopeID)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.ConstraintName != l4RuntimeSpecConstraint {
			t.Errorf("intent with guard_rules %s: err=%v", name, err)
		}
	}
	if rules, tcp, intel := compile(save(fixture.pool, fixture.scopeID, fixture.userID, fixture.subscriptionID, site.ID, geo[:1])); len(rules) != 1 ||
		tcp != 12 || intel != 0 {
		t.Fatalf("client IP guarded stream: tcp v%d ip_intel v%d rules=%+v", tcp, intel, rules)
	}
	if rules, tcp, intel := compile(save(fixture.pool, fixture.scopeID, fixture.userID, fixture.subscriptionID, site.ID, nil)); rules != nil || tcp != 12 || intel != 0 {
		t.Fatalf("unguarded stream: tcp v%d ip_intel v%d rules=%+v", tcp, intel, rules)
	}
}

// G4-d against the real schema: geo guard rules on an L4 stream go through
// the same library readiness gate as WAF IP intelligence rules (a node that
// never applied a verified library is refused); client IP rules do not.
func TestL4GeoGuardRulesWaitForTheIPIntelLibrary(t *testing.T) {
	fixture := newPublishFixture(t)
	stream := edgeconfig.L4StreamRuntimeV2{Listener: edgeconfig.L4ListenerV2{Protocol: "tcp", Address: "*", Port: 18443},
		GuardRules: []edgeconfig.L4GuardRuleV2{{ID: "66666666-6666-4666-8666-666666666661", Action: edgeconfig.L4GuardActionDrop,
			Geo: []edgeconfig.WAFIPIntel{{Field: edgeconfig.WAFIPIntelCountry, Values: []string{"US"}}}}}}
	validate := func(stream edgeconfig.L4StreamRuntimeV2) error {
		var required []*agentv1.Capability
		for _, capability := range siteRuntimeV2StreamsRequired([]edgeconfig.L4StreamRuntimeV2{stream}) {
			if capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_IP_INTEL {
				required = append(required, capability) // the gate under test, without tcp v10
			}
		}
		var err error
		if txErr := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
			err = ValidateFeatureCapabilityTargets(t.Context(), tx, []uuid.UUID{fixture.nodeID}, required)
			return nil
		}); txErr != nil {
			t.Fatal(txErr)
		}
		return err
	}
	var refusal *TargetCapabilityError
	if err := validate(stream); !errors.As(err, &refusal) || refusal.NodeID != fixture.nodeID || !refusal.ipIntelLibraryPending() ||
		!strings.Contains(err.Error(), "IP intelligence library") {
		t.Fatalf("geo guard rule without a library: %v", err)
	}
	stream.GuardRules[0].Geo = nil
	stream.GuardRules[0].ClientIP = &edgeconfig.L4GuardClientIP{CIDRs: []string{"192.0.2.0/24"}}
	if err := validate(stream); err != nil {
		t.Fatalf("client IP guard rule: %v", err)
	}
}
