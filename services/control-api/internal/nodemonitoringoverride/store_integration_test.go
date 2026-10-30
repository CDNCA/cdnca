package nodemonitoringoverride

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/nodemonitoringoutbox"
	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
)

type overrideHarness struct {
	t        *testing.T
	ctx      context.Context
	pool     *pgxpool.Pool
	actor    Actor
	now      time.Time
	store    *Store
	outbox   *nodemonitoringoutbox.Store
	config   *systemconfig.Service
	configID uuid.UUID
	display  int
}

func newOverrideHarness(t *testing.T) *overrideHarness {
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	t.Cleanup(cancel)
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "node_monitoring_override_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, done := databasetest.CleanupContext()
		defer done()
		if _, err := admin.Exec(cleanup, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop isolated override schema: %v", err)
		}
	})
	config, err := pgxpool.ParseConfig(databaseURL)
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
		t.Fatal(err)
	}
	harness := &overrideHarness{t: t, ctx: ctx, pool: pool, actor: Actor{UserID: uuid.New(), ScopeID: uuid.New()},
		now: time.Date(2026, 10, 13, 8, 0, 0, 0, time.UTC), configID: uuid.New()}
	roleID := uuid.New()
	harness.exec(`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, harness.actor.ScopeID)
	harness.exec(`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'override-owner','Override owner','test-only')`, harness.actor.UserID)
	harness.exec(`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, harness.actor.ScopeID, harness.actor.UserID)
	harness.exec(`INSERT INTO roles(id,scope_id,name,system_role) VALUES($1,$2,'platform_owner',true)`, roleID, harness.actor.ScopeID)
	harness.exec(`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'system_configuration.read'),($1,'system_configuration.manage')`, roleID)
	harness.exec(`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, harness.actor.ScopeID, harness.actor.UserID, roleID)
	harness.exec(`INSERT INTO config_versions(id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,
		generator_name,generator_version,status,idempotency_key,request_digest,created_at,published_at)
		VALUES($1,$2,'serving-config',$3,'override-test','1','releasable','override-serving-config',$3,$4,$4)`,
		harness.configID, harness.actor.ScopeID, make([]byte, 32), harness.now)
	clock := func() time.Time { return harness.now }
	if harness.store, err = NewStore(pool, clock); err != nil {
		t.Fatal(err)
	}
	if harness.outbox, err = nodemonitoringoutbox.NewStore(pool, clock); err != nil {
		t.Fatal(err)
	}
	if harness.config, err = systemconfig.NewServiceWithDependencies(pool, audit.New(pool), clock); err != nil {
		t.Fatal(err)
	}
	return harness
}

func (harness *overrideHarness) exec(query string, args ...any) {
	harness.t.Helper()
	if _, err := harness.pool.Exec(harness.ctx, query, args...); err != nil {
		harness.t.Fatal(err)
	}
}

func (harness *overrideHarness) addNode(serving bool) uuid.UUID {
	harness.t.Helper()
	id := uuid.New()
	harness.display++
	harness.exec(`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id) VALUES($1,$2,$3,'active',$4,$5)`,
		id, harness.actor.ScopeID, id.String(), harness.actor.UserID, harness.display)
	if serving {
		harness.serve(id)
	}
	return id
}

func (harness *overrideHarness) serve(id uuid.UUID) {
	harness.t.Helper()
	harness.exec(`INSERT INTO node_config_state(node_id,configuration_scope_id,current_config_version_id,updated_at)
		VALUES($1,$2,$3,$4)`, id, harness.actor.ScopeID, harness.configID, harness.now)
}

func (harness *overrideHarness) activate(head int64, interval int) {
	harness.t.Helper()
	actor := systemconfig.Actor{UserID: harness.actor.UserID, ScopeID: harness.actor.ScopeID, ScopeKind: "platform"}
	key := fmt.Sprintf("override-%d", head+1)
	configuration := systemconfig.ProjectBootstrapConfiguration()
	monitoring := systemconfig.EffectiveNodeMonitoring(configuration.NodeMonitoring)
	monitoring.ProbeIntervalMS = interval
	configuration.NodeMonitoring = &monitoring
	draft, err := harness.config.CreateDraft(harness.ctx, actor, systemconfig.CreateDraftRequest{
		ExpectedHeadRevision: head, Configuration: configuration, IdempotencyKey: key + "-draft", RequestID: key + "-draft",
	})
	if err != nil {
		harness.t.Fatal(err)
	}
	checks := []systemconfig.PreflightCheck{}
	for _, name := range []string{systemconfig.PreflightSchema, systemconfig.PreflightReferences,
		systemconfig.PreflightCapacity, systemconfig.PreflightNginxSafety, systemconfig.PreflightErrorPages} {
		checks = append(checks, systemconfig.PreflightCheck{Name: name, Status: systemconfig.CheckPass})
	}
	if _, err := harness.config.RecordPreflight(harness.ctx, actor, systemconfig.RecordPreflightRequest{
		Revision: draft.Revision, ExpectedStatus: systemconfig.StatusDraft, SnapshotSHA256: draft.SnapshotSHA256,
		Checks: checks, IdempotencyKey: key + "-preflight", RequestID: key + "-preflight",
	}); err != nil {
		harness.t.Fatal(err)
	}
	if _, err := harness.config.Activate(harness.ctx, actor, systemconfig.ActivateRequest{
		Revision: draft.Revision, ExpectedActiveRevision: head, IdempotencyKey: key + "-activate", RequestID: key + "-activate",
	}); err != nil {
		harness.t.Fatal(err)
	}
}

type deliveredConfig struct {
	ConfigRevision uint64  `json:"config_revision"`
	MonitorEnabled *bool   `json:"monitor_enabled"`
	Protocol       string  `json:"protocol"`
	ProbeTimeoutMS int     `json:"probe_timeout_ms"`
	MonitorPort    *uint16 `json:"monitor_port"`
}

// claim publishes every due command and returns the delivered configs by node.
func (harness *overrideHarness) claim() map[uuid.UUID][]deliveredConfig {
	harness.t.Helper()
	commands, err := harness.outbox.ClaimCommands(harness.ctx, uuid.New(), 64, time.Minute)
	if err != nil {
		harness.t.Fatal(err)
	}
	result := map[uuid.UUID][]deliveredConfig{}
	for index, command := range commands {
		artifact := new(agentv1.NodeMonitoringArtifact)
		if err := proto.Unmarshal(command.Payload, artifact); err != nil {
			harness.t.Fatal(err)
		}
		var config deliveredConfig
		if err := json.Unmarshal(artifact.CanonicalConfigJson, &config); err != nil || config.ConfigRevision != command.ConfigRevision ||
			artifact.PublicationSequence != command.ConfigRevision {
			harness.t.Fatalf("command revision binding broken: %v", err)
		}
		result[command.NodeID] = append(result[command.NodeID], config)
		if err := harness.outbox.MarkPublished(harness.ctx, command, nodemonitoringoutbox.CommandStream, uint64(index+1)); err != nil {
			harness.t.Fatal(err)
		}
	}
	return result
}

func boolPointer(value bool) *bool        { return &value }
func stringPointer(value string) *string { return &value }
func intPointer(value int) *int          { return &value }

func TestNodeMonitoringOverrideDeliversEffectiveRevisionToServingNodeOnly(t *testing.T) {
	harness := newOverrideHarness(t)
	serving, other, blank := harness.addNode(true), harness.addNode(true), harness.addNode(false)

	// Saved before any platform activation: stored, nothing delivered yet.
	view, replayed, err := harness.store.Put(harness.ctx, harness.actor, PutRequest{NodeID: serving, ExpectedRevision: 0,
		Fields: Fields{MonitorEnabled: boolPointer(true), Protocol: stringPointer("http"), ProbeTimeoutMS: intPointer(5000),
			MonitorPort: intPointer(8080)}, IdempotencyKey: "put-1", RequestID: "request-1"})
	if err != nil || replayed || view.Revision != 1 || view.PlatformState != "unconfigured" || view.EffectiveRevision != nil ||
		view.DeliveryState != "serving" {
		t.Fatalf("pre-activation Put() = %#v, %v, %v", view, replayed, err)
	}
	if delivered := harness.claim(); len(delivered) != 0 {
		t.Fatalf("override delivered without an active platform policy: %v", delivered)
	}

	harness.activate(0, 10_000)
	delivered := harness.claim()
	if len(delivered) != 2 || len(delivered[serving]) != 1 || len(delivered[other]) != 1 || len(delivered[blank]) != 0 {
		t.Fatalf("activation delivered %v", delivered)
	}
	got := delivered[serving][0]
	if got.ConfigRevision != 2 || got.Protocol != "http" || got.ProbeTimeoutMS != 5000 || got.MonitorPort == nil || *got.MonitorPort != 8080 {
		t.Fatalf("overridden node config = %#v", got)
	}
	if plain := delivered[other][0]; plain.ConfigRevision != 1 || plain.Protocol == "http" || plain.MonitorPort != nil {
		t.Fatalf("override leaked to other node: %#v", plain)
	}

	// Changing the override delivers a strictly newer revision to that node only.
	harness.now = harness.now.Add(time.Minute)
	view, _, err = harness.store.Put(harness.ctx, harness.actor, PutRequest{NodeID: serving, ExpectedRevision: 1,
		Fields: Fields{MonitorEnabled: boolPointer(false), Protocol: stringPointer("tcp"), ProbeTimeoutMS: intPointer(3000)},
		IdempotencyKey: "put-2", RequestID: "request-2"})
	if err != nil || view.Revision != 2 || view.EffectiveRevision == nil || *view.EffectiveRevision != 3 ||
		view.EffectivePolicy == nil || view.EffectivePolicy.Enabled || view.EffectivePolicy.RequestedProtocol != "tcp" ||
		view.EffectivePolicy.ProbeTimeoutMS != 3000 || view.EffectivePolicy.RequestedPort != nil || view.EffectiveAction != "none" {
		t.Fatalf("second Put() = %#v, %v", view, err)
	}
	delivered = harness.claim()
	if len(delivered) != 1 || len(delivered[serving]) != 1 || delivered[serving][0].ConfigRevision != 3 ||
		delivered[serving][0].MonitorEnabled == nil || *delivered[serving][0].MonitorEnabled {
		t.Fatalf("override change delivered %v", delivered)
	}
	if again := harness.claim(); len(again) != 0 {
		t.Fatalf("override was redelivered: %v", again)
	}

	// Replaying the same request returns the stored response without a write.
	replay, replayed, err := harness.store.Put(harness.ctx, harness.actor, PutRequest{NodeID: serving, ExpectedRevision: 1,
		Fields: Fields{MonitorEnabled: boolPointer(false), Protocol: stringPointer("tcp"), ProbeTimeoutMS: intPointer(3000)},
		IdempotencyKey: "put-2", RequestID: "request-2b"})
	if err != nil || !replayed || replay.Revision != 2 {
		t.Fatalf("replay = %#v, %v, %v", replay, replayed, err)
	}
	if _, _, err := harness.store.Put(harness.ctx, harness.actor, PutRequest{NodeID: serving, ExpectedRevision: 1,
		Fields: Fields{}, IdempotencyKey: "put-2", RequestID: "request-2c"}); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("reused key with other input: %v", err)
	}
	if _, _, err := harness.store.Put(harness.ctx, harness.actor, PutRequest{NodeID: serving, ExpectedRevision: 1,
		Fields: Fields{}, IdempotencyKey: "put-3", RequestID: "request-3"}); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale revision: %v", err)
	}
	// An unchanged save is a no-op: no revision bump, no redelivery.
	if view, _, err = harness.store.Put(harness.ctx, harness.actor, PutRequest{NodeID: serving, ExpectedRevision: 2,
		Fields: Fields{MonitorEnabled: boolPointer(false), Protocol: stringPointer("tcp"), ProbeTimeoutMS: intPointer(3000)},
		IdempotencyKey: "put-4", RequestID: "request-4"}); err != nil || view.Revision != 2 {
		t.Fatalf("unchanged Put() = %#v, %v", view, err)
	}
	if again := harness.claim(); len(again) != 0 {
		t.Fatalf("unchanged save redelivered: %v", again)
	}

	// A later platform activation keeps the override and stays monotonic.
	harness.activate(1, 10_000)
	delivered = harness.claim()
	if len(delivered) != 2 || delivered[serving][0].ConfigRevision != 4 || delivered[serving][0].Protocol != "tcp" ||
		delivered[other][0].ConfigRevision != 2 {
		t.Fatalf("second activation delivered %v", delivered)
	}

	// Clearing the override still advances the node revision.
	if view, _, err = harness.store.Put(harness.ctx, harness.actor, PutRequest{NodeID: serving, ExpectedRevision: 2,
		Fields: Fields{}, IdempotencyKey: "put-5", RequestID: "request-5"}); err != nil || view.Revision != 3 ||
		*view.EffectiveRevision != 5 || !view.EffectivePolicy.Enabled {
		t.Fatalf("clear Put() = %#v, %v", view, err)
	}
	if delivered = harness.claim(); len(delivered[serving]) != 1 || delivered[serving][0].ConfigRevision != 5 ||
		delivered[serving][0].MonitorEnabled != nil {
		t.Fatalf("clear delivered %v", delivered)
	}

	// A blank node stores its override and receives it once it serves.
	if view, _, err = harness.store.Put(harness.ctx, harness.actor, PutRequest{NodeID: blank, ExpectedRevision: 0,
		Fields: Fields{Protocol: stringPointer("ping")}, IdempotencyKey: "put-6", RequestID: "request-6"}); err != nil ||
		view.DeliveryState != "awaiting_configuration" || *view.EffectiveRevision != 3 {
		t.Fatalf("blank Put() = %#v, %v", view, err)
	}
	if delivered = harness.claim(); len(delivered) != 0 {
		t.Fatalf("blank node received monitoring before serving: %v", delivered)
	}
	harness.serve(blank)
	if delivered = harness.claim(); len(delivered) != 1 || delivered[blank][0].ConfigRevision != 3 || delivered[blank][0].Protocol != "ping" {
		t.Fatalf("serving blank node delivered %v", delivered)
	}

	var audits int
	if err := harness.pool.QueryRow(harness.ctx, `SELECT count(*) FROM audit_events
		WHERE action='node.monitoring_override.update' AND scope_id=$1`, harness.actor.ScopeID).Scan(&audits); err != nil || audits != 4 {
		t.Fatalf("override audits = %d, %v; want 4 changing writes", audits, err)
	}
}

func TestNodeMonitoringOverrideValidation(t *testing.T) {
	harness := newOverrideHarness(t)
	node := harness.addNode(true)
	harness.activate(0, 5_000)
	for name, test := range map[string]struct {
		fields Fields
		want   error
	}{
		"protocol":         {Fields{Protocol: stringPointer("udp")}, ErrInvalidInput},
		"timeout low":      {Fields{ProbeTimeoutMS: intPointer(99)}, ErrInvalidInput},
		"timeout high":     {Fields{ProbeTimeoutMS: intPointer(60_001)}, ErrInvalidInput},
		"timeout interval": {Fields{ProbeTimeoutMS: intPointer(6_000)}, ErrTimeoutTooLong},
		"port low":         {Fields{MonitorPort: intPointer(0)}, ErrInvalidInput},
		"port high":        {Fields{MonitorPort: intPointer(65_536)}, ErrInvalidInput},
		"action":           {Fields{MonitorAction: stringPointer("stop")}, ErrInvalidInput},
	} {
		_, _, err := harness.store.Put(harness.ctx, harness.actor, PutRequest{NodeID: node, Fields: test.fields,
			IdempotencyKey: "invalid-" + strings.ReplaceAll(name, " ", "-"), RequestID: "invalid"})
		if !errors.Is(err, test.want) {
			t.Errorf("%s: error = %v, want %v", name, err, test.want)
		}
	}
	if _, err := harness.store.Get(harness.ctx, Actor{UserID: harness.actor.UserID, ScopeID: uuid.New()}, node); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign scope read: %v", err)
	}
	if _, err := harness.store.Get(harness.ctx, harness.actor, uuid.New()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("absent node read: %v", err)
	}
	view, err := harness.store.Get(harness.ctx, harness.actor, node)
	if err != nil || view.Revision != 0 || view.UpdatedAt != nil || *view.EffectiveRevision != 1 || view.EffectivePolicy.ProbeIntervalMS != 5_000 {
		t.Fatalf("Get() = %#v, %v", view, err)
	}
}
