package nodemonitoringoutbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/nodemonitoringpublication"
	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
)

func TestNodeMonitoringBackfillUsesCurrentActiveRevision(t *testing.T) {
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "node_monitoring_backfill_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, done := databasetest.CleanupContext()
		defer done()
		if _, err := admin.Exec(cleanup, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop isolated backfill schema: %v", err)
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
	actor := systemconfig.Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform"}
	roleID := uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, []any{actor.ScopeID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'backfill-owner','Backfill owner','test-only')`, []any{actor.UserID}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{actor.ScopeID, actor.UserID}},
		{`INSERT INTO roles(id,scope_id,name,system_role) VALUES($1,$2,'platform_owner',true)`, []any{roleID, actor.ScopeID}},
		{`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'system_configuration.read'),($1,'system_configuration.manage')`, []any{roleID}},
		{`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, []any{actor.ScopeID, actor.UserID, roleID}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Date(2026, 10, 8, 12, 0, 0, 123456000, time.UTC)
	clock := func() time.Time { return now }
	store, err := NewStore(pool, clock)
	if err != nil {
		t.Fatal(err)
	}
	service, err := systemconfig.NewServiceWithDependencies(pool, audit.New(pool), clock)
	if err != nil {
		t.Fatal(err)
	}
	servingConfigID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO config_versions(
		id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,
		generator_name,generator_version,status,idempotency_key,request_digest,created_at,published_at
	) VALUES($1,$2,'serving-config',$3,'backfill-test','1','releasable','backfill-serving-config',$3,$4,$4)`,
		servingConfigID, actor.ScopeID, make([]byte, 32), now); err != nil {
		t.Fatal(err)
	}
	nextDisplayID := 0
	// A node only serves traffic (and therefore has a probe target) after its
	// first signed edge configuration activation recorded current_config_version_id.
	serve := func(id uuid.UUID) {
		t.Helper()
		if _, err := pool.Exec(ctx, `INSERT INTO node_config_state(node_id,configuration_scope_id,current_config_version_id,updated_at)
			VALUES($1,$2,$3,$4)`, id, actor.ScopeID, servingConfigID, now); err != nil {
			t.Fatal(err)
		}
	}
	addBlankNode := func(state string) uuid.UUID {
		t.Helper()
		id := uuid.New()
		nextDisplayID++
		if _, err := pool.Exec(ctx, `INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id)
			VALUES($1,$2,$3,$4,$5,$6)`, id, actor.ScopeID, id.String(), state, actor.UserID, nextDisplayID); err != nil {
			t.Fatal(err)
		}
		return id
	}
	addNode := func(state string) uuid.UUID {
		t.Helper()
		id := addBlankNode(state)
		serve(id)
		return id
	}
	claim := func(limit int) []Command {
		t.Helper()
		commands, err := store.ClaimCommands(ctx, uuid.New(), limit, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		return commands
	}
	addNode("active")
	if commands := claim(32); len(commands) != 0 {
		t.Fatal("bootstrap defaults were published without an active revision")
	}
	activate := func(head int64) systemconfig.Revision {
		t.Helper()
		key := fmt.Sprintf("backfill-%d", head+1)
		draft, err := service.CreateDraft(ctx, actor, systemconfig.CreateDraftRequest{
			ExpectedHeadRevision: head, Configuration: systemconfig.ProjectBootstrapConfiguration(),
			IdempotencyKey: key + "-draft", RequestID: key + "-draft",
		})
		if err != nil {
			t.Fatal(err)
		}
		checks := []systemconfig.PreflightCheck{}
		for _, name := range []string{systemconfig.PreflightSchema, systemconfig.PreflightReferences,
			systemconfig.PreflightCapacity, systemconfig.PreflightNginxSafety, systemconfig.PreflightErrorPages} {
			checks = append(checks, systemconfig.PreflightCheck{Name: name, Status: systemconfig.CheckPass})
		}
		if _, err := service.RecordPreflight(ctx, actor, systemconfig.RecordPreflightRequest{
			Revision: draft.Revision, ExpectedStatus: systemconfig.StatusDraft, SnapshotSHA256: draft.SnapshotSHA256,
			Checks: checks, IdempotencyKey: key + "-preflight", RequestID: key + "-preflight",
		}); err != nil {
			t.Fatal(err)
		}
		active, err := service.Activate(ctx, actor, systemconfig.ActivateRequest{
			Revision: draft.Revision, ExpectedActiveRevision: head,
			IdempotencyKey: key + "-activate", RequestID: key + "-activate",
		})
		if err != nil {
			t.Fatal(err)
		}
		return active
	}
	active := activate(0)
	now = now.Add(time.Hour)
	lateNode := addNode("active")
	for _, state := range []string{"pending", "draining", "disabled", "retired"} {
		addNode(state)
	}
	commands := claim(32)
	if len(commands) != 2 {
		t.Fatalf("current active revision backfill claimed %d commands, want 2 active nodes", len(commands))
	}
	document := systemconfig.CategoryDocument{Schema: "cdnca.system-configuration/v2",
		Category: systemconfig.CategoryNodeMonitoring, HeadRevision: active.Revision,
		ActiveRevision: active.Revision, Revision: active.Revision, Status: systemconfig.StatusActive,
		SnapshotSHA256: active.SnapshotSHA256,
		Value:          systemconfig.EffectiveNodeMonitoring(active.Configuration.NodeMonitoring)}
	for index, command := range commands {
		artifact := new(agentv1.NodeMonitoringArtifact)
		if err := proto.Unmarshal(command.Payload, artifact); err != nil {
			t.Fatal(err)
		}
		want, err := nodemonitoringpublication.BuildArtifact(command.NodeID.String(), document, active.StateChangedAt)
		if err != nil || !proto.Equal(artifact, want) {
			t.Fatalf("backfill changed the original activation artifact: err=%v", err)
		}
		wantPayload, err := (proto.MarshalOptions{Deterministic: true}).Marshal(want)
		if err != nil || !bytes.Equal(command.Payload, wantPayload) {
			t.Fatalf("backfill changed the original deterministic payload: %v", err)
		}
		if index == 0 {
			err = store.MarkPublished(ctx, command, CommandStream, 1)
		} else {
			err = store.FailCommand(ctx, command, "test_permanent_failure")
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	var before []byte
	if err := pool.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(outbox) ORDER BY node_id)::text::bytea
		FROM node_monitoring_command_outbox outbox`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	store, err = NewStore(pool, clock)
	if err != nil {
		t.Fatal(err)
	}
	if commands := claim(32); len(commands) != 0 {
		t.Fatal("restart reopened published or failed commands")
	}
	var after []byte
	if err := pool.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(outbox) ORDER BY node_id)::text::bytea
		FROM node_monitoring_command_outbox outbox`).Scan(&after); err != nil || !bytes.Equal(before, after) {
		t.Fatalf("reconciliation rewrote existing outbox facts: %v", err)
	}
	var activatedAt time.Time
	if err := pool.QueryRow(ctx, `SELECT state_changed_at FROM system_configuration_revisions
		WHERE platform_scope_id=$1 AND revision=$2`, actor.ScopeID, active.Revision).Scan(&activatedAt); err != nil ||
		!activatedAt.Equal(active.StateChangedAt) {
		t.Fatalf("original activation time changed: %v", err)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM node_monitoring_command_outbox WHERE node_id=$1`, lateNode).Scan(&count); err != nil || count != 1 {
		t.Fatalf("late node command count=%d err=%v", count, err)
	}

	// A freshly enrolled node that has never activated a signed edge
	// configuration runs no OpenResty listener. Delivering monitoring to it makes
	// the Agent preflight reject the artifact, which closes the gateway session
	// and redelivers forever, so it must wait until it is actually serving.
	blank := addBlankNode("active")
	if commands := claim(32); len(commands) != 0 {
		t.Fatalf("blank active node received %d monitoring commands before serving a configuration", len(commands))
	}
	bound := addBlankNode("active")
	if _, err := pool.Exec(ctx, `INSERT INTO node_config_state(node_id,configuration_scope_id,updated_at)
		VALUES($1,$2,$3)`, bound, actor.ScopeID, now); err != nil {
		t.Fatal(err)
	}
	if commands := claim(32); len(commands) != 0 {
		t.Fatalf("bound but never activated node received %d monitoring commands", len(commands))
	}
	serve(blank)
	if _, err := pool.Exec(ctx, `UPDATE node_config_state SET current_config_version_id=$2,revision=revision+1
		WHERE node_id=$1`, bound, servingConfigID); err != nil {
		t.Fatal(err)
	}
	commands = claim(32)
	if len(commands) != 2 {
		t.Fatalf("first configuration activation produced %d monitoring commands, want 2", len(commands))
	}
	for _, command := range commands {
		if (command.NodeID != blank && command.NodeID != bound) || command.ConfigRevision != uint64(active.Revision) {
			t.Fatalf("serving backfill claimed unexpected command: %#v", command)
		}
		if err := store.MarkPublished(ctx, command, CommandStream, 1); err != nil {
			t.Fatal(err)
		}
	}
	if commands := claim(32); len(commands) != 0 {
		t.Fatalf("serving backfill was not idempotent: %d commands", len(commands))
	}
	for _, nodeID := range []uuid.UUID{blank, bound} {
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM node_monitoring_command_outbox WHERE node_id=$1`, nodeID).Scan(&count); err != nil || count != 1 {
			t.Fatalf("serving node %s command count=%d err=%v, want exactly one", nodeID, count, err)
		}
	}

	addNode("active")
	addNode("active")
	if err := store.reconcileActiveNodeMonitoring(ctx, 2); err != nil {
		t.Fatal(err)
	}
	inflight := claim(1)
	if len(inflight) != 1 {
		t.Fatalf("claimed %d commands, want one publishing and one still pending", len(inflight))
	}
	if err := pool.QueryRow(ctx, `SELECT count(DISTINCT state) FROM node_monitoring_command_outbox`).Scan(&count); err != nil || count != 4 {
		t.Fatalf("all four outbox states are not covered: %d %v", count, err)
	}
	if err := pool.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(outbox) ORDER BY node_id)::text::bytea
		FROM node_monitoring_command_outbox outbox`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err := store.reconcileActiveNodeMonitoring(ctx, 32); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(outbox) ORDER BY node_id)::text::bytea
		FROM node_monitoring_command_outbox outbox`).Scan(&after); err != nil || !bytes.Equal(before, after) {
		t.Fatalf("reconciliation modified a pending/publishing/terminal command: %v", err)
	}
	for _, command := range append(inflight, claim(1)...) {
		if err := store.MarkPublished(ctx, command, CommandStream, 2); err != nil {
			t.Fatal(err)
		}
	}

	now = now.Add(time.Minute)
	active = activate(active.Revision)
	lateCurrent := addNode("active")
	addNode("active")
	addNode("active")
	commands = claim(2)
	if len(commands) != 2 {
		t.Fatalf("bounded batch claimed %d commands, want 2", len(commands))
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM node_monitoring_command_outbox WHERE config_revision=$1`, active.Revision).Scan(&count); err != nil || count != 2 {
		t.Fatalf("bounded reconciliation inserted %d commands, want 2: %v", count, err)
	}
	if _, err := store.ClaimCommands(ctx, uuid.New(), 129, time.Minute); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("oversized batch was accepted: %v", err)
	}
	seen := map[uuid.UUID]bool{}
	for _, command := range commands {
		seen[command.ID] = true
		if err := store.MarkPublished(ctx, command, CommandStream, 3); err != nil {
			t.Fatal(err)
		}
	}
	start := make(chan struct{})
	results := make(chan []Command, 8)
	failures := make(chan error, 8)
	var workers sync.WaitGroup
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			commands, err := store.ClaimCommands(ctx, uuid.New(), 2, time.Minute)
			if err != nil {
				failures <- err
				return
			}
			results <- commands
		}()
	}
	close(start)
	workers.Wait()
	close(failures)
	close(results)
	for err := range failures {
		t.Fatalf("concurrent reconciliation failed: %v", err)
	}
	for batch := range results {
		for _, command := range batch {
			if seen[command.ID] || command.ConfigRevision != uint64(active.Revision) {
				t.Fatalf("concurrent worker claimed duplicate or stale command: %#v", command)
			}
			seen[command.ID] = true
			if err := store.MarkPublished(ctx, command, CommandStream, 4); err != nil {
				t.Fatal(err)
			}
		}
	}
	if len(seen) != 9 {
		t.Fatalf("concurrent workers claimed %d distinct commands, want 9 serving active nodes", len(seen))
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM node_monitoring_command_outbox
		WHERE node_id=$1 AND config_revision<$2`, lateCurrent, active.Revision).Scan(&count); err != nil || count != 0 {
		t.Fatalf("late node received superseded configuration: %d %v", count, err)
	}
	if commands := claim(32); len(commands) != 0 {
		t.Fatalf("concurrent reconciliation was not idempotent: %d commands", len(commands))
	}

	first, last := addNode("active"), addNode("active")
	if first.String() > last.String() {
		first, last = last, first
	}
	// The second insert fails after the first succeeds, proving the complete
	// batch is rolled back instead of leaving a partially reconciled command set.
	if _, err := pool.Exec(ctx, fmt.Sprintf(`CREATE FUNCTION reject_backfill_test() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.node_id='%s'::uuid THEN RAISE EXCEPTION 'injected backfill failure'; END IF; RETURN NEW; END $$;
		CREATE TRIGGER reject_backfill_test BEFORE INSERT ON node_monitoring_command_outbox
		FOR EACH ROW EXECUTE FUNCTION reject_backfill_test()`, last)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimCommands(ctx, uuid.New(), 2, time.Minute); err == nil {
		t.Fatal("injected reconciliation failure was accepted")
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM node_monitoring_command_outbox
		WHERE node_id=ANY($1::uuid[])`, []uuid.UUID{first, last}).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed batch left partial outbox facts: %d %v", count, err)
	}
	if _, err := pool.Exec(ctx, `DROP TRIGGER reject_backfill_test ON node_monitoring_command_outbox;
		DROP FUNCTION reject_backfill_test()`); err != nil {
		t.Fatal(err)
	}
	if commands := claim(2); len(commands) != 2 {
		t.Fatalf("reconciliation did not recover from transaction failure: %d commands", len(commands))
	}
}
