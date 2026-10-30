//go:build integration

package nodeporttransition

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"
	_ "unsafe"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	_ "github.com/cdnca/cdnca/services/control-api/internal/database"
	migrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

//go:linkname migratePortTransitionTestFS github.com/cdnca/cdnca/services/control-api/internal/database.migrateFS
func migratePortTransitionTestFS(context.Context, *pgxpool.Pool, string, fs.FS) error

func TestPortTransitionDurableStatusReceipts(t *testing.T) {
	pool := portTransitionTestPool(t)
	legacy := seedPortTransition(t, pool)
	if _, err := pool.Exec(t.Context(), `INSERT INTO node_gateway_port_transition_status_events(id,transition_id,node_id,revision,status_revision,state,active_endpoint,certificate_sha256,error_code,event_id,puback_stream,puback_sequence,observed_at)
		VALUES($1,$2,$3,1,1,'failed',$4,$5,'candidate_dial_failed',$6,'legacy_stream',1,now())`, uuid.New(), legacy.ID, legacy.NodeID, legacy.OldEndpoint.Address, legacy.CertificateSHA256, uuid.New()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE node_gateway_port_transitions SET state='failed',status_revision=1,error_code='candidate_dial_failed' WHERE id=$1`, legacy.ID); err != nil {
		t.Fatal(err)
	}
	up, _ := migrations.FS.ReadFile("256_node_port_transition_status_receipts.up.sql")
	down, _ := migrations.FS.ReadFile("256_node_port_transition_status_receipts.down.sql")
	if err := applyPortReceiptTestMigration(t.Context(), pool, string(up)); err != nil {
		t.Fatal(err)
	}
	var legacyHash []byte
	if err := pool.QueryRow(t.Context(), `SELECT payload_sha256 FROM node_gateway_port_transition_status_events WHERE transition_id=$1`, legacy.ID).Scan(&legacyHash); err != nil || legacyHash != nil {
		t.Fatalf("historical receipt digest was fabricated: %x %v", legacyHash, err)
	}
	if err := applyPortReceiptTestMigration(t.Context(), pool, string(down)); err != nil {
		t.Fatalf("historical NULL receipt rollback: %v", err)
	}
	if err := applyPortReceiptTestMigration(t.Context(), pool, string(up)); err != nil {
		t.Fatal(err)
	}
	value := seedPortTransition(t, pool)
	service := NewService(NewPostgresStore(pool, time.Now), time.Now, uuid.New)
	first := portTransitionStatusForTest(value, 1, StateSwitched)
	if _, err := service.ApplyStatus(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	// PostgreSQL rounds observed_at to microseconds; identity must retain the raw payload hash.
	changed := first
	changed.PayloadSHA256 = bytes.Repeat([]byte{7}, 32)
	changed.ObservedAt = first.ObservedAt.Add(time.Nanosecond)
	if _, err := service.ApplyStatus(t.Context(), changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed payload accepted: %v", err)
	}
	for _, change := range []func(*StatusReport){
		func(r *StatusReport) { r.EventID = uuid.New() },
		func(r *StatusReport) { r.NodeID = uuid.New() },
		func(r *StatusReport) { r.CertificateSHA256 = strings.Repeat("b", 64) },
		func(r *StatusReport) { r.ActiveEndpoint.ServerName = "wrong.example.com" },
	} {
		changed := first
		change(&changed)
		if _, err := service.ApplyStatus(t.Context(), changed); err == nil {
			t.Fatal("changed identity accepted")
		}
	}
	action := ActionRequest{TransitionID: value.ID, NodeID: value.NodeID, RequestID: uuid.NewString(), IdempotencyKey: "finalize-receipt"}
	actor := Actor{ScopeID: value.ScopeID, UserID: value.CreatedByUserID}
	if _, err := service.Finalize(t.Context(), actor, action); err != nil {
		t.Fatal(err)
	}
	terminal := portTransitionStatusForTest(value, 2, StateFinalized)
	if _, err := service.ApplyStatus(t.Context(), terminal); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Finalize(t.Context(), actor, action); err != nil {
		t.Fatalf("completed action replay: %v", err)
	}
	changedAction := action
	changedAction.IdempotencyKey = "different"
	if _, err := service.Finalize(t.Context(), actor, changedAction); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed completed action accepted: %v", err)
	}
	first.PubAckSequence = 33
	got, err := service.ApplyStatus(t.Context(), first)
	if err != nil || got.State != StateFinalized || got.StatusRevision != 2 {
		t.Fatalf("late exact replay regressed projection: %+v %v", got, err)
	}
	var failures sync.WaitGroup
	for range 6 {
		failures.Add(1)
		go func() {
			defer failures.Done()
			_, err := service.ApplyStatus(t.Context(), terminal)
			if err != nil {
				t.Errorf("concurrent exact replay: %v", err)
			}
		}()
	}
	failures.Wait()
	var count int
	if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM node_gateway_port_transition_status_events WHERE transition_id=$1", value.ID).Scan(&count); err != nil || count != 2 {
		t.Fatalf("replay inserted receipts: %d %v", count, err)
	}
	if _, err := pool.Exec(t.Context(), "UPDATE node_gateway_port_transition_status_events SET payload_sha256=$1", []byte{1}); err == nil {
		t.Fatal("invalid digest length accepted")
	}
	if err := applyPortReceiptTestMigration(t.Context(), pool, string(down)); err == nil {
		t.Fatal("rollback erased durable identity")
	} else {
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "P2561" {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(t.Context(), "UPDATE node_gateway_port_transition_status_events SET payload_sha256=NULL WHERE status_revision=1"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ApplyStatus(t.Context(), first); !errors.Is(err, ErrConflict) {
		t.Fatalf("legacy NULL receipt inferred as equal: %v", err)
	}
	// Real JetStream processing after rejected and duplicate messages must remain alive.
	connection, js := newPortTransitionTestNATS(t)
	config := DefaultNATSRuntimeConfig()
	config.FetchTimeout = 100 * time.Millisecond
	config.RetryDelay = 20 * time.Millisecond
	runtime, err := NewNATSRuntime(NewPostgresStore(pool, time.Now), service, connection, config, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- runtime.runStatuses(ctx) }()
	defer func() {
		cancel()
		select {
		case <-result:
		case <-time.After(time.Second):
			t.Error("consumer did not stop")
		}
	}()
	status := portTransitionProtoForTest(value, 2, StateFinalized)
	// Use the same terminal identity and original deterministic wire bytes.
	status.Event.EventId = terminal.EventID.String()
	status.Event.OccurredTime = timestamppb.New(terminal.ObservedAt)
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	conflicting := proto.Clone(status).(*agentv1.GatewayPortTransitionStatus)
	conflicting.Event.EventId = uuid.NewString()
	conflictPayload, err := proto.MarshalOptions{Deterministic: true}.Marshal(conflicting)
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{[]byte("malformed"), conflictPayload, payload, payload} {
		if _, err := js.Publish(fmt.Sprintf("%s.%s_%s_2", portTransitionStatusPrefix, value.NodeID, value.ID), data); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		info, err := js.ConsumerInfo(portTransitionStatusStream, portTransitionConsumer)
		if err != nil {
			t.Fatal(err)
		}
		if info.Delivered.Stream >= 4 && info.NumAckPending == 0 && info.NumPending == 0 {
			break
		}
		select {
		case err := <-result:
			result <- err
			t.Fatalf("consumer exited: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("receipts not acknowledged: %+v", info)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func portTransitionProtoForTest(value Transition, revision uint64, state State) *agentv1.GatewayPortTransitionStatus {
	protoState := agentv1.GatewayPortTransitionState_GATEWAY_PORT_TRANSITION_STATE_SWITCHED
	if state == StateFinalized {
		protoState = agentv1.GatewayPortTransitionState_GATEWAY_PORT_TRANSITION_STATE_FINALIZED
	}
	return &agentv1.GatewayPortTransitionStatus{Schema: agentv1.GatewayPortTransitionSchema_GATEWAY_PORT_TRANSITION_SCHEMA_V1, TransitionId: value.ID.String(), NodeId: value.NodeID.String(), Revision: 1, StatusRevision: revision, State: protoState, ActiveEndpoint: &agentv1.GatewayEndpoint{Address: value.NewEndpoint.Address, ServerName: value.NewEndpoint.ServerName}, CertificateSha256: value.CertificateSHA256, Event: &commonv1.EventMetadata{EventId: uuid.NewString(), OccurredTime: timestamppb.New(time.Date(2026, 9, 28, 8, 0, 0, 123456789, time.UTC))}}
}
func portTransitionStatusForTest(value Transition, revision uint64, state State) StatusReport {
	status := portTransitionProtoForTest(value, revision, state)
	payload, _ := proto.MarshalOptions{Deterministic: true}.Marshal(status)
	hash := sha256.Sum256(payload)
	return StatusReport{TransitionID: value.ID, NodeID: value.NodeID, Revision: 1, StatusRevision: revision, State: state, ActiveEndpoint: value.NewEndpoint, CertificateSHA256: value.CertificateSHA256, EventID: uuid.MustParse(status.Event.EventId), ObservedAt: status.Event.OccurredTime.AsTime(), PubAckStream: portTransitionStatusStream, PubAckSequence: revision, PayloadSHA256: hash[:]}
}

func seedPortTransition(t *testing.T, pool *pgxpool.Pool) Transition {
	t.Helper()
	scope, user, node, id := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	var existingScope uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&existingScope); err == nil {
		scope = existingScope
	} else if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO access_scopes(id,kind) VALUES($1,'platform') ON CONFLICT(id) DO NOTHING`, []any{scope}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'Port test','unused')`, []any{user, user.String()}},
		{`WITH allocated AS (INSERT INTO node_display_id_sequences(scope_id,next_value) VALUES($2,2) ON CONFLICT(scope_id) DO UPDATE SET next_value=node_display_id_sequences.next_value+1 RETURNING next_value-1 AS display_id) INSERT INTO nodes(id,scope_id,name,created_by_user_id,display_id) SELECT $1,$2,$4,$3,display_id FROM allocated`, []any{node, scope, user, node.String()}},
		{`INSERT INTO node_gateway_port_transitions(id,scope_id,node_id,revision,expected_node_revision,old_endpoint,new_endpoint,server_name,old_listen_address,new_listen_address,compatibility_deadline,rollback_deadline,certificate_sha256,state,status_revision,active_endpoint,request_id,idempotency_key,request_sha256,created_by_user_id,created_at,updated_at)
   VALUES($1,$2,$3,1,1,'gateway.example.com:7443','gateway.example.com:8443','gateway.example.com','0.0.0.0:7443','0.0.0.0:8443',$4,$5,$6,'switching',0,'gateway.example.com:7443',$7,$7,decode(repeat('a',64),'hex'),$8,$9,$9)`, []any{id, scope, node, now.Add(time.Hour), now.Add(2 * time.Hour), strings.Repeat("a", 64), uuid.NewString(), user, now}},
	} {
		if _, err := pool.Exec(t.Context(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	value, err := NewPostgresStore(pool, time.Now).Get(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func portTransitionTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is required")
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "port_receipts_256_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	var pool *pgxpool.Pool
	t.Cleanup(func() {
		if pool != nil {
			pool.Close()
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := dropPortTransitionTestSchema(ctx, admin, schema); err != nil {
			t.Errorf("drop isolated schema %s: %v", schema, err)
		}
		admin.Close()
	})
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err = pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	// Exercise the real base chain; the parent release integrates independently owned 254/255.
	source := fstest.MapFS{}
	for version := 1; version <= 253; version++ {
		for _, direction := range []string{"up", "down"} {
			names, err := fs.Glob(migrations.FS, fmt.Sprintf("%03d_*.%s.sql", version, direction))
			if err != nil || len(names) != 1 {
				t.Fatalf("migration %d: %v %v", version, names, err)
			}
			content, err := migrations.FS.ReadFile(names[0])
			if err != nil {
				t.Fatal(err)
			}
			source[names[0]] = &fstest.MapFile{Data: content}
		}
	}
	if err := migratePortTransitionTestFS(t.Context(), pool, "up", source); err != nil {
		t.Fatal(err)
	}
	return pool
}

func applyPortReceiptTestMigration(ctx context.Context, pool *pgxpool.Pool, sql string) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, sql); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func dropPortTransitionTestSchema(ctx context.Context, pool *pgxpool.Pool, schema string) error {
	if !strings.HasPrefix(schema, "port_receipts_256_") {
		return errors.New("invalid test schema")
	}
	// Release relation locks between tables so a full migration chain can be cleaned
	// on the same bounded PostgreSQL instance used by other test packages.
	rows, err := pool.Query(ctx, `SELECT tablename FROM pg_tables WHERE schemaname=$1 ORDER BY tablename`, schema)
	if err != nil {
		return err
	}
	var tables []string
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			rows.Close()
			return err
		}
		tables = append(tables, table)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, table := range tables {
		if _, err := pool.Exec(ctx, "DROP TABLE IF EXISTS "+pgx.Identifier{schema, table}.Sanitize()+" CASCADE"); err != nil {
			return err
		}
	}
	_, err = pool.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
	return err
}
