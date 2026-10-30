//go:build integration

package nodeporttransition

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/fs"
	"math/big"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
)

func TestPortCreateUsesDERCertificateIdentity(t *testing.T) {
	f := newPortCreateReplayFixture(t)
	first, err := f.service.Create(t.Context(), f.actor, f.request)
	if err != nil {
		t.Fatal(err)
	}
	if first.CertificateSHA256 != f.derHash {
		t.Fatalf("fresh transition certificate=%q, want DER %q", first.CertificateSHA256, f.derHash)
	}
	var stored string
	var payload []byte
	var payloadDigest []byte
	if err := f.pool.QueryRow(t.Context(), `SELECT t.certificate_sha256,o.payload,o.payload_sha256
		FROM node_gateway_port_transitions t JOIN node_gateway_port_transition_command_outbox o ON o.transition_id=t.id
		WHERE t.id=$1`, first.ID).Scan(&stored, &payload, &payloadDigest); err != nil {
		t.Fatal(err)
	}
	command := new(agentv1.GatewayPortTransitionCommand)
	if err := proto.Unmarshal(payload, command); err != nil {
		t.Fatal(err)
	}
	if stored != f.derHash || command.CertificateSha256 != f.derHash {
		t.Fatalf("fresh transition/outbox certificate stored=%q command=%q want DER %q", stored, command.CertificateSha256, f.derHash)
	}
	payloadSum := sha256.Sum256(payload)
	if hex.EncodeToString(payloadSum[:]) != hex.EncodeToString(payloadDigest) {
		t.Fatalf("outbox payload digest=%x does not match payload=%x", payloadDigest, payloadSum)
	}
	before := f.facts(t)
	for name, certificate := range map[string]string{"PEM": f.pemHash, "other": strings.Repeat("f", 64)} {
		t.Run(name, func(t *testing.T) {
			request := f.request
			request.CertificateSHA256 = certificate
			request.RequestID, request.IdempotencyKey = uuid.NewString(), uuid.NewString()
			if _, err := f.service.Create(t.Context(), f.actor, request); !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("certificate=%q got %v, want ErrUnauthenticated", certificate, err)
			}
			if f.facts(t) != before {
				t.Fatal("rejected explicit certificate changed durable facts")
			}
		})
	}
	if _, err := f.pool.Exec(t.Context(), `UPDATE node_gateway_port_transitions SET state='finalized',active_endpoint=new_endpoint WHERE id=$1`, first.ID); err != nil {
		t.Fatal(err)
	}
	request := f.request
	request.CertificateSHA256 = f.derHash
	request.RequestID, request.IdempotencyKey = uuid.NewString(), uuid.NewString()
	second, err := f.service.Create(t.Context(), f.actor, request)
	if err != nil || second.CertificateSHA256 != f.derHash {
		t.Fatalf("explicit DER create=%+v err=%v", second, err)
	}
}

func TestPortCreatePreservesHistoricalPEMReceiptAndRejectsDERStatus(t *testing.T) {
	f := newPortCreateReplayFixture(t)
	request := f.request
	historicalID := uuid.New()
	createdAt := f.now()
	requestDigestInput := struct {
		NodeID                uuid.UUID `json:"node_id"`
		ExpectedNodeRevision  int64     `json:"expected_node_revision"`
		OldEndpoint           Endpoint  `json:"old_endpoint"`
		NewEndpoint           Endpoint  `json:"new_endpoint"`
		CompatibilityDeadline time.Time `json:"compatibility_deadline"`
		RollbackDeadline      time.Time `json:"rollback_deadline"`
		CertificateSHA256     string    `json:"certificate_sha256"`
	}{request.NodeID, request.ExpectedNodeRevision, request.OldEndpoint, request.NewEndpoint,
		request.CompatibilityDeadline.UTC(), request.RollbackDeadline.UTC(), request.CertificateSHA256}
	encoded, err := json.Marshal(requestDigestInput)
	if err != nil {
		t.Fatal(err)
	}
	requestDigest := sha256.Sum256(encoded)
	historical := Transition{ID: historicalID, ScopeID: f.actor.ScopeID, NodeID: request.NodeID, Revision: 1,
		ExpectedNodeRevision: request.ExpectedNodeRevision, OldEndpoint: request.OldEndpoint, NewEndpoint: request.NewEndpoint,
		CompatibilityDeadline: request.CompatibilityDeadline, RollbackDeadline: request.RollbackDeadline,
		CertificateSHA256: f.pemHash, State: StatePreparing, ActiveEndpoint: request.OldEndpoint,
		RequestID: request.RequestID, IdempotencyKey: request.IdempotencyKey, CreatedByUserID: f.actor.UserID,
		CreatedAt: createdAt, UpdatedAt: createdAt}
	tx, err := f.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(t.Context(), `INSERT INTO node_gateway_port_transitions(
		id,scope_id,node_id,revision,expected_node_revision,old_endpoint,new_endpoint,server_name,
		old_listen_address,new_listen_address,compatibility_deadline,rollback_deadline,certificate_sha256,
		state,status_revision,active_endpoint,error_code,request_id,idempotency_key,request_sha256,
		created_by_user_id,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,0,$6,'',$15,$16,$17,$18,$19,$19)`,
		historical.ID, historical.ScopeID, historical.NodeID, historical.Revision, historical.ExpectedNodeRevision,
		historical.OldEndpoint.Address, historical.NewEndpoint.Address, historical.OldEndpoint.ServerName,
		historical.OldEndpoint.ListenAddress, historical.NewEndpoint.ListenAddress, historical.CompatibilityDeadline,
		historical.RollbackDeadline, historical.CertificateSHA256, historical.State, historical.RequestID,
		historical.IdempotencyKey, requestDigest[:], historical.CreatedByUserID, historical.CreatedAt)
	if err != nil {
		_ = tx.Rollback(t.Context())
		t.Fatal(err)
	}
	if err := insertCommandOutbox(t.Context(), tx, historical, ActionSwitch, historical.RequestID, historical.IdempotencyKey, historical.CreatedAt); err != nil {
		_ = tx.Rollback(t.Context())
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	var originalPayload []byte
	if err := f.pool.QueryRow(t.Context(), `SELECT payload FROM node_gateway_port_transition_command_outbox WHERE transition_id=$1`, historical.ID).Scan(&originalPayload); err != nil {
		t.Fatal(err)
	}
	command := new(agentv1.GatewayPortTransitionCommand)
	if err := proto.Unmarshal(originalPayload, command); err != nil || command.CertificateSha256 != f.pemHash {
		t.Fatalf("historical command lost PEM certificate identity: %v", err)
	}
	f.clock.Store(request.RollbackDeadline.Add(time.Hour).UnixNano())
	if _, err := f.pool.Exec(t.Context(), `UPDATE nodes SET revision=revision+1 WHERE id=$1`, request.NodeID); err != nil {
		t.Fatal(err)
	}
	before := f.facts(t)
	got, err := f.service.Create(t.Context(), f.actor, request)
	if err != nil || got.ID != historical.ID || got.CertificateSHA256 != f.pemHash {
		t.Fatalf("historical PEM replay=%+v err=%v", got, err)
	}
	if f.facts(t) != before {
		t.Fatal("historical replay changed transition or outbox bytes")
	}
	var replayedPayload []byte
	if err := f.pool.QueryRow(t.Context(), `SELECT payload FROM node_gateway_port_transition_command_outbox WHERE transition_id=$1`, historical.ID).Scan(&replayedPayload); err != nil || !bytes.Equal(originalPayload, replayedPayload) {
		t.Fatalf("historical outbox bytes changed: %v", err)
	}
	reported := historical
	reported.CertificateSHA256 = f.derHash
	report := portTransitionStatusForTest(reported, 1, StateSwitched)
	if _, err := f.service.ApplyStatus(t.Context(), report); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("DER status against historical PEM transition got %v, want ErrUnauthenticated", err)
	}
	if _, err := f.service.store.(*PostgresStore).ApplyStatus(t.Context(), report); !errors.Is(err, ErrConflict) {
		t.Fatalf("Store accepted DER status against historical PEM transition: %v", err)
	}
	var statusEvents int
	if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM node_gateway_port_transition_status_events WHERE transition_id=$1`, historical.ID).Scan(&statusEvents); err != nil || statusEvents != 0 {
		t.Fatalf("rejected DER status inserted events=%d err=%v", statusEvents, err)
	}
	if f.facts(t) != before {
		t.Fatal("rejected DER status changed historical facts")
	}
}

func TestPortCreateReplaysAfterWindowExpires(t *testing.T) {
	f := newPortCreateReplayFixture(t)
	first, err := f.service.Create(t.Context(), f.actor, f.request)
	if err != nil {
		t.Fatal(err)
	}
	before := f.facts(t)
	for _, at := range []time.Time{
		f.request.CompatibilityDeadline.Add(-time.Minute),
		f.request.CompatibilityDeadline.Add(-time.Minute + time.Nanosecond),
		f.request.CompatibilityDeadline,
		f.request.CompatibilityDeadline.Add(time.Second),
		f.request.RollbackDeadline.Add(time.Second),
	} {
		t.Run(at.Format(time.RFC3339Nano), func(t *testing.T) {
			f.clock.Store(at.UnixNano())
			samples := f.storeSamples.Load()
			got, err := f.service.Create(t.Context(), f.actor, f.request)
			if err != nil || got.ID != first.ID || got.RequestID != first.RequestID || got.CreatedByUserID != first.CreatedByUserID || !got.CreatedAt.Equal(first.CreatedAt) || got.CertificateSHA256 != first.CertificateSHA256 {
				t.Fatalf("historical replay=%+v err=%v", got, err)
			}
			if f.storeSamples.Load() != samples || f.facts(t) != before {
				t.Fatal("replay sampled the fresh-create clock or changed durable facts")
			}
		})
	}
	changed := f.request
	changed.NewEndpoint.Address = "gateway.example.com:9443"
	changed.NewEndpoint.ListenAddress = "0.0.0.0:9443"
	if _, err := f.service.Create(t.Context(), f.actor, changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed expired replay error=%v, want conflict", err)
	}
	fresh := f.request
	fresh.IdempotencyKey, fresh.RequestID = uuid.NewString(), uuid.NewString()
	if _, err := f.service.Create(t.Context(), f.actor, fresh); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expired fresh create error=%v, want invalid input", err)
	}
	if f.facts(t) != before {
		t.Fatal("failed changed replay or expired fresh create changed durable facts")
	}
}

func TestPortCreateReplayPreservesExistingIdentitySemantics(t *testing.T) {
	f := newPortCreateReplayFixture(t)
	first, err := f.service.Create(t.Context(), f.actor, f.request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(t.Context(), `UPDATE nodes SET revision=revision+1 WHERE id=$1`, f.request.NodeID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(t.Context(), `UPDATE node_gateway_port_transitions SET state='finalized',active_endpoint=new_endpoint,status_revision=1 WHERE id=$1`, first.ID); err != nil {
		t.Fatal(err)
	}
	before := f.facts(t)
	f.clock.Store(f.request.RollbackDeadline.Add(time.Second).UnixNano())
	actor, request := f.actor, f.request
	actor.UserID, request.RequestID = uuid.New(), uuid.NewString()
	got, err := f.service.Create(t.Context(), actor, request)
	if err != nil || got.ID != first.ID || got.State != StateFinalized || got.RequestID != first.RequestID || got.CreatedByUserID != first.CreatedByUserID || got.CertificateSHA256 != first.CertificateSHA256 {
		t.Fatalf("scope/key/payload replay lost original identity or current projection: %+v %v", got, err)
	}
	request.CertificateSHA256 = strings.Repeat("f", 64)
	if _, err := f.service.Create(t.Context(), actor, request); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed certificate payload error=%v, want conflict", err)
	}
	if f.facts(t) != before {
		t.Fatal("identity replay changed durable transition/outbox")
	}
}

func TestPortCreateRechecksWindowAfterNodeLock(t *testing.T) {
	for _, expired := range []bool{false, true} {
		name := "less_than_minimum"
		if expired {
			name = "expired"
		}
		t.Run(name, func(t *testing.T) {
			f := newPortCreateReplayFixture(t)
			blocker, err := f.pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer blocker.Rollback(t.Context())
			var blockerPID int
			if err := blocker.QueryRow(t.Context(), `SELECT pg_backend_pid() FROM nodes n JOIN node_certificates c ON c.node_id=n.id WHERE n.id=$1 FOR UPDATE OF n,c`, f.request.NodeID).Scan(&blockerPID); err != nil {
				t.Fatal(err)
			}
			before := f.facts(t)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			result := make(chan error, 1)
			go func() { _, err := f.service.Create(ctx, f.actor, f.request); result <- err }()
			waitPortCreateBlocked(t, f.pool, blockerPID, 1)
			if f.storeSamples.Load() != 0 {
				t.Fatal("Store clock sampled before acquiring node/certificate locks")
			}
			at := f.request.CompatibilityDeadline.Add(-time.Minute + time.Nanosecond)
			if expired {
				at = f.request.CompatibilityDeadline
			}
			f.clock.Store(at.UnixNano())
			if err := blocker.Commit(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := <-result; !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("fresh create after lock wait error=%v, want invalid input", err)
			}
			if f.storeSamples.Load() != 1 || f.facts(t) != before {
				t.Fatalf("expired create samples=%d or changed durable facts", f.storeSamples.Load())
			}
		})
	}
}

func TestPortCreateFreshWindowBoundaries(t *testing.T) {
	f := newPortCreateReplayFixture(t)
	for _, test := range []struct {
		name          string
		compat, retry time.Duration
		valid         bool
	}{
		{"minimum", time.Minute, time.Hour, true},
		{"below_minimum", time.Minute - time.Nanosecond, time.Hour, false},
		{"maximum_compatibility", 24 * time.Hour, 48 * time.Hour, true},
		{"above_maximum_compatibility", 24*time.Hour + time.Nanosecond, 48 * time.Hour, false},
		{"maximum_rollback", time.Hour, 48 * time.Hour, true},
		{"above_maximum_rollback", time.Hour, 48*time.Hour + time.Nanosecond, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := f.request
			request.IdempotencyKey, request.RequestID = uuid.NewString(), uuid.NewString()
			request.CompatibilityDeadline, request.RollbackDeadline = f.now().Add(test.compat), f.now().Add(test.retry)
			before := f.facts(t)
			got, err := f.service.Create(t.Context(), f.actor, request)
			if !test.valid {
				if !errors.Is(err, ErrInvalidInput) || f.facts(t) != before {
					t.Fatalf("invalid boundary error=%v or changed durable facts", err)
				}
				return
			}
			if err != nil || got.ID == uuid.Nil || !got.CreatedAt.Equal(f.now()) {
				t.Fatalf("valid boundary result=%+v err=%v", got, err)
			}
			if _, err := f.pool.Exec(t.Context(), `UPDATE node_gateway_port_transitions SET state='finalized',active_endpoint=new_endpoint WHERE id=$1`, got.ID); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPortCreateConcurrentStoredReplay(t *testing.T) {
	f := newPortCreateReplayFixture(t)
	first, err := f.service.Create(t.Context(), f.actor, f.request)
	if err != nil {
		t.Fatal(err)
	}
	before := f.facts(t)
	f.clock.Store(f.request.RollbackDeadline.Add(time.Second).UnixNano())
	var workers sync.WaitGroup
	for range 6 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			got, err := f.service.Create(t.Context(), f.actor, f.request)
			if err != nil || got.ID != first.ID {
				t.Errorf("stored concurrent replay ID=%s err=%v", got.ID, err)
			}
		}()
	}
	workers.Wait()
	if f.facts(t) != before {
		t.Fatal("concurrent stored replays changed durable facts")
	}
}

func TestPortCreateConcurrentFirstRequests(t *testing.T) {
	for _, variant := range []string{"same_payload", "different_payload", "different_key"} {
		t.Run(variant, func(t *testing.T) {
			f := newPortCreateReplayFixture(t)
			second := f.request
			switch variant {
			case "different_payload":
				second.NewEndpoint.Address, second.NewEndpoint.ListenAddress = "gateway.example.com:9443", "0.0.0.0:9443"
			case "different_key":
				second.IdempotencyKey, second.RequestID = uuid.NewString(), uuid.NewString()
			}
			blocker, err := f.pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer blocker.Rollback(t.Context())
			var blockerPID int
			if err := blocker.QueryRow(t.Context(), `SELECT pg_backend_pid() FROM nodes n JOIN node_certificates c ON c.node_id=n.id WHERE n.id=$1 FOR UPDATE OF n,c`, f.request.NodeID).Scan(&blockerPID); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			type result struct {
				value Transition
				err   error
			}
			results := make(chan result, 2)
			for _, request := range []CreateRequest{f.request, second} {
				go func() {
					value, err := f.service.Create(ctx, f.actor, request)
					results <- result{value, err}
				}()
			}
			waitPortCreateBlocked(t, f.pool, blockerPID, 2)
			if err := blocker.Commit(t.Context()); err != nil {
				t.Fatal(err)
			}
			ids := map[uuid.UUID]bool{}
			successes, conflicts := 0, 0
			for range 2 {
				got := <-results
				switch {
				case got.err == nil:
					successes++
					ids[got.value.ID] = true
				case errors.Is(got.err, ErrConflict):
					conflicts++
				default:
					t.Errorf("concurrent first create returned unstable error: %v", got.err)
				}
			}
			wantSuccesses := 1
			if variant == "same_payload" {
				wantSuccesses = 2
			}
			var transitions, outbox int
			if err := f.pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM node_gateway_port_transitions),(SELECT count(*) FROM node_gateway_port_transition_command_outbox)`).Scan(&transitions, &outbox); err != nil {
				t.Fatal(err)
			}
			if successes != wantSuccesses || conflicts != 2-wantSuccesses || len(ids) != 1 || ids[uuid.Nil] || transitions != 1 || outbox != 1 {
				t.Fatalf("successes=%d conflicts=%d IDs=%v transitions=%d outbox=%d", successes, conflicts, ids, transitions, outbox)
			}
		})
	}
}

func TestPortCreateRetryLimitAndErrorClassification(t *testing.T) {
	for _, test := range []struct {
		code     string
		attempts int
		conflict bool
	}{
		{"40001", 3, true},
		{"23505", 1, true},
		{"22012", 1, false},
	} {
		t.Run(test.code, func(t *testing.T) {
			f := newPortCreateReplayFixture(t)
			injectPortCreateFailure(t, f.pool, test.code)
			before := f.facts(t)
			_, err := f.service.Create(t.Context(), f.actor, f.request)
			if test.conflict {
				if !errors.Is(err, ErrConflict) {
					t.Errorf("database error=%v, want domain conflict", err)
				}
			} else {
				var databaseError interface{ SQLState() string }
				if !errors.As(err, &databaseError) || databaseError.SQLState() != test.code {
					t.Errorf("unrelated database error changed: %v", err)
				}
			}
			var attempts int
			if err := f.pool.QueryRow(t.Context(), `SELECT last_value FROM port_create_attempts`).Scan(&attempts); err != nil {
				t.Fatal(err)
			}
			if attempts != test.attempts || f.facts(t) != before {
				t.Fatalf("attempts=%d want=%d or changed durable facts", attempts, test.attempts)
			}
		})
	}
}

func TestPortCreateCancellationDuringRetry(t *testing.T) {
	f := newPortCreateReplayFixture(t)
	injectPortCreateFailure(t, f.pool, "40001")
	before := f.facts(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	f.service.store.(*PostgresStore).now = func() time.Time {
		if f.storeSamples.Add(1) == 2 {
			cancel()
		}
		return f.now()
	}
	if _, err := f.service.Create(ctx, f.actor, f.request); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled retry error=%v, want context canceled", err)
	}
	if f.storeSamples.Load() != 2 || f.facts(t) != before {
		t.Fatal("canceled operation retried again or changed durable facts")
	}
}

func TestPortCreateDeadlineDuringLockWait(t *testing.T) {
	f := newPortCreateReplayFixture(t)
	blocker, err := f.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(t.Context())
	var blockerPID int
	if err := blocker.QueryRow(t.Context(), `SELECT pg_backend_pid() FROM nodes WHERE id=$1 FOR UPDATE`, f.request.NodeID).Scan(&blockerPID); err != nil {
		t.Fatal(err)
	}
	before := f.facts(t)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := f.service.Create(ctx, f.actor, f.request); result <- err }()
	waitPortCreateBlocked(t, f.pool, blockerPID, 1)
	if err := <-result; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lock wait timeout error=%v, want deadline exceeded", err)
	}
	if f.storeSamples.Load() != 0 || f.facts(t) != before {
		t.Fatal("expired operation reached create or changed durable facts")
	}
}

func injectPortCreateFailure(t *testing.T, pool *pgxpool.Pool, code string) {
	t.Helper()
	// A sequence survives transaction rollback and counts actual database attempts.
	if _, err := pool.Exec(t.Context(), `CREATE SEQUENCE port_create_attempts;
		CREATE FUNCTION port_create_fail() RETURNS trigger LANGUAGE plpgsql AS $body$
		BEGIN
			PERFORM nextval('port_create_attempts');
			RAISE EXCEPTION USING ERRCODE=TG_ARGV[0],MESSAGE='isolated create failure';
		END $body$;
		CREATE TRIGGER port_create_failure BEFORE INSERT ON node_gateway_port_transitions
		FOR EACH ROW EXECUTE FUNCTION port_create_fail('`+code+`')`); err != nil {
		t.Fatal(err)
	}
}

type portCreateReplayFixture struct {
	pool         *pgxpool.Pool
	service      *Service
	actor        Actor
	request      CreateRequest
	pemHash      string
	derHash      string
	clock        atomic.Int64
	storeSamples atomic.Int32
}

func (f *portCreateReplayFixture) now() time.Time { return time.Unix(0, f.clock.Load()).UTC() }

func (f *portCreateReplayFixture) facts(t *testing.T) string {
	t.Helper()
	var facts string
	if err := f.pool.QueryRow(t.Context(), `SELECT jsonb_build_object(
		'transitions',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY r.id),'[]'::jsonb) FROM node_gateway_port_transitions r),
		'outbox',(SELECT coalesce(jsonb_agg(to_jsonb(o) ORDER BY o.id),'[]'::jsonb) FROM node_gateway_port_transition_command_outbox o))::text`).Scan(&facts); err != nil {
		t.Fatal(err)
	}
	return facts
}

func waitPortCreateBlocked(t *testing.T, pool *pgxpool.Pool, blockerPID, count int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting int
		if err := pool.QueryRow(ctx, `WITH RECURSIVE blocked(pid) AS (
			SELECT pid FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid))
			UNION SELECT a.pid FROM pg_stat_activity a JOIN blocked b ON b.pid=ANY(pg_blocking_pids(a.pid)))
			SELECT count(*) FROM blocked`, blockerPID).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting >= count {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("expected %d creators blocked by node/certificate lock, saw %d", count, waiting)
		case <-ticker.C:
		}
	}
}

func newPortCreateReplayFixture(t *testing.T) *portCreateReplayFixture {
	t.Helper()
	pool := portTransitionTestPool(t)
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	embedded, err := fs.Glob(migrations.FS, "*.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	var count, first, head, verified int
	if err := pool.QueryRow(t.Context(), `SELECT count(*),min(version),max(version),count(*) FILTER(WHERE integrity_state='verified') FROM schema_migrations`).Scan(&count, &first, &head, &verified); err != nil || first != 1 || count != len(embedded) || head != len(embedded) || verified != count {
		t.Fatalf("full migration chain count=%d range=%d..%d verified=%d want=%d err=%v", count, first, head, verified, len(embedded), err)
	}
	f := &portCreateReplayFixture{pool: pool, actor: Actor{ScopeID: uuid.New(), UserID: uuid.New()}}
	if err := pool.QueryRow(t.Context(), `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&f.actor.ScopeID); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal(err)
	}
	f.clock.Store(time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC).UnixNano())
	now := f.now()
	node, token, authorization, epoch := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	certificatePEM, pemDigest, derDigest := portCreateCertificate(t, now, node)
	f.pemHash = pemDigest
	f.derHash = derDigest
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO access_scopes(id,kind) VALUES($1,'platform') ON CONFLICT(id) DO NOTHING`, []any{f.actor.ScopeID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'Port replay test','unused')`, []any{f.actor.UserID, f.actor.UserID.String()}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{f.actor.ScopeID, f.actor.UserID}},
		{`INSERT INTO nodes(id,scope_id,name,created_by_user_id,display_id) VALUES($1,$2,'Port replay fixture',$3,1)`, []any{node, f.actor.ScopeID, f.actor.UserID}},
		{`INSERT INTO control_installation_entitlement(installation_id) VALUES('port-replay-test')`, nil},
		{`INSERT INTO node_ca_key_epochs(id,installation_id,epoch,key_id,ca_certificate_pem,ca_certificate_sha256,public_key_sha256,not_before,not_after,status,request_id,request_digest,created_by_scope_id,created_by_user_id,created_at)
		 VALUES($1,'port-replay-test',1,'port-test','test',decode(repeat('a',64),'hex'),decode(repeat('b',64),'hex'),$2,$3,'active',$4,decode(repeat('c',64),'hex'),$5,$6,$2)`, []any{epoch, now, now.Add(24 * time.Hour), uuid.New(), f.actor.ScopeID, f.actor.UserID}},
		{`INSERT INTO node_enrollment_tokens(id,node_id,purpose,token_hash,created_by_user_id,created_at,expires_at)
		 VALUES($1,$2,'initial_enrollment',decode(repeat('d',64),'hex'),$3,$4,$5)`, []any{token, node, f.actor.UserID, now, now.Add(time.Hour)}},
		{`INSERT INTO node_enrollment_authorizations(id,token_id,node_id,purpose,request_id,request_digest,authorized_at)
		 VALUES($1,$2,$3,'initial_enrollment',$5,decode(repeat('e',64),'hex'),$4)`, []any{authorization, token, node, now, authorization.String()}},
		{`INSERT INTO node_identity_authorizations(id,token_id,node_id,purpose,request_id,request_digest,token_hash,csr_der,csr_sha256,machine_fingerprint_sha256,protocol_min_major,protocol_min_minor,protocol_max_major,protocol_max_minor,selected_protocol_major,selected_protocol_minor,capabilities_snapshot,capabilities_sha256,gateway_workload_identity,gateway_instance_id,artifact_key_id,artifact_public_key,status,authorized_at,expires_at)
		 VALUES($1,$2,$3,'initial_enrollment',$1,decode(repeat('e',64),'hex'),decode(repeat('d',64),'hex'),'test',decode(repeat('a',64),'hex'),decode(repeat('a',64),'hex'),1,0,1,0,1,0,'{}',decode(repeat('a',64),'hex'),'spiffe://cdn-platform/gateway/test','test','x25519:test',decode(repeat('a',64),'hex'),'authorized',$4,$5)`, []any{authorization, token, node, now, now.Add(time.Hour)}},
		{`INSERT INTO node_certificates(id,node_id,issuance_kind,enrollment_authorization_id,serial_number,csr_sha256,certificate_public_key_sha256,uri_san,not_before,not_after,renewal_at,leaf_certificate_pem,issuing_chain_pem,leaf_certificate_sha256,status,issued_at,owner_scope_id,installation_id,ca_epoch_id,leaf_der_sha256,rotation_status,lifecycle_revision,lifecycle_request_id,lifecycle_request_digest,lifecycle_bound_at)
		 VALUES($1,$2,'initial',$3,'abc',decode(repeat('a',64),'hex'),decode(repeat('b',64),'hex'),$4,$5,$6,$7,$8,ARRAY[$9::bytea],decode($10,'hex'),'active',$5,$11,'port-replay-test',$12,decode($13,'hex'),'current',1,$14,decode(repeat('e',64),'hex'),$5)`, []any{uuid.New(), node, authorization, "spiffe://cdn-platform/node/" + node.String(), now, now.Add(24 * time.Hour), now.Add(12 * time.Hour), certificatePEM, certificatePEM, f.pemHash, f.actor.ScopeID, epoch, f.derHash, uuid.New()}},
	} {
		if _, err := pool.Exec(t.Context(), statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	f.request = CreateRequest{NodeID: node, ExpectedNodeRevision: 1,
		OldEndpoint:           Endpoint{Address: "gateway.example.com:7443", ServerName: "gateway.example.com", ListenAddress: "0.0.0.0:7443"},
		NewEndpoint:           Endpoint{Address: "gateway.example.com:8443", ServerName: "gateway.example.com", ListenAddress: "0.0.0.0:8443"},
		CompatibilityDeadline: now.Add(30 * time.Minute), RollbackDeadline: now.Add(time.Hour), RequestID: uuid.NewString(), IdempotencyKey: uuid.NewString()}
	store := NewPostgresStore(pool, func() time.Time { f.storeSamples.Add(1); return f.now() })
	f.service = NewService(store, f.now, uuid.New)
	return f
}

func portCreateCertificate(t *testing.T, now time.Time, nodeID uuid.UUID) ([]byte, string, string) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(0xabc), Subject: pkix.Name{CommonName: "port-replay"},
		NotBefore: now, NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	identityURI, err := url.Parse("spiffe://cdn-platform/node/" + nodeID.String())
	if err != nil {
		t.Fatal(err)
	}
	template.URIs = []*url.URL{identityURI}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	pemDigest := sha256.Sum256(pemBytes)
	derDigest := sha256.Sum256(der)
	parsed, err := x509.ParseCertificate(der)
	if err != nil || !bytes.Equal(parsed.Raw, der) {
		t.Fatalf("generated certificate DER cannot be parsed back: %v", err)
	}
	parsedDigest := sha256.Sum256(parsed.Raw)
	if parsedDigest != derDigest {
		t.Fatalf("parsed Raw digest=%x differs from DER digest=%x", parsedDigest, derDigest)
	}
	if pemDigest == derDigest {
		t.Fatal("generated PEM and DER digests unexpectedly match")
	}
	return pemBytes, hex.EncodeToString(pemDigest[:]), hex.EncodeToString(derDigest[:])
}
