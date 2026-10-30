//go:build integration

package migrations_test

import (
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/domaineventsource"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestDomainEventOutbox368Migration rolls 368 up/down/up and exercises the
// generic outbox: per-subject sequencing, dedup replay and conflict, the
// payload contract, tenant/site binding, immutability, and the guarded down.
func TestDomainEventOutbox368Migration(t *testing.T) {
	const version = 368
	pool := migrationPoolAt(t, version-1)
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(t.Context(), pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	var active int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM plugin_webhook_event_contracts_122
		WHERE status='active' AND event_type IN ('io.cdnca.deployment.v1.status_changed','io.cdnca.site.v1.updated')`).
		Scan(&active); err != nil || active != 2 {
		t.Fatalf("active first-batch contracts = %d, %v", active, err)
	}

	tenant := seedSiteGroup082Identity(t, pool, "domain-event-368")
	other := seedSiteGroup082Identity(t, pool, "domain-event-368-other")
	siteID := uuid.New()
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO sites(id,scope_id,display_id,owner_user_id,domain,origins,origin_hosts,
			created_by_user_id,updated_by_user_id,created_at,updated_at)
		VALUES($1,$2,1,$3,'events-368.example.test',ARRAY['192.0.2.10:80'],ARRAY['192.0.2.10'],$3,$3,now(),now());
		INSERT INTO site_origin_pools(site_id,updated_at) VALUES($1,now());
		INSERT INTO site_origins(site_id,position,host,port,weight,enabled) VALUES($1,1,'192.0.2.10',80,1,true)`,
		pgx.QueryExecModeSimpleProtocol, siteID, tenant.scopeID, tenant.userID); err != nil {
		t.Fatal(err)
	}
	// The site insert committed site.updated(created) through the deferred
	// trigger; an origin change commits one more fact for the next revision.
	if _, err := pool.Exec(t.Context(), `UPDATE sites SET origins=ARRAY['192.0.2.20:80'],
		origin_hosts=ARRAY['192.0.2.20'],revision=revision+1,updated_at=now() WHERE id=$1`, siteID); err != nil {
		t.Fatal(err)
	}
	// A revision-free runtime projection emits nothing.
	if _, err := pool.Exec(t.Context(), `UPDATE sites SET ipv6_runtime_state=ipv6_runtime_state WHERE id=$1`, siteID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE sites SET enabled=false,status='disabled',revision=revision+1,updated_at=now() WHERE id=$1`, siteID); err != nil {
		t.Fatal(err)
	}
	rows, err := pool.Query(t.Context(), `SELECT subject_sequence,payload->>'change',payload->'changed_fields'::text
		FROM domain_event_outbox_368 WHERE subject=$1 ORDER BY subject_sequence`, "site/"+siteID.String())
	if err != nil {
		t.Fatal(err)
	}
	type siteRow struct {
		sequence int64
		change   string
		fields   string
	}
	siteRows, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (siteRow, error) {
		var value siteRow
		return value, row.Scan(&value.sequence, &value.change, &value.fields)
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []siteRow{{1, "created", "[]"}, {2, "updated", `["origins"]`}, {3, "disabled", `["status"]`}}
	if len(siteRows) != len(want) {
		t.Fatalf("site facts = %+v", siteRows)
	}
	for index := range want {
		if siteRows[index] != want[index] {
			t.Fatalf("site facts = %+v, want %+v", siteRows, want)
		}
	}

	deploymentID := uuid.New()
	deploymentFact := func(event uuid.UUID, transition uint64, state string) domaineventsource.Fact {
		fact, err := domaineventsource.NewDeploymentStatusFact(domaineventsource.DeploymentStatus{
			EventID: event, TenantScopeID: tenant.scopeID, DeploymentID: deploymentID, NodeID: uuid.New(),
			RolloutID: uuid.New(), Attempt: 1, TransitionSequence: transition, State: state,
			OccurredAt: time.Now().UTC(),
		})
		if err != nil {
			t.Fatal(err)
		}
		return fact
	}
	appendFact := func(fact domaineventsource.Fact) (domaineventsource.Appended, error) {
		var result domaineventsource.Appended
		err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			var err error
			result, err = domaineventsource.EnqueueTx(t.Context(), tx, fact)
			return err
		})
		return result, err
	}
	first := deploymentFact(uuid.Must(uuid.NewV7()), 1, "queued")
	got, err := appendFact(first)
	if err != nil || got.SubjectSequence != 1 || got.Replayed {
		t.Fatalf("first append = %+v, %v", got, err)
	}
	second, err := appendFact(deploymentFact(uuid.Must(uuid.NewV7()), 2, "healthy"))
	if err != nil || second.SubjectSequence != 2 {
		t.Fatalf("second append = %+v, %v", second, err)
	}
	// Same dedup key and same fact: idempotent replay of the business write.
	if replay, err := appendFact(first); err != nil || !replay.Replayed || replay.ID != first.ID || replay.SubjectSequence != 1 {
		t.Fatalf("replay = %+v, %v", replay, err)
	}
	// Same dedup key, different fact: reported conflict, sequence untouched.
	conflicting := first
	conflicting.Data = map[string]any{}
	for key, value := range first.Data {
		conflicting.Data[key] = value
	}
	conflicting.Data["state"] = "failed"
	if _, err := appendFact(conflicting); !errors.Is(err, domaineventsource.ErrDedupConflict) {
		t.Fatalf("conflict = %v", err)
	}
	var head int64
	if err := pool.QueryRow(t.Context(), `SELECT last_sequence FROM domain_event_subject_heads_368
		WHERE subject=$1`, "deployment/"+deploymentID.String()).Scan(&head); err != nil || head != 2 {
		t.Fatalf("subject head = %d, %v", head, err)
	}

	// The site belongs to another tenant: the fact is rejected in SQL.
	foreign := domaineventsource.Fact{ID: uuid.Must(uuid.NewV7()), EventType: domaineventsource.SiteUpdatedType,
		TenantScopeID: other.scopeID, SiteID: siteID, Subject: "site/" + siteID.String(),
		DedupKey: "site-368/foreign", OccurredAt: time.Now().UTC(),
		Data: map[string]any{"site_id": siteID.String(), "change": "updated", "changed_fields": []string{"origins"}}}
	assertDomainEvent368Code(t, appendErr(appendFact(foreign)), "P3683")
	// SQL rejects a payload outside the contract even if Go were bypassed.
	_, err = pool.Exec(t.Context(), `SELECT * FROM domain_event_append_368($1,$2,$3,$4,$5,'raw-368/1',now(),$6::jsonb)`,
		uuid.New(), domaineventsource.SiteUpdatedType, tenant.scopeID, siteID, "site/"+siteID.String(),
		`{"site_id":"`+siteID.String()+`","change":"updated","changed_fields":["origins"],"origin_password":"x"}`)
	assertDomainEvent368Code(t, err, "P3683")
	_, err = pool.Exec(t.Context(), `SELECT * FROM domain_event_append_368($1,$2,$3,NULL,$4,'raw-368/2',now(),$5::jsonb)`,
		uuid.New(), domaineventsource.DeploymentStatusChangedType, tenant.scopeID, "site/"+siteID.String(),
		`{"deployment_id":"`+uuid.NewString()+`"}`)
	assertDomainEvent368Code(t, err, "P3683")

	_, err = pool.Exec(t.Context(), `UPDATE domain_event_outbox_368 SET payload='{}'::jsonb WHERE id=$1`, first.ID)
	assertDomainEvent368Code(t, err, "P3684")
	_, err = pool.Exec(t.Context(), `DELETE FROM domain_event_outbox_368 WHERE id=$1`, first.ID)
	assertDomainEvent368Code(t, err, "P3682")
	_, err = pool.Exec(t.Context(), `UPDATE domain_event_types_368 SET site_bound=false`)
	assertDomainEvent368Code(t, err, "P3681")

	assertDomainEvent368Code(t, migrateVersionIsolated(t.Context(), pool, "down", version), "P3689")
	assertDomainEventSubscribable368(t, pool)
}

func appendErr(_ domaineventsource.Appended, err error) error { return err }

// Reserved contracts stay unsubscribable at the database boundary.
func assertDomainEventSubscribable368(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	var subscribable []string
	rows, err := pool.Query(t.Context(), `SELECT event_type FROM plugin_webhook_event_contracts_122
		WHERE status='active' ORDER BY event_type`)
	if err != nil {
		t.Fatal(err)
	}
	subscribable, err = pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	// At version 368 only the first batch is active (369 adds the rest).
	want := []string{domaineventsource.DeploymentStatusChangedType, domaineventsource.SiteUpdatedType,
		"io.cdnca.webhook.v1.test"}
	if len(subscribable) != len(want) {
		t.Fatalf("active contracts = %v, want %v", subscribable, want)
	}
	for index := range want {
		if subscribable[index] != want[index] {
			t.Fatalf("active contracts = %v, want %v", subscribable, want)
		}
	}
}

func assertDomainEvent368Code(t *testing.T, err error, want string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != want {
		t.Fatalf("error = %v, want SQLSTATE %s", err, want)
	}
}
