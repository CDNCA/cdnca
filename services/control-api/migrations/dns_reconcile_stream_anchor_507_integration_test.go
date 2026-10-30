//go:build integration

package migrations_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsreconcile"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 运行（gap-tests，待出包前全量跑，本任务只做 vet）：
//
//	GOTOOLCHAIN=go1.27.3 TEST_DATABASE_URL=... TEST_DATABASE_TEMPLATE=int_tpl \
//	  go -C services/control-api test -tags integration -count=1 -v \
//	  -run 'TestDNSReconcileStreamAnchor507' ./migrations
//
// 两个变量缺一即 t.Skip（go test 仍显示 ok），回报 SKIP 行数须为 0。

// TestDNSReconcileStreamAnchor507RoundTripAndDownGuard: a 506 head with a
// site-anchored DNS task and an in-flight 089 claim → up/down/up 507 (site
// facts do not block the rollback) → the site branch of
// dns_reconcile_anchor_507 is bit-identical to 089 (revision, site config
// digest, authority digest equal both the 089 functions and the claim stored
// before 507), the pre-507 claim still passes the rewritten claim trigger →
// a stream-anchored task (site_id NULL) makes down refuse with P5072.
func TestDNSReconcileStreamAnchor507RoundTripAndDownGuard(t *testing.T) {
	const version = 507
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	site := seedDNSProviderClaim089(t, pool, "anchor-507-site")
	siteClaim := insertDNSProviderClaim089(t, pool, site)
	var claimRevision int64
	var claimConfig, claimAuthority []byte
	if err := pool.QueryRow(ctx, `SELECT expected_site_revision,site_config_digest,authority_digest
		FROM dns_reconcile_provider_mutation_claims WHERE tenant_id=$1 AND claim_id=$2`,
		site.tenantID, siteClaim).Scan(&claimRevision, &claimConfig, &claimAuthority); err != nil {
		t.Fatal(err)
	}

	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d with site facts: %v", step, version, err)
		}
	}

	var anchorRevision, siteRevision int64
	var anchorConfig, anchorAuthority, siteConfig, siteAuthority []byte
	if err := pool.QueryRow(ctx, `SELECT anchor.revision,anchor.config_digest,anchor.authority_digest,
		site.revision,dns_reconcile_site_config_digest_089(site),
		dns_reconcile_authority_digest_089(site.scope_id,site,zone,provider)
		FROM sites site
		JOIN dns_zones zone ON zone.scope_id=site.scope_id AND zone.id=$2
		JOIN dns_providers provider ON provider.scope_id=zone.scope_id AND provider.id=zone.provider_id
		CROSS JOIN LATERAL dns_reconcile_anchor_507(site.scope_id,site.id,NULL,zone,provider) anchor
		WHERE site.id=$1`, site.siteID, site.zoneID).Scan(&anchorRevision, &anchorConfig, &anchorAuthority,
		&siteRevision, &siteConfig, &siteAuthority); err != nil {
		t.Fatal(err)
	}
	if anchorRevision != siteRevision || anchorRevision != claimRevision ||
		!bytes.Equal(anchorConfig, siteConfig) || !bytes.Equal(anchorConfig, claimConfig) ||
		!bytes.Equal(anchorAuthority, siteAuthority) || !bytes.Equal(anchorAuthority, claimAuthority) {
		t.Fatalf("site anchor differs from 089: revision %d/%d/%d config %x/%x/%x authority %x/%x/%x",
			anchorRevision, siteRevision, claimRevision, anchorConfig, siteConfig, claimConfig,
			anchorAuthority, siteAuthority, claimAuthority)
	}
	// The claim written before 507 is still valid under the 507 claim trigger.
	if _, err := pool.Exec(ctx, `UPDATE dns_reconcile_provider_mutation_claims
		SET state='uncertain',provider_request_id=$3,lease_expires_at=clock_timestamp()
		WHERE tenant_id=$1 AND client_request_id=$2 AND claim_id=$4`, site.tenantID, site.clientRequestID,
		"dns-reconcile-"+strings.Repeat("b", 32), siteClaim); err != nil {
		t.Fatalf("pre-507 site claim transition under 507: %v", err)
	}

	if _, err := seedDNSStreamAnchor507(t, pool, "down-guard", 19507, true, 20); err != nil {
		t.Fatalf("seed stream-anchored task: %v", err)
	}
	assertDNSProviderClaimCode089(t, migrateVersionIsolated(ctx, pool, "down", version), "P5072")
	var head int64
	if err := pool.QueryRow(ctx, `SELECT max(version) FROM schema_migrations`).Scan(&head); err != nil || head != version {
		t.Fatalf("head after refused down = %d %v", head, err)
	}
}

// TestDNSReconcileStreamAnchor507StreamBindClaimAndRecovery (release head):
// a stream-anchored DNS task (site_id NULL) binds the stream's CNAME binding
// revision and DNS authority digest; a stream without a CNAME binding cannot
// get a task (P8902); a claim built from dns_reconcile_anchor_507 is
// accepted, a stale binding revision is refused (P8902) and an in-flight
// claim locks the stream's DNS authority (P8903); the recovery continuation
// is consumed when the snapshot's SiteID is the stream ID and refused for
// another anchor ID (P8902).
func TestDNSReconcileStreamAnchor507StreamBindClaimAndRecovery(t *testing.T) {
	pool := releaseHeadMigrationPool(t)
	ctx := t.Context()

	t.Run("bind", func(t *testing.T) {
		fixture, err := seedDNSStreamAnchor507(t, pool, "bind", 19511, true, 20)
		if err != nil {
			t.Fatal(err)
		}
		var siteNull bool
		var stream uuid.UUID
		var revision int64
		var bound, expected []byte
		if err := pool.QueryRow(ctx, `SELECT task.site_id IS NULL,task.stream_id,task.provider_mutation_site_revision,
			task.provider_mutation_site_config_digest,dns_reconcile_stream_config_digest_507(forward)
			FROM dns_reconcile_tasks task JOIN l4_forwards forward ON forward.id=task.stream_id
			WHERE task.tenant_id=$1 AND task.job_id=$2`, fixture.tenantID, fixture.jobID).
			Scan(&siteNull, &stream, &revision, &bound, &expected); err != nil {
			t.Fatal(err)
		}
		if !siteNull || stream != fixture.streamID || revision != 1 || !bytes.Equal(bound, expected) {
			t.Fatalf("stream task bound site-null=%t stream=%s revision=%d digest %x want %x",
				siteNull, stream, revision, bound, expected)
		}
		_, err = seedDNSStreamAnchor507(t, pool, "bind-unbound", 19512, false, 20)
		assertDNSProviderClaimCode089(t, err, "P8902")
	})

	t.Run("claim", func(t *testing.T) {
		fixture, err := seedDNSStreamAnchor507(t, pool, "claim", 19513, true, 20)
		if err != nil {
			t.Fatal(err)
		}
		// a binding revision moved after the task was created: the anchor no
		// longer matches the task's bound revision
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `UPDATE cname_stream_bindings SET binding_revision=binding_revision+1
			WHERE tenant_scope_id=$1 AND stream_id=$2`, fixture.scopeID, fixture.streamID); err != nil {
			_ = tx.Rollback(context.Background())
			t.Fatal(err)
		}
		assertDNSProviderClaimCode089(t, insertDNSStreamClaim507(ctx, tx, fixture, uuid.New()), "P8902")
		_ = tx.Rollback(context.Background())

		claimID := uuid.New()
		if err := insertDNSStreamClaim507(ctx, pool, fixture, claimID); err != nil {
			t.Fatalf("stream claim: %v", err)
		}
		var siteNull bool
		var stream uuid.UUID
		if err := pool.QueryRow(ctx, `SELECT site_id IS NULL,stream_id FROM dns_reconcile_provider_mutation_claims
			WHERE tenant_id=$1 AND claim_id=$2`, fixture.tenantID, claimID).Scan(&siteNull, &stream); err != nil ||
			!siteNull || stream != fixture.streamID {
			t.Fatalf("stream claim anchor site-null=%t stream=%s %v", siteNull, stream, err)
		}
		// the claim's anchor is immutable
		_, err = pool.Exec(ctx, `UPDATE dns_reconcile_provider_mutation_claims SET stream_id=$3
			WHERE tenant_id=$1 AND claim_id=$2`, fixture.tenantID, claimID, uuid.New())
		assertDNSProviderClaimCode089(t, err, "P8902")
		// in flight: the stream's DNS authority (owner, package, deletion) is locked
		for _, query := range []string{
			`UPDATE l4_forwards SET package_subscription_id=$2 WHERE id=$1`,
			`UPDATE l4_forwards SET deleted_at=clock_timestamp() WHERE id=$1`,
		} {
			args := []any{fixture.streamID}
			if strings.Contains(query, "$2") {
				args = append(args, uuid.New())
			}
			_, err := pool.Exec(ctx, query, args...)
			assertDNSProviderClaimCode089(t, err, "P8903")
		}
	})

	t.Run("recovery continuation", func(t *testing.T) {
		for _, test := range []struct {
			name   string
			port   int
			anchor func(dnsStreamAnchorFixture507) uuid.UUID
			want   string
		}{
			{name: "stream anchor", port: 19514, anchor: func(f dnsStreamAnchorFixture507) uuid.UUID { return f.streamID }},
			{name: "foreign anchor", port: 19515, anchor: func(dnsStreamAnchorFixture507) uuid.UUID { return uuid.New() }, want: "P8902"},
		} {
			t.Run(test.name, func(t *testing.T) {
				fixture, err := seedDNSStreamAnchor507(t, pool, "recovery-"+strings.ReplaceAll(test.name, " ", "-"), test.port, true, 1)
				if err != nil {
					t.Fatal(err)
				}
				err = continueDNSStreamRecovery507(t, pool, fixture, test.anchor(fixture))
				if test.want == "" {
					if err != nil {
						t.Fatalf("stream recovery continuation: %v", err)
					}
					var consumed bool
					if err := pool.QueryRow(ctx, `SELECT consumed_at IS NOT NULL FROM dns_reconcile_provider_recovery_continuations
						WHERE tenant_id=$1 AND job_id=$2`, fixture.tenantID, fixture.jobID).Scan(&consumed); err != nil || !consumed {
						t.Fatalf("continuation consumed=%t %v", consumed, err)
					}
					return
				}
				assertDNSProviderClaimCode089(t, err, test.want)
			})
		}
	})
}

type dnsStreamAnchorFixture507 struct {
	tenantID, scopeID, userID, streamID, allocationID, zoneID, providerID, jobID uuid.UUID
	clientRequestID                                                              string
}

// seedDNSStreamAnchor507 seeds a stream of its own scope (bound: with a
// CNAME stream binding at revision 1) and its DNS reconcile job, task
// (stream_id, site_id NULL) and one apply operation. The stream, its CNAME
// allocation and binding are written with triggers and foreign keys off
// (session_replication_role replica: the L4 listener and CNAME issuance
// chains are not what 507 is about); the task, zone and provider go through
// every trigger. The returned error is the task insert's.
func seedDNSStreamAnchor507(t *testing.T, pool *pgxpool.Pool, suffix string, port int, bound bool,
	maxAttempts int,
) (dnsStreamAnchorFixture507, error) {
	t.Helper()
	f := dnsStreamAnchorFixture507{tenantID: uuid.New(), scopeID: uuid.New(), userID: uuid.New(), streamID: uuid.New(),
		allocationID: uuid.New(), zoneID: uuid.New(), providerID: uuid.New(), jobID: uuid.New(),
		clientRequestID: "claim-507-" + suffix}
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Microsecond)
	username := "dns507" + strings.ReplaceAll(f.userID.String(), "-", "")[:20]
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,$2)`, []any{f.tenantID, "DNS 507 " + suffix}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{f.scopeID, f.tenantID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,$3,'hash')`, []any{f.userID, username, "DNS 507 " + suffix}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{f.scopeID, f.userID}},
		{`INSERT INTO dns_providers(id,scope_id,name,provider_type,credential_key_id,credential_ciphertext,status,
			created_by_user_id,updated_by_user_id) VALUES($1,$2,'stream-provider','cloudflare','claim-key',$3,'verified',$4,$4)`,
			[]any{f.providerID, f.scopeID, append(make([]byte, 29), 1), f.userID}},
		{`INSERT INTO dns_zones(id,scope_id,provider_id,name,status,created_by_user_id,updated_by_user_id)
			VALUES($1,$2,$3,'example.test','draft',$4,$4)`, []any{f.zoneID, f.scopeID, f.providerID, f.userID}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatalf("seed %.60s: %v", statement.query, err)
		}
	}
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		statements := []struct {
			query string
			args  []any
		}{
			{`SET LOCAL session_replication_role='replica'`, nil},
			{`INSERT INTO l4_forwards(id,scope_id,display_id,package_subscription_id,owner_user_id,name,protocol,listen_address,
				listen_port,upstream_address,upstream_port,connect_timeout_ms,response_timeout_ms,max_connections_per_client,
				proxy_protocol_v1,enabled,created_by_user_id,updated_by_user_id,created_at,updated_at)
				VALUES($1,$2,1,$3,$4,$5,'tcp','*',$6,'192.0.2.10',9000,3000,30000,100,false,true,$4,$4,$7,$7)`,
				[]any{f.streamID, f.scopeID, uuid.New(), f.userID, "DNS 507 " + suffix, port, now}},
		}
		if bound {
			statements = append(statements,
				struct {
					query string
					args  []any
				}{`INSERT INTO cname_allocations(id,tenant_id,tenant_scope_id,owner_user_id,mode,stream_owner_id,current_claim_id,
					current_revision,generation,state,job_id,created_at,updated_at)
					VALUES($1,$2,$3,$4,'site',$5,$6,1,1,'done',$7,$8,$8)`,
					[]any{f.allocationID, f.tenantID, f.scopeID, f.userID, f.streamID, uuid.New(), uuid.New(), now}},
				struct {
					query string
					args  []any
				}{`INSERT INTO cname_stream_bindings(tenant_scope_id,stream_id,allocation_id,mode,binding_revision,created_at,updated_at)
					VALUES($1,$2,$3,'site',1,$4,$4)`, []any{f.scopeID, f.streamID, f.allocationID, now}})
		}
		statements = append(statements, struct {
			query string
			args  []any
		}{`SET LOCAL session_replication_role='origin'`, nil})
		for _, statement := range statements {
			if _, err := tx.Exec(ctx, statement.query, statement.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed stream %s: %v", suffix, err)
	}
	digest := make([]byte, 32)
	operation, err := json.Marshal(dnsStreamOperation507)
	if err != nil {
		t.Fatal(err)
	}
	err = pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{`INSERT INTO background_jobs(id,tenant_id,kind,subject,idempotency_key,request_digest,request_id,trace_id,
				state,attempt,max_attempts,claimable_at,total_count,created_at,updated_at)
				VALUES($1,$2,'dns_reconcile','dns_reconcile/'||$7::text,$3,$4,'request-507','','queued',0,$6,$5,1,$5,$5)`,
				[]any{f.jobID, f.tenantID, "job-507-" + suffix, digest, now, maxAttempts, f.streamID}},
			{`INSERT INTO background_job_items(tenant_id,job_id,ordinal,item_id,state) VALUES($1,$2,1,'reconcile','pending')`,
				[]any{f.tenantID, f.jobID}},
			{`INSERT INTO dns_reconcile_tasks(tenant_id,tenant_scope_id,job_id,stream_id,zone_id,idempotency_key,
				job_idempotency_key,payload_digest,job_request_digest,canonical_request,plan_digest,deterministic_plan,
				initial_provider_revision,required_consecutive,created_at)
				VALUES($1,$2,$3,$4,$5,$6,$7,$8,$8,'{}'::jsonb,$8,'{}'::jsonb,1,3,$9)`,
				[]any{f.tenantID, f.scopeID, f.jobID, f.streamID, f.zoneID, "raw-507-" + suffix, "job-507-" + suffix, digest, now}},
			{`INSERT INTO dns_reconcile_operations(tenant_id,job_id,phase,ordinal,source_sequence,action,
				client_request_id,operation,created_at) VALUES($1,$2,'apply',1,1,'create',$3,$4::jsonb,$5)`,
				[]any{f.tenantID, f.jobID, f.clientRequestID, operation, now}},
		} {
			if _, err := tx.Exec(ctx, statement.query, statement.args...); err != nil {
				return err
			}
		}
		return nil
	})
	return f, err
}

// insertDNSStreamClaim507 writes the stream task's apply claim as the
// runtime does (dnsproviderremotesource reconcile.go): every digest from
// dns_reconcile_anchor_507.
func insertDNSStreamClaim507(ctx context.Context, executor dnsProviderClaimExecutor089,
	f dnsStreamAnchorFixture507, claimID uuid.UUID,
) error {
	_, err := executor.Exec(ctx, `INSERT INTO dns_reconcile_provider_mutation_claims(
		tenant_id,client_request_id,job_id,phase,operation_ordinal,site_id,stream_id,zone_id,provider_id,
		claim_id,lease_expires_at,state,expected_site_revision,expected_zone_revision,expected_provider_revision,
		site_config_digest,operation_digest,authority_digest,provider_config_digest,credential_digest,
		provider_request_id,claimed_at)
		SELECT operation.tenant_id,operation.client_request_id,operation.job_id,operation.phase,operation.ordinal,
			NULL,task.stream_id,task.zone_id,provider.id,$1,statement_timestamp()+interval '2 minutes','claimed',
			anchor.revision,zone.revision,provider.revision,anchor.config_digest,
			dns_reconcile_operation_digest_089(operation.operation),anchor.authority_digest,
			dns_reconcile_provider_config_digest_089(zone,provider),
			dns_reconcile_credential_digest_089(provider.credential_key_id,provider.credential_ciphertext),
			$4,statement_timestamp()
		FROM dns_reconcile_operations operation
		JOIN dns_reconcile_tasks task ON task.tenant_id=operation.tenant_id AND task.job_id=operation.job_id
		JOIN dns_zones zone ON zone.scope_id=task.tenant_scope_id AND zone.id=task.zone_id
		JOIN dns_providers provider ON provider.scope_id=zone.scope_id AND provider.id=zone.provider_id
		CROSS JOIN LATERAL dns_reconcile_anchor_507(task.tenant_scope_id,task.site_id,task.stream_id,zone,provider) anchor
		WHERE operation.tenant_id=$2 AND operation.client_request_id=$3`, claimID, f.tenantID, f.clientRequestID,
		"dns-reconcile-"+strings.Repeat("b", 32))
	return err
}

// dnsStreamOperation507 is the apply operation of every stream fixture (the
// stored operation JSON is its encoding, so the recovery event's Operation
// equals dns_reconcile_operations.operation).
var dnsStreamOperation507 = dnscheck.ProviderOperation{
	Sequence: 1, Action: dnscheck.ProviderCreate, Name: "l4.example.test.",
	Type: dnscheck.RecordCNAME, Value: "edge.example.test.", TTL: 300, Reason: "missing_record",
}

// continueDNSStreamRecovery507 runs the 089 recovery continuation of a
// stream task (as TestDNSReconcileProviderMutationClaims089ContinuationLocks
// LiveZoneRevisionAtCommit does for a site): the job fails with
// provider_recovery_pending, the claim settles as conflict, then one
// transaction grants the continuation, requeues the job, appends the
// applying event whose snapshot SiteID is anchor and consumes the grant.
func continueDNSStreamRecovery507(t *testing.T, pool *pgxpool.Pool, f dnsStreamAnchorFixture507, anchor uuid.UUID) error {
	t.Helper()
	ctx := t.Context()
	jobs, err := jobstate.NewStore(pool, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := jobs.Claim(ctx, jobstate.ClaimInput{TenantID: f.tenantID, Kind: dnsreconcile.JobKind,
		WorkerID: "dns507-recovery", Limit: 1, LeaseDuration: time.Minute})
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim job=(%+v,%v)", claimed, err)
	}
	if _, err := jobs.Report(ctx, jobstate.ReportInput{TenantID: f.tenantID, JobID: f.jobID, WorkerID: claimed[0].WorkerID,
		LeaseID: claimed[0].LeaseID, Report: jobstate.Report{ItemID: dnsreconcile.JobItemID, State: jobstate.ItemFailed,
			Code: "provider_recovery_pending", Attempt: 1, Sequence: 7}}); err != nil {
		t.Fatal(err)
	}
	pending := dnscheck.ReconcileResult{
		TenantID: f.tenantID, SiteID: anchor, ZoneID: f.zoneID,
		Status: dnscheck.TaskFailed, InitialRevision: 1, ProviderRevision: 1,
		ErrorClass: dnscheck.ProviderErrorTransient, ErrorCode: "provider_recovery_pending",
		CompensationPlan: []dnscheck.ProviderOperation{},
		Operations: []dnscheck.OperationResult{{
			SourceSequence: 1, Operation: dnsStreamOperation507, ClientRequestID: f.clientRequestID,
			ProviderRequestID: dnsproviderremote.ProviderMutationRequestID(f.clientRequestID),
			Status:            dnscheck.OperationTransientFailed, ErrorClass: dnscheck.ProviderErrorTransient,
			ErrorCode: "provider_recovery_pending", ReportSequence: 7, Attempts: 3,
		}},
	}
	pendingJSON, err := json.Marshal(pending)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO dns_reconcile_task_events(
		tenant_id,job_id,event_sequence,source,status,provider_revision,result_snapshot,
		compensation_plan,error_class,error_code,occurred_at)
		VALUES($1,$2,1,'control','failed',1,$3,'[]'::jsonb,'transient','provider_recovery_pending',clock_timestamp())`,
		f.tenantID, f.jobID, pendingJSON); err != nil {
		t.Fatal(err)
	}
	claimID := uuid.New()
	if err := insertDNSStreamClaim507(ctx, pool, f, claimID); err != nil {
		t.Fatalf("stream claim: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE dns_reconcile_provider_mutation_claims
		SET state='conflict',final_zone_revision=expected_zone_revision,finalized_at=statement_timestamp()
		WHERE tenant_id=$1 AND client_request_id=$2 AND claim_id=$3`, f.tenantID, f.clientRequestID, claimID); err != nil {
		t.Fatal(err)
	}
	recovered := pending
	recovered.Operations = append([]dnscheck.OperationResult(nil), pending.Operations...)
	recovered.Status, recovered.ErrorClass, recovered.ErrorCode = dnscheck.TaskApplying, dnscheck.ProviderErrorNone, ""
	recovered.Operations[0].Status = dnscheck.OperationPlanned
	recovered.Operations[0].ErrorClass, recovered.Operations[0].ErrorCode = dnscheck.ProviderErrorNone, ""
	recoveredJSON, err := json.Marshal(recovered)
	if err != nil {
		t.Fatal(err)
	}
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		var grantedAt time.Time
		if err := tx.QueryRow(ctx, `INSERT INTO dns_reconcile_provider_recovery_continuations(
			tenant_id,client_request_id,claim_id,job_id,continuation_attempt,
			previous_item_attempt,previous_item_sequence,result_attempts,event_sequence,
			recovery_event_sequence,recovery_result_digest,granted_at)
			VALUES($1,$2,$3,$4,2,1,7,3,1,2,sha256(convert_to($5::jsonb::text,'UTF8')),clock_timestamp())
			RETURNING granted_at`, f.tenantID, f.clientRequestID, claimID, f.jobID, recoveredJSON).Scan(&grantedAt); err != nil {
			return err
		}
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{`UPDATE background_jobs SET state='queued',max_attempts=2,completed_count=succeeded_count,failed_count=0,
				lease_id=NULL,lease_owner=NULL,lease_expires_at=NULL,claimable_at=$3,last_error_code=NULL,
				completed_at=NULL,updated_at=$3 WHERE tenant_id=$1 AND id=$2`, []any{f.tenantID, f.jobID, grantedAt}},
			{`UPDATE background_job_items SET state='pending',error_code=NULL,completed_at=NULL
				WHERE tenant_id=$1 AND job_id=$2 AND item_id='reconcile'`, []any{f.tenantID, f.jobID}},
			{`INSERT INTO dns_reconcile_task_events(tenant_id,job_id,event_sequence,source,status,provider_revision,
				result_snapshot,compensation_plan,error_class,error_code,occurred_at)
				VALUES($1,$2,2,'control','applying',1,$3,'[]'::jsonb,'',NULL,clock_timestamp())`,
				[]any{f.tenantID, f.jobID, recoveredJSON}},
			{`UPDATE dns_reconcile_provider_recovery_continuations SET consumed_at=clock_timestamp()
				WHERE tenant_id=$1 AND job_id=$2`, []any{f.tenantID, f.jobID}},
		} {
			if _, err := tx.Exec(ctx, statement.query, statement.args...); err != nil {
				return err
			}
		}
		return nil
	})
}
