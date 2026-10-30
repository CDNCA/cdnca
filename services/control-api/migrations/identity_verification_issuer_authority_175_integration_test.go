//go:build integration

package migrations_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestIdentityVerificationIssuerAuthority175Lifecycle(t *testing.T) {
	pool := openIdentityVerificationIssuer175Pool(t)
	applyIdentityVerificationIssuer175(t, pool)
	if err := pool.Ping(t.Context()); err != nil {
		t.Fatalf("apply migration 175: %v", err)
	}

	assertIdentityVerificationIssuer175Schema(t, pool, true)
	fixture := seedIdentityVerificationIssuer175(t, pool)
	assertIdentityVerificationIssuer175AuditAndImmutability(t, pool, fixture)
	assertIdentityVerificationIssuer175TerminalRetention(t, pool)

	assertIdentityVerificationIssuer175Code(t, rollbackIdentityVerificationIssuer175(t, pool), "P1756")
	clearIdentityVerificationIssuer175Facts(t, pool)
	if err := rollbackIdentityVerificationIssuer175(t, pool); err != nil {
		t.Fatalf("rollback empty migration 175: %v", err)
	}
	assertIdentityVerificationIssuer175Schema(t, pool, false)
	applyIdentityVerificationIssuer175(t, pool)
	if err := pool.Ping(t.Context()); err != nil {
		t.Fatalf("reapply migration 175: %v", err)
	}
	assertIdentityVerificationIssuer175Schema(t, pool, true)
}

type identityVerificationIssuer175Fixture struct {
	scopeID, actorID, authSessionID, providerSessionID, uploadID, reservationID uuid.UUID
	materialID, bindingID                                                       uuid.UUID
	createdAt, expiresAt                                                        time.Time
}

func seedIdentityVerificationIssuer175(t *testing.T, pool *pgxpool.Pool) identityVerificationIssuer175Fixture {
	t.Helper()
	fixture := identityVerificationIssuer175Fixture{
		scopeID: uuid.New(), actorID: uuid.New(), authSessionID: uuid.New(), providerSessionID: uuid.New(),
		uploadID: uuid.New(), reservationID: uuid.New(), materialID: uuid.New(), bindingID: uuid.New(),
		createdAt: time.Date(2045, 8, 9, 1, 2, 3, 0, time.UTC),
	}
	fixture.expiresAt = fixture.createdAt.Add(time.Hour)

	replicaExecIdentityVerificationIssuer175(t, pool, `
		INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
		VALUES($1,$2,$3,$4,$5,$6,$7);
		INSERT INTO identity_verification_provider_sessions_v1(
			id,tenant_scope_id,actor_user_id,actor_session_id,kind,provider,provider_request_id,
			evidence_token_digest,idempotency_key,request_id,request_digest_sha256,state,revision,
			attempt_count,created_at,updated_at,expires_at,retention_until
		) VALUES($8,$4,$3,$1,'personal_initial','trusted-kyc','provider-request-175',$9,
			'provider-session-175','provider-request-175',$10,'pending',1,0,$6,$6,$7,$11);
		INSERT INTO identity_verification_provider_uploads_v1(
			id,session_id,tenant_scope_id,actor_user_id,material_kind,object_key,object_sha256,
			size_bytes,content_type,encryption_key_id,idempotency_key,request_id,state,revision,
			created_at,updated_at,expires_at
		) VALUES($12,$8,$4,$3,'identity_document',$13,$14,1024,'image/jpeg','kms-key-175',
			'upload-175','upload-request-175','issued',1,$6,$6,$7);
		INSERT INTO audit_events(
			id,scope_id,stream_position,actor_user_id,action,resource_type,resource_id,request_id,
			result,payload,event_hash,occurred_at
		) VALUES($15,$4,1,$3,'identity_verification.evidence_reservation.issued',
			'identity_verification_evidence_reservation',$16::text,'reservation-175','success',
			jsonb_build_object('state','issued','revision','1'),$17,$6);
		INSERT INTO identity_verification_evidence_reservations(
			id,tenant_scope_id,actor_user_id,session_id,kind,token_digest,resolver_name,
			resolver_reference,private_object_reference,private_envelope_digest,evidence_request_digest,
			evidence_claim_digest,evidence_payload,state,revision,created_at,updated_at,expires_at
		) VALUES($16,$4,$3,$1,'personal_initial',$9,'trusted-resolver','resolver-reference-175',
			'identity/object/175',$18,$19,$20,'{}','issued',1,$6,$6,$7)`,
		fixture.authSessionID, uuid.New(), fixture.actorID, fixture.scopeID, bytes.Repeat([]byte{1}, 32),
		fixture.createdAt, fixture.expiresAt, fixture.providerSessionID, bytes.Repeat([]byte{2}, 32),
		bytes.Repeat([]byte{3}, 32), fixture.createdAt.Add(24*time.Hour), fixture.uploadID,
		fmt.Sprintf("identity-verification/%s/%s/%s/%s", fixture.scopeID, fixture.actorID,
			fixture.providerSessionID, fixture.uploadID), bytes.Repeat([]byte{4}, 32), uuid.New(),
		fixture.reservationID, bytes.Repeat([]byte{5}, 32), bytes.Repeat([]byte{6}, 32),
		bytes.Repeat([]byte{7}, 32), bytes.Repeat([]byte{8}, 32))
	return fixture
}

func assertIdentityVerificationIssuer175AuditAndImmutability(
	t *testing.T,
	pool *pgxpool.Pool,
	fixture identityVerificationIssuer175Fixture,
) {
	t.Helper()
	insertMaterial := `INSERT INTO identity_verification_provider_material_envelopes_v1(
		id,upload_id,session_id,tenant_scope_id,actor_user_id,envelope_provider,envelope_key_id,
		encrypted_envelope,envelope_aad_sha256,created_at
	) VALUES($1,$2,$3,$4,$5,'aws-kms','kms-key-175',$6,$7,$8)`
	_, err := pool.Exec(t.Context(), insertMaterial, fixture.materialID, fixture.uploadID,
		fixture.providerSessionID, fixture.scopeID, fixture.actorID, bytes.Repeat([]byte{9}, 32),
		bytes.Repeat([]byte{10}, 32), fixture.createdAt)
	assertIdentityVerificationIssuer175Code(t, err, "P1753")

	replicaExecIdentityVerificationIssuer175(t, pool, `INSERT INTO audit_events(
		id,scope_id,stream_position,actor_user_id,action,resource_type,resource_id,request_id,
		result,payload,event_hash,occurred_at
	) VALUES($1,$2,2,$3,'identity_verification.material_envelope.created',
		'identity_verification_material_envelope',$4::text,$5,'success',
		jsonb_build_object('session_id',$6::text,'upload_id',$7::text),$8,$9)`,
		uuid.New(), fixture.scopeID, fixture.actorID, fixture.materialID,
		"identity-material-envelope-"+fixture.materialID.String(), fixture.providerSessionID,
		fixture.uploadID, bytes.Repeat([]byte{11}, 32), fixture.createdAt)
	if _, err := pool.Exec(t.Context(), insertMaterial, fixture.materialID, fixture.uploadID,
		fixture.providerSessionID, fixture.scopeID, fixture.actorID, bytes.Repeat([]byte{9}, 32),
		bytes.Repeat([]byte{10}, 32), fixture.createdAt); err != nil {
		t.Fatalf("insert audited material envelope: %v", err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO identity_verification_evidence_issue_bindings_v1(
		id,reservation_id,tenant_scope_id,actor_user_id,session_id,kind,workload_id,
		certificate_fingerprint,idempotency_digest,issuer_request_digest,evidence_claim_digest,
		token_digest,created_at,expires_at
	) VALUES($1,$2,$3,$4,$5,'personal_initial','issuer-workload-175',$6,$7,$8,$9,$10,$11,$12)`,
		fixture.bindingID, fixture.reservationID, fixture.scopeID, fixture.actorID, fixture.authSessionID,
		bytes.Repeat([]byte{12}, 32), bytes.Repeat([]byte{13}, 32), bytes.Repeat([]byte{14}, 32),
		bytes.Repeat([]byte{8}, 32), bytes.Repeat([]byte{2}, 32), fixture.createdAt,
		fixture.expiresAt); err != nil {
		t.Fatalf("insert evidence issue binding: %v", err)
	}
	for _, statement := range []string{
		"UPDATE identity_verification_provider_material_envelopes_v1 SET envelope_key_id='other'",
		"DELETE FROM identity_verification_evidence_issue_bindings_v1",
		"TRUNCATE identity_verification_provider_material_envelopes_v1",
		"TRUNCATE identity_verification_evidence_issue_bindings_v1",
	} {
		_, err := pool.Exec(t.Context(), statement)
		assertIdentityVerificationIssuer175Code(t, err, "P1752")
	}
}

func assertIdentityVerificationIssuer175TerminalRetention(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	caseID, scopeID, actorID := uuid.New(), uuid.New(), uuid.New()
	createdAt := time.Date(2045, 8, 10, 1, 2, 3, 0, time.UTC)
	terminalAt := createdAt.Add(time.Hour)
	replicaExecIdentityVerificationIssuer175(t, pool, `
		INSERT INTO identity_verification_cases(
			id,tenant_scope_id,applicant_user_id,kind,status,subject_fingerprint,revision,
			created_at,state_changed_at,retention_until,evidence_settlement_required
		) VALUES($1,$2,$3,'personal_initial','draft',$4,1,$5,$5,$6,true);
		INSERT INTO identity_verification_state_events(
			id,tenant_scope_id,case_id,case_revision,from_status,to_status,actor_user_id,
			reason_code,occurred_at
		) VALUES($7,$2,$1,2,'draft','withdrawn',$3,'user.withdrawn',$8)`,
		caseID, scopeID, actorID, bytes.Repeat([]byte{15}, 32), createdAt,
		createdAt.Add(24*time.Hour), uuid.New(), terminalAt)

	_, err := pool.Exec(t.Context(), `UPDATE identity_verification_cases SET
		status='withdrawn',revision=2,state_changed_at=$2,terminal_at=$2,retention_until=$3 WHERE id=$1`,
		caseID, terminalAt, createdAt.Add(24*time.Hour))
	assertIdentityVerificationIssuer175Code(t, err, "P1754")
	wantRetention := terminalAt.Add(24 * time.Hour)
	if _, err := pool.Exec(t.Context(), `UPDATE identity_verification_cases SET
		status='withdrawn',revision=2,state_changed_at=$2,terminal_at=$2,retention_until=$3 WHERE id=$1`,
		caseID, terminalAt, wantRetention); err != nil {
		t.Fatalf("apply terminal retention: %v", err)
	}
	var got time.Time
	if err := pool.QueryRow(t.Context(), `SELECT retention_until FROM identity_verification_cases WHERE id=$1`,
		caseID).Scan(&got); err != nil || !got.Equal(wantRetention) {
		t.Fatalf("terminal retention=%v err=%v, want %v", got, err, wantRetention)
	}
}

func assertIdentityVerificationIssuer175Schema(t *testing.T, pool *pgxpool.Pool, want bool) {
	t.Helper()
	var material, binding, settlementColumn bool
	if err := pool.QueryRow(t.Context(), `SELECT
		to_regclass('identity_verification_provider_material_envelopes_v1') IS NOT NULL,
		to_regclass('identity_verification_evidence_issue_bindings_v1') IS NOT NULL,
		EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema()
			AND table_name='identity_verification_provider_settlements_v1'
			AND column_name='organization_name')`).Scan(&material, &binding, &settlementColumn); err != nil {
		t.Fatal(err)
	}
	if material != want || binding != want || settlementColumn != want {
		t.Fatalf("migration 175 schema material=%t binding=%t settlement_column=%t, want %t",
			material, binding, settlementColumn, want)
	}
}

func clearIdentityVerificationIssuer175Facts(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	replicaExecIdentityVerificationIssuer175(t, pool, `
		DELETE FROM identity_verification_evidence_issue_bindings_v1;
		DELETE FROM identity_verification_provider_material_envelopes_v1;
		DELETE FROM audit_events WHERE action='identity_verification.material_envelope.created'
			OR resource_type='identity_verification_material_envelope'`)
}

func replicaExecIdentityVerificationIssuer175(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), "SET LOCAL session_replication_role=replica"); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), sql, append([]any{pgx.QueryExecModeSimpleProtocol}, args...)...)
		return err
	}); err != nil {
		t.Fatalf("insert migration 175 fixture: %v", err)
	}
}

func openIdentityVerificationIssuer175Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	admin, err := pgxpool.New(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "identity_verification_issuer_175_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^identity_verification_issuer_175_[a-f0-9]{32}$`).MatchString(schema) {
		admin.Close()
		t.Fatalf("unsafe schema %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.MaxConns = 4
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop migration 175 schema: %v", err)
		}
		admin.Close()
	})
	if _, err := pool.Exec(t.Context(), identityVerificationIssuer175BaselineSQL, pgx.QueryExecModeSimpleProtocol); err != nil {
		pool.Close()
		admin.Close()
		t.Fatalf("create migration 175 authority baseline: %v", err)
	}
	return pool
}

func applyIdentityVerificationIssuer175(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	up, err := controlmigrations.FS.ReadFile("175_identity_verification_issuer_authority.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := controlmigrations.FS.ReadFile("175_identity_verification_issuer_authority.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), string(up), pgx.QueryExecModeSimpleProtocol); err != nil {
		t.Fatalf("apply migration 175: %v", err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO schema_migrations(
		version,migration_id,checksum_sha256,down_checksum_sha256,integrity_state,metadata_recorded_at
	) VALUES(175,'175_identity_verification_issuer_authority',$1,$2,'verified',clock_timestamp())`,
		fmt.Sprintf("%x", sha256.Sum256(up)), fmt.Sprintf("%x", sha256.Sum256(down))); err != nil {
		t.Fatalf("record migration 175: %v", err)
	}
}

func rollbackIdentityVerificationIssuer175(t *testing.T, pool *pgxpool.Pool) error {
	t.Helper()
	down, err := controlmigrations.FS.ReadFile("175_identity_verification_issuer_authority.down.sql")
	if err != nil {
		return err
	}
	if _, err := pool.Exec(t.Context(), string(down), pgx.QueryExecModeSimpleProtocol); err != nil {
		return err
	}
	_, err = pool.Exec(t.Context(), "DELETE FROM schema_migrations WHERE version=175")
	return err
}

const identityVerificationIssuer175BaselineSQL = `
CREATE TABLE schema_migrations(
    version bigint PRIMARY KEY,
    migration_id text NOT NULL,
    checksum_sha256 text NOT NULL,
    down_checksum_sha256 text NOT NULL,
    integrity_state text NOT NULL,
    metadata_recorded_at timestamptz NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
INSERT INTO schema_migrations(version,migration_id,checksum_sha256,down_checksum_sha256,integrity_state,metadata_recorded_at)
SELECT version,'fixture_'||version,repeat('a',64),repeat('b',64),'verified',clock_timestamp()
FROM generate_series(1,174) version;
UPDATE schema_migrations SET migration_id='174_firewall_action_authority',
    checksum_sha256='d73f059af5beffa4fe3d76b9ff1a360b02a1a40a0a4be0a3cab085f3900d082a',
    down_checksum_sha256='7b81cf1d669f70ebc8e9696280b3daf3ccc2cad831a86cd27302b4a1be323331'
WHERE version=174;

CREATE TABLE auth_sessions(
    id uuid PRIMARY KEY, scope_id uuid NOT NULL, user_id uuid NOT NULL,
    family_id uuid NOT NULL, refresh_token_hash bytea NOT NULL,
    created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
    UNIQUE(id,scope_id,user_id)
);
CREATE TABLE identity_verification_provider_sessions_v1(
    id uuid PRIMARY KEY, tenant_scope_id uuid NOT NULL, actor_user_id uuid NOT NULL,
    actor_session_id uuid NOT NULL, kind text NOT NULL, provider text NOT NULL,
    provider_request_id text NOT NULL, evidence_token_digest bytea NOT NULL,
    idempotency_key text NOT NULL, request_id text NOT NULL, request_digest_sha256 bytea NOT NULL,
    state text NOT NULL, revision bigint NOT NULL, attempt_count bigint NOT NULL,
    created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
    retention_until timestamptz NOT NULL,
    UNIQUE(tenant_scope_id,id,actor_user_id)
);
CREATE TABLE identity_verification_provider_uploads_v1(
    id uuid PRIMARY KEY, session_id uuid NOT NULL, tenant_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL, material_kind text NOT NULL, object_key text NOT NULL,
    object_version text, object_sha256 bytea NOT NULL, size_bytes bigint NOT NULL,
    content_type text NOT NULL, encryption_key_id text NOT NULL, idempotency_key text NOT NULL,
    request_id text NOT NULL, state text NOT NULL, revision bigint NOT NULL,
    created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
    finalized_at timestamptz
);
CREATE TABLE identity_verification_provider_settlements_v1(
    id uuid PRIMARY KEY, session_id uuid NOT NULL, tenant_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL, kind text NOT NULL
);
CREATE TABLE identity_verification_cases(
    id uuid PRIMARY KEY, tenant_scope_id uuid NOT NULL, applicant_user_id uuid NOT NULL,
    kind text NOT NULL, status text NOT NULL, subject_fingerprint bytea NOT NULL,
    organization_name text, legal_person_fingerprint bytea, agent_fingerprint bytea,
    agent_relationship text, reviewer_user_id uuid, revision bigint NOT NULL,
    created_at timestamptz NOT NULL, state_changed_at timestamptz NOT NULL,
    submitted_at timestamptz, expires_at timestamptz, terminal_at timestamptz,
    retention_until timestamptz NOT NULL, evidence_settlement_required boolean NOT NULL DEFAULT true,
    UNIQUE(tenant_scope_id,id,applicant_user_id)
);
CREATE TABLE identity_verification_evidence_reservations(
    id uuid PRIMARY KEY, tenant_scope_id uuid NOT NULL, actor_user_id uuid NOT NULL,
    session_id uuid NOT NULL, kind text NOT NULL, idempotency_digest bytea,
    token_digest bytea NOT NULL, resolver_name text NOT NULL, resolver_reference text NOT NULL,
    private_object_reference text NOT NULL, private_envelope_digest bytea NOT NULL,
    evidence_request_digest bytea NOT NULL, evidence_claim_digest bytea NOT NULL,
    evidence_payload jsonb NOT NULL, state text NOT NULL, revision bigint NOT NULL,
    case_id uuid, core_request_digest bytea, created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL, expires_at timestamptz NOT NULL
);
CREATE TABLE audit_events(
    id uuid PRIMARY KEY, scope_id uuid NOT NULL, stream_position bigint NOT NULL,
    actor_user_id uuid, action text NOT NULL, resource_type text NOT NULL, resource_id text NOT NULL,
    request_id text NOT NULL, result text NOT NULL, payload jsonb NOT NULL,
    previous_hash bytea, event_hash bytea NOT NULL, occurred_at timestamptz NOT NULL
);
CREATE FUNCTION protect_identity_verification_case() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RETURN NEW; END; $$;
CREATE TRIGGER identity_verification_cases_protected BEFORE UPDATE OR DELETE ON identity_verification_cases
FOR EACH ROW EXECUTE FUNCTION protect_identity_verification_case();
CREATE TABLE identity_verification_state_events(
    id uuid PRIMARY KEY, tenant_scope_id uuid NOT NULL, case_id uuid NOT NULL,
    case_revision bigint NOT NULL, from_status text, to_status text NOT NULL,
    actor_user_id uuid NOT NULL, reason_code text NOT NULL, occurred_at timestamptz NOT NULL
);
CREATE TABLE identity_verification_submissions(
    id uuid PRIMARY KEY, tenant_scope_id uuid NOT NULL, case_id uuid NOT NULL,
    applicant_user_id uuid NOT NULL, case_revision bigint NOT NULL,
    submitted_at timestamptz NOT NULL, expires_at timestamptz NOT NULL
);
CREATE TABLE identity_verification_review_assignments(
    id uuid PRIMARY KEY, tenant_scope_id uuid NOT NULL, case_id uuid NOT NULL,
    reviewer_user_id uuid NOT NULL, case_revision bigint NOT NULL, assigned_at timestamptz NOT NULL
);
CREATE TABLE identity_verification_reviews(
    id uuid PRIMARY KEY, tenant_scope_id uuid NOT NULL, case_id uuid NOT NULL,
    reviewer_user_id uuid NOT NULL, decision text NOT NULL, expected_revision bigint NOT NULL,
    resulting_revision bigint NOT NULL, reviewed_at timestamptz NOT NULL
);
CREATE TABLE identity_verified_persons(
    tenant_scope_id uuid NOT NULL, applicant_user_id uuid NOT NULL,
    identity_fingerprint bytea NOT NULL, initial_case_id uuid, approved_at timestamptz
);
CREATE TABLE identity_verified_organizations(
    tenant_scope_id uuid NOT NULL, subject_fingerprint bytea NOT NULL,
    approved_case_id uuid, approved_at timestamptz
);
`

func assertIdentityVerificationIssuer175Code(t *testing.T, err error, want string) {
	t.Helper()
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != want {
		t.Fatalf("error=%v SQLSTATE=%q, want %s", err, postgresErrorCodeIdentityVerification175(err), want)
	}
}

func postgresErrorCodeIdentityVerification175(err error) string {
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) {
		return postgresError.Code
	}
	return ""
}
