//go:build integration

package migrations_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestDNSACMERuntimeMigration048(t *testing.T) {
	pool := openDNSACMERuntimeDatabase(t)
	applyDNSACMEMigrationsThrough(t, pool, 48)
	assertDNSACMEMigrationVersion(t, pool, 48)
	assertDNSACMERelation(t, pool, "dns_acme_worker_proof_consumptions", false)

	applyDNSACMEMigration048(t, pool, "down")
	assertDNSACMEMigrationVersion(t, pool, 47)
	assertDNSACMERelation(t, pool, "acme_tenant_key_facts", false)
	applyDNSACMEMigration048(t, pool, "up")
	assertDNSACMEMigrationVersion(t, pool, 48)
	assertRuntimeForeignKeys(t, pool)

	fixture := seedDNSACMERuntimeFixture(t, pool)
	assertKeyMaterialOneOf(t, pool, fixture)
	seedACMEKeyAndAccountFacts(t, pool, fixture)
	assertDNSACMEDownRejectsFacts(t, pool)
	assertACMEOperationBindings(t, pool, fixture)
	seedACMEOperationAtAuthorizing(t, pool, fixture, fixture.orderID, "dns-01", &fixture.providerID)
	assertDNSPublicationFacts(t, pool, fixture)
	assertHTTPPublicationFacts(t, pool, fixture)
	assertOutboxLeaseLifecycle(t, pool, fixture)
	seedIssuedOrder(t, pool, &fixture)
	assertRenewalClaimLifecycle(t, pool, fixture)
	assertRuntimeFactsAreImmutable(t, pool, fixture)
	assertDNSACMEDownRejectsFacts(t, pool)
}

type dnsACMERuntimeFixture struct {
	tenantID          uuid.UUID
	scopeID           uuid.UUID
	actorID           uuid.UUID
	providerID        uuid.UUID
	orderID           uuid.UUID
	httpOrderID       uuid.UUID
	accountKeyID      uuid.UUID
	certificateKeyID  uuid.UUID
	accountKeyRef     string
	certificateKeyRef string
	accountURI        string
	directoryURL      string
	leaseToken        uuid.UUID
	leaseExpiresAt    time.Time
	challengeID       uuid.UUID
	challengeValue    string
	assetID           uuid.UUID
	assetVersionID    uuid.UUID
}

func seedDNSACMERuntimeFixture(t *testing.T, pool *pgxpool.Pool) dnsACMERuntimeFixture {
	t.Helper()
	fixture := dnsACMERuntimeFixture{
		tenantID: uuid.New(), scopeID: uuid.New(), actorID: uuid.New(), providerID: uuid.New(),
		orderID: uuid.New(), httpOrderID: uuid.New(), accountKeyID: uuid.New(),
		certificateKeyID: uuid.New(), accountKeyRef: "account-key-v1",
		certificateKeyRef: "certificate-key-v1", accountURI: "https://ca.example/acct/1",
		directoryURL: "https://ca.example/directory",
	}
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,'ACME runtime tenant')`, []any{fixture.tenantID}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{fixture.scopeID, fixture.tenantID}},
		{`INSERT INTO users(id,username,display_name,password_hash)
		  VALUES($1,$2,'ACME owner','test-hash')`, []any{fixture.actorID, "acme-" + strings.ReplaceAll(fixture.actorID.String(), "-", "")[:12]}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{fixture.scopeID, fixture.actorID}},
		{`INSERT INTO dns_providers(
			id,scope_id,name,provider_type,credential_key_id,credential_ciphertext,status,
			created_by_user_id,updated_by_user_id
		  ) VALUES($1,$2,'ACME DNS','cloudflare','credential-key',decode(repeat('ab',32),'hex'),
			'verified',$3,$3)`, []any{fixture.providerID, fixture.scopeID, fixture.actorID}},
	}
	for _, statement := range statements {
		if _, err := pool.Exec(t.Context(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	return fixture
}

func assertKeyMaterialOneOf(t *testing.T, pool *pgxpool.Pool, fixture dnsACMERuntimeFixture) {
	t.Helper()
	base := `INSERT INTO acme_tenant_key_facts(
		tenant_scope_id,id,key_ref,purpose,algorithm,public_key_spki_sha256,
		external_key_reference,wrapped_key_ciphertext,wrapping_key_id,wrapping_nonce,
		wrapping_aad_sha256,created_by_user_id
	) VALUES($1,$2,$3,'account','ecdsa',decode(repeat('01',32),'hex'),$4,$5,$6,$7,$8,$9)`
	requirePostgresError(t, execSQL(pool, base,
		fixture.scopeID, uuid.New(), "invalid-both", "kms://account",
		bytesOf(32, 2), "wrap-key", bytesOf(12, 3), bytesOf(32, 4), fixture.actorID))
	requirePostgresError(t, execSQL(pool, base,
		fixture.scopeID, uuid.New(), "invalid-neither", nil, nil, nil, nil, nil, fixture.actorID))
}

func seedACMEKeyAndAccountFacts(t *testing.T, pool *pgxpool.Pool, fixture dnsACMERuntimeFixture) {
	t.Helper()
	_, err := pool.Exec(t.Context(), `INSERT INTO acme_tenant_key_facts(
		tenant_scope_id,id,key_ref,purpose,algorithm,public_key_spki_sha256,
		external_key_reference,created_by_user_id
	) VALUES($1,$2,$3,'account','ecdsa',$4,'kms://tenant/account-key',$5)`,
		fixture.scopeID, fixture.accountKeyID, fixture.accountKeyRef, bytesOf(32, 5), fixture.actorID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(t.Context(), `INSERT INTO acme_tenant_key_facts(
		tenant_scope_id,id,key_ref,purpose,algorithm,public_key_spki_sha256,
		wrapped_key_ciphertext,wrapping_key_id,wrapping_nonce,wrapping_aad_sha256,
		created_by_user_id
	) VALUES($1,$2,$3,'certificate','ecdsa',$4,$5,'tenant-kek-v1',$6,$7,$8)`,
		fixture.scopeID, fixture.certificateKeyID, fixture.certificateKeyRef,
		bytesOf(32, 21), bytesOf(48, 7), bytesOf(12, 8), bytesOf(32, 9), fixture.actorID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(t.Context(), `INSERT INTO acme_account_registration_facts(
		tenant_scope_id,id,account_key_id,directory_url,account_uri,contacts,
		terms_agreed_at,registered_at,created_by_user_id
	) VALUES($1,$2,$3,$4,$5,ARRAY['mailto:ops@example.test'],
		statement_timestamp()-interval '1 second',statement_timestamp(),$6)`,
		fixture.scopeID, uuid.New(), fixture.accountKeyID, fixture.directoryURL,
		fixture.accountURI, fixture.actorID)
	if err != nil {
		t.Fatal(err)
	}
}

func assertACMEOperationBindings(t *testing.T, pool *pgxpool.Pool, fixture dnsACMERuntimeFixture) {
	t.Helper()
	insertCertificateOrder(t, pool, fixture, fixture.orderID, "dns-01", &fixture.providerID, nil)
	insertOutbox(t, pool, fixture.scopeID, fixture.orderID)
	requireP0001(t, execSQL(pool, `UPDATE certificate_orders SET
		status='active',revision=revision+1,updated_at=statement_timestamp()
		WHERE scope_id=$1 AND id=$2`, fixture.scopeID, fixture.orderID))

	wrongActor := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO users(id,username,display_name,password_hash)
		VALUES($1,$2,'Other owner','test-hash')`, wrongActor,
		"other-"+strings.ReplaceAll(wrongActor.String(), "-", "")[:12]); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`,
		fixture.scopeID, wrongActor); err != nil {
		t.Fatal(err)
	}
	snapshot := operationSnapshot(t, fixture, fixture.orderID, "dns-01", &fixture.providerID, wrongActor)
	requireP0001(t, execOperationAndInitialEvent(pool, fixture, fixture.orderID, wrongActor,
		&fixture.providerID, snapshot, uuid.New(), time.Now().UTC().Add(5*time.Minute)))
	legacySnapshot := operationSnapshot(t, fixture, fixture.orderID, "dns-01", &fixture.providerID, fixture.actorID)
	var legacy map[string]any
	if err := json.Unmarshal(legacySnapshot, &legacy); err != nil {
		t.Fatal(err)
	}
	legacy["TenantID"] = fixture.scopeID.String()
	delete(legacy, "ScopeID")
	legacySnapshot, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	requireP0001(t, execOperationAndInitialEvent(pool, fixture, fixture.orderID, fixture.actorID,
		&fixture.providerID, legacySnapshot, uuid.New(), time.Now().UTC().Add(5*time.Minute)))
}

func seedACMEOperationAtAuthorizing(
	t *testing.T,
	pool *pgxpool.Pool,
	fixture dnsACMERuntimeFixture,
	orderID uuid.UUID,
	challengeType string,
	providerID *uuid.UUID,
) {
	t.Helper()
	token := uuid.New()
	expires := time.Now().UTC().Add(10 * time.Minute).Truncate(time.Microsecond)
	snapshot := operationSnapshot(t, fixture, orderID, challengeType, providerID, fixture.actorID)
	if err := execOperationAndInitialEvent(pool, fixture, orderID, fixture.actorID,
		providerID, snapshot, token, expires); err != nil {
		t.Fatal(err)
	}
	events := []struct {
		revision    int
		eventType   string
		phase       string
		intent      bool
		orderURL    any
		finalizeURL any
		authURLs    []string
	}{
		{2, "account_registered", "claimed", false, nil, nil, []string{}},
		{3, "order_intent", "claimed", true, nil, nil, []string{}},
		{4, "order_created", "ordered", false, "https://ca.example/order/1", "https://ca.example/finalize/1", []string{"https://ca.example/authz/1"}},
		{5, "authorizing", "authorizing", false, "https://ca.example/order/1", "https://ca.example/finalize/1", []string{"https://ca.example/authz/1"}},
	}
	for _, event := range events {
		_, err := pool.Exec(t.Context(), `INSERT INTO acme_issuance_operation_events(
			tenant_scope_id,operation_id,revision,event_type,phase,status,fence_token,
			order_intent_pending,lease_token,lease_expires_at,account_uri,order_url,
			finalize_url,authorization_urls,occurred_at
		) VALUES($1,$2,$3,$4,$5,'active',$6,$7,$6,$8,$9,$10,$11,$12,statement_timestamp())`,
			fixture.scopeID, orderID.String(), event.revision, event.eventType, event.phase,
			token, event.intent, expires, fixture.accountURI, event.orderURL, event.finalizeURL,
			event.authURLs)
		if err != nil {
			t.Fatalf("insert operation event %s: %v", event.eventType, err)
		}
	}
	if orderID == fixture.orderID {
		fixture.leaseToken = token
		fixture.leaseExpiresAt = expires
	}
	// The caller that needs the lease reads the canonical database fact.
	if err := pool.QueryRow(t.Context(), `SELECT lease_token,lease_expires_at
		FROM acme_issuance_operation_events WHERE tenant_scope_id=$1 AND operation_id=$2
		ORDER BY revision DESC LIMIT 1`, fixture.scopeID, orderID.String()).Scan(&token, &expires); err != nil {
		t.Fatal(err)
	}
}

func assertDNSPublicationFacts(t *testing.T, pool *pgxpool.Pool, fixture dnsACMERuntimeFixture) {
	t.Helper()
	var token uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT lease_token FROM acme_issuance_operation_events
		WHERE tenant_scope_id=$1 AND operation_id=$2 ORDER BY revision DESC LIMIT 1`,
		fixture.scopeID, fixture.orderID.String()).Scan(&token); err != nil {
		t.Fatal(err)
	}
	attemptID := uuid.New()
	exactValue := "dns-challenge-value"
	digest := sha256.Sum256([]byte(exactValue))
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO acme_issuance_challenge_attempts(
			tenant_scope_id,operation_id,attempt_id,attempt_number,authorization_url,
			challenge_url,challenge_type,identifier,wildcard,record_name,token,exact_value,created_at
		) VALUES($1,$2,$3,1,'https://ca.example/authz/1','https://ca.example/challenge/1',
			'dns-01','example.test',false,'_acme-challenge.example.test.','token-1',$4,
			statement_timestamp())`, fixture.scopeID, fixture.orderID.String(), attemptID, exactValue); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO acme_issuance_challenge_events(
			tenant_scope_id,operation_id,attempt_id,revision,state,lease_token,
			exact_value_sha256,occurred_at
		) VALUES($1,$2,$3,1,'intent',$4,$5,statement_timestamp())`,
			fixture.scopeID, fixture.orderID.String(), attemptID, token, digest[:])
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	providerRef := fixture.providerID.String()
	requireP0001(t, execSQL(pool, `INSERT INTO acme_issuance_challenge_events(
		tenant_scope_id,operation_id,attempt_id,revision,state,lease_token,
		provider_ref,remote_record_ref,exact_value_sha256,occurred_at
	) VALUES($1,$2,$3,2,'published',$4,$5,'record-1',$6,statement_timestamp())`,
		fixture.scopeID, fixture.orderID.String(), attemptID, token, providerRef, bytesOf(32, 99)))
	requirePostgresError(t, execSQL(pool, `INSERT INTO acme_issuance_challenge_events(
		tenant_scope_id,operation_id,attempt_id,revision,state,lease_token,
		provider_ref,remote_record_ref,exact_value_sha256,occurred_at
	) VALUES($1,$2,$3,2,'published',$4,$5,$6,$7,statement_timestamp())`,
		fixture.scopeID, fixture.orderID.String(), attemptID, token, providerRef,
		strings.Repeat("r", 1025), digest[:]))
	if _, err := pool.Exec(t.Context(), `INSERT INTO acme_issuance_challenge_events(
		tenant_scope_id,operation_id,attempt_id,revision,state,lease_token,
		provider_ref,remote_record_ref,exact_value_sha256,occurred_at
	) VALUES($1,$2,$3,2,'published',$4,$5,'record-1',$6,statement_timestamp())`,
		fixture.scopeID, fixture.orderID.String(), attemptID, token, providerRef, digest[:]); err != nil {
		t.Fatal(err)
	}
	requireP0001(t, execSQL(pool, `INSERT INTO acme_issuance_challenge_events(
		tenant_scope_id,operation_id,attempt_id,revision,state,lease_token,
		provider_ref,remote_record_ref,exact_value_sha256,occurred_at
	) VALUES($1,$2,$3,3,'cleanup_claimed',$4,$5,'forged-record',$6,statement_timestamp())`,
		fixture.scopeID, fixture.orderID.String(), attemptID, token, providerRef, digest[:]))
	for _, event := range []struct {
		revision int
		state    string
	}{{3, "cleanup_claimed"}, {4, "cleaned"}} {
		if _, err := pool.Exec(t.Context(), `INSERT INTO acme_issuance_challenge_events(
			tenant_scope_id,operation_id,attempt_id,revision,state,lease_token,
			provider_ref,remote_record_ref,exact_value_sha256,occurred_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,'record-1',$8,statement_timestamp())`,
			fixture.scopeID, fixture.orderID.String(), attemptID, event.revision, event.state,
			token, providerRef, digest[:]); err != nil {
			t.Fatal(err)
		}
	}
}

func assertHTTPPublicationFacts(t *testing.T, pool *pgxpool.Pool, fixture dnsACMERuntimeFixture) {
	t.Helper()
	insertCertificateOrder(t, pool, fixture, fixture.httpOrderID, "http-01", nil, nil)
	insertOutbox(t, pool, fixture.scopeID, fixture.httpOrderID)
	seedACMEOperationAtAuthorizing(t, pool, fixture, fixture.httpOrderID, "http-01", nil)
	var token uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT lease_token FROM acme_issuance_operation_events
		WHERE tenant_scope_id=$1 AND operation_id=$2 ORDER BY revision DESC LIMIT 1`,
		fixture.scopeID, fixture.httpOrderID.String()).Scan(&token); err != nil {
		t.Fatal(err)
	}
	attemptID := uuid.New()
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO acme_issuance_challenge_attempts(
			tenant_scope_id,operation_id,attempt_id,attempt_number,authorization_url,
			challenge_url,challenge_type,identifier,wildcard,record_name,token,exact_value,created_at
		) VALUES($1,$2,$3,1,'https://ca.example/authz/1','https://ca.example/challenge/http',
			'http-01','example.test',false,'example.test','http-token','http-value',
			statement_timestamp())`, fixture.scopeID, fixture.httpOrderID.String(), attemptID); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO acme_issuance_challenge_events(
			tenant_scope_id,operation_id,attempt_id,revision,state,lease_token,
			provider_ref,remote_record_ref,exact_value_sha256,occurred_at
		) VALUES($1,$2,$3,1,'intent',$4,'forged','forged',$5,statement_timestamp())`,
			fixture.scopeID, fixture.httpOrderID.String(), attemptID, token, bytesOf(32, 1))
		return err
	})
	requireP0001(t, err)

	err = pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO acme_issuance_challenge_attempts(
			tenant_scope_id,operation_id,attempt_id,attempt_number,authorization_url,
			challenge_url,challenge_type,identifier,wildcard,record_name,token,exact_value,created_at
		) VALUES($1,$2,$3,1,'https://ca.example/authz/1','https://ca.example/challenge/http',
			'http-01','example.test',false,'example.test','http-token','http-value',
			statement_timestamp())`, fixture.scopeID, fixture.httpOrderID.String(), attemptID); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO acme_issuance_challenge_events(
			tenant_scope_id,operation_id,attempt_id,revision,state,lease_token,occurred_at
		) VALUES($1,$2,$3,1,'intent',$4,statement_timestamp())`,
			fixture.scopeID, fixture.httpOrderID.String(), attemptID, token)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func assertOutboxLeaseLifecycle(t *testing.T, pool *pgxpool.Pool, fixture dnsACMERuntimeFixture) {
	t.Helper()
	firstToken := uuid.New()
	requireP0001(t, execSQL(pool, `UPDATE dns_acme_outbox SET
		status='processing',attempts=attempts+1,lease_token=$2,
		lease_expires_at=statement_timestamp()+interval '5 minutes',
		payload='{"tampered":true}',updated_at=statement_timestamp()
		WHERE aggregate_id=$1`, fixture.orderID, firstToken))
	if _, err := pool.Exec(t.Context(), `UPDATE dns_acme_outbox SET
		status='processing',attempts=attempts+1,lease_token=$2,
		lease_expires_at=statement_timestamp()+interval '5 minutes',updated_at=statement_timestamp()
		WHERE aggregate_id=$1`, fixture.orderID, firstToken); err != nil {
		t.Fatal(err)
	}
	requireP0001(t, execSQL(pool, `UPDATE dns_acme_outbox SET
		status='completed',lease_token=$2,completed_at=statement_timestamp(),
		updated_at=statement_timestamp() WHERE aggregate_id=$1`, fixture.orderID, uuid.New()))
	if _, err := pool.Exec(t.Context(), `UPDATE dns_acme_outbox SET
		status='failed',last_error_code='provider_unavailable',
		next_attempt_at=statement_timestamp()+interval '100 milliseconds',
		updated_at=statement_timestamp() WHERE aggregate_id=$1`, fixture.orderID); err != nil {
		t.Fatal(err)
	}
	requireP0001(t, execSQL(pool, `UPDATE dns_acme_outbox SET
		status='processing',attempts=attempts+1,lease_token=$2,
		lease_expires_at=statement_timestamp()+interval '5 minutes',last_error_code=NULL,
		updated_at=statement_timestamp() WHERE aggregate_id=$1`, fixture.orderID, uuid.New()))
	if _, err := pool.Exec(t.Context(), `SELECT pg_sleep(0.15)`); err != nil {
		t.Fatal(err)
	}
	secondToken := uuid.New()
	if _, err := pool.Exec(t.Context(), `UPDATE dns_acme_outbox SET
		status='processing',attempts=attempts+1,lease_token=$2,
		lease_expires_at=statement_timestamp()+interval '5 minutes',last_error_code=NULL,
		updated_at=statement_timestamp() WHERE aggregate_id=$1`, fixture.orderID, secondToken); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE dns_acme_outbox SET
		status='completed',completed_at=statement_timestamp(),updated_at=statement_timestamp()
		WHERE aggregate_id=$1 AND lease_token=$2`, fixture.orderID, secondToken); err != nil {
		t.Fatal(err)
	}

	shortToken := uuid.New()
	if _, err := pool.Exec(t.Context(), `UPDATE dns_acme_outbox SET
		status='processing',attempts=attempts+1,lease_token=$2,
		lease_expires_at=statement_timestamp()+interval '100 milliseconds',updated_at=statement_timestamp()
		WHERE aggregate_id=$1`, fixture.httpOrderID, shortToken); err != nil {
		t.Fatal(err)
	}
	requireP0001(t, execSQL(pool, `UPDATE dns_acme_outbox SET
		status='processing',attempts=attempts+1,lease_token=$2,
		lease_expires_at=statement_timestamp()+interval '5 minutes',updated_at=statement_timestamp()
		WHERE aggregate_id=$1`, fixture.httpOrderID, uuid.New()))
	if _, err := pool.Exec(t.Context(), `SELECT pg_sleep(0.15)`); err != nil {
		t.Fatal(err)
	}
	takeoverToken := uuid.New()
	if _, err := pool.Exec(t.Context(), `UPDATE dns_acme_outbox SET
		status='processing',attempts=attempts+1,lease_token=$2,
		lease_expires_at=statement_timestamp()+interval '5 minutes',updated_at=statement_timestamp()
		WHERE aggregate_id=$1`, fixture.httpOrderID, takeoverToken); err != nil {
		t.Fatal(err)
	}
}

func seedIssuedOrder(t *testing.T, pool *pgxpool.Pool, fixture *dnsACMERuntimeFixture) {
	t.Helper()
	var leaseToken uuid.UUID
	var leaseExpiresAt time.Time
	if err := pool.QueryRow(t.Context(), `SELECT lease_token,lease_expires_at
		FROM acme_issuance_operation_events WHERE tenant_scope_id=$1 AND operation_id=$2
		ORDER BY revision DESC LIMIT 1`, fixture.scopeID, fixture.orderID.String()).Scan(
		&leaseToken, &leaseExpiresAt); err != nil {
		t.Fatal(err)
	}
	for _, event := range []struct {
		revision  int
		eventType string
		phase     string
	}{{6, "authorization_ready", "ready"}, {7, "finalize_intent", "finalizing"}} {
		if _, err := pool.Exec(t.Context(), `INSERT INTO acme_issuance_operation_events(
			tenant_scope_id,operation_id,revision,event_type,phase,status,fence_token,
			lease_token,lease_expires_at,account_uri,order_url,finalize_url,authorization_urls,
			occurred_at
		) VALUES($1,$2,$3,$4,$5,'active',$6,$6,$7,$8,'https://ca.example/order/1',
			'https://ca.example/finalize/1',ARRAY['https://ca.example/authz/1'],statement_timestamp())`,
			fixture.scopeID, fixture.orderID.String(), event.revision, event.eventType,
			event.phase, leaseToken, leaseExpiresAt, fixture.accountURI); err != nil {
			t.Fatal(err)
		}
	}
	for _, status := range []string{"validating", "issuing"} {
		if _, err := pool.Exec(t.Context(), `UPDATE certificate_orders SET
			status=$3,revision=revision+1,updated_at=statement_timestamp()
			WHERE scope_id=$1 AND id=$2`, fixture.scopeID, fixture.orderID, status); err != nil {
			t.Fatal(err)
		}
	}
	fixture.assetID = uuid.New()
	fixture.assetVersionID = uuid.New()
	fingerprint := bytesOf(32, 20)
	spki := bytesOf(32, 21)
	aad := bytesOf(32, 22)
	notBefore := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	notAfter := time.Now().UTC().Add(90 * 24 * time.Hour).Truncate(time.Microsecond)
	authorizationDigest := sha256.Sum256([]byte("https://ca.example/authz/1\x00"))
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO certificate_assets(
			tenant_scope_id,id,name,source,created_by_user_id,updated_by_user_id,created_at,updated_at
		) VALUES($1,$2,'example.test ACME','acme',$3,$3,statement_timestamp(),statement_timestamp())`,
			fixture.scopeID, fixture.assetID, fixture.actorID); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO certificate_asset_versions(
			tenant_scope_id,id,asset_id,version,initial_status,fingerprint_sha256,certificate_pem,
			public_key_sha256,private_key_reference,private_key_aad_sha256,sans,leaf_subject,
			serial_number,public_key_algorithm,public_key_bits,signature_algorithm,not_before,
			not_after,acme_order_id,renewal_due_at,imported_by_user_id,imported_at
		) VALUES($1,$2,$3,1,'default',$4,'certificate-pem',$5,$6,$7,ARRAY['example.test'],
			'CN=example.test','01','ecdsa',256,'ecdsa-with-SHA256',$8,$9,$10,$11,$12,
			statement_timestamp())`, fixture.scopeID, fixture.assetVersionID, fixture.assetID,
			fingerprint, spki, fixture.certificateKeyRef, aad, notBefore, notAfter,
			fixture.orderID, notAfter.Add(-30*24*time.Hour), fixture.actorID); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO certificate_asset_private_key_envelope_facts(
			tenant_scope_id,asset_id,version_id,sequence,certificate_fingerprint_sha256,
			certificate_public_key_sha256,private_key_reference,aad_sha256,private_key_ciphertext,
			private_key_key_id,private_key_nonce,private_key_metadata,change_kind,request_id,
			changed_by_user_id,changed_at
		) VALUES($1,$2,$3,1,$4,$5,$6,$7,$8,'asset-kek-v1',$9,'{}','initial','acme-save-1',
			$10,statement_timestamp())`, fixture.scopeID, fixture.assetID, fixture.assetVersionID,
			fingerprint, spki, fixture.certificateKeyRef, aad, bytesOf(48, 23), bytesOf(12, 24),
			fixture.actorID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	requireP0001(t, execSQL(pool, `UPDATE certificate_orders SET
		status='issued',not_after=$3,issued_asset_id=$4,issued_asset_version_id=$5,
		issued_at=statement_timestamp(),leaf_fingerprint_sha256=$6,leaf_spki_sha256=$7,
		acme_directory_url=$8,acme_account_key_ref=$9,certificate_key_ref=$10,
		external_order_url='https://ca.example/order/1',authorization_urls_sha256=$11,
		certificate_url='https://ca.example/certificate/1',revision=revision+1,
		updated_at=statement_timestamp() WHERE scope_id=$1 AND id=$2`,
		fixture.scopeID, fixture.orderID, notAfter, fixture.assetID, fixture.assetVersionID,
		bytesOf(32, 99), spki, fixture.directoryURL, fixture.accountKeyRef,
		fixture.certificateKeyRef, authorizationDigest[:]))
	if _, err := pool.Exec(t.Context(), `UPDATE certificate_orders SET
		status='issued',not_after=$3,issued_asset_id=$4,issued_asset_version_id=$5,
		issued_at=statement_timestamp(),leaf_fingerprint_sha256=$6,leaf_spki_sha256=$7,
		acme_directory_url=$8,acme_account_key_ref=$9,certificate_key_ref=$10,
		external_order_url='https://ca.example/order/1',authorization_urls_sha256=$11,
		certificate_url='https://ca.example/certificate/1',revision=revision+1,
		updated_at=statement_timestamp() WHERE scope_id=$1 AND id=$2`,
		fixture.scopeID, fixture.orderID, notAfter, fixture.assetID, fixture.assetVersionID,
		fingerprint, spki, fixture.directoryURL, fixture.accountKeyRef,
		fixture.certificateKeyRef, authorizationDigest[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO acme_issuance_operation_events(
		tenant_scope_id,operation_id,revision,event_type,phase,status,fence_token,
		lease_token,lease_expires_at,account_uri,order_url,finalize_url,authorization_urls,
		certificate_url,certificate_spki_sha256,leaf_fingerprint_sha256,occurred_at
	) VALUES($1,$2,8,'certificate_saved','certificate_saved','active',$3,$3,$4,$5,
		'https://ca.example/order/1','https://ca.example/finalize/1',
		ARRAY['https://ca.example/authz/1'],'https://ca.example/certificate/1',$6,$7,
		statement_timestamp())`, fixture.scopeID, fixture.orderID.String(), leaseToken,
		leaseExpiresAt, fixture.accountURI, spki, fingerprint); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO acme_issuance_operation_events(
		tenant_scope_id,operation_id,revision,event_type,phase,status,fence_token,
		account_uri,order_url,finalize_url,authorization_urls,certificate_url,
		certificate_spki_sha256,leaf_fingerprint_sha256,occurred_at
	) VALUES($1,$2,9,'completed','completed','completed',$3,$4,
		'https://ca.example/order/1','https://ca.example/finalize/1',
		ARRAY['https://ca.example/authz/1'],'https://ca.example/certificate/1',$5,$6,
		statement_timestamp())`, fixture.scopeID, fixture.orderID.String(), leaseToken,
		fixture.accountURI, spki, fingerprint); err != nil {
		t.Fatal(err)
	}
	for _, status := range []string{"deploying", "active"} {
		if _, err := pool.Exec(t.Context(), `UPDATE certificate_orders SET
			status=$3,revision=revision+1,updated_at=statement_timestamp()
			WHERE scope_id=$1 AND id=$2`, fixture.scopeID, fixture.orderID, status); err != nil {
			t.Fatal(err)
		}
	}
}

func assertRenewalClaimLifecycle(t *testing.T, pool *pgxpool.Pool, fixture dnsACMERuntimeFixture) {
	t.Helper()
	firstToken := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO acme_renewal_claim_facts(
		tenant_scope_id,source_order_id,revision,actor_user_id,event_type,status,
		fence_token,lease_token,lease_expires_at,occurred_at
	) VALUES($1,$2,1,$3,'claim_created','active',$4,$4,
		statement_timestamp()+interval '5 minutes',statement_timestamp())`,
		fixture.scopeID, fixture.orderID, fixture.actorID, firstToken); err != nil {
		t.Fatal(err)
	}
	requireP0001(t, execSQL(pool, `INSERT INTO acme_renewal_claim_facts(
		tenant_scope_id,source_order_id,revision,actor_user_id,event_type,status,
		fence_token,next_attempt_at,failure_code,occurred_at
	) VALUES($1,$2,2,$3,'retry_scheduled','retry_wait',$4,
		statement_timestamp()+interval '100 milliseconds','temporary',statement_timestamp())`,
		fixture.scopeID, fixture.orderID, fixture.actorID, uuid.New()))
	if _, err := pool.Exec(t.Context(), `INSERT INTO acme_renewal_claim_facts(
		tenant_scope_id,source_order_id,revision,actor_user_id,event_type,status,
		fence_token,next_attempt_at,failure_code,occurred_at
	) VALUES($1,$2,2,$3,'retry_scheduled','retry_wait',$4,
		statement_timestamp()+interval '100 milliseconds','temporary',statement_timestamp())`,
		fixture.scopeID, fixture.orderID, fixture.actorID, firstToken); err != nil {
		t.Fatal(err)
	}
	requireP0001(t, execSQL(pool, `INSERT INTO acme_renewal_claim_facts(
		tenant_scope_id,source_order_id,revision,actor_user_id,event_type,status,
		fence_token,lease_token,lease_expires_at,occurred_at
	) VALUES($1,$2,3,$3,'lease_taken_over','active',$4,$4,
		statement_timestamp()+interval '5 minutes',statement_timestamp())`,
		fixture.scopeID, fixture.orderID, fixture.actorID, uuid.New()))
	if _, err := pool.Exec(t.Context(), `SELECT pg_sleep(0.15)`); err != nil {
		t.Fatal(err)
	}
	takeoverToken := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO acme_renewal_claim_facts(
		tenant_scope_id,source_order_id,revision,actor_user_id,event_type,status,
		fence_token,lease_token,lease_expires_at,occurred_at
	) VALUES($1,$2,3,$3,'lease_taken_over','active',$4,$4,
		statement_timestamp()+interval '5 minutes',statement_timestamp())`,
		fixture.scopeID, fixture.orderID, fixture.actorID, takeoverToken); err != nil {
		t.Fatal(err)
	}
	renewalOrderID := uuid.New()
	insertCertificateOrder(t, pool, fixture, renewalOrderID, "dns-01", &fixture.providerID, &fixture.orderID)
	if _, err := pool.Exec(t.Context(), `INSERT INTO acme_renewal_claim_facts(
		tenant_scope_id,source_order_id,revision,actor_user_id,event_type,status,
		fence_token,renewal_order_id,occurred_at
	) VALUES($1,$2,4,$3,'completed','completed',$4,$5,statement_timestamp())`,
		fixture.scopeID, fixture.orderID, fixture.actorID, takeoverToken, renewalOrderID); err != nil {
		t.Fatal(err)
	}
}

func assertRuntimeFactsAreImmutable(t *testing.T, pool *pgxpool.Pool, fixture dnsACMERuntimeFixture) {
	t.Helper()
	requireP0001(t, execSQL(pool, `UPDATE acme_tenant_key_facts SET key_ref='forged'
		WHERE tenant_scope_id=$1 AND id=$2`, fixture.scopeID, fixture.accountKeyID))
	requireP0001(t, execSQL(pool, `DELETE FROM acme_account_registration_facts
		WHERE tenant_scope_id=$1`, fixture.scopeID))
	requireP0001(t, execSQL(pool, `UPDATE acme_issuance_challenge_events
		SET remote_record_ref='forged' WHERE tenant_scope_id=$1 AND remote_record_ref IS NOT NULL`,
		fixture.scopeID))
	requireP0001(t, execSQL(pool, `DELETE FROM certificate_orders WHERE scope_id=$1 AND id=$2`,
		fixture.scopeID, fixture.orderID))
	requireP0001(t, execSQL(pool, `TRUNCATE acme_renewal_claim_facts`))

	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(t.Context(), `UPDATE acme_tenant_key_facts
		SET key_ref='replica-forged' WHERE tenant_scope_id=$1 AND id=$2`,
		fixture.scopeID, fixture.accountKeyID)
	requireP0001(t, err)
}

func assertDNSACMEDownRejectsFacts(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	script, err := fs.ReadFile(controlmigrations.FS, "048_dns_acme_runtime.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	err = pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(t.Context(), string(script))
		return err
	})
	requireP0001(t, err)
	assertDNSACMEMigrationVersion(t, pool, 48)
	assertDNSACMERelation(t, pool, "acme_tenant_key_facts", true)
}

func insertCertificateOrder(
	t *testing.T,
	pool *pgxpool.Pool,
	fixture dnsACMERuntimeFixture,
	orderID uuid.UUID,
	challengeType string,
	providerID *uuid.UUID,
	renewalOf *uuid.UUID,
) {
	t.Helper()
	_, err := pool.Exec(t.Context(), `INSERT INTO certificate_orders(
		id,scope_id,dns_provider_id,domains,challenge_type,auto_renew,renewal_of_order_id,
		created_by_user_id,updated_by_user_id
	) VALUES($1,$2,$3,ARRAY['example.test'],$4,true,$5,$6,$6)`,
		orderID, fixture.scopeID, providerID, challengeType, renewalOf, fixture.actorID)
	if err != nil {
		t.Fatal(err)
	}
}

func insertOutbox(t *testing.T, pool *pgxpool.Pool, scopeID, orderID uuid.UUID) {
	t.Helper()
	_, err := pool.Exec(t.Context(), `INSERT INTO dns_acme_outbox(
		id,scope_id,aggregate_type,aggregate_id,event_type,payload
	) VALUES($1,$2,'certificate_order',$3,'certificate.order.requested',
		jsonb_build_object('order_id',$3::uuid))`, uuid.New(), scopeID, orderID)
	if err != nil {
		t.Fatal(err)
	}
}

func operationSnapshot(
	t *testing.T,
	fixture dnsACMERuntimeFixture,
	orderID uuid.UUID,
	challengeType string,
	providerID *uuid.UUID,
	actorID uuid.UUID,
) []byte {
	t.Helper()
	providerRef := ""
	if providerID != nil {
		providerRef = providerID.String()
	}
	value := map[string]any{
		"TenantID": fixture.tenantID.String(), "ScopeID": fixture.scopeID.String(), "OperationID": orderID.String(),
		"ActorUserID": actorID.String(), "ProviderRef": providerRef,
		"DirectoryURL": fixture.directoryURL, "AccountKeyRef": fixture.accountKeyRef,
		"CertificateKeyRef": fixture.certificateKeyRef, "Domains": []string{"example.test"},
		"ChallengeType": challengeType,
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func execOperationAndInitialEvent(
	pool *pgxpool.Pool,
	fixture dnsACMERuntimeFixture,
	orderID, actorID uuid.UUID,
	providerID *uuid.UUID,
	snapshot []byte,
	token uuid.UUID,
	expires time.Time,
) error {
	return pgx.BeginFunc(context.Background(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(context.Background(), `INSERT INTO acme_issuance_operations(
			tenant_scope_id,operation_id,request_digest,request_snapshot,directory_url,
			certificate_key_ref,certificate_order_id,actor_user_id,dns_provider_id,
			account_key_ref,created_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,statement_timestamp())`,
			fixture.scopeID, orderID.String(), bytesOf(32, 31), snapshot, fixture.directoryURL,
			fixture.certificateKeyRef, orderID, actorID, providerID, fixture.accountKeyRef); err != nil {
			return err
		}
		_, err := tx.Exec(context.Background(), `INSERT INTO acme_issuance_operation_events(
			tenant_scope_id,operation_id,revision,event_type,phase,status,fence_token,
			lease_token,lease_expires_at,occurred_at
		) VALUES($1,$2,1,'claim_created','claimed','active',$3,$3,$4,statement_timestamp())`,
			fixture.scopeID, orderID.String(), token, expires)
		return err
	})
}

func openDNSACMERuntimeDatabase(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.Ping(ctx); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	var version string
	if err := admin.QueryRow(ctx, `SHOW server_version`).Scan(&version); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	if !strings.HasPrefix(version, "17.") {
		admin.Close()
		t.Fatalf("PostgreSQL version = %q, want 17.x", version)
	}
	schema := "dns_acme_runtime_048_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^dns_acme_runtime_048_[a-f0-9]{32}$`).MatchString(schema) {
		admin.Close()
		t.Fatalf("unsafe test schema %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupCtx, cleanupCancel := databasetest.CleanupContext()
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop DNS ACME runtime schema: %v", err)
		}
		admin.Close()
	})
	return pool
}

func applyDNSACMEMigrationsThrough(t *testing.T, pool *pgxpool.Pool, target int) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `CREATE TABLE schema_migrations(
		version bigint PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT statement_timestamp()
	)`); err != nil {
		t.Fatal(err)
	}
	for version := 1; version <= target; version++ {
		matches, err := fs.Glob(controlmigrations.FS, fmt.Sprintf("%03d_*.up.sql", version))
		if err != nil || len(matches) != 1 {
			t.Fatalf("migration %03d match count = %d, error = %v", version, len(matches), err)
		}
		script, err := fs.ReadFile(controlmigrations.FS, matches[0])
		if err != nil {
			t.Fatal(err)
		}
		if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(t.Context(), string(script)); err != nil {
				return err
			}
			_, err := tx.Exec(t.Context(), `INSERT INTO schema_migrations(version) VALUES($1)`, version)
			return err
		}); err != nil {
			t.Fatalf("apply migration %03d (%s): %v", version, matches[0], err)
		}
	}
}

func applyDNSACMEMigration048(t *testing.T, pool *pgxpool.Pool, direction string) {
	t.Helper()
	script, err := fs.ReadFile(controlmigrations.FS, "048_dns_acme_runtime."+direction+".sql")
	if err != nil {
		t.Fatal(err)
	}
	err = pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), string(script)); err != nil {
			return err
		}
		if direction == "up" {
			_, err = tx.Exec(t.Context(), `INSERT INTO schema_migrations(version) VALUES(48)`)
		} else {
			_, err = tx.Exec(t.Context(), `DELETE FROM schema_migrations WHERE version=48`)
		}
		return err
	})
	if err != nil {
		t.Fatalf("apply migration 048 %s: %v", direction, err)
	}
}

func assertDNSACMEMigrationVersion(t *testing.T, pool *pgxpool.Pool, want int64) {
	t.Helper()
	var got int64
	if err := pool.QueryRow(t.Context(), `SELECT COALESCE(max(version),0) FROM schema_migrations`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("migration version = %d, want %d", got, want)
	}
}

func assertDNSACMERelation(t *testing.T, pool *pgxpool.Pool, name string, want bool) {
	t.Helper()
	var got bool
	if err := pool.QueryRow(t.Context(), `SELECT to_regclass($1) IS NOT NULL`, name).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("relation %s exists = %t, want %t", name, got, want)
	}
}

func assertRuntimeForeignKeys(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	want := []string{
		"acme_tenant_key_facts_actor_fk_048",
		"acme_account_registration_key_fk_048",
		"acme_account_registration_actor_fk_048",
		"acme_issuance_operations_order_fk_048",
		"acme_issuance_operations_actor_fk_048",
		"acme_issuance_operations_provider_fk_048",
		"acme_issuance_operations_account_key_fk_048",
		"acme_issuance_operations_certificate_key_fk_048",
		"certificate_orders_issued_asset_fk_048",
		"certificate_orders_created_actor_fk_048",
		"certificate_orders_updated_actor_fk_048",
		"acme_renewal_claim_source_order_fk_048",
		"acme_renewal_claim_result_order_fk_048",
		"acme_renewal_claim_actor_fk_048",
	}
	var got int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM pg_constraint
		WHERE contype='f' AND connamespace=current_schema()::regnamespace AND conname=ANY($1)`, want).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != len(want) {
		t.Fatalf("runtime foreign key count = %d, want %d", got, len(want))
	}
}

func execSQL(pool *pgxpool.Pool, query string, args ...any) error {
	_, err := pool.Exec(context.Background(), query, args...)
	return err
}

func requireP0001(t *testing.T, err error) {
	t.Helper()
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != "P0001" {
		t.Fatalf("error = %v, want PostgreSQL P0001", err)
	}
}

func requirePostgresError(t *testing.T, err error) {
	t.Helper()
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) {
		t.Fatalf("error = %v, want PostgreSQL error", err)
	}
}

func bytesOf(length int, value byte) []byte {
	result := make([]byte, length)
	for index := range result {
		result[index] = value
	}
	return result
}
