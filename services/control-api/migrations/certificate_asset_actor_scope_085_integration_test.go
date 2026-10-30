//go:build integration

package migrations_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/fs"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock/protocol"
	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func latestMigrationVersion(t *testing.T) int64 {
	t.Helper()
	matches, err := fs.Glob(controlmigrations.FS, "*.up.sql")
	if err != nil || len(matches) == 0 {
		t.Fatalf("list migrations: %v %v", matches, err)
	}
	sort.Strings(matches)
	version, err := strconv.ParseInt(strings.SplitN(matches[len(matches)-1], "_", 2)[0], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return version
}

var certificateActorScope085Now = time.Date(2026, 8, 1, 8, 0, 0, 0, time.UTC)

type certificateIdentity085 struct {
	tenantScope   uuid.UUID
	tenantUser    uuid.UUID
	platformScope uuid.UUID
	platformUser  uuid.UUID
	platformRole  uuid.UUID
}

type certificateEnvelope085 struct{}

type certificateWriteResult085 struct {
	result certificateasset.ImportResult
	err    error
}

func (certificateEnvelope085) Seal(_ context.Context, _ certificateasset.PrivateKeySealRequest) (certificateasset.PrivateKeyEnvelope, error) {
	return certificateasset.PrivateKeyEnvelope{KeyID: "certificate-085-key", Ciphertext: make([]byte, 32), Nonce: make([]byte, 12), Metadata: json.RawMessage(`{}`)}, nil
}

func (certificateEnvelope085) SealOpaque(_ context.Context, _ certificateasset.OpaquePrivateKeySealRequest) (certificateasset.PrivateKeyEnvelope, error) {
	return certificateasset.PrivateKeyEnvelope{}, errors.New("opaque sealing is not used")
}

func (certificateEnvelope085) Unseal(_ context.Context, _ certificateasset.PrivateKeyUnsealRequest) ([]byte, error) {
	return nil, errors.New("unsealing is not used")
}

func (certificateEnvelope085) Rewrap(_ context.Context, request certificateasset.PrivateKeyRewrapRequest) (certificateasset.PrivateKeyEnvelope, error) {
	request.Envelope.KeyID = request.TargetKeyID
	return request.Envelope, nil
}

func TestCertificateAssetActorScope085RoundTripAndLegacyBackfill(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 84)
	assertCertificateHead084(t, pool)
	identity := seedCertificateIdentity085(t, pool)
	assetID := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO certificate_assets(
		tenant_scope_id,id,name,source,created_by_user_id,updated_by_user_id,created_at,updated_at
	) VALUES($1,$2,'legacy certificate','uploaded',$3,$3,$4,$4)`, identity.tenantScope,
		assetID, identity.tenantUser, certificateActorScope085Now); err != nil {
		t.Fatal(err)
	}

	if err := migrateVersionIsolated(t.Context(), pool, "up", 85); err != nil {
		t.Fatalf("apply 085: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 85)
	assertCertificateActorColumns085(t, pool, true)
	var createdScope, updatedScope uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT created_by_scope_id,updated_by_scope_id
		FROM certificate_assets WHERE tenant_scope_id=$1 AND id=$2`, identity.tenantScope, assetID).
		Scan(&createdScope, &updatedScope); err != nil {
		t.Fatal(err)
	}
	if createdScope != identity.tenantScope || updatedScope != identity.tenantScope {
		t.Fatalf("legacy actor scopes = %s/%s, want target %s", createdScope, updatedScope, identity.tenantScope)
	}
	assertCertificatePlatformRole085(t, pool, identity.platformRole, true)

	if err := migrateVersionIsolated(t.Context(), pool, "down", 85); err != nil {
		t.Fatalf("empty platform 085 down: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 84)
	assertCertificateActorColumns085(t, pool, false)
	assertCertificatePlatformRole085(t, pool, identity.platformRole, false)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 85); err != nil {
		t.Fatalf("reapply 085: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 85)
}

func TestCertificateAssetActorScope085PlatformLifecycleAndRollbackFence(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 84)
	assertCertificateHead084(t, pool)
	identity := seedCertificateIdentity085(t, pool)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 85); err != nil {
		t.Fatal(err)
	}
	// The current Store depends on columns added after 085 (086/116/213/276), so the
	// rollback fence is exercised with a directly written platform-actor asset row.
	if _, err := pool.Exec(t.Context(), `INSERT INTO certificate_assets(
		tenant_scope_id,id,name,source,created_by_scope_id,created_by_user_id,updated_by_scope_id,updated_by_user_id,created_at,updated_at
	) VALUES($1,$2,'platform fence certificate','uploaded',$3,$4,$3,$4,$5,$5)`, identity.tenantScope, uuid.New(),
		identity.platformScope, identity.platformUser, certificateActorScope085Now); err != nil {
		t.Fatal(err)
	}
	assertCertificateCode085(t, migrateVersionIsolated(t.Context(), pool, "down", 85), "P8501")
	assertPackageCommerceRBAC079Ledger(t, pool, 85)
	// Created before the head migration so later migrations backfill its required columns.
	siteID := insertCertificateSite085(t, pool, identity, "www.certificate-085.example")

	// The platform lifecycle runs the current Store on the current release head.
	if err := migrateVersionIsolated(t.Context(), pool, "up", latestMigrationVersion(t)); err != nil {
		t.Fatalf("apply release head: %v", err)
	}
	sessionID, sessionDigest := uuid.New(), make([]byte, 32)
	if _, err := pool.Exec(t.Context(), `INSERT INTO auth_sessions(
		id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at
	) VALUES($1,$2,$3,$4,$5,now()-interval '1 minute',now()+interval '1 hour')`, sessionID, uuid.New(),
		identity.platformUser, identity.platformScope, sessionDigest); err != nil {
		t.Fatal(err)
	}
	actor := certificateasset.Actor{UserID: identity.platformUser, ScopeID: identity.platformScope,
		ScopeKind: certificateasset.ScopePlatform, SessionID: sessionID}
	store, err := certificateasset.NewStoreWithDependencies(pool, certificateEnvelope085{}, audit.New(pool), func() time.Time {
		return certificateActorScope085Now
	})
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM, privateKeyPEM := certificateMaterial085(t, "www.certificate-085.example")
	result, err := store.Import(t.Context(), actor, certificateasset.ImportRequest{
		TenantScopeID: identity.tenantScope, Name: "platform managed certificate", Source: certificateasset.SourceUploaded,
		CertificatePEM: certificatePEM, PrivateKeyPEM: privateKeyPEM,
		IdempotencyKey: "certificate-085-import", RequestID: "certificate-085-import",
	})
	if err != nil {
		t.Fatalf("platform import: %v", err)
	}
	if _, err := store.Activate(t.Context(), actor, certificateasset.ActivateRequest{
		TenantScopeID: identity.tenantScope, AssetID: result.Asset.ID, VersionID: result.Version.ID,
		ExpectedRevision: 1, IdempotencyKey: "certificate-085-activate", RequestID: "certificate-085-activate",
	}); err != nil {
		t.Fatalf("platform activate: %v", err)
	}
	if _, err := store.Bind(t.Context(), actor, certificateasset.BindRequest{
		TenantScopeID: identity.tenantScope, SiteID: siteID, AssetID: result.Asset.ID, VersionID: result.Version.ID,
		ExpectedRevision: 0, IdempotencyKey: "certificate-085-bind", RequestID: "certificate-085-bind",
	}); err != nil {
		t.Fatalf("platform bind: %v", err)
	}
	if _, err := store.Unbind(t.Context(), actor, certificateasset.UnbindRequest{
		TenantScopeID: identity.tenantScope, SiteID: siteID, ExpectedRevision: 1,
		IdempotencyKey: "certificate-085-unbind", RequestID: "certificate-085-unbind",
	}); err != nil {
		t.Fatalf("platform unbind: %v", err)
	}
	if _, err := store.Rewrap(t.Context(), actor, certificateasset.RewrapRequest{
		TenantScopeID: identity.tenantScope, AssetID: result.Asset.ID, VersionID: result.Version.ID,
		ExpectedEnvelopeSequence: 1, TargetKeyID: "certificate-085-key-rotated",
		IdempotencyKey: "certificate-085-rewrap", RequestID: "certificate-085-rewrap",
	}); err != nil {
		t.Fatalf("platform rewrap: %v", err)
	}
	// 资产吊销接口已下线；历史吊销事实仍须接受平台身份，直接按原写法落库。
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `UPDATE certificate_assets SET revision=3,updated_by_scope_id=$3,
			updated_by_user_id=$4,updated_at=$5 WHERE tenant_scope_id=$1 AND id=$2 AND revision=2`,
			identity.tenantScope, result.Asset.ID, identity.platformScope, identity.platformUser,
			certificateActorScope085Now); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO certificate_asset_revocation_facts(
			tenant_scope_id,asset_id,version_id,expected_asset_revision,resulting_asset_revision,
			reason,request_id,actor_scope_id,revoked_by_user_id,revoked_at
		) VALUES($1,$2,$3,2,3,'operator requested','certificate-085-revoke',$4,$5,$6)`,
			identity.tenantScope, result.Asset.ID, result.Version.ID, identity.platformScope,
			identity.platformUser, certificateActorScope085Now)
		return err
	}); err != nil {
		t.Fatalf("platform revocation fact: %v", err)
	}
	if _, err := store.Delete(t.Context(), actor, certificateasset.DeleteRequest{
		TenantScopeID: identity.tenantScope, AssetID: result.Asset.ID, ExpectedRevision: 3,
		IdempotencyKey: "certificate-085-delete", RequestID: "certificate-085-delete",
	}); err != nil {
		t.Fatalf("platform delete: %v", err)
	}
	assertCertificatePlatformFacts085(t, pool, identity, result.Asset.ID)

	var forgedTenantMembership bool
	if err := pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM memberships WHERE scope_id=$1 AND user_id=$2)`,
		identity.tenantScope, identity.platformUser).Scan(&forgedTenantMembership); err != nil || forgedTenantMembership {
		t.Fatalf("platform actor tenant membership exists=%t err=%v", forgedTenantMembership, err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE memberships SET status='suspended' WHERE scope_id=$1 AND user_id=$2`,
		identity.platformScope, identity.platformUser); err != nil {
		t.Fatal(err)
	}
	if _, err := store.List(t.Context(), actor, identity.tenantScope, true); !errors.Is(err, certificateasset.ErrPermissionDenied) {
		t.Fatalf("suspended platform actor list error = %v", err)
	}
}

func TestCertificateAssetActorScope085RequiresFrozen084Head(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 83)
	script, err := fs.ReadFile(controlmigrations.FS, "085_certificate_asset_actor_scope.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(t.Context(), string(script))
	assertCertificateCode085(t, err, "P8500")
	assertPackageCommerceRBAC079Ledger(t, pool, 83)
	assertCertificateActorColumns085(t, pool, false)
}

func TestCertificateAssetActorScope085DownSerializesWithNewerHead(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 84)
	assertCertificateHead084(t, pool)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 85); err != nil {
		t.Fatal(err)
	}
	migration086, err := loadPackageCommerceRBAC079Migration(86)
	if err != nil {
		t.Fatal(err)
	}

	newer, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = newer.Rollback(context.Background()) }()
	var newerPID int
	if err := newer.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&newerPID); err != nil {
		t.Fatal(err)
	}
	if _, err := newer.Exec(t.Context(), `INSERT INTO schema_migrations(
		version,migration_id,checksum_sha256,down_checksum_sha256,integrity_state,metadata_recorded_at
	) VALUES($1,$2,$3,$4,'verified',clock_timestamp())`, migration086.version,
		migration086.identifier, migration086.upChecksum, migration086.downChecksum); err != nil {
		t.Fatal(err)
	}

	downPool, downPID := certificateSingleConnectionPool085(t, pool, "certificate_085_down")
	downScript, err := fs.ReadFile(controlmigrations.FS, "085_certificate_asset_actor_scope.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	downResult := make(chan error, 1)
	go func() {
		downResult <- pgx.BeginFunc(context.Background(), downPool, func(tx pgx.Tx) error {
			_, err := tx.Exec(context.Background(), string(downScript))
			return err
		})
	}()
	waitCertificateBlocked085(t, pool, downPID, newerPID)
	if err := newer.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	err = receiveCertificateError085(t, downResult)
	assertCertificateCode085(t, err, "P8501")
	var head85, head86 bool
	if err := pool.QueryRow(t.Context(), `SELECT
		EXISTS(SELECT 1 FROM schema_migrations WHERE version=85),
		EXISTS(SELECT 1 FROM schema_migrations WHERE version=86)`).Scan(&head85, &head86); err != nil {
		t.Fatal(err)
	}
	if !head85 || !head86 {
		t.Fatalf("serialized down changed ledger: head85=%t head86=%t", head85, head86)
	}
	assertCertificateActorColumns085(t, pool, true)
}

func TestCertificateAssetWriteCommitsBeforeConcurrentMembershipRevoke(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 84)
	assertCertificateHead084(t, pool)
	identity, store, writeApplication := certificateAuthorizedStore085(t, pool, "write_first")

	blocker, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocker.Rollback(context.Background()) }()
	var blockerPID int
	if err := blocker.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&blockerPID); err != nil {
		t.Fatal(err)
	}
	if _, err := blocker.Exec(t.Context(), `LOCK TABLE certificate_asset_write_requests IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}

	certificatePEM, privateKeyPEM := certificateMaterial085(t, "write-first.certificate-085.example")
	writeResult := make(chan certificateWriteResult085, 1)
	go func() {
		result, err := store.Import(context.Background(), certificateasset.Actor{
			UserID: identity.tenantUser, ScopeID: identity.tenantScope, ScopeKind: certificateasset.ScopeTenant,
		}, certificateasset.ImportRequest{
			TenantScopeID: identity.tenantScope, Name: "write first certificate", Source: certificateasset.SourceUploaded,
			CertificatePEM: certificatePEM, PrivateKeyPEM: privateKeyPEM,
			IdempotencyKey: "certificate-085-write-first", RequestID: "certificate-085-write-first",
		})
		writeResult <- certificateWriteResult085{result: result, err: err}
	}()
	writePID := waitCertificateApplicationBlocked085(t, pool, writeApplication, blockerPID)

	revoke, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = revoke.Rollback(context.Background()) }()
	var revokePID int
	if err := revoke.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&revokePID); err != nil {
		t.Fatal(err)
	}
	revokeResult := make(chan error, 1)
	go func() {
		revokeResult <- revokeCertificateMembership085(context.Background(), revoke, identity)
	}()
	waitCertificateBlocked085(t, pool, revokePID, writePID)
	if err := blocker.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	written := receiveCertificateWrite085(t, writeResult)
	if written.err != nil || written.result.Asset.ID == uuid.Nil {
		t.Fatalf("authorized in-flight write result=%#v err=%v", written.result, written.err)
	}
	if err := receiveCertificateError085(t, revokeResult); err != nil {
		t.Fatal(err)
	}
	if err := revoke.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertCertificateRequestFacts085(t, pool, "certificate-085-write-first", true)

	secondPEM, secondKeyPEM := certificateMaterial085(t, "write-after-revoke.certificate-085.example")
	_, err = store.Import(t.Context(), certificateasset.Actor{
		UserID: identity.tenantUser, ScopeID: identity.tenantScope, ScopeKind: certificateasset.ScopeTenant,
	}, certificateasset.ImportRequest{
		TenantScopeID: identity.tenantScope, Name: "write after revoke", Source: certificateasset.SourceUploaded,
		CertificatePEM: secondPEM, PrivateKeyPEM: secondKeyPEM,
		IdempotencyKey: "certificate-085-after-revoke", RequestID: "certificate-085-after-revoke",
	})
	if !errors.Is(err, certificateasset.ErrPermissionDenied) {
		t.Fatalf("write after committed revoke error=%v", err)
	}
	assertCertificateRequestFacts085(t, pool, "certificate-085-after-revoke", false)
}

func TestCertificateAssetMembershipRevokeCommitsBeforeConcurrentWrite(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 84)
	assertCertificateHead084(t, pool)
	identity, store, writeApplication := certificateAuthorizedStore085(t, pool, "revoke_first")

	revoke, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = revoke.Rollback(context.Background()) }()
	var revokePID int
	if err := revoke.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&revokePID); err != nil {
		t.Fatal(err)
	}
	if err := revokeCertificateMembership085(t.Context(), revoke, identity); err != nil {
		t.Fatal(err)
	}

	certificatePEM, privateKeyPEM := certificateMaterial085(t, "revoke-first.certificate-085.example")
	writeResult := make(chan certificateWriteResult085, 1)
	go func() {
		result, err := store.Import(context.Background(), certificateasset.Actor{
			UserID: identity.tenantUser, ScopeID: identity.tenantScope, ScopeKind: certificateasset.ScopeTenant,
		}, certificateasset.ImportRequest{
			TenantScopeID: identity.tenantScope, Name: "revoke first certificate", Source: certificateasset.SourceUploaded,
			CertificatePEM: certificatePEM, PrivateKeyPEM: privateKeyPEM,
			IdempotencyKey: "certificate-085-revoke-first", RequestID: "certificate-085-revoke-first",
		})
		writeResult <- certificateWriteResult085{result: result, err: err}
	}()
	waitCertificateApplicationBlocked085(t, pool, writeApplication, revokePID)
	if err := revoke.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	denied := receiveCertificateWrite085(t, writeResult)
	if !errors.Is(denied.err, certificateasset.ErrPermissionDenied) {
		t.Fatalf("revoke-first write result=%#v err=%v", denied.result, denied.err)
	}
	assertCertificateRequestFacts085(t, pool, "certificate-085-revoke-first", false)
}

func certificateAuthorizedStore085(
	t *testing.T,
	pool *pgxpool.Pool,
	name string,
) (certificateIdentity085, *certificateasset.Store, string) {
	t.Helper()
	identity := seedCertificateIdentity085(t, pool)
	// The current Store needs the release head (it writes columns added after 085).
	if err := migrateVersionIsolated(t.Context(), pool, "up", latestMigrationVersion(t)); err != nil {
		t.Fatal(err)
	}
	applicationName := "certificate_085_" + name
	writePool, _ := certificateSingleConnectionPool085(t, pool, applicationName)
	store, err := certificateasset.NewStoreWithDependencies(writePool, certificateEnvelope085{}, audit.New(writePool), func() time.Time {
		return certificateActorScope085Now
	})
	if err != nil {
		t.Fatal(err)
	}
	return identity, store, applicationName
}

func certificateSingleConnectionPool085(
	t *testing.T,
	pool *pgxpool.Pool,
	applicationName string,
) (*pgxpool.Pool, int) {
	t.Helper()
	config := pool.Config().Copy()
	config.MaxConns = 1
	config.MinConns = 0
	config.ConnConfig.RuntimeParams["application_name"] = applicationName
	isolated, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(isolated.Close)
	connection, err := isolated.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Release()
	var backendPID int
	if err := connection.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&backendPID); err != nil {
		t.Fatal(err)
	}
	return isolated, backendPID
}

func revokeCertificateMembership085(
	ctx context.Context,
	tx pgx.Tx,
	identity certificateIdentity085,
) error {
	if _, err := protocol.BeginAuthorityMutation(ctx, tx, protocol.OperationMembershipSuspend,
		[]uuid.UUID{identity.tenantScope}); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE memberships SET status='suspended'
		WHERE scope_id=$1 AND user_id=$2`, identity.tenantScope, identity.tenantUser)
	return err
}

func waitCertificateApplicationBlocked085(
	t *testing.T,
	pool *pgxpool.Pool,
	applicationName string,
	blockerPID int,
) int {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var backendPID int
		var blocked bool
		err := pool.QueryRow(t.Context(), `SELECT pid,$2::integer=ANY(pg_blocking_pids(pid))
			FROM pg_stat_activity WHERE application_name=$1 AND datname=current_database()
			ORDER BY backend_start DESC LIMIT 1`, applicationName, blockerPID).Scan(&backendPID, &blocked)
		if err == nil && blocked {
			return backendPID
		}
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("inspect certificate application %q blocked by %d: %v", applicationName, blockerPID, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	var backendPID int
	var state, waitType, waitEvent, query string
	err := pool.QueryRow(t.Context(), `SELECT pid,state,COALESCE(wait_event_type,''),COALESCE(wait_event,''),query
		FROM pg_stat_activity WHERE application_name=$1 AND datname=current_database()
		ORDER BY backend_start DESC LIMIT 1`, applicationName).Scan(&backendPID, &state, &waitType, &waitEvent, &query)
	t.Fatalf("certificate application %q did not block behind %d: pid=%d state=%q wait=%q/%q query=%q err=%v",
		applicationName, blockerPID, backendPID, state, waitType, waitEvent, query, err)
	return 0
}

func waitCertificateBlocked085(t *testing.T, pool *pgxpool.Pool, waiterPID, blockerPID int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var blocked bool
		err := pool.QueryRow(t.Context(), `SELECT $2::integer = ANY(pg_blocking_pids($1::integer))`,
			waiterPID, blockerPID).Scan(&blocked)
		if err == nil && blocked {
			return
		}
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("inspect certificate backend %d blocked by %d: %v", waiterPID, blockerPID, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("certificate backend %d did not block behind %d", waiterPID, blockerPID)
}

func receiveCertificateWrite085(t *testing.T, result <-chan certificateWriteResult085) certificateWriteResult085 {
	t.Helper()
	select {
	case value := <-result:
		return value
	case <-time.After(15 * time.Second):
		t.Fatal("certificate write result timed out")
		return certificateWriteResult085{}
	}
}

func receiveCertificateError085(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(15 * time.Second):
		t.Fatal("certificate concurrent operation timed out")
		return nil
	}
}

func assertCertificateRequestFacts085(t *testing.T, pool *pgxpool.Pool, requestID string, expected bool) {
	t.Helper()
	var writes, audits, denials int
	// A refused import rolls back its write and records one result=denied
	// audit event on its own (b41127ae); only success events are write facts.
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM certificate_asset_write_requests WHERE idempotency_key=$1),
		(SELECT count(*) FROM audit_events WHERE request_id=$1 AND action='certificate.asset.import' AND result='success'),
		(SELECT count(*) FROM audit_events WHERE request_id=$1 AND action='certificate.asset.import' AND result='denied')`,
		requestID).Scan(&writes, &audits, &denials); err != nil {
		t.Fatal(err)
	}
	want, wantDenials := 0, 1
	if expected {
		want, wantDenials = 1, 0
	}
	if writes != want || audits != want || denials != wantDenials {
		t.Fatalf("certificate request %q facts writes=%d audits=%d denials=%d want=%d/%d",
			requestID, writes, audits, denials, want, wantDenials)
	}
}

func seedCertificateIdentity085(t *testing.T, pool *pgxpool.Pool) certificateIdentity085 {
	t.Helper()
	identity := certificateIdentity085{
		tenantScope: uuid.New(), tenantUser: uuid.New(), platformScope: uuid.New(),
		platformUser: uuid.New(), platformRole: uuid.New(),
	}
	tenantID, tenantRole := uuid.New(), uuid.New()
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		statements := []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO tenants(id,display_name) VALUES($1,'certificate 085 tenant')`, []any{tenantID}},
			{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2),($3,'platform',NULL)`, []any{identity.tenantScope, tenantID, identity.platformScope}},
			{`INSERT INTO users(id,username,display_name,password_hash) VALUES
				($1,$2,'certificate tenant actor','test-password-hash'),
				($3,$4,'certificate platform actor','test-password-hash')`, []any{
				identity.tenantUser, "certificate-tenant-" + identity.tenantUser.String(),
				identity.platformUser, "certificate-platform-" + identity.platformUser.String(),
			}},
			{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2),($3,$4)`, []any{identity.tenantScope, identity.tenantUser, identity.platformScope, identity.platformUser}},
			{`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES
				($1,$2,'tenant_owner','certificate owner',true),
				($3,$4,'platform_owner','platform owner',true)`, []any{tenantRole, identity.tenantScope, identity.platformRole, identity.platformScope}},
			{`INSERT INTO role_permissions(role_id,permission_name) VALUES
				($1,'certificates.read'),($1,'certificates.manage')`, []any{tenantRole}},
			{`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3),($4,$5,$6)`, []any{identity.tenantScope, identity.tenantUser, tenantRole, identity.platformScope, identity.platformUser, identity.platformRole}},
		}
		for _, statement := range statements {
			if _, err := tx.Exec(t.Context(), statement.sql, statement.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func insertCertificateSite085(t *testing.T, pool *pgxpool.Pool, identity certificateIdentity085, domain string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO sites(
			id,scope_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,updated_by_user_id
		) VALUES($1,$2,$3,$4,ARRAY['origin.example.test:443'],ARRAY['origin.example.test'],$3,$3)`,
			id, identity.tenantScope, identity.tenantUser, domain); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO site_origin_pools(site_id) VALUES($1)`, id); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO site_origins(site_id,position,host,port)
			VALUES($1,1,'origin.example.test',443)`, id)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func certificateMaterial085(t *testing.T, domain string) ([]byte, []byte) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{
		SerialNumber: big.NewInt(8500), Subject: pkix.Name{CommonName: "Certificate 085 Root"},
		NotBefore: certificateActorScope085Now.Add(-time.Hour), NotAfter: certificateActorScope085Now.Add(365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, IsCA: true, BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(8501), Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain},
		NotBefore: certificateActorScope085Now.Add(-time.Hour), NotAfter: certificateActorScope085Now.Add(90 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})...)
	return certificatePEM,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
}

func assertCertificateActorColumns085(t *testing.T, pool *pgxpool.Pool, want bool) {
	t.Helper()
	columns := [][2]string{
		{"certificate_assets", "created_by_scope_id"}, {"certificate_assets", "updated_by_scope_id"},
		{"certificate_assets", "deleted_by_scope_id"}, {"certificate_asset_versions", "actor_scope_id"},
		{"certificate_asset_private_key_envelope_facts", "actor_scope_id"},
		{"certificate_asset_activation_facts", "actor_scope_id"},
		{"certificate_asset_revocation_facts", "actor_scope_id"},
		{"certificate_site_binding_facts", "actor_scope_id"}, {"certificate_asset_write_requests", "actor_scope_id"},
	}
	for _, column := range columns {
		var got bool
		if err := pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM information_schema.columns
			WHERE table_schema=current_schema() AND table_name=$1 AND column_name=$2)`, column[0], column[1]).Scan(&got); err != nil || got != want {
			t.Fatalf("%s.%s exists=%t want=%t err=%v", column[0], column[1], got, want, err)
		}
	}
}

func assertCertificatePlatformRole085(t *testing.T, pool *pgxpool.Pool, roleID uuid.UUID, want bool) {
	t.Helper()
	var count int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM role_permissions WHERE role_id=$1
		AND permission_name IN ('certificates.read','certificates.manage')`, roleID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if (count == 2) != want {
		t.Fatalf("platform certificate permission count=%d want_present=%t", count, want)
	}
}

func assertCertificatePlatformFacts085(t *testing.T, pool *pgxpool.Pool, identity certificateIdentity085, assetID uuid.UUID) {
	t.Helper()
	checks := []struct{ table, scopeColumn, userColumn string }{
		{"certificate_asset_versions", "actor_scope_id", "imported_by_user_id"},
		{"certificate_asset_private_key_envelope_facts", "actor_scope_id", "changed_by_user_id"},
		{"certificate_asset_activation_facts", "actor_scope_id", "activated_by_user_id"},
		{"certificate_asset_revocation_facts", "actor_scope_id", "revoked_by_user_id"},
		{"certificate_site_binding_facts", "actor_scope_id", "changed_by_user_id"},
		{"certificate_asset_write_requests", "actor_scope_id", "actor_user_id"},
	}
	for _, check := range checks {
		query := `SELECT count(*) FROM ` + check.table + ` WHERE tenant_scope_id=$1 AND ` + check.scopeColumn + `=$2 AND ` + check.userColumn + `=$3`
		var count int
		if err := pool.QueryRow(t.Context(), query, identity.tenantScope, identity.platformScope, identity.platformUser).Scan(&count); err != nil || count == 0 {
			t.Fatalf("%s platform facts=%d err=%v", check.table, count, err)
		}
	}
	var assetActors bool
	if err := pool.QueryRow(t.Context(), `SELECT created_by_scope_id=$2 AND updated_by_scope_id=$2 AND deleted_by_scope_id=$2
		AND created_by_user_id=$3 AND updated_by_user_id=$3 AND deleted_by_user_id=$3
		FROM certificate_assets WHERE tenant_scope_id=$1 AND id=$4`, identity.tenantScope, identity.platformScope,
		identity.platformUser, assetID).Scan(&assetActors); err != nil || !assetActors {
		t.Fatalf("certificate asset platform actor facts=%t err=%v", assetActors, err)
	}
	var invalidAudits int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE scope_id=$1
		AND action LIKE 'certificate.asset.%' AND (
			payload->>'actor_scope_id' IS DISTINCT FROM $2 OR payload->>'target_scope_id' IS DISTINCT FROM $1::text OR
			payload->>'operation' IS DISTINCT FROM action OR COALESCE(payload->>'reason','')=''
		)`, identity.tenantScope, identity.platformScope.String()).Scan(&invalidAudits); err != nil || invalidAudits != 0 {
		t.Fatalf("invalid certificate audit payloads=%d err=%v", invalidAudits, err)
	}
}

func assertCertificateCode085(t *testing.T, err error, want string) {
	t.Helper()
	var pgError *pgconn.PgError
	if !errors.As(err, &pgError) || pgError.Code != want {
		t.Fatalf("PostgreSQL error=%v code=%q want=%q", err, func() string {
			if pgError == nil {
				return ""
			}
			return pgError.Code
		}(), want)
	}
}

func assertCertificateHead084(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	var identifier, up, down, integrity string
	var metadata, applied bool
	if err := pool.QueryRow(t.Context(), `SELECT migration_id,checksum_sha256,down_checksum_sha256,
		integrity_state,metadata_recorded_at IS NOT NULL,applied_at IS NOT NULL
		FROM schema_migrations WHERE version=84`).Scan(&identifier, &up, &down, &integrity, &metadata, &applied); err != nil {
		t.Fatal(err)
	}
	if identifier != "084_plugin_webhook_control" ||
		up != "f51e909422b4254b49204d85cd4adec7ad0fed9da29686fd872651010220a56d" ||
		down != "b914352bc35e24c6bd9d12b90255ab42586dfb9e31438825961c02cb37cbc3be" ||
		integrity != "verified" || !metadata || !applied {
		t.Fatalf("084 ledger id=%s up=%s down=%s integrity=%s metadata=%t applied=%t",
			identifier, up, down, integrity, metadata, applied)
	}
}
