package plugininstallation

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrStorageUnavailable = errors.New("plugin installation storage unavailable")

type PostgresRepository struct {
	pool    *pgxpool.Pool
	now     func() time.Time
	auditor *audit.Log
}

func NewPostgresRepository(pool *pgxpool.Pool, now func() time.Time) (*PostgresRepository, error) {
	if !configuredPluginInstallationPool(pool) || now == nil {
		return nil, ErrInvalidInput
	}
	return &PostgresRepository{pool: pool, now: now, auditor: audit.NewWithClock(pool, now)}, nil
}

func (repository *PostgresRepository) List(ctx context.Context, actor Actor, request ListRequest) (Page, error) {
	if ctx == nil || repository == nil || repository.pool == nil || request.TenantID != actor.TenantID ||
		request.Limit < 1 || request.Limit > 100 {
		return Page{}, ErrInvalidInput
	}
	tx, err := repository.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return Page{}, postgresError(ctx, err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := authorizePluginInstallationActor(ctx, tx, actor, PermissionRead); err != nil {
		return Page{}, err
	}
	cursorTime, cursorID, err := decodePluginInstallationCursor(request.Cursor, request.Status, request.PluginID)
	if err != nil {
		return Page{}, err
	}
	rows, err := tx.Query(ctx, `SELECT tenant_scope_id,authorization_id,installation_id,verification_id,
		plugin_id,plugin_version,manifest_sha256,configuration_schema_sha256,manifest_scopes,approved_scopes,
		sensitive_scopes,status,revision,identity_generation,lkg_verification_id,lkg_version,
		stable_reason_code,created_at,updated_at,resource_scope,entrypoint_type
		FROM plugin_installation_heads
		WHERE `+visibleHeads(actor, "$1")+` AND ($2='' OR status=$2) AND ($3='' OR plugin_id=$3) AND
		($4::timestamptz IS NULL OR (updated_at,authorization_id)<($4,$5))
		ORDER BY updated_at DESC,authorization_id DESC LIMIT $6`, request.TenantID, request.Status,
		request.PluginID, cursorTime, cursorID, request.Limit+1)
	if err != nil {
		return Page{}, postgresError(ctx, err)
	}
	defer rows.Close()
	items := make([]InstallationView, 0, request.Limit+1)
	for rows.Next() {
		item, err := scanPluginInstallation(rows)
		if err != nil {
			return Page{}, postgresError(ctx, err)
		}
		items = append(items, installationViewFor(actor, item))
	}
	if err := rows.Err(); err != nil {
		return Page{}, postgresError(ctx, err)
	}
	if err := attachTargets(ctx, tx, actor, items); err != nil {
		return Page{}, err
	}
	page := Page{Items: items}
	if len(items) > request.Limit {
		page.Items = items[:request.Limit]
		last := page.Items[len(page.Items)-1].Installation
		page.NextCursor, err = encodePluginInstallationCursor(last.UpdatedAt, last.AuthorizationID,
			request.Status, request.PluginID)
		if err != nil {
			return Page{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return Page{}, postgresError(ctx, err)
	}
	return page, nil
}

func (repository *PostgresRepository) Get(ctx context.Context, actor Actor,
	authorizationID uuid.UUID) (InstallationView, error) {
	if ctx == nil || repository == nil || repository.pool == nil || authorizationID == uuid.Nil {
		return InstallationView{}, ErrInvalidInput
	}
	tx, err := repository.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return InstallationView{}, postgresError(ctx, err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := authorizePluginInstallationActor(ctx, tx, actor, PermissionRead); err != nil {
		return InstallationView{}, err
	}
	value, err := loadVisiblePluginInstallation(ctx, tx, actor, authorizationID)
	if err != nil {
		return InstallationView{}, err
	}
	views := []InstallationView{installationViewFor(actor, value)}
	if err := attachTargets(ctx, tx, actor, views); err != nil {
		return InstallationView{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return InstallationView{}, postgresError(ctx, err)
	}
	return views[0], nil
}

// visibleHeads is the head filter of a list: a tenant reads its own heads and the tenant plugins the platform
// administrator installed for it (migration 636); the platform scope reads the heads it holds.
func visibleHeads(actor Actor, scope string) string {
	if actor.resourceScope() == ResourceScopeTenant {
		return "(tenant_scope_id=" + scope + " OR (resource_scope='tenant' AND tenant_scope_id<>" + scope +
			" AND plugin_installation_covers_tenant_636(authorization_id," + scope + ")))"
	}
	return "tenant_scope_id=" + scope
}

// loadVisiblePluginInstallation reads one head the actor may see (visibleHeads). Writes keep using the exact scope
// (loadPluginInstallation): a tenant never writes a head the platform holds.
func loadVisiblePluginInstallation(ctx context.Context, tx pgx.Tx, actor Actor,
	authorizationID uuid.UUID) (Installation, error) {
	value, err := scanPluginInstallation(tx.QueryRow(ctx, `SELECT tenant_scope_id,authorization_id,installation_id,
		verification_id,plugin_id,plugin_version,manifest_sha256,configuration_schema_sha256,manifest_scopes,
		approved_scopes,sensitive_scopes,status,revision,identity_generation,lkg_verification_id,lkg_version,
		stable_reason_code,created_at,updated_at,resource_scope,entrypoint_type
		FROM plugin_installation_heads WHERE authorization_id=$2 AND `+visibleHeads(actor, "$1"), actor.TenantID,
		authorizationID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Installation{}, ErrNotFound
	}
	if err != nil {
		return Installation{}, postgresError(ctx, err)
	}
	return value, nil
}

// installationViewFor marks who manages a stored head: a tenant manages only the heads its own scope holds.
func installationViewFor(actor Actor, value Installation) InstallationView {
	view := installationView(value)
	view.ManagedBy = ManagedByPlatform
	if actor.resourceScope() == ResourceScopeTenant && value.TenantID == actor.TenantID {
		view.ManagedBy = ManagedByTenant
	}
	return view
}

// attachTargets adds the target sets to the platform administrator's view of its tenant plugins. Tenants never read
// which other tenants a plugin is installed for.
func attachTargets(ctx context.Context, tx pgx.Tx, actor Actor, views []InstallationView) error {
	if actor.resourceScope() != ResourceScopePlatform {
		return nil
	}
	ids := make([]uuid.UUID, 0, len(views))
	for _, view := range views {
		if view.Installation.ResourceScope == ResourceScopeTenant {
			ids = append(ids, view.Installation.AuthorizationID)
		}
	}
	targets, err := loadTargetsFor(ctx, tx, ids)
	if err != nil {
		return err
	}
	for index := range views {
		views[index].Targets = targets[views[index].Installation.AuthorizationID]
	}
	return nil
}

func (repository *PostgresRepository) HasReceipt(ctx context.Context, actor Actor, authorizationID uuid.UUID,
	idempotencyKey string) (bool, error) {
	if ctx == nil || repository == nil || repository.pool == nil || authorizationID == uuid.Nil ||
		!idempotencyPattern.MatchString(idempotencyKey) {
		return false, ErrInvalidInput
	}
	tx, err := repository.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return false, postgresError(ctx, err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := authorizePluginInstallationActor(ctx, tx, actor, PermissionManage); err != nil {
		return false, err
	}
	var found bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM plugin_installation_receipts
		WHERE tenant_scope_id=$1 AND authorization_id=$2 AND idempotency_key=$3)`, actor.TenantID, authorizationID,
		idempotencyKey).Scan(&found); err != nil {
		return false, postgresError(ctx, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, postgresError(ctx, err)
	}
	return found, nil
}

// Receipt returns this scope's persisted receipt of the authorization under the idempotency key (ReceiptReader).
func (repository *PostgresRepository) Receipt(ctx context.Context, actor Actor, authorizationID uuid.UUID,
	idempotencyKey string) (Receipt, bool, error) {
	if ctx == nil || repository == nil || repository.pool == nil || authorizationID == uuid.Nil ||
		!idempotencyPattern.MatchString(idempotencyKey) {
		return Receipt{}, false, ErrInvalidInput
	}
	// Read-write only because Replay locks the row (FOR UPDATE); nothing is written and the transaction rolls back.
	tx, err := repository.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Receipt{}, false, postgresError(ctx, err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := authorizePluginInstallationActor(ctx, tx, actor, PermissionManage); err != nil {
		return Receipt{}, false, err
	}
	transaction := &postgresTransaction{tx: tx, tenantID: actor.TenantID, authorizationID: authorizationID,
		actor: actor, auditor: repository.auditor, ctx: ctx}
	return transaction.Replay(idempotencyKey)
}

func (repository *PostgresRepository) Apply(ctx context.Context, actor Actor, command Command,
	verifier CandidateVerifier) (MutationResult, error) {
	if ctx == nil || repository == nil || repository.pool == nil || command.TenantID != actor.TenantID {
		return MutationResult{}, ErrInvalidInput
	}
	store := &postgresStore{repository: repository, actor: actor}
	result, err := (Service{Store: store, Verifier: verifier, Now: repository.now}).Apply(ctx, command)
	if err != nil {
		return MutationResult{}, err
	}
	return result, nil
}

type postgresStore struct {
	repository *PostgresRepository
	actor      Actor
}

func (store *postgresStore) Transact(ctx context.Context, tenantID, authorizationID uuid.UUID,
	callback func(Transaction) error) error {
	if ctx == nil || store == nil || store.repository == nil || store.repository.pool == nil ||
		tenantID != store.actor.TenantID || authorizationID == uuid.Nil || callback == nil {
		return ErrInvalidInput
	}
	tx, err := store.repository.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return postgresError(ctx, err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := authorizePluginInstallationActor(ctx, tx, store.actor, PermissionManage); err != nil {
		return err
	}
	// One lock per authorization (not per scope): two tenants confirming the same authorization concurrently
	// serialize, so the target binding check below sees the other's head (migration 605 unique index backs it).
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('plugin-installation:' || $1::text,0))`,
		authorizationID); err != nil {
		return postgresError(ctx, err)
	}
	transaction := &postgresTransaction{tx: tx, tenantID: tenantID, authorizationID: authorizationID,
		actor: store.actor, auditor: store.repository.auditor, ctx: ctx}
	if err := callback(transaction); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		if ctx.Err() != nil {
			return ErrResultUnknown
		}
		return fmt.Errorf("%w: commit plugin installation", ErrResultUnknown)
	}
	return nil
}

type postgresTransaction struct {
	tx              pgx.Tx
	tenantID        uuid.UUID
	authorizationID uuid.UUID
	actor           Actor
	auditor         *audit.Log
	ctx             context.Context
}

func (transaction *postgresTransaction) Current() (Installation, bool, error) {
	value, err := loadPluginInstallation(transaction.ctx, transaction.tx, transaction.tenantID,
		transaction.authorizationID, true)
	if errors.Is(err, ErrNotFound) {
		return Installation{}, false, nil
	}
	if err != nil {
		return Installation{}, false, err
	}
	return value, true, nil
}

func (transaction *postgresTransaction) BoundElsewhere() (bool, error) {
	var bound bool
	if err := transaction.tx.QueryRow(transaction.ctx, `SELECT EXISTS(SELECT 1 FROM plugin_installation_heads
		WHERE authorization_id=$1 AND tenant_scope_id<>$2)`, transaction.authorizationID,
		transaction.tenantID).Scan(&bound); err != nil {
		return false, postgresError(transaction.ctx, err)
	}
	return bound, nil
}

func (transaction *postgresTransaction) Replay(idempotencyKey string) (Receipt, bool, error) {
	var receipt Receipt
	var digest, snapshot []byte
	var reason, stableReason, attemptedVersion *string
	var attemptedVerificationID *uuid.UUID
	err := transaction.tx.QueryRow(transaction.ctx, `SELECT id,action,idempotency_key,request_id,
		request_digest,from_revision,to_revision,result,reason,stable_reason_code,attempted_verification_id,
		attempted_version,response_snapshot,occurred_at
		FROM plugin_installation_receipts
		WHERE tenant_scope_id=$1 AND authorization_id=$2 AND idempotency_key=$3 FOR UPDATE`,
		transaction.tenantID, transaction.authorizationID, idempotencyKey).Scan(&receipt.ID, &receipt.Action,
		&receipt.IdempotencyKey, &receipt.RequestID, &digest, &receipt.FromRevision, &receipt.ToRevision,
		&receipt.Result, &reason, &stableReason, &attemptedVerificationID, &attemptedVersion, &snapshot,
		&receipt.OccurredAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Receipt{}, false, nil
	}
	if err != nil || len(digest) != 32 || strictJSON(snapshot, &receipt.Snapshot) != nil {
		return Receipt{}, false, postgresError(transaction.ctx, err)
	}
	receipt.TenantID, receipt.AuthorizationID = transaction.tenantID, transaction.authorizationID
	copy(receipt.RequestDigest[:], digest)
	if reason != nil {
		receipt.Reason = *reason
	}
	if stableReason != nil {
		receipt.StableReasonCode = *stableReason
	}
	if attemptedVerificationID != nil {
		receipt.AttemptedVerificationID = *attemptedVerificationID
	}
	if attemptedVersion != nil {
		receipt.AttemptedVersion = *attemptedVersion
	}
	if !validStoredInstallation(receipt.Snapshot) {
		return Receipt{}, false, ErrStorageUnavailable
	}
	return receipt, true, nil
}

func (transaction *postgresTransaction) Save(value Installation, receipt Receipt) error {
	manifestDigest, manifestErr := hex.DecodeString(value.ManifestSHA256)
	configurationDigest, configurationErr := hex.DecodeString(value.ConfigurationSchemaSHA256)
	if manifestErr != nil || configurationErr != nil || !validStoredInstallation(value) ||
		receipt.TenantID != transaction.tenantID || receipt.AuthorizationID != transaction.authorizationID {
		return ErrInvalidInput
	}
	if receipt.FromRevision == 0 {
		_, err := transaction.tx.Exec(transaction.ctx, `INSERT INTO plugin_installation_heads(
			tenant_scope_id,authorization_id,installation_id,verification_id,plugin_id,plugin_version,
			manifest_sha256,configuration_schema_sha256,manifest_scopes,approved_scopes,sensitive_scopes,
			status,revision,identity_generation,lkg_verification_id,lkg_version,stable_reason_code,created_at,updated_at,
			resource_scope,entrypoint_type
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$18,$19,$20)`,
			value.TenantID, value.AuthorizationID, value.InstallationID, value.VerificationID, value.PluginID,
			value.Version, manifestDigest, configurationDigest, value.ManifestScopes, value.ApprovedScopes,
			value.SensitiveScopes, value.Status, value.Revision, value.IdentityGeneration,
			nullableUUID(value.LKGVerificationID), nullableString(value.LKGVersion),
			nullableString(value.StableReasonCode), value.UpdatedAt, value.ResourceScope, value.EntrypointType)
		if err != nil {
			return postgresError(transaction.ctx, err)
		}
	} else {
		command, err := transaction.tx.Exec(transaction.ctx, `UPDATE plugin_installation_heads SET
			verification_id=$3,plugin_version=$4,manifest_sha256=$5,configuration_schema_sha256=$6,
			manifest_scopes=$7,approved_scopes=$8,sensitive_scopes=$9,status=$10,revision=$11,
			identity_generation=$12,lkg_verification_id=$13,lkg_version=$14,stable_reason_code=$15,updated_at=$16
			WHERE tenant_scope_id=$1 AND authorization_id=$2 AND revision=$17`, value.TenantID,
			value.AuthorizationID, value.VerificationID, value.Version, manifestDigest, configurationDigest,
			value.ManifestScopes, value.ApprovedScopes, value.SensitiveScopes, value.Status, value.Revision,
			value.IdentityGeneration, nullableUUID(value.LKGVerificationID), nullableString(value.LKGVersion),
			nullableString(value.StableReasonCode), value.UpdatedAt, receipt.FromRevision)
		if err != nil {
			return postgresError(transaction.ctx, err)
		}
		if command.RowsAffected() != 1 {
			return ErrRevisionConflict
		}
	}
	snapshot, err := json.Marshal(receipt.Snapshot)
	if err != nil {
		return ErrInvalidInput
	}
	_, err = transaction.tx.Exec(transaction.ctx, `INSERT INTO plugin_installation_receipts(
		id,tenant_scope_id,authorization_id,action,idempotency_key,request_id,request_digest,
		from_revision,to_revision,result,reason,stable_reason_code,attempted_verification_id,
		attempted_version,response_snapshot,actor_user_id,actor_session_id,occurred_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`, receipt.ID,
		receipt.TenantID, receipt.AuthorizationID, receipt.Action, receipt.IdempotencyKey, receipt.RequestID,
		receipt.RequestDigest[:], receipt.FromRevision, receipt.ToRevision, receipt.Result,
		nullableString(receipt.Reason), nullableString(receipt.StableReasonCode),
		nullableUUID(receipt.AttemptedVerificationID), nullableString(receipt.AttemptedVersion), snapshot,
		transaction.actor.UserID, transaction.actor.SessionID, receipt.OccurredAt)
	if err != nil {
		return postgresError(transaction.ctx, err)
	}
	return transaction.auditor.Append(transaction.ctx, transaction.tx, audit.Event{
		ScopeID: transaction.tenantID, ActorUserID: &transaction.actor.UserID,
		Action: "plugin_installation." + receipt.Action, ResourceType: "plugin_installation",
		ResourceID: receipt.AuthorizationID.String(), RequestID: receipt.RequestID, Result: "success",
		Payload: map[string]any{"receipt_id": receipt.ID.String(), "result": receipt.Result,
			"from_revision": receipt.FromRevision, "to_revision": receipt.ToRevision,
			"reason_present": receipt.Reason != "", "resource_scope": value.ResourceScope,
			"entrypoint_type": value.EntrypointType,
			"plugin_id":       value.PluginID, "version": value.Version, "status": value.Status},
	})
}

// licenseReportReceiptColumns are the receipt columns scanned by scanLicenseReportReceipts, as "receipt".
const licenseReportReceiptColumns = `receipt.id,receipt.tenant_scope_id,receipt.authorization_id,
		receipt.action,receipt.idempotency_key,receipt.request_id,receipt.request_digest,receipt.from_revision,
		receipt.to_revision,receipt.result,receipt.reason,receipt.stable_reason_code,receipt.attempted_verification_id,
		receipt.attempted_version,receipt.response_snapshot,receipt.occurred_at`

// UnreportedReceipts implements LicenseReportLedger (migration 684). It runs as the control plane itself (the
// background replay has no session): it reads committed receipts and changes nothing.
func (repository *PostgresRepository) UnreportedReceipts(ctx context.Context, installationID, authorizationID uuid.UUID,
	limit int) ([]Receipt, error) {
	if ctx == nil || repository == nil || repository.pool == nil || limit < 1 || limit > 1000 {
		return nil, ErrInvalidInput
	}
	rows, err := repository.pool.Query(ctx, `SELECT `+licenseReportReceiptColumns+`
		FROM plugin_installation_receipts receipt
		JOIN plugin_installation_heads head ON head.tenant_scope_id=receipt.tenant_scope_id AND
			head.authorization_id=receipt.authorization_id
		WHERE NOT EXISTS (SELECT 1 FROM plugin_installation_license_reports report WHERE report.receipt_id=receipt.id)
			AND ($1::uuid IS NULL OR head.installation_id=$1) AND ($2::uuid IS NULL OR receipt.authorization_id=$2)
		ORDER BY receipt.authorization_id,receipt.to_revision LIMIT $3`,
		nullableUUID(installationID), nullableUUID(authorizationID), limit)
	if err != nil {
		return nil, postgresError(ctx, err)
	}
	return scanLicenseReportReceipts(ctx, rows)
}

// PendingAuthorizations implements LicenseReportLedger: one EXISTS per requested authorization, so a page is
// marked from its own receipts whatever the backlog of other authorizations.
func (repository *PostgresRepository) PendingAuthorizations(ctx context.Context, installationID uuid.UUID,
	authorizationIDs []uuid.UUID) (map[uuid.UUID]bool, error) {
	if ctx == nil || repository == nil || repository.pool == nil || len(authorizationIDs) > 1000 {
		return nil, ErrInvalidInput
	}
	pending := make(map[uuid.UUID]bool, len(authorizationIDs))
	if len(authorizationIDs) == 0 {
		return pending, nil
	}
	rows, err := repository.pool.Query(ctx, `SELECT requested.id FROM unnest($2::uuid[]) AS requested(id)
		WHERE EXISTS (SELECT 1 FROM plugin_installation_receipts receipt
			JOIN plugin_installation_heads head ON head.tenant_scope_id=receipt.tenant_scope_id AND
				head.authorization_id=receipt.authorization_id
			WHERE receipt.authorization_id=requested.id AND ($1::uuid IS NULL OR head.installation_id=$1) AND
				NOT EXISTS (SELECT 1 FROM plugin_installation_license_reports report WHERE report.receipt_id=receipt.id))`,
		nullableUUID(installationID), authorizationIDs)
	if err != nil {
		return nil, postgresError(ctx, err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return nil, postgresError(ctx, err)
	}
	for _, id := range ids {
		pending[id] = true
	}
	return pending, nil
}

// DueReports implements LicenseReportLedger: only the oldest unacknowledged
// receipt of each authorization, skipping those backing off; never attempted first, then the least recently
// attempted, so an authorization that keeps failing cannot hold the window.
func (repository *PostgresRepository) DueReports(ctx context.Context, installationID uuid.UUID, limit int) ([]Receipt, error) {
	if ctx == nil || repository == nil || repository.pool == nil || limit < 1 || limit > 1000 {
		return nil, ErrInvalidInput
	}
	rows, err := repository.pool.Query(ctx, `SELECT `+licenseReportReceiptColumns+` FROM (
			SELECT DISTINCT ON (receipt.authorization_id) receipt.*
			FROM plugin_installation_receipts receipt
			JOIN plugin_installation_heads head ON head.tenant_scope_id=receipt.tenant_scope_id AND
				head.authorization_id=receipt.authorization_id
			WHERE NOT EXISTS (SELECT 1 FROM plugin_installation_license_reports report WHERE report.receipt_id=receipt.id)
				AND ($1::uuid IS NULL OR head.installation_id=$1)
			ORDER BY receipt.authorization_id,receipt.to_revision) receipt
		LEFT JOIN plugin_installation_license_report_attempts attempt ON attempt.receipt_id=receipt.id
		WHERE attempt.receipt_id IS NULL OR attempt.next_attempt_at<=$2
		ORDER BY attempt.last_attempted_at NULLS FIRST,receipt.authorization_id LIMIT $3`,
		nullableUUID(installationID), repository.now().UTC(), limit)
	if err != nil {
		return nil, postgresError(ctx, err)
	}
	return scanLicenseReportReceipts(ctx, rows)
}

// RecordReportFailure implements LicenseReportLedger: the wait doubles per failure of the receipt (from base<<1,
// at most base<<5) and never exceeds maxWait.
func (repository *PostgresRepository) RecordReportFailure(ctx context.Context, receiptID uuid.UUID,
	base, maxWait time.Duration) (int, time.Duration, error) {
	if ctx == nil || repository == nil || repository.pool == nil || receiptID == uuid.Nil || base <= 0 || maxWait < base {
		return 0, 0, ErrInvalidInput
	}
	now := repository.now().UTC()
	var failures int
	var next time.Time
	err := repository.pool.QueryRow(ctx, `INSERT INTO plugin_installation_license_report_attempts AS attempt(
			receipt_id,failures,last_attempted_at,next_attempt_at)
		VALUES($1,1,$2::timestamptz,$2::timestamptz+LEAST($4::bigint,$3::bigint*2)*interval '1 microsecond')
		ON CONFLICT (receipt_id) DO UPDATE SET failures=attempt.failures+1,last_attempted_at=$2::timestamptz,
			next_attempt_at=$2::timestamptz+LEAST($4::bigint,$3::bigint*(1::bigint<<LEAST(attempt.failures+1,5)))*interval '1 microsecond'
		RETURNING failures,next_attempt_at`, receiptID, now, base.Microseconds(), maxWait.Microseconds()).
		Scan(&failures, &next)
	if err != nil {
		return 0, 0, postgresError(ctx, err)
	}
	return failures, next.Sub(now), nil
}

func scanLicenseReportReceipts(ctx context.Context, rows pgx.Rows) ([]Receipt, error) {
	receipts, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Receipt, error) {
		var receipt Receipt
		var digest, snapshot []byte
		var reason, stableReason, attemptedVersion *string
		var attemptedVerificationID *uuid.UUID
		if err := row.Scan(&receipt.ID, &receipt.TenantID, &receipt.AuthorizationID, &receipt.Action,
			&receipt.IdempotencyKey, &receipt.RequestID, &digest, &receipt.FromRevision, &receipt.ToRevision,
			&receipt.Result, &reason, &stableReason, &attemptedVerificationID, &attemptedVersion, &snapshot,
			&receipt.OccurredAt); err != nil {
			return Receipt{}, err
		}
		if len(digest) != 32 || strictJSON(snapshot, &receipt.Snapshot) != nil || !validStoredInstallation(receipt.Snapshot) {
			return Receipt{}, ErrStorageUnavailable
		}
		copy(receipt.RequestDigest[:], digest)
		if reason != nil {
			receipt.Reason = *reason
		}
		if stableReason != nil {
			receipt.StableReasonCode = *stableReason
		}
		if attemptedVerificationID != nil {
			receipt.AttemptedVerificationID = *attemptedVerificationID
		}
		if attemptedVersion != nil {
			receipt.AttemptedVersion = *attemptedVersion
		}
		return receipt, nil
	})
	if errors.Is(err, ErrStorageUnavailable) {
		return nil, err
	}
	if err != nil {
		return nil, postgresError(ctx, err)
	}
	return receipts, nil
}

// MarkReported implements LicenseReportLedger: the license service signed for the receipt.
func (repository *PostgresRepository) MarkReported(ctx context.Context, receiptID uuid.UUID, lifecycleRevision uint64) error {
	if ctx == nil || repository == nil || repository.pool == nil || receiptID == uuid.Nil || lifecycleRevision == 0 {
		return ErrInvalidInput
	}
	if _, err := repository.pool.Exec(ctx, `INSERT INTO plugin_installation_license_reports(receipt_id,lifecycle_revision,
		reported_at) VALUES($1,$2,$3) ON CONFLICT (receipt_id) DO NOTHING`, receiptID, lifecycleRevision,
		repository.now().UTC()); err != nil {
		return postgresError(ctx, err)
	}
	return nil
}

func authorizePluginInstallationActor(ctx context.Context, tx pgx.Tx, actor Actor, permission string) error {
	if actor.UserID == uuid.Nil || actor.SessionID == uuid.Nil || actor.TenantID == uuid.Nil ||
		(permission != PermissionRead && permission != PermissionManage) {
		return identity.ErrInvalidSession
	}
	// Platform resources are managed in the platform scope with the exact platform permissions; tenant
	// plugins in a tenant scope with the tenant permissions (no fallback either way).
	scopeKind := actor.resourceScope()
	if scopeKind == ResourceScopePlatform {
		permission = map[string]string{PermissionRead: PermissionPlatformRead, PermissionManage: PermissionPlatformManage}[permission]
	}
	var allowed bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM auth_sessions AS session
		JOIN users AS user_account ON user_account.id=session.user_id AND user_account.status='active'
		JOIN memberships AS membership ON membership.scope_id=session.scope_id AND
			membership.user_id=session.user_id AND membership.status='active'
		JOIN access_scopes AS scope ON scope.id=session.scope_id AND scope.kind=$5 AND
			(scope.kind='platform' OR scope.tenant_id IS NOT NULL)
		JOIN role_assignments AS assignment ON assignment.scope_id=membership.scope_id AND assignment.user_id=membership.user_id
		JOIN roles AS role ON role.scope_id=assignment.scope_id AND role.id=assignment.role_id
		JOIN role_permissions AS grant_row ON grant_row.role_id=role.id AND grant_row.permission_name=$4
		WHERE session.id=$1 AND session.user_id=$2 AND session.scope_id=$3 AND
			session.revoked_at IS NULL AND session.expires_at>transaction_timestamp()
	)`, actor.SessionID, actor.UserID, actor.TenantID, permission, scopeKind).Scan(&allowed)
	if err != nil {
		return postgresError(ctx, err)
	}
	if !allowed {
		return identity.ErrPermissionDenied
	}
	return nil
}

type pluginInstallationScanner interface {
	Scan(...any) error
}

func loadPluginInstallation(ctx context.Context, tx pgx.Tx, tenantID,
	authorizationID uuid.UUID, lock bool) (Installation, error) {
	query := `SELECT tenant_scope_id,authorization_id,installation_id,verification_id,
		plugin_id,plugin_version,manifest_sha256,configuration_schema_sha256,manifest_scopes,approved_scopes,
		sensitive_scopes,status,revision,identity_generation,lkg_verification_id,lkg_version,
		stable_reason_code,created_at,updated_at,resource_scope,entrypoint_type
		FROM plugin_installation_heads WHERE tenant_scope_id=$1 AND authorization_id=$2`
	if lock {
		query += " FOR UPDATE"
	}
	value, err := scanPluginInstallation(tx.QueryRow(ctx, query, tenantID, authorizationID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Installation{}, ErrNotFound
	}
	if err != nil {
		return Installation{}, postgresError(ctx, err)
	}
	return value, nil
}

func scanPluginInstallation(scanner pluginInstallationScanner) (Installation, error) {
	var value Installation
	var manifestDigest, configurationDigest []byte
	var lkgVerificationID *uuid.UUID
	var lkgVersion, stableReason *string
	var createdAt time.Time
	err := scanner.Scan(&value.TenantID, &value.AuthorizationID, &value.InstallationID,
		&value.VerificationID, &value.PluginID, &value.Version, &manifestDigest, &configurationDigest,
		&value.ManifestScopes, &value.ApprovedScopes, &value.SensitiveScopes, &value.Status, &value.Revision,
		&value.IdentityGeneration, &lkgVerificationID, &lkgVersion, &stableReason, &createdAt, &value.UpdatedAt,
		&value.ResourceScope, &value.EntrypointType)
	if err != nil {
		return Installation{}, err
	}
	if len(manifestDigest) != 32 || len(configurationDigest) != 32 {
		return Installation{}, ErrStorageUnavailable
	}
	value.Schema = Schema
	value.ManifestSHA256, value.ConfigurationSchemaSHA256 = hex.EncodeToString(manifestDigest), hex.EncodeToString(configurationDigest)
	if lkgVerificationID != nil {
		value.LKGVerificationID = *lkgVerificationID
	}
	if lkgVersion != nil {
		value.LKGVersion = *lkgVersion
	}
	if stableReason != nil {
		value.StableReasonCode = *stableReason
	}
	if !validStoredInstallation(value) || value.UpdatedAt.Before(createdAt) {
		return Installation{}, ErrStorageUnavailable
	}
	return value, nil
}

func validStoredInstallation(value Installation) bool {
	return value.Schema == Schema && value.Revision > 0 && value.IdentityGeneration > 0 &&
		(value.Status == StatusEnabled || value.Status == StatusDisabled || value.Status == StatusUninstalled) &&
		validCandidate(candidateFromInstallation(value)) && !value.UpdatedAt.IsZero() &&
		((value.LKGVerificationID == uuid.Nil) == (value.LKGVersion == ""))
}

func installationView(value Installation) InstallationView {
	newScopes := make([]string, 0)
	for _, scope := range value.ManifestScopes {
		if _, found := slices.BinarySearch(value.ApprovedScopes, scope); !found {
			newScopes = append(newScopes, scope)
		}
	}
	return InstallationView{Installation: value, NewScopes: newScopes}
}

type pluginInstallationCursor struct {
	UpdatedAt       string    `json:"updated_at"`
	AuthorizationID uuid.UUID `json:"authorization_id"`
	Status          string    `json:"status"`
	PluginID        string    `json:"plugin_id"`
}

func encodePluginInstallationCursor(updatedAt time.Time, authorizationID uuid.UUID,
	status, pluginID string) (string, error) {
	wire := pluginInstallationCursor{UpdatedAt: updatedAt.UTC().Format(time.RFC3339Nano),
		AuthorizationID: authorizationID, Status: status, PluginID: pluginID}
	encoded, err := json.Marshal(wire)
	if err != nil {
		return "", ErrStorageUnavailable
	}
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

func decodePluginInstallationCursor(value, status, pluginID string) (*time.Time, *uuid.UUID, error) {
	if value == "" {
		return nil, nil, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, nil, ErrInvalidInput
	}
	var wire pluginInstallationCursor
	if strictJSON(decoded, &wire) != nil || wire.AuthorizationID == uuid.Nil ||
		wire.Status != status || wire.PluginID != pluginID {
		return nil, nil, ErrInvalidInput
	}
	canonical, err := json.Marshal(wire)
	parsed, timeErr := time.Parse(time.RFC3339Nano, wire.UpdatedAt)
	if err != nil || timeErr != nil || !bytes.Equal(canonical, decoded) || parsed.IsZero() ||
		parsed.UTC().Format(time.RFC3339Nano) != wire.UpdatedAt {
		return nil, nil, ErrInvalidInput
	}
	parsed, id := parsed.UTC(), wire.AuthorizationID
	return &parsed, &id, nil
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullableUUID(value uuid.UUID) any {
	if value == uuid.Nil {
		return nil
	}
	return value
}

func postgresError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if err == nil {
		return ErrStorageUnavailable
	}
	// Keep only the safe classification of the cause (SQLSTATE, constraint name): never the database message or
	// detail, which can carry row values such as an idempotency key.
	failure := StorageFailure{}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		failure.SQLState, failure.Constraint = pgErr.Code, pgErr.ConstraintName
	}
	return failure
}

// StorageFailure is a plugin installation storage error reduced to what is safe to log.
type StorageFailure struct {
	SQLState   string
	Constraint string
}

func (failure StorageFailure) Error() string {
	if failure.SQLState == "" {
		return ErrStorageUnavailable.Error()
	}
	return ErrStorageUnavailable.Error() + ": sqlstate " + failure.SQLState
}

func (StorageFailure) Unwrap() error { return ErrStorageUnavailable }

// StorageFailureOf returns the storage classification carried by err (zero when none).
func StorageFailureOf(err error) StorageFailure {
	var failure StorageFailure
	errors.As(err, &failure)
	return failure
}

func configuredPluginInstallationPool(pool *pgxpool.Pool) (configured bool) {
	if pool == nil {
		return false
	}
	defer func() {
		if recover() != nil {
			configured = false
		}
	}()
	return pool.Config() != nil
}
