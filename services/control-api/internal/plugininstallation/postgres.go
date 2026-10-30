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
		WHERE tenant_scope_id=$1 AND ($2='' OR status=$2) AND ($3='' OR plugin_id=$3) AND
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
		items = append(items, installationView(item))
	}
	if err := rows.Err(); err != nil {
		return Page{}, postgresError(ctx, err)
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
	value, err := loadPluginInstallation(ctx, tx, actor.TenantID, authorizationID, false)
	if err != nil {
		return InstallationView{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return InstallationView{}, postgresError(ctx, err)
	}
	return installationView(value), nil
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
	return fmt.Errorf("%w: plugin installation postgres", ErrStorageUnavailable)
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
