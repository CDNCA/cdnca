package accountregistration

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresStore struct {
	pool             *pgxpool.Pool
	auditor          *audit.Log
	notifications    *notification.Store
	successTemplates RegistrationSuccessTemplateReader
}

func NewPostgresStore(pool *pgxpool.Pool) (*PostgresStore, error) {
	return NewPostgresStoreWithNotifications(pool, nil, nil)
}

func NewPostgresStoreWithNotifications(
	pool *pgxpool.Pool,
	notifications *notification.Store,
	successTemplates RegistrationSuccessTemplateReader,
) (*PostgresStore, error) {
	if !registrationPoolConfigured(pool) {
		return nil, ErrInvalidStore
	}
	return &PostgresStore{
		pool: pool, auditor: audit.New(pool), notifications: notifications,
		successTemplates: successTemplates,
	}, nil
}

func (store *PostgresStore) Register(ctx context.Context, record RegistrationRecord) (StoreResult, error) {
	if store == nil || !registrationPoolConfigured(store.pool) || store.auditor == nil || !validRegistrationRecord(record) {
		return StoreResult{}, ErrInvalidStore
	}
	var result StoreResult
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		claimed, replayed, err := claimRegistrationReceipt(ctx, tx, record)
		if err != nil {
			return err
		}
		if replayed {
			result.Replayed = true
			return nil
		}
		if !claimed {
			return ErrIncompleteReceipt
		}

		savepoint, err := tx.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin account registration identity savepoint: %w", err)
		}
		createdErr := createRegistrationIdentity(ctx, savepoint, record)
		if createdErr != nil {
			_ = savepoint.Rollback(ctx)
			if isDuplicateRegistrationIdentity(createdErr) {
				return completeRegistrationReceipt(ctx, tx, record, "duplicate")
			}
			return createdErr
		}
		if err := savepoint.Commit(ctx); err != nil {
			return fmt.Errorf("release account registration identity savepoint: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO account_registration_terms_159(
				registration_id,scope_id,user_id,terms_version,accepted_at
			) VALUES($1,$2,$3,$4,$5)`,
			record.RegistrationID, record.ScopeID, record.UserID, record.TermsVersion, record.CreatedAt,
		); err != nil {
			return fmt.Errorf("persist account registration terms: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO account_registration_verification_intents_159(
				id,registration_id,scope_id,user_id,verification_channel,created_at
			) VALUES($1,$2,$3,$4,$5,$6)`,
			record.VerificationID, record.RegistrationID, record.ScopeID, record.UserID,
			record.VerificationChannel, record.CreatedAt,
		); err != nil {
			return fmt.Errorf("persist account registration verification intent: %w", err)
		}
		if err := store.enqueueRegistrationSuccess(ctx, tx, record); err != nil {
			return err
		}
		if err := store.auditor.Append(ctx, tx, audit.Event{
			ScopeID: record.ScopeID, Action: "identity.account_registration.accept",
			ResourceType: "user", ResourceID: record.UserID.String(), RequestID: record.RequestID,
			Result: "success", Payload: map[string]any{
				"terms_version": record.TermsVersion, "verification_channel": record.VerificationChannel,
			},
		}); err != nil {
			return fmt.Errorf("audit account registration: %w", err)
		}
		return completeRegistrationReceipt(ctx, tx, record, "created")
	})
	if err != nil {
		return StoreResult{}, fmt.Errorf("register account: %w", err)
	}
	return result, nil
}

func (store *PostgresStore) enqueueRegistrationSuccess(
	ctx context.Context,
	tx pgx.Tx,
	record RegistrationRecord,
) error {
	if store == nil || store.notifications == nil || store.successTemplates == nil {
		return nil
	}
	ref, variables, found, err := store.successTemplates.GetRegistrationSuccessTemplateTx(ctx, tx, record.ScopeID)
	if err != nil || !found {
		// Existing installations can predate the system-settings template rows;
		// registration remains available until a settings revision publishes one.
		return nil
	}
	request, err := registrationSuccessEnqueueRequest(record, ref, variables)
	if err != nil {
		return err
	}
	_, err = store.notifications.EnqueueTx(ctx, tx, request)
	if err != nil {
		return fmt.Errorf("enqueue account registration success: %w", err)
	}
	return nil
}

func registrationSuccessEnqueueRequest(
	record RegistrationRecord,
	ref notification.TemplateRef,
	variables []string,
) (notification.EnqueueRequest, error) {
	contextValues := make(notification.TemplateContext, len(variables))
	for _, variable := range variables {
		if variable != "username" {
			return notification.EnqueueRequest{}, fmt.Errorf("enqueue account registration success: unsupported template variable %q", variable)
		}
		contextValues[variable] = notification.PublicValue(record.Username)
	}
	return notification.EnqueueRequest{
		ScopeID:       record.ScopeID,
		RecipientID:   record.UserID,
		SourceEventID: "account-registration-success:" + record.RegistrationID.String(),
		EventType:     notification.EventTypeAccountRegistrationSuccess,
		Policy:        notification.DeliverySystemRequired,
		Templates: map[notification.Channel]notification.TemplateRef{
			notification.ChannelEmail: ref,
		},
		Contexts: map[notification.Channel]notification.TemplateContext{
			notification.ChannelEmail: contextValues,
		},
		AuditRequestID: record.RequestID,
	}, nil
}

func claimRegistrationReceipt(
	ctx context.Context,
	tx pgx.Tx,
	record RegistrationRecord,
) (claimed bool, replayed bool, err error) {
	tag, err := tx.Exec(ctx, `
		INSERT INTO account_registration_requests_159(
			id,idempotency_key,request_id,request_digest,subject_digest,state,created_at
		) VALUES($1,$2,$3,$4,$5,'pending',$6)
		ON CONFLICT(idempotency_key) DO NOTHING`,
		record.RegistrationID, record.IdempotencyKey, record.RequestID,
		record.RequestDigest[:], record.SubjectDigest[:], record.CreatedAt,
	)
	if err != nil {
		return false, false, fmt.Errorf("claim account registration receipt: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return true, false, nil
	}
	var digest []byte
	var state string
	if err := tx.QueryRow(ctx, `
		SELECT request_digest,state
		FROM account_registration_requests_159
		WHERE idempotency_key=$1
		FOR UPDATE`, record.IdempotencyKey).Scan(&digest, &state); err != nil {
		return false, false, fmt.Errorf("read account registration replay: %w", err)
	}
	if len(digest) != len(record.RequestDigest) || subtle.ConstantTimeCompare(digest, record.RequestDigest[:]) != 1 {
		return false, false, ErrIdempotencyConflict
	}
	if state != "completed" {
		return false, false, ErrIncompleteReceipt
	}
	return false, true, nil
}

func createRegistrationIdentity(ctx context.Context, tx pgx.Tx, record RegistrationRecord) error {
	if _, err := tx.Exec(ctx, `
		INSERT INTO tenants(id,display_name,created_at,updated_at)
		VALUES($1,$2,$3,$3)`, record.TenantID, record.DisplayName, record.CreatedAt); err != nil {
		return fmt.Errorf("insert registration tenant: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO access_scopes(id,kind,tenant_id,created_at)
		VALUES($1,'tenant',$2,$3)`, record.ScopeID, record.TenantID, record.CreatedAt); err != nil {
		return fmt.Errorf("insert registration scope: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO users(id,username,display_name,email,phone,password_hash,created_at,updated_at)
		VALUES($1,$2,$3,NULLIF($4,''),NULLIF($5,''),$6,$7,$7)`,
		record.UserID, record.Username, record.DisplayName, record.Email, record.Phone,
		record.PasswordHash, record.CreatedAt,
	); err != nil {
		return fmt.Errorf("insert registration user: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO memberships(scope_id,user_id,status,created_at)
		VALUES($1,$2,'active',$3)`, record.ScopeID, record.UserID, record.CreatedAt); err != nil {
		return fmt.Errorf("insert registration membership: %w", err)
	}
	if err := identity.SeedTenantSystemRoles(ctx, tx, record.ScopeID, record.OwnerRoleID, record.ViewerRoleID, record.CreatedAt); err != nil {
		return fmt.Errorf("insert registration roles: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO role_assignments(scope_id,user_id,role_id,assigned_at)
		VALUES($1,$2,$3,$4)`, record.ScopeID, record.UserID, record.OwnerRoleID, record.CreatedAt); err != nil {
		return fmt.Errorf("insert registration owner assignment: %w", err)
	}
	return nil
}

func completeRegistrationReceipt(ctx context.Context, tx pgx.Tx, record RegistrationRecord, outcome string) error {
	var tenantID, scopeID, userID *uuid.UUID
	if outcome == "created" {
		tenantID, scopeID, userID = &record.TenantID, &record.ScopeID, &record.UserID
	}
	tag, err := tx.Exec(ctx, `
		UPDATE account_registration_requests_159
		SET state='completed',outcome=$2,tenant_id=$3,scope_id=$4,user_id=$5,
		    response_status=202,completed_at=$6
		WHERE id=$1 AND state='pending'`,
		record.RegistrationID, outcome, tenantID, scopeID, userID, record.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("complete account registration receipt: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrIncompleteReceipt
	}
	return nil
}

func isDuplicateRegistrationIdentity(err error) bool {
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != "23505" {
		return false
	}
	switch postgresError.ConstraintName {
	case "users_username_lower_idx", "users_email_registration_unique_159", "users_phone_registration_unique_159":
		return true
	default:
		return false
	}
}

func validRegistrationRecord(record RegistrationRecord) bool {
	return record.RegistrationID != uuid.Nil && record.TenantID != uuid.Nil && record.ScopeID != uuid.Nil &&
		record.UserID != uuid.Nil && record.OwnerRoleID != uuid.Nil && record.ViewerRoleID != uuid.Nil &&
		record.VerificationID != uuid.Nil && record.Username != "" && record.PasswordHash != "" &&
		record.DisplayName != "" && record.TermsVersion != "" && record.IdempotencyKey != "" &&
		record.RequestID != "" && !record.CreatedAt.IsZero()
}

func registrationPoolConfigured(pool *pgxpool.Pool) (configured bool) {
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
