package pluginwebhookcontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool                *pgxpool.Pool
	iam                 *iamlock.Authorizer
	entitlement         *entitlementguard.Guard
	cipher              *secretCipher
	targets             TargetValidator
	commitBusinessWrite func(context.Context, pgx.Tx) error
}

func NewStore(pool *pgxpool.Pool, iam *iamlock.Authorizer, entitlement *entitlementguard.Guard, keys Keyring, targets TargetValidator) (*Store, error) {
	if pool == nil || iam == nil || entitlement == nil || !iam.Configured() || keys == nil || targets == nil {
		return nil, ErrInvalidConfig
	}
	cipherSuite, err := newSecretCipher(keys, nil)
	if err != nil {
		return nil, err
	}
	return &Store{pool: pool, iam: iam, entitlement: entitlement, cipher: cipherSuite, targets: targets, commitBusinessWrite: commitTransaction}, nil
}

func commitTransaction(ctx context.Context, tx pgx.Tx) error {
	return tx.Commit(ctx)
}

func (store *Store) authorize(ctx context.Context, tx pgx.Tx, actor Actor, permission string) error {
	if store == nil || store.iam == nil || tx == nil || actor.validate() != nil || actor.rawSession == "" {
		return ErrPermissionDenied
	}
	sealed, err := store.iam.AuthorizeSession(ctx, tx, actor.rawSession, actor.TargetScopeID, permission)
	if err != nil {
		if errors.Is(err, iamlock.ErrPermissionDenied) || errors.Is(err, iamlock.ErrInvalidCredential) || errors.Is(err, iamlock.ErrInvalidInput) {
			return ErrPermissionDenied
		}
		return ErrStoreUnavailable
	}
	if !sealed.Valid() || sealed.UserID() != actor.ActorUserID || sealed.AuthenticationScopeID() != actor.ActorScopeID || sealed.TargetScopeID() != actor.TargetScopeID {
		return ErrPermissionDenied
	}
	return nil
}

func databaseTime(ctx context.Context, tx pgx.Tx) (time.Time, error) {
	var value time.Time
	err := tx.QueryRow(ctx, `SELECT transaction_timestamp()`).Scan(&value)
	return value.UTC(), err
}

func requestDigest(actor Actor, operation, idempotencyKey string, body any) ([32]byte, error) {
	if actor.validate() != nil {
		return [32]byte{}, ErrPermissionDenied
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return [32]byte{}, err
	}
	input := []byte("cdnca.plugin-webhook.request/v1")
	for _, part := range []string{actor.TargetScopeID.String(), actor.ActorScopeID.String(), actor.ActorUserID.String(), operation, idempotencyKey} {
		input = append(input, 0)
		input = append(input, part...)
	}
	input = append(input, 0)
	return sha256.Sum256(append(input, encoded...)), nil
}

func validIdempotencyKey(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for index, current := range value {
		if current > unicode.MaxASCII || index == 0 && !asciiAlphaNumeric(byte(current)) || index > 0 && !asciiAlphaNumeric(byte(current)) && !strings.ContainsRune("._:-", current) {
			return false
		}
	}
	return true
}

func asciiAlphaNumeric(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

type storedRequest struct {
	ID             uuid.UUID
	Operation      string
	Digest         []byte
	SubscriptionID uuid.UUID
	DeliveryID     *uuid.UUID
	RotationID     *uuid.UUID
	ResponseStatus *int
	ReceiptKeyID   *string
	ReceiptNonce   []byte
	ReceiptCipher  []byte
	ReceiptExpires *time.Time
	ReceiptCleared *time.Time
	CompletedAt    *time.Time
}

func loadStoredRequest(ctx context.Context, tx pgx.Tx, actor Actor, key string) (storedRequest, error) {
	var result storedRequest
	err := tx.QueryRow(ctx, `SELECT id,operation,request_digest,subscription_id,delivery_id,rotation_id,response_status,receipt_wrapping_key_id,receipt_nonce,receipt_ciphertext,receipt_expires_at,receipt_cleared_at,completed_at FROM plugin_webhook_write_requests WHERE tenant_scope_id=$1 AND actor_scope_id=$2 AND actor_user_id=$3 AND idempotency_key=$4 FOR UPDATE`, actor.TargetScopeID, actor.ActorScopeID, actor.ActorUserID, key).Scan(&result.ID, &result.Operation, &result.Digest, &result.SubscriptionID, &result.DeliveryID, &result.RotationID, &result.ResponseStatus, &result.ReceiptKeyID, &result.ReceiptNonce, &result.ReceiptCipher, &result.ReceiptExpires, &result.ReceiptCleared, &result.CompletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return storedRequest{}, ErrNotFound
	}
	return result, err
}

func lockIdempotency(ctx context.Context, tx pgx.Tx, actor Actor, key string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended(
		'plugin-webhook-idempotency:'||$1::uuid::text||':'||$2::uuid::text||':'||$3::uuid::text||':'||$4,84))`,
		actor.TargetScopeID, actor.ActorScopeID, actor.ActorUserID, key)
	return err
}

func validateStoredRequest(stored storedRequest, operation string, digest [32]byte, subscription uuid.UUID, resource *uuid.UUID) error {
	if stored.Operation != operation || !bytes.Equal(stored.Digest, digest[:]) || subscription != uuid.Nil && stored.SubscriptionID != subscription {
		return ErrIdempotencyConflict
	}
	if resource != nil {
		found := stored.DeliveryID
		if strings.Contains(operation, "secret.") {
			found = stored.RotationID
		}
		if found == nil || *found != *resource {
			return ErrIdempotencyConflict
		}
	}
	if stored.CompletedAt == nil {
		return ErrResultUnknown
	}
	return nil
}

func mapStoreError(err error) error {
	if err == nil {
		return nil
	}
	var postgres *pgconn.PgError
	if errors.As(err, &postgres) {
		switch postgres.Code {
		case "P8402", "P3687": // P3687: the bound installation lost the event permission (368) or site filter (370)
			return ErrPermissionDenied
		case "P3701", "P3702": // migration 370: invalid site filter or a site outside the tenant
			return ErrInvalidInput
		case "P8406":
			if strings.Contains(postgres.Message, "pending") {
				return ErrRotationPending
			}
			return ErrStateConflict
		case "P8407":
			return ErrStateConflict
		case "P8404":
			if strings.Contains(postgres.Message, "not replayable") {
				return ErrDeliveryNotReplayable
			}
			return fmt.Errorf("%w: %s", ErrStateConflict, postgres.Message)
		case "P8408":
			switch postgres.Detail {
			case "plugin_webhook.rate_limited":
				return RateLimitError{RetryAfter: time.Second}
			case "plugin_webhook.quota_exceeded":
				return ErrQuotaExceeded
			case "plugin_webhook.entitlement_denied":
				return ErrEntitlementDenied
			default:
				return fmt.Errorf("%w: plugin webhook invariant violation", ErrStoreUnavailable)
			}
		case "23505":
			return ErrIdempotencyConflict
		case "40001", "40P01":
			return ErrResultUnknown
		}
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return fmt.Errorf("%w: %v", ErrStoreUnavailable, err)
}

func mapWriteCommitError(err error) error {
	if err == nil {
		return nil
	}
	var postgres *pgconn.PgError
	if errors.As(err, &postgres) {
		if postgres.Code == "40001" || postgres.Code == "40P01" {
			return fmt.Errorf("%w: transaction rolled back", ErrStoreUnavailable)
		}
		return mapStoreError(err)
	}
	if errors.Is(err, pgx.ErrTxCommitRollback) {
		return fmt.Errorf("%w: transaction rolled back", ErrStoreUnavailable)
	}
	return fmt.Errorf("%w: %v", ErrResultUnknown, err)
}

func parseU64(value string) (uint64, error) {
	result, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, ErrStoreUnavailable
	}
	return result, nil
}

func encodeCursor(timestamp time.Time, id uuid.UUID) string {
	return base64.RawURLEncoding.EncodeToString([]byte(timestamp.UTC().Format(time.RFC3339Nano) + "\x00" + id.String()))
}

func decodeCursor(value string) (time.Time, uuid.UUID, error) {
	if value == "" {
		return time.Time{}, uuid.Nil, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) > 256 || !utf8.Valid(decoded) {
		return time.Time{}, uuid.Nil, ErrInvalidInput
	}
	parts := strings.Split(string(decoded), "\x00")
	if len(parts) != 2 {
		return time.Time{}, uuid.Nil, ErrInvalidInput
	}
	timestamp, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return time.Time{}, uuid.Nil, ErrInvalidInput
	}
	id, err := uuid.Parse(parts[1])
	if err != nil || id == uuid.Nil {
		return time.Time{}, uuid.Nil, ErrInvalidInput
	}
	return timestamp.UTC(), id, nil
}

func normalizeSubscription(value *Subscription) {
	if value != nil {
		value.CreatedAt = value.CreatedAt.UTC()
		value.UpdatedAt = value.UpdatedAt.UTC()
	}
}
func normalizeDelivery(value *Delivery) {
	if value != nil {
		value.CreatedAt = value.CreatedAt.UTC()
		if value.NextAttemptAt != nil {
			current := value.NextAttemptAt.UTC()
			value.NextAttemptAt = &current
		}
		if value.CompletedAt != nil {
			current := value.CompletedAt.UTC()
			value.CompletedAt = &current
		}
	}
}
