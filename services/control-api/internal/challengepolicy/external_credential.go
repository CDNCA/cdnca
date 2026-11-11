package challengepolicy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/challengepublication"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// CredentialCipher seals an external credential secret under the challenge
// fact KEK (challengepublication.AESGCMFactWriterCipher).
type CredentialCipher interface {
	KeyID() string
	EncryptBound(context.Context, []byte, []byte) ([]byte, error)
}

// UseCredentialCipher enables PUT /external-credential.
func (store *Store) UseCredentialCipher(cipher CredentialCipher) {
	if store != nil && !isNilDependency(cipher) {
		store.credentials = cipher
	}
}

// pruneExternalCredential drops the credential of a policy that is deleted,
// left external mode or changed provider, in the revision's transaction: a
// credential is only ever the one of the policy's current provider.
func pruneExternalCredential(ctx context.Context, tx pgx.Tx, item storedPolicy) error {
	if item.Deleted || item.External == nil {
		_, err := tx.Exec(ctx, `DELETE FROM challenge_external_credentials WHERE policy_id=$1 AND tenant_scope_id=$2`,
			item.ID, item.TenantScopeID)
		return err
	}
	_, err := tx.Exec(ctx, `DELETE FROM challenge_external_credentials
		WHERE policy_id=$1 AND tenant_scope_id=$2 AND provider<>$3`, item.ID, item.TenantScopeID, item.External.Provider)
	return err
}

// PutExternalCredential stores the provider credential and moves the policy
// to a new revision in one transaction, so publishing that revision ships the
// new secret (If-Match is the policy revision).
func (store *Store) PutExternalCredential(ctx context.Context, actor Actor, request ExternalCredentialRequest,
	digest [32]byte) (WriteResult, error) {
	if store.credentials == nil {
		return WriteResult{}, ErrCredentialUnavailable
	}
	return store.change(ctx, actor, request.TargetScopeID, request.ID, request.ExpectedRevision,
		request.WriteMetadata, digest, "update", true, func(tx pgx.Tx, item *storedPolicy) error {
			if item.Mode != ModeExternal || item.External == nil || item.External.Provider != request.Provider {
				return ErrProviderMismatch
			}
			var revision int64
			err := tx.QueryRow(ctx, `SELECT revision FROM challenge_external_credentials
				WHERE policy_id=$1 AND tenant_scope_id=$2 FOR UPDATE`, item.ID, item.TenantScopeID).Scan(&revision)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			revision++
			aad, err := challengepublication.ExternalCredentialAAD(item.ID, request.Provider, request.AppID,
				request.Environment, revision)
			if err != nil {
				return ErrValidation
			}
			ciphertext, err := store.credentials.EncryptBound(ctx, request.Secret, aad)
			if err != nil {
				return ErrCredentialUnavailable
			}
			now := store.now().UTC().Truncate(time.Microsecond)
			if _, err := tx.Exec(ctx, `
				INSERT INTO challenge_external_credentials (
					policy_id, tenant_scope_id, provider, app_id, environment, secret_ciphertext,
					wrapping_key_id, revision, updated_by_user_id, created_at, updated_at
				) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$10)
				ON CONFLICT (policy_id) DO UPDATE SET provider=EXCLUDED.provider, app_id=EXCLUDED.app_id,
					environment=EXCLUDED.environment, secret_ciphertext=EXCLUDED.secret_ciphertext,
					wrapping_key_id=EXCLUDED.wrapping_key_id, revision=EXCLUDED.revision,
					updated_by_user_id=EXCLUDED.updated_by_user_id, updated_at=EXCLUDED.updated_at`,
				item.ID, item.TenantScopeID, request.Provider, request.AppID, request.Environment, ciphertext,
				store.credentials.KeyID(), revision, actor.UserID, now); err != nil {
				return err
			}
			// Never the secret: provider, app id and environment only.
			return store.auditor.Append(ctx, tx, audit.Event{
				ScopeID: item.TenantScopeID, ActorUserID: &actor.UserID,
				Action: "challenge_policy.external_credential.update", ResourceType: "challenge_policy",
				ResourceID: item.ID.String(), RequestID: request.RequestID, Result: "success",
				Payload: map[string]any{"trace_id": request.TraceID, "provider": request.Provider,
					"app_id": request.AppID, "environment": request.Environment, "credential_revision": revision},
			})
		})
}

func (store *Store) GetExternalCredential(ctx context.Context, actor Actor, targetScopeID, id uuid.UUID) (
	ExternalCredentialStatus, error) {
	var result ExternalCredentialStatus
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if _, err := store.authorize(ctx, tx, actor, targetScopeID, PermissionRead); err != nil {
			return err
		}
		item, err := selectPolicy(ctx, tx, targetScopeID, id, false)
		if err != nil {
			return err
		}
		if item.External != nil {
			result.Provider = item.External.Provider
		}
		var updatedAt time.Time
		err = tx.QueryRow(ctx, `SELECT provider, app_id, environment, revision, updated_at
			FROM challenge_external_credentials WHERE policy_id=$1 AND tenant_scope_id=$2`, id, targetScopeID).
			Scan(&result.Provider, &result.AppID, &result.Environment, &result.Revision, &updatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		result.SecretConfigured = true
		result.UpdatedAt = &updatedAt
		return nil
	})
	if err != nil {
		return ExternalCredentialStatus{}, normalizeStoreError(err)
	}
	return result, nil
}

func (service *Service) PutExternalCredential(ctx context.Context, actor Actor, request ExternalCredentialRequest) (
	WriteResult, error) {
	if err := validateTarget(actor, request.TargetScopeID); err != nil {
		return WriteResult{}, err
	}
	if request.ID == uuid.Nil || request.ExpectedRevision < 1 || !validWriteMetadata(request.WriteMetadata) {
		return WriteResult{}, ErrInvalidInput
	}
	if request.Environment == "" {
		request.Environment = "production"
	}
	if !challengepublication.ValidExternalProvider(request.Provider) ||
		!challengepublication.ValidExternalAppID(request.AppID) || !validExternalSecret(request.Secret) ||
		(request.Environment != "sandbox" && request.Environment != "production") {
		return WriteResult{}, ErrValidation
	}
	secretDigest := sha256.Sum256(request.Secret)
	digest, err := digestRequest(struct {
		TargetScopeID uuid.UUID `json:"target_scope_id"`
		ID            uuid.UUID `json:"id"`
		Revision      int64     `json:"revision"`
		Provider      string    `json:"provider"`
		AppID         string    `json:"app_id"`
		Environment   string    `json:"environment"`
		Secret        string    `json:"secret_sha256"`
	}{request.TargetScopeID, request.ID, request.ExpectedRevision, request.Provider, request.AppID,
		request.Environment, hex.EncodeToString(secretDigest[:])})
	if err != nil {
		return WriteResult{}, ErrUnavailable
	}
	return service.store.PutExternalCredential(ctx, actor, request, digest)
}

func (service *Service) GetExternalCredential(ctx context.Context, actor Actor, targetScopeID, id uuid.UUID) (
	ExternalCredentialStatus, error) {
	if err := validateTarget(actor, targetScopeID); err != nil {
		return ExternalCredentialStatus{}, err
	}
	if id == uuid.Nil {
		return ExternalCredentialStatus{}, ErrInvalidInput
	}
	return service.store.GetExternalCredential(ctx, actor, targetScopeID, id)
}

// validExternalSecret: 16..256 printable ASCII bytes, no surrounding space
// (the bounds the artifact and the Agent verifier enforce).
func validExternalSecret(secret []byte) bool {
	if len(secret) < 16 || len(secret) > 256 || secret[0] == ' ' || secret[len(secret)-1] == ' ' {
		return false
	}
	for _, character := range secret {
		if character < 0x20 || character > 0x7e {
			return false
		}
	}
	return true
}
