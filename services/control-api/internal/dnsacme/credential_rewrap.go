package dnsacme

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const maxCredentialRewrapBatch = 100

type CredentialRewrapItem struct {
	ProviderID       uuid.UUID
	ExpectedRevision int64
	IdempotencyKey   string
}

type CredentialRewrapRequest struct {
	RequestID string
	Items     []CredentialRewrapItem
}

type CredentialRewrapResult struct {
	ProviderID        uuid.UUID `json:"provider_id"`
	Revision          int64     `json:"revision"`
	CredentialVersion int64     `json:"credential_version"`
}

type CredentialRewrapProgress struct {
	Requested int                      `json:"requested"`
	Completed int                      `json:"completed"`
	NextIndex int                      `json:"next_index"`
	Items     []CredentialRewrapResult `json:"items"`
}

func (s *Service) RewrapProviderCredentials(
	ctx context.Context,
	actor Actor,
	request CredentialRewrapRequest,
) (CredentialRewrapProgress, error) {
	progress := CredentialRewrapProgress{Requested: len(request.Items)}
	if !validCredentialRewrapRequest(actor, request) {
		return progress, ErrInvalidInput
	}
	cipher, ok := s.cipher.(BoundCredentialCipher)
	if !ok || s.store == nil || s.store.pool == nil || s.store.auditor == nil {
		return progress, ErrCredentialUnavailable
	}
	progress.Items = make([]CredentialRewrapResult, 0, len(request.Items))
	for index, item := range request.Items {
		result, err := s.store.rewrapProviderCredential(ctx, actor, request.RequestID, item, cipher)
		if err != nil {
			progress.NextIndex = index
			return progress, err
		}
		progress.Items = append(progress.Items, result)
		progress.Completed++
		progress.NextIndex = index + 1
	}
	return progress, nil
}

func validCredentialRewrapRequest(actor Actor, request CredentialRewrapRequest) bool {
	if !validActor(actor) || len(request.Items) == 0 || len(request.Items) > maxCredentialRewrapBatch {
		return false
	}
	providers := make(map[uuid.UUID]struct{}, len(request.Items))
	keys := make(map[string]struct{}, len(request.Items))
	for _, item := range request.Items {
		if item.ProviderID == uuid.Nil || item.ExpectedRevision < 1 ||
			!validMetadata(item.IdempotencyKey, request.RequestID) {
			return false
		}
		if _, duplicate := providers[item.ProviderID]; duplicate {
			return false
		}
		if _, duplicate := keys[item.IdempotencyKey]; duplicate {
			return false
		}
		providers[item.ProviderID] = struct{}{}
		keys[item.IdempotencyKey] = struct{}{}
	}
	return true
}

func (s *Store) rewrapProviderCredential(
	ctx context.Context,
	actor Actor,
	requestID string,
	item CredentialRewrapItem,
	cipher BoundCredentialCipher,
) (CredentialRewrapResult, error) {
	var result CredentialRewrapResult
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var target providerCredentialTarget
		var keyID string
		var ciphertext []byte
		var credentialVersion int64
		var credentialRevoked bool
		err := tx.QueryRow(ctx, `SELECT provider.id,provider.scope_id,provider.name,provider.provider_type,
			provider.credentials_configured,provider.status,provider.revision,provider.created_at,provider.updated_at,
			scope.tenant_id,provider.credential_key_id,provider.credential_ciphertext,
			provider.credential_version,provider.credential_revoked
			FROM dns_providers AS provider
			JOIN access_scopes AS scope ON scope.id=provider.scope_id AND scope.kind='tenant'
			JOIN tenants AS tenant ON tenant.id=scope.tenant_id AND tenant.status='active'
			WHERE provider.id=$1 AND ($2='platform' OR provider.scope_id=$3)
			FOR UPDATE OF provider`, item.ProviderID, actor.ScopeKind, actor.ScopeID).Scan(
			&target.ID, &target.ScopeID, &target.Name, &target.ProviderType,
			&target.CredentialsConfigured, &target.Status, &target.Revision,
			&target.CreatedAt, &target.UpdatedAt, &target.TenantID, &keyID, &ciphertext,
			&credentialVersion, &credentialRevoked,
		)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		defer clear(ciphertext)
		digest, err := digestRequest(struct {
			ProviderID       uuid.UUID `json:"provider_id"`
			ExpectedRevision int64     `json:"expected_revision"`
		}{item.ProviderID, item.ExpectedRevision})
		if err != nil {
			return err
		}
		replay, err := reserveWrite(ctx, tx, actor, target.ScopeID, "dns.provider.credential_rewrap", item.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if replay != nil {
			return json.Unmarshal(replay, &result)
		}
		if target.Revision != item.ExpectedRevision {
			return ErrRevisionConflict
		}
		if credentialRevoked || credentialVersion < 1 || keyID == "" || len(ciphertext) == 0 {
			return ErrCredentialUnavailable
		}
		newKeyID, rebound, err := cipher.RewrapCredential(target.binding(), keyID, ciphertext)
		if err != nil {
			return ErrCredentialUnavailable
		}
		defer clear(rebound)
		err = tx.QueryRow(ctx, `UPDATE dns_providers
			SET credential_key_id=$4,credential_ciphertext=$5,
			    credential_version=credential_version+1,revision=revision+1,
			    updated_by_user_id=$6,updated_at=now()
			WHERE id=$1 AND scope_id=$2 AND revision=$3
			  AND credential_key_id=$7 AND credential_version=$8 AND credential_revoked=false
			RETURNING revision,credential_version`, target.ID, target.ScopeID, target.Revision,
			newKeyID, rebound, actor.UserID, keyID, credentialVersion).Scan(&result.Revision, &result.CredentialVersion)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrRevisionConflict
		}
		if err != nil {
			return err
		}
		result.ProviderID = target.ID
		if err := s.appendAudit(ctx, tx, actor, target.ScopeID, requestID,
			"dns.provider.credential_rewrap", "dns_provider", target.ID, map[string]any{
				"credential_version": result.CredentialVersion,
				"revision":           result.Revision,
			}); err != nil {
			return err
		}
		return completeWrite(ctx, tx, actor, "dns.provider.credential_rewrap",
			item.IdempotencyKey, target.ID, result)
	})
	return result, err
}
