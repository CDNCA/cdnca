package originauthcontrol

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (service *Service) CreateCredential(
	ctx context.Context,
	actor Actor,
	request CreateCredentialRequest,
) (CredentialWriteResult, error) {
	if err := validateTarget(actor, request.TargetScopeID); err != nil {
		return CredentialWriteResult{}, err
	}
	if !validWriteMetadata(request.WriteMetadata) {
		return CredentialWriteResult{}, ErrInvalidInput
	}
	now := storeTime(service.now())
	if err := validateCredentialInput(request.Provider, request.Name, request.Secret, now); err != nil {
		return CredentialWriteResult{}, err
	}
	request.Secret.NotBefore = storeTime(request.Secret.NotBefore)
	request.Secret.ExpiresAt = storeTime(request.Secret.ExpiresAt)
	digest, err := digestRequest(struct {
		TargetScopeID uuid.UUID        `json:"target_scope_id"`
		Provider      string           `json:"provider"`
		Name          string           `json:"name"`
		Secret        CredentialSecret `json:"secret"`
	}{request.TargetScopeID, request.Provider, request.Name, request.Secret})
	if err != nil {
		return CredentialWriteResult{}, ErrUnavailable
	}
	credentialID, revisionRef := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	var result CredentialWriteResult
	err = pgx.BeginFunc(ctx, service.pool, func(tx pgx.Tx) error {
		tenantID, err := service.authorizeTarget(ctx, tx, actor, request.TargetScopeID, PermissionManage)
		if err != nil {
			return err
		}
		write, err := service.claimWrite(ctx, tx, actor, request.TargetScopeID,
			"origin_auth.credential.create", request.WriteMetadata, digest)
		if err != nil {
			return err
		}
		if write.found {
			if err := json.Unmarshal(write.responseBody, &result.Credential); err != nil {
				return ErrUnavailable
			}
			result.Replayed = true
			return nil
		}
		if err := service.checkEntitlement(ctx, tx, actor, request.TargetScopeID, credentialID,
			request.WriteMetadata, "origin_auth.credential.create"); err != nil {
			return err
		}
		plaintext, err := encodeSecret(request.Provider, request.Secret)
		if err != nil {
			return ErrEncryptionUnavailable
		}
		sealed, err := service.keyring.seal(plaintext, credentialAAD(credentialID, 1, request.Provider))
		clearBytes(plaintext)
		if err != nil {
			return err
		}
		defer clearBytes(sealed.ciphertext)
		cipherDigest := digestCiphertext(sealed.ciphertext)
		if err := service.appendAudit(ctx, tx, actor, request.TargetScopeID, credentialID,
			request.WriteMetadata, "origin_auth.credential.create", "origin_auth_credential", map[string]any{
				"provider": request.Provider, "revision": 1, "status": StatusPending,
			}); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO origin_auth_credentials(
			id,tenant_scope_id,tenant_id,provider,name,created_by_scope_id,created_by_user_id,
			request_id,trace_id,created_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, credentialID, request.TargetScopeID, tenantID,
			request.Provider, request.Name, actor.ScopeID, actor.UserID, request.RequestID,
			request.TraceID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO origin_auth_credential_revisions(
			credential_id,revision,revision_ref,operation,status,envelope_key_id,secret_ciphertext,
			secret_ciphertext_sha256,not_before,expires_at,created_by_scope_id,created_by_user_id,
			request_id,trace_id,created_at)
			VALUES($1,1,$2,'create','pending',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
			credentialID, revisionRef, sealed.keyID, sealed.ciphertext, cipherDigest[:],
			request.Secret.NotBefore, request.Secret.ExpiresAt, actor.ScopeID, actor.UserID,
			request.RequestID, request.TraceID, now); err != nil {
			return err
		}
		result.Credential = Credential{
			ID: credentialID, TenantScope: request.TargetScopeID, Provider: request.Provider, Name: request.Name,
			Status: StatusPending, Revision: 1, RevisionRef: revisionRef,
			NotBefore: request.Secret.NotBefore, ExpiresAt: request.Secret.ExpiresAt,
			CreatedAt: now, UpdatedAt: now,
		}
		return service.completeWrite(ctx, tx, actor, "origin_auth.credential.create",
			request.IdempotencyKey, credentialID, 201, result.Credential)
	})
	clearSecret(&request.Secret)
	if err != nil {
		return CredentialWriteResult{}, normalizeServiceError(err)
	}
	return result, nil
}

func (service *Service) ReplaceCredential(
	ctx context.Context,
	actor Actor,
	request ReplaceCredentialRequest,
) (CredentialWriteResult, error) {
	if err := validateTarget(actor, request.TargetScopeID); err != nil {
		return CredentialWriteResult{}, err
	}
	if request.CredentialID == uuid.Nil || request.ExpectedRevision < 1 ||
		request.ExpectedRevision > maxSafeRevision || !validWriteMetadata(request.WriteMetadata) {
		return CredentialWriteResult{}, ErrInvalidInput
	}
	now := storeTime(service.now())
	digest, err := digestRequest(struct {
		TargetScopeID    uuid.UUID        `json:"target_scope_id"`
		CredentialID     uuid.UUID        `json:"credential_id"`
		ExpectedRevision int64            `json:"expected_revision"`
		Secret           CredentialSecret `json:"secret"`
	}{request.TargetScopeID, request.CredentialID, request.ExpectedRevision, request.Secret})
	if err != nil {
		return CredentialWriteResult{}, ErrUnavailable
	}
	var result CredentialWriteResult
	err = pgx.BeginFunc(ctx, service.pool, func(tx pgx.Tx) error {
		if _, err := service.authorizeTarget(ctx, tx, actor, request.TargetScopeID, PermissionManage); err != nil {
			return err
		}
		write, err := service.claimWrite(ctx, tx, actor, request.TargetScopeID,
			"origin_auth.credential.replace", request.WriteMetadata, digest)
		if err != nil {
			return err
		}
		if write.found {
			if err := json.Unmarshal(write.responseBody, &result.Credential); err != nil {
				return ErrUnavailable
			}
			result.Replayed = true
			return nil
		}
		stored, err := loadCredential(ctx, tx, request.TargetScopeID, request.CredentialID, true)
		if err != nil {
			return err
		}
		if stored.Revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		if stored.Status == StatusDeleted {
			return ErrConflict
		}
		if err := validateCredentialInput(stored.Provider, stored.Name, request.Secret, now); err != nil {
			return err
		}
		request.Secret.NotBefore, request.Secret.ExpiresAt = storeTime(request.Secret.NotBefore), storeTime(request.Secret.ExpiresAt)
		if err := service.checkEntitlement(ctx, tx, actor, request.TargetScopeID, request.CredentialID,
			request.WriteMetadata, "origin_auth.credential.replace"); err != nil {
			return err
		}
		nextRevision := stored.Revision + 1
		revisionRef := uuid.Must(uuid.NewV7())
		plaintext, err := encodeSecret(stored.Provider, request.Secret)
		if err != nil {
			return ErrEncryptionUnavailable
		}
		sealed, err := service.keyring.seal(plaintext, credentialAAD(stored.ID, nextRevision, stored.Provider))
		clearBytes(plaintext)
		if err != nil {
			return err
		}
		defer clearBytes(sealed.ciphertext)
		cipherDigest := digestCiphertext(sealed.ciphertext)
		if err := service.appendAudit(ctx, tx, actor, request.TargetScopeID, stored.ID,
			request.WriteMetadata, "origin_auth.credential.replace", "origin_auth_credential", map[string]any{
				"provider": stored.Provider, "revision": nextRevision, "status": StatusPending,
			}); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO origin_auth_credential_revisions(
			credential_id,revision,revision_ref,operation,status,envelope_key_id,secret_ciphertext,
			secret_ciphertext_sha256,not_before,expires_at,created_by_scope_id,created_by_user_id,
			request_id,trace_id,created_at)
			VALUES($1,$2,$3,'replace','pending',$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
			stored.ID, nextRevision, revisionRef, sealed.keyID, sealed.ciphertext, cipherDigest[:],
			request.Secret.NotBefore, request.Secret.ExpiresAt, actor.ScopeID, actor.UserID,
			request.RequestID, request.TraceID, now); err != nil {
			return err
		}
		result.Credential = stored.Credential
		result.Credential.Status, result.Credential.Revision = StatusPending, nextRevision
		result.Credential.RevisionRef, result.Credential.VerifiedAt = revisionRef, nil
		result.Credential.NotBefore, result.Credential.ExpiresAt = request.Secret.NotBefore, request.Secret.ExpiresAt
		result.Credential.UpdatedAt = now
		return service.completeWrite(ctx, tx, actor, "origin_auth.credential.replace",
			request.IdempotencyKey, stored.ID, 200, result.Credential)
	})
	clearSecret(&request.Secret)
	if err != nil {
		return CredentialWriteResult{}, normalizeServiceError(err)
	}
	return result, nil
}

func (service *Service) VerifyCredential(
	ctx context.Context,
	actor Actor,
	request CredentialMutationRequest,
) (CredentialWriteResult, error) {
	if err := validateTarget(actor, request.TargetScopeID); err != nil {
		return CredentialWriteResult{}, err
	}
	if request.CredentialID == uuid.Nil || request.ExpectedRevision < 1 || !validWriteMetadata(request.WriteMetadata) {
		return CredentialWriteResult{}, ErrInvalidInput
	}
	digest, err := credentialTransitionDigest(request, "verify")
	if err != nil {
		return CredentialWriteResult{}, ErrUnavailable
	}
	if replay, found, err := service.findCredentialReplay(ctx, actor, request, "verify", digest); err != nil {
		return CredentialWriteResult{}, err
	} else if found {
		return replay, nil
	}
	if service.verifier == nil {
		return CredentialWriteResult{}, ErrVerifierUnavailable
	}
	stored, err := service.readCredentialForMutation(ctx, actor, request)
	if err != nil {
		return CredentialWriteResult{}, err
	}
	if stored.Status != StatusPending {
		return CredentialWriteResult{}, ErrConflict
	}
	secret, err := service.decryptCredential(stored)
	if err != nil {
		return CredentialWriteResult{}, err
	}
	verificationErr := service.verifier.Verify(ctx, VerificationRequest{Provider: stored.Provider, Credential: secret})
	clearSecret(&secret)
	if verificationErr != nil {
		if errors.Is(verificationErr, ErrVerificationRejected) {
			return CredentialWriteResult{}, ErrVerificationRejected
		}
		if errors.Is(verificationErr, context.Canceled) || errors.Is(verificationErr, context.DeadlineExceeded) {
			return CredentialWriteResult{}, verificationErr
		}
		return CredentialWriteResult{}, ErrVerifierUnavailable
	}
	return service.transitionCredential(ctx, actor, request, "verify", StatusVerified)
}

func (service *Service) DisableCredential(
	ctx context.Context,
	actor Actor,
	request CredentialMutationRequest,
) (CredentialWriteResult, error) {
	return service.transitionCredential(ctx, actor, request, "disable", StatusDisabled)
}

func (service *Service) DeleteCredential(
	ctx context.Context,
	actor Actor,
	request CredentialMutationRequest,
) (CredentialWriteResult, error) {
	return service.transitionCredential(ctx, actor, request, "delete", StatusDeleted)
}

func (service *Service) readCredentialForMutation(
	ctx context.Context,
	actor Actor,
	request CredentialMutationRequest,
) (storedCredential, error) {
	if err := validateTarget(actor, request.TargetScopeID); err != nil {
		return storedCredential{}, err
	}
	if request.CredentialID == uuid.Nil || request.ExpectedRevision < 1 || !validWriteMetadata(request.WriteMetadata) {
		return storedCredential{}, ErrInvalidInput
	}
	var stored storedCredential
	err := service.authorizedRead(ctx, actor, request.TargetScopeID, PermissionManage, func(tx pgx.Tx) error {
		var err error
		stored, err = loadCredential(ctx, tx, request.TargetScopeID, request.CredentialID, false)
		if err != nil {
			return err
		}
		if stored.Revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		return nil
	})
	if err != nil {
		return storedCredential{}, normalizeServiceError(err)
	}
	return stored, nil
}

func (service *Service) transitionCredential(
	ctx context.Context,
	actor Actor,
	request CredentialMutationRequest,
	operation, status string,
) (CredentialWriteResult, error) {
	if err := validateTarget(actor, request.TargetScopeID); err != nil {
		return CredentialWriteResult{}, err
	}
	if request.CredentialID == uuid.Nil || request.ExpectedRevision < 1 || !validWriteMetadata(request.WriteMetadata) {
		return CredentialWriteResult{}, ErrInvalidInput
	}
	digest, err := credentialTransitionDigest(request, operation)
	if err != nil {
		return CredentialWriteResult{}, ErrUnavailable
	}
	apiOperation := "origin_auth.credential." + operation
	var result CredentialWriteResult
	err = pgx.BeginFunc(ctx, service.pool, func(tx pgx.Tx) error {
		if _, err := service.authorizeTarget(ctx, tx, actor, request.TargetScopeID, PermissionManage); err != nil {
			return err
		}
		write, err := service.claimWrite(ctx, tx, actor, request.TargetScopeID, apiOperation, request.WriteMetadata, digest)
		if err != nil {
			return err
		}
		if write.found {
			if err := json.Unmarshal(write.responseBody, &result.Credential); err != nil {
				return ErrUnavailable
			}
			result.Replayed = true
			return nil
		}
		stored, err := loadCredential(ctx, tx, request.TargetScopeID, request.CredentialID, true)
		if err != nil {
			return err
		}
		if stored.Revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		if stored.Status == StatusDeleted || status == StatusVerified && stored.Status != StatusPending ||
			status == StatusDisabled && stored.Status != StatusPending && stored.Status != StatusVerified {
			return ErrConflict
		}
		if status == StatusDisabled || status == StatusDeleted {
			active, err := credentialUsedByActiveRule(ctx, tx, stored.ID, stored.Revision)
			if err != nil {
				return err
			}
			if active {
				return ErrConflict
			}
		}
		if operation == "verify" {
			if err := service.checkEntitlement(ctx, tx, actor, request.TargetScopeID, stored.ID,
				request.WriteMetadata, apiOperation); err != nil {
				return err
			}
		}
		now := storeTime(service.now())
		nextRevision, revisionRef := stored.Revision+1, uuid.Must(uuid.NewV7())
		if err := service.appendAudit(ctx, tx, actor, request.TargetScopeID, stored.ID,
			request.WriteMetadata, apiOperation, "origin_auth_credential", map[string]any{
				"provider": stored.Provider, "revision": nextRevision, "status": status,
			}); err != nil {
			return err
		}
		var verifiedAt *time.Time
		var verificationCode any
		if status == StatusVerified {
			verifiedAt, verificationCode = &now, "verified"
		}
		if _, err := tx.Exec(ctx, `INSERT INTO origin_auth_credential_revisions(
			credential_id,revision,revision_ref,operation,status,envelope_key_id,secret_ciphertext,
			secret_ciphertext_sha256,not_before,expires_at,verified_at,verification_code,
			created_by_scope_id,created_by_user_id,request_id,trace_id,created_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
			stored.ID, nextRevision, revisionRef, operation, status, stored.keyID, stored.ciphertext,
			stored.cipherDigest, stored.NotBefore, stored.ExpiresAt, verifiedAt, verificationCode,
			actor.ScopeID, actor.UserID, request.RequestID, request.TraceID, now); err != nil {
			return err
		}
		result.Credential = stored.Credential
		result.Credential.Status, result.Credential.Revision = status, nextRevision
		result.Credential.RevisionRef, result.Credential.VerifiedAt = revisionRef, verifiedAt
		result.Credential.UpdatedAt = now
		return service.completeWrite(ctx, tx, actor, apiOperation, request.IdempotencyKey,
			stored.ID, 200, result.Credential)
	})
	if err != nil {
		return CredentialWriteResult{}, normalizeServiceError(err)
	}
	return result, nil
}

func credentialTransitionDigest(request CredentialMutationRequest, operation string) ([32]byte, error) {
	return digestRequest(struct {
		TargetScopeID    uuid.UUID `json:"target_scope_id"`
		CredentialID     uuid.UUID `json:"credential_id"`
		ExpectedRevision int64     `json:"expected_revision"`
		Operation        string    `json:"operation"`
	}{request.TargetScopeID, request.CredentialID, request.ExpectedRevision, operation})
}

func (service *Service) findCredentialReplay(
	ctx context.Context,
	actor Actor,
	request CredentialMutationRequest,
	operation string,
	digest [32]byte,
) (CredentialWriteResult, bool, error) {
	var existingTarget uuid.UUID
	var existingDigest, body []byte
	var status *int
	var completedAt *time.Time
	found := false
	err := service.authorizedRead(ctx, actor, request.TargetScopeID, PermissionManage, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT target_scope_id,request_digest,response_body,response_status,completed_at
			FROM origin_auth_write_requests
			WHERE actor_scope_id=$1 AND actor_user_id=$2 AND operation=$3 AND idempotency_key=$4`,
			actor.ScopeID, actor.UserID, "origin_auth.credential."+operation, request.IdempotencyKey).Scan(
			&existingTarget, &existingDigest, &body, &status, &completedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		found = err == nil
		return err
	})
	if err != nil {
		return CredentialWriteResult{}, false, normalizeServiceError(err)
	}
	if !found {
		return CredentialWriteResult{}, false, nil
	}
	if existingTarget != request.TargetScopeID || !equalBytes(existingDigest, digest[:]) || status == nil || completedAt == nil {
		return CredentialWriteResult{}, false, ErrIdempotencyConflict
	}
	var result CredentialWriteResult
	if err := json.Unmarshal(body, &result.Credential); err != nil {
		return CredentialWriteResult{}, false, ErrUnavailable
	}
	result.Replayed = true
	return result, true, nil
}

func (service *Service) GetCredential(
	ctx context.Context,
	actor Actor,
	targetScopeID, credentialID uuid.UUID,
) (Credential, error) {
	if err := validateTarget(actor, targetScopeID); err != nil {
		return Credential{}, err
	}
	if credentialID == uuid.Nil {
		return Credential{}, ErrInvalidInput
	}
	var stored storedCredential
	err := service.authorizedRead(ctx, actor, targetScopeID, PermissionRead, func(tx pgx.Tx) error {
		var err error
		stored, err = loadCredential(ctx, tx, targetScopeID, credentialID, false)
		return err
	})
	if err != nil {
		return Credential{}, normalizeServiceError(err)
	}
	return stored.Credential, nil
}

func (service *Service) ListCredentials(
	ctx context.Context,
	actor Actor,
	filter CredentialListFilter,
) (CredentialList, error) {
	if err := validateTarget(actor, filter.TargetScopeID); err != nil {
		return CredentialList{}, err
	}
	if filter.Limit < 1 || filter.Limit > 100 ||
		len(filter.Cursor) > maxCursorBytes || filter.Provider != "" && filter.Provider != ProviderS3 &&
		filter.Provider != ProviderOSS && filter.Provider != ProviderCOS ||
		filter.Status != "" && filter.Status != StatusPending && filter.Status != StatusVerified &&
			filter.Status != StatusDisabled && filter.Status != StatusDeleted {
		return CredentialList{}, ErrInvalidInput
	}
	cursor, err := decodeCursor(filter.Cursor)
	if err != nil {
		return CredentialList{}, err
	}
	items := make([]Credential, 0, filter.Limit+1)
	err = service.authorizedRead(ctx, actor, filter.TargetScopeID, PermissionRead, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT c.id,c.tenant_scope_id,c.provider,c.name,r.status,r.revision,
			r.revision_ref,r.not_before,r.expires_at,r.verified_at,c.created_at,r.created_at
			FROM origin_auth_credentials c
			JOIN LATERAL (SELECT * FROM origin_auth_credential_revisions revision
				WHERE revision.credential_id=c.id ORDER BY revision.revision DESC LIMIT 1) r ON true
			WHERE c.tenant_scope_id=$1 AND ($2='' OR c.provider=$2) AND ($3='' OR r.status=$3)
			  AND ($4::timestamptz IS NULL OR (c.created_at,c.id) < ($4,$5))
			ORDER BY c.created_at DESC,c.id DESC LIMIT $6`, filter.TargetScopeID, filter.Provider,
			filter.Status, nullableCursorTime(cursor), nullableCursorID(cursor), filter.Limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item Credential
			if err := rows.Scan(&item.ID, &item.TenantScope, &item.Provider, &item.Name, &item.Status,
				&item.Revision, &item.RevisionRef, &item.NotBefore, &item.ExpiresAt, &item.VerifiedAt,
				&item.CreatedAt, &item.UpdatedAt); err != nil {
				return err
			}
			items = append(items, item)
		}
		return rows.Err()
	})
	if err != nil {
		return CredentialList{}, normalizeServiceError(err)
	}
	result := CredentialList{Items: items}
	if len(items) > filter.Limit {
		last := items[filter.Limit-1]
		result.Items = items[:filter.Limit]
		result.NextCursor, err = encodeCursor(pageCursor{CreatedAt: last.CreatedAt, ID: last.ID})
		if err != nil {
			return CredentialList{}, ErrUnavailable
		}
	}
	return result, nil
}

type credentialQueryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func loadCredential(
	ctx context.Context,
	database credentialQueryer,
	targetScopeID, credentialID uuid.UUID,
	lock bool,
) (storedCredential, error) {
	locking := ""
	if lock {
		locking = " FOR UPDATE OF c"
	}
	query := `SELECT c.id,c.tenant_scope_id,c.tenant_id,c.provider,c.name,r.status,r.revision,r.revision_ref,
		r.not_before,r.expires_at,r.verified_at,c.created_at,r.created_at,r.envelope_key_id,
		r.secret_ciphertext,r.secret_ciphertext_sha256
		FROM origin_auth_credentials c
		JOIN LATERAL (SELECT * FROM origin_auth_credential_revisions revision
			WHERE revision.credential_id=c.id ORDER BY revision.revision DESC LIMIT 1) r ON true
		WHERE c.tenant_scope_id=$1 AND c.id=$2` + locking
	var stored storedCredential
	err := database.QueryRow(ctx, query, targetScopeID, credentialID).Scan(
		&stored.ID, &stored.TenantScope, &stored.tenantID, &stored.Provider, &stored.Name,
		&stored.Status, &stored.Revision, &stored.RevisionRef, &stored.NotBefore, &stored.ExpiresAt,
		&stored.VerifiedAt, &stored.CreatedAt, &stored.UpdatedAt, &stored.keyID,
		&stored.ciphertext, &stored.cipherDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		return storedCredential{}, ErrNotFound
	}
	if err != nil {
		return storedCredential{}, err
	}
	return stored, nil
}

func credentialUsedByActiveRule(ctx context.Context, tx pgx.Tx, credentialID uuid.UUID, revision int64) (bool, error) {
	var used bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM origin_auth_rules identity
		JOIN LATERAL (SELECT * FROM origin_auth_rule_revisions rule_revision
			WHERE rule_revision.rule_id=identity.id ORDER BY rule_revision.revision DESC LIMIT 1) current ON true
		WHERE current.enabled AND NOT current.deleted AND
		  (ROW(current.current_credential_id,current.current_credential_revision)=ROW($1,$2) OR
		   ROW(current.previous_credential_id,current.previous_credential_revision)=ROW($1,$2)))`,
		credentialID, revision).Scan(&used)
	return used, err
}

func nullableCursorTime(cursor *pageCursor) any {
	if cursor == nil {
		return nil
	}
	return cursor.CreatedAt
}

func nullableCursorID(cursor *pageCursor) any {
	if cursor == nil {
		return nil
	}
	return cursor.ID
}
