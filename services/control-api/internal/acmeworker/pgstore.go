package acmeworker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const terminalChallengeCleanupLeaseDuration = 45 * time.Second

type PGOperationStore struct {
	pool *pgxpool.Pool
}

type pgChallengeCleanupClaim struct {
	store     *PGOperationStore
	lease     OperationLease
	challenge ChallengeIdentity
	revision  int64
	closed    bool
}

var _ TerminalChallengeCleanupStore = (*PGOperationStore)(nil)

func NewPGOperationStore(pool *pgxpool.Pool) (*PGOperationStore, error) {
	if pool == nil {
		return nil, failure(CodeInvalidInput, nil)
	}
	return &PGOperationStore{pool: pool}, nil
}

func (s *PGOperationStore) Claim(
	ctx context.Context,
	request IssueRequest,
	digest string,
	now, leaseUntil time.Time,
) (OperationClaim, error) {
	leaseDuration := leaseUntil.Sub(now)
	digestBytes, err := decodeDigest(digest)
	if err != nil || request.TenantID == uuid.Nil || request.ScopeID == uuid.Nil || !validFrozenIssueRequest(request) ||
		digest != issueRequestDigest(request) || leaseDuration <= 0 || leaseDuration > 24*time.Hour {
		return OperationClaim{}, failure(CodeInvalidInput, err)
	}
	snapshot, err := json.Marshal(request)
	if err != nil {
		return OperationClaim{}, failure(CodeOperationStoreFailed, err)
	}
	var result OperationClaim
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		claimKey := request.ScopeID.String() + "/" + request.OperationID
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, claimKey); err != nil {
			return err
		}
		boundSchema, err := hasACMEBinding048(ctx, tx)
		if err != nil {
			return err
		}
		var operationExists bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM acme_issuance_operations
				WHERE tenant_scope_id=$1 AND operation_id=$2
			)`, request.ScopeID, request.OperationID).Scan(&operationExists); err != nil {
			return err
		}
		inserted := false
		if !operationExists && boundSchema {
			var providerID *uuid.UUID
			if request.ChallengeType == ChallengeDNS01 {
				parsed, parseErr := uuid.Parse(request.ProviderRef)
				if parseErr != nil {
					return failure(CodeInvalidInput, parseErr)
				}
				providerID = &parsed
			}
			command, insertErr := tx.Exec(ctx, `
				INSERT INTO acme_issuance_operations (
					tenant_scope_id, operation_id, request_digest, request_snapshot,
					directory_url, certificate_key_ref, certificate_order_id,
					actor_user_id, dns_provider_id, account_key_ref, created_at
				) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
				ON CONFLICT DO NOTHING`,
				request.ScopeID, request.OperationID, digestBytes, snapshot,
				requestDirectory(request), request.CertificateKeyRef, request.CertificateOrderID,
				request.ActorUserID, providerID, request.AccountKeyRef, now.UTC(),
			)
			if insertErr != nil {
				return insertErr
			}
			inserted = command.RowsAffected() == 1
		} else if !operationExists {
			command, insertErr := tx.Exec(ctx, `
				INSERT INTO acme_issuance_operations (
					tenant_scope_id, operation_id, request_digest, request_snapshot,
					directory_url, certificate_key_ref, created_at
				) VALUES ($1,$2,$3,$4,$5,$6,$7)
				ON CONFLICT DO NOTHING`,
				request.ScopeID, request.OperationID, digestBytes, snapshot,
				requestDirectory(request), request.CertificateKeyRef, now.UTC(),
			)
			if insertErr != nil {
				return insertErr
			}
			inserted = command.RowsAffected() == 1
		}
		var storedDigest []byte
		var storedSnapshot []byte
		var databaseNow time.Time
		if err := tx.QueryRow(ctx, `
			SELECT request_digest, request_snapshot, statement_timestamp()
			FROM acme_issuance_operations
			WHERE tenant_scope_id=$1 AND operation_id=$2
			FOR UPDATE`, request.ScopeID, request.OperationID,
		).Scan(&storedDigest, &storedSnapshot, &databaseNow); err != nil {
			return err
		}
		if !bytes.Equal(storedDigest, digestBytes) {
			return failure(CodeOperationConflict, nil)
		}
		var storedRequest IssueRequest
		if err := json.Unmarshal(storedSnapshot, &storedRequest); err != nil {
			return err
		}
		if !validFrozenIssueRequest(storedRequest) || issueRequestDigest(storedRequest) != digest {
			return failure(CodeOperationStoreFailed, nil)
		}
		if !issueRequestsEqual(storedRequest, request) {
			return failure(CodeOperationConflict, nil)
		}
		if err := lockCertificateOrderAuthority(ctx, tx, request.ScopeID,
			request.CertificateOrderID, boundSchema); err != nil {
			return err
		}
		databaseLeaseUntil := databaseNow.Add(leaseDuration)
		if inserted {
			token, err := uuid.NewV7()
			if err != nil {
				return err
			}
			lease := OperationLease{
				TenantID: request.TenantID, ScopeID: request.ScopeID,
				OperationID: request.OperationID, Token: token,
				ExpiresAt: databaseLeaseUntil.UTC(), Revision: 1, Request: storedRequest, Digest: digest,
				State: OperationState{Phase: PhaseClaimed, Status: OperationActive},
			}
			if err := insertOperationEvent(ctx, tx, lease, "claim_created", lease.Token, now.UTC(), time.Time{}); err != nil {
				return err
			}
			result = OperationClaim{State: OperationClaimed, Lease: lease}
			return nil
		}

		lease, nextReconcile, err := loadLatestOperation(
			ctx, tx, request.TenantID, request.ScopeID, request.OperationID, storedRequest, digest,
		)
		if err != nil {
			return err
		}
		switch lease.State.Status {
		case OperationCompleted:
			result = OperationClaim{State: OperationDone, Lease: lease}
			return nil
		case OperationFailed:
			result = OperationClaim{State: OperationTerminal, Lease: lease}
			return nil
		case OperationActive:
			if lease.ExpiresAt.After(databaseNow) {
				result = OperationClaim{State: OperationBusy, Lease: lease}
				return nil
			}
		case OperationRetryWait:
			if nextReconcile.After(databaseNow) {
				result = OperationClaim{State: OperationBusy, Lease: lease}
				return nil
			}
		default:
			return fmt.Errorf("unknown ACME operation status %q", lease.State.Status)
		}

		token, err := uuid.NewV7()
		if err != nil {
			return err
		}
		lease.Token = token
		lease.ExpiresAt = databaseLeaseUntil.UTC()
		lease.Revision++
		lease.State.Status = OperationActive
		lease.State.FailureCode = ""
		if err := insertOperationEvent(ctx, tx, lease, "lease_taken_over", lease.Token, now.UTC(), time.Time{}); err != nil {
			return err
		}
		result = OperationClaim{State: OperationClaimed, Lease: lease}
		return nil
	})
	if err != nil {
		var workerError *Error
		if errors.As(err, &workerError) {
			return OperationClaim{}, workerError
		}
		return OperationClaim{}, failure(CodeOperationStoreFailed, err)
	}
	return result, nil
}

func (s *PGOperationStore) Advance(
	ctx context.Context,
	lease OperationLease,
	eventType string,
	next OperationState,
	now time.Time,
) (OperationLease, error) {
	var result OperationLease
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		current, _, err := lockAndFence(ctx, tx, lease)
		if err != nil {
			return err
		}
		if err := lockLeaseCertificateOrderAuthority(ctx, tx, lease); err != nil {
			return err
		}
		if phaseRank(next.Phase) < phaseRank(current.State.Phase) {
			return failure(CodeOperationConflict, nil)
		}
		current.Revision++
		fenceToken := current.Token
		current.State = cloneOperationState(next)
		if next.Status == OperationCompleted || next.Status == OperationFailed {
			current.Token = uuid.Nil
			current.ExpiresAt = time.Time{}
		}
		if err := insertOperationEvent(ctx, tx, current, eventType, fenceToken, now.UTC(), time.Time{}); err != nil {
			return err
		}
		result = current
		return nil
	})
	if err != nil {
		return OperationLease{}, mapStoreError(err)
	}
	return result, nil
}

func (s *PGOperationStore) Release(
	ctx context.Context,
	lease OperationLease,
	code ErrorCode,
	retry bool,
	now, retryAt time.Time,
) error {
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		current, _, err := lockAndFence(ctx, tx, lease)
		if err != nil {
			return err
		}
		current.Revision++
		fenceToken := current.Token
		current.Token = uuid.Nil
		current.ExpiresAt = time.Time{}
		current.State.FailureCode = code
		eventType := "failed"
		nextReconcile := time.Time{}
		if retry {
			current.State.Status = OperationRetryWait
			eventType = "retry_scheduled"
			nextReconcile = retryAt.UTC()
		} else {
			current.State.Status = OperationFailed
		}
		return insertOperationEvent(ctx, tx, current, eventType, fenceToken, now.UTC(), nextReconcile)
	})
	if err != nil {
		return mapStoreError(err)
	}
	return nil
}

func (s *PGOperationStore) PrepareChallenge(
	ctx context.Context,
	lease OperationLease,
	challenge ChallengeIdentity,
	now time.Time,
) (ChallengeIdentity, error) {
	if !challengeMatchesRequest(challenge, lease) || challenge.TXTHandle != (RemoteTXTHandle{}) ||
		challenge.ZeroMatchCleanupClaimed {
		return ChallengeIdentity{}, failure(CodeOperationConflict, nil)
	}
	var result ChallengeIdentity
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, _, err := lockAndFence(ctx, tx, lease); err != nil {
			return err
		}
		if err := lockLeaseCertificateOrderAuthority(ctx, tx, lease); err != nil {
			return err
		}
		boundSchema, err := hasACMEBinding048(ctx, tx)
		if err != nil {
			return err
		}
		attemptID, err := uuid.NewV7()
		if err != nil {
			return err
		}
		var attemptNumber int
		if err := tx.QueryRow(ctx, `
			SELECT COALESCE(max(attempt_number),0)+1
			FROM acme_issuance_challenge_attempts
			WHERE tenant_scope_id=$1 AND operation_id=$2 AND authorization_url=$3`,
			lease.ScopeID, lease.OperationID, challenge.AuthorizationURL,
		).Scan(&attemptNumber); err != nil {
			return err
		}
		challenge.TenantID = lease.Request.TenantID
		challenge.ScopeID = lease.Request.ScopeID
		challenge.ProviderID = lease.Request.ProviderID
		challenge.ZoneID = lease.Request.ZoneID
		challenge.OperationID = lease.OperationID
		challenge.AttemptID = attemptID
		_, err = tx.Exec(ctx, `
			INSERT INTO acme_issuance_challenge_attempts (
				tenant_scope_id, operation_id, attempt_id, attempt_number,
				authorization_url, challenge_url, challenge_type, identifier,
				wildcard, record_name, token, exact_value, created_at
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
			challenge.ScopeID, challenge.OperationID, challenge.AttemptID, attemptNumber,
			challenge.AuthorizationURL, challenge.ChallengeURL, challenge.ChallengeType,
			challenge.Identifier, challenge.Wildcard, challenge.RecordName,
			challenge.Token, challenge.ExactValue, now.UTC(),
		)
		if err != nil {
			return err
		}
		if challenge.ChallengeType == ChallengeDNS01 && boundSchema {
			exactDigest := sha256.Sum256([]byte(challenge.ExactValue))
			_, err = tx.Exec(ctx, `
				INSERT INTO acme_issuance_challenge_events (
					tenant_scope_id, operation_id, attempt_id, revision, state, lease_token,
					exact_value_sha256, occurred_at
				) VALUES ($1,$2,$3,1,'intent',$4,$5,$6)`,
				challenge.ScopeID, challenge.OperationID, challenge.AttemptID,
				lease.Token, exactDigest[:], now.UTC(),
			)
		} else {
			_, err = tx.Exec(ctx, `
				INSERT INTO acme_issuance_challenge_events (
					tenant_scope_id, operation_id, attempt_id, revision, state, lease_token, occurred_at
				) VALUES ($1,$2,$3,1,'intent',$4,$5)`,
				challenge.ScopeID, challenge.OperationID, challenge.AttemptID, lease.Token, now.UTC(),
			)
		}
		if err == nil {
			result = challenge
		}
		return err
	})
	if err != nil {
		return ChallengeIdentity{}, mapStoreError(err)
	}
	return result, nil
}

func (s *PGOperationStore) MarkChallenge(
	ctx context.Context,
	lease OperationLease,
	challenge ChallengeIdentity,
	state string,
	now time.Time,
) error {
	if state != "published" {
		return failure(CodeInvalidInput, nil)
	}
	if !challengeMatchesRequest(challenge, lease) || challenge.ZeroMatchCleanupClaimed {
		return failure(CodeOperationConflict, nil)
	}
	if challenge.ChallengeType == ChallengeDNS01 {
		if err := validateRemoteTXTHandle(challenge.TXTHandle, lease.Request.ProviderRef); err != nil {
			return failure(CodeInvalidInput, err)
		}
	} else if challenge.TXTHandle != (RemoteTXTHandle{}) {
		return failure(CodeInvalidInput, nil)
	}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, _, err := lockAndFence(ctx, tx, lease); err != nil {
			return err
		}
		if err := lockLeaseCertificateOrderAuthority(ctx, tx, lease); err != nil {
			return err
		}
		var revision int64
		var currentState string
		var providerRef, recordRef *string
		if err := tx.QueryRow(ctx, `
			SELECT latest.revision, latest.state, latest.provider_ref, latest.remote_record_ref
			FROM acme_issuance_challenge_attempts attempt
			JOIN LATERAL (
				SELECT revision, state, to_jsonb(event)->>'provider_ref' AS provider_ref,
				       to_jsonb(event)->>'remote_record_ref' AS remote_record_ref
				FROM acme_issuance_challenge_events event
				WHERE event.tenant_scope_id=attempt.tenant_scope_id
				  AND event.operation_id=attempt.operation_id
				  AND event.attempt_id=attempt.attempt_id
				ORDER BY revision DESC LIMIT 1
			) latest ON true
			WHERE attempt.tenant_scope_id=$1 AND attempt.operation_id=$2 AND attempt.attempt_id=$3
			  AND attempt.authorization_url=$4 AND attempt.challenge_url=$5
			  AND attempt.challenge_type=$6 AND attempt.identifier=$7 AND attempt.wildcard=$8
			  AND attempt.record_name=$9 AND attempt.token=$10 AND attempt.exact_value=$11`,
			challenge.ScopeID, challenge.OperationID, challenge.AttemptID,
			challenge.AuthorizationURL, challenge.ChallengeURL, challenge.ChallengeType,
			challenge.Identifier, challenge.Wildcard, challenge.RecordName,
			challenge.Token, challenge.ExactValue,
		).Scan(&revision, &currentState, &providerRef, &recordRef); err != nil {
			return err
		}
		if currentState == state {
			if challenge.ChallengeType == ChallengeDNS01 &&
				(stringValue(providerRef) != challenge.TXTHandle.ProviderRef ||
					stringValue(recordRef) != challenge.TXTHandle.RecordRef) {
				return failure(CodeOperationConflict, nil)
			}
			return nil
		}
		var err error
		if challenge.ChallengeType == ChallengeDNS01 {
			exactDigest := sha256.Sum256([]byte(challenge.ExactValue))
			_, err = tx.Exec(ctx, `
				INSERT INTO acme_issuance_challenge_events (
					tenant_scope_id, operation_id, attempt_id, revision, state, lease_token,
					provider_ref, remote_record_ref, exact_value_sha256, occurred_at
				) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
				lease.ScopeID, lease.OperationID, challenge.AttemptID, revision+1,
				state, lease.Token, challenge.TXTHandle.ProviderRef, challenge.TXTHandle.RecordRef,
				exactDigest[:], now.UTC(),
			)
		} else {
			_, err = tx.Exec(ctx, `
				INSERT INTO acme_issuance_challenge_events (
					tenant_scope_id, operation_id, attempt_id, revision, state, lease_token, occurred_at
				) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
				lease.ScopeID, lease.OperationID, challenge.AttemptID, revision+1,
				state, lease.Token, now.UTC(),
			)
		}
		return err
	})
	if err != nil {
		return mapStoreError(err)
	}
	return nil
}

func (s *PGOperationStore) ClaimChallengeCleanup(
	ctx context.Context,
	lease OperationLease,
	challenge ChallengeIdentity,
	now time.Time,
) (ChallengeCleanupClaim, error) {
	if !challengeMatchesRequest(challenge, lease) || challenge.ZeroMatchCleanupClaimed {
		return nil, failure(CodeOperationConflict, nil)
	}
	if challenge.ChallengeType == ChallengeDNS01 {
		if challenge.TXTHandle != (RemoteTXTHandle{}) {
			if err := validateRemoteTXTHandle(challenge.TXTHandle, lease.Request.ProviderRef); err != nil {
				return nil, failure(CodeChallengeCleanupFailed, err)
			}
		}
	} else if challenge.TXTHandle != (RemoteTXTHandle{}) {
		return nil, failure(CodeOperationConflict, nil)
	}
	var result *pgChallengeCleanupClaim
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		_, databaseNow, err := lockAndFence(ctx, tx, lease)
		if err != nil {
			return err
		}
		revision, state, claimToken, providerRef, recordRef, err := loadChallengeCleanupState(
			ctx, tx, challenge,
		)
		if err != nil {
			return err
		}
		if challenge.ChallengeType == ChallengeDNS01 {
			storedEmpty := providerRef == nil && recordRef == nil
			requestedEmpty := challenge.TXTHandle == (RemoteTXTHandle{})
			if (providerRef == nil) != (recordRef == nil) || storedEmpty != requestedEmpty ||
				!requestedEmpty && (stringValue(providerRef) != challenge.TXTHandle.ProviderRef ||
					stringValue(recordRef) != challenge.TXTHandle.RecordRef) ||
				requestedEmpty && state == "published" {
				return failure(CodeOperationConflict, nil)
			}
		}
		if state == "cleaned" {
			return failure(CodeOperationConflict, nil)
		}
		if state == "cleanup_claimed" && claimToken == lease.Token {
			return &Error{Code: CodeChallengeCleanupFailed, Temporary: true}
		}
		if state != "intent" && state != "published" && state != "cleanup_claimed" {
			return failure(CodeOperationConflict, nil)
		}
		if challenge.ChallengeType == ChallengeDNS01 {
			exactDigest := sha256.Sum256([]byte(challenge.ExactValue))
			providerValue, recordValue := nullableTXTHandle(challenge.TXTHandle)
			_, err = tx.Exec(ctx, `
				INSERT INTO acme_issuance_challenge_events (
					tenant_scope_id, operation_id, attempt_id, revision, state, lease_token,
					provider_ref, remote_record_ref, exact_value_sha256, occurred_at
				) VALUES ($1,$2,$3,$4,'cleanup_claimed',$5,$6,$7,$8,$9)`,
				challenge.ScopeID, challenge.OperationID, challenge.AttemptID,
				revision+1, lease.Token, providerValue, recordValue, exactDigest[:], databaseNow,
			)
		} else {
			_, err = tx.Exec(ctx, `
				INSERT INTO acme_issuance_challenge_events (
					tenant_scope_id, operation_id, attempt_id, revision, state, lease_token, occurred_at
				) VALUES ($1,$2,$3,$4,'cleanup_claimed',$5,$6)`,
				challenge.ScopeID, challenge.OperationID, challenge.AttemptID,
				revision+1, lease.Token, databaseNow,
			)
		}
		if err == nil {
			result = &pgChallengeCleanupClaim{
				store: s, lease: lease, challenge: challenge, revision: revision + 1,
			}
		}
		return err
	})
	if err != nil {
		return nil, mapStoreError(err)
	}
	return result, nil
}

func (c *pgChallengeCleanupClaim) Complete(ctx context.Context, _ time.Time) error {
	if c.closed {
		return failure(CodeOperationConflict, nil)
	}
	if !challengeMatchesRequest(c.challenge, c.lease) {
		return failure(CodeOperationConflict, nil)
	}
	if c.challenge.ChallengeType == ChallengeDNS01 {
		if c.challenge.TXTHandle != (RemoteTXTHandle{}) &&
			validateRemoteTXTHandle(c.challenge.TXTHandle, c.lease.Request.ProviderRef) != nil {
			return failure(CodeOperationConflict, nil)
		}
	} else if c.challenge.TXTHandle != (RemoteTXTHandle{}) {
		return failure(CodeOperationConflict, nil)
	}
	err := pgx.BeginFunc(ctx, c.store.pool, func(tx pgx.Tx) error {
		_, databaseNow, err := lockAndFence(ctx, tx, c.lease)
		if err != nil {
			return err
		}
		revision, state, claimToken, providerRef, recordRef, err := loadChallengeCleanupState(
			ctx, tx, c.challenge,
		)
		if err != nil {
			return err
		}
		storedHandleMatches := true
		if c.challenge.ChallengeType == ChallengeDNS01 {
			storedEmpty := providerRef == nil && recordRef == nil
			requestedEmpty := c.challenge.TXTHandle == (RemoteTXTHandle{})
			storedHandleMatches = (providerRef == nil) == (recordRef == nil) && storedEmpty == requestedEmpty &&
				(requestedEmpty || stringValue(providerRef) == c.challenge.TXTHandle.ProviderRef &&
					stringValue(recordRef) == c.challenge.TXTHandle.RecordRef)
		}
		if revision != c.revision || state != "cleanup_claimed" || claimToken != c.lease.Token || !storedHandleMatches {
			return failure(CodeOperationConflict, nil)
		}
		if c.challenge.ChallengeType == ChallengeDNS01 {
			exactDigest := sha256.Sum256([]byte(c.challenge.ExactValue))
			providerValue, recordValue := nullableTXTHandle(c.challenge.TXTHandle)
			_, err = tx.Exec(ctx, `
				INSERT INTO acme_issuance_challenge_events (
					tenant_scope_id, operation_id, attempt_id, revision, state, lease_token,
					provider_ref, remote_record_ref, exact_value_sha256, occurred_at
				) VALUES ($1,$2,$3,$4,'cleaned',$5,$6,$7,$8,$9)`,
				c.challenge.ScopeID, c.challenge.OperationID, c.challenge.AttemptID,
				c.revision+1, c.lease.Token, providerValue, recordValue, exactDigest[:], databaseNow,
			)
		} else {
			_, err = tx.Exec(ctx, `
				INSERT INTO acme_issuance_challenge_events (
					tenant_scope_id, operation_id, attempt_id, revision, state, lease_token, occurred_at
				) VALUES ($1,$2,$3,$4,'cleaned',$5,$6)`,
				c.challenge.ScopeID, c.challenge.OperationID, c.challenge.AttemptID,
				c.revision+1, c.lease.Token, databaseNow,
			)
		}
		return err
	})
	if err != nil {
		return mapStoreError(err)
	}
	c.closed = true
	return nil
}

func (c *pgChallengeCleanupClaim) Abort(context.Context) error {
	c.closed = true
	return nil
}

func nullableTXTHandle(handle RemoteTXTHandle) (*string, *string) {
	if handle == (RemoteTXTHandle{}) {
		return nil, nil
	}
	providerRef := handle.ProviderRef
	recordRef := handle.RecordRef
	return &providerRef, &recordRef
}

func loadChallengeCleanupState(
	ctx context.Context,
	tx pgx.Tx,
	challenge ChallengeIdentity,
) (int64, string, uuid.UUID, *string, *string, error) {
	var revision int64
	var state string
	var leaseToken uuid.UUID
	var providerRef, recordRef *string
	err := tx.QueryRow(ctx, `
		SELECT latest.revision, latest.state, latest.lease_token,
		       latest.provider_ref, latest.remote_record_ref
		FROM acme_issuance_challenge_attempts attempt
		JOIN LATERAL (
			SELECT revision, state, lease_token,
			       to_jsonb(event)->>'provider_ref' AS provider_ref,
			       to_jsonb(event)->>'remote_record_ref' AS remote_record_ref
			FROM acme_issuance_challenge_events event
			WHERE event.tenant_scope_id=attempt.tenant_scope_id
			  AND event.operation_id=attempt.operation_id
			  AND event.attempt_id=attempt.attempt_id
			ORDER BY revision DESC LIMIT 1
		) latest ON true
		WHERE attempt.tenant_scope_id=$1 AND attempt.operation_id=$2 AND attempt.attempt_id=$3
		  AND attempt.authorization_url=$4 AND attempt.challenge_url=$5
		  AND attempt.challenge_type=$6 AND attempt.identifier=$7 AND attempt.wildcard=$8
		  AND attempt.record_name=$9 AND attempt.token=$10 AND attempt.exact_value=$11`,
		challenge.ScopeID, challenge.OperationID, challenge.AttemptID,
		challenge.AuthorizationURL, challenge.ChallengeURL, challenge.ChallengeType,
		challenge.Identifier, challenge.Wildcard, challenge.RecordName,
		challenge.Token, challenge.ExactValue,
	).Scan(&revision, &state, &leaseToken, &providerRef, &recordRef)
	if errors.Is(err, pgx.ErrNoRows) {
		err = failure(CodeOperationConflict, nil)
	}
	return revision, state, leaseToken, providerRef, recordRef, err
}

func (s *PGOperationStore) OutstandingChallenges(
	ctx context.Context,
	lease OperationLease,
	_ time.Time,
) ([]ChallengeIdentity, error) {
	var result []ChallengeIdentity
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, _, err := lockAndFence(ctx, tx, lease); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `
			SELECT attempt.attempt_id, attempt.authorization_url, attempt.challenge_url,
			       attempt.challenge_type, attempt.identifier, attempt.wildcard,
			       attempt.record_name, attempt.token, attempt.exact_value,
			       latest.state, latest.provider_ref, latest.remote_record_ref
			FROM acme_issuance_challenge_attempts attempt
			JOIN LATERAL (
				SELECT state, to_jsonb(event)->>'provider_ref' AS provider_ref,
				       to_jsonb(event)->>'remote_record_ref' AS remote_record_ref
				FROM acme_issuance_challenge_events event
				WHERE event.tenant_scope_id=attempt.tenant_scope_id
				  AND event.operation_id=attempt.operation_id
				  AND event.attempt_id=attempt.attempt_id
				ORDER BY revision DESC LIMIT 1
			) latest ON true
			WHERE attempt.tenant_scope_id=$1 AND attempt.operation_id=$2
			  AND latest.state <> 'cleaned'
			ORDER BY attempt.created_at, attempt.attempt_id`, lease.ScopeID, lease.OperationID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			item := ChallengeIdentity{
				TenantID: lease.Request.TenantID, ScopeID: lease.Request.ScopeID,
				ProviderID: lease.Request.ProviderID, ZoneID: lease.Request.ZoneID,
				OperationID: lease.OperationID, ProviderRef: lease.Request.ProviderRef,
			}
			var state string
			var providerRef, recordRef *string
			if err := rows.Scan(&item.AttemptID, &item.AuthorizationURL, &item.ChallengeURL,
				&item.ChallengeType, &item.Identifier, &item.Wildcard, &item.RecordName,
				&item.Token, &item.ExactValue, &state, &providerRef, &recordRef); err != nil {
				return err
			}
			if providerRef != nil || recordRef != nil {
				item.TXTHandle = RemoteTXTHandle{
					ProviderRef: stringValue(providerRef), RecordRef: stringValue(recordRef),
				}
				if item.ChallengeType != ChallengeDNS01 ||
					validateRemoteTXTHandle(item.TXTHandle, lease.Request.ProviderRef) != nil {
					return failure(CodeOperationStoreFailed, nil)
				}
			}
			item.ZeroMatchCleanupClaimed = item.ChallengeType == ChallengeDNS01 &&
				item.TXTHandle == (RemoteTXTHandle{}) && state == "cleanup_claimed"
			result = append(result, item)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, mapStoreError(err)
	}
	return result, nil
}

func (s *PGOperationStore) Recoverable(ctx context.Context, _ time.Time, limit int) ([]IssueRequest, error) {
	if limit < 1 || limit > 1000 {
		return nil, failure(CodeInvalidInput, nil)
	}
	rows, err := s.pool.Query(ctx, `
		SELECT operation.tenant_scope_id, operation.operation_id,
		       operation.request_digest, operation.request_snapshot
		FROM acme_issuance_operations operation
		JOIN certificate_orders certificate_order
		  ON certificate_order.scope_id=operation.tenant_scope_id
		 AND certificate_order.id=operation.certificate_order_id
		LEFT JOIN certificate_orders renewal_parent
		  ON renewal_parent.scope_id=certificate_order.scope_id
		 AND renewal_parent.id=certificate_order.renewal_of_order_id
		JOIN LATERAL (
			SELECT status, lease_expires_at, next_reconcile_at, occurred_at
			FROM acme_issuance_operation_events event
			WHERE event.tenant_scope_id=operation.tenant_scope_id
			  AND event.operation_id=operation.operation_id
			ORDER BY revision DESC LIMIT 1
		) latest ON true
		WHERE ((latest.status='active' AND latest.lease_expires_at <= statement_timestamp())
		    OR (latest.status='retry_wait' AND latest.next_reconcile_at <= statement_timestamp()))
		  AND certificate_order.status IN ('pending','validating','issuing','issued')
		  AND (certificate_order.renewal_of_order_id IS NULL
		       OR renewal_parent.status IN ('active','renewal_due'))
		ORDER BY latest.occurred_at, operation.tenant_scope_id, operation.operation_id
		LIMIT $1`, limit)
	if err != nil {
		return nil, failure(CodeOperationStoreFailed, err)
	}
	defer rows.Close()
	result := make([]IssueRequest, 0)
	for rows.Next() {
		var scopeID uuid.UUID
		var operationID string
		var digestBytes []byte
		var raw []byte
		if err := rows.Scan(&scopeID, &operationID, &digestBytes, &raw); err != nil {
			return nil, failure(CodeOperationStoreFailed, err)
		}
		var request IssueRequest
		if err := json.Unmarshal(raw, &request); err != nil {
			return nil, failure(CodeOperationStoreFailed, err)
		}
		digest := "sha256:" + hex.EncodeToString(digestBytes)
		if request.ScopeID != scopeID || request.OperationID != operationID ||
			!validFrozenIssueRequest(request) || issueRequestDigest(request) != digest {
			return nil, failure(CodeOperationStoreFailed, nil)
		}
		result = append(result, request)
	}
	if err := rows.Err(); err != nil {
		return nil, failure(CodeOperationStoreFailed, err)
	}
	return result, nil
}

func (s *PGOperationStore) ClaimTerminalChallengeCleanup(
	ctx context.Context,
) (TerminalChallengeCleanupLease, bool, error) {
	if s == nil || s.pool == nil || ctx == nil {
		return TerminalChallengeCleanupLease{}, false, failure(CodeInvalidInput, nil)
	}
	var result TerminalChallengeCleanupLease
	found := false
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var storedDigest, storedSnapshot, exactValueDigest []byte
		var providerRef, recordRef *string
		var databaseNow time.Time
		challenge := ChallengeIdentity{}
		err := tx.QueryRow(ctx, `
			SELECT operation.request_digest,operation.request_snapshot,
			       attempt.attempt_id,attempt.authorization_url,attempt.challenge_url,
			       attempt.challenge_type,attempt.identifier,attempt.wildcard,
			       attempt.record_name,attempt.token,attempt.exact_value,
			       latest_challenge.revision,
			       latest_challenge.provider_ref,latest_challenge.remote_record_ref,
			       latest_challenge.exact_value_sha256,
			       statement_timestamp()
			FROM acme_issuance_operations operation
			JOIN certificate_orders certificate_order
			  ON certificate_order.scope_id=operation.tenant_scope_id
			 AND certificate_order.id=operation.certificate_order_id
			LEFT JOIN certificate_orders renewal_parent
			  ON renewal_parent.scope_id=certificate_order.scope_id
			 AND renewal_parent.id=certificate_order.renewal_of_order_id
			JOIN LATERAL (
				SELECT status,lease_expires_at
				FROM acme_issuance_operation_events event
				WHERE event.tenant_scope_id=operation.tenant_scope_id
				  AND event.operation_id=operation.operation_id
				ORDER BY revision DESC LIMIT 1
			) latest_operation ON true
			JOIN acme_issuance_challenge_attempts attempt
			  ON attempt.tenant_scope_id=operation.tenant_scope_id
			 AND attempt.operation_id=operation.operation_id
			JOIN LATERAL (
				SELECT revision,state,lease_token,provider_ref,remote_record_ref,
				       exact_value_sha256,occurred_at
				FROM acme_issuance_challenge_events event
				WHERE event.tenant_scope_id=attempt.tenant_scope_id
				  AND event.operation_id=attempt.operation_id
				  AND event.attempt_id=attempt.attempt_id
				ORDER BY revision DESC LIMIT 1
			) latest_challenge ON true
			WHERE (certificate_order.status IN ('failed','revoked')
			       OR renewal_parent.status IN ('failed','revoked'))
			  AND (latest_operation.status <> 'active'
			       OR latest_operation.lease_expires_at <= statement_timestamp())
			  AND latest_challenge.state IN ('published','cleanup_claimed')
			  AND (latest_challenge.state='published'
			       OR latest_challenge.occurred_at + $1::bigint * interval '1 microsecond'
			          <= statement_timestamp())
			ORDER BY latest_challenge.occurred_at,operation.tenant_scope_id,
			         operation.operation_id,attempt.attempt_id
			LIMIT 1 FOR UPDATE OF operation,attempt SKIP LOCKED`,
			terminalChallengeCleanupLeaseDuration.Microseconds(),
		).Scan(
			&storedDigest, &storedSnapshot,
			&challenge.AttemptID, &challenge.AuthorizationURL, &challenge.ChallengeURL,
			&challenge.ChallengeType, &challenge.Identifier, &challenge.Wildcard,
			&challenge.RecordName, &challenge.Token, &challenge.ExactValue,
			&result.Revision, &providerRef, &recordRef, &exactValueDigest, &databaseNow,
		)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		var request IssueRequest
		if err := json.Unmarshal(storedSnapshot, &request); err != nil ||
			!validFrozenIssueRequest(request) ||
			issueRequestDigest(request) != "sha256:"+hex.EncodeToString(storedDigest) {
			return failure(CodeOperationStoreFailed, err)
		}
		challenge.TenantID = request.TenantID
		challenge.ScopeID = request.ScopeID
		challenge.ProviderID = request.ProviderID
		challenge.ZoneID = request.ZoneID
		challenge.OperationID = request.OperationID
		challenge.ProviderRef = request.ProviderRef
		challenge.TXTHandle = RemoteTXTHandle{
			ProviderRef: stringValue(providerRef), RecordRef: stringValue(recordRef),
		}
		if err := validateTerminalCleanupPublishedIdentity(
			request, challenge, providerRef, recordRef, exactValueDigest,
		); err != nil {
			return err
		}
		claimToken, err := uuid.NewV7()
		if err != nil {
			return err
		}
		result.Token = claimToken
		result.Revision++
		result.ExpiresAt = databaseNow.UTC().Add(terminalChallengeCleanupLeaseDuration)
		result.Request = request
		result.RequestDigest = "sha256:" + hex.EncodeToString(storedDigest)
		result.Challenge = challenge
		result.ChallengeSHA256 = terminalChallengeCleanupDigest(challenge)
		if result.ChallengeSHA256 == ([sha256.Size]byte{}) {
			return failure(CodeOperationStoreFailed, nil)
		}
		if err := insertTerminalChallengeCleanupEvent(
			ctx, tx, challenge, result.Revision, "cleanup_claimed", claimToken, databaseNow,
		); err != nil {
			return err
		}
		found = true
		return nil
	})
	if err != nil {
		return TerminalChallengeCleanupLease{}, false, mapStoreError(err)
	}
	return result, found, nil
}

func (s *PGOperationStore) FenceTerminalChallengeCleanup(
	ctx context.Context,
	lease TerminalChallengeCleanupLease,
) error {
	if s == nil || s.pool == nil || ctx == nil || !validTerminalChallengeCleanupLease(lease) {
		return failure(CodeInvalidInput, nil)
	}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		_, err := s.fenceTerminalChallengeCleanupTx(ctx, tx, lease)
		return err
	})
	if err != nil {
		return mapStoreError(err)
	}
	return nil
}

func (s *PGOperationStore) CompleteTerminalChallengeCleanup(
	ctx context.Context,
	lease TerminalChallengeCleanupLease,
) error {
	if s == nil || s.pool == nil || ctx == nil || !validTerminalChallengeCleanupLease(lease) {
		return failure(CodeInvalidInput, nil)
	}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		databaseNow, err := s.fenceTerminalChallengeCleanupTx(ctx, tx, lease)
		if err != nil {
			return err
		}
		if err := insertTerminalChallengeCleanupEvent(
			ctx, tx, lease.Challenge, lease.Revision+1, "cleaned", lease.Token, databaseNow,
		); err != nil {
			return err
		}
		actorID := lease.Request.ActorUserID
		requestID := uuid.NewSHA1(lease.Challenge.AttemptID, []byte("certificate.challenge.terminal_cleanup")).String()
		return audit.NewWithClock(s.pool, func() time.Time { return databaseNow }).Append(ctx, tx, audit.Event{
			ScopeID: lease.Request.ScopeID, ActorUserID: &actorID,
			Action: "certificate.challenge.terminal_cleanup", ResourceType: "acme_challenge_attempt",
			ResourceID: lease.Challenge.AttemptID.String(), RequestID: requestID, Result: "success",
			Payload: map[string]any{
				"operation_id":     lease.Request.OperationID,
				"challenge_type":   lease.Challenge.ChallengeType,
				"challenge_sha256": hex.EncodeToString(lease.ChallengeSHA256[:]),
				"reason":           "certificate_authority_terminal",
			},
		})
	})
	if err != nil {
		return mapStoreError(err)
	}
	return nil
}

func (s *PGOperationStore) fenceTerminalChallengeCleanupTx(
	ctx context.Context,
	tx pgx.Tx,
	lease TerminalChallengeCleanupLease,
) (time.Time, error) {
	challenge := lease.Challenge
	var storedDigest, storedSnapshot, exactValueDigest []byte
	var providerRef, recordRef *string
	var claimedAt, databaseNow time.Time
	err := tx.QueryRow(ctx, `
		SELECT operation.request_digest,operation.request_snapshot,
		       latest_challenge.provider_ref,latest_challenge.remote_record_ref,
		       latest_challenge.exact_value_sha256,latest_challenge.occurred_at,
		       statement_timestamp()
		FROM acme_issuance_operations operation
		JOIN certificate_orders certificate_order
		  ON certificate_order.scope_id=operation.tenant_scope_id
		 AND certificate_order.id=operation.certificate_order_id
		LEFT JOIN certificate_orders renewal_parent
		  ON renewal_parent.scope_id=certificate_order.scope_id
		 AND renewal_parent.id=certificate_order.renewal_of_order_id
		JOIN LATERAL (
			SELECT status,lease_expires_at
			FROM acme_issuance_operation_events event
			WHERE event.tenant_scope_id=operation.tenant_scope_id
			  AND event.operation_id=operation.operation_id
			ORDER BY revision DESC LIMIT 1
		) latest_operation ON true
		JOIN acme_issuance_challenge_attempts attempt
		  ON attempt.tenant_scope_id=operation.tenant_scope_id
		 AND attempt.operation_id=operation.operation_id
		JOIN LATERAL (
			SELECT revision,state,lease_token,provider_ref,remote_record_ref,
			       exact_value_sha256,occurred_at
			FROM acme_issuance_challenge_events event
			WHERE event.tenant_scope_id=attempt.tenant_scope_id
			  AND event.operation_id=attempt.operation_id
			  AND event.attempt_id=attempt.attempt_id
			ORDER BY revision DESC LIMIT 1
		) latest_challenge ON true
		WHERE operation.tenant_scope_id=$1 AND operation.operation_id=$2
		  AND (certificate_order.status IN ('failed','revoked')
		       OR renewal_parent.status IN ('failed','revoked'))
		  AND (latest_operation.status <> 'active'
		       OR latest_operation.lease_expires_at <= statement_timestamp())
		  AND attempt.attempt_id=$3 AND attempt.authorization_url=$4
		  AND attempt.challenge_url=$5 AND attempt.challenge_type=$6
		  AND attempt.identifier=$7 AND attempt.wildcard=$8
		  AND attempt.record_name=$9 AND attempt.token=$10 AND attempt.exact_value=$11
		  AND latest_challenge.revision=$12 AND latest_challenge.state='cleanup_claimed'
		  AND latest_challenge.lease_token=$13
		FOR UPDATE OF operation,attempt`,
		lease.Request.ScopeID, lease.Request.OperationID, challenge.AttemptID,
		challenge.AuthorizationURL, challenge.ChallengeURL, challenge.ChallengeType,
		challenge.Identifier, challenge.Wildcard, challenge.RecordName,
		challenge.Token, challenge.ExactValue, lease.Revision, lease.Token,
	).Scan(
		&storedDigest, &storedSnapshot, &providerRef, &recordRef,
		&exactValueDigest, &claimedAt, &databaseNow,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, failure(CodeLeaseLost, nil)
	}
	if err != nil {
		return time.Time{}, err
	}
	var storedRequest IssueRequest
	if err := json.Unmarshal(storedSnapshot, &storedRequest); err != nil ||
		!validFrozenIssueRequest(storedRequest) ||
		issueRequestDigest(storedRequest) != "sha256:"+hex.EncodeToString(storedDigest) {
		return time.Time{}, failure(CodeOperationStoreFailed, err)
	}
	if !issueRequestsEqual(storedRequest, lease.Request) ||
		lease.RequestDigest != "sha256:"+hex.EncodeToString(storedDigest) ||
		!claimedAt.UTC().Add(terminalChallengeCleanupLeaseDuration).Equal(lease.ExpiresAt.UTC()) ||
		!lease.ExpiresAt.After(databaseNow.UTC()) ||
		lease.ChallengeSHA256 != terminalChallengeCleanupDigest(challenge) {
		return time.Time{}, failure(CodeLeaseLost, nil)
	}
	if err := validateTerminalCleanupPublishedIdentity(
		storedRequest, challenge, providerRef, recordRef, exactValueDigest,
	); err != nil {
		return time.Time{}, err
	}
	return databaseNow.UTC(), nil
}

func validateTerminalCleanupPublishedIdentity(
	request IssueRequest,
	challenge ChallengeIdentity,
	providerRef, recordRef *string,
	exactValueDigest []byte,
) error {
	lease := OperationLease{
		TenantID: request.TenantID, ScopeID: request.ScopeID,
		OperationID: request.OperationID, Request: request,
	}
	if !challengeMatchesRequest(challenge, lease) || challenge.AttemptID == uuid.Nil ||
		challenge.ChallengeType != request.ChallengeType || challenge.ZeroMatchCleanupClaimed {
		return failure(CodeOperationConflict, nil)
	}
	if challenge.ChallengeType == ChallengeHTTP01 {
		if providerRef != nil || recordRef != nil || len(exactValueDigest) != 0 ||
			challenge.TXTHandle != (RemoteTXTHandle{}) {
			return failure(CodeOperationConflict, nil)
		}
		return nil
	}
	if challenge.ChallengeType != ChallengeDNS01 || providerRef == nil || recordRef == nil ||
		stringValue(providerRef) != challenge.TXTHandle.ProviderRef ||
		stringValue(recordRef) != challenge.TXTHandle.RecordRef ||
		validateRemoteTXTHandle(challenge.TXTHandle, request.ProviderRef) != nil {
		return failure(CodeOperationConflict, nil)
	}
	wantDigest := sha256.Sum256([]byte(challenge.ExactValue))
	if !bytes.Equal(exactValueDigest, wantDigest[:]) {
		return failure(CodeOperationConflict, nil)
	}
	return nil
}

func insertTerminalChallengeCleanupEvent(
	ctx context.Context,
	tx pgx.Tx,
	challenge ChallengeIdentity,
	revision int64,
	state string,
	claimToken uuid.UUID,
	databaseNow time.Time,
) error {
	if state != "cleanup_claimed" && state != "cleaned" {
		return failure(CodeInvalidInput, nil)
	}
	var rowsAffected int64
	if challenge.ChallengeType == ChallengeDNS01 {
		exactDigest := sha256.Sum256([]byte(challenge.ExactValue))
		result, err := tx.Exec(ctx, `
			INSERT INTO acme_issuance_challenge_events (
				tenant_scope_id,operation_id,attempt_id,revision,state,lease_token,
				provider_ref,remote_record_ref,exact_value_sha256,occurred_at
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
			challenge.ScopeID, challenge.OperationID, challenge.AttemptID, revision,
			state, claimToken, challenge.TXTHandle.ProviderRef, challenge.TXTHandle.RecordRef,
			exactDigest[:], databaseNow.UTC(),
		)
		if err != nil {
			return err
		}
		rowsAffected = result.RowsAffected()
	} else {
		result, err := tx.Exec(ctx, `
			INSERT INTO acme_issuance_challenge_events (
				tenant_scope_id,operation_id,attempt_id,revision,state,lease_token,occurred_at
			) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			challenge.ScopeID, challenge.OperationID, challenge.AttemptID, revision,
			state, claimToken, databaseNow.UTC(),
		)
		if err != nil {
			return err
		}
		rowsAffected = result.RowsAffected()
	}
	if rowsAffected != 1 {
		return failure(CodeLeaseLost, nil)
	}
	return nil
}

func hasACMEBinding048(ctx context.Context, tx pgx.Tx) (bool, error) {
	var exists bool
	err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM pg_attribute
			WHERE attrelid='acme_issuance_operations'::regclass
			  AND attname='certificate_order_id' AND NOT attisdropped
		)`).Scan(&exists)
	return exists, err
}

func lockLeaseCertificateOrderAuthority(ctx context.Context, tx pgx.Tx, lease OperationLease) error {
	boundSchema, err := hasACMEBinding048(ctx, tx)
	if err != nil {
		return err
	}
	return lockCertificateOrderAuthority(ctx, tx, lease.ScopeID,
		lease.Request.CertificateOrderID, boundSchema)
}

func lockCertificateOrderAuthority(
	ctx context.Context,
	tx pgx.Tx,
	scopeID, orderID uuid.UUID,
	boundSchema bool,
) error {
	if !boundSchema {
		return nil
	}
	var childStatus string
	var parentID *uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT status,renewal_of_order_id FROM certificate_orders
		WHERE scope_id=$1 AND id=$2 FOR SHARE`, scopeID, orderID).Scan(&childStatus, &parentID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return failure(CodeOperationConflict, nil)
		}
		return err
	}
	var parentStatus *string
	if parentID != nil {
		var status string
		if err := tx.QueryRow(ctx, `SELECT status FROM certificate_orders
			WHERE scope_id=$1 AND id=$2 FOR SHARE`, scopeID, *parentID).Scan(&status); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return failure(CodeOperationConflict, nil)
			}
			return err
		}
		parentStatus = &status
	}
	if !certificateOrderAuthorityAllows(childStatus, parentStatus) {
		return failure(CodeOperationConflict, nil)
	}
	return nil
}

func certificateOrderAuthorityAllows(childStatus string, parentStatus *string) bool {
	switch childStatus {
	case "pending", "validating", "issuing", "issued":
	default:
		return false
	}
	return parentStatus == nil || *parentStatus == "active" || *parentStatus == "renewal_due"
}

// FenceTx verifies the lease against the database clock while retaining the
// caller's transaction and row lock for an atomic dependent write.
func (s *PGOperationStore) FenceTx(
	ctx context.Context,
	tx pgx.Tx,
	lease OperationLease,
) (OperationLease, time.Time, error) {
	if s == nil || tx == nil {
		return OperationLease{}, time.Time{}, failure(CodeInvalidInput, nil)
	}
	current, databaseNow, err := lockAndFence(ctx, tx, lease)
	if err != nil {
		return OperationLease{}, time.Time{}, mapStoreError(err)
	}
	if err := lockLeaseCertificateOrderAuthority(ctx, tx, lease); err != nil {
		return OperationLease{}, time.Time{}, mapStoreError(err)
	}
	return current, databaseNow, nil
}

func lockAndFence(
	ctx context.Context,
	tx pgx.Tx,
	lease OperationLease,
) (OperationLease, time.Time, error) {
	var databaseNow time.Time
	var storedDigest []byte
	var storedSnapshot []byte
	if err := tx.QueryRow(ctx, `
		SELECT request_digest, request_snapshot, statement_timestamp()
		FROM acme_issuance_operations
		WHERE tenant_scope_id=$1 AND operation_id=$2 FOR UPDATE`,
		lease.ScopeID, lease.OperationID,
	).Scan(&storedDigest, &storedSnapshot, &databaseNow); err != nil {
		return OperationLease{}, time.Time{}, err
	}
	var storedRequest IssueRequest
	if err := json.Unmarshal(storedSnapshot, &storedRequest); err != nil ||
		!validFrozenIssueRequest(storedRequest) || issueRequestDigest(storedRequest) != "sha256:"+hex.EncodeToString(storedDigest) {
		return OperationLease{}, time.Time{}, failure(CodeOperationStoreFailed, err)
	}
	storedDigestString := "sha256:" + hex.EncodeToString(storedDigest)
	if lease.Digest != storedDigestString || !issueRequestsEqual(lease.Request, storedRequest) {
		return OperationLease{}, time.Time{}, failure(CodeLeaseLost, nil)
	}
	current, _, err := loadLatestOperation(
		ctx, tx, lease.TenantID, lease.ScopeID, lease.OperationID, storedRequest, storedDigestString,
	)
	if err != nil {
		return OperationLease{}, time.Time{}, err
	}
	if current.Revision != lease.Revision || current.Token != lease.Token ||
		current.State.Status != OperationActive || !current.ExpiresAt.After(databaseNow) {
		return OperationLease{}, time.Time{}, failure(CodeLeaseLost, nil)
	}
	return current, databaseNow.UTC(), nil
}

func loadLatestOperation(
	ctx context.Context,
	tx pgx.Tx,
	tenantID uuid.UUID,
	scopeID uuid.UUID,
	operationID string,
	request IssueRequest,
	digest string,
) (OperationLease, time.Time, error) {
	lease := OperationLease{
		TenantID: tenantID, ScopeID: scopeID, OperationID: operationID, Request: request, Digest: digest,
	}
	var token *uuid.UUID
	var leaseExpires, nextReconcile *time.Time
	var accountURI, orderURL, finalizeURL, certificateURL, failureCode *string
	var spkiDigest, fingerprint []byte
	err := tx.QueryRow(ctx, `
		SELECT revision, phase, status, order_intent_pending, lease_token, lease_expires_at, next_reconcile_at,
		       account_uri, order_url, finalize_url, authorization_urls, certificate_url,
		       certificate_spki_sha256, leaf_fingerprint_sha256, failure_code
		FROM acme_issuance_operation_events
		WHERE tenant_scope_id=$1 AND operation_id=$2
		ORDER BY revision DESC LIMIT 1`, scopeID, operationID,
	).Scan(
		&lease.Revision, &lease.State.Phase, &lease.State.Status, &lease.State.OrderIntentPending,
		&token, &leaseExpires, &nextReconcile,
		&accountURI, &orderURL, &finalizeURL, &lease.State.AuthorizationURLs, &certificateURL,
		&spkiDigest, &fingerprint, &failureCode,
	)
	if err != nil {
		return OperationLease{}, time.Time{}, err
	}
	if token != nil {
		lease.Token = *token
	}
	if leaseExpires != nil {
		lease.ExpiresAt = leaseExpires.UTC()
	}
	lease.State.AccountURI = stringValue(accountURI)
	lease.State.OrderURL = stringValue(orderURL)
	lease.State.FinalizeURL = stringValue(finalizeURL)
	lease.State.CertificateURL = stringValue(certificateURL)
	lease.State.FailureCode = ErrorCode(stringValue(failureCode))
	if len(spkiDigest) > 0 {
		lease.State.CertificateSPKIDigest = "sha256:" + hex.EncodeToString(spkiDigest)
	}
	if len(fingerprint) > 0 {
		lease.State.LeafFingerprint = "sha256:" + hex.EncodeToString(fingerprint)
	}
	if nextReconcile != nil {
		return lease, nextReconcile.UTC(), nil
	}
	return lease, time.Time{}, nil
}

func insertOperationEvent(
	ctx context.Context,
	tx pgx.Tx,
	lease OperationLease,
	eventType string,
	fenceToken uuid.UUID,
	now, nextReconcile time.Time,
) error {
	var token any
	var expires any
	if lease.Token != uuid.Nil {
		token = lease.Token
		expires = lease.ExpiresAt.UTC()
	}
	var retryAt any
	if !nextReconcile.IsZero() {
		retryAt = nextReconcile.UTC()
	}
	spki, err := decodeOptionalDigest(lease.State.CertificateSPKIDigest)
	if err != nil {
		return err
	}
	fingerprint, err := decodeOptionalDigest(lease.State.LeafFingerprint)
	if err != nil {
		return err
	}
	authorizationURLs := lease.State.AuthorizationURLs
	if authorizationURLs == nil {
		authorizationURLs = []string{}
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO acme_issuance_operation_events (
			tenant_scope_id, operation_id, revision, event_type, phase, status,
			fence_token, order_intent_pending, lease_token, lease_expires_at, next_reconcile_at, account_uri, order_url,
			finalize_url, authorization_urls, certificate_url, certificate_spki_sha256,
			leaf_fingerprint_sha256, failure_code, occurred_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NULLIF($12,''),NULLIF($13,''),
		          NULLIF($14,''),$15,NULLIF($16,''),$17,$18,NULLIF($19,''),$20)`,
		lease.ScopeID, lease.OperationID, lease.Revision, eventType, lease.State.Phase,
		lease.State.Status, fenceToken, lease.State.OrderIntentPending, token, expires, retryAt, lease.State.AccountURI,
		lease.State.OrderURL, lease.State.FinalizeURL, authorizationURLs,
		lease.State.CertificateURL, spki, fingerprint, lease.State.FailureCode, now.UTC(),
	)
	return err
}

func decodeDigest(value string) ([]byte, error) {
	if !strings.HasPrefix(value, "sha256:") {
		return nil, errors.New("invalid digest prefix")
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	if err != nil || len(decoded) != 32 {
		return nil, errors.New("invalid digest")
	}
	return decoded, nil
}

func decodeOptionalDigest(value string) ([]byte, error) {
	if value == "" {
		return nil, nil
	}
	return decodeDigest(value)
}

func requestDirectory(request IssueRequest) string {
	return request.DirectoryURL
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func cloneOperationState(value OperationState) OperationState {
	value.AuthorizationURLs = append([]string(nil), value.AuthorizationURLs...)
	return value
}

func phaseRank(value OperationPhase) int {
	switch value {
	case PhaseClaimed:
		return 1
	case PhaseOrdered:
		return 2
	case PhaseAuthorizing:
		return 3
	case PhaseReady:
		return 4
	case PhaseFinalizing:
		return 5
	case PhaseCertificateSaved:
		return 6
	case PhaseCompleted:
		return 7
	default:
		return 0
	}
}

func mapStoreError(err error) error {
	var workerError *Error
	if errors.As(err, &workerError) {
		return workerError
	}
	return failure(CodeOperationStoreFailed, err)
}
