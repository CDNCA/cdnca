package acmeedge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/edgestatus"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type storedPublication struct {
	Publication
	requestDigest []byte
}

type deploymentRecord struct {
	DeploymentState
	tenantScopeID uuid.UUID
	siteID        uuid.UUID
	revision      int64
	maxAttempts   int
}

type outboxStateRecord struct {
	outboxID          uuid.UUID
	deploymentID      uuid.UUID
	deploymentAttempt int
	status            string
	publishAttempts   int
	availableAt       time.Time
	leaseToken        *uuid.UUID
	leaseExpiresAt    *time.Time
}

const maximumOutboxPublishAttempts = 100

type terminalDeliveryBinding struct {
	tenantScopeID uuid.UUID
	siteID        uuid.UUID
	versionID     uuid.UUID
	nodeID        uuid.UUID
	publicationID uuid.UUID
	requestID     uuid.UUID
	revision      int64
	payloadSHA256 [32]byte
}

func lockOverlayState(
	ctx context.Context,
	tx pgx.Tx,
	tenantScopeID uuid.UUID,
	siteID uuid.UUID,
	now time.Time,
) (int64, error) {
	if _, err := tx.Exec(ctx, `
		INSERT INTO acme_http01_overlay_states(
			tenant_scope_id,site_id,current_revision,created_at,updated_at
		)
		SELECT site.scope_id,site.id,0,$3,$3
		FROM sites site
		JOIN access_scopes scope ON scope.id=site.scope_id AND scope.kind='tenant'
		WHERE site.scope_id=$1 AND site.id=$2 AND site.deleted_at IS NULL
		  AND site.enabled=true AND site.status='active'
		ON CONFLICT (tenant_scope_id,site_id) DO NOTHING`, tenantScopeID, siteID, now); err != nil {
		return 0, fmt.Errorf("%w: initialize overlay state", ErrPersistence)
	}
	var revision int64
	if err := tx.QueryRow(ctx, `
		SELECT current_revision
		FROM acme_http01_overlay_states
		WHERE tenant_scope_id=$1 AND site_id=$2
		FOR UPDATE`, tenantScopeID, siteID).Scan(&revision); errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrInvalidInput
	} else if err != nil {
		return 0, fmt.Errorf("%w: lock overlay state", ErrPersistence)
	}
	return revision, nil
}

func loadPublicationByKey(
	ctx context.Context,
	tx pgx.Tx,
	tenantScopeID uuid.UUID,
	siteID uuid.UUID,
	idempotencyKey string,
) (storedPublication, bool, error) {
	var stored storedPublication
	var snapshotDigest []byte
	err := tx.QueryRow(ctx, `
		SELECT publication.id,version.id,publication.mode,publication.tenant_scope_id,publication.site_id,
		       publication.revision,version.sealed_snapshot_sha256,publication.token_count,
		       publication.node_count,publication.created_at,publication.request_digest
		FROM acme_http01_overlay_publications publication
		JOIN acme_http01_overlay_versions version ON version.publication_id=publication.id
		WHERE publication.tenant_scope_id=$1 AND publication.site_id=$2
		  AND publication.idempotency_key=$3`, tenantScopeID, siteID, idempotencyKey).Scan(
		&stored.ID, &stored.VersionID, &stored.Mode, &stored.TenantScopeID, &stored.SiteID,
		&stored.Revision, &snapshotDigest, &stored.TokenCount, &stored.NodeCount,
		&stored.CreatedAt, &stored.requestDigest,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return storedPublication{}, false, nil
	}
	if err != nil || len(snapshotDigest) != sha256.Size || len(stored.requestDigest) != sha256.Size {
		return storedPublication{}, false, fmt.Errorf("%w: read idempotent publication", ErrPersistence)
	}
	copy(stored.SealedSnapshotSHA256[:], snapshotDigest)
	return stored, true, nil
}

func loadChallengeSecrets(
	ctx context.Context,
	tx pgx.Tx,
	tenantScopeID uuid.UUID,
	siteID uuid.UUID,
	references []ChallengeReference,
) ([]challengeSecret, error) {
	result := make([]challengeSecret, 0, len(references))
	for _, reference := range references {
		var secret challengeSecret
		secret.Reference = reference
		err := tx.QueryRow(ctx, `
			SELECT attempt.identifier,attempt.token,attempt.exact_value
			FROM acme_issuance_challenge_attempts attempt
			JOIN sites site ON site.scope_id=attempt.tenant_scope_id
			  AND site.id=$4 AND site.domain=attempt.identifier
			JOIN LATERAL (
				SELECT event.state
				FROM acme_issuance_challenge_events event
				WHERE event.tenant_scope_id=attempt.tenant_scope_id
				  AND event.operation_id=attempt.operation_id
				  AND event.attempt_id=attempt.attempt_id
				ORDER BY event.revision DESC
				LIMIT 1
			) latest ON latest.state IN ('intent','published')
			WHERE attempt.tenant_scope_id=$1 AND attempt.operation_id=$2
			  AND attempt.attempt_id=$3 AND attempt.challenge_type='http-01'
			  AND attempt.wildcard=false`, tenantScopeID, reference.OperationID, reference.AttemptID, siteID).Scan(
			&secret.Domain, &secret.Token, &secret.Value,
		)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrChallengeIneligible
		}
		if err != nil {
			return nil, fmt.Errorf("%w: read challenge reference", ErrPersistence)
		}
		result = append(result, secret)
	}
	return result, nil
}

func validateEligibleNodes(ctx context.Context, tx pgx.Tx, tenantScopeID uuid.UUID, nodes []uuid.UUID) error {
	var count int
	if err := tx.QueryRow(ctx, `
		SELECT count(*)
		FROM nodes
		WHERE id=ANY($2::uuid[]) AND admin_state='active' AND tenant_carries_node_287($1,id)`, tenantScopeID, nodes).Scan(&count); err != nil {
		return fmt.Errorf("%w: validate overlay targets", ErrPersistence)
	}
	if count != len(nodes) {
		return ErrTargetIneligible
	}
	return nil
}

func validateApplySite(ctx context.Context, tx pgx.Tx, tenantScopeID, siteID uuid.UUID) error {
	var eligible bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM sites
			WHERE scope_id=$1 AND id=$2 AND deleted_at IS NULL
			  AND enabled=true AND status='active' AND '80'=ANY(http_ports)
		)`, tenantScopeID, siteID).Scan(&eligible); err != nil {
		return fmt.Errorf("%w: validate HTTP-01 site", ErrPersistence)
	}
	if !eligible {
		return ErrChallengeIneligible
	}
	return nil
}

func loadCurrentOverlaySnapshot(
	ctx context.Context,
	tx pgx.Tx,
	tenantScopeID uuid.UUID,
	siteID uuid.UUID,
	revision int64,
) ([]ChallengeReference, []uuid.UUID, error) {
	var versionID uuid.UUID
	if err := tx.QueryRow(ctx, `
		SELECT id FROM acme_http01_overlay_versions
		WHERE tenant_scope_id=$1 AND site_id=$2 AND revision=$3`, tenantScopeID, siteID, revision).Scan(&versionID); errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, ErrRevisionConflict
	} else if err != nil {
		return nil, nil, fmt.Errorf("%w: read current overlay version", ErrPersistence)
	}
	tokenRows, err := tx.Query(ctx, `
		SELECT operation_id,challenge_attempt_id
		FROM acme_http01_overlay_token_facts
		WHERE version_id=$1 ORDER BY operation_id,challenge_attempt_id`, versionID)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: read current overlay tokens", ErrPersistence)
	}
	var challenges []ChallengeReference
	for tokenRows.Next() {
		var reference ChallengeReference
		if err := tokenRows.Scan(&reference.OperationID, &reference.AttemptID); err != nil {
			tokenRows.Close()
			return nil, nil, fmt.Errorf("%w: scan current overlay token", ErrPersistence)
		}
		challenges = append(challenges, reference)
	}
	if err := tokenRows.Err(); err != nil {
		tokenRows.Close()
		return nil, nil, fmt.Errorf("%w: iterate current overlay tokens", ErrPersistence)
	}
	tokenRows.Close()
	targetRows, err := tx.Query(ctx, `
		SELECT node_id FROM acme_http01_overlay_targets
		WHERE version_id=$1 ORDER BY node_id`, versionID)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: read current overlay targets", ErrPersistence)
	}
	defer targetRows.Close()
	var nodes []uuid.UUID
	for targetRows.Next() {
		var nodeID uuid.UUID
		if err := targetRows.Scan(&nodeID); err != nil {
			return nil, nil, fmt.Errorf("%w: scan current overlay target", ErrPersistence)
		}
		nodes = append(nodes, nodeID)
	}
	if err := targetRows.Err(); err != nil {
		return nil, nil, fmt.Errorf("%w: iterate current overlay targets", ErrPersistence)
	}
	if len(nodes) == 0 {
		return nil, nil, fmt.Errorf("%w: current overlay has no targets", ErrPersistence)
	}
	return challenges, nodes, nil
}

func insertPublicationChain(
	ctx context.Context,
	tx pgx.Tx,
	publication Publication,
	request normalizedPublishRequest,
	requestDigest [32]byte,
	tokens []SealedToken,
	nodes []uuid.UUID,
	subjectPrefix string,
) error {
	if _, err := tx.Exec(ctx, `
		INSERT INTO acme_http01_overlay_publications(
			id,mode,tenant_scope_id,site_id,expected_revision,revision,idempotency_key,
			request_digest,request_id,token_count,node_count,max_attempts,deadline_at,created_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		publication.ID, publication.Mode, publication.TenantScopeID, publication.SiteID, request.ExpectedRevision,
		publication.Revision, request.IdempotencyKey, requestDigest[:], request.RequestUUID,
		publication.TokenCount, publication.NodeCount, request.MaxAttempts, request.Deadline, publication.CreatedAt,
	); err != nil {
		return mapPublicationInsertError(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO acme_http01_overlay_versions(
			id,publication_id,tenant_scope_id,site_id,revision,sealed_snapshot_sha256,created_at
		) VALUES($1,$2,$3,$4,$5,$6,$7)`, publication.VersionID, publication.ID,
		publication.TenantScopeID, publication.SiteID, publication.Revision,
		publication.SealedSnapshotSHA256[:], publication.CreatedAt); err != nil {
		return fmt.Errorf("%w: insert overlay version", ErrPersistence)
	}
	for _, token := range tokens {
		if _, err := tx.Exec(ctx, `
			INSERT INTO acme_http01_overlay_token_facts(
				version_id,tenant_scope_id,site_id,revision,ordinal,operation_id,
				challenge_attempt_id,domain,token_sha256,value_sha256,key_id,nonce,
				ciphertext,aad_sha256,created_at
			) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
			publication.VersionID, publication.TenantScopeID, publication.SiteID, publication.Revision,
			token.Ordinal, token.OperationID, token.ChallengeAttemptID, token.Domain,
			token.TokenSHA256[:], token.ValueSHA256[:], token.KeyID, token.Nonce,
			token.Ciphertext, token.AADSHA256[:], publication.CreatedAt,
		); err != nil {
			return fmt.Errorf("%w: insert sealed token fact", ErrPersistence)
		}
	}
	for index, nodeID := range nodes {
		if _, err := tx.Exec(ctx, `
			INSERT INTO acme_http01_overlay_targets(
				version_id,tenant_scope_id,site_id,revision,ordinal,node_id,created_at
			) VALUES($1,$2,$3,$4,$5,$6,$7)`, publication.VersionID, publication.TenantScopeID,
			publication.SiteID, publication.Revision, index+1, nodeID, publication.CreatedAt); err != nil {
			return fmt.Errorf("%w: insert overlay target", ErrPersistence)
		}
		deploymentID := uuid.NewSHA1(publication.VersionID, append([]byte("deployment/"), nodeID[:]...))
		if _, err := tx.Exec(ctx, `
			INSERT INTO acme_http01_overlay_deployments(
				id,attempt,version_id,tenant_scope_id,site_id,revision,node_id,retry_request_id,
				deadline_at,max_attempts,created_at
			) VALUES($1,1,$2,$3,$4,$5,$6,NULL,$7,$8,$9)`, deploymentID, publication.VersionID,
			publication.TenantScopeID, publication.SiteID, publication.Revision, nodeID,
			request.Deadline, request.MaxAttempts, publication.CreatedAt); err != nil {
			return fmt.Errorf("%w: insert overlay deployment", ErrPersistence)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO acme_http01_overlay_deployment_events(
				deployment_id,deployment_attempt,sequence,state,occurred_at
			) VALUES($1,1,1,'queued',$2)`, deploymentID, publication.CreatedAt); err != nil {
			return fmt.Errorf("%w: queue overlay deployment", ErrPersistence)
		}
		outboxID := overlayOutboxID(deploymentID, 1)
		payloadDigest, err := deliveryPayloadDigest(publication, deploymentID, 1, nodeID, tokens)
		if err != nil {
			return ErrInvalidInput
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO acme_http01_overlay_outbox(
				id,deployment_id,deployment_attempt,version_id,node_id,subject,payload_sha256,created_at
			) VALUES($1,$2,1,$3,$4,$5,$6,$7)`, outboxID, deploymentID, publication.VersionID,
			nodeID, subjectPrefix+"."+nodeID.String(), payloadDigest[:], publication.CreatedAt); err != nil {
			return fmt.Errorf("%w: insert overlay outbox", ErrPersistence)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO acme_http01_overlay_outbox_states(
				outbox_id,status,publish_attempts,available_at,updated_at
			) VALUES($1,'pending',0,$2,$2)`, outboxID, publication.CreatedAt); err != nil {
			return fmt.Errorf("%w: initialize overlay outbox", ErrPersistence)
		}
	}
	result, err := tx.Exec(ctx, `
		UPDATE acme_http01_overlay_states
		SET current_revision=$3,updated_at=$4
		WHERE tenant_scope_id=$1 AND site_id=$2 AND current_revision=$5`, publication.TenantScopeID,
		publication.SiteID, publication.Revision, publication.CreatedAt, request.ExpectedRevision)
	if err != nil || result.RowsAffected() != 1 {
		return ErrRevisionConflict
	}
	return nil
}

func mapPublicationInsertError(err error) error {
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) {
		switch postgresError.Code {
		case "23505":
			return ErrIdempotencyConflict
		case "P0001":
			return ErrRevisionConflict
		}
	}
	return fmt.Errorf("%w: insert overlay publication", ErrPersistence)
}

func deliveryPayloadDigest(
	publication Publication,
	deploymentID uuid.UUID,
	deploymentAttempt int,
	nodeID uuid.UUID,
	tokens []SealedToken,
) ([32]byte, error) {
	document := struct {
		Schema            string        `json:"schema"`
		Mode              string        `json:"mode"`
		TenantScopeID     uuid.UUID     `json:"tenant_scope_id"`
		SiteID            uuid.UUID     `json:"site_id"`
		Revision          int64         `json:"revision"`
		VersionID         uuid.UUID     `json:"version_id"`
		DeploymentID      uuid.UUID     `json:"deployment_id"`
		DeploymentAttempt int           `json:"deployment_attempt"`
		NodeID            uuid.UUID     `json:"node_id"`
		Tokens            []SealedToken `json:"tokens"`
	}{
		Schema: "cdnca.acme.http01-overlay-delivery/v1", Mode: publication.Mode, TenantScopeID: publication.TenantScopeID,
		SiteID: publication.SiteID, Revision: publication.Revision, VersionID: publication.VersionID,
		DeploymentID: deploymentID, DeploymentAttempt: deploymentAttempt, NodeID: nodeID, Tokens: tokens,
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func overlayOutboxID(deploymentID uuid.UUID, attempt int) uuid.UUID {
	return uuid.NewSHA1(deploymentID, []byte(fmt.Sprintf("outbox/%d", attempt)))
}

func (s *Service) ClaimDeliveries(ctx context.Context, request ClaimRequest) ([]SealedDelivery, error) {
	if ctx == nil || request.Limit < 1 || request.Limit > 1000 ||
		request.LeaseDuration < time.Second || request.LeaseDuration > 5*time.Minute {
		return nil, ErrInvalidInput
	}
	now := s.clock().UTC().Truncate(time.Microsecond)
	var deliveries []SealedDelivery
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := expireDeliveryClaims(ctx, tx, now, request.Limit, s.retryDelay); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `
			SELECT state.outbox_id
			FROM acme_http01_overlay_outbox_states state
			JOIN acme_http01_overlay_outbox outbox ON outbox.id=state.outbox_id
			JOIN LATERAL (
				SELECT event.state
				FROM acme_http01_overlay_deployment_events event
				WHERE event.deployment_id=outbox.deployment_id
				  AND event.deployment_attempt=outbox.deployment_attempt
				ORDER BY event.sequence DESC LIMIT 1
			) latest ON latest.state IN ('queued','retry_queued')
			WHERE state.status IN ('pending','retry') AND state.available_at <= $1
			ORDER BY state.available_at,state.outbox_id
			FOR UPDATE OF state SKIP LOCKED
			LIMIT $2`, now, request.Limit)
		if err != nil {
			return fmt.Errorf("%w: claim overlay deliveries", ErrPersistence)
		}
		var outboxIDs []uuid.UUID
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return fmt.Errorf("%w: scan overlay delivery claim", ErrPersistence)
			}
			outboxIDs = append(outboxIDs, id)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("%w: iterate overlay delivery claims", ErrPersistence)
		}
		rows.Close()
		for _, outboxID := range outboxIDs {
			leaseToken := uuid.New()
			leaseExpiresAt := now.Add(request.LeaseDuration)
			var publishAttempt int
			if err := tx.QueryRow(ctx, `
				UPDATE acme_http01_overlay_outbox_states
				SET status='claimed',publish_attempts=publish_attempts+1,
				    lease_token=$2,lease_expires_at=$3,last_failure_code=NULL,updated_at=$4
				WHERE outbox_id=$1
				RETURNING publish_attempts`, outboxID, leaseToken, leaseExpiresAt, now).Scan(&publishAttempt); err != nil {
				return fmt.Errorf("%w: fence overlay delivery", ErrPersistence)
			}
			sequence, err := nextOutboxAttemptSequence(ctx, tx, outboxID)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO acme_http01_overlay_outbox_attempts(
					outbox_id,sequence,publish_attempt,event_type,lease_token,occurred_at
				) VALUES($1,$2,$3,'claimed',$4,$5)`, outboxID, sequence, publishAttempt, leaseToken, now); err != nil {
				return fmt.Errorf("%w: append overlay delivery claim", ErrPersistence)
			}
			delivery, err := loadSealedDelivery(ctx, tx, outboxID, leaseToken, leaseExpiresAt, publishAttempt)
			if err != nil {
				return err
			}
			deliveries = append(deliveries, delivery)
		}
		return nil
	})
	return deliveries, err
}

func expireDeliveryClaims(
	ctx context.Context,
	tx pgx.Tx,
	now time.Time,
	limit int,
	retryDelay time.Duration,
) error {
	rows, err := tx.Query(ctx, `
		SELECT outbox_id,publish_attempts,lease_token
		FROM acme_http01_overlay_outbox_states
		WHERE status='claimed' AND lease_expires_at <= $1
		ORDER BY lease_expires_at,outbox_id
		FOR UPDATE SKIP LOCKED
		LIMIT $2`, now, limit)
	if err != nil {
		return fmt.Errorf("%w: read expired overlay claims", ErrPersistence)
	}
	type expiredClaim struct {
		id      uuid.UUID
		attempt int
		lease   uuid.UUID
	}
	var expired []expiredClaim
	for rows.Next() {
		var claim expiredClaim
		if err := rows.Scan(&claim.id, &claim.attempt, &claim.lease); err != nil {
			rows.Close()
			return fmt.Errorf("%w: scan expired overlay claim", ErrPersistence)
		}
		expired = append(expired, claim)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("%w: iterate expired overlay claims", ErrPersistence)
	}
	rows.Close()
	for _, claim := range expired {
		sequence, err := nextOutboxAttemptSequence(ctx, tx, claim.id)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO acme_http01_overlay_outbox_attempts(
				outbox_id,sequence,publish_attempt,event_type,lease_token,failure_code,occurred_at
			) VALUES($1,$2,$3,'retry',$4,'lease_expired',$5)`, claim.id, sequence,
			claim.attempt, claim.lease, now); err != nil {
			return fmt.Errorf("%w: append expired overlay claim", ErrPersistence)
		}
		if _, err := tx.Exec(ctx, `
			UPDATE acme_http01_overlay_outbox_states
			SET status='retry',lease_token=NULL,lease_expires_at=NULL,
			    available_at=$2,last_failure_code='lease_expired',updated_at=$3
			WHERE outbox_id=$1`, claim.id, now.Add(retryDelay), now); err != nil {
			return fmt.Errorf("%w: retry expired overlay claim", ErrPersistence)
		}
	}
	return nil
}

func nextOutboxAttemptSequence(ctx context.Context, tx pgx.Tx, outboxID uuid.UUID) (int64, error) {
	var sequence int64
	if err := tx.QueryRow(ctx, `
		SELECT COALESCE(max(sequence),0)+1
		FROM acme_http01_overlay_outbox_attempts
		WHERE outbox_id=$1`, outboxID).Scan(&sequence); err != nil {
		return 0, fmt.Errorf("%w: read overlay outbox sequence", ErrPersistence)
	}
	return sequence, nil
}

func loadSealedDelivery(
	ctx context.Context,
	tx pgx.Tx,
	outboxID uuid.UUID,
	leaseToken uuid.UUID,
	leaseExpiresAt time.Time,
	publishAttempt int,
) (SealedDelivery, error) {
	var delivery SealedDelivery
	var payloadDigest []byte
	err := tx.QueryRow(ctx, `
		SELECT outbox.id,publication.mode,outbox.deployment_id,outbox.deployment_attempt,
		       version.tenant_scope_id,version.site_id,version.revision,version.id,
		       outbox.node_id,outbox.subject,outbox.payload_sha256
		FROM acme_http01_overlay_outbox outbox
		JOIN acme_http01_overlay_versions version ON version.id=outbox.version_id
		JOIN acme_http01_overlay_publications publication ON publication.id=version.publication_id
		WHERE outbox.id=$1`, outboxID).Scan(
		&delivery.OutboxID, &delivery.Mode, &delivery.DeploymentID, &delivery.DeploymentAttempt,
		&delivery.TenantScopeID, &delivery.SiteID, &delivery.DomainRevision, &delivery.VersionID,
		&delivery.NodeID, &delivery.Subject, &payloadDigest,
	)
	if err != nil || len(payloadDigest) != sha256.Size {
		return SealedDelivery{}, fmt.Errorf("%w: load overlay delivery", ErrPersistence)
	}
	delivery.LeaseToken = leaseToken
	delivery.LeaseExpiresAt = leaseExpiresAt
	delivery.PublishAttempt = publishAttempt
	copy(delivery.PayloadSHA256[:], payloadDigest)
	tokens, err := loadVersionTokens(ctx, tx, delivery.VersionID)
	if err != nil {
		return SealedDelivery{}, err
	}
	delivery.Tokens = tokens
	return delivery, nil
}

func loadVersionTokens(ctx context.Context, tx pgx.Tx, versionID uuid.UUID) ([]SealedToken, error) {
	rows, err := tx.Query(ctx, `
		SELECT ordinal,operation_id,challenge_attempt_id,domain,token_sha256,value_sha256,
		       key_id,nonce,ciphertext,aad_sha256
		FROM acme_http01_overlay_token_facts
		WHERE version_id=$1 ORDER BY ordinal`, versionID)
	if err != nil {
		return nil, fmt.Errorf("%w: read sealed overlay tokens", ErrPersistence)
	}
	defer rows.Close()
	var tokens []SealedToken
	for rows.Next() {
		var token SealedToken
		var tokenDigest, valueDigest, aadDigest []byte
		if err := rows.Scan(&token.Ordinal, &token.OperationID, &token.ChallengeAttemptID,
			&token.Domain, &tokenDigest, &valueDigest, &token.KeyID, &token.Nonce,
			&token.Ciphertext, &aadDigest); err != nil {
			return nil, fmt.Errorf("%w: scan sealed overlay token", ErrPersistence)
		}
		if len(tokenDigest) != sha256.Size || len(valueDigest) != sha256.Size || len(aadDigest) != sha256.Size {
			return nil, fmt.Errorf("%w: invalid sealed overlay digest", ErrPersistence)
		}
		copy(token.TokenSHA256[:], tokenDigest)
		copy(token.ValueSHA256[:], valueDigest)
		copy(token.AADSHA256[:], aadDigest)
		token.Nonce = slices.Clone(token.Nonce)
		token.Ciphertext = slices.Clone(token.Ciphertext)
		tokens = append(tokens, token)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: iterate sealed overlay tokens", ErrPersistence)
	}
	return tokens, nil
}

func (s *Service) CompleteDelivery(ctx context.Context, request CompleteDeliveryRequest) error {
	if ctx == nil || request.OutboxID == uuid.Nil || request.LeaseToken == uuid.Nil ||
		(request.Published && (request.Retryable || request.FailureCode != "" || request.RetryAfter != 0)) ||
		(!request.Published && (!failureCodePattern.MatchString(request.FailureCode) || request.RetryAfter < 0 ||
			request.RetryAfter > time.Hour)) {
		return ErrInvalidInput
	}
	now := s.clock().UTC().Truncate(time.Microsecond)
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		state, err := lockOutboxState(ctx, tx, request.OutboxID)
		if err != nil {
			return err
		}
		if state.status != "claimed" || state.leaseToken == nil || *state.leaseToken != request.LeaseToken ||
			state.leaseExpiresAt == nil || !state.leaseExpiresAt.After(now) {
			matched, err := completedDeliveryMatches(ctx, tx, request, state, s.retryDelay)
			if err != nil {
				return err
			}
			if matched {
				return nil
			}
			return ErrClaimLost
		}
		sequence, err := nextOutboxAttemptSequence(ctx, tx, request.OutboxID)
		if err != nil {
			return err
		}
		if request.Published {
			if _, err := tx.Exec(ctx, `
				INSERT INTO acme_http01_overlay_outbox_attempts(
					outbox_id,sequence,publish_attempt,event_type,lease_token,occurred_at
				) VALUES($1,$2,$3,'published',$4,$5)`, request.OutboxID, sequence,
				state.publishAttempts, request.LeaseToken, now); err != nil {
				return fmt.Errorf("%w: append overlay publish result", ErrPersistence)
			}
			if _, err := tx.Exec(ctx, `
				UPDATE acme_http01_overlay_outbox_states
				SET status='published',lease_token=NULL,lease_expires_at=NULL,
				    last_failure_code=NULL,updated_at=$2
				WHERE outbox_id=$1`, request.OutboxID, now); err != nil {
				return fmt.Errorf("%w: complete overlay delivery", ErrPersistence)
			}
			_, err = appendDeploymentEvent(ctx, tx, state.deploymentID, state.deploymentAttempt,
				DeploymentDispatched, uuid.Nil, [32]byte{}, "", now)
			return err
		}

		terminal := !request.Retryable || state.publishAttempts >= maximumOutboxPublishAttempts
		eventType := "exhausted"
		status := "exhausted"
		availableAt := now
		if !terminal {
			eventType = "retry"
			status = "retry"
			delay := request.RetryAfter
			if delay == 0 {
				delay = s.retryDelay
			}
			availableAt = now.Add(delay)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO acme_http01_overlay_outbox_attempts(
				outbox_id,sequence,publish_attempt,event_type,lease_token,failure_code,occurred_at
			) VALUES($1,$2,$3,$4,$5,$6,$7)`, request.OutboxID, sequence,
			state.publishAttempts, eventType, request.LeaseToken, request.FailureCode, now); err != nil {
			return fmt.Errorf("%w: append overlay delivery failure", ErrPersistence)
		}
		if _, err := tx.Exec(ctx, `
			UPDATE acme_http01_overlay_outbox_states
			SET status=$2,lease_token=NULL,lease_expires_at=NULL,available_at=$3,
			    last_failure_code=$4,updated_at=$5
			WHERE outbox_id=$1`, request.OutboxID, status, availableAt, request.FailureCode, now); err != nil {
			return fmt.Errorf("%w: fail overlay delivery", ErrPersistence)
		}
		if terminal {
			if err := s.recordTerminalDeliveryFailure(ctx, tx, state, request, now); err != nil {
				return err
			}
		}
		return nil
	})
}

func lockOutboxState(ctx context.Context, tx pgx.Tx, outboxID uuid.UUID) (outboxStateRecord, error) {
	var state outboxStateRecord
	err := tx.QueryRow(ctx, `
		SELECT state.outbox_id,outbox.deployment_id,outbox.deployment_attempt,
		       state.status,state.publish_attempts,state.available_at,state.lease_token,state.lease_expires_at
		FROM acme_http01_overlay_outbox_states state
		JOIN acme_http01_overlay_outbox outbox ON outbox.id=state.outbox_id
		WHERE state.outbox_id=$1 FOR UPDATE OF state`, outboxID).Scan(
		&state.outboxID, &state.deploymentID, &state.deploymentAttempt, &state.status,
		&state.publishAttempts, &state.availableAt, &state.leaseToken, &state.leaseExpiresAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return outboxStateRecord{}, ErrNotFound
	}
	if err != nil {
		return outboxStateRecord{}, fmt.Errorf("%w: lock overlay outbox", ErrPersistence)
	}
	return state, nil
}

func completedDeliveryMatches(
	ctx context.Context,
	tx pgx.Tx,
	request CompleteDeliveryRequest,
	state outboxStateRecord,
	defaultRetryDelay time.Duration,
) (bool, error) {
	var eventType, failureCode string
	var occurredAt time.Time
	err := tx.QueryRow(ctx, `
		SELECT event_type,COALESCE(failure_code,''),occurred_at
		FROM acme_http01_overlay_outbox_attempts
		WHERE outbox_id=$1 AND lease_token=$2 AND event_type <> 'claimed'
		ORDER BY sequence DESC LIMIT 1`, request.OutboxID, request.LeaseToken).Scan(&eventType, &failureCode, &occurredAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("%w: read overlay delivery result", ErrPersistence)
	}
	expectedType := "exhausted"
	if request.Published {
		expectedType = "published"
	} else if request.Retryable && state.publishAttempts < maximumOutboxPublishAttempts {
		expectedType = "retry"
	}
	if eventType != expectedType || failureCode != request.FailureCode {
		return false, nil
	}
	if expectedType == "retry" && !completedDeliveryRetryAfterMatches(
		occurredAt, state.availableAt, request.RetryAfter, defaultRetryDelay,
	) {
		return false, nil
	}
	if expectedType != "exhausted" {
		return true, nil
	}
	receiptID := terminalDeliveryReceiptID(request.OutboxID, request.FailureCode)
	var recordedFailure string
	err = tx.QueryRow(ctx, `
		SELECT failure_code FROM acme_http01_overlay_deployment_events
		WHERE receipt_id=$1 AND state='failed'`, receiptID).Scan(&recordedFailure)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("%w: read terminal overlay delivery receipt", ErrPersistence)
	}
	return recordedFailure == request.FailureCode, nil
}

func completedDeliveryRetryAfterMatches(
	occurredAt time.Time,
	availableAt time.Time,
	requested time.Duration,
	defaultRetryDelay time.Duration,
) bool {
	if requested < 0 || defaultRetryDelay < 0 {
		return false
	}
	effectiveDelay := requested
	if effectiveDelay == 0 {
		effectiveDelay = defaultRetryDelay
	}
	expectedAvailableAt := occurredAt.UTC().Truncate(time.Microsecond).Add(effectiveDelay).Truncate(time.Microsecond)
	return expectedAvailableAt.Equal(availableAt.UTC().Truncate(time.Microsecond))
}

func (s *Service) recordTerminalDeliveryFailure(
	ctx context.Context,
	tx pgx.Tx,
	state outboxStateRecord,
	request CompleteDeliveryRequest,
	now time.Time,
) error {
	binding, err := loadTerminalDeliveryBinding(ctx, tx, state)
	if err != nil {
		return err
	}
	receiptID := terminalDeliveryReceiptID(request.OutboxID, request.FailureCode)
	digest, err := terminalDeliveryReceiptDigest(state, binding, receiptID, request.FailureCode, now)
	if err != nil {
		return ErrInvalidInput
	}
	if _, err := appendDeploymentEvent(ctx, tx, state.deploymentID, state.deploymentAttempt,
		DeploymentFailed, receiptID, digest, request.FailureCode, now); err != nil {
		return err
	}
	return s.auditor.Append(ctx, tx, audit.Event{
		ScopeID: binding.tenantScopeID, ActorUserID: nil,
		Action: "acme_http01_overlay.delivery_failed", ResourceType: "acme_http01_overlay_deployment",
		ResourceID: state.deploymentID.String(), RequestID: receiptID.String(), Result: "failure",
		Payload: map[string]any{
			"attempt": state.deploymentAttempt, "site_id": binding.siteID.String(),
			"revision": binding.revision, "version_id": binding.versionID.String(),
			"node_id": binding.nodeID.String(), "failure_code": request.FailureCode,
			"outbox_id": request.OutboxID.String(),
		},
	})
}

func loadTerminalDeliveryBinding(ctx context.Context, tx pgx.Tx, state outboxStateRecord) (terminalDeliveryBinding, error) {
	var binding terminalDeliveryBinding
	var payloadDigest []byte
	err := tx.QueryRow(ctx, `
		SELECT deployment.tenant_scope_id,deployment.site_id,deployment.version_id,
		       deployment.node_id,deployment.revision,publication.id,publication.request_id,
		       outbox.payload_sha256
		FROM acme_http01_overlay_outbox outbox
		JOIN acme_http01_overlay_deployments deployment
		  ON deployment.id=outbox.deployment_id AND deployment.attempt=outbox.deployment_attempt
		JOIN acme_http01_overlay_versions version ON version.id=deployment.version_id
		JOIN acme_http01_overlay_publications publication ON publication.id=version.publication_id
		WHERE outbox.id=$1 AND deployment.id=$2 AND deployment.attempt=$3`,
		state.outboxID, state.deploymentID, state.deploymentAttempt).Scan(
		&binding.tenantScopeID, &binding.siteID, &binding.versionID, &binding.nodeID,
		&binding.revision, &binding.publicationID, &binding.requestID, &payloadDigest,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return terminalDeliveryBinding{}, ErrNotFound
	}
	if err != nil || len(payloadDigest) != sha256.Size {
		return terminalDeliveryBinding{}, fmt.Errorf("%w: read terminal overlay delivery binding", ErrPersistence)
	}
	copy(binding.payloadSHA256[:], payloadDigest)
	return binding, nil
}

func terminalDeliveryReceiptID(outboxID uuid.UUID, failureCode string) uuid.UUID {
	return uuid.NewSHA1(outboxID, []byte("terminal-failure/"+failureCode))
}

func terminalDeliveryReceiptDigest(
	state outboxStateRecord,
	binding terminalDeliveryBinding,
	receiptID uuid.UUID,
	failureCode string,
	occurredAt time.Time,
) ([32]byte, error) {
	commandEventID := uuid.NewSHA1(state.deploymentID, []byte(fmt.Sprintf("acme-http01-overlay/command/%d", state.deploymentAttempt)))
	artifactID := uuid.NewSHA1(binding.versionID, []byte("acme-http01-overlay/artifact"))
	encoded, err := json.Marshal(struct {
		Schema            string     `json:"schema"`
		ReceiptID         uuid.UUID  `json:"receipt_id"`
		OutboxID          uuid.UUID  `json:"outbox_id"`
		DeploymentID      uuid.UUID  `json:"deployment_id"`
		DeploymentAttempt int        `json:"deployment_attempt"`
		VersionID         uuid.UUID  `json:"version_id"`
		Revision          int64      `json:"revision"`
		NodeID            uuid.UUID  `json:"node_id"`
		PublicationID     uuid.UUID  `json:"publication_id"`
		RequestID         uuid.UUID  `json:"request_id"`
		CommandEventID    uuid.UUID  `json:"command_event_id"`
		ArtifactID        uuid.UUID  `json:"artifact_id"`
		CausationID       uuid.UUID  `json:"causation_id"`
		TaskID            *uuid.UUID `json:"task_id"`
		PayloadSHA256     [32]byte   `json:"payload_sha256"`
		FailureCode       string     `json:"failure_code"`
		OccurredAt        time.Time  `json:"occurred_at"`
	}{
		Schema: "cdnca.acme.http01-overlay-terminal-receipt/v1", ReceiptID: receiptID,
		OutboxID: state.outboxID, DeploymentID: state.deploymentID,
		DeploymentAttempt: state.deploymentAttempt, VersionID: binding.versionID,
		Revision: binding.revision, NodeID: binding.nodeID, PublicationID: binding.publicationID,
		RequestID: binding.requestID, CommandEventID: commandEventID, ArtifactID: artifactID,
		CausationID: commandEventID, TaskID: nil, PayloadSHA256: binding.payloadSHA256,
		FailureCode: failureCode, OccurredAt: occurredAt,
	})
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func (s *Service) RecordReceipt(ctx context.Context, receipt Receipt) (DeploymentState, error) {
	if ctx == nil {
		return DeploymentState{}, ErrInvalidInput
	}
	var state DeploymentState
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		state, err = s.RecordReceiptTx(ctx, tx, receipt)
		return err
	})
	return state, err
}

func (s *Service) RecordReceiptTx(ctx context.Context, tx pgx.Tx, receipt Receipt) (DeploymentState, error) {
	if ctx == nil || tx == nil || receipt.DeploymentID == uuid.Nil || receipt.DeploymentAttempt < 1 ||
		receipt.ReceiptID == uuid.Nil || (receipt.State != DeploymentApplied && receipt.State != DeploymentHealthy &&
		receipt.State != DeploymentFailed) ||
		(receipt.State == DeploymentFailed) != failureCodePattern.MatchString(receipt.FailureCode) {
		return DeploymentState{}, ErrInvalidInput
	}
	now := s.clock().UTC().Truncate(time.Microsecond)
	if receipt.OccurredAt.IsZero() {
		receipt.OccurredAt = now
	} else {
		receipt.OccurredAt = receipt.OccurredAt.UTC().Truncate(time.Microsecond)
	}
	if receipt.OccurredAt.After(now.Add(time.Minute)) || receipt.OccurredAt.Before(now.Add(-24*time.Hour)) {
		return DeploymentState{}, ErrInvalidInput
	}
	digest, err := receiptDigest(receipt)
	if err != nil {
		return DeploymentState{}, ErrInvalidInput
	}
	if existing, found, err := loadReceipt(ctx, tx, receipt.ReceiptID); err != nil {
		return DeploymentState{}, err
	} else if found {
		if !bytes.Equal(existing.digest, digest[:]) {
			return DeploymentState{}, ErrReceiptConflict
		}
		existing.DeploymentState.Replayed = true
		return existing.DeploymentState, nil
	}
	record, err := lockLatestDeployment(ctx, tx, receipt.DeploymentID)
	if err != nil {
		return DeploymentState{}, err
	}
	if record.DeploymentAttempt != receipt.DeploymentAttempt {
		return DeploymentState{}, ErrStaleAttempt
	}
	state, err := appendDeploymentEvent(ctx, tx, receipt.DeploymentID, receipt.DeploymentAttempt,
		receipt.State, receipt.ReceiptID, digest, receipt.FailureCode, receipt.OccurredAt)
	if err != nil {
		return DeploymentState{}, err
	}
	if receipt.State == DeploymentHealthy {
		if err := advanceHealthyProjection(ctx, tx, record.tenantScopeID, record.siteID, record.revision, now); err != nil {
			return DeploymentState{}, err
		}
	}
	if err := s.auditor.Append(ctx, tx, audit.Event{
		ScopeID: record.tenantScopeID, ActorUserID: nil,
		Action: "acme_http01_overlay.receipt", ResourceType: "acme_http01_overlay_deployment",
		ResourceID: receipt.DeploymentID.String(), RequestID: receipt.ReceiptID.String(), Result: "success",
		Payload: map[string]any{
			"attempt": receipt.DeploymentAttempt, "state": receipt.State,
			"site_id": record.siteID.String(), "revision": record.revision,
			"node_id": record.NodeID.String(), "failure_code": receipt.FailureCode,
		},
	}); err != nil {
		return DeploymentState{}, err
	}
	return state, nil
}

type storedReceipt struct {
	DeploymentState
	digest []byte
}

func loadReceipt(ctx context.Context, tx pgx.Tx, receiptID uuid.UUID) (storedReceipt, bool, error) {
	var receipt storedReceipt
	err := tx.QueryRow(ctx, `
		SELECT event.deployment_id,event.deployment_attempt,deployment.version_id,deployment.node_id,
		       event.state,event.sequence,deployment.deadline_at,event.occurred_at,event.receipt_digest
		FROM acme_http01_overlay_deployment_events event
		JOIN acme_http01_overlay_deployments deployment
		  ON deployment.id=event.deployment_id AND deployment.attempt=event.deployment_attempt
		WHERE event.receipt_id=$1`, receiptID).Scan(
		&receipt.DeploymentID, &receipt.DeploymentAttempt, &receipt.VersionID, &receipt.NodeID,
		&receipt.State, &receipt.Sequence, &receipt.Deadline, &receipt.OccurredAt, &receipt.digest,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return storedReceipt{}, false, nil
	}
	if err != nil || len(receipt.digest) != sha256.Size {
		return storedReceipt{}, false, fmt.Errorf("%w: read overlay receipt", ErrPersistence)
	}
	return receipt, true, nil
}

func receiptDigest(receipt Receipt) ([32]byte, error) {
	encoded, err := json.Marshal(struct {
		DeploymentID      uuid.UUID `json:"deployment_id"`
		DeploymentAttempt int       `json:"deployment_attempt"`
		ReceiptID         uuid.UUID `json:"receipt_id"`
		State             string    `json:"state"`
		FailureCode       string    `json:"failure_code,omitempty"`
		OccurredAt        time.Time `json:"occurred_at"`
	}{receipt.DeploymentID, receipt.DeploymentAttempt, receipt.ReceiptID, receipt.State, receipt.FailureCode, receipt.OccurredAt})
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func lockLatestDeployment(ctx context.Context, tx pgx.Tx, deploymentID uuid.UUID) (deploymentRecord, error) {
	var record deploymentRecord
	err := tx.QueryRow(ctx, `
		SELECT deployment.id,deployment.attempt,deployment.version_id,deployment.node_id,
		       deployment.deadline_at,deployment.tenant_scope_id,deployment.site_id,
		       deployment.revision,deployment.max_attempts
		FROM acme_http01_overlay_deployments deployment
		WHERE deployment.id=$1
		ORDER BY deployment.attempt DESC LIMIT 1
		FOR UPDATE`, deploymentID).Scan(
		&record.DeploymentID, &record.DeploymentAttempt, &record.VersionID, &record.NodeID,
		&record.Deadline, &record.tenantScopeID, &record.siteID, &record.revision, &record.maxAttempts,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return deploymentRecord{}, ErrNotFound
	}
	if err != nil {
		return deploymentRecord{}, fmt.Errorf("%w: lock overlay deployment", ErrPersistence)
	}
	return record, nil
}

func appendDeploymentEvent(
	ctx context.Context,
	tx pgx.Tx,
	deploymentID uuid.UUID,
	deploymentAttempt int,
	state string,
	receiptID uuid.UUID,
	receiptDigest [32]byte,
	failureCode string,
	occurredAt time.Time,
) (DeploymentState, error) {
	var current DeploymentState
	err := tx.QueryRow(ctx, `
		SELECT deployment.id,deployment.attempt,deployment.version_id,deployment.node_id,
		       event.state,event.sequence,deployment.deadline_at,event.occurred_at
		FROM acme_http01_overlay_deployments deployment
		JOIN LATERAL (
			SELECT state,sequence,occurred_at
			FROM acme_http01_overlay_deployment_events
			WHERE deployment_id=deployment.id AND deployment_attempt=deployment.attempt
			ORDER BY sequence DESC LIMIT 1
		) event ON true
		WHERE deployment.id=$1 AND deployment.attempt=$2
		FOR UPDATE OF deployment`, deploymentID, deploymentAttempt).Scan(
		&current.DeploymentID, &current.DeploymentAttempt, &current.VersionID, &current.NodeID,
		&current.State, &current.Sequence, &current.Deadline, &current.OccurredAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return DeploymentState{}, ErrNotFound
	}
	if err != nil {
		return DeploymentState{}, fmt.Errorf("%w: read overlay deployment state", ErrPersistence)
	}
	occurredAt = orderAfterPredecessor(occurredAt, current.OccurredAt)
	if occurredAt.Before(current.OccurredAt) || !validDeploymentTransition(current.State, state) {
		return DeploymentState{}, ErrInvalidTransition
	}
	var receiptIDValue any
	var receiptDigestValue any
	if receiptID != uuid.Nil {
		receiptIDValue = receiptID
		receiptDigestValue = receiptDigest[:]
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO acme_http01_overlay_deployment_events(
			deployment_id,deployment_attempt,sequence,state,receipt_id,receipt_digest,
			failure_code,occurred_at
		) VALUES($1,$2,$3,$4,$5,$6,NULLIF($7,''),$8)`, deploymentID, deploymentAttempt,
		current.Sequence+1, state, receiptIDValue, receiptDigestValue, failureCode, occurredAt)
	if err != nil {
		var postgresError *pgconn.PgError
		if errors.As(err, &postgresError) && postgresError.Code == "23505" {
			return DeploymentState{}, ErrReceiptConflict
		}
		return DeploymentState{}, fmt.Errorf("%w: append overlay deployment event", ErrPersistence)
	}
	current.State = state
	current.Sequence++
	current.OccurredAt = occurredAt
	return current, nil
}

// orderAfterPredecessor: a node receipt's time is the node clock, the event
// before it (dispatched) the controller's. Within the cross-host skew the
// receipt is ordered at its predecessor (063 refuses an event earlier than the
// one before it); a node status was refused the same way.
func orderAfterPredecessor(occurredAt, predecessor time.Time) time.Time {
	if occurredAt.Before(predecessor) && !occurredAt.Before(predecessor.Add(-edgestatus.CrossHostClockSkew)) {
		return predecessor
	}
	return occurredAt
}

func validDeploymentTransition(from, to string) bool {
	switch from {
	case DeploymentQueued, DeploymentRetryQueued:
		return to == DeploymentDispatched || to == DeploymentFailed || to == DeploymentTimedOut
	case DeploymentDispatched:
		return to == DeploymentApplied || to == DeploymentFailed || to == DeploymentTimedOut
	case DeploymentApplied:
		return to == DeploymentHealthy || to == DeploymentFailed || to == DeploymentTimedOut
	default:
		return false
	}
}

func (s *Service) RetryDeployment(ctx context.Context, request RetryRequest) (Outbox, error) {
	requestID, requestErr := uuid.Parse(request.RequestID)
	now := s.clock().UTC().Truncate(time.Microsecond)
	request.Deadline = request.Deadline.UTC().Truncate(time.Microsecond)
	if ctx == nil || request.DeploymentID == uuid.Nil || requestErr != nil || requestID.String() != request.RequestID ||
		!request.Deadline.After(now) || request.Deadline.Sub(now) > 24*time.Hour {
		return Outbox{}, ErrInvalidInput
	}
	var outbox Outbox
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if existing, found, err := loadRetryOutbox(ctx, tx, requestID); err != nil {
			return err
		} else if found {
			if existing.DeploymentID != request.DeploymentID || !existing.deadline.Equal(request.Deadline) {
				return ErrIdempotencyConflict
			}
			outbox = existing.Outbox
			return nil
		}
		record, err := lockLatestDeployment(ctx, tx, request.DeploymentID)
		if err != nil {
			return err
		}
		// 同一请求并发：上面的重放查询可能早于对方提交，而行锁取到的已是对方插入的新 attempt。
		// 持锁后重查一次重放，命中则回放胜者结果，而不是按新 attempt 的状态判非法迁移。
		if existing, found, err := loadRetryOutbox(ctx, tx, requestID); err != nil {
			return err
		} else if found {
			if existing.DeploymentID != request.DeploymentID || !existing.deadline.Equal(request.Deadline) {
				return ErrIdempotencyConflict
			}
			outbox = existing.Outbox
			return nil
		}
		publicationDeadline, publicationMaxAttempts, err := loadPublicationRetryPolicy(ctx, tx, record.VersionID)
		if err != nil {
			return err
		}
		if !request.Deadline.Equal(publicationDeadline) || record.maxAttempts != publicationMaxAttempts ||
			!record.Deadline.Equal(publicationDeadline) {
			return ErrInvalidInput
		}
		outbox, err = s.insertRetryDeploymentTx(ctx, tx, record, requestID, publicationDeadline, now)
		return err
	})
	return outbox, err
}

func loadPublicationRetryPolicy(ctx context.Context, tx pgx.Tx, versionID uuid.UUID) (time.Time, int, error) {
	var deadline time.Time
	var maxAttempts int
	if err := tx.QueryRow(ctx, `
		SELECT publication.deadline_at,publication.max_attempts
		FROM acme_http01_overlay_versions version
		JOIN acme_http01_overlay_publications publication ON publication.id=version.publication_id
		WHERE version.id=$1`, versionID).Scan(&deadline, &maxAttempts); errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, 0, ErrNotFound
	} else if err != nil {
		return time.Time{}, 0, fmt.Errorf("%w: read overlay retry policy", ErrPersistence)
	}
	return deadline.UTC().Truncate(time.Microsecond), maxAttempts, nil
}

func (s *Service) insertRetryDeploymentTx(
	ctx context.Context,
	tx pgx.Tx,
	record deploymentRecord,
	requestID uuid.UUID,
	publicationDeadline time.Time,
	now time.Time,
) (Outbox, error) {
	current, err := currentDeploymentState(ctx, tx, record.DeploymentID, record.DeploymentAttempt)
	if err != nil {
		return Outbox{}, err
	}
	if current.State != DeploymentFailed && current.State != DeploymentTimedOut {
		return Outbox{}, ErrInvalidTransition
	}
	if record.DeploymentAttempt >= record.maxAttempts {
		return Outbox{}, ErrAttemptsExhausted
	}
	if !publicationDeadline.After(now) || !record.Deadline.Equal(publicationDeadline) {
		return Outbox{}, ErrInvalidInput
	}
	nextAttempt := record.DeploymentAttempt + 1
	insertResult, err := tx.Exec(ctx, `
		INSERT INTO acme_http01_overlay_deployments(
			id,attempt,version_id,tenant_scope_id,site_id,revision,node_id,retry_request_id,
			deadline_at,max_attempts,created_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		ON CONFLICT DO NOTHING`, record.DeploymentID, nextAttempt,
		record.VersionID, record.tenantScopeID, record.siteID, record.revision, record.NodeID,
		requestID, publicationDeadline, record.maxAttempts, now)
	if err != nil {
		return Outbox{}, fmt.Errorf("%w: insert overlay deployment retry", ErrPersistence)
	}
	if insertResult.RowsAffected() == 0 {
		if existing, found, err := loadRetryOutbox(ctx, tx, requestID); err != nil {
			return Outbox{}, err
		} else if found {
			if existing.DeploymentID != record.DeploymentID || !existing.deadline.Equal(publicationDeadline) {
				return Outbox{}, ErrIdempotencyConflict
			}
			return existing.Outbox, nil
		}
		return Outbox{}, ErrInvalidTransition
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO acme_http01_overlay_deployment_events(
			deployment_id,deployment_attempt,sequence,state,occurred_at
		) VALUES($1,$2,1,'retry_queued',$3)`, record.DeploymentID, nextAttempt, now); err != nil {
		return Outbox{}, fmt.Errorf("%w: queue overlay deployment retry", ErrPersistence)
	}
	tokens, err := loadVersionTokens(ctx, tx, record.VersionID)
	if err != nil {
		return Outbox{}, err
	}
	publication, err := loadPublicationByVersion(ctx, tx, record.VersionID)
	if err != nil {
		return Outbox{}, err
	}
	payloadDigest, err := deliveryPayloadDigest(publication, record.DeploymentID, nextAttempt, record.NodeID, tokens)
	if err != nil {
		return Outbox{}, ErrInvalidInput
	}
	outbox := Outbox{
		ID: overlayOutboxID(record.DeploymentID, nextAttempt), DeploymentID: record.DeploymentID,
		DeploymentAttempt: nextAttempt, VersionID: record.VersionID, NodeID: record.NodeID, CreatedAt: now,
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO acme_http01_overlay_outbox(
			id,deployment_id,deployment_attempt,version_id,node_id,subject,payload_sha256,created_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, outbox.ID, outbox.DeploymentID,
		outbox.DeploymentAttempt, outbox.VersionID, outbox.NodeID,
		s.subject+"."+outbox.NodeID.String(), payloadDigest[:], now); err != nil {
		return Outbox{}, fmt.Errorf("%w: insert overlay retry outbox", ErrPersistence)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO acme_http01_overlay_outbox_states(
			outbox_id,status,publish_attempts,available_at,updated_at
		) VALUES($1,'pending',0,$2,$2)`, outbox.ID, now); err != nil {
		return Outbox{}, fmt.Errorf("%w: initialize overlay retry outbox", ErrPersistence)
	}
	if err := s.auditor.Append(ctx, tx, audit.Event{
		ScopeID: record.tenantScopeID, ActorUserID: nil,
		Action: "acme_http01_overlay.retry", ResourceType: "acme_http01_overlay_deployment",
		ResourceID: record.DeploymentID.String(), RequestID: requestID.String(), Result: "success",
		Payload: map[string]any{
			"attempt": nextAttempt, "site_id": record.siteID.String(), "revision": record.revision,
			"node_id": record.NodeID.String(), "deadline_at": publicationDeadline.Format(time.RFC3339Nano),
		},
	}); err != nil {
		return Outbox{}, err
	}
	return outbox, nil
}

type retryOutboxReplay struct {
	Outbox
	deadline time.Time
}

func loadRetryOutbox(ctx context.Context, tx pgx.Tx, requestID uuid.UUID) (retryOutboxReplay, bool, error) {
	var replay retryOutboxReplay
	err := tx.QueryRow(ctx, `
		SELECT outbox.id,outbox.deployment_id,outbox.deployment_attempt,outbox.version_id,
		       outbox.node_id,outbox.created_at,deployment.deadline_at
		FROM acme_http01_overlay_deployments deployment
		JOIN acme_http01_overlay_outbox outbox ON outbox.deployment_id=deployment.id
		  AND outbox.deployment_attempt=deployment.attempt
		WHERE deployment.retry_request_id=$1`, requestID).Scan(
		&replay.ID, &replay.DeploymentID, &replay.DeploymentAttempt,
		&replay.VersionID, &replay.NodeID, &replay.CreatedAt, &replay.deadline,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return retryOutboxReplay{}, false, nil
	}
	if err != nil {
		return retryOutboxReplay{}, false, fmt.Errorf("%w: read overlay retry replay", ErrPersistence)
	}
	replay.deadline = replay.deadline.UTC().Truncate(time.Microsecond)
	return replay, true, nil
}

func loadPublicationByVersion(ctx context.Context, tx pgx.Tx, versionID uuid.UUID) (Publication, error) {
	var publication Publication
	var snapshotDigest []byte
	err := tx.QueryRow(ctx, `
		SELECT publication.id,version.id,publication.mode,publication.tenant_scope_id,publication.site_id,
		       publication.revision,version.sealed_snapshot_sha256,publication.token_count,
		       publication.node_count,publication.created_at
		FROM acme_http01_overlay_versions version
		JOIN acme_http01_overlay_publications publication ON publication.id=version.publication_id
		WHERE version.id=$1`, versionID).Scan(
		&publication.ID, &publication.VersionID, &publication.Mode, &publication.TenantScopeID, &publication.SiteID,
		&publication.Revision, &snapshotDigest, &publication.TokenCount, &publication.NodeCount,
		&publication.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Publication{}, ErrNotFound
	}
	if err != nil || len(snapshotDigest) != sha256.Size {
		return Publication{}, fmt.Errorf("%w: read overlay version", ErrPersistence)
	}
	copy(publication.SealedSnapshotSHA256[:], snapshotDigest)
	return publication, nil
}

func currentDeploymentState(ctx context.Context, tx pgx.Tx, deploymentID uuid.UUID, attempt int) (DeploymentState, error) {
	var state DeploymentState
	err := tx.QueryRow(ctx, `
		SELECT deployment.id,deployment.attempt,deployment.version_id,deployment.node_id,
		       event.state,event.sequence,deployment.deadline_at,event.occurred_at
		FROM acme_http01_overlay_deployments deployment
		JOIN LATERAL (
			SELECT state,sequence,occurred_at
			FROM acme_http01_overlay_deployment_events
			WHERE deployment_id=deployment.id AND deployment_attempt=deployment.attempt
			ORDER BY sequence DESC LIMIT 1
		) event ON true
		WHERE deployment.id=$1 AND deployment.attempt=$2`, deploymentID, attempt).Scan(
		&state.DeploymentID, &state.DeploymentAttempt, &state.VersionID, &state.NodeID,
		&state.State, &state.Sequence, &state.Deadline, &state.OccurredAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return DeploymentState{}, ErrNotFound
	}
	if err != nil {
		return DeploymentState{}, fmt.Errorf("%w: read overlay deployment", ErrPersistence)
	}
	return state, nil
}

func (s *Service) MarkTimedOut(ctx context.Context, now time.Time, limit int) (int, error) {
	if ctx == nil || now.IsZero() || limit < 1 || limit > 1000 {
		return 0, ErrInvalidInput
	}
	now = now.UTC().Truncate(time.Microsecond)
	count := 0
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT deployment.id,deployment.attempt,deployment.tenant_scope_id,
			       deployment.site_id,deployment.revision,deployment.node_id
			FROM acme_http01_overlay_deployments deployment
			JOIN LATERAL (
				SELECT state
				FROM acme_http01_overlay_deployment_events
				WHERE deployment_id=deployment.id AND deployment_attempt=deployment.attempt
				ORDER BY sequence DESC LIMIT 1
			) latest ON latest.state IN ('queued','retry_queued','dispatched','applied')
			WHERE deployment.deadline_at <= $1
			  AND NOT EXISTS (
				SELECT 1 FROM acme_http01_overlay_deployments newer
				WHERE newer.id=deployment.id AND newer.attempt > deployment.attempt
			  )
			ORDER BY deployment.deadline_at,deployment.id
			FOR UPDATE OF deployment SKIP LOCKED
			LIMIT $2`, now, limit)
		if err != nil {
			return fmt.Errorf("%w: claim timed out overlay deployments", ErrPersistence)
		}
		type candidate struct {
			id, tenant, site, node uuid.UUID
			attempt                int
			revision               int64
		}
		var candidates []candidate
		for rows.Next() {
			var item candidate
			if err := rows.Scan(&item.id, &item.attempt, &item.tenant, &item.site, &item.revision, &item.node); err != nil {
				rows.Close()
				return fmt.Errorf("%w: scan timed out overlay deployment", ErrPersistence)
			}
			candidates = append(candidates, item)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("%w: iterate timed out overlay deployments", ErrPersistence)
		}
		rows.Close()
		for _, item := range candidates {
			if _, err := appendDeploymentEvent(ctx, tx, item.id, item.attempt, DeploymentTimedOut,
				uuid.Nil, [32]byte{}, "deployment_timed_out", now); err != nil {
				return err
			}
			if err := exhaustTimedOutOutbox(ctx, tx, item.id, item.attempt, now); err != nil {
				return err
			}
			if err := s.auditor.Append(ctx, tx, audit.Event{
				ScopeID: item.tenant, ActorUserID: nil,
				Action: "acme_http01_overlay.timeout", ResourceType: "acme_http01_overlay_deployment",
				ResourceID: item.id.String(), RequestID: item.id.String(), Result: "success",
				Payload: map[string]any{
					"attempt": item.attempt, "site_id": item.site.String(), "revision": item.revision,
					"node_id": item.node.String(),
				},
			}); err != nil {
				return err
			}
			count++
		}
		return nil
	})
	return count, err
}

func exhaustTimedOutOutbox(ctx context.Context, tx pgx.Tx, deploymentID uuid.UUID, attempt int, now time.Time) error {
	var outboxID uuid.UUID
	var status string
	var publishAttempts int
	var leaseToken *uuid.UUID
	err := tx.QueryRow(ctx, `
		SELECT state.outbox_id,state.status,state.publish_attempts,state.lease_token
		FROM acme_http01_overlay_outbox outbox
		JOIN acme_http01_overlay_outbox_states state ON state.outbox_id=outbox.id
		WHERE outbox.deployment_id=$1 AND outbox.deployment_attempt=$2
		FOR UPDATE OF state`, deploymentID, attempt).Scan(&outboxID, &status, &publishAttempts, &leaseToken)
	if err != nil {
		return fmt.Errorf("%w: lock timed out overlay outbox", ErrPersistence)
	}
	if status == "published" || status == "exhausted" {
		return nil
	}
	sequence, err := nextOutboxAttemptSequence(ctx, tx, outboxID)
	if err != nil {
		return err
	}
	var attemptLease any
	switch status {
	case "pending":
		publishAttempts = 0
	case "claimed":
		if leaseToken == nil {
			return fmt.Errorf("%w: timed out overlay claim has no lease", ErrPersistence)
		}
		attemptLease = *leaseToken
	case "retry":
		var retryLease uuid.UUID
		if err := tx.QueryRow(ctx, `
			SELECT lease_token FROM acme_http01_overlay_outbox_attempts
			WHERE outbox_id=$1 ORDER BY sequence DESC LIMIT 1`, outboxID).Scan(&retryLease); err != nil {
			return fmt.Errorf("%w: read timed out overlay retry lease", ErrPersistence)
		}
		attemptLease = retryLease
	default:
		return fmt.Errorf("%w: invalid timed out overlay outbox state", ErrPersistence)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO acme_http01_overlay_outbox_attempts(
			outbox_id,sequence,publish_attempt,event_type,lease_token,failure_code,occurred_at
		) VALUES($1,$2,$3,'exhausted',$4,'deployment_timed_out',$5)`, outboxID, sequence,
		publishAttempts, attemptLease, now); err != nil {
		return fmt.Errorf("%w: exhaust timed out overlay outbox", ErrPersistence)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE acme_http01_overlay_outbox_states
		SET status='exhausted',lease_token=NULL,lease_expires_at=NULL,
		    last_failure_code='deployment_timed_out',updated_at=$2
		WHERE outbox_id=$1`, outboxID, now); err != nil {
		return fmt.Errorf("%w: exhaust timed out overlay outbox", ErrPersistence)
	}
	return nil
}

func (s *Service) VersionHealth(
	ctx context.Context,
	tenantScopeID uuid.UUID,
	siteID uuid.UUID,
	revision int64,
) (Health, error) {
	if ctx == nil || tenantScopeID == uuid.Nil || siteID == uuid.Nil || revision <= 0 {
		return Health{}, ErrInvalidInput
	}
	return versionHealthQuery(ctx, s.pool, tenantScopeID, siteID, revision)
}

type queryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func versionHealthQuery(
	ctx context.Context,
	db queryer,
	tenantScopeID uuid.UUID,
	siteID uuid.UUID,
	revision int64,
) (Health, error) {
	var health Health
	err := db.QueryRow(ctx, `
		WITH version AS (
			SELECT id,tenant_scope_id,site_id,revision
			FROM acme_http01_overlay_versions
			WHERE tenant_scope_id=$1 AND site_id=$2 AND revision=$3
		), latest_attempt AS (
			SELECT DISTINCT ON (deployment.id)
			       deployment.id,deployment.attempt,deployment.version_id
			FROM acme_http01_overlay_deployments deployment
			JOIN version ON version.id=deployment.version_id
			ORDER BY deployment.id,deployment.attempt DESC
		), latest_state AS (
			SELECT attempt.version_id,event.state
			FROM latest_attempt attempt
			JOIN LATERAL (
				SELECT state
				FROM acme_http01_overlay_deployment_events
				WHERE deployment_id=attempt.id AND deployment_attempt=attempt.attempt
				ORDER BY sequence DESC LIMIT 1
			) event ON true
		)
		SELECT version.tenant_scope_id,version.site_id,version.revision,version.id,
		       count(latest_state.state)::integer,
		       count(*) FILTER (WHERE latest_state.state='healthy')::integer,
		       count(*) FILTER (WHERE latest_state.state IN ('failed','timed_out'))::integer,
		       count(*) FILTER (WHERE latest_state.state NOT IN ('healthy','failed','timed_out'))::integer
		FROM version
		JOIN latest_state ON latest_state.version_id=version.id
		GROUP BY version.tenant_scope_id,version.site_id,version.revision,version.id`,
		tenantScopeID, siteID, revision).Scan(
		&health.TenantScopeID, &health.SiteID, &health.Revision, &health.VersionID,
		&health.TargetCount, &health.HealthyCount, &health.FailedCount, &health.PendingCount,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Health{}, ErrNotFound
	}
	if err != nil {
		return Health{}, fmt.Errorf("%w: read overlay version health", ErrPersistence)
	}
	health.Healthy = health.TargetCount > 0 && health.HealthyCount == health.TargetCount
	return health, nil
}

func advanceHealthyProjection(
	ctx context.Context,
	tx pgx.Tx,
	tenantScopeID uuid.UUID,
	siteID uuid.UUID,
	revision int64,
	now time.Time,
) error {
	health, err := versionHealthQuery(ctx, tx, tenantScopeID, siteID, revision)
	if err != nil {
		return err
	}
	if !health.Healthy {
		return nil
	}
	if _, err := tx.Exec(ctx, `
		UPDATE acme_http01_overlay_states
		SET latest_healthy_revision=$3,updated_at=$4
		WHERE tenant_scope_id=$1 AND site_id=$2
		  AND (latest_healthy_revision IS NULL OR latest_healthy_revision < $3)`,
		tenantScopeID, siteID, revision, now); err != nil {
		return fmt.Errorf("%w: advance healthy overlay revision", ErrPersistence)
	}
	return nil
}

func (s *Service) AwaitHealthy(
	ctx context.Context,
	tenantScopeID uuid.UUID,
	siteID uuid.UUID,
	revision int64,
	poll time.Duration,
) (Health, error) {
	if ctx == nil || poll <= 0 || poll > time.Minute {
		return Health{}, ErrInvalidInput
	}
	for {
		health, err := s.VersionHealth(ctx, tenantScopeID, siteID, revision)
		if err != nil {
			return Health{}, err
		}
		if health.Healthy || health.FailedCount > 0 {
			return health, nil
		}
		timer := time.NewTimer(poll)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return Health{}, ctx.Err()
		case <-timer.C:
		}
	}
}

func (s *Service) LatestHealthy(
	ctx context.Context,
	tenantScopeID uuid.UUID,
	siteID uuid.UUID,
) (HealthyRevision, error) {
	if ctx == nil || tenantScopeID == uuid.Nil || siteID == uuid.Nil {
		return HealthyRevision{}, ErrInvalidInput
	}
	var result HealthyRevision
	var digest []byte
	err := s.pool.QueryRow(ctx, `
		SELECT state.tenant_scope_id,state.site_id,state.latest_healthy_revision,
		       version.id,version.sealed_snapshot_sha256,state.updated_at
		FROM acme_http01_overlay_states state
		JOIN acme_http01_overlay_versions version
		  ON version.tenant_scope_id=state.tenant_scope_id AND version.site_id=state.site_id
		 AND version.revision=state.latest_healthy_revision
		WHERE state.tenant_scope_id=$1 AND state.site_id=$2`, tenantScopeID, siteID).Scan(
		&result.TenantScopeID, &result.SiteID, &result.Revision,
		&result.VersionID, &digest, &result.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return HealthyRevision{}, ErrNotFound
	}
	if err != nil || len(digest) != sha256.Size {
		return HealthyRevision{}, fmt.Errorf("%w: read latest healthy overlay", ErrPersistence)
	}
	copy(result.SnapshotSHA256[:], digest)
	return result, nil
}
