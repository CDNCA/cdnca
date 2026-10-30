package challengepolicy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/challengepublication"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type DurableBindingPublisher struct {
	pool      *pgxpool.Pool
	publisher *edgepublish.Service
	clock     func() time.Time
}

func NewDurableBindingPublisher(pool *pgxpool.Pool, publisher *edgepublish.Service,
	clock func() time.Time) (*DurableBindingPublisher, error) {
	if pool == nil || publisher == nil || clock == nil {
		return nil, ErrInvalidHandlerConfig
	}
	return &DurableBindingPublisher{pool: pool, publisher: publisher, clock: clock}, nil
}

func (publisher *DurableBindingPublisher) PublishChallengeBinding(
	ctx context.Context, request challengepublication.BindingRequest,
) (challengepublication.ConfigPublication, error) {
	if publisher == nil || ctx == nil || !validChallengeBindingRequest(request) {
		return challengepublication.ConfigPublication{}, challengepublication.ErrInvalidRuntime
	}
	digest, err := challengeBindingRequestDigest(request)
	if err != nil {
		return challengepublication.ConfigPublication{}, challengepublication.ErrInvalidRuntime
	}
	var result challengepublication.ConfigPublication
	err = pgx.BeginFunc(ctx, publisher.pool, func(tx pgx.Tx) error {
		var replayed bool
		result, replayed, err = loadChallengeBindingReplay(ctx, tx, request, digest)
		if err != nil || replayed {
			return err
		}
		now := publisher.clock().UTC().Truncate(time.Microsecond)
		bindingRevision, err := stageChallengeBinding(ctx, tx, request, digest, now)
		if err != nil {
			return err
		}
		var sourceRevision int64
		if _, err := tx.Exec(ctx, `SELECT advance_edge_configuration_scope_revision($1)`, request.TenantScopeID); err != nil {
			return fmt.Errorf("advance challenge edge source revision: %w", err)
		}
		if err := tx.QueryRow(ctx, `SELECT source_revision FROM edge_configuration_scopes
			WHERE scope_id=$1 FOR UPDATE`, request.TenantScopeID).Scan(&sourceRevision); err != nil || sourceRevision < 1 {
			return fmt.Errorf("load challenge edge source revision: %w", err)
		}
		edgeKey := sha256.Sum256([]byte("challenge-binding\x00" + request.IdempotencyKey))
		published, err := publisher.publisher.PublishTx(ctx, tx, edgepublish.PublishRequest{
			Actor: request.Actor, ConfigurationScopeID: request.TenantScopeID,
			ExpectedSourceRevision: sourceRevision, NodeIDs: append([]uuid.UUID(nil), request.NodeIDs...),
			HealthCheck: request.HealthCheck, MaxAttempts: 3, Deadline: request.Deadline,
			IdempotencyKey: "challenge." + hex.EncodeToString(edgeKey[:]), RequestID: request.RequestID,
			CorrelationID: request.CorrelationID, Traceparent: request.Traceparent, TaskID: request.TaskID,
		})
		if err != nil {
			return err
		}
		// Nodes not ready for the binding (offline,
		// isolated, disabled) are held for this revision; the redeliverer
		// completes them and republishes.
		if len(request.DeferredNodeIDs) > 0 {
			if err := publisher.publisher.DeferChallengeNodesTx(ctx, tx, edgepublish.ChallengeDeferral{
				Actor: request.Actor, ScopeID: request.TenantScopeID, SourceRevision: published.SourceRevision,
				RequestID: request.RequestID, PublishedNodeIDs: append([]uuid.UUID(nil), request.NodeIDs...),
				DeferredNodeIDs: append([]uuid.UUID(nil), request.DeferredNodeIDs...), SiteID: request.SiteID,
				PolicyID: request.PolicyID, PolicyVersion: request.PolicyRevision, SecretRolloutID: request.Secret.RolloutID,
			}); err != nil {
				return err
			}
		}
		command, err := tx.Exec(ctx, `UPDATE challenge_site_binding_revisions_138
			SET state='active',edge_publication_id=$4,edge_source_revision=$5,activated_at=$6
			WHERE tenant_scope_id=$1 AND site_id=$2 AND binding_revision=$3 AND state='candidate'`,
			request.TenantScopeID, request.SiteID, bindingRevision, published.PublicationID,
			published.SourceRevision, now)
		if err != nil || command.RowsAffected() != 1 {
			return fmt.Errorf("activate durable challenge binding: %w", err)
		}
		result = challengepublication.ConfigPublication{PublicationID: published.PublicationID,
			Revision: published.SourceRevision}
		return nil
	})
	if err != nil {
		return challengepublication.ConfigPublication{}, err
	}
	return result, nil
}

func validChallengeBindingRequest(request challengepublication.BindingRequest) bool {
	return request.TenantScopeID != uuid.Nil && request.TenantID != uuid.Nil && request.SiteID != uuid.Nil &&
		request.PolicyID != uuid.Nil && request.PolicyRevision > 0 && request.Secret.RolloutID != uuid.Nil &&
		request.Secret.ConfigVersionID != uuid.Nil && request.Secret.Revision > 0 && request.Actor.UserID != uuid.Nil &&
		request.Actor.ScopeID != uuid.Nil && request.Host != "" && request.Host == strings.ToLower(request.Host) &&
		len(request.NodeIDs) > 0 && len(request.NodeIDs)+len(request.DeferredNodeIDs) <= 10000 &&
		!slices.ContainsFunc(request.DeferredNodeIDs, func(nodeID uuid.UUID) bool {
			return nodeID == uuid.Nil || slices.Contains(request.NodeIDs, nodeID)
		}) && request.HealthCheck.ActivationTimeout > 0 &&
		request.HealthCheck.ObservationWindow > 0 && request.HealthCheck.RequiredConsecutiveSuccesses > 0 &&
		!request.Deadline.IsZero() && request.IdempotencyKey != "" && request.RequestID != "" && request.CorrelationID != ""
}

func challengeBindingRequestDigest(request challengepublication.BindingRequest) ([sha256.Size]byte, error) {
	canonical := struct {
		TenantScopeID, TenantID, SiteID, PolicyID string
		SecretRolloutID, SecretConfigVersionID    string
		ActorUserID, ActorScopeID, ActorScopeKind string
		ActorSessionID, Host, Deadline            string
		PolicyRevision, SecretRevision            int64
		ActivationTimeout, ObservationWindow      int64
		RequiredConsecutiveSuccesses              uint32
		NodeIDs, DeferredNodeIDs                  []string
	}{
		TenantScopeID: request.TenantScopeID.String(), TenantID: request.TenantID.String(),
		SiteID: request.SiteID.String(), PolicyID: request.PolicyID.String(),
		SecretRolloutID:       request.Secret.RolloutID.String(),
		SecretConfigVersionID: request.Secret.ConfigVersionID.String(),
		ActorUserID:           request.Actor.UserID.String(), ActorScopeID: request.Actor.ScopeID.String(),
		ActorScopeKind: request.Actor.ScopeKind, ActorSessionID: request.Actor.SessionID.String(),
		Host: request.Host, Deadline: request.Deadline.UTC().Format(time.RFC3339Nano),
		PolicyRevision: request.PolicyRevision, SecretRevision: request.Secret.Revision,
		ActivationTimeout:            int64(request.HealthCheck.ActivationTimeout),
		ObservationWindow:            int64(request.HealthCheck.ObservationWindow),
		RequiredConsecutiveSuccesses: request.HealthCheck.RequiredConsecutiveSuccesses,
		NodeIDs:                      make([]string, len(request.NodeIDs)),
		DeferredNodeIDs:              make([]string, len(request.DeferredNodeIDs)),
	}
	for index, nodeID := range request.NodeIDs {
		canonical.NodeIDs[index] = nodeID.String()
	}
	for index, nodeID := range request.DeferredNodeIDs {
		canonical.DeferredNodeIDs[index] = nodeID.String()
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func loadChallengeBindingReplay(ctx context.Context, tx pgx.Tx, request challengepublication.BindingRequest,
	digest [sha256.Size]byte) (challengepublication.ConfigPublication, bool, error) {
	var storedDigest []byte
	var publicationID *uuid.UUID
	var sourceRevision *int64
	err := tx.QueryRow(ctx, `SELECT request_digest,edge_publication_id,edge_source_revision
		FROM challenge_site_binding_revisions_138
		WHERE tenant_scope_id=$1 AND idempotency_key=$2 FOR SHARE`, request.TenantScopeID,
		request.IdempotencyKey).Scan(&storedDigest, &publicationID, &sourceRevision)
	if errors.Is(err, pgx.ErrNoRows) {
		return challengepublication.ConfigPublication{}, false, nil
	}
	if err != nil {
		return challengepublication.ConfigPublication{}, false, err
	}
	if !bytes.Equal(storedDigest, digest[:]) || publicationID == nil || sourceRevision == nil ||
		*publicationID == uuid.Nil || *sourceRevision < 1 {
		return challengepublication.ConfigPublication{}, false, ErrIdempotencyConflict
	}
	return challengepublication.ConfigPublication{PublicationID: *publicationID, Revision: *sourceRevision}, true, nil
}

func stageChallengeBinding(ctx context.Context, tx pgx.Tx, request challengepublication.BindingRequest,
	digest [sha256.Size]byte, now time.Time) (int64, error) {
	var tenantID uuid.UUID
	var domain string
	if err := tx.QueryRow(ctx, `SELECT scope.tenant_id,site.domain FROM sites site
		JOIN access_scopes scope ON scope.id=site.scope_id AND scope.kind='tenant'
		WHERE site.scope_id=$1 AND site.id=$2 AND site.deleted_at IS NULL AND site.enabled
		FOR SHARE OF site,scope`, request.TenantScopeID, request.SiteID).Scan(&tenantID, &domain); err != nil ||
		tenantID != request.TenantID || !edgeconfig.ChallengeHostCoversSite(domain, request.Host) {
		return 0, ErrConflict
	}
	// A wildcard site's binding names the host of its current policy (one
	// concrete host under the wildcard); binding another host's policy moves
	// it (migration 345). Other sites' binding host is the site domain.
	wildcard := strings.HasPrefix(domain, "*.")
	if _, err := tx.Exec(ctx, `INSERT INTO challenge_site_bindings_138(
		tenant_scope_id,tenant_id,site_id,host,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$5) ON CONFLICT(tenant_scope_id,site_id) DO NOTHING`,
		request.TenantScopeID, request.TenantID, request.SiteID, request.Host, now); err != nil {
		return 0, err
	}
	var activeRevision *int64
	var currentHost string
	if err := tx.QueryRow(ctx, `SELECT host,active_binding_revision FROM challenge_site_bindings_138
		WHERE tenant_scope_id=$1 AND site_id=$2 FOR UPDATE`, request.TenantScopeID,
		request.SiteID).Scan(&currentHost, &activeRevision); err != nil || currentHost != request.Host && !wildcard {
		return 0, ErrConflict
	}
	bindingRevision := int64(1)
	if activeRevision != nil {
		var activePolicyID uuid.UUID
		var activePolicyRevision int64
		if err := tx.QueryRow(ctx, `SELECT policy_id,policy_revision FROM challenge_site_binding_revisions_138
			WHERE tenant_scope_id=$1 AND site_id=$2 AND binding_revision=$3 FOR SHARE`,
			request.TenantScopeID, request.SiteID, *activeRevision).Scan(&activePolicyID, &activePolicyRevision); err != nil {
			return 0, err
		}
		if !challengeBindingPolicyAdvanceAllowed(activePolicyID, activePolicyRevision,
			request.PolicyID, request.PolicyRevision) {
			return 0, ErrRevisionConflict
		}
		bindingRevision = *activeRevision + 1
	}
	_, err := tx.Exec(ctx, `INSERT INTO challenge_site_binding_revisions_138(
		tenant_scope_id,tenant_id,site_id,host,binding_revision,policy_id,policy_revision,
		secret_rollout_id,secret_config_version_id,secret_revision,state,idempotency_key,
		request_digest,request_id,correlation_id,actor_scope_id,actor_user_id,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'candidate',$11,$12,$13,$14,$15,$16,$17)`,
		request.TenantScopeID, request.TenantID, request.SiteID, request.Host, bindingRevision,
		request.PolicyID, request.PolicyRevision, request.Secret.RolloutID, request.Secret.ConfigVersionID,
		request.Secret.Revision, request.IdempotencyKey, digest[:], request.RequestID,
		request.CorrelationID, request.Actor.ScopeID, request.Actor.UserID, now)
	if err != nil {
		return 0, err
	}
	_, err = tx.Exec(ctx, `UPDATE challenge_site_bindings_138 SET
		lkg_binding_revision=active_binding_revision,active_binding_revision=$3,updated_at=$4,host=$5
		WHERE tenant_scope_id=$1 AND site_id=$2`, request.TenantScopeID, request.SiteID, bindingRevision, now, request.Host)
	return bindingRevision, err
}

func challengeBindingPolicyAdvanceAllowed(activePolicyID uuid.UUID, activePolicyRevision int64,
	nextPolicyID uuid.UUID, nextPolicyRevision int64) bool {
	if activePolicyID == uuid.Nil || activePolicyRevision < 1 || nextPolicyID == uuid.Nil || nextPolicyRevision < 1 {
		return false
	}
	return activePolicyID != nextPolicyID || nextPolicyRevision > activePolicyRevision
}

var _ challengepublication.ConfigPublisher = (*DurableBindingPublisher)(nil)
