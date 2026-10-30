package challengepublication

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ErrRedeliveryOriginMissing: the binding's challenge secret config version or
// policy revision is gone.
var ErrRedeliveryOriginMissing = errors.New("challenge redelivery origin is missing")

// RedeliveryFacts are what a redelivery rebuilds from: the policy document
// the binding published (its secret config version's canonical snapshot) and
// the policy revision it was built from.
type RedeliveryFacts struct {
	OriginSnapshot  []byte
	OriginGenerator string
	Policy          PublicationSnapshot
}

type RedeliveryFactSource interface {
	LoadRedeliveryFactsTx(context.Context, pgx.Tx, edgepublish.ChallengeRedelivery) (RedeliveryFacts, error)
}

type systemSecretRolloutStore interface {
	CreateSystemSecretRolloutTx(context.Context, pgx.Tx, edgedeployment.SystemSecretRolloutRequest,
		edgedeployment.SecretArtifactBuilder) (edgedeployment.CreateRolloutResult, error)
}

// RedeliveryPolicy is the rollout policy of a redelivery (the challenge
// publication planner's health check).
type RedeliveryPolicy struct {
	HealthCheck edgedeployment.HealthCheckPolicy
}

// ChallengeSecretRedeliverer is edgepublish.ChallengeRedeliverer's secret
// rollout: the published challenge policy document, rebuilt from the policy
// revision and its key facts, to one node.
type ChallengeSecretRedeliverer struct {
	source   RedeliveryFactSource
	keys     KeyResolver
	store    systemSecretRolloutStore
	producer *ArtifactProducer
	policy   RedeliveryPolicy
}

func NewChallengeSecretRedeliverer(source RedeliveryFactSource, keys KeyResolver, store systemSecretRolloutStore,
	producer *ArtifactProducer, policy RedeliveryPolicy) (*ChallengeSecretRedeliverer, error) {
	if nilDependency(source) || nilDependency(keys) || nilDependency(store) || producer == nil ||
		policy.HealthCheck.ActivationTimeout <= 0 || policy.HealthCheck.ObservationWindow <= 0 ||
		policy.HealthCheck.RequiredConsecutiveSuccesses == 0 {
		return nil, ErrInvalidRuntime
	}
	return &ChallengeSecretRedeliverer{source: source, keys: keys, store: store, producer: producer, policy: policy}, nil
}

func (redeliverer *ChallengeSecretRedeliverer) RedeliverChallengeSecretTx(
	ctx context.Context, tx pgx.Tx, item edgepublish.ChallengeRedelivery,
) (uuid.UUID, error) {
	if redeliverer == nil || ctx == nil || item.ScopeID == uuid.Nil || item.NodeID == uuid.Nil ||
		item.AccountableUserID == uuid.Nil || item.IdempotencyKey == "" {
		return uuid.Nil, ErrInvalidRuntime
	}
	facts, err := redeliverer.source.LoadRedeliveryFactsTx(ctx, tx, item)
	if errors.Is(err, ErrRedeliveryOriginMissing) {
		return uuid.Nil, fmt.Errorf("%w: %w", edgepublish.ErrChallengeRedeliveryUnrecoverable, err)
	}
	if err != nil {
		return uuid.Nil, err
	}
	defer zeroBytes(facts.OriginSnapshot)
	if facts.OriginGenerator != edgepublish.ChallengeSecretGeneratorName {
		return uuid.Nil, fmt.Errorf("%w: origin is not a challenge secret", edgepublish.ErrChallengeRedeliveryUnrecoverable)
	}
	// Key facts are read through their own pool: an unavailable key is
	// retried (bounded), a key that resolves to another document is not.
	keys, err := redeliverer.keys.ResolveChallengeKeys(ctx, facts.Policy)
	if err != nil || !validResolvedKeys(keys) || !validExternalResolvedKeys(facts.Policy, keys) {
		clearResolvedKeys(&keys)
		return uuid.Nil, ErrKeyUnavailable
	}
	material := buildArtifactMaterial(facts.Policy, keys)
	clearResolvedKeys(&keys)
	defer clearMaterial(&material)
	document, err := json.Marshal(material.Policy) // PolicyDocument
	if err != nil {
		return uuid.Nil, err
	}
	defer zeroBytes(document)
	// The node must get exactly what the binding published: same policy, same
	// key identities. Anything else needs the tenant's publication.
	if !bytes.Equal(document, facts.OriginSnapshot) {
		return uuid.Nil, fmt.Errorf("%w: the published policy document cannot be rebuilt",
			edgepublish.ErrChallengeRedeliveryUnrecoverable)
	}
	builder, err := NewSecretArtifactBuilder(redeliverer.producer, material)
	if err != nil {
		return uuid.Nil, fmt.Errorf("%w: %w", edgepublish.ErrChallengeRedeliveryUnrecoverable, err)
	}
	result, err := redeliverer.store.CreateSystemSecretRolloutTx(ctx, tx, edgedeployment.SystemSecretRolloutRequest{
		ConfigurationScopeID: item.ScopeID, AccountableUserID: item.AccountableUserID, NodeIDs: []uuid.UUID{item.NodeID},
		CanonicalSnapshot: document, GeneratorName: edgepublish.ChallengeSecretGeneratorName, GeneratorVersion: "1.0.0",
		PayloadDigest: sha256.Sum256(document),
		RequiredCapabilities: []*agentv1.Capability{
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_ATOMIC_RELEASE, ApiVersion: 1},
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_CONFIG_PRECHECK, ApiVersion: 1},
		},
		HealthCheck: redeliverer.policy.HealthCheck, Deadline: item.Deadline, IdempotencyKey: item.IdempotencyKey,
		RequestID: uuid.NewString(), CorrelationID: uuid.NewString(), Reason: "challenge_redelivery",
	}, builder)
	if err != nil {
		return uuid.Nil, err
	}
	return result.Rollout.ID, nil
}

var _ edgepublish.ChallengeSecretRedeliverer = (*ChallengeSecretRedeliverer)(nil)

// PolicyDocument is the challenge policy document a publication of snapshot
// with keys stores as its config version's canonical snapshot (and the
// redelivery must rebuild byte for byte).
func PolicyDocument(snapshot PublicationSnapshot, keys ResolvedKeys) ([]byte, error) {
	material := buildArtifactMaterial(snapshot, keys)
	defer clearMaterial(&material)
	return json.Marshal(material.Policy)
}

// PostgresRedeliveryFactSource reads the binding's published document and
// policy revision in the redelivery's transaction.
type PostgresRedeliveryFactSource struct{}

func (PostgresRedeliveryFactSource) LoadRedeliveryFactsTx(
	ctx context.Context, tx pgx.Tx, item edgepublish.ChallengeRedelivery,
) (RedeliveryFacts, error) {
	if ctx == nil || tx == nil {
		return RedeliveryFacts{}, ErrInvalidRuntime
	}
	var facts RedeliveryFacts
	err := tx.QueryRow(ctx, `SELECT canonical_snapshot,generator_name FROM config_versions
		WHERE id=$1 AND configuration_scope_id=$2`, item.OriginConfigVersionID, item.ScopeID).
		Scan(&facts.OriginSnapshot, &facts.OriginGenerator)
	if errors.Is(err, pgx.ErrNoRows) {
		return RedeliveryFacts{}, ErrRedeliveryOriginMissing
	}
	if err != nil {
		return RedeliveryFacts{}, err
	}
	var routes []byte
	var provider, appReference *string
	policy := &facts.Policy
	err = tx.QueryRow(ctx, `SELECT policy_id,tenant_scope_id,tenant_id,site_id,host,revision,priority,mode,
		min_delay_seconds,challenge_ttl_seconds,pass_ttl_seconds,clock_skew_seconds,attempts_per_nonce,
		failure_window_seconds,max_failures_per_window,ip_binding,bind_user_agent,bypass_routes,key_reference,
		external_provider,external_app_reference
		FROM challenge_policy_revisions WHERE policy_id=$1 AND revision=$2 AND tenant_scope_id=$3 AND site_id=$4`,
		item.PolicyID, item.PolicyVersion, item.ScopeID, item.SiteID).Scan(&policy.PolicyID, &policy.TenantScopeID,
		&policy.TenantID, &policy.SiteID, &policy.Host, &policy.Revision, &policy.Priority, &policy.Mode,
		&policy.MinDelaySeconds, &policy.ChallengeTTLSeconds, &policy.PassTTLSeconds, &policy.ClockSkewSeconds,
		&policy.AttemptsPerNonce, &policy.FailureWindowSeconds, &policy.MaxFailuresPerWindow, &policy.IPBinding,
		&policy.BindUserAgent, &routes, &policy.KeyReference, &provider, &appReference)
	if errors.Is(err, pgx.ErrNoRows) {
		zeroBytes(facts.OriginSnapshot)
		return RedeliveryFacts{}, ErrRedeliveryOriginMissing
	}
	if err != nil {
		zeroBytes(facts.OriginSnapshot)
		return RedeliveryFacts{}, err
	}
	if err := json.Unmarshal(routes, &policy.BypassRoutes); err != nil || (provider == nil) != (appReference == nil) {
		zeroBytes(facts.OriginSnapshot)
		return RedeliveryFacts{}, ErrRedeliveryOriginMissing
	}
	if policy.BypassRoutes == nil {
		policy.BypassRoutes = []BypassRoute{} // as publication passes them (never null)
	}
	if provider != nil {
		policy.ExternalProvider = &ExternalProviderReference{Provider: *provider, AppReference: *appReference}
	}
	return facts, nil
}

var _ RedeliveryFactSource = PostgresRedeliveryFactSource{}
