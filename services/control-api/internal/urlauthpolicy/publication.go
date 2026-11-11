package urlauthpolicy

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ErrPublicationUnavailable: an enabled policy cannot reach its nodes (no
// edge publication runtime); the write is refused rather than shown as
// protecting a site it does not (url_auth_unavailable).
var ErrPublicationUnavailable = fmt.Errorf("%w: URL auth publication is unavailable", ErrUnavailable)

// Publisher delivers an enabled policy version to the nodes of its scope in
// the policy write's transaction.
type Publisher interface {
	PublishURLAuthPolicyTx(ctx context.Context, tx pgx.Tx, actorUserID uuid.UUID, item Policy, requestID string) error
}

// SetPublisher installs the publisher of enabled policies.
func (s *Service) SetPublisher(publisher Publisher) {
	if s != nil && s.store != nil {
		s.store.publisher = publisher
	}
}

// afterWrite runs in every policy write's transaction: an enabled policy's
// version is delivered first (its secret rollout), then the scope's
// configuration advances and its automatic publication is queued, so the
// site objects name (or stop naming) the version (edgepublish
// bindSiteRuntimeV2URLAuth). A disabled policy needs no delivery.
func (s *Store) afterWrite(ctx context.Context, tx pgx.Tx, actorUserID uuid.UUID, item Policy, requestID string) error {
	if item.Enabled {
		if s.publisher == nil {
			return ErrPublicationUnavailable
		}
		if err := s.publisher.PublishURLAuthPolicyTx(ctx, tx, actorUserID, item, requestID); err != nil {
			return err
		}
	}
	var siteScopeID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT scope_id FROM sites WHERE id=$1`, item.Site.ID).Scan(&siteScopeID); err != nil {
		return fmt.Errorf("read URL auth policy site scope: %w", err)
	}
	if _, err := tx.Exec(ctx, `SELECT advance_edge_configuration_scope_revision($1)`, siteScopeID); err != nil {
		return fmt.Errorf("advance URL auth edge configuration: %w", err)
	}
	if _, err := edgeautopublish.EnqueueSiteSettingTx(ctx, tx, siteScopeID, item.Site.ID, requestID); err != nil {
		return fmt.Errorf("queue URL auth site publication: %w", err)
	}
	return nil
}

// URLAuthAPIVersion is CAPABILITY_NAME_URL_AUTH v1.
const URLAuthAPIVersion uint32 = 1

const (
	publicationGenerator = "url-auth-policy"
	publicationDeadline  = 15 * time.Minute
)

type systemSecretRolloutStore interface {
	CreateSystemSecretRolloutTx(context.Context, pgx.Tx, edgedeployment.SystemSecretRolloutRequest,
		edgedeployment.SecretArtifactBuilder) (edgedeployment.CreateRolloutResult, error)
}

// ArtifactPublisher is the production Publisher: a system secret rollout
// of the policy version (ArtifactProducer, HPKE to each node's artifact
// recipient key) to the scope's active nodes that declare URL_AUTH. A node
// without it is left out; the site's publication refuses it too.
type ArtifactPublisher struct {
	rollouts systemSecretRolloutStore
	cipher   BoundSecretCipher
	producer *ArtifactProducer
}

func NewArtifactPublisher(rollouts systemSecretRolloutStore, cipher BoundSecretCipher, producer *ArtifactProducer) (*ArtifactPublisher, error) {
	if rollouts == nil || cipher == nil || producer == nil {
		return nil, ErrUnavailable
	}
	return &ArtifactPublisher{rollouts: rollouts, cipher: cipher, producer: producer}, nil
}

func (publisher *ArtifactPublisher) PublishURLAuthPolicyTx(ctx context.Context, tx pgx.Tx, actorUserID uuid.UUID, item Policy, requestID string) error {
	if publisher == nil || ctx == nil || tx == nil || actorUserID == uuid.Nil || item.ID == uuid.Nil || !item.Enabled {
		return ErrInvalidInput
	}
	nodeIDs, err := urlAuthNodes(ctx, tx, item.ScopeID)
	if err != nil || len(nodeIDs) == 0 {
		return err // no node can take it yet: the site's publication refuses them
	}
	material, err := loadMaterialTx(ctx, tx, publisher.cipher, item.ID)
	if err != nil {
		return err
	}
	defer clearArtifactSecrets(material.Keys)
	snapshot, err := json.Marshal(material.Snapshot)
	if err != nil {
		return err
	}
	scopeID := item.ScopeID
	builder := func(ctx context.Context, binding edgedeployment.SecretArtifactBinding) (edgedeployment.ArtifactInput, error) {
		return publisher.producer.Build(ctx, ArtifactBuildRequest{
			EventID: binding.EventID, DeploymentID: binding.DeploymentID, ConfigVersionID: binding.ConfigVersionID,
			ArtifactID: binding.ArtifactID, ConfigurationScopeID: scopeID, Attempt: binding.Attempt,
			RecipientKeyID: binding.RecipientKeyID, RecipientPublicKey: binding.RecipientPublicKey,
		}, material)
	}
	if len(requestID) > 128 {
		requestID = requestID[:128]
	}
	_, err = publisher.rollouts.CreateSystemSecretRolloutTx(ctx, tx, edgedeployment.SystemSecretRolloutRequest{
		ConfigurationScopeID: scopeID, AccountableUserID: actorUserID, NodeIDs: nodeIDs,
		CanonicalSnapshot: snapshot, GeneratorName: publicationGenerator, GeneratorVersion: "1.0.0",
		PayloadDigest: sha256.Sum256(snapshot), RequiredCapabilities: requiredCapabilities(),
		HealthCheck: edgedeployment.HealthCheckPolicy{ActivationTimeout: 30 * time.Second,
			ObservationWindow: 15 * time.Second, RequiredConsecutiveSuccesses: 3},
		Deadline:       time.Now().UTC().Add(publicationDeadline),
		IdempotencyKey: fmt.Sprintf("url-auth-%s-%d", item.ID, item.Revision),
		RequestID:      uuid.NewString(), CorrelationID: uuid.NewString(), Reason: "url_auth_policy_publish",
	}, builder)
	return err
}

func requiredCapabilities() []*agentv1.Capability {
	return []*agentv1.Capability{
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_ATOMIC_RELEASE, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_CONFIG_PRECHECK, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_URL_AUTH, ApiVersion: URLAuthAPIVersion},
	}
}

// urlAuthNodes is the scope's active nodes whose session declares URL_AUTH.
func urlAuthNodes(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx, `SELECT id FROM nodes WHERE scope_id=$1 AND admin_state='active' ORDER BY id`, scopeID)
	if err != nil {
		return nil, fmt.Errorf("read URL auth nodes: %w", err)
	}
	nodeIDs, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil || len(nodeIDs) == 0 {
		return nil, err
	}
	refusal := edgepublish.ValidateFeatureCapabilityTargets(ctx, tx, nodeIDs, requiredCapabilities()[2:])
	if refusal == nil {
		return nodeIDs, nil
	}
	var target *edgepublish.TargetCapabilityError
	if !errors.As(refusal, &target) {
		return nil, refusal
	}
	refused := append([]uuid.UUID{target.NodeID}, target.OtherNodeIDs...)
	return slices.DeleteFunc(nodeIDs, func(id uuid.UUID) bool { return slices.Contains(refused, id) }), nil
}

// plainCipher adapts the control plane's credential cipher, which seals
// URL auth keys without associated data (Service.newKey), to the artifact
// publication's BoundSecretCipher.
type plainCipher struct {
	base interface {
		SecretCipher
		Decrypt(string, []byte) ([]byte, error)
	}
}

// PublicationCipher is cipher as the publication reads the keys Service
// sealed with it.
func PublicationCipher(cipher SecretCipher) (BoundSecretCipher, error) {
	if bound, ok := cipher.(BoundSecretCipher); ok {
		return bound, nil
	}
	base, ok := cipher.(interface {
		SecretCipher
		Decrypt(string, []byte) ([]byte, error)
	})
	if !ok || base == nil {
		return nil, ErrEncryptionUnavailable
	}
	return plainCipher{base: base}, nil
}

func (c plainCipher) Encrypt(value []byte) (string, []byte, error) { return c.base.Encrypt(value) }
func (c plainCipher) IdempotencyDigest(value []byte) [32]byte      { return c.base.IdempotencyDigest(value) }
func (c plainCipher) EncryptBound([]byte, []byte) (string, []byte, error) {
	return "", nil, ErrEncryptionUnavailable
}
func (c plainCipher) DecryptBound(keyID string, ciphertext, _ []byte) ([]byte, error) {
	return c.base.Decrypt(keyID, ciphertext)
}
func (c plainCipher) SecretDigest(value []byte) [32]byte { return c.base.IdempotencyDigest(value) }
