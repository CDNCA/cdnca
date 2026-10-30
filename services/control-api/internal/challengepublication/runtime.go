package challengepublication

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
)

const (
	StateQueued  = "queued"
	StateRunning = "running"
	StateHealthy = "healthy"
	StateFailed  = "failed"
	StateActive  = "active"

	ReasonWaitingForNodes           = "waiting_for_nodes"
	ReasonNodeApplyFailed           = "node_apply_failed"
	ReasonExternalAdapterMissing    = "external_adapter_missing"
	ReasonConfigurationPublishFail  = "configuration_publish_failed"
	ExternalCredentialSchemaVersion = "cdnca.challenge.external-credential/v1"
)

var (
	ErrInvalidRuntime             = errors.New("invalid challenge publication runtime")
	ErrKeyUnavailable             = errors.New("challenge key unavailable")
	ErrExternalAdapterUnavailable = errors.New("external challenge adapter unavailable")
	ErrRolloutNotHealthy          = errors.New("challenge rollout is not healthy")
	ErrRolloutFailed              = errors.New("challenge rollout failed")
)

type ExternalProviderReference struct {
	Provider     string
	AppReference string
}

type PublicationSnapshot struct {
	PolicyID, TenantScopeID, TenantID, SiteID uuid.UUID
	Host                                      string
	Revision                                  int64
	Priority                                  int
	Mode                                      string
	MinDelaySeconds                           int
	ChallengeTTLSeconds                       int
	PassTTLSeconds                            int
	ClockSkewSeconds                          int
	AttemptsPerNonce                          int
	FailureWindowSeconds                      int
	MaxFailuresPerWindow                      int
	IPBinding                                 string
	BindUserAgent                             bool
	BypassRoutes                              []BypassRoute
	KeyReference                              string
	ExternalProvider                          *ExternalProviderReference
}

type ResolvedKeys struct {
	Current            ArtifactSecret
	Previous           *ArtifactSecret
	ExternalCredential *ExternalCredentialSecret
}

type ExternalCredentialSecret struct {
	SchemaVersion string `json:"schema_version"`
	Provider      string `json:"provider"`
	AppID         string `json:"app_id"`
	Secret        []byte `json:"secret"`
	Environment   string `json:"environment"`
}

type PublishRequest struct {
	Policy               PublicationSnapshot
	Actor                edgedeployment.Actor
	EdgeActor            edgepublish.Actor
	NodeIDs              []uuid.UUID
	RequiredCapabilities []*agentv1.Capability
	HealthCheck          edgedeployment.HealthCheckPolicy
	Deadline             time.Time
	IdempotencyKey       string
	RequestID            string
	CorrelationID        string
	Traceparent          string
	TaskID               *string
}

type SecretPublication struct {
	RolloutID, ConfigVersionID uuid.UUID
	Revision                   int64
	Replayed                   bool
}

type StatusRequest struct {
	Actor         edgedeployment.Actor
	TenantScopeID uuid.UUID
	RolloutID     uuid.UUID
}

type RolloutStatus struct {
	RolloutID       uuid.UUID `json:"rollout_id"`
	ConfigVersionID uuid.UUID `json:"-"`
	Revision        int64     `json:"-"`
	State           string    `json:"state"`
	Reason          string    `json:"reason"`
	Total           int       `json:"total"`
	Pending         int       `json:"pending"`
	Running         int       `json:"running"`
	Healthy         int       `json:"healthy"`
	Failed          int       `json:"failed"`
	Cancelled       int       `json:"cancelled"`
	// Superseded: nodes that ignored the secret as an old release
	// (edgedeployment.DeploymentSuperseded); not failed (fix-cfgflow3).
	Superseded int `json:"superseded"`
}

type BindingRequest struct {
	TenantScopeID, TenantID, SiteID, PolicyID uuid.UUID
	Host                                      string
	PolicyRevision                            int64
	Secret                                    SecretPublication
	Actor                                     edgepublish.Actor
	// NodeIDs get the binding; DeferredNodeIDs (NodeReadiness.Deferred) are
	// held for it and left to the challenge redeliverer.
	NodeIDs, DeferredNodeIDs                 []uuid.UUID
	HealthCheck                              edgedeployment.HealthCheckPolicy
	Deadline                                 time.Time
	IdempotencyKey, RequestID, CorrelationID string
	Traceparent                              string
	TaskID                                   *string
}

type ConfigPublication struct {
	PublicationID uuid.UUID `json:"publication_id"`
	Revision      int64     `json:"revision"`
}

type PromoteRequest struct {
	PublishRequest
	Secret SecretPublication
	// Readiness classifies every node of PublishRequest.NodeIDs (the secret
	// rollout's nodes) exactly once (ClassifyPromotionNodes).
	Readiness NodeReadiness
}

// PromotionNodeFact is one secret rollout node at promotion time: its
// deployment's state and whether the node can take commands now.
type PromotionNodeFact struct {
	NodeID          uuid.UUID
	DeploymentState string
	// Superseded: the deployment failed as an ignored old release
	// (edgedeployment.SupersededDeploymentSQL).
	Superseded     bool
	DeadlinePassed bool
	// Active: admin_state active. Online: an online session. Isolated: the
	// node isolation state is isolated.
	Active, Online, Isolated bool
}

// NodeReadiness splits a challenge secret rollout's nodes for promotion,
// each list sorted:
//   - Ready: installed the policy (a healthy deployment) on an active node;
//     the binding is published to them.
//   - Waiting: online, still applying within its deadline; holds the promotion.
//   - Failed: online, failed, cancelled or past its deadline; refuses it.
//   - Deferred: offline, isolated, disabled, no longer planned or ignored the
//     secret as an old release (it runs a newer revision); does not
//     hold the promotion back: the binding is held for them and the
//     redeliverer completes them once they are back.
type NodeReadiness struct {
	Ready, Waiting, Failed, Deferred []uuid.UUID
}

// ClassifyPromotionNodes classifies facts; a node outside planned (the
// scope's current targets) is deferred.
func ClassifyPromotionNodes(facts []PromotionNodeFact, planned []uuid.UUID) NodeReadiness {
	var result NodeReadiness
	for _, fact := range facts {
		switch {
		case !fact.Active || !slices.Contains(planned, fact.NodeID):
			result.Deferred = append(result.Deferred, fact.NodeID)
		case fact.DeploymentState == "healthy":
			result.Ready = append(result.Ready, fact.NodeID)
		case !fact.Online || fact.Isolated || fact.Superseded:
			result.Deferred = append(result.Deferred, fact.NodeID)
		case terminalDeploymentState(fact.DeploymentState) || fact.DeadlinePassed:
			result.Failed = append(result.Failed, fact.NodeID)
		default:
			result.Waiting = append(result.Waiting, fact.NodeID)
		}
	}
	for _, list := range []*[]uuid.UUID{&result.Ready, &result.Waiting, &result.Failed, &result.Deferred} {
		slices.SortFunc(*list, compareNodeID)
	}
	return result
}

func terminalDeploymentState(state string) bool {
	return state == "failed" || state == "reverted" || state == "rollback_failed" || state == "cancelled"
}

func compareNodeID(left, right uuid.UUID) int { return bytes.Compare(left[:], right[:]) }

// covers reports whether readiness lists every node exactly once.
func (readiness NodeReadiness) covers(nodeIDs []uuid.UUID) bool {
	all := slices.Concat(readiness.Ready, readiness.Waiting, readiness.Failed, readiness.Deferred)
	want := slices.Clone(nodeIDs)
	slices.SortFunc(all, compareNodeID)
	slices.SortFunc(want, compareNodeID)
	return slices.Equal(all, want) && len(slices.Compact(slices.Clone(want))) == len(want)
}

type PromotionStatus struct {
	RolloutStatus
	ConfigPublication *ConfigPublication `json:"config_publication,omitempty"`
}

type KeyResolver interface {
	ResolveChallengeKeys(context.Context, PublicationSnapshot) (ResolvedKeys, error)
}

type KeyResolverFunc func(context.Context, PublicationSnapshot) (ResolvedKeys, error)

func (resolve KeyResolverFunc) ResolveChallengeKeys(
	ctx context.Context, snapshot PublicationSnapshot,
) (ResolvedKeys, error) {
	if resolve == nil {
		return ResolvedKeys{}, ErrKeyUnavailable
	}
	keys, err := resolve(ctx, snapshot)
	if err != nil {
		return ResolvedKeys{}, err
	}
	return cloneResolvedKeys(keys), nil
}

type SecretPublisher interface {
	PublishChallengeSecret(context.Context, PublishRequest, ArtifactMaterial) (SecretPublication, error)
}

type RolloutReader interface {
	ChallengeRolloutStatus(context.Context, StatusRequest) (RolloutStatus, error)
}

type ConfigPublisher interface {
	PublishChallengeBinding(context.Context, BindingRequest) (ConfigPublication, error)
}

type ConfigPublisherFunc func(context.Context, BindingRequest) (ConfigPublication, error)

func (publish ConfigPublisherFunc) PublishChallengeBinding(
	ctx context.Context, request BindingRequest,
) (ConfigPublication, error) {
	if publish == nil {
		return ConfigPublication{}, ErrInvalidRuntime
	}
	return publish(ctx, request)
}

type Runtime struct {
	keys     KeyResolver
	secrets  SecretPublisher
	rollouts RolloutReader
	configs  ConfigPublisher
}

func NewRuntime(keys KeyResolver, secrets SecretPublisher, rollouts RolloutReader, configs ConfigPublisher) (*Runtime, error) {
	if nilDependency(keys) || nilDependency(secrets) || nilDependency(rollouts) || nilDependency(configs) {
		return nil, ErrInvalidRuntime
	}
	return &Runtime{keys: keys, secrets: secrets, rollouts: rollouts, configs: configs}, nil
}

func (runtime *Runtime) Publish(ctx context.Context, request PublishRequest) (SecretPublication, error) {
	if runtime == nil || ctx == nil || !validPublishRequest(request) {
		return SecretPublication{}, ErrInvalidRuntime
	}
	keys, err := runtime.keys.ResolveChallengeKeys(ctx, request.Policy)
	if err != nil || !validResolvedKeys(keys) || !validExternalResolvedKeys(request.Policy, keys) {
		clearResolvedKeys(&keys)
		return SecretPublication{}, ErrKeyUnavailable
	}
	defer clearResolvedKeys(&keys)
	material := buildArtifactMaterial(request.Policy, keys)
	defer clearMaterial(&material)
	result, err := runtime.secrets.PublishChallengeSecret(ctx, request, material)
	if err != nil {
		return SecretPublication{}, err
	}
	if result.RolloutID == uuid.Nil || result.ConfigVersionID == uuid.Nil || result.Revision < 1 {
		return SecretPublication{}, ErrInvalidRuntime
	}
	return result, nil
}

func validExternalResolvedKeys(snapshot PublicationSnapshot, keys ResolvedKeys) bool {
	if snapshot.Mode != "external" {
		return snapshot.ExternalProvider == nil && keys.ExternalCredential == nil
	}
	credential := keys.ExternalCredential
	return snapshot.ExternalProvider != nil && credential != nil &&
		credential.SchemaVersion == ExternalCredentialSchemaVersion &&
		credential.Provider == snapshot.ExternalProvider.Provider && validIdentifier(credential.AppID) &&
		len(credential.Secret) >= 16 && len(credential.Secret) <= 256 &&
		(credential.Environment == "sandbox" || credential.Environment == "production")
}

func (runtime *Runtime) Status(ctx context.Context, request StatusRequest) (RolloutStatus, error) {
	if runtime == nil || ctx == nil || request.Actor.UserID == uuid.Nil || request.TenantScopeID == uuid.Nil ||
		request.RolloutID == uuid.Nil {
		return RolloutStatus{}, ErrInvalidRuntime
	}
	status, err := runtime.rollouts.ChallengeRolloutStatus(ctx, request)
	if err != nil {
		return RolloutStatus{}, err
	}
	if !validRolloutStatus(status, request.RolloutID) {
		return RolloutStatus{}, ErrInvalidRuntime
	}
	return status, nil
}

func (runtime *Runtime) Promote(ctx context.Context, request PromoteRequest) (PromotionStatus, error) {
	if runtime == nil || ctx == nil || !validPublishRequest(request.PublishRequest) ||
		request.Secret.RolloutID == uuid.Nil || request.Secret.ConfigVersionID == uuid.Nil || request.Secret.Revision < 1 {
		return PromotionStatus{}, ErrInvalidRuntime
	}
	status, err := runtime.rollouts.ChallengeRolloutStatus(ctx, StatusRequest{
		Actor: request.Actor, TenantScopeID: request.Policy.TenantScopeID, RolloutID: request.Secret.RolloutID,
	})
	if err != nil {
		return PromotionStatus{}, err
	}
	if !validRolloutStatus(status, request.Secret.RolloutID) {
		return PromotionStatus{}, ErrInvalidRuntime
	}
	readiness := request.Readiness
	if !readiness.covers(request.NodeIDs) {
		return PromotionStatus{}, ErrInvalidRuntime
	}
	// The gate is the nodes' readiness, not the rollout as a whole: a node
	// offline, isolated or disabled keeps the rollout running (or past its
	// deadline, failed) without holding the promotion back.
	result := PromotionStatus{RolloutStatus: status}
	switch {
	case len(readiness.Failed) > 0:
		result.State, result.Reason = StateFailed, ReasonNodeApplyFailed
		return result, ErrRolloutFailed
	case len(readiness.Waiting) > 0 || len(readiness.Ready) == 0:
		result.State, result.Reason = StateRunning, ReasonWaitingForNodes
		return result, ErrRolloutNotHealthy
	}
	publication, err := runtime.configs.PublishChallengeBinding(ctx, BindingRequest{
		TenantScopeID: request.Policy.TenantScopeID, TenantID: request.Policy.TenantID,
		SiteID: request.Policy.SiteID, PolicyID: request.Policy.PolicyID,
		Host: request.Policy.Host, PolicyRevision: request.Policy.Revision, Secret: request.Secret,
		Actor: request.EdgeActor, NodeIDs: slices.Clone(readiness.Ready),
		DeferredNodeIDs: slices.Clone(readiness.Deferred), HealthCheck: request.HealthCheck,
		Deadline: request.Deadline, IdempotencyKey: request.IdempotencyKey + ".binding",
		RequestID: request.RequestID, CorrelationID: request.CorrelationID,
		Traceparent: request.Traceparent, TaskID: request.TaskID,
	})
	if err != nil {
		result.State, result.Reason = StateFailed, ReasonConfigurationPublishFail
		return result, err
	}
	if publication.PublicationID == uuid.Nil || publication.Revision < 1 {
		return PromotionStatus{}, ErrInvalidRuntime
	}
	result.State, result.Reason, result.ConfigPublication = StateActive, "-", &publication
	return result, nil
}

func validPublishRequest(request PublishRequest) bool {
	policy := request.Policy
	return policy.PolicyID != uuid.Nil && policy.TenantScopeID != uuid.Nil && policy.TenantID != uuid.Nil &&
		policy.SiteID != uuid.Nil && policy.Revision > 0 && policy.Host != "" && policy.KeyReference != "" &&
		policy.Priority > 0 && (policy.Mode == "delay" || policy.Mode == "click" || policy.Mode == "slider" ||
		policy.Mode == "captcha" || policy.Mode == "external") && len(request.NodeIDs) > 0 && request.IdempotencyKey != ""
}

func validResolvedKeys(keys ResolvedKeys) bool {
	if keys.Current.KeyID == "" || len(keys.Current.Secret) < 32 || len(keys.Current.Secret) > 128 {
		return false
	}
	return keys.Previous == nil || keys.Previous.KeyID != "" && keys.Previous.KeyID != keys.Current.KeyID &&
		len(keys.Previous.Secret) >= 32 && len(keys.Previous.Secret) <= 128
}

func buildArtifactMaterial(snapshot PublicationSnapshot, keys ResolvedKeys) ArtifactMaterial {
	policy := Policy{
		SchemaVersion: PolicySchemaVersion, PolicyVersion: uint64(snapshot.Revision), Algorithm: "hmac-sha256",
		CookieName: "cdnca_challenge", TrustedProxies: []string{}, BypassRoutes: slices.Clone(snapshot.BypassRoutes),
		CurrentKey: KeyReference{KeyID: keys.Current.KeyID},
		Rules: []Rule{{
			RuleID: snapshot.PolicyID.String(), Priority: uint32(snapshot.Priority), TenantID: snapshot.TenantID.String(),
			SiteID: snapshot.SiteID.String(), Host: snapshot.Host, Mode: snapshot.Mode,
			MinDelaySeconds: uint32(snapshot.MinDelaySeconds), ChallengeTTLSeconds: uint32(snapshot.ChallengeTTLSeconds),
			PassTTLSeconds: uint32(snapshot.PassTTLSeconds), ClockSkewSeconds: uint32(snapshot.ClockSkewSeconds),
			AttemptsPerNonce: uint32(snapshot.AttemptsPerNonce), FailureWindowSeconds: uint32(snapshot.FailureWindowSeconds),
			MaxFailuresPerWindow: uint32(snapshot.MaxFailuresPerWindow), IPBinding: snapshot.IPBinding,
			BindUserAgent: snapshot.BindUserAgent,
		}},
	}
	result := ArtifactMaterial{PolicyID: snapshot.PolicyID, TenantID: snapshot.TenantID, Policy: policy,
		Keys: []ArtifactSecret{{KeyID: keys.Current.KeyID, Secret: slices.Clone(keys.Current.Secret)}}}
	if snapshot.ExternalProvider != nil && keys.ExternalCredential != nil {
		result.Policy.Rules[0].ExternalProvider = &ExternalProvider{
			Provider: keys.ExternalCredential.Provider, AppID: keys.ExternalCredential.AppID,
		}
		result.ExternalCredentials = []ExternalCredential{{TenantID: snapshot.TenantID.String(),
			SiteID: snapshot.SiteID.String(), Provider: keys.ExternalCredential.Provider,
			AppID: keys.ExternalCredential.AppID, Secret: slices.Clone(keys.ExternalCredential.Secret),
			Environment: keys.ExternalCredential.Environment}}
	}
	if keys.Previous != nil {
		policyKey := KeyReference{KeyID: keys.Previous.KeyID}
		result.Policy.PreviousKey = &policyKey
		result.Keys = append(result.Keys, ArtifactSecret{KeyID: keys.Previous.KeyID, Secret: slices.Clone(keys.Previous.Secret)})
	}
	return result
}

func validRolloutStatus(status RolloutStatus, rolloutID uuid.UUID) bool {
	if status.RolloutID != rolloutID || status.ConfigVersionID == uuid.Nil || status.Revision < 1 ||
		status.Total < 1 || status.Total > 10000 || status.Pending < 0 ||
		status.Running < 0 || status.Healthy < 0 || status.Failed < 0 || status.Cancelled < 0 || status.Superseded < 0 ||
		status.Pending+status.Running+status.Healthy+status.Failed+status.Cancelled+status.Superseded != status.Total {
		return false
	}
	switch status.State {
	case StateQueued, StateRunning:
		return status.Reason == "" || status.Reason == ReasonWaitingForNodes
	case StateHealthy:
		return status.Healthy+status.Superseded == status.Total && status.Reason == ""
	case StateFailed:
		return status.Failed > 0 && status.Reason == ReasonNodeApplyFailed
	default:
		return false
	}
}

func clearResolvedKeys(keys *ResolvedKeys) {
	if keys == nil {
		return
	}
	zeroBytes(keys.Current.Secret)
	if keys.Previous != nil {
		zeroBytes(keys.Previous.Secret)
	}
	if keys.ExternalCredential != nil {
		zeroBytes(keys.ExternalCredential.Secret)
	}
	*keys = ResolvedKeys{}
}

func cloneResolvedKeys(keys ResolvedKeys) ResolvedKeys {
	result := ResolvedKeys{Current: ArtifactSecret{KeyID: keys.Current.KeyID, Secret: slices.Clone(keys.Current.Secret)}}
	if keys.Previous != nil {
		result.Previous = &ArtifactSecret{KeyID: keys.Previous.KeyID, Secret: slices.Clone(keys.Previous.Secret)}
	}
	if keys.ExternalCredential != nil {
		value := *keys.ExternalCredential
		value.Secret = slices.Clone(keys.ExternalCredential.Secret)
		result.ExternalCredential = &value
	}
	return result
}

func clearMaterial(material *ArtifactMaterial) {
	if material == nil {
		return
	}
	for index := range material.Keys {
		zeroBytes(material.Keys[index].Secret)
	}
	for index := range material.ExternalCredentials {
		zeroBytes(material.ExternalCredentials[index].Secret)
	}
	*material = ArtifactMaterial{}
}

func nilDependency(value any) bool {
	if value == nil {
		return true
	}
	kind := reflect.ValueOf(value).Kind()
	return (kind == reflect.Interface || kind == reflect.Pointer || kind == reflect.Func) && reflect.ValueOf(value).IsNil()
}

type secretRolloutStore interface {
	CreateSecretRollout(context.Context, edgedeployment.SecretRolloutRequest, edgedeployment.SecretArtifactBuilder) (edgedeployment.CreateRolloutResult, error)
}

type DurableSecretPublisher struct {
	store    secretRolloutStore
	producer *ArtifactProducer
}

func NewDurableSecretPublisher(store secretRolloutStore, producer *ArtifactProducer) (*DurableSecretPublisher, error) {
	if nilDependency(store) || producer == nil {
		return nil, ErrInvalidRuntime
	}
	return &DurableSecretPublisher{store: store, producer: producer}, nil
}

func (publisher *DurableSecretPublisher) PublishChallengeSecret(
	ctx context.Context, request PublishRequest, material ArtifactMaterial,
) (SecretPublication, error) {
	if publisher == nil || ctx == nil {
		return SecretPublication{}, ErrInvalidRuntime
	}
	builder, err := NewSecretArtifactBuilder(publisher.producer, material)
	if err != nil {
		return SecretPublication{}, err
	}
	snapshot, err := json.Marshal(material.Policy)
	if err != nil {
		return SecretPublication{}, err
	}
	digest := sha256.Sum256(snapshot)
	result, err := publisher.store.CreateSecretRollout(ctx, edgedeployment.SecretRolloutRequest{
		Actor: request.Actor, ConfigurationScopeID: request.Policy.TenantScopeID, NodeIDs: slices.Clone(request.NodeIDs),
		CanonicalSnapshot: snapshot, GeneratorName: edgepublish.ChallengeSecretGeneratorName, GeneratorVersion: "1.0.0",
		PayloadDigest: digest, RequiredCapabilities: request.RequiredCapabilities, HealthCheck: request.HealthCheck,
		Deadline: request.Deadline, IdempotencyKey: request.IdempotencyKey, RequestID: request.RequestID,
		CorrelationID: request.CorrelationID, Traceparent: request.Traceparent, TaskID: request.TaskID,
	}, builder)
	zeroBytes(snapshot)
	if err != nil {
		return SecretPublication{}, err
	}
	return SecretPublication{RolloutID: result.Rollout.ID, ConfigVersionID: result.Rollout.ConfigVersionID,
		Revision: result.Rollout.Revision, Replayed: result.Replayed}, nil
}

type rolloutStore interface {
	GetRollout(context.Context, edgedeployment.Actor, uuid.UUID, uuid.UUID) (edgedeployment.RolloutSnapshot, error)
}

type DurableRolloutReader struct{ store rolloutStore }

func NewDurableRolloutReader(store rolloutStore) (*DurableRolloutReader, error) {
	if nilDependency(store) {
		return nil, ErrInvalidRuntime
	}
	return &DurableRolloutReader{store: store}, nil
}

var _ KeyResolver = KeyResolverFunc(nil)

var _ ConfigPublisher = ConfigPublisherFunc(nil)

func (reader *DurableRolloutReader) ChallengeRolloutStatus(ctx context.Context, request StatusRequest) (RolloutStatus, error) {
	if reader == nil || ctx == nil {
		return RolloutStatus{}, ErrInvalidRuntime
	}
	snapshot, err := reader.store.GetRollout(ctx, request.Actor, request.TenantScopeID, request.RolloutID)
	if err != nil {
		return RolloutStatus{}, err
	}
	status := RolloutStatus{RolloutID: snapshot.ID, ConfigVersionID: snapshot.ConfigVersionID, Revision: snapshot.Revision,
		Total: snapshot.Progress.Total, Pending: snapshot.Progress.Pending,
		Running: snapshot.Progress.Running, Healthy: snapshot.Progress.Succeeded, Failed: snapshot.Progress.Failed,
		Cancelled: snapshot.Progress.Cancelled, Superseded: snapshot.Progress.Superseded}
	switch snapshot.State {
	case edgedeployment.RolloutStateQueued:
		status.State, status.Reason = StateQueued, ReasonWaitingForNodes
	case edgedeployment.RolloutStateRunning:
		status.State, status.Reason = StateRunning, ReasonWaitingForNodes
	case edgedeployment.RolloutStateSucceeded:
		status.State = StateHealthy
	case edgedeployment.RolloutStateFailed, edgedeployment.RolloutStatePartialFailed, edgedeployment.RolloutStateCancelled:
		status.State, status.Reason = StateFailed, ReasonNodeApplyFailed
	default:
		return RolloutStatus{}, ErrInvalidRuntime
	}
	return status, nil
}
