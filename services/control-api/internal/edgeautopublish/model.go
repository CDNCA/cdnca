package edgeautopublish

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

const (
	ModeManual    = "manual"
	ModeAutomatic = "automatic"

	ScopeKindTenant   = "tenant"
	ScopeKindPlatform = "platform"

	SourceSite = "site"
	SourceL4   = "l4"
	// SourceLineGroup: a line group used by the scope changed its node set (FX02).
	SourceLineGroup = "line_group"
	// SourceNodeSync: a node held for failed configuration sync is retried (NF04).
	SourceNodeSync = "node_sync"
	// SourceNodeCapability: a node the scope's publication refused gained
	// capabilities.
	SourceNodeCapability = "node_capability"
	// SourceRuleCatalog: a security rule catalog delivery changed the CRS
	// rule text the scope's release embeds; the
	// delivery is the source resource.
	SourceRuleCatalog = "rule_catalog"
	// SourceChallengeDelivery: a node confirmed the JS challenge policy the
	// control plane redelivered to it; the node is
	// the source resource.
	SourceChallengeDelivery = "challenge_delivery"
	// SourceModuleEntitlement: the lease grants again a module the scope's
	// latest publication uses; the source resource is
	// ModuleEntitlementSourceID.
	SourceModuleEntitlement = "module_entitlement"
	// SourceNodeNetworks: the platform's node addresses changed and the
	// scope's latest release exempts the old ones from DDoS protection
	//; the source resource is NodeNetworksSourceID.
	SourceNodeNetworks = "node_networks"

	OperationLineGroupNodesChanged  = "line_group.nodes_changed"
	OperationNodeSyncRetry          = "node.sync_retry"
	OperationNodeCapabilitiesChange = "node.capabilities_changed"
	OperationRuleCatalogUpdated     = "security_rule_catalog.updated"
	OperationNodeChallengeDelivered = "node.challenge_delivered"
	OperationModulesGranted         = "entitlement.modules_granted"
	OperationNodeNetworksChanged    = "node.networks_changed"

	PermissionSitesManage   = "sites.manage"
	PermissionStreamsManage = "streams.manage"

	ReasonResourceMutation   = "resource_mutation"
	ReasonNodeSetChanged     = "node_set_changed"
	ReasonSyncRetry          = "sync_retry"
	ReasonCapabilityChange   = "capability_changed"
	ReasonCatalogChange      = "catalog_changed"
	ReasonChallengeDelivered = "challenge_delivered"
	ReasonEntitlementChanged = "entitlement_changed"
	ReasonNodeNetworksChange = "node_networks_changed"

	StatePending     = "pending"
	StateLeased      = "leased"
	StateRetryWait   = "retry_wait"
	StateReconciling = "reconciling"
	StateSucceeded   = "succeeded"
	StateFailed      = "failed"
	StateSuperseded  = "superseded"

	SuccessApplyHealthy       = "apply_healthy"
	SuccessRollbackReverted   = "rollback_reverted"
	FailureRBACRevoked        = "rbac_revoked"
	FailurePublishUnknown     = "publish_outcome_unknown"
	FailureActorUnavailable   = "publication_actor_unavailable"
	FailureApplyReverted      = "apply_reverted"
	FailureRollbackUnexpected = "rollback_unexpected_state"
	FailureDeploymentFailed   = "deployment_failed"
	FailureRollbackFailed     = "rollback_failed"
	FailureCancelled          = "cancelled"
	// FailureNoTargetNodes: no node serves the scope's line groups (nor its
	// packages' primary/backup groups). A node joining one republishes (FX02).
	FailureNoTargetNodes = "no_target_nodes"
	// FailureNodeCapability: every target node lacks a capability or JS
	// challenge policy the release needs. The refusal is held and
	// republished once a node has it.
	FailureNodeCapability = "node_capability_unavailable"
	// FailureNodeArtifactsSyncing: every target node is refused only because
	// a node artifact the release needs (a rule pack, the IP library) has not
	// reached it yet through its node artifact set (O2). The refusal is held
	// and republished once the node applies the set.
	FailureNodeArtifactsSyncing = "node_artifacts_syncing"
	// FailureNodeScopeConflict: a target node refuses the scope because of
	// another tenant's configuration there (edgepublish.CrossScopeConflictError,
	// e.g. a domain or port that tenant already serves). Retrying cannot change it; the
	// refusal is in the edge_publication.node_scope_conflict audit (adm-fix-a2:
	// 73 retried one 350 times as publish_outcome_unknown until its deadline).
	FailureNodeScopeConflict = "node_scope_conflict"
)

var (
	ErrInvalidInput        = errors.New("invalid automatic edge publication input")
	ErrPermissionDenied    = errors.New("automatic edge publication permission denied")
	ErrIdempotencyConflict = errors.New("automatic edge publication idempotency conflict")
	ErrStaleClaim          = errors.New("automatic edge publication claim is stale")
	ErrNoTargetNodes       = errors.New("automatic edge publication has no target nodes")
)

type Actor struct {
	UserID    uuid.UUID
	ScopeID   uuid.UUID
	ScopeKind string
}

type TargetSnapshot struct {
	ID       uuid.UUID
	Revision int64
	SHA256   [32]byte
}

type Policy struct {
	TargetScopeID                uuid.UUID
	Revision                     int64
	Mode                         string
	NodeIDs                      []uuid.UUID
	TargetSnapshot               *TargetSnapshot
	ActivationTimeout            time.Duration
	ObservationWindow            time.Duration
	RequiredConsecutiveSuccesses uint32
	MaxAttempts                  uint32
	DeadlineWindow               time.Duration
}

type EnqueueInput struct {
	Actor                       Actor
	TargetScopeID               uuid.UUID
	SourceKind                  string
	SourceResourceID            uuid.UUID
	Operation                   string
	Reason                      string
	Permission                  string
	SourceRequestID             string
	PublishIntentID             uuid.UUID
	ConfigurationSourceRevision int64
}

type EnqueueResult struct {
	RequestID uuid.UUID
	Enqueued  bool
	Replayed  bool
}

type Request struct {
	ID               uuid.UUID
	TargetScopeID    uuid.UUID
	ActorScopeID     uuid.UUID
	ActorUserID      uuid.UUID
	ActorScopeKind   string
	SourceKind       string
	SourceResourceID uuid.UUID
	PublishIntentID  uuid.UUID
	SourceRevision   int64
	Operation        string
	Reason           string
	Permission       string
	SourceRequestID  string
	IdempotencyKey   string
	CorrelationID    uuid.UUID
	RequestDigest    [32]byte
	PolicyRevision   int64
	CreatedAt        time.Time
}

type Claim struct {
	Request       Request
	Policy        Policy
	LeaseToken    uuid.UUID
	StateSequence int64
	Attempt       int
}

func IsStaleClaim(err error) bool { return errors.Is(err, ErrStaleClaim) }
