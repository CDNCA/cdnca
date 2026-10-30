package edgepublish

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrInvalidInput           = errors.New("invalid edge publication input")
	ErrNoActiveResources      = errors.New("edge publication has no active resources")
	ErrTLSMaterialUnavailable = errors.New("edge publication TLS material is unavailable")
	ErrIdempotencyConflict    = errors.New("edge publication idempotency conflict")
	ErrRevisionConflict       = errors.New("edge publication source revision conflict")
	// ErrAlreadyPublished (P10): the expected source revision is current but
	// already has a publication; nothing new to publish. It is a
	// ErrRevisionConflict for callers that do not tell the two apart.
	ErrAlreadyPublished        = fmt.Errorf("%w: source revision is already published", ErrRevisionConflict)
	ErrUnauthenticated         = errors.New("edge publication authentication required")
	ErrPermissionDenied        = errors.New("edge publication permission denied")
	ErrEntitlementDenied       = errors.New("edge publication entitlement denied")
	ErrAutomaticRequestExpired = errors.New("automatic edge publication request expired")
	ErrTargetIneligible        = errors.New("edge publication target is ineligible")
	ErrTargetSnapshotConflict  = errors.New("edge publication target snapshot conflict")
	// ErrSiteL2Unavailable: a site's custom L2 configuration has no node
	// among the target's L2 endpoints (site-backend6).
	ErrSiteL2Unavailable         = errors.New("site custom L2 configuration has no L2 node in the publication target")
	ErrUnsupportedSecurityPolicy = errors.New("edge security policy cannot be represented safely")
	ErrSecurityPolicyBudget      = errors.New("edge security policy exceeds bundle budget")
	ErrNotFound                  = errors.New("edge publication not found")
	ErrSigningFailed             = errors.New("edge configuration signing failed")
	ErrPersistence               = errors.New("edge publication persistence failed")
)

const (
	canonicalTargetSchema     = "cdnca.edge.target-snapshot/v1"
	ScopeKindPlatform         = "platform"
	ScopeKindTenant           = "tenant"
	PermissionRead            = "edge_publications.read"
	PermissionManage          = "edge_publications.manage"
	EntitlementStatusValid    = "valid"
	EntitlementStatusGrace    = "grace"
	TargetKindExplicit        = "explicit"
	TargetKindResolver        = "resolver"
	maxPublicationTargets     = 10000
	maxCanonicalSnapshotBytes = maxSiteRuntimeV2DocumentBytes
)

type ArtifactSigner interface {
	KeyID() string
	PublicKey() ed25519.PublicKey
	Sign(context.Context, []byte) ([]byte, error)
}

type AuditAppender interface {
	Append(context.Context, pgx.Tx, audit.Event) error
}

type EntitlementAuthorizer interface {
	AuthorizePublication(context.Context, pgx.Tx, EntitlementRequest) (EntitlementDecision, error)
}

type TargetResolver interface {
	ResolveTarget(context.Context, pgx.Tx, uuid.UUID, TargetSnapshotReference) (TargetSnapshot, error)
}

type AutomaticPublicationCoordinator interface {
	PrepareAutomaticPublication(
		context.Context,
		pgx.Tx,
		AutomaticClaimReference,
	) (PreparedAutomaticPublication, error)
	RecordAutomaticPublication(
		context.Context,
		pgx.Tx,
		AutomaticClaimReference,
		PublishResult,
		time.Time,
	) error
}

type AutomaticClaimReference struct {
	RequestID     uuid.UUID
	LeaseToken    uuid.UUID
	StateSequence int64
}

type actorCredential struct {
	raw string
}

type Actor struct {
	UserID     uuid.UUID
	ScopeID    uuid.UUID
	ScopeKind  string
	SessionID  uuid.UUID
	credential *actorCredential
	// system marks the control plane republishing on its own;
	// UserID/ScopeID are then the accountable principal of the facts.
	system *systemActorFacts
}

const redactedActor = "edgepublish.Actor{session:redacted}"

func NewSessionActor(userID, scopeID uuid.UUID, scopeKind string, sessionID uuid.UUID, rawToken string) (Actor, error) {
	if userID == uuid.Nil || scopeID == uuid.Nil || (scopeKind != ScopeKindPlatform && scopeKind != ScopeKindTenant) || sessionID == uuid.Nil ||
		rawToken == "" || len(rawToken) > 8192 || strings.ContainsAny(rawToken, " \t\r\n") {
		return Actor{}, ErrInvalidInput
	}
	return Actor{
		UserID: userID, ScopeID: scopeID, ScopeKind: scopeKind, SessionID: sessionID,
		credential: &actorCredential{raw: rawToken},
	}, nil
}

func (actor Actor) rawSession() string {
	if actor.credential == nil {
		return ""
	}
	return actor.credential.raw
}

func (Actor) Format(state fmt.State, _ rune) { _, _ = state.Write([]byte(redactedActor)) }
func (Actor) String() string                 { return redactedActor }
func (Actor) GoString() string               { return redactedActor }

func (Actor) MarshalJSON() ([]byte, error) {
	return []byte(`"edgepublish.Actor{session:redacted}"`), nil
}

type EntitlementRequest struct {
	Actor                  Actor
	ConfigurationScopeID   uuid.UUID
	ExpectedSourceRevision int64
	NodeCount              int
	EvaluatedAt            time.Time
}

type EntitlementDecision struct {
	Allowed         bool
	LocallyVerified bool
	InGrace         bool
	Status          string
	LeaseSerial     uint64
	EvaluatedAt     time.Time
}

type TargetSnapshotReference struct {
	ID       uuid.UUID
	Revision int64
	SHA256   [32]byte
}

type TargetSnapshot struct {
	Reference TargetSnapshotReference
	NodeIDs   []uuid.UUID
	Topology  *L2TopologySnapshot
}

type L2TopologySnapshot struct {
	Revision          int64
	SourceLineGroupID uuid.UUID
	SourceRevision    int64
	ProbeIntervalMS   int
	FailureThreshold  int
	RecoveryThreshold int
	TargetIdentities  []L2TopologyIdentity
	Endpoints         []L2TopologyEndpoint
	// Config: the line group revision's L2 configuration (节点管理 > L2配置,
	// migration 504), the package default of its sites; nil = every L2
	// endpoint, round robin by the line group's endpoint weights.
	Config *L2TopologyConfig
	// Conditions (A19-b, per site, siteL2Topology): the configuration's L2
	// conditions whose L1 node rules some target matches, each with its
	// request rules, the matching targets and its member endpoints.
	Conditions []L2TopologyCondition
	// Passthrough (L2_ROUTING v2, a node-list publication, fix-autol2b):
	// the topology was worked out per site at publication from the site's
	// line group (siteL2PublicationTopology); the L1 reaches the L2 on the
	// visitor's protocol and port, the endpoints' scheme and port are
	// nominal. SourceLineGroupID is nil for a custom configuration of a
	// site without a line group.
	Passthrough bool
	// Sites (Passthrough, the publication's topology only): each site's
	// resolved topology; a site absent has no L2.
	Sites map[uuid.UUID]*L2TopologySnapshot `json:",omitempty"`
}

// L2TopologyCondition is an L2 condition as a site object carries it
// (edgesite.L2Condition): NodeIDs nil = every target node.
type L2TopologyCondition struct {
	ID          uuid.UUID
	Rules       []edgesite.L2Rule
	NodeIDs     []uuid.UUID
	EndpointIDs []uuid.UUID
}

// L2TopologyConfig is an L2 configuration (l2_topology_configs) as the
// publication applies it (A19): its load method picks the L2 pool's
// algorithm and its enabled members, in sort order, the L2 endpoints and
// their weights.
type L2TopologyConfig struct {
	ID         uuid.UUID
	Mode       string // cache | global
	LoadMethod string // rr | url_hash
	Members    []L2TopologyMember
	// Conditions: the rules of the members' L2 conditions (节点管理 >
	// L2配置 > L2条件), by condition id.
	Conditions map[uuid.UUID][]edgesite.L2Rule
}

type L2TopologyMember struct {
	NodeID uuid.UUID
	Weight int
	// ConditionID: the member's L2 condition (nil = a default candidate).
	ConditionID *uuid.UUID
}

type L2TopologyIdentity struct {
	NodeID             uuid.UUID
	MTLSIdentitySHA256 [32]byte
	// Location: an L1 target's display id and IP location (nodes
	// management_settings ip_location), what L2 condition node rules
	// (node_id, node_country, node_isp, node_province, node_city) match.
	Location L2NodeLocation
}

type L2NodeLocation struct {
	DisplayID, CountryCode, ISP, Province, City string
}

type L2TopologyEndpoint struct {
	EndpointID         uuid.UUID
	NodeID             uuid.UUID
	Address            string
	Port               int
	Weight             int
	MTLSIdentitySHA256 [32]byte
}

type Config struct {
	StateRoot             string
	HealthPort            uint16
	GeneratorName         string
	GeneratorVersion      string
	Clock                 func() time.Time
	EntitlementAuthorizer EntitlementAuthorizer
	TargetResolver        TargetResolver
	Auditor               AuditAppender
	// ModuleRequirements is the publication gate of the modules (PA-15): a
	// snapshot that uses a module is refused unless the lease grants it.
	ModuleRequirements []ModuleRequirement
	// ModuleGrants overrides the EntitlementAuthorizer as the source of the
	// granted module codes.
	ModuleGrants ModuleGrantReader
	// LazyCertificateCacheMax is ssl_certificate_cache max= on the nodes'
	// lazy default servers (site runtime v7).
	LazyCertificateCacheMax int64
}

func DefaultConfig() Config {
	return Config{
		StateRoot: "/var/lib/cdnca-edge", HealthPort: 18080,
		GeneratorName: "cdnca-edgepublish", GeneratorVersion: "1.0.0", Clock: time.Now,
		TargetResolver:          NewSnapshotTargetResolver(),
		LazyCertificateCacheMax: edgeconfig.DefaultLazyCertificateCacheMax,
	}
}

type PublishRequest struct {
	Actor                  Actor
	ConfigurationScopeID   uuid.UUID
	ExpectedSourceRevision int64
	SiteRuntimeSchema      string
	NodeIDs                []uuid.UUID
	TargetSnapshot         *TargetSnapshotReference
	HealthCheck            edgedeployment.HealthCheckPolicy
	MaxAttempts            uint32
	Deadline               time.Time
	IdempotencyKey         string
	RequestID              string
	CorrelationID          string
	Traceparent            string
	TaskID                 *string
	Rollout                edgedeployment.RolloutPolicy
	SystemConfiguration    *SystemConfigurationSource
}

type SystemConfigurationSource struct {
	PlatformScopeID uuid.UUID
	Revision        int64
	SnapshotSHA256  [32]byte
	Nginx           edgeconfig.NginxSettings
	DDoS            *edgeconfig.DDoSProtection
	// AccessLogFields is the access_log_fields category being published
	// (nil: the default).
	AccessLogFields *edgeconfig.AccessLogFields
}

type SystemConfigurationPublishRequest struct {
	Actor                  Actor
	PlatformScopeID        uuid.UUID
	Revision               int64
	SnapshotSHA256         [32]byte
	ConfigurationScopeID   uuid.UUID
	ExpectedSourceRevision int64
	NodeIDs                []uuid.UUID
	Nginx                  edgeconfig.NginxSettings
	DDoS                   *edgeconfig.DDoSProtection
	AccessLogFields        *edgeconfig.AccessLogFields
	IdempotencyKey         string
	RequestID              string
	CorrelationID          string
}

type PreparedAutomaticPublication struct {
	Request     PublishRequest
	DatabaseNow time.Time
}

type PublishResult struct {
	PublicationID           uuid.UUID
	ConfigurationScopeID    uuid.UUID
	SourceRevision          int64
	ConfigVersionID         uuid.UUID
	RolloutID               uuid.UUID
	CanonicalSnapshotSHA256 [32]byte
	ArtifactSHA256          [32]byte
	TargetKind              string
	TargetSnapshot          *TargetSnapshotReference
	TargetSnapshotSHA256    [32]byte
	NodeCount               int
	CreatedAt               time.Time
	Replayed                bool
}

type RollbackRequest struct {
	Actor                Actor
	ConfigurationScopeID uuid.UUID
	PublicationID        uuid.UUID
	NodeIDs              []uuid.UUID
	TargetSnapshot       *TargetSnapshotReference
	HealthCheck          edgedeployment.HealthCheckPolicy
	MaxAttempts          uint32
	Deadline             time.Time
	IdempotencyKey       string
	RequestID            string
	CorrelationID        string
	Traceparent          string
	TaskID               *string
	Rollout              edgedeployment.RolloutPolicy
}

type RollbackResult struct {
	PublicationID        uuid.UUID
	ConfigurationScopeID uuid.UUID
	ConfigVersionID      uuid.UUID
	RolloutID            uuid.UUID
	TargetKind           string
	TargetSnapshot       *TargetSnapshotReference
	TargetSnapshotSHA256 [32]byte
	NodeCount            int
	CreatedAt            time.Time
	Replayed             bool
}

type PublicationPageRequest struct {
	Limit  int
	Cursor string
}

type PublicationPage struct {
	Items                 []PublishResult
	NextCursor            string
	CurrentSourceRevision int64
	// PendingModules: modules the scope's latest publication uses that the
	// lease no longer grants; the scope is pending republication (359).
	PendingModules []ModulePublicationHold
	// AutomaticFailure: the scope's latest automatic publication request
	// ended without publishing for a reason the tenant can act on;
	// nil otherwise.
	AutomaticFailure *AutomaticPublicationFailure
}

// AutomaticPublicationFailure is a terminal automatic request that published
// nothing: reason is no_target_nodes, node_capability_unavailable or
// node_artifacts_syncing (ArtifactSync: how far the refused nodes' node
// artifact sets have arrived, nil before any node has one).
type AutomaticPublicationFailure struct {
	Reason         string
	SourceRevision int64
	FailedAt       time.Time
	ArtifactSync   *ArtifactSyncProgress
}

// ArtifactSyncProgress counts the node artifact segments the refused nodes
// have received of their newest sets, and estimates the whole minutes until
// the slowest node has its set.
type ArtifactSyncProgress struct {
	ReceivedSegments int
	TotalSegments    int
	RemainingMinutes int
}
