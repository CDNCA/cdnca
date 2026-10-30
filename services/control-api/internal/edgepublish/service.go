package edgepublish

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cdnca/cdnca/libs/edgeconfig/crawlerdefaults"
	"net/netip"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	edgeconfigprojection "github.com/cdnca/cdnca/services/control-api/internal/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypublication"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	publishKeyPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	labelPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	traceparentPattern = regexp.MustCompile(`^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$`)
)

type Service struct {
	pool        *pgxpool.Pool
	deployments *edgedeployment.Store
	signer      ArtifactSigner
	authorizer  EntitlementAuthorizer
	coordinator AutomaticPublicationCoordinator
	resolver    TargetResolver
	auditor     AuditAppender
	writeAuth   TxAuthorizer
	config      Config
}

type normalizedPublishRequest struct {
	PublishRequest
	RequestUUID        uuid.UUID
	CorrelationUUID    uuid.UUID
	allowExpiredReplay bool
	// overlay replaces compiling the scope's rows (system stop overlay).
	overlay *publicationOverlay
}

type normalizedRollbackRequest struct {
	RollbackRequest
	RequestUUID     uuid.UUID
	CorrelationUUID uuid.UUID
}

type snapshotOrigin struct {
	Host   string `json:"host"`
	Port   uint16 `json:"port"`
	Weight uint8  `json:"weight"`
}

type snapshotSite struct {
	ID                     string                          `json:"id"`
	PackageConnections     *int64                          `json:"package_connections,omitempty"`
	PackageSubscriptionID  string                          `json:"package_subscription_id,omitempty"`
	Revision               int64                           `json:"revision"`
	Domain                 string                          `json:"domain"`
	ListenPort             uint16                          `json:"listen_port"`
	IPv6Enabled            *bool                           `json:"ipv6_enabled,omitempty"`
	Origins                []snapshotOrigin                `json:"origins"`
	Balance                string                          `json:"balance"`
	FailoverTries          uint8                           `json:"failover_tries"`
	ConnectTimeoutMS       int                             `json:"connect_timeout_ms"`
	ReadTimeoutMS          int                             `json:"read_timeout_ms"`
	KeepaliveIdleTimeoutMS *int                            `json:"origin_keepalive_idle_timeout_ms,omitempty"`
	TLSProtocols           []string                        `json:"tls_protocols,omitempty"`
	WebSocket              bool                            `json:"websocket"`
	Range                  bool                            `json:"range"`
	Cache                  *edgeconfig.CachePolicyDocument `json:"cache,omitempty"`
	SecurityPolicies       []edgeconfig.SecurityPolicy     `json:"security_policies,omitempty"`
	SecurityBindings       []snapshotSecurityBinding       `json:"security_bindings,omitempty"`
	Challenge              *snapshotChallengeBinding       `json:"challenge,omitempty"`
	CapturePolicy          *snapshotCapturePolicy          `json:"capture_policy,omitempty"`
}

type snapshotChallengeBinding struct {
	PolicyID              string `json:"policy_id"`
	PolicyRevision        int64  `json:"policy_revision"`
	BindingRevision       int64  `json:"binding_revision"`
	SecretConfigVersionID string `json:"secret_config_version_id"`
}

type snapshotSecurityBinding struct {
	PublicationID string `json:"publication_id"`
	PolicyID      string `json:"policy_id"`
	PolicyVersion int64  `json:"policy_version"`
	Kind          string `json:"kind"`
	RuntimeSHA256 string `json:"runtime_sha256"`
}

// snapshotStream is one published L4 forward's v2 runtime fact.
type snapshotStream struct {
	ID        string
	Revision  int64
	RuntimeV2 *edgeconfig.L4StreamRuntimeV2
}

type snapshotSystemConfiguration struct {
	PlatformScopeID string `json:"platform_scope_id"`
	Revision        int64  `json:"revision"`
	SnapshotSHA256  string `json:"snapshot_sha256"`
}

type siteFact struct {
	id           uuid.UUID
	revision     int64
	domain       string
	domains      []string
	httpPorts    []string
	httpsEnabled bool
	httpsPorts   []string
	tlsProtocols []string
	// TLS profile (migration 367); clientCAPEM is "" with
	// client verification off.
	tlsCipherPreset string
	// tlsCipherSuites: the custom preset's list.
	tlsCipherSuites  []string
	tlsOCSPStapling  bool
	tlsClientAuth    string
	tlsClientCAPEM   string
	ipv6Enabled      bool
	ipv6DesiredSet   bool
	balance          string
	failoverTries    int
	connectTimeoutMS int
	readTimeoutMS    int
	// forceHTTPS redirects plain HTTP to httpsRedirectPort (0: lowest HTTPS
	// port) with httpsRedirectStatus, except httpsRedirectExclude.
	forceHTTPS           bool
	httpsRedirectPort    int
	httpsRedirectStatus  int
	httpsRedirectExclude []string
	// access is the site's request handling, nil for none.
	access *edgeconfig.SiteAccess
	// keepaliveIdleTimeoutMS is nil for the node default reuse (on, 60s),
	// 0 for off, else the idle timeout.
	keepaliveIdleTimeoutMS *int
	origins                []snapshotOrigin
	challenge              *challengeBindingFact
	// cacheSharedAcrossDomains (所有域名共用缓存): the v2 cache keys every
	// domain by the primary instead of the request host.
	cacheSharedAcrossDomains bool
	// forwarding (367) and originExtras (per origin, parallel to origins)
	// are read for the v2 document only.
	forwarding   *originForwardingFact
	originExtras []originExtraFact
	// activeLevel is the pool's current active origin level (origin
	// failover, site_origin_failover_states; 0 without a row).
	activeLevel int
	// HTTPS protocols (migration 515): the zero value is
	// the default (HTTP/2 and HTTP/3 on); tlsPreferServerCiphers nil follows
	// the cipher preset.
	http2Off               bool
	http3Off               bool
	tlsPreferServerCiphers *bool
}

type originExtraFact struct {
	level    int
	maxConns int
}

type challengeBindingFact struct {
	tenantScopeID, siteID, policyID, secretConfigVersionID uuid.UUID
	host                                                   string
	policyRevision, bindingRevision                        int64
}

type cachePolicyRuleFact struct {
	order             int
	extensions        []string
	pathPrefix        string
	statusCodes       []int
	action            edgeconfig.CacheRuleAction
	ttlSeconds        int64
	browserTTLSeconds int64
	pathRegex         string
	contentTypes      []string
	extras            edgeconfig.CacheRuleExtras
}

type cachePolicyFact struct {
	siteID                 uuid.UUID
	revision               int64
	edgeSourceRevision     int64
	bindingMode            string
	definitionID           uuid.UUID
	definitionRevision     int64
	definitionSourceSiteID uuid.UUID
	schemaVersion          int
	mode                   edgeconfig.CacheMode
	rules                  []cachePolicyRuleFact
	queryMode              edgeconfig.CacheQueryMode
	queryNames             []string
	varyHeaders            []string
	diskQuotaBytes         int64
	// extensions: the definition's site runtime v2 policy extensions
	// (stale-if-error, background update, object size bounds, slices).
	extensions edgeconfig.CachePolicyDocument
}

const (
	cachePolicySchemaV1 = 1
	cachePolicySchemaV2 = 2
)

type securityBindingFact struct {
	siteID          uuid.UUID
	bindingID       uuid.UUID
	publicationID   uuid.UUID
	bindingRevision int64
	policy          securitypolicy.Policy
	runtimeSHA256   [sha256.Size]byte
	// detach (security activation candidates only, sec-rebind): withdraw the
	// site's binding of policy.Kind (replaceSecurityBinding).
	detach bool
	// quickBlock (site runtime v2 WAF bindings only): the site's own quick
	// block override (site_quick_block_overrides), applied over the
	// published library version once its runtime digest is checked.
	quickBlock *securitypolicy.QuickBlockOverride
	// trustedCrawlers (CC bindings): the downloaded official crawler ranges
	// dataset, attachSiteTrustedCrawlers.
	trustedCrawlers *crawlerdefaults.Dataset
	// crs (WAF bindings whose policy runs a managed WAF): the CRS inputs and
	// the site's own CRS override (site_crs_overrides), attachCRSBindings.
	crs *securitypublication.CRSInputs
	// ipLists (ACL / WAF bindings whose rules name IP lists): the lists'
	// current contents, attachSiteIPLists.
	ipLists securitypolicy.ResolvedIPLists
}

func NewService(pool *pgxpool.Pool, deployments *edgedeployment.Store, signer ArtifactSigner, config Config) (*Service, error) {
	return newServiceWithWriteAuthorizer(pool, deployments, signer, config, denyWriteAuthorizer{})
}

func NewIAMService(
	pool *pgxpool.Pool,
	deployments *edgedeployment.Store,
	signer ArtifactSigner,
	config Config,
	authorizer *iamlock.Authorizer,
) (*Service, error) {
	if authorizer == nil {
		return nil, ErrInvalidInput
	}
	return newServiceWithWriteAuthorizer(pool, deployments, signer, config, iamWriteAuthorizer{authorizer: authorizer})
}

func NewAutomaticService(
	pool *pgxpool.Pool,
	deployments *edgedeployment.Store,
	signer ArtifactSigner,
	config Config,
	coordinator AutomaticPublicationCoordinator,
) (*Service, error) {
	if nilServiceDependency(coordinator) {
		return nil, ErrInvalidInput
	}
	service, err := newServiceWithWriteAuthorizer(pool, deployments, signer, config, denyWriteAuthorizer{})
	if err != nil {
		return nil, err
	}
	service.coordinator = coordinator
	return service, nil
}

func newServiceWithWriteAuthorizer(
	pool *pgxpool.Pool,
	deployments *edgedeployment.Store,
	signer ArtifactSigner,
	config Config,
	writeAuth TxAuthorizer,
) (*Service, error) {
	if pool == nil || deployments == nil || nilServiceDependency(signer) || config.Clock == nil || config.HealthPort == 0 ||
		nilServiceDependency(config.EntitlementAuthorizer) || config.StateRoot == "" ||
		!labelPattern.MatchString(config.GeneratorName) || !labelPattern.MatchString(config.GeneratorVersion) ||
		nilServiceDependency(writeAuth) || config.Auditor != nil && nilServiceDependency(config.Auditor) ||
		config.TargetResolver != nil && nilServiceDependency(config.TargetResolver) ||
		config.ModuleGrants != nil && nilServiceDependency(config.ModuleGrants) ||
		validateModuleRequirements(config.ModuleRequirements) != nil {
		return nil, ErrInvalidInput
	}
	auditor := config.Auditor
	if auditor == nil {
		auditor = audit.New(pool)
	}
	return &Service{
		pool: pool, deployments: deployments, signer: signer, authorizer: config.EntitlementAuthorizer,
		resolver: config.TargetResolver, auditor: auditor, writeAuth: writeAuth, config: config,
	}, nil
}

func nilServiceDependency(value any) bool {
	if value == nil {
		return true
	}
	kind := reflect.ValueOf(value).Kind()
	return (kind == reflect.Chan || kind == reflect.Func || kind == reflect.Interface || kind == reflect.Map ||
		kind == reflect.Pointer || kind == reflect.Slice) && reflect.ValueOf(value).IsNil()
}

func (s *Service) Publish(ctx context.Context, request PublishRequest) (PublishResult, error) {
	if ctx == nil {
		return PublishResult{}, ErrInvalidInput
	}
	now := s.config.Clock().UTC().Truncate(time.Microsecond)
	normalized, err := normalizePublishReplayRequest(request, now)
	if err != nil {
		return PublishResult{}, err
	}
	var result PublishResult
	var committedRejection error
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		result, err = s.publishTx(ctx, tx, normalized, now)
		if errors.Is(err, ErrEntitlementDenied) {
			committedRejection = err
			return nil
		}
		return err
	})
	if err != nil {
		s.recordCrossScopeConflict(ctx, normalized.PublishRequest, err)
		s.recordCapabilityHold(ctx, normalized.PublishRequest, normalized.NodeIDs, err)
		s.recordModuleDenial(ctx, normalized.PublishRequest, err)
		return PublishResult{}, err
	}
	if committedRejection != nil {
		return PublishResult{}, committedRejection
	}
	return result, nil
}

// PublishTx publishes an already-authorized caller's immutable source facts in
// the caller transaction. Any compile, signing, or rollout error rolls the
// caller's source projection back with the publication.
func (s *Service) PublishTx(ctx context.Context, tx pgx.Tx, request PublishRequest) (PublishResult, error) {
	if s == nil || ctx == nil || tx == nil {
		return PublishResult{}, ErrInvalidInput
	}
	now := s.config.Clock().UTC().Truncate(time.Microsecond)
	normalized, err := normalizePublishReplayRequest(request, now)
	if err != nil {
		return PublishResult{}, err
	}
	return s.publishTx(ctx, tx, normalized, now)
}

func (s *Service) PublishAutomatic(
	ctx context.Context,
	reference AutomaticClaimReference,
) (PublishResult, error) {
	if ctx == nil || reference.RequestID == uuid.Nil || reference.LeaseToken == uuid.Nil ||
		reference.StateSequence < 2 {
		return PublishResult{}, ErrInvalidInput
	}
	if s == nil || nilServiceDependency(s.coordinator) {
		return PublishResult{}, ErrPermissionDenied
	}
	var result PublishResult
	var committedRejection error
	var attempted PublishRequest
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		prepared, err := s.coordinator.PrepareAutomaticPublication(ctx, tx, reference)
		if errors.Is(err, ErrAutomaticRequestExpired) {
			committedRejection = err
			return nil
		}
		if err != nil {
			return err
		}
		normalized, err := normalizeAutomaticPublishRequest(prepared.Request, prepared.DatabaseNow)
		if err != nil {
			return err
		}
		attempted = normalized.PublishRequest
		if len(normalized.NodeIDs) > 0 {
			// Nodes lacking a gated capability are left out and held
			// (listed); the rest get the release. A node upgrade republishes.
			var published []uuid.UUID
			var refused []systemRefusal
			result, published, refused, err = s.publishExcludingIncapableTx(ctx, tx, normalized.NodeIDs,
				func(nodes []uuid.UUID) (normalizedPublishRequest, error) {
					request := prepared.Request
					request.NodeIDs = nodes
					return normalizeAutomaticPublishRequest(request, prepared.DatabaseNow)
				}, prepared.DatabaseNow)
			if err == nil && len(published) == 0 {
				err = refusedAllError(refused)
			}
			if err == nil && len(refused) > 0 {
				// N15: the audit says what each left-out node lacks.
				err = s.insertCapabilityHoldTx(ctx, tx, normalized.PublishRequest, normalized.NodeIDs,
					refusedNodeIDs(refused), capabilityHoldFacts(refused), true)
			}
		} else {
			result, err = s.publishAuthorizedTx(ctx, tx, normalized, prepared.DatabaseNow)
		}
		if errors.Is(err, ErrEntitlementDenied) {
			committedRejection = err
			return nil
		}
		if err != nil {
			return err
		}
		return s.coordinator.RecordAutomaticPublication(ctx, tx, reference, result, prepared.DatabaseNow)
	})
	if err != nil {
		s.recordCrossScopeConflict(ctx, attempted, err)
		s.recordCapabilityHold(ctx, attempted, attempted.NodeIDs, err)
		s.recordModuleDenial(ctx, attempted, err)
		return PublishResult{}, err
	}
	if committedRejection != nil {
		return PublishResult{}, committedRejection
	}
	return result, nil
}

func (s *Service) Rollback(ctx context.Context, request RollbackRequest) (RollbackResult, error) {
	if ctx == nil {
		return RollbackResult{}, ErrInvalidInput
	}
	now := s.config.Clock().UTC().Truncate(time.Microsecond)
	normalized, err := normalizeRollbackReplayRequest(request, now)
	if err != nil {
		return RollbackResult{}, err
	}
	var result RollbackResult
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		result, err = s.rollbackTx(ctx, tx, normalized, now)
		return err
	})
	if err != nil {
		return RollbackResult{}, err
	}
	return result, nil
}

func (s *Service) rollbackTx(
	ctx context.Context,
	tx pgx.Tx,
	request normalizedRollbackRequest,
	now time.Time,
) (RollbackResult, error) {
	if err := s.writeAuth.Authorize(ctx, tx, request.Actor, request.ConfigurationScopeID, PermissionManage); err != nil {
		return RollbackResult{}, err
	}
	var configVersionID uuid.UUID
	if err := tx.QueryRow(ctx, `
		SELECT config_version_id
		FROM edge_config_publications
		WHERE configuration_scope_id=$1 AND id=$2 AND contract_version=1`,
		request.ConfigurationScopeID, request.PublicationID).Scan(&configVersionID); errors.Is(err, pgx.ErrNoRows) {
		return RollbackResult{}, ErrNotFound
	} else if err != nil {
		return RollbackResult{}, fmt.Errorf("%w: load rollback publication", ErrPersistence)
	}
	targetRequest := normalizedPublishRequest{PublishRequest: PublishRequest{
		ConfigurationScopeID: request.ConfigurationScopeID,
		NodeIDs:              request.NodeIDs,
		TargetSnapshot:       request.TargetSnapshot,
	}}
	rolloutIdempotencyKey := "edgepublish.rollback." + request.IdempotencyKey
	if _, err := tx.Exec(ctx, `SELECT pg_catalog.pg_advisory_xact_lock(
		pg_catalog.hashtextextended('edge-rollout-idempotency:v1:' || $1::text || ':' || $2,0))`,
		request.ConfigurationScopeID, rolloutIdempotencyKey); err != nil {
		return RollbackResult{}, fmt.Errorf("%w: lock rollback idempotency", ErrPersistence)
	}
	var replay bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM rollouts
		WHERE configuration_scope_id=$1 AND idempotency_key=$2)`,
		request.ConfigurationScopeID, rolloutIdempotencyKey).Scan(&replay); err != nil {
		return RollbackResult{}, fmt.Errorf("%w: read rollback idempotency", ErrPersistence)
	}
	if !replay {
		now = s.config.Clock().UTC().Truncate(time.Microsecond)
		if !request.Deadline.After(now) {
			return RollbackResult{}, ErrInvalidInput
		}
	}
	var target TargetSnapshot
	var targetDigest [sha256.Size]byte
	var err error
	if replay {
		target, targetDigest, err = s.resolveTargetIdentity(ctx, tx, targetRequest)
	} else {
		target, targetDigest, err = s.resolveTarget(ctx, tx, targetRequest)
	}
	if err != nil {
		return RollbackResult{}, err
	}
	// A site runtime v2 version is releasable only with exactly its
	// document's capabilities (edgedeployment requireReleasableConfig); v1
	// versions keep requiring none here.
	requiredCapabilities, _, err := edgedeployment.SiteRuntimeV2ConfigCapabilitiesTx(
		ctx, tx, request.ConfigurationScopeID, configVersionID)
	if err != nil {
		return RollbackResult{}, err
	}
	rollout, err := s.deployments.CreateRolloutTx(ctx, tx, edgedeployment.CreateRolloutRequest{
		ConfigurationScopeID: request.ConfigurationScopeID,
		ConfigVersionID:      configVersionID,
		Action:               agentv1.DeploymentAction_DEPLOYMENT_ACTION_ROLLBACK,
		RequiredCapabilities: requiredCapabilities,
		NodeIDs:              target.NodeIDs,
		HealthCheck:          request.HealthCheck,
		Deadline:             request.Deadline,
		IdempotencyKey:       rolloutIdempotencyKey,
		RequestID:            request.RequestID,
		CorrelationID:        request.CorrelationID,
		Traceparent:          request.Traceparent,
		TaskID:               request.TaskID,
		MaxAttempts:          request.MaxAttempts,
		ContractVersion:      rolloutContractVersion(request.Rollout), Rollout: request.Rollout,
	})
	if err != nil {
		return RollbackResult{}, err
	}
	result := RollbackResult{
		PublicationID: request.PublicationID, ConfigurationScopeID: request.ConfigurationScopeID,
		ConfigVersionID: configVersionID, RolloutID: rollout.Rollout.ID,
		TargetKind: targetKind(targetRequest), TargetSnapshot: cloneTargetReference(request.TargetSnapshot),
		TargetSnapshotSHA256: targetDigest, NodeCount: len(target.NodeIDs), CreatedAt: rollout.Rollout.CreatedAt,
		Replayed: rollout.Replayed,
	}
	if result.Replayed {
		return result, nil
	}
	if err := s.auditor.Append(ctx, tx, audit.Event{
		ScopeID: request.Actor.ScopeID, ActorUserID: &request.Actor.UserID,
		Action: "edge_publication.rollback", ResourceType: "edge_config_publication",
		ResourceID: request.PublicationID.String(), RequestID: request.RequestID, Result: "success",
		Payload: rollbackAuditPayload(request, map[string]any{
			"operation": "rollback", "reason": "operator_requested",
			"configuration_scope_id": request.ConfigurationScopeID.String(),
			"config_version_id":      configVersionID.String(), "rollout_id": result.RolloutID.String(),
			"target_kind": result.TargetKind, "target_sha256": fmt.Sprintf("%x", targetDigest[:]),
			"node_count": result.NodeCount,
		}),
	}); err != nil {
		return RollbackResult{}, fmt.Errorf("%w: append rollback audit", ErrPersistence)
	}
	return result, nil
}

func (s *Service) publishTx(ctx context.Context, tx pgx.Tx, request normalizedPublishRequest, now time.Time) (PublishResult, error) {
	permission := PermissionManage
	if request.Actor.ScopeKind == ScopeKindTenant {
		permission = "sites.manage"
	}
	if err := s.writeAuth.Authorize(ctx, tx, request.Actor, request.ConfigurationScopeID, permission); err != nil {
		return PublishResult{}, err
	}
	return s.publishAuthorizedTx(ctx, tx, request, now)
}

func (s *Service) publishAuthorizedTx(
	ctx context.Context,
	tx pgx.Tx,
	request normalizedPublishRequest,
	now time.Time,
) (PublishResult, error) {
	if err := lockHTTPPolicyPublicationFacts(ctx, tx, request.ConfigurationScopeID); err != nil {
		return PublishResult{}, err
	}
	sourceRevision, err := lockConfigurationScope(ctx, tx, request.ConfigurationScopeID, now)
	if err != nil {
		return PublishResult{}, err
	}
	configID := uuid.NewSHA1(request.ConfigurationScopeID, []byte(request.IdempotencyKey))
	requestDigest, err := publicationRequestDigest(request)
	if err != nil {
		return PublishResult{}, err
	}
	if existing, found, err := loadPublication(ctx, tx, request.ConfigurationScopeID, request.IdempotencyKey); err != nil {
		return PublishResult{}, err
	} else if found {
		if !bytes.Equal(existing.requestDigest, requestDigest[:]) || existing.result.ConfigVersionID != configID {
			return PublishResult{}, ErrIdempotencyConflict
		}
		existing.result.Replayed = true
		return existing.result, nil
	}
	if err := checkPackageRuntime(ctx, tx, request.ConfigurationScopeID, now, nil); err != nil {
		return PublishResult{}, err
	}
	if request.allowExpiredReplay {
		now = s.config.Clock().UTC().Truncate(time.Microsecond)
		if !request.Deadline.After(now) {
			return PublishResult{}, ErrInvalidInput
		}
	}
	if exists, err := publicationExistsForRequestID(ctx, tx, request.ConfigurationScopeID, request.RequestUUID); err != nil {
		return PublishResult{}, err
	} else if exists {
		return PublishResult{}, ErrIdempotencyConflict
	}
	if sourceRevision != request.ExpectedSourceRevision {
		return PublishResult{}, ErrRevisionConflict
	}
	if exists, err := publicationExistsForSourceRevision(ctx, tx, request.ConfigurationScopeID, sourceRevision); err != nil {
		return PublishResult{}, err
	} else if exists {
		return PublishResult{}, ErrAlreadyPublished
	}
	target, targetDigest, err := s.resolveTarget(ctx, tx, request)
	if err != nil {
		return PublishResult{}, err
	}
	decision, authorizationErr := s.authorizer.AuthorizePublication(ctx, tx, EntitlementRequest{
		Actor: request.Actor, ConfigurationScopeID: request.ConfigurationScopeID,
		ExpectedSourceRevision: request.ExpectedSourceRevision, NodeCount: len(target.NodeIDs), EvaluatedAt: now,
	})
	if authorizationErr != nil || !validEntitlementDecision(decision, now) {
		reason := "decision_rejected"
		if authorizationErr != nil {
			reason = "decision_unavailable"
		}
		if err := s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: request.Actor.ScopeID, ActorUserID: auditActorUserID(request.Actor),
			Action: "edge_publication.entitlement_check", ResourceType: "edge_configuration_scope",
			ResourceID: request.ConfigurationScopeID.String(), RequestID: request.RequestID, Result: "denied",
			Payload: publishAuditPayload(request, map[string]any{
				"reason": reason, "expected_source_revision": request.ExpectedSourceRevision,
				"node_count": len(target.NodeIDs), "locally_verified": decision.LocallyVerified,
				"in_grace": decision.InGrace, "status": decision.Status, "lease_serial": decision.LeaseSerial,
			}),
		}); err != nil {
			return PublishResult{}, fmt.Errorf("%w: append entitlement audit", ErrPersistence)
		}
		return PublishResult{}, ErrEntitlementDenied
	}
	if err := claimEligibleNodes(ctx, tx, request.ConfigurationScopeID, target.NodeIDs, now); err != nil {
		return PublishResult{}, err
	}
	var (
		snapshotBytes          []byte
		snapshotDigest         [sha256.Size]byte
		artifactDigest         [sha256.Size]byte
		artifacts              []edgedeployment.ArtifactInput
		nodeArtifactBindings   []edgedeployment.NodeArtifactBinding
		capabilities           []*agentv1.Capability
		rolloutMaxAttempts     = request.MaxAttempts
		telemetrySubscriptions map[uuid.UUID]uuid.UUID
		// siteObjects is the release's site object delivery (site runtime v8).
		siteObjects *siteObjectRelease
	)
	if request.overlay != nil && request.overlay.base.v2 == nil {
		return PublishResult{}, ErrInvalidInput
	}
	// v2Inputs is the source kept as the stop overlay's base.
	var v2Inputs *siteRuntimeV2Inputs
	{
		var bundle edgeconfig.Bundle
		if request.overlay != nil {
			snapshotBytes, snapshotDigest, bundle, _, capabilities, telemetrySubscriptions, v2Inputs, err =
				request.overlay.compileSiteRuntimeV2(ctx, tx, s, request.ConfigurationScopeID, configID, sourceRevision,
					target.NodeIDs, now)
		} else {
			v2Inputs = new(siteRuntimeV2Inputs)
			snapshotBytes, snapshotDigest, bundle, _, capabilities, telemetrySubscriptions, err = s.compileSiteRuntimeV2FactsCapture(
				ctx, tx, request.ConfigurationScopeID, configID, sourceRevision, target, now, request.SystemConfiguration, v2Inputs)
		}
		if err != nil {
			return PublishResult{}, err
		}
		recipients, err := lockConfigurationArtifactRecipients(
			ctx, tx, request.ConfigurationScopeID, target.NodeIDs, now,
		)
		if err != nil {
			return PublishResult{}, err
		}
		if siteObjects, err = s.buildSiteObjectRelease(ctx, tx, request.ConfigurationScopeID, configID, bundle,
			recipients, capabilities, now); err != nil {
			return PublishResult{}, err
		}
		nodeArtifactBindings, artifacts = siteObjects.bindings, siteObjects.artifacts
		if artifactDigest, err = siteObjects.artifactSetDigest(); err != nil {
			return PublishResult{}, err
		}
		rolloutMaxAttempts = 1
	}
	if err := validateL4AdditionalListenerTargets(ctx, tx, request.ConfigurationScopeID, target.NodeIDs, capabilities, now); err != nil {
		return PublishResult{}, err
	}
	// CC proof of work and the CRS managed WAF reach agents that predate them
	// only through required_capabilities, refused on the node after commit;
	// refuse here instead, naming the node and the feature.
	if err := validateFeatureCapabilityTargets(ctx, tx, target.NodeIDs, capabilities); err != nil {
		return PublishResult{}, err
	}
	if err := s.validateModuleEntitlements(ctx, tx, snapshotBytes); err != nil {
		return PublishResult{}, err
	}
	// The new release uses only granted modules: the scope is no longer
	// pending republication for a revoked one (migration 364).
	if err := clearModuleHoldsTx(ctx, tx, request.ConfigurationScopeID); err != nil {
		return PublishResult{}, err
	}
	// A JS challenge loads its policy file at master start; nodes the
	// challenge rollout has not reached would fail the reload.
	challengeTargets, err := siteRuntimeV2ChallengePolicyTargets(snapshotBytes)
	if err != nil {
		return PublishResult{}, err
	}
	if err := validateChallengePolicyTargets(ctx, tx, request.ConfigurationScopeID, target.NodeIDs, challengeTargets); err != nil {
		return PublishResult{}, err
	}
	if err := validateCrossScopeComposition(ctx, tx, request.ConfigurationScopeID, target.NodeIDs, snapshotBytes); err != nil {
		return PublishResult{}, err
	}
	configResult, err := s.deployments.PersistReleasableConfigTx(ctx, tx, configID, edgedeployment.PersistConfigRequest{
		ConfigurationScopeID: request.ConfigurationScopeID,
		CanonicalSnapshot:    snapshotBytes,
		GeneratorName:        s.config.GeneratorName,
		GeneratorVersion:     s.config.GeneratorVersion,
		IdempotencyKey:       "edgepublish.config." + request.IdempotencyKey,
		Artifacts:            artifacts,
	})
	if err != nil {
		return PublishResult{}, err
	}
	if configResult.ConfigVersion.ID != configID {
		return PublishResult{}, fmt.Errorf("%w: persisted config ID mismatch", ErrPersistence)
	}
	if siteObjects != nil {
		if err := siteObjects.persist(ctx, tx, now); err != nil {
			return PublishResult{}, err
		}
	}
	if err := persistSiteIPv6RolloutTargets(
		ctx, tx, request.ConfigurationScopeID, configID, sourceRevision, snapshotBytes, now,
	); err != nil {
		return PublishResult{}, err
	}
	if err := persistPackageMonitorMetricAuthority(ctx, tx, request.ConfigurationScopeID, configID,
		sourceRevision, target.NodeIDs, now); err != nil {
		return PublishResult{}, err
	}
	if err := persistTelemetrySiteBindings(ctx, tx, configID, telemetrySubscriptions); err != nil {
		return PublishResult{}, err
	}
	if err := persistCompileInputs(ctx, tx, request.ConfigurationScopeID, configID, sourceRevision,
		request.overlay != nil, v2Inputs, capabilities, now); err != nil {
		return PublishResult{}, err
	}
	rolloutResult, err := s.deployments.CreateRolloutTx(ctx, tx, edgedeployment.CreateRolloutRequest{
		ConfigurationScopeID: request.ConfigurationScopeID,
		ConfigVersionID:      configID,
		Action:               agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY,
		NodeIDs:              target.NodeIDs,
		NodeArtifactBindings: nodeArtifactBindings,
		RequiredCapabilities: capabilities,
		HealthCheck:          request.HealthCheck,
		Deadline:             request.Deadline,
		IdempotencyKey:       "edgepublish.rollout." + request.IdempotencyKey,
		RequestID:            request.RequestID,
		CorrelationID:        request.CorrelationID,
		Traceparent:          request.Traceparent,
		TaskID:               request.TaskID,
		MaxAttempts:          rolloutMaxAttempts,
		ContractVersion:      rolloutContractVersion(request.Rollout), Rollout: request.Rollout,
	})
	if err != nil {
		return PublishResult{}, err
	}
	result := PublishResult{
		PublicationID:        uuid.NewSHA1(configID, []byte("publication")),
		ConfigurationScopeID: request.ConfigurationScopeID, SourceRevision: sourceRevision,
		ConfigVersionID: configID, RolloutID: rolloutResult.Rollout.ID,
		CanonicalSnapshotSHA256: snapshotDigest, ArtifactSHA256: artifactDigest,
		TargetKind: targetKind(request), TargetSnapshot: cloneTargetReference(request.TargetSnapshot),
		TargetSnapshotSHA256: targetDigest, NodeCount: len(target.NodeIDs), CreatedAt: now,
	}
	if err := insertPublication(ctx, tx, result, request, requestDigest); err != nil {
		return PublishResult{}, err
	}
	// The publication's accountable actor (migration 046 requires the match);
	// a system republication says actor_kind=system in the payload.
	payload := map[string]any{
		"configuration_scope_id": request.ConfigurationScopeID.String(),
		"source_revision":        sourceRevision, "source_sha256": fmt.Sprintf("%x", snapshotDigest[:]),
		"target_kind": result.TargetKind, "target_sha256": fmt.Sprintf("%x", targetDigest[:]),
		"node_count": result.NodeCount, "config_version_id": result.ConfigVersionID.String(),
		"rollout_id": result.RolloutID.String(), "entitlement_lease_serial": decision.LeaseSerial,
	}
	if v2Inputs != nil && len(v2Inputs.L2Skipped) > 0 {
		payload["l2_skipped_sites"] = siteL2SkippedPayload(v2Inputs.L2Skipped)
	}
	if err := s.auditor.Append(ctx, tx, audit.Event{
		ScopeID: request.Actor.ScopeID, ActorUserID: &request.Actor.UserID,
		Action: "edge_publication.publish", ResourceType: "edge_config_publication",
		ResourceID: result.PublicationID.String(), RequestID: request.RequestID, Result: "success",
		Payload: publishAuditPayload(request, payload),
	}); err != nil {
		return PublishResult{}, fmt.Errorf("%w: append publication audit", ErrPersistence)
	}
	var tenantID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT tenant_id FROM access_scopes
		WHERE id=$1 AND kind=$2`, request.ConfigurationScopeID, ScopeKindTenant).Scan(&tenantID); err != nil || tenantID == uuid.Nil {
		return PublishResult{}, fmt.Errorf("%w: load publication tenant", ErrPersistence)
	}
	items := make([]jobstate.CreateItem, len(target.NodeIDs))
	for index, nodeID := range target.NodeIDs {
		node := nodeID
		items[index] = jobstate.CreateItem{ItemID: nodeID.String(), NodeID: &node}
	}
	if _, err := jobstate.CreateTx(ctx, tx, jobstate.CreateInput{
		JobID: result.PublicationID, TenantID: tenantID, Kind: "edge.publication",
		Subject:        result.PublicationID.String(),
		IdempotencyKey: "edge.publication." + result.PublicationID.String(),
		Payload:        requestDigest[:], Items: items, MaxAttempts: request.MaxAttempts,
		RequestID: request.RequestID, TraceID: request.Traceparent,
	}, now); err != nil {
		return PublishResult{}, fmt.Errorf("%w: create publication background job", ErrPersistence)
	}
	claim, err := jobstate.StartTx(ctx, tx, jobstate.StartInput{
		TenantID: tenantID, JobID: result.PublicationID, Kind: "edge.publication",
		WorkerID: "edge.publication." + result.PublicationID.String(), LeaseDuration: time.Hour,
	}, now)
	if err != nil {
		return PublishResult{}, fmt.Errorf("%w: start publication background job", ErrPersistence)
	}
	for _, nodeID := range target.NodeIDs {
		if _, err := jobstate.ReportTx(ctx, tx, jobstate.ReportInput{
			TenantID: tenantID, JobID: result.PublicationID,
			WorkerID: claim.WorkerID, LeaseID: claim.LeaseID,
			Report: jobstate.Report{
				ItemID: nodeID.String(), State: jobstate.ItemSucceeded,
				Attempt: claim.Job.Attempt, Sequence: 1,
			},
		}, now); err != nil {
			return PublishResult{}, fmt.Errorf("%w: complete publication background job", ErrPersistence)
		}
	}
	return result, nil
}

func publishAuditPayload(request normalizedPublishRequest, payload map[string]any) map[string]any {
	payload["authentication_scope_id"] = request.Actor.ScopeID.String()
	payload["request_id"] = request.RequestID
	payload["idempotency_key"] = request.IdempotencyKey
	payload["correlation_id"] = request.CorrelationID
	payload["traceparent"] = request.Traceparent
	if request.Actor.SessionID != uuid.Nil {
		payload["session_id"] = request.Actor.SessionID.String()
	}
	if request.TaskID != nil {
		payload["task_id"] = *request.TaskID
	}
	if system := request.Actor.system; system != nil {
		payload["actor_kind"] = "system"
		payload["accountable_user_id"] = request.Actor.UserID.String()
		payload["system_republication_attempt_id"] = system.attemptID.String()
		payload["system_triggers"] = system.triggers
	}
	return payload
}

func rollbackAuditPayload(request normalizedRollbackRequest, payload map[string]any) map[string]any {
	payload["authentication_scope_id"] = request.Actor.ScopeID.String()
	payload["request_id"] = request.RequestID
	payload["idempotency_key"] = request.IdempotencyKey
	payload["correlation_id"] = request.CorrelationID
	payload["traceparent"] = request.Traceparent
	if request.Actor.SessionID != uuid.Nil {
		payload["session_id"] = request.Actor.SessionID.String()
	}
	if request.TaskID != nil {
		payload["task_id"] = *request.TaskID
	}
	return payload
}

func validTraceparent(value string) bool {
	matches := traceparentPattern.FindStringSubmatch(value)
	return len(matches) == 4 && matches[1] != strings.Repeat("0", 32) && matches[2] != strings.Repeat("0", 16)
}

func normalizePublishRequest(request PublishRequest, now time.Time) (normalizedPublishRequest, error) {
	return normalizePublishRequestForActor(request, now, false, false)
}

func normalizePublishReplayRequest(request PublishRequest, now time.Time) (normalizedPublishRequest, error) {
	return normalizePublishRequestForActor(request, now, false, true)
}

func normalizeAutomaticPublishRequest(request PublishRequest, now time.Time) (normalizedPublishRequest, error) {
	return normalizePublishRequestForActor(request, now, true, false)
}

func normalizePublishRequestForActor(
	request PublishRequest,
	now time.Time,
	automatic bool,
	allowExpiredReplay bool,
) (normalizedPublishRequest, error) {
	if request.SystemConfiguration != nil {
		return normalizedPublishRequest{}, ErrInvalidInput
	}
	request.SiteRuntimeSchema = ResolveSiteRuntimeSchema(request.SiteRuntimeSchema)
	requestUUID, requestErr := uuid.Parse(request.RequestID)
	correlationUUID, correlationErr := uuid.Parse(request.CorrelationID)
	automaticActorInvalid := automatic &&
		(request.Actor.ScopeKind != ScopeKindTenant && request.Actor.ScopeKind != ScopeKindPlatform ||
			request.Actor.SessionID != uuid.Nil || request.Actor.rawSession() != "")
	manualActorInvalid := !automatic && request.Actor.ScopeKind != ScopeKindPlatform && request.Actor.ScopeKind != ScopeKindTenant
	if request.Actor.UserID == uuid.Nil || request.Actor.ScopeID == uuid.Nil || manualActorInvalid || automaticActorInvalid ||
		request.ConfigurationScopeID == uuid.Nil || request.ExpectedSourceRevision <= 0 ||
		request.SiteRuntimeSchema != siteRuntimeV2Schema ||
		requestErr != nil || requestUUID.String() != request.RequestID ||
		correlationErr != nil || correlationUUID.String() != request.CorrelationID || !publishKeyPattern.MatchString(request.IdempotencyKey) ||
		(len(request.NodeIDs) == 0) == (request.TargetSnapshot == nil) || len(request.NodeIDs) > maxPublicationTargets ||
		request.MaxAttempts == 0 || request.MaxAttempts > 10 ||
		request.HealthCheck.ActivationTimeout <= 0 || request.HealthCheck.ObservationWindow <= 0 ||
		request.HealthCheck.ActivationTimeout%time.Millisecond != 0 || request.HealthCheck.ObservationWindow%time.Millisecond != 0 ||
		request.HealthCheck.RequiredConsecutiveSuccesses == 0 || request.Deadline.IsZero() ||
		!allowExpiredReplay && !request.Deadline.After(now) || len(request.Traceparent) > 512 ||
		strings.TrimSpace(request.Traceparent) != request.Traceparent || request.Traceparent != "" && !validTraceparent(request.Traceparent) ||
		(request.TaskID != nil && !labelPattern.MatchString(*request.TaskID)) {
		return normalizedPublishRequest{}, ErrInvalidInput
	}
	if !validRolloutPolicyInput(request.Rollout) {
		return normalizedPublishRequest{}, ErrInvalidInput
	}
	nodeIDs := slices.Clone(request.NodeIDs)
	for _, nodeID := range nodeIDs {
		if nodeID == uuid.Nil {
			return normalizedPublishRequest{}, ErrInvalidInput
		}
	}
	sort.Slice(nodeIDs, func(i, j int) bool { return bytes.Compare(nodeIDs[i][:], nodeIDs[j][:]) < 0 })
	if len(slices.Compact(slices.Clone(nodeIDs))) != len(nodeIDs) {
		return normalizedPublishRequest{}, ErrInvalidInput
	}
	request.NodeIDs = nodeIDs
	if request.TargetSnapshot != nil {
		if request.TargetSnapshot.ID == uuid.Nil || request.TargetSnapshot.Revision <= 0 || request.TargetSnapshot.SHA256 == ([32]byte{}) {
			return normalizedPublishRequest{}, ErrInvalidInput
		}
		request.TargetSnapshot = cloneTargetReference(request.TargetSnapshot)
	}
	request.Deadline = request.Deadline.UTC()
	if request.TaskID != nil {
		value := *request.TaskID
		request.TaskID = &value
	}
	return normalizedPublishRequest{PublishRequest: request, RequestUUID: requestUUID,
		CorrelationUUID: correlationUUID, allowExpiredReplay: allowExpiredReplay}, nil
}

func normalizeRollbackRequest(request RollbackRequest, now time.Time) (normalizedRollbackRequest, error) {
	return normalizeRollbackRequestWithDeadline(request, now, true)
}

func normalizeRollbackReplayRequest(request RollbackRequest, now time.Time) (normalizedRollbackRequest, error) {
	return normalizeRollbackRequestWithDeadline(request, now, false)
}

func normalizeRollbackRequestWithDeadline(
	request RollbackRequest,
	now time.Time,
	requireFutureDeadline bool,
) (normalizedRollbackRequest, error) {
	requestUUID, requestErr := uuid.Parse(request.RequestID)
	correlationUUID, correlationErr := uuid.Parse(request.CorrelationID)
	if request.Actor.UserID == uuid.Nil || request.Actor.ScopeID == uuid.Nil || request.Actor.ScopeKind != ScopeKindPlatform ||
		request.ConfigurationScopeID == uuid.Nil || request.PublicationID == uuid.Nil ||
		requestErr != nil || requestUUID.String() != request.RequestID ||
		correlationErr != nil || correlationUUID.String() != request.CorrelationID ||
		!publishKeyPattern.MatchString(request.IdempotencyKey) ||
		(len(request.NodeIDs) == 0) == (request.TargetSnapshot == nil) || len(request.NodeIDs) > maxPublicationTargets ||
		request.MaxAttempts == 0 || request.MaxAttempts > 10 ||
		request.HealthCheck.ActivationTimeout <= 0 || request.HealthCheck.ObservationWindow <= 0 ||
		request.HealthCheck.ActivationTimeout%time.Millisecond != 0 || request.HealthCheck.ObservationWindow%time.Millisecond != 0 ||
		request.HealthCheck.RequiredConsecutiveSuccesses == 0 || request.Deadline.IsZero() ||
		requireFutureDeadline && !request.Deadline.After(now) || len(request.Traceparent) > 512 ||
		strings.TrimSpace(request.Traceparent) != request.Traceparent ||
		request.Traceparent != "" && !validTraceparent(request.Traceparent) ||
		(request.TaskID != nil && !labelPattern.MatchString(*request.TaskID)) {
		return normalizedRollbackRequest{}, ErrInvalidInput
	}
	if !validRolloutPolicyInput(request.Rollout) {
		return normalizedRollbackRequest{}, ErrInvalidInput
	}
	nodeIDs := slices.Clone(request.NodeIDs)
	for _, nodeID := range nodeIDs {
		if nodeID == uuid.Nil {
			return normalizedRollbackRequest{}, ErrInvalidInput
		}
	}
	sort.Slice(nodeIDs, func(i, j int) bool { return bytes.Compare(nodeIDs[i][:], nodeIDs[j][:]) < 0 })
	if len(slices.Compact(slices.Clone(nodeIDs))) != len(nodeIDs) {
		return normalizedRollbackRequest{}, ErrInvalidInput
	}
	request.NodeIDs = nodeIDs
	if request.TargetSnapshot != nil {
		if request.TargetSnapshot.ID == uuid.Nil || request.TargetSnapshot.Revision <= 0 ||
			request.TargetSnapshot.SHA256 == ([32]byte{}) {
			return normalizedRollbackRequest{}, ErrInvalidInput
		}
		request.TargetSnapshot = cloneTargetReference(request.TargetSnapshot)
	}
	request.Deadline = request.Deadline.UTC()
	if request.TaskID != nil {
		value := *request.TaskID
		request.TaskID = &value
	}
	return normalizedRollbackRequest{RollbackRequest: request,
		RequestUUID: requestUUID, CorrelationUUID: correlationUUID}, nil
}

// loadCRSInputs is what a managed WAF compiles against: the synced CRS rule
// text (waf_set:crs_rules, signed by the license service) and the usable
// downloaded free CRS profile packs (PA-12). A missing rule text is
// ErrUnsupportedSecurityPolicy (fail closed).
func loadCRSInputs(ctx context.Context, tx pgx.Tx) (*securitypublication.CRSInputs, error) {
	var body []byte
	err := tx.QueryRow(ctx, `SELECT body FROM security_system_rules
		WHERE system_key='waf_set:crs_rules' AND status='active'`).Scan(&body)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUnsupportedSecurityPolicy
	}
	if err != nil {
		return nil, fmt.Errorf("%w: load CRS rule text", ErrPersistence)
	}
	var item rulecatalog.ItemBody
	if err := json.Unmarshal(body, &item); err != nil || item.WAFRuleSet == nil || item.WAFRuleSet.Bundle == nil {
		return nil, ErrUnsupportedSecurityPolicy
	}
	rules, err := securitypolicy.EdgeCRSRuleText(*item.WAFRuleSet.Bundle)
	if err != nil {
		return nil, ErrUnsupportedSecurityPolicy
	}
	profiles, err := securitypolicy.LoadCRSProfilesTx(ctx, tx, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	apps, err := securitypolicy.LoadCRSAppsTx(ctx, tx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	return &securitypublication.CRSInputs{Profiles: profiles, RuleText: rules, Apps: apps}, nil
}

func loadPackageSubscriptionFacts(
	ctx context.Context,
	tx pgx.Tx,
	scopeID uuid.UUID,
	statusRecoverySiteIDs []uuid.UUID,
) (map[uuid.UUID]uuid.UUID, error) {
	rows, err := tx.Query(ctx, `
		SELECT site.id,site.package_subscription_id
		FROM sites site
		JOIN package_subscriptions package_subscription
		  ON package_subscription.tenant_scope_id=site.scope_id AND package_subscription.id=site.package_subscription_id
		WHERE site.scope_id=$1 AND site.deleted_at IS NULL AND site.enabled
		  AND package_subscription.admin_enabled=true AND package_subscription.deleted_at IS NULL
		  AND package_subscription.suspended_at IS NULL
		  AND (site.status NOT IN ('package_expired','traffic_exceeded') OR site.id=ANY($2::uuid[]))
		  AND site.package_subscription_id IS NOT NULL
		ORDER BY site.id`, scopeID, statusRecoverySiteIDs)
	if err != nil {
		return nil, fmt.Errorf("%w: load package subscription facts", ErrPersistence)
	}
	defer rows.Close()
	result := make(map[uuid.UUID]uuid.UUID)
	for rows.Next() {
		var siteID, subscriptionID uuid.UUID
		if err := rows.Scan(&siteID, &subscriptionID); err != nil || siteID == uuid.Nil || subscriptionID == uuid.Nil {
			return nil, fmt.Errorf("%w: invalid package subscription fact", ErrPersistence)
		}
		result[siteID] = subscriptionID
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("%w: iterate package subscription facts", ErrPersistence)
	}
	return result, nil
}

// persistTelemetrySiteBindings records the package subscription of each site
// of a site runtime v2 version (nil for config-source v1, whose snapshot
// carries it), so node authorization binds the sites' telemetry exactly as
// the encrypted telemetry manifest does (migration 295).
func persistTelemetrySiteBindings(ctx context.Context, tx pgx.Tx, configID uuid.UUID, subscriptions map[uuid.UUID]uuid.UUID) error {
	if subscriptions == nil {
		return nil
	}
	siteIDs := make([]uuid.UUID, 0, len(subscriptions))
	subscriptionIDs := make([]uuid.UUID, 0, len(subscriptions))
	for siteID, subscriptionID := range subscriptions {
		siteIDs = append(siteIDs, siteID)
		subscriptionIDs = append(subscriptionIDs, subscriptionID)
	}
	// uuid.Nil marks a site without a subscription.
	_, err := tx.Exec(ctx, `INSERT INTO config_version_telemetry_site_bindings(config_version_id,site_id,package_subscription_id)
		SELECT $1,binding.site_id,NULLIF(binding.subscription_id,'00000000-0000-0000-0000-000000000000'::uuid)
		FROM unnest($2::uuid[],$3::uuid[]) AS binding(site_id,subscription_id)
		ON CONFLICT (config_version_id,site_id) DO NOTHING`, configID, siteIDs, subscriptionIDs)
	if err != nil {
		return fmt.Errorf("%w: persist telemetry site bindings", ErrPersistence)
	}
	return nil
}

func persistPackageMonitorMetricAuthority(
	ctx context.Context,
	tx pgx.Tx,
	scopeID, configVersionID uuid.UUID,
	sourceRevision int64,
	nodeIDs []uuid.UUID,
	validFrom time.Time,
) error {
	command, err := tx.Exec(ctx, `
		INSERT INTO package_monitor_site_subscription_bindings_114(
		  tenant_scope_id,site_id,subscription_id,config_version_id,binding_revision,
		  valid_from,binding_digest,created_at)
		SELECT site.scope_id,site.id,site.package_subscription_id,$2,$3,$4,
		       package_monitor_site_binding_digest_114(site.scope_id,site.id,site.package_subscription_id,$2,$3,$4),$4
		FROM sites site
		JOIN package_subscriptions package_subscription
		  ON package_subscription.tenant_scope_id=site.scope_id AND package_subscription.id=site.package_subscription_id
		WHERE site.scope_id=$1 AND site.deleted_at IS NULL AND site.enabled
		  AND package_subscription.admin_enabled=true AND package_subscription.deleted_at IS NULL
		  AND package_subscription.suspended_at IS NULL
		  AND site.status NOT IN ('package_expired','traffic_exceeded')
		  AND site.package_subscription_id IS NOT NULL
		  AND EXISTS (SELECT 1 FROM site_origins origin WHERE origin.site_id=site.id AND origin.enabled)
		ON CONFLICT (config_version_id,site_id) DO NOTHING`,
		scopeID, configVersionID, sourceRevision, validFrom)
	if err != nil {
		return fmt.Errorf("%w: persist package subscription authority", ErrPersistence)
	}
	if command.RowsAffected() == 0 {
		return nil
	}
	if len(nodeIDs) == 0 {
		return fmt.Errorf("%w: package metric installation authority is empty", ErrPersistence)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO package_monitor_config_installations_114(
		  tenant_scope_id,config_version_id,node_id,installation_id,valid_from)
		SELECT $1,$2,target.node_id,certificate.installation_id,$4
		FROM unnest($3::uuid[]) AS target(node_id)
		JOIN nodes node ON node.id=target.node_id AND node.admin_state='active'
		JOIN access_scopes node_scope ON node_scope.id=node.scope_id
		  AND (node_scope.kind='platform' OR node.scope_id=$1)
		JOIN node_config_state state ON state.node_id=node.id
		  AND state.configuration_scope_id=$1 AND NOT state.reconciliation_required
		JOIN LATERAL (
		  SELECT cert.installation_id
		  FROM node_certificates cert
		  WHERE cert.node_id=target.node_id AND cert.status='active'
		    AND cert.rotation_status='current' AND cert.not_after>$4
		  ORDER BY cert.issued_at DESC LIMIT 1
		) certificate ON true
		ON CONFLICT (config_version_id,node_id) DO NOTHING`, scopeID, configVersionID, nodeIDs, validFrom); err != nil {
		return fmt.Errorf("%w: persist package metric installations", ErrPersistence)
	}
	var installed int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM package_monitor_config_installations_114
		WHERE tenant_scope_id=$1 AND config_version_id=$2 AND node_id=ANY($3::uuid[])`,
		scopeID, configVersionID, nodeIDs).Scan(&installed); err != nil || installed != len(nodeIDs) {
		return fmt.Errorf("%w: package metric installation authority incomplete", ErrPersistence)
	}
	return nil
}

// compileSiteFact compiles a site for one port. domains is the server_name a
// CC host condition may name (nil: the primary, the legacy server).
func compileSiteFact(scopeID uuid.UUID, fact siteFact, port uint16, cachePolicy *cachePolicyFact, bindings []securityBindingFact, domains []string) (snapshotSite, edgeconfig.Site, error) {
	var challengeFact *edgeconfigprojection.ChallengeBindingFact
	if fact.challenge != nil {
		challengeFact = &edgeconfigprojection.ChallengeBindingFact{
			TenantScopeID: fact.challenge.tenantScopeID, SiteID: fact.challenge.siteID,
			Host: fact.challenge.host, PolicyID: fact.challenge.policyID,
			PolicyRevision: fact.challenge.policyRevision, BindingRevision: fact.challenge.bindingRevision,
			SecretConfigVersionID: fact.challenge.secretConfigVersionID,
		}
	}
	challenge, err := edgeconfigprojection.ProjectSiteChallenge(scopeID, fact.id, fact.domain, challengeFact)
	if err != nil {
		return snapshotSite{}, edgeconfig.Site{}, ErrInvalidInput
	}
	securityPolicies, err := compileSecurityPolicies(fact, port, bindings)
	if err != nil {
		return snapshotSite{}, edgeconfig.Site{}, err
	}
	ipv6Enabled := siteFactIPv6Enabled(fact)
	snapshot := snapshotSite{
		ID: fact.id.String(), Revision: fact.revision, Domain: fact.domain,
		ListenPort: port, IPv6Enabled: disabledIPv6Snapshot(ipv6Enabled),
		Origins: slices.Clone(fact.origins), Balance: fact.balance,
		FailoverTries: uint8(fact.failoverTries), ConnectTimeoutMS: fact.connectTimeoutMS,
		ReadTimeoutMS: fact.readTimeoutMS, KeepaliveIdleTimeoutMS: cloneIntPointer(fact.keepaliveIdleTimeoutMS),
		TLSProtocols: slices.Clone(fact.tlsProtocols),
		WebSocket:    true, Range: true, SecurityPolicies: securityPolicies,
	}
	site := edgeconfig.Site{
		ID: fact.id.String(), Domain: fact.domain, ListenPort: port, Protocol: edgeconfig.ProtocolHTTP,
		IPv6Enabled: boolPointer(ipv6Enabled),
		Origins:     edgeOrigins(fact.origins), Balance: edgeconfig.BalanceMethod(fact.balance),
		FailoverTries: uint8(fact.failoverTries), ConnectTimeout: time.Duration(fact.connectTimeoutMS) * time.Millisecond,
		ReadTimeout:                time.Duration(fact.readTimeoutMS) * time.Millisecond,
		OriginKeepaliveIdleTimeout: keepaliveIdleTimeout(fact.keepaliveIdleTimeoutMS),
		WebSocket:                  true, Range: true,
		ACL: edgeconfig.ACLPolicy{DefaultAction: edgeconfig.ACLAllow},
	}
	if challenge != nil {
		snapshot.Challenge = &snapshotChallengeBinding{PolicyID: challenge.PolicyID,
			PolicyRevision: challenge.PolicyRevision, BindingRevision: challenge.BindingRevision,
			SecretConfigVersionID: challenge.SecretConfigVersionID}
		runtime := challenge.Runtime
		site.Challenge = &runtime
	}
	cacheSnapshot, cache, err := compileCachePolicy(fact.id, cachePolicy)
	if err != nil {
		return snapshotSite{}, edgeconfig.Site{}, err
	}
	snapshot.Cache = cacheSnapshot
	site.Cache = cache
	activeBindings := make([]securitypublication.ActiveBinding, 0, len(bindings))
	for _, binding := range bindings {
		compiled, compileErr := securitypolicy.CompileRuntimeSnapshot(binding.policy, fact.id)
		if compileErr != nil || compiled.SHA256 != binding.runtimeSHA256 || binding.publicationID == uuid.Nil {
			return snapshotSite{}, edgeconfig.Site{}, ErrUnsupportedSecurityPolicy
		}
		activeBindings = append(activeBindings, securitypublication.ActiveBinding{
			BindingID: binding.bindingID, PublicationID: binding.publicationID, BindingRevision: binding.bindingRevision,
			RuntimeSnapshotSHA256: binding.runtimeSHA256,
			Snapshot:              compiled.Snapshot, CRS: binding.crs, TrustedCrawlers: binding.trustedCrawlers,
			IPLists: binding.ipLists,
		})
	}
	compiled, err := securitypublication.CompileSiteSecurityBindingsFor(site, domains, scopeID, fact.id, activeBindings)
	if err != nil {
		return snapshotSite{}, edgeconfig.Site{}, ErrUnsupportedSecurityPolicy
	}
	compiled.Site.ACL = edgeconfig.ACLPolicy{DefaultAction: edgeconfig.ACLAllow}
	compiled.Site.WAF = edgeconfig.WAFPolicy{}
	compiled.Site.SecurityPolicies = securityPolicies
	snapshot.SecurityBindings = make([]snapshotSecurityBinding, len(compiled.Bindings))
	for index, binding := range compiled.Bindings {
		snapshot.SecurityBindings[index] = snapshotSecurityBinding{
			PublicationID: binding.PublicationID.String(), PolicyID: binding.PolicyID.String(),
			PolicyVersion: binding.PolicyVersion, Kind: binding.Kind,
			RuntimeSHA256: fmt.Sprintf("%x", binding.RuntimeSnapshotSHA256[:]),
		}
	}
	return snapshot, compiled.Site, nil
}

func boolPointer(value bool) *bool {
	return &value
}

func disabledIPv6Snapshot(enabled bool) *bool {
	if enabled {
		return nil
	}
	return boolPointer(false)
}

func siteFactIPv6Enabled(fact siteFact) bool {
	return !fact.ipv6DesiredSet || fact.ipv6Enabled
}

func validateSiteTLSProtocols(protocols []string) ([]string, error) {
	if edgeconfig.ValidateSiteTLSProtocols(protocols) != nil {
		return nil, ErrInvalidInput
	}
	return slices.Clone(protocols), nil
}

// siteFactTLSProfile is a site fact's listener TLS profile (the baseline
// fields are left empty so a baseline site's document is unchanged).
func siteFactTLSProfile(fact siteFact) (edgeconfig.TLSProfile, error) {
	profile := edgeconfig.TLSProfile{Protocols: slices.Clone(fact.tlsProtocols), OCSPStapling: fact.tlsOCSPStapling}
	if fact.tlsCipherPreset != edgeconfig.TLSCipherModern {
		profile.CipherPreset = fact.tlsCipherPreset
	}
	if fact.tlsCipherPreset == edgeconfig.TLSCipherCustom {
		profile.CipherSuites = slices.Clone(fact.tlsCipherSuites)
	}
	if fact.tlsClientAuth != edgeconfig.ClientAuthOff {
		if edgeconfig.ValidateClientCABundle([]byte(fact.tlsClientCAPEM)) != nil {
			return edgeconfig.TLSProfile{}, ErrInvalidInput
		}
		profile.ClientAuth, profile.ClientCARef = fact.tlsClientAuth, edgeconfig.ClientCARefFor([]byte(fact.tlsClientCAPEM))
	} else if fact.tlsClientCAPEM != "" {
		return edgeconfig.TLSProfile{}, ErrInvalidInput
	}
	// Only a value that differs from the preset's is published (canonical).
	if prefer := fact.tlsPreferServerCiphers; prefer != nil && *prefer != edgeconfig.PresetPrefersServerCiphers(profile.CipherPreset) {
		value := *prefer
		profile.PreferServerCiphers = &value
	}
	if profile.Validate() != nil {
		return edgeconfig.TLSProfile{}, ErrInvalidInput
	}
	return profile, nil
}

func compileCachePolicy(siteID uuid.UUID, fact *cachePolicyFact) (*edgeconfig.CachePolicyDocument, edgeconfig.CachePolicy, error) {
	if fact == nil {
		return nil, edgeconfig.CachePolicy{Mode: edgeconfig.CacheDisabled}, nil
	}
	if siteID == uuid.Nil || fact.siteID != siteID || fact.revision < 1 || fact.edgeSourceRevision < 1 ||
		(fact.bindingMode != "inherit" && fact.bindingMode != "override") || fact.definitionID == uuid.Nil ||
		fact.definitionRevision < 1 || fact.definitionSourceSiteID == uuid.Nil ||
		(fact.bindingMode == "override" && fact.definitionSourceSiteID != siteID) ||
		(fact.schemaVersion != cachePolicySchemaV1 && fact.schemaVersion != cachePolicySchemaV2) ||
		fact.diskQuotaBytes < 0 {
		return nil, edgeconfig.CachePolicy{}, ErrInvalidInput
	}
	policy := edgeconfig.CachePolicy{
		Revision: uint64(fact.revision), Mode: fact.mode, QueryMode: fact.queryMode,
		QueryNames: slices.Clone(fact.queryNames), VaryHeaders: slices.Clone(fact.varyHeaders),
	}
	if fact.schemaVersion == cachePolicySchemaV2 {
		policy.SchemaVersion = edgeconfig.CachePolicyDocumentSchemaV2
	}
	if fact.mode != edgeconfig.CacheDisabled {
		policy.ZoneSizeBytes = 1 << 20
		policy.MaxSizeBytes = fact.diskQuotaBytes
		policy.DefaultTTL = 60 * time.Second
	}
	policy.Rules = make([]edgeconfig.CacheRule, len(fact.rules))
	for index, rule := range fact.rules {
		if rule.order != index+1 || !validCachePolicyRuleFact(fact.schemaVersion, rule) {
			return nil, edgeconfig.CachePolicy{}, ErrInvalidInput
		}
		policy.Rules[index] = edgeconfig.CacheRule{
			Order: rule.order, Extensions: slices.Clone(rule.extensions), PathPrefix: rule.pathPrefix,
			StatusCodes: slices.Clone(rule.statusCodes), Action: rule.action,
			TTL:        time.Duration(rule.ttlSeconds) * time.Second,
			BrowserTTL: time.Duration(rule.browserTTLSeconds) * time.Second,
			PathRegex:  rule.pathRegex, ContentTypes: slices.Clone(rule.contentTypes),
			CacheRuleExtras: rule.extras.Clone(),
		}
		if index == 0 && fact.mode == edgeconfig.CacheOverride && fact.schemaVersion == cachePolicySchemaV1 {
			policy.DefaultTTL = policy.Rules[index].TTL
		}
		if fact.schemaVersion == cachePolicySchemaV1 && len(rule.extensions) == 0 && rule.pathPrefix == "" {
			for _, status := range rule.statusCodes {
				policy.StatusTTLs = append(policy.StatusTTLs, edgeconfig.CacheStatusTTL{Status: status, TTL: policy.Rules[index].TTL})
			}
		}
	}
	document := edgeconfig.CachePolicyDocument{
		SchemaVersion: policy.SchemaVersion, Revision: policy.Revision, Mode: policy.Mode, QueryMode: policy.QueryMode,
		QueryNames: slices.Clone(policy.QueryNames), VaryHeaders: slices.Clone(policy.VaryHeaders),
		DiskQuotaBytes: policy.MaxSizeBytes, Rules: make([]edgeconfig.CacheRuleDocument, len(policy.Rules)),
		StaleIfError: fact.extensions.StaleIfError, BackgroundUpdate: fact.extensions.BackgroundUpdate,
		MinObjectBytes: fact.extensions.MinObjectBytes, MaxObjectBytes: fact.extensions.MaxObjectBytes,
		SliceBytes: fact.extensions.SliceBytes,
	}
	for index, rule := range policy.Rules {
		document.Rules[index] = edgeconfig.CacheRuleDocument{
			Order: rule.Order, Extensions: slices.Clone(rule.Extensions), PathPrefix: rule.PathPrefix,
			StatusCodes: slices.Clone(rule.StatusCodes), Action: rule.Action,
			TTLSeconds: int64(rule.TTL / time.Second), BrowserTTLSeconds: int64(rule.BrowserTTL / time.Second),
			PathRegex: rule.PathRegex, ContentTypes: slices.Clone(rule.ContentTypes),
			CacheRuleExtras: rule.CacheRuleExtras.Clone(),
		}
	}
	return &document, policy, nil
}

func validCachePolicyRuleFact(schemaVersion int, rule cachePolicyRuleFact) bool {
	switch schemaVersion {
	case cachePolicySchemaV1:
		return rule.action == "" && rule.browserTTLSeconds == 0 &&
			rule.ttlSeconds >= 1 && rule.ttlSeconds <= 365*24*60*60
	case cachePolicySchemaV2:
		if rule.action == edgeconfig.CacheRuleActionNoCache {
			return rule.ttlSeconds == 0 && rule.browserTTLSeconds == 0
		}
		return rule.action == edgeconfig.CacheRuleActionCache &&
			rule.ttlSeconds >= 1 && rule.ttlSeconds <= 365*24*60*60 &&
			rule.browserTTLSeconds >= 0 && rule.browserTTLSeconds <= rule.ttlSeconds
	default:
		return false
	}
}

func compileSecurityPolicies(fact siteFact, port uint16, bindings []securityBindingFact) ([]edgeconfig.SecurityPolicy, error) {
	// The legacy renderer serves the primary domain only.
	return compileSecurityPoliciesFor(fact, []string{fact.domain}, port, bindings)
}

// compileSecurityPoliciesFor compiles the site's bound ACL/WAF policies for a
// server whose server_name is domains (compileSecurityRuleMatchesFor).
func compileSecurityPoliciesFor(fact siteFact, domains []string, port uint16, bindings []securityBindingFact) ([]edgeconfig.SecurityPolicy, error) {
	policies := make([]edgeconfig.SecurityPolicy, 0, len(bindings))
	seenKinds := make(map[string]struct{}, len(bindings))
	totalRules := 0
	for _, binding := range bindings {
		policy := binding.policy
		if binding.siteID != fact.id || binding.bindingRevision < 1 || policy.ID == uuid.Nil || policy.Revision < 1 {
			return nil, ErrUnsupportedSecurityPolicy
		}
		compiled, err := securitypolicy.CompileRuntimeSnapshot(policy, fact.id)
		if err != nil || compiled.SHA256 != binding.runtimeSHA256 {
			return nil, ErrUnsupportedSecurityPolicy
		}
		if binding.quickBlock != nil {
			// The site's quick block replaces the library's system rules
			// (same reserved IDs and slot); the binding stays the published
			// library version.
			if policy, err = securitypolicy.SiteQuickBlockPolicy(policy, *binding.quickBlock); err != nil {
				return nil, fmt.Errorf("%w: site quick block: %w", ErrUnsupportedSecurityPolicy, err)
			}
		}
		if _, duplicate := seenKinds[policy.Kind]; duplicate {
			return nil, ErrUnsupportedSecurityPolicy
		}
		seenKinds[policy.Kind] = struct{}{}
		if policy.Kind == securitypolicy.KindCC {
			continue
		}
		kind := edgeconfig.SecurityKind(policy.Kind)
		if kind != edgeconfig.SecurityACL && kind != edgeconfig.SecurityWAF {
			return nil, ErrUnsupportedSecurityPolicy
		}
		defaultAction, err := compileSecurityAction(policy.DefaultAction)
		if err != nil || defaultAction == edgeconfig.WAFLog {
			return nil, ErrUnsupportedSecurityPolicy
		}
		rules := make([]edgeconfig.WAFRule, 0, len(policy.Rules))
		for _, rule := range policy.Rules {
			if kind == edgeconfig.SecurityWAF && rule.Action == securitypolicy.ActionManagedWAF {
				// The site's ManagedWAF (securitypublication.compileWAF), not a Lua rule.
				continue
			}
			action, err := compileSecurityAction(rule.Action)
			if err != nil || (rule.Flow != securitypolicy.FlowContinue && rule.Flow != securitypolicy.FlowStop) {
				return nil, ErrUnsupportedSecurityPolicy
			}
			matches, err := compileSecurityRuleMatchesFor(domains, port, rule.Conditions, binding.ipLists)
			if err != nil {
				return nil, err
			}
			if !rule.Enabled {
				continue
			}
			actionConfig, err := compileSecurityActionConfig(kind, rule)
			if err != nil {
				return nil, err
			}
			for _, match := range matches {
				rules = append(rules, edgeconfig.WAFRule{
					RuleID: rule.ID.String(), Match: match, Action: action, Control: edgeconfig.WAFControl(rule.Flow),
					ActionConfig: actionConfig,
				})
				if totalRules+len(rules) > edgeconfig.MaxSecurityRulesPerSite {
					return nil, ErrSecurityPolicyBudget
				}
			}
		}
		totalRules += len(rules)
		mode, autoBlock := compileWAFSettings(policy.WAFSettings)
		policies = append(policies, edgeconfig.SecurityPolicy{
			Kind: kind, PolicyID: policy.ID.String(), PolicyVersion: policy.Revision,
			BindingRevision: binding.bindingRevision, RuntimeSHA256: fmt.Sprintf("%x", binding.runtimeSHA256[:]),
			Enabled: policy.Enabled, DefaultAction: defaultAction, Rules: rules, Mode: mode, AutoBlock: autoBlock,
		})
	}
	sort.Slice(policies, func(left, right int) bool { return policies[left].Kind < policies[right].Kind })
	return policies, nil
}

func compileSecurityAction(action string) (edgeconfig.WAFAction, error) {
	switch action {
	case securitypolicy.ActionAllow:
		return edgeconfig.WAFAllow, nil
	case securitypolicy.ActionBlock:
		return edgeconfig.WAFBlock, nil
	case securitypolicy.ActionLog:
		return edgeconfig.WAFLog, nil
	case securitypolicy.ActionChallenge:
		return edgeconfig.WAFChallenge, nil
	case securitypolicy.ActionBan:
		return edgeconfig.WAFBan, nil
	default:
		return "", ErrUnsupportedSecurityPolicy
	}
}

// compileSecurityActionConfig maps a WAF challenge / ban rule's parameters;
// nil for every other action. ACL policies take neither action.
func compileSecurityActionConfig(kind edgeconfig.SecurityKind, rule securitypolicy.Rule) (*edgeconfig.WAFActionConfig, error) {
	switch rule.Action {
	case securitypolicy.ActionBan:
		if kind != edgeconfig.SecurityWAF || rule.ActionConfig.WAFBan == nil {
			return nil, ErrUnsupportedSecurityPolicy
		}
		return &edgeconfig.WAFActionConfig{BanSeconds: rule.ActionConfig.WAFBan.BanSeconds}, nil
	case securitypolicy.ActionChallenge:
		if kind != edgeconfig.SecurityWAF || rule.ActionConfig.WAFChallenge == nil {
			return nil, ErrUnsupportedSecurityPolicy
		}
		return &edgeconfig.WAFActionConfig{PassSeconds: rule.ActionConfig.WAFChallenge.PassSeconds,
			PowBits: rule.ActionConfig.WAFChallenge.PowBits}, nil
	}
	return nil, nil
}

// compileWAFSettings maps a WAF policy's observe mode and auto block.
func compileWAFSettings(settings *securitypolicy.WAFSettings) (edgeconfig.WAFMode, *edgeconfig.WAFAutoBlock) {
	if settings == nil {
		return edgeconfig.WAFModeDefend, nil
	}
	mode := edgeconfig.WAFModeDefend
	if settings.Mode == securitypolicy.WAFModeObserve {
		mode = edgeconfig.WAFModeObserve
	}
	var autoBlock *edgeconfig.WAFAutoBlock
	if value := settings.AutoBlock; value != nil {
		autoBlock = &edgeconfig.WAFAutoBlock{WindowSeconds: value.WindowSeconds, HitThreshold: value.HitThreshold,
			BlockSeconds: value.BlockSeconds}
	}
	return mode, autoBlock
}

func compileSecurityRuleMatches(domain string, port uint16, conditions []securitypolicy.Condition) ([]edgeconfig.WAFMatch, error) {
	return compileSecurityRuleMatchesFor([]string{domain}, port, conditions, nil)
}

// compileSecurityRuleMatchesFor compiles a rule for a server whose
// server_name is domains (the primary first). The server scopes the rule:
// one exact domain also keeps it as the implicit host (the legacy renderer's
// form). Several domains (v2 aliases) or a wildcard ("*.x.example", which no
// request host equals) carry no host, so the rule holds on every host the
// server serves; a host condition, decided here against one domain, cannot
// be decided for all of them and is refused.
func compileSecurityRuleMatchesFor(domains []string, port uint16, conditions []securitypolicy.Condition, ipLists securitypolicy.ResolvedIPLists) ([]edgeconfig.WAFMatch, error) {
	if len(domains) == 0 {
		return nil, ErrUnsupportedSecurityPolicy
	}
	domain := domains[0]
	severalHosts := len(domains) != 1 || strings.HasPrefix(domain, "*.")
	host := domain
	if severalHosts {
		host = ""
	}
	matches := []edgeconfig.WAFMatch{{Host: host, Port: port}}
	seenFields := make(map[string]struct{}, len(conditions))
	for _, condition := range conditions {
		// Content conditions are cdnca_waf.lua inspect clauses, mapped as
		// securitypublication.edgeWAFInspect and the node precheck
		// (securityRuntimeInspect) do; they may repeat (ANDed).
		inspect, ok, err := securityRuleInspect(condition)
		if !ok {
			if _, duplicate := seenFields[condition.Field]; duplicate && condition.Field != "client_ip" {
				return nil, ErrUnsupportedSecurityPolicy
			}
			seenFields[condition.Field] = struct{}{}
		}
		if ok {
			if err != nil {
				return nil, ErrUnsupportedSecurityPolicy
			}
			for index := range matches {
				matches[index].Inspect = append(append([]edgeconfig.WAFInspect(nil), matches[index].Inspect...), inspect)
			}
			continue
		}
		switch condition.Field {
		case "host":
			if severalHosts {
				return nil, ErrUnsupportedSecurityPolicy
			}
			matched, ok := securityStringMatch(domain, condition.Operator, condition.Values)
			if !ok {
				return nil, ErrUnsupportedSecurityPolicy
			}
			if !matched {
				return nil, nil
			}
		case "port":
			matched, ok := securityPortMatch(port, condition.Operator, condition.Values)
			if !ok {
				return nil, ErrUnsupportedSecurityPolicy
			}
			if !matched {
				return nil, nil
			}
		case "method":
			if condition.Operator != "equals" && condition.Operator != "in" {
				return nil, ErrUnsupportedSecurityPolicy
			}
			var err error
			matches, err = expandSecurityMatches(matches, condition.Values, func(match *edgeconfig.WAFMatch, value string) {
				match.Method = value
			})
			if err != nil {
				return nil, err
			}
		case "path":
			kind := edgeconfig.WAFPathExact
			if condition.Operator == "prefix" {
				kind = edgeconfig.WAFPathPrefix
			} else if condition.Operator != "equals" && condition.Operator != "in" {
				return nil, ErrUnsupportedSecurityPolicy
			}
			var err error
			matches, err = expandSecurityMatches(matches, condition.Values, func(match *edgeconfig.WAFMatch, value string) {
				match.Path = &edgeconfig.WAFPathMatch{Kind: kind, Value: value}
			})
			if err != nil {
				return nil, err
			}
		case "header":
			if condition.Operator != "equals" && condition.Operator != "in" {
				return nil, ErrUnsupportedSecurityPolicy
			}
			var err error
			matches, err = expandSecurityMatches(matches, condition.Values, func(match *edgeconfig.WAFMatch, value string) {
				match.Header = &edgeconfig.WAFHeaderMatch{Name: condition.Key, Kind: edgeconfig.WAFHeaderExact, Value: value}
			})
			if err != nil {
				return nil, err
			}
		case "client_ip":
			values := make([]string, len(condition.Values))
			for index, value := range condition.Values {
				if condition.Operator == "equals" {
					address, err := netip.ParseAddr(value)
					if err != nil || address.Is4In6() {
						return nil, ErrUnsupportedSecurityPolicy
					}
					values[index] = netip.PrefixFrom(address, address.BitLen()).String()
				} else if condition.Operator == "ip_in_cidr" {
					prefix, err := netip.ParsePrefix(value)
					if err != nil || prefix.Addr().Is4In6() || prefix.Addr().IsMulticast() {
						return nil, ErrUnsupportedSecurityPolicy
					}
					values[index] = prefix.Masked().String()
				} else {
					return nil, ErrUnsupportedSecurityPolicy
				}
			}
			var err error
			matches, err = intersectSecurityCIDRMatches(matches, values)
			if err != nil {
				return nil, err
			}
		case "ja4":
			// One set condition ($cdnca_ja4 is one of the values); needs
			// CAPABILITY_NAME_JA4 (requiredCapabilities).
			values, err := edgeconfig.NormalizeWAFJA4(append([]string(nil), condition.Values...))
			if err != nil || condition.Key != "" || condition.Operator != "equals" && condition.Operator != "in" && condition.Operator != "not_in" {
				return nil, ErrUnsupportedSecurityPolicy
			}
			for index := range matches {
				// not_in: WAFMatch.NotJA4, needs WAF_JA4_NEGATION (fix-ja4rule).
				if condition.Operator == "not_in" {
					matches[index].NotJA4 = values
				} else {
					matches[index].JA4 = values
				}
			}
		case "ip_list":
			// A named IP list, expanded to its current contents; needs WAF v4.
			list, ok := ipLists.Condition(condition)
			if !ok {
				return nil, ErrUnsupportedSecurityPolicy
			}
			for index := range matches {
				matches[index].IPLists = append(append([]edgeconfig.WAFIPList(nil), matches[index].IPLists...), list)
			}
		case "carrier", "ip_tag", "asn", "country", "province", "city":
			// Looked up in the node's IP intelligence library; needs
			// CAPABILITY_NAME_IP_INTEL v2 (requiredCapabilities).
			condition, _, err := edgeconfig.IPIntelPolicyCondition(condition.Field, condition.Operator, condition.Key, condition.Values)
			if err != nil {
				return nil, ErrUnsupportedSecurityPolicy
			}
			for index := range matches {
				matches[index].IPIntel = append(append([]edgeconfig.WAFIPIntel(nil), matches[index].IPIntel...), condition)
			}
		default:
			return nil, ErrUnsupportedSecurityPolicy
		}
	}
	for index := range matches {
		if matches[index].Inspect == nil {
			continue
		}
		// The node renders the clauses from the runtime snapshot, whose
		// conditions are ordered by field, operator, key and values.
		sort.SliceStable(matches[index].Inspect, func(left, right int) bool {
			a, b := matches[index].Inspect[left], matches[index].Inspect[right]
			if a.Target != b.Target {
				return a.Target < b.Target
			}
			if a.Operator != b.Operator {
				return a.Operator < b.Operator
			}
			if a.Key != b.Key {
				return a.Key < b.Key
			}
			return slices.Compare(a.Values, b.Values) < 0
		})
		if _, err := edgeconfig.NormalizeWAFInspect(matches[index].Inspect); err != nil {
			return nil, ErrUnsupportedSecurityPolicy
		}
	}
	for index := range matches {
		if matches[index].IPIntel == nil {
			continue
		}
		// carrier and ip_tag both become tag conditions; canonical order.
		normalized, err := edgeconfig.NormalizeWAFIPIntel(matches[index].IPIntel)
		if err != nil {
			return nil, ErrUnsupportedSecurityPolicy
		}
		matches[index].IPIntel = normalized
	}
	return matches, nil
}

func intersectSecurityCIDRMatches(matches []edgeconfig.WAFMatch, values []string) ([]edgeconfig.WAFMatch, error) {
	if len(values) == 0 {
		return nil, ErrSecurityPolicyBudget
	}
	result := make([]edgeconfig.WAFMatch, 0, len(matches))
	for _, match := range matches {
		for _, value := range values {
			intersection := value
			if match.SourceCIDR != "" {
				previous := netip.MustParsePrefix(match.SourceCIDR)
				current := netip.MustParsePrefix(value)
				switch {
				case previous.Addr().BitLen() != current.Addr().BitLen():
					continue
				case previous.Bits() <= current.Bits() && previous.Contains(current.Addr()):
					intersection = current.String()
				case current.Bits() <= previous.Bits() && current.Contains(previous.Addr()):
					intersection = previous.String()
				default:
					continue
				}
			}
			candidate := match
			candidate.SourceCIDR = intersection
			if slices.ContainsFunc(result, func(existing edgeconfig.WAFMatch) bool {
				return reflect.DeepEqual(existing, candidate)
			}) {
				continue
			}
			if len(result) == edgeconfig.MaxSecurityRulesPerSite {
				return nil, ErrSecurityPolicyBudget
			}
			result = append(result, candidate)
		}
	}
	return result, nil
}

// securityRuleInspect mirrors securitypublication.edgeWAFInspect.
func securityRuleInspect(condition securitypolicy.Condition) (edgeconfig.WAFInspect, bool, error) {
	return edgeconfig.WAFInspectPolicyCondition(condition.Field, condition.Operator, condition.Key, condition.Values,
		condition.Filters, condition.BodyOverflow)
}

func expandSecurityMatches(
	matches []edgeconfig.WAFMatch,
	values []string,
	set func(*edgeconfig.WAFMatch, string),
) ([]edgeconfig.WAFMatch, error) {
	if len(values) == 0 || len(matches) > edgeconfig.MaxSecurityRulesPerSite/len(values) {
		return nil, ErrSecurityPolicyBudget
	}
	result := make([]edgeconfig.WAFMatch, 0, len(matches)*len(values))
	for _, match := range matches {
		for _, value := range values {
			copy := match
			set(&copy, value)
			result = append(result, copy)
		}
	}
	return result, nil
}

func securityStringMatch(actual, operator string, values []string) (bool, bool) {
	contains := func(candidate string) bool { return slices.Contains(values, candidate) }
	switch operator {
	case "equals", "in":
		return contains(actual), true
	case "not_equals", "not_in":
		return !contains(actual), true
	case "prefix":
		for _, value := range values {
			if strings.HasPrefix(actual, value) {
				return true, true
			}
		}
		return false, true
	case "suffix":
		for _, value := range values {
			if strings.HasSuffix(actual, value) {
				return true, true
			}
		}
		return false, true
	case "contains":
		for _, value := range values {
			if strings.Contains(actual, value) {
				return true, true
			}
		}
		return false, true
	default:
		return false, false
	}
}

func securityPortMatch(actual uint16, operator string, values []string) (bool, bool) {
	if len(values) == 0 {
		return false, false
	}
	actualValue := strconv.FormatUint(uint64(actual), 10)
	switch operator {
	case "in":
		return slices.Contains(values, actualValue), true
	case "not_in":
		return !slices.Contains(values, actualValue), true
	case "number_eq", "number_gte", "number_lte":
		if len(values) != 1 {
			return false, false
		}
		value, err := strconv.ParseUint(values[0], 10, 16)
		if err != nil || value == 0 {
			return false, false
		}
		switch operator {
		case "number_eq":
			return uint64(actual) == value, true
		case "number_gte":
			return uint64(actual) >= value, true
		default:
			return uint64(actual) <= value, true
		}
	default:
		return false, false
	}
}

func edgeOrigins(values []snapshotOrigin) []edgeconfig.Origin {
	result := make([]edgeconfig.Origin, len(values))
	for index, origin := range values {
		result[index] = edgeconfig.Origin{Host: origin.Host, Port: origin.Port, Weight: origin.Weight}
	}
	return result
}

func publicationRequestDigest(request normalizedPublishRequest) ([32]byte, error) {
	nodes := make([]string, len(request.NodeIDs))
	for index, nodeID := range request.NodeIDs {
		nodes[index] = nodeID.String()
	}
	siteRuntimeSchema := request.SiteRuntimeSchema
	var rollout *edgedeployment.RolloutPolicy
	if request.Rollout.Strategy != "" {
		value := request.Rollout
		rollout = &value
	}
	encoded, err := json.Marshal(struct {
		ScopeID             string                        `json:"scope_id"`
		ExpectedRevision    int64                         `json:"expected_source_revision"`
		SiteRuntimeSchema   string                        `json:"site_runtime_schema,omitempty"`
		NodeIDs             []string                      `json:"node_ids,omitempty"`
		TargetSnapshot      *TargetSnapshotReference      `json:"target_snapshot,omitempty"`
		ActivationTimeoutMS int64                         `json:"activation_timeout_ms"`
		ObservationWindowMS int64                         `json:"observation_window_ms"`
		RequiredSuccesses   uint32                        `json:"required_successes"`
		MaxAttempts         uint32                        `json:"max_attempts"`
		Deadline            string                        `json:"deadline"`
		Rollout             *edgedeployment.RolloutPolicy `json:"rollout,omitempty"`
		SystemConfiguration *SystemConfigurationSource    `json:"system_configuration,omitempty"`
	}{request.ConfigurationScopeID.String(), request.ExpectedSourceRevision, siteRuntimeSchema, nodes, request.TargetSnapshot,
		request.HealthCheck.ActivationTimeout.Milliseconds(), request.HealthCheck.ObservationWindow.Milliseconds(),
		request.HealthCheck.RequiredConsecutiveSuccesses, request.MaxAttempts,
		request.Deadline.Format(time.RFC3339Nano), rollout, request.SystemConfiguration})
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: encode publication digest", ErrInvalidInput)
	}
	return sha256.Sum256(encoded), nil
}

func rolloutContractVersion(policy edgedeployment.RolloutPolicy) int16 {
	if policy.Strategy == edgedeployment.RolloutStrategyCanary {
		return 2
	}
	return 1
}

func validRolloutPolicyInput(policy edgedeployment.RolloutPolicy) bool {
	if policy == (edgedeployment.RolloutPolicy{}) {
		return true
	}
	return policy.Strategy == edgedeployment.RolloutStrategyCanary && policy.CanarySize >= 1 && policy.CanarySize <= 1000 &&
		policy.BatchSize >= 1 && policy.BatchSize <= 1000 && policy.FailureThreshold >= 1 &&
		policy.FailureThreshold <= 10000 && policy.CohortCount == 0
}

func cloneIntPointer(value *int) *int {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

// keepaliveIdleTimeout is a site's origin keepalive for the v1 renderer: nil
// keeps the node default, 0 turns reuse off.
func keepaliveIdleTimeout(value *int) *time.Duration {
	if value == nil {
		return nil
	}
	timeout := time.Duration(*value) * time.Millisecond
	return &timeout
}
