package gatewayclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/acmehttp01"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/cachetask"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/challenge"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/deployment"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/firewall"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/objectstore"
	"github.com/cdnca/cdnca/libs/edgeconfig/autodefense"
	"github.com/cdnca/cdnca/libs/edgeconfig/sched302"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var errCertificateRenewed = errors.New("gateway client certificate renewed")

// errCapabilitiesLearned: the Gateway listed an optional capability this
// Agent held back (GatewayHello.known_capabilities); reconnect once so the
// next hello advertises it.
var errCapabilitiesLearned = errors.New("gateway supports held-back capabilities")

const (
	gatewayJournalLockName     = ".gateway-journal.lock"
	firewallControlAPIVersion  = 1
	maximumFirewallCIDRTargets = 10_000
)

type journalLease struct {
	ancestor          *os.File
	namespace         *os.File
	namespaceLockDir  *os.File
	namespaceLock     *os.File
	parent            *os.File
	parentLockDir     *os.File
	parentLock        *os.File
	directory         *os.File
	lock              *os.File
	namespaceName     string
	namespaceInfo     os.FileInfo
	namespaceLockName string
	namespaceLockInfo os.FileInfo
	parentName        string
	parentInfo        os.FileInfo
	parentLockName    string
	parentLockInfo    os.FileInfo
	directoryName     string
	directoryInfo     os.FileInfo
	lockInfo          os.FileInfo
	once              sync.Once
	err               error
}

type Client struct {
	config          Config
	dialer          Dialer
	// learnEndpoints receives the GatewayHello endpoint list (GW-07).
	learnEndpoints func([]*agentv1.GatewayEndpointV1, string)
	// learnNodeOwner receives GatewayHello node_owner_scope_id before any
	// command of the session is handled (A08 host firewall gate).
	learnNodeOwner  func(context.Context, string) error
	manager         DeploymentManager
	certificate     CertificateConsumer
	challenge       ChallengeConsumer
	urlAuth         URLAuthArtifactConsumer
	errorPage       ErrorPageArtifactConsumer
	originAuth      OriginAuthArtifactConsumer
	acmeHTTP01      acmehttp01.Consumer
	cacheTasks      CacheTaskManager
	cacheTaskConfig cachetask.Config
	firewall        FirewallCommandHandler
	runtimeProbe    RuntimeStatusProbe
	renewer         CertificateRenewer
	onRenewed       func(string)
	recoverer       CertificateRecoverer
	drain           DrainPlanHandler
	upgrades        UpgradeRuntime
	nodeMonitoring  *NodeMonitoringBridge
	signerTrust     SignerTrustApplier
	installationBan InstallationBanApplier
	siteDrop        SiteDropApplier
	gatewayAddress  *GatewayAddressRuntime
	securityBans    SecurityBanApplier
	sched302        Sched302Applier
	autoDefense     AutoDefenseRuntime
	artifactSets    ArtifactSetRuntime
	// declaredIPIntel: this session's hello declared IP_INTEL (an applied
	// node artifact set holds a library).
	declaredIPIntel atomic.Bool
	marketProbe     MarketProbeExecutor
	l4Live          L4LiveExecutor
	// gatewayKnowsL4Live: a Gateway listed L4_LIVE_CONNECTIONS in
	// known_capabilities, so advertising it cannot cost the session facts
	// on a Gateway that does not know it.
	gatewayKnowsL4Live atomic.Bool
	liveCapability     *liveCapability // changes at run time (XDP_FILTER)
	extraChecks        func() []*agentv1.CheckResult
	nodeInventory      func(context.Context) *agentv1.ReportNodeNetworkInventoryV1Request
	portTransition     *PortTransitionRuntime
	trust              *TrustStore
	store              *durableStore
	overlayStore       *overlayDurableStore
	cacheStore         *cacheControlDurableStore
	cacheCancels       *cacheCancelRegistry
	activeIdentity     activeConfigIdentityState
	journalLease       *journalLease
	closeOnce          sync.Once
	closeErr           error
	lifecycleMu        sync.Mutex
	running            bool
	closed             bool
	runCancel          context.CancelFunc
	runDone            chan struct{}
	now                func() time.Time
	jitter             func(time.Duration) time.Duration

	// siteObjects is the object store of site_runtime 9 deployments.
	siteObjects       *objectstore.Store
	dynamicRouting    DynamicRoutingApplier
	siteObjectStatsMu sync.Mutex
	siteObjectStats   SiteObjectFetchStats
}

// FirewallCommandHandler consumes one strictly validated immutable carrier and
// returns its bound terminal status. Business execution and persistence remain
// outside the gateway client.
type FirewallCommandHandler interface {
	HandleFirewallCommand(context.Context, *agentv1.FirewallCommand) (*agentv1.FirewallStatus, error)
}

type FirewallManager interface {
	Apply(context.Context, firewall.FirewallVersion) (firewall.Result, error)
}

// RuntimeStatusProbe reads the local data-plane health used in heartbeats.
// A nil Firewall probe means the firewall runtime is not enabled.
type RuntimeStatusProbe struct {
	OpenResty func(context.Context, string) error
	Firewall  func(context.Context) error
	// ErrorLog, when set, is the dynamic routing node's error.log summary
	// (EdgeRuntimeStatus.error_log).
	ErrorLog func() *agentv1.ErrorLogSummary
	// MarketProbeRole is reported as EdgeRuntimeStatus.market_probe.
	MarketProbeRole agentv1.MarketProbeRole
	// NativeRuntime, when set (native nodes), is the outcome of the last
	// native runtime switch (EdgeRuntimeStatus.native_runtime); nil: absent.
	NativeRuntime func() *agentv1.NativeRuntimeStatus
}

type CertificateRenewer interface {
	Renew(context.Context, agentv1.AgentGatewayServiceClient) (bool, string, error)
}

// CertificateRecoverer recovers an expired client certificate over the
// Gateway enrollment listener (ADR 0013 GW-02; enrollment.Recoverer).
type CertificateRecoverer interface {
	RecoveryDue() bool
	Recover(context.Context) (bool, string, error)
}

type firewallManagerHandler struct {
	manager FirewallManager
	now     func() time.Time
}

type workResult struct {
	item workItem
	err  error
}

type workKind uint8

const (
	workDeployment workKind = iota + 1
	workACMEHTTP01Overlay
	workCacheControl
)

type workItem struct {
	kind workKind
	key  string
}

type receiveResult struct {
	response *agentv1.ConnectResponse
	err      error
}

func New(config Config, dialer Dialer, manager DeploymentManager, trust *TrustStore, options ...ClientOption) (*Client, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	if dialer == nil || manager == nil || trust == nil {
		return nil, fmt.Errorf("%w: dialer, deployment manager, and trust store are required", ErrInvalidConfiguration)
	}
	config.Capabilities = proto.Clone(config.Capabilities).(*agentv1.AgentCapabilities)
	config.SupportedVersions = proto.Clone(config.SupportedVersions).(*commonv1.ProtocolVersionRange)
	config.ArtifactDecryptionPrivateKey = append([]byte(nil), config.ArtifactDecryptionPrivateKey...)
	if err := ensureActiveConfigIdentityCapability(config.Capabilities); err != nil {
		return nil, fmt.Errorf("%w: active config identity capability must be v1", ErrInvalidConfiguration)
	}
	if err := ensureDeploymentStatusAckReceiptCapability(config.Capabilities); err != nil {
		return nil, fmt.Errorf("%w: deployment status acknowledgement receipt capability must be v1", ErrInvalidConfiguration)
	}
	lease, err := acquireJournalLease(config.JournalDir)
	if err != nil {
		return nil, err
	}
	keepLease := false
	defer func() {
		if !keepLease {
			_ = lease.Close()
		}
	}()
	store, overlayStore, cacheStore, err := initializeJournalStores(
		lease, config.MaxCommandBytes, config.MaxStatusBytes,
	)
	if err != nil {
		return nil, err
	}
	if err := lease.Verify(); err != nil {
		return nil, err
	}
	client := &Client{
		config: config, dialer: dialer, manager: manager, trust: trust, store: store, overlayStore: overlayStore, cacheStore: cacheStore,
		cacheCancels: newCacheCancelRegistry(),
		journalLease: lease, now: time.Now, cacheTaskConfig: cachetask.DefaultConfig(),
		jitter: func(duration time.Duration) time.Duration {
			return time.Duration(float64(duration) * (0.8 + rand.Float64()*0.4))
		},
	}
	for _, option := range options {
		if option == nil {
			return nil, fmt.Errorf("%w: client option is nil", ErrInvalidConfiguration)
		}
		if err := option(client); err != nil {
			return nil, err
		}
	}
	if client.challenge == nil {
		if provider, ok := manager.(interface{ StateRoot() string }); ok {
			installer, err := challenge.NewArtifactInstaller(provider.StateRoot())
			if err != nil {
				return nil, fmt.Errorf("%w: initialize challenge consumer: %v", ErrInvalidConfiguration, err)
			}
			client.challenge = installer
		}
	}
	if client.cacheTasks == nil {
		client.config.Capabilities.Features = removeCapability(client.config.Capabilities.Features, agentv1.CapabilityName_CAPABILITY_NAME_CACHE_CONTROL)
	}
	if client.firewall == nil {
		client.config.Capabilities.Features = removeCapability(client.config.Capabilities.Features, agentv1.CapabilityName_CAPABILITY_NAME_FIREWALL_CONTROL)
	}
	if client.drain == nil {
		client.config.Capabilities.Features = removeCapability(client.config.Capabilities.Features, agentv1.CapabilityName_CAPABILITY_NAME_DRAIN_CONTROL)
	}
	keepLease = true
	return client, nil
}

func WithFirewallCommandHandler(handler FirewallCommandHandler) ClientOption {
	return func(client *Client) error {
		if handler == nil {
			return fmt.Errorf("%w: firewall command handler is required", ErrInvalidConfiguration)
		}
		client.firewall = handler
		return nil
	}
}

// WithNodeOwnerHandler hands the node owner scope of every GatewayHello to
// learn (the host firewall's SetOwnerScope).
func WithNodeOwnerHandler(learn func(context.Context, string) error) ClientOption {
	return func(client *Client) error {
		if learn == nil {
			return fmt.Errorf("%w: node owner handler is required", ErrInvalidConfiguration)
		}
		client.learnNodeOwner = learn
		return nil
	}
}

func WithFirewallManager(manager FirewallManager) ClientOption {
	return func(client *Client) error {
		if manager == nil {
			return fmt.Errorf("%w: firewall manager is required", ErrInvalidConfiguration)
		}
		client.firewall = newFirewallManagerHandler(manager, func() time.Time { return client.now() })
		return nil
	}
}

func WithRuntimeStatusProbe(probe RuntimeStatusProbe) ClientOption {
	return func(client *Client) error {
		if probe.OpenResty == nil {
			return fmt.Errorf("%w: OpenResty runtime status probe is required", ErrInvalidConfiguration)
		}
		client.runtimeProbe = probe
		return nil
	}
}

func WithCertificateRenewer(renewer CertificateRenewer, onRenewed func(string)) ClientOption {
	return func(client *Client) error {
		if renewer == nil {
			return fmt.Errorf("%w: certificate renewer is required", ErrInvalidConfiguration)
		}
		client.renewer = renewer
		client.onRenewed = onRenewed
		return nil
	}
}

// WithCertificateRecoverer makes Run recover an expired client certificate
// before dialing: an expired certificate cannot pass the mTLS handshake, so
// the agent keeps serving (OpenResty is independent) and retries recovery
// with the recoverer's own backoff until it succeeds.
func WithCertificateRecoverer(recoverer CertificateRecoverer) ClientOption {
	return func(client *Client) error {
		if recoverer == nil {
			return fmt.Errorf("%w: certificate recoverer is required", ErrInvalidConfiguration)
		}
		client.recoverer = recoverer
		return nil
	}
}

func newFirewallManagerHandler(manager FirewallManager, now func() time.Time) FirewallCommandHandler {
	return &firewallManagerHandler{manager: manager, now: now}
}

func firewallCommandDigest(command *agentv1.FirewallCommand) ([]byte, error) {
	if command == nil {
		return nil, fmt.Errorf("%w: firewall command is missing", ErrInvalidMessage)
	}
	identity := proto.Clone(command).(*agentv1.FirewallCommand)
	identity.CommandSha256 = nil
	identity.Signature = nil
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(identity)
	if err != nil {
		return nil, fmt.Errorf("%w: encode firewall command identity", ErrInvalidMessage)
	}
	digest := sha256.Sum256(encoded)
	return digest[:], nil
}

func verifyFirewallCommandSignature(command *agentv1.FirewallCommand, trust *TrustStore) error {
	if len(command.Signature) == 0 && command.SigningKeyId == "" &&
		command.SignatureAlgorithm == agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_UNSPECIFIED {
		return nil
	}
	key, ok := trust.key(command.SigningKeyId)
	ed25519Key, typed := key.(ed25519.PublicKey)
	if !ok || !typed || len(ed25519Key) != ed25519.PublicKeySize ||
		command.SignatureAlgorithm != agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519 ||
		len(command.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("%w: firewall command signature metadata is invalid", ErrInvalidMessage)
	}
	identity := proto.Clone(command).(*agentv1.FirewallCommand)
	identity.CommandSha256 = nil
	identity.Signature = nil
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(identity)
	if err != nil || !ed25519.Verify(ed25519Key, encoded, command.Signature) {
		return fmt.Errorf("%w: firewall command signature is invalid", ErrInvalidMessage)
	}
	return nil
}

func validateFirewallCommand(command *agentv1.FirewallCommand, config Config, now time.Time) error {
	if command == nil || proto.Size(command) > config.MaxCommandBytes || cacheControlMessageHasUnknown(command.ProtoReflect()) {
		return fmt.Errorf("%w: firewall command is missing, oversized, or contains unknown fields", ErrInvalidMessage)
	}
	event := command.Event
	if event == nil || !canonicalUUID(event.EventId) || !canonicalUUID(event.RequestId) ||
		event.OccurredTime == nil || event.OccurredTime.CheckValid() != nil ||
		!boundedMetadata(event.Traceparent, false) || !boundedMetadata(event.CorrelationId, false) ||
		event.TaskId == nil || event.GetTaskId() != command.TaskId ||
		(event.CausationId != nil && !canonicalUUID(event.GetCausationId())) {
		return fmt.Errorf("%w: firewall command event is invalid", ErrInvalidMessage)
	}
	if command.Schema != agentv1.FirewallSchema_FIREWALL_SCHEMA_V1 || !safeIdentifier(command.TaskId) ||
		command.TaskRevision == 0 || !canonicalUUID(command.IdempotencyKey) ||
		!canonicalUUID(command.TenantId) || !canonicalUUID(command.SiteId) ||
		!canonicalUUID(command.NodeId) || command.NodeId != config.NodeID || command.PolicyVersion == 0 ||
		command.TaskRevision <= command.ExpectedActivePolicyVersion || !validFirewallPolicyIdentity(command.PolicyKind, command.PolicyId) {
		return fmt.Errorf("%w: firewall command identity or scope is invalid", ErrInvalidMessage)
	}
	switch command.Operation {
	case agentv1.FirewallOperation_FIREWALL_OPERATION_APPLY:
		if command.PolicyVersion != command.ExpectedActivePolicyVersion+1 ||
			command.RecoveryReason != agentv1.FirewallRecoveryReason_FIREWALL_RECOVERY_REASON_NOT_APPLICABLE {
			return fmt.Errorf("%w: firewall apply ordering is invalid", ErrInvalidMessage)
		}
	case agentv1.FirewallOperation_FIREWALL_OPERATION_RECOVER:
		if command.PolicyVersion != command.ExpectedActivePolicyVersion+1 ||
			command.RecoveryReason == agentv1.FirewallRecoveryReason_FIREWALL_RECOVERY_REASON_UNSPECIFIED ||
			command.RecoveryReason == agentv1.FirewallRecoveryReason_FIREWALL_RECOVERY_REASON_NOT_APPLICABLE {
			return fmt.Errorf("%w: firewall recovery ordering or reason is invalid", ErrInvalidMessage)
		}
		if _, known := agentv1.FirewallRecoveryReason_name[int32(command.RecoveryReason)]; !known {
			return fmt.Errorf("%w: firewall recovery reason is unknown", ErrInvalidMessage)
		}
	default:
		return fmt.Errorf("%w: firewall operation is unknown", ErrInvalidMessage)
	}
	if len(command.Targets) > maximumFirewallCIDRTargets {
		return fmt.Errorf("%w: too many firewall CIDR targets", ErrInvalidMessage)
	}
	seenCIDRs := make(map[string]struct{}, len(command.Targets))
	for index, target := range command.Targets {
		if target == nil || target.Ordinal != uint32(index+1) || target.TenantId != command.TenantId || target.SiteId != command.SiteId {
			return fmt.Errorf("%w: firewall CIDR ownership or order is invalid", ErrInvalidMessage)
		}
		if target.Action != agentv1.FirewallCIDRAction_FIREWALL_CIDR_ACTION_ALLOW && target.Action != agentv1.FirewallCIDRAction_FIREWALL_CIDR_ACTION_DENY {
			return fmt.Errorf("%w: firewall CIDR action is unknown", ErrInvalidMessage)
		}
		if !validFirewallProtocolPorts(target.Protocol, target.PortStart, target.PortEnd) {
			return fmt.Errorf("%w: firewall target protocol or port range is invalid", ErrInvalidMessage)
		}
		prefix, err := netip.ParsePrefix(target.Cidr)
		address := prefix.Addr()
		if err != nil || prefix != prefix.Masked() || prefix.String() != target.Cidr || address.Is4In6() ||
			address.IsUnspecified() || address.IsMulticast() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || prefix.Bits() == 0 ||
			!safeIdentifier(target.Source) || len(target.Source) > 64 || !safeIdentifier(target.ReasonCode) {
			return fmt.Errorf("%w: firewall CIDR target is invalid", ErrInvalidMessage)
		}
		targetKey := fmt.Sprintf("%s\x00%d\x00%d\x00%d", target.Cidr, target.Protocol, target.PortStart, target.PortEnd)
		if _, exists := seenCIDRs[targetKey]; exists {
			return fmt.Errorf("%w: duplicate firewall CIDR target", ErrInvalidMessage)
		}
		seenCIDRs[targetKey] = struct{}{}
		if target.ExpirationTime != nil && (target.ExpirationTime.CheckValid() != nil || !target.ExpirationTime.AsTime().After(now)) {
			return fmt.Errorf("%w: firewall CIDR expiration is invalid", ErrInvalidMessage)
		}
	}
	if command.DeadlineTime == nil || command.DeadlineTime.CheckValid() != nil ||
		!command.DeadlineTime.AsTime().After(now) || command.DeadlineTime.AsTime().After(now.Add(24*time.Hour)) {
		return fmt.Errorf("%w: firewall command deadline is invalid", ErrInvalidMessage)
	}
	digest, err := firewallCommandDigest(command)
	if err != nil || len(command.CommandSha256) != sha256.Size || !bytes.Equal(command.CommandSha256, digest) {
		return fmt.Errorf("%w: firewall command identity digest is invalid", ErrInvalidMessage)
	}
	return nil
}

func validFirewallPolicyIdentity(kind, id string) bool {
	if kind == "" && id == "" {
		return true
	}
	return (kind == "acl" || kind == "global") && canonicalUUID(id)
}

func validFirewallProtocolPorts(protocol agentv1.FirewallProtocol, start, end uint32) bool {
	switch protocol {
	case agentv1.FirewallProtocol_FIREWALL_PROTOCOL_UNSPECIFIED, agentv1.FirewallProtocol_FIREWALL_PROTOCOL_ANY,
		agentv1.FirewallProtocol_FIREWALL_PROTOCOL_ICMP:
		return start == 0 && end == 0
	case agentv1.FirewallProtocol_FIREWALL_PROTOCOL_TCP, agentv1.FirewallProtocol_FIREWALL_PROTOCOL_UDP:
		return start == 0 && end == 0 || start > 0 && end >= start && end <= 65535
	default:
		return false
	}
}

func (handler *firewallManagerHandler) HandleFirewallCommand(ctx context.Context, command *agentv1.FirewallCommand) (*agentv1.FirewallStatus, error) {
	version, err := firewallVersionFromCommand(command)
	if err != nil {
		return nil, err
	}
	result, err := handler.manager.Apply(ctx, version)
	if err != nil {
		return nil, err
	}
	if result.TaskID != command.TaskId || result.TaskRevision != command.TaskRevision || result.IdempotencyKey != command.IdempotencyKey ||
		result.TenantID != command.TenantId || result.SiteID != command.SiteId || result.PolicyVersion != command.PolicyVersion ||
		result.ExpectedActivePolicyVersion != command.ExpectedActivePolicyVersion {
		return nil, fmt.Errorf("%w: firewall manager result is not bound to command", ErrInvalidMessage)
	}
	state := agentv1.FirewallStatusState_FIREWALL_STATUS_STATE_UNSPECIFIED
	switch result.State {
	case firewall.StateApplied:
		state = agentv1.FirewallStatusState_FIREWALL_STATUS_STATE_APPLIED
		if command.Operation == agentv1.FirewallOperation_FIREWALL_OPERATION_RECOVER {
			state = agentv1.FirewallStatusState_FIREWALL_STATUS_STATE_ROLLED_BACK
		}
	case firewall.StateFailed:
		state = agentv1.FirewallStatusState_FIREWALL_STATUS_STATE_FAILED
	case firewall.StateRolledBack:
		state = agentv1.FirewallStatusState_FIREWALL_STATUS_STATE_ROLLED_BACK
	case firewall.StateRollbackFailed:
		state = agentv1.FirewallStatusState_FIREWALL_STATUS_STATE_FAILED
	default:
		return nil, fmt.Errorf("%w: firewall manager result state is unknown", ErrInvalidMessage)
	}
	taskID, causationID := command.TaskId, command.Event.EventId
	eventID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(fmt.Sprintf("firewall:%s:%d:%s", command.Event.EventId, result.TaskRevision, result.State))).String()
	status := &agentv1.FirewallStatus{
		Event: &commonv1.EventMetadata{
			EventId: eventID, RequestId: command.Event.RequestId, OccurredTime: timestamppb.New(handler.now().UTC()),
			Traceparent: command.Event.Traceparent, CausationId: &causationID, CorrelationId: command.Event.CorrelationId, TaskId: &taskID,
		},
		Schema: command.Schema, TaskId: command.TaskId, TaskRevision: command.TaskRevision,
		IdempotencyKey: command.IdempotencyKey, TenantId: command.TenantId, SiteId: command.SiteId, NodeId: command.NodeId,
		PolicyVersion: command.PolicyVersion, ExpectedActivePolicyVersion: command.ExpectedActivePolicyVersion,
		Operation: command.Operation, RecoveryReason: command.RecoveryReason,
		CommandSha256: append([]byte(nil), command.CommandSha256...), State: state, StatusRevision: 1,
		ActivePolicyVersion: result.ActivePolicyVersion, ActivePolicyUnchanged: result.RunningVersionUnchanged,
		ErrorCode: result.ErrorCode,
	}
	if result.State == firewall.StateRollbackFailed {
		status.ActivePolicyVersion = 0
		status.ActivePolicyUnchanged = false
	}
	return status, nil
}

func firewallVersionFromCommand(command *agentv1.FirewallCommand) (firewall.FirewallVersion, error) {
	if command == nil {
		return firewall.FirewallVersion{}, ErrInvalidMessage
	}
	operation := firewall.OperationApply
	if command.Operation == agentv1.FirewallOperation_FIREWALL_OPERATION_RECOVER {
		operation = firewall.OperationRecover
	}
	reason := map[agentv1.FirewallRecoveryReason]firewall.RecoveryReason{
		agentv1.FirewallRecoveryReason_FIREWALL_RECOVERY_REASON_NOT_APPLICABLE:    firewall.RecoveryReasonNotApplicable,
		agentv1.FirewallRecoveryReason_FIREWALL_RECOVERY_REASON_FALSE_POSITIVE:    firewall.RecoveryReasonFalsePositive,
		agentv1.FirewallRecoveryReason_FIREWALL_RECOVERY_REASON_POLICY_REGRESSION: firewall.RecoveryReasonPolicyRegression,
		agentv1.FirewallRecoveryReason_FIREWALL_RECOVERY_REASON_HEALTH_FAILURE:    firewall.RecoveryReasonHealthFailure,
		agentv1.FirewallRecoveryReason_FIREWALL_RECOVERY_REASON_OPERATOR_REQUEST:  firewall.RecoveryReasonOperatorRequest,
	}[command.RecoveryReason]
	policyKind, policyID := command.PolicyKind, command.PolicyId
	if policyKind == "" && policyID == "" {
		policyKind = "legacy_acl"
		policyID = uuid.NewSHA1(uuid.MustParse(command.SiteId), []byte("cdnca.firewall.legacy_acl")).String()
	}
	entries := make([]firewall.Entry, 0, len(command.Targets))
	for _, target := range command.Targets {
		action := firewall.ActionDeny
		if target.Action == agentv1.FirewallCIDRAction_FIREWALL_CIDR_ACTION_ALLOW {
			action = firewall.ActionAllow
		}
		entry := firewall.Entry{
			TenantID: target.TenantId, SiteID: target.SiteId, Action: action,
			Network: target.Cidr, Protocol: firewallProtocolFromCommand(target.Protocol),
			PortStart: uint16(target.PortStart), PortEnd: uint16(target.PortEnd),
			Source: target.Source, Reason: target.ReasonCode,
		}
		if target.ExpirationTime != nil {
			expires := target.ExpirationTime.AsTime().UTC()
			entry.ExpiresAt = &expires
		}
		entries = append(entries, entry)
	}
	return firewall.FirewallVersion{
		TaskID: command.TaskId, TaskRevision: command.TaskRevision, IdempotencyKey: command.IdempotencyKey,
		TenantID: command.TenantId, SiteID: command.SiteId, PolicyKind: policyKind, PolicyID: policyID, PolicyVersion: command.PolicyVersion,
		ExpectedActivePolicyVersion: command.ExpectedActivePolicyVersion,
		Operation:                   operation, RecoveryReason: reason, CommandDigest: hex.EncodeToString(command.CommandSha256),
		VersionID: "runtime-" + command.IdempotencyKey, Entries: entries,
	}, nil
}

func firewallProtocolFromCommand(protocol agentv1.FirewallProtocol) firewall.Protocol {
	switch protocol {
	case agentv1.FirewallProtocol_FIREWALL_PROTOCOL_TCP:
		return firewall.ProtocolTCP
	case agentv1.FirewallProtocol_FIREWALL_PROTOCOL_UDP:
		return firewall.ProtocolUDP
	case agentv1.FirewallProtocol_FIREWALL_PROTOCOL_ICMP:
		return firewall.ProtocolICMP
	default:
		return firewall.ProtocolAny
	}
}

func validateFirewallStatusForCommand(status *agentv1.FirewallStatus, command *agentv1.FirewallCommand, config Config) error {
	if status == nil || proto.Size(status) > config.MaxStatusBytes || cacheControlMessageHasUnknown(status.ProtoReflect()) || command == nil {
		return fmt.Errorf("%w: firewall status is missing, oversized, or contains unknown fields", ErrInvalidMessage)
	}
	event := status.Event
	if event == nil || !canonicalUUID(event.EventId) || event.RequestId != command.Event.RequestId ||
		event.OccurredTime == nil || event.OccurredTime.CheckValid() != nil ||
		!boundedMetadata(event.Traceparent, false) || !boundedMetadata(event.CorrelationId, false) ||
		event.CausationId == nil || event.GetCausationId() != command.Event.EventId ||
		event.TaskId == nil || event.GetTaskId() != command.TaskId {
		return fmt.Errorf("%w: firewall status event is invalid", ErrInvalidMessage)
	}
	if status.Schema != command.Schema || status.TaskId != command.TaskId || status.TaskRevision != command.TaskRevision ||
		status.IdempotencyKey != command.IdempotencyKey || status.TenantId != command.TenantId || status.SiteId != command.SiteId ||
		status.NodeId != command.NodeId || status.PolicyVersion != command.PolicyVersion ||
		status.ExpectedActivePolicyVersion != command.ExpectedActivePolicyVersion || status.Operation != command.Operation ||
		status.RecoveryReason != command.RecoveryReason || !bytes.Equal(status.CommandSha256, command.CommandSha256) || status.StatusRevision == 0 {
		return fmt.Errorf("%w: firewall status is not bound to its command", ErrInvalidMessage)
	}
	switch status.State {
	case agentv1.FirewallStatusState_FIREWALL_STATUS_STATE_APPLIED:
		if command.Operation != agentv1.FirewallOperation_FIREWALL_OPERATION_APPLY || status.ActivePolicyVersion != command.PolicyVersion ||
			status.ActivePolicyUnchanged || status.ErrorCode != "" {
			return fmt.Errorf("%w: firewall applied status is inconsistent", ErrInvalidMessage)
		}
	case agentv1.FirewallStatusState_FIREWALL_STATUS_STATE_FAILED:
		rollbackFailed := status.ErrorCode == "ROLLBACK_FAILED" && status.ActivePolicyVersion == 0 && !status.ActivePolicyUnchanged
		if (!rollbackFailed && (status.ActivePolicyVersion != command.ExpectedActivePolicyVersion || !status.ActivePolicyUnchanged)) || !safeIdentifier(status.ErrorCode) {
			return fmt.Errorf("%w: firewall failed status is inconsistent", ErrInvalidMessage)
		}
	case agentv1.FirewallStatusState_FIREWALL_STATUS_STATE_ROLLED_BACK:
		if command.Operation == agentv1.FirewallOperation_FIREWALL_OPERATION_APPLY {
			if status.ActivePolicyVersion != command.ExpectedActivePolicyVersion || !status.ActivePolicyUnchanged || !safeIdentifier(status.ErrorCode) {
				return fmt.Errorf("%w: firewall rollback status is inconsistent", ErrInvalidMessage)
			}
		} else if status.ActivePolicyVersion != command.PolicyVersion || status.ActivePolicyUnchanged || status.ErrorCode != "" {
			return fmt.Errorf("%w: firewall recovery status is inconsistent", ErrInvalidMessage)
		}
	default:
		return fmt.Errorf("%w: firewall status state is unknown", ErrInvalidMessage)
	}
	return nil
}

func (c *Client) dispatchFirewallCommand(ctx context.Context, command *agentv1.FirewallCommand) (*agentv1.FirewallStatus, error) {
	if c.firewall == nil {
		return nil, fmt.Errorf("%w: firewall command handler is unavailable", ErrInvalidMessage)
	}
	if err := validateFirewallCommand(command, c.config, c.now()); err != nil {
		return nil, err
	}
	if err := verifyFirewallCommandSignature(command, c.trust); err != nil {
		return nil, err
	}
	immutable := proto.Clone(command).(*agentv1.FirewallCommand)
	status, err := c.firewall.HandleFirewallCommand(ctx, immutable)
	if err != nil {
		return nil, err
	}
	if err := validateFirewallStatusForCommand(status, command, c.config); err != nil {
		return nil, err
	}
	return proto.Clone(status).(*agentv1.FirewallStatus), nil
}

func negotiateFirewallControlV1(gateway *agentv1.GatewayHello, local *agentv1.AgentCapabilities) (bool, error) {
	localV1 := false
	for _, capability := range local.GetFeatures() {
		if capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_FIREWALL_CONTROL {
			if capability.GetApiVersion() != firewallControlAPIVersion {
				return false, fmt.Errorf("%w: local firewall capability version is unsupported", ErrInvalidMessage)
			}
			localV1 = true
		}
	}
	gatewayV1 := false
	for _, capability := range gateway.GetEnabledCapabilities() {
		if capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_FIREWALL_CONTROL {
			if capability.GetApiVersion() != firewallControlAPIVersion {
				return false, fmt.Errorf("%w: Gateway firewall capability version is unsupported", ErrInvalidMessage)
			}
			gatewayV1 = true
		}
	}
	if gatewayV1 && !localV1 {
		return false, fmt.Errorf("%w: Gateway enabled an unadvertised firewall capability", ErrInvalidMessage)
	}
	return gatewayV1 && localV1, nil
}

func acquireJournalLease(path string) (*journalLease, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return nil, fmt.Errorf("%w: gateway journal path must be absolute and clean", ErrInvalidConfiguration)
	}
	parentPath := filepath.Dir(path)
	if err := rejectSymlinkPathComponents(parentPath, false); err != nil {
		return nil, err
	}
	parentInfo, err := os.Lstat(parentPath)
	if err != nil || parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() {
		return nil, fmt.Errorf("%w: gateway journal parent must be a directory and not a symlink", ErrInvalidConfiguration)
	}
	namespacePath := filepath.Dir(parentPath)
	namespaceInfo, err := os.Lstat(namespacePath)
	if err != nil || namespaceInfo.Mode()&os.ModeSymlink != 0 || !namespaceInfo.IsDir() {
		return nil, fmt.Errorf("%w: gateway journal namespace must be a directory and not a symlink", ErrInvalidConfiguration)
	}
	ancestorPath := filepath.Dir(namespacePath)
	namespaceName := filepath.Base(namespacePath)
	if namespacePath == string(filepath.Separator) {
		namespaceName = "."
	}
	ancestorFD, err := unix.Open(ancestorPath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, fmt.Errorf("open gateway journal lease ancestor: %w", err)
	}
	ancestor := os.NewFile(uintptr(ancestorFD), ancestorPath)
	if ancestor == nil {
		_ = unix.Close(ancestorFD)
		return nil, fmt.Errorf("open gateway journal lease ancestor")
	}
	closeAncestor := true
	defer func() {
		if closeAncestor {
			_ = ancestor.Close()
		}
	}()
	parentName := filepath.Base(parentPath)
	if parentPath == string(filepath.Separator) {
		parentName = "."
	}
	namespaceFD, err := unix.Openat(ancestorFD, namespaceName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, fmt.Errorf("open gateway journal lease namespace: %w", err)
	}
	namespace := os.NewFile(uintptr(namespaceFD), namespacePath)
	if namespace == nil {
		_ = unix.Close(namespaceFD)
		return nil, fmt.Errorf("open gateway journal lease namespace")
	}
	closeNamespace := true
	defer func() {
		if closeNamespace {
			_ = namespace.Close()
		}
	}()
	openedNamespaceInfo, err := namespace.Stat()
	if err != nil || !os.SameFile(namespaceInfo, openedNamespaceInfo) || !openedNamespaceInfo.IsDir() {
		return nil, fmt.Errorf("gateway journal lease namespace changed during acquisition")
	}
	parentFD, err := unix.Openat(namespaceFD, parentName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, fmt.Errorf("open gateway journal lease parent: %w", err)
	}
	parent := os.NewFile(uintptr(parentFD), parentPath)
	if parent == nil {
		_ = unix.Close(parentFD)
		return nil, fmt.Errorf("open gateway journal lease parent")
	}
	closeParent := true
	defer func() {
		if closeParent {
			_ = parent.Close()
		}
	}()
	openedParentInfo, err := parent.Stat()
	if err != nil || !os.SameFile(parentInfo, openedParentInfo) || !openedParentInfo.IsDir() {
		return nil, fmt.Errorf("gateway journal lease parent changed during acquisition")
	}
	namespaceLockName := gatewayJournalNamespaceLockName(path)
	namespaceLockDir := ancestor
	namespaceLockFD, createdNamespaceLock, err := openJournalLeaseLock(ancestorFD, namespaceLockName)
	if errors.Is(err, unix.EROFS) || errors.Is(err, unix.EACCES) {
		// ProtectSystem=strict makes immutable ancestors read-only. Keep the
		// external lock when it already exists; otherwise use the bound state
		// directory, whose identity is still verified through ancestorFD.
		probeFD, probeErr := unix.Openat(ancestorFD, namespaceLockName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if probeErr == nil {
			_ = unix.Close(probeFD)
		} else if errors.Is(probeErr, unix.ENOENT) || errors.Is(probeErr, unix.EACCES) {
			namespaceLockDir = parent
			namespaceLockFD, createdNamespaceLock, err = openJournalLeaseLock(int(parent.Fd()), namespaceLockName)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("open gateway journal namespace lease: %w", err)
	}
	namespaceLock := os.NewFile(uintptr(namespaceLockFD), namespaceLockName)
	if namespaceLock == nil {
		_ = unix.Close(namespaceLockFD)
		return nil, fmt.Errorf("open gateway journal namespace lease")
	}
	closeNamespaceLock := true
	defer func() {
		if closeNamespaceLock {
			_ = namespaceLock.Close()
		}
	}()
	namespaceLockInfo, err := namespaceLock.Stat()
	var namespaceLockStat unix.Stat_t
	if statErr := unix.Fstat(namespaceLockFD, &namespaceLockStat); err != nil || statErr != nil || !namespaceLockInfo.Mode().IsRegular() || namespaceLockInfo.Mode().Perm()&0o077 != 0 || namespaceLockStat.Nlink != 1 {
		return nil, fmt.Errorf("gateway journal namespace lease file is invalid")
	}
	if err := unix.Flock(namespaceLockFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("gateway journal is already owned by another client")
		}
		return nil, fmt.Errorf("lock gateway journal namespace lease: %w", err)
	}
	parentLockName := gatewayJournalParentLockName(path)
	parentLockDir := namespace
	parentLockFD, createdParentLock, err := openJournalLeaseLock(namespaceFD, parentLockName)
	if errors.Is(err, unix.EROFS) || errors.Is(err, unix.EACCES) {
		probeFD, probeErr := unix.Openat(namespaceFD, parentLockName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if probeErr == nil {
			_ = unix.Close(probeFD)
		} else if errors.Is(probeErr, unix.ENOENT) || errors.Is(probeErr, unix.EACCES) {
			parentLockDir = parent
			parentLockFD, createdParentLock, err = openJournalLeaseLock(int(parent.Fd()), parentLockName)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("open gateway journal parent lease: %w", err)
	}
	parentLock := os.NewFile(uintptr(parentLockFD), parentLockName)
	if parentLock == nil {
		_ = unix.Close(parentLockFD)
		return nil, fmt.Errorf("open gateway journal parent lease")
	}
	closeParentLock := true
	defer func() {
		if closeParentLock {
			_ = parentLock.Close()
		}
	}()
	parentLockInfo, err := parentLock.Stat()
	var parentLockStat unix.Stat_t
	if statErr := unix.Fstat(parentLockFD, &parentLockStat); err != nil || statErr != nil || !parentLockInfo.Mode().IsRegular() || parentLockInfo.Mode().Perm()&0o077 != 0 || parentLockStat.Nlink != 1 {
		return nil, fmt.Errorf("gateway journal parent lease file is invalid")
	}
	if err := unix.Flock(parentLockFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("gateway journal is already owned by another client")
		}
		return nil, fmt.Errorf("lock gateway journal parent lease: %w", err)
	}
	journalName := filepath.Base(path)
	createdDirectory := false
	directoryFD, err := unix.Openat(parentFD, journalName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if errors.Is(err, unix.ENOENT) {
		if err := unix.Mkdirat(parentFD, journalName, 0o700); err != nil {
			return nil, fmt.Errorf("create gateway journal lease directory: %w", err)
		}
		createdDirectory = true
		directoryFD, err = unix.Openat(parentFD, journalName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	}
	if err != nil {
		return nil, fmt.Errorf("open gateway journal lease directory: %w", err)
	}
	directory := os.NewFile(uintptr(directoryFD), path)
	if directory == nil {
		_ = unix.Close(directoryFD)
		return nil, fmt.Errorf("open gateway journal lease directory")
	}
	closeDirectory := true
	defer func() {
		if closeDirectory {
			_ = directory.Close()
		}
	}()
	directoryInfo, err := directory.Stat()
	if err != nil || !directoryInfo.IsDir() || directoryInfo.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("gateway journal lease directory is invalid")
	}
	if err := unix.Flock(directoryFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("gateway journal is already owned by another client")
		}
		return nil, fmt.Errorf("lock gateway journal lease directory: %w", err)
	}

	created := false
	lockFD, err := unix.Openat(
		directoryFD, gatewayJournalLockName,
		unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_CREAT|unix.O_EXCL,
		0o600,
	)
	if errors.Is(err, unix.EEXIST) {
		lockFD, err = unix.Openat(directoryFD, gatewayJournalLockName, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	} else if err == nil {
		created = true
	}
	if err != nil {
		return nil, fmt.Errorf("open gateway journal lease: %w", err)
	}
	lock := os.NewFile(uintptr(lockFD), gatewayJournalLockName)
	if lock == nil {
		_ = unix.Close(lockFD)
		return nil, fmt.Errorf("open gateway journal lease")
	}
	closeLock := true
	defer func() {
		if closeLock {
			_ = lock.Close()
		}
	}()
	info, err := lock.Stat()
	var lockStat unix.Stat_t
	if statErr := unix.Fstat(lockFD, &lockStat); err != nil || statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || lockStat.Nlink != 1 {
		return nil, fmt.Errorf("gateway journal lease file is invalid")
	}
	if err := unix.Flock(lockFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("gateway journal is already owned by another client")
		}
		return nil, fmt.Errorf("lock gateway journal lease: %w", err)
	}
	lease := &journalLease{
		ancestor: ancestor, namespace: namespace, namespaceLockDir: namespaceLockDir, namespaceLock: namespaceLock,
		parent: parent, parentLockDir: parentLockDir, parentLock: parentLock, directory: directory, lock: lock,
		namespaceName: namespaceName, namespaceInfo: openedNamespaceInfo,
		namespaceLockName: namespaceLockName, namespaceLockInfo: namespaceLockInfo,
		parentName: parentName, parentInfo: openedParentInfo,
		parentLockName: parentLockName, parentLockInfo: parentLockInfo,
		directoryName: journalName, directoryInfo: directoryInfo, lockInfo: info,
	}
	if err := lease.Verify(); err != nil {
		_ = unix.Flock(lockFD, unix.LOCK_UN)
		return nil, err
	}
	if created || createdDirectory || createdParentLock || createdNamespaceLock {
		if err := namespaceLock.Sync(); err != nil {
			_ = unix.Flock(lockFD, unix.LOCK_UN)
			return nil, err
		}
		if err := parentLock.Sync(); err != nil {
			_ = unix.Flock(lockFD, unix.LOCK_UN)
			return nil, err
		}
		if err := lock.Sync(); err != nil {
			_ = unix.Flock(lockFD, unix.LOCK_UN)
			return nil, err
		}
		if err := directory.Sync(); err != nil {
			_ = unix.Flock(lockFD, unix.LOCK_UN)
			return nil, err
		}
		if err := parent.Sync(); err != nil {
			_ = unix.Flock(lockFD, unix.LOCK_UN)
			return nil, err
		}
		if err := namespace.Sync(); err != nil {
			_ = unix.Flock(lockFD, unix.LOCK_UN)
			return nil, err
		}
		if err := ancestor.Sync(); err != nil {
			_ = unix.Flock(lockFD, unix.LOCK_UN)
			return nil, err
		}
	}
	closeAncestor = false
	closeNamespace = false
	closeNamespaceLock = false
	closeParent = false
	closeParentLock = false
	closeDirectory = false
	closeLock = false
	return lease, nil
}

func openJournalLeaseLock(dirFD int, name string) (fd int, created bool, err error) {
	fd, err = unix.Openat(dirFD, name, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_CREAT|unix.O_EXCL, 0o600)
	if errors.Is(err, unix.EEXIST) {
		fd, err = unix.Openat(dirFD, name, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	} else if err == nil {
		created = true
	}
	return fd, created, err
}

func gatewayJournalParentLockName(path string) string {
	digest := sha256.Sum256([]byte(path))
	return fmt.Sprintf(".gateway-journal-%x.lock", digest[:])
}

func gatewayJournalNamespaceLockName(path string) string {
	digest := sha256.Sum256([]byte(path))
	return fmt.Sprintf(".gateway-journal-namespace-%x.lock", digest[:])
}

func initializeJournalStores(lease *journalLease, maxCommandBytes, maxStatusBytes int) (*durableStore, *overlayDurableStore, *cacheControlDurableStore, error) {
	if err := lease.Verify(); err != nil {
		return nil, nil, nil, err
	}
	journalRoot := lease.descriptorPath()
	if journalRoot == "" {
		return nil, nil, nil, fmt.Errorf("gateway journal descriptor path is unavailable")
	}
	artifacts, err := openOrCreateJournalDirectoryAt(lease.directory, "artifacts")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("initialize deployment artifact journal: %w", err)
	}
	if err := artifacts.Close(); err != nil {
		return nil, nil, nil, err
	}
	overlay, err := openOrCreateJournalDirectoryAt(lease.directory, "acme-http01-overlay")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("initialize ACME overlay journal: %w", err)
	}
	overlayArtifacts, err := openOrCreateJournalDirectoryAt(overlay, "artifacts")
	if err != nil {
		overlay.Close()
		return nil, nil, nil, fmt.Errorf("initialize ACME overlay artifact journal: %w", err)
	}
	if err := overlayArtifacts.Close(); err != nil {
		overlay.Close()
		return nil, nil, nil, err
	}
	if err := overlay.Close(); err != nil {
		return nil, nil, nil, err
	}
	cache, err := openOrCreateJournalDirectoryAt(lease.directory, "cache-control")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("initialize cache-control journal: %w", err)
	}
	if err := cache.Close(); err != nil {
		return nil, nil, nil, err
	}
	if err := lease.Verify(); err != nil {
		return nil, nil, nil, err
	}
	overlayRoot := filepath.Join(journalRoot, "acme-http01-overlay")
	return &durableStore{
			directory: journalRoot, artifacts: filepath.Join(journalRoot, "artifacts"),
			maxCommandBytes: maxCommandBytes, maxStatusBytes: maxStatusBytes,
		}, &overlayDurableStore{
			directory: overlayRoot, artifacts: filepath.Join(overlayRoot, "artifacts"),
			maxCommandBytes: maxCommandBytes, maxStatusBytes: maxStatusBytes,
		}, &cacheControlDurableStore{
			directory: filepath.Join(journalRoot, "cache-control"), maxCommandBytes: maxCommandBytes,
			maxStatusBytes: maxStatusBytes, now: time.Now,
		}, nil
}

func openOrCreateJournalDirectoryAt(parent *os.File, name string) (*os.File, error) {
	if parent == nil || name == "" || filepath.Base(name) != name || name == "." || name == ".." {
		return nil, fmt.Errorf("gateway journal directory name is invalid")
	}
	created := false
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if errors.Is(err, unix.ENOENT) {
		if err := unix.Mkdirat(int(parent.Fd()), name, 0o700); err != nil {
			return nil, err
		}
		created = true
		fd, err = unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	}
	if err != nil {
		return nil, err
	}
	directory := os.NewFile(uintptr(fd), name)
	if directory == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("open gateway journal directory")
	}
	info, err := directory.Stat()
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		directory.Close()
		return nil, fmt.Errorf("gateway journal directory is invalid")
	}
	if created {
		if err := directory.Sync(); err != nil {
			directory.Close()
			return nil, err
		}
		if err := parent.Sync(); err != nil {
			directory.Close()
			return nil, err
		}
	}
	return directory, nil
}

func (l *journalLease) descriptorPath() string {
	if l == nil || l.directory == nil {
		return ""
	}
	switch runtime.GOOS {
	case "linux":
		return filepath.Join("/proc/self/fd", fmt.Sprint(l.directory.Fd()))
	case "darwin":
		var stat unix.Stat_t
		if err := unix.Fstat(int(l.directory.Fd()), &stat); err != nil {
			return ""
		}
		return fmt.Sprintf("/.vol/%d/%d", uint64(stat.Dev), uint64(stat.Ino))
	default:
		return ""
	}
}

func (l *journalLease) Verify() error {
	if l == nil || l.ancestor == nil || l.namespace == nil || l.namespaceLockDir == nil || l.namespaceLock == nil || l.parent == nil || l.parentLockDir == nil || l.parentLock == nil || l.directory == nil || l.lock == nil ||
		l.namespaceName == "" || l.namespaceInfo == nil || l.namespaceLockName == "" || l.namespaceLockInfo == nil ||
		l.parentName == "" || l.parentInfo == nil || l.parentLockName == "" || l.parentLockInfo == nil || l.directoryName == "" || l.directoryInfo == nil || l.lockInfo == nil {
		return fmt.Errorf("gateway journal lease is invalid")
	}
	namespaceFD, err := unix.Openat(int(l.ancestor.Fd()), l.namespaceName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("gateway journal namespace changed: %w", err)
	}
	namespace := os.NewFile(uintptr(namespaceFD), l.namespaceName)
	if namespace == nil {
		_ = unix.Close(namespaceFD)
		return fmt.Errorf("gateway journal namespace changed")
	}
	namespaceInfo, statErr := namespace.Stat()
	_ = namespace.Close()
	if statErr != nil || !os.SameFile(l.namespaceInfo, namespaceInfo) || !namespaceInfo.IsDir() {
		return fmt.Errorf("gateway journal namespace changed")
	}
	namespaceLockFD, err := unix.Openat(int(l.namespaceLockDir.Fd()), l.namespaceLockName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("gateway journal namespace lease file changed: %w", err)
	}
	namespaceLock := os.NewFile(uintptr(namespaceLockFD), l.namespaceLockName)
	if namespaceLock == nil {
		_ = unix.Close(namespaceLockFD)
		return fmt.Errorf("gateway journal namespace lease file changed")
	}
	namespaceLockInfo, statErr := namespaceLock.Stat()
	var namespaceLockStat unix.Stat_t
	fstatErr := unix.Fstat(namespaceLockFD, &namespaceLockStat)
	_ = namespaceLock.Close()
	if statErr != nil || fstatErr != nil || !os.SameFile(l.namespaceLockInfo, namespaceLockInfo) || !namespaceLockInfo.Mode().IsRegular() || namespaceLockInfo.Mode().Perm()&0o077 != 0 || namespaceLockStat.Nlink != 1 {
		return fmt.Errorf("gateway journal namespace lease file changed")
	}
	parentFD, err := unix.Openat(int(l.namespace.Fd()), l.parentName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("gateway journal parent changed: %w", err)
	}
	parent := os.NewFile(uintptr(parentFD), l.parentName)
	if parent == nil {
		_ = unix.Close(parentFD)
		return fmt.Errorf("gateway journal parent changed")
	}
	parentInfo, statErr := parent.Stat()
	_ = parent.Close()
	if statErr != nil || !os.SameFile(l.parentInfo, parentInfo) || !parentInfo.IsDir() {
		return fmt.Errorf("gateway journal parent changed")
	}
	parentLockFD, err := unix.Openat(int(l.parentLockDir.Fd()), l.parentLockName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("gateway journal parent lease file changed: %w", err)
	}
	parentLock := os.NewFile(uintptr(parentLockFD), l.parentLockName)
	if parentLock == nil {
		_ = unix.Close(parentLockFD)
		return fmt.Errorf("gateway journal parent lease file changed")
	}
	parentLockInfo, statErr := parentLock.Stat()
	var parentLockStat unix.Stat_t
	fstatErr = unix.Fstat(parentLockFD, &parentLockStat)
	_ = parentLock.Close()
	if statErr != nil || fstatErr != nil || !os.SameFile(l.parentLockInfo, parentLockInfo) || !parentLockInfo.Mode().IsRegular() || parentLockInfo.Mode().Perm()&0o077 != 0 || parentLockStat.Nlink != 1 {
		return fmt.Errorf("gateway journal parent lease file changed")
	}
	directoryFD, err := unix.Openat(int(l.parent.Fd()), l.directoryName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("gateway journal lease directory changed: %w", err)
	}
	directory := os.NewFile(uintptr(directoryFD), l.directoryName)
	if directory == nil {
		_ = unix.Close(directoryFD)
		return fmt.Errorf("gateway journal lease directory changed")
	}
	directoryInfo, statErr := directory.Stat()
	_ = directory.Close()
	if statErr != nil || !os.SameFile(l.directoryInfo, directoryInfo) || !directoryInfo.IsDir() || directoryInfo.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("gateway journal lease directory changed")
	}
	lockFD, err := unix.Openat(int(l.directory.Fd()), gatewayJournalLockName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("gateway journal lease file changed: %w", err)
	}
	lock := os.NewFile(uintptr(lockFD), gatewayJournalLockName)
	if lock == nil {
		_ = unix.Close(lockFD)
		return fmt.Errorf("gateway journal lease file changed")
	}
	lockInfo, statErr := lock.Stat()
	var lockStat unix.Stat_t
	fstatErr = unix.Fstat(lockFD, &lockStat)
	_ = lock.Close()
	if statErr != nil || fstatErr != nil || !os.SameFile(l.lockInfo, lockInfo) || !lockInfo.Mode().IsRegular() || lockInfo.Mode().Perm()&0o077 != 0 || lockStat.Nlink != 1 {
		return fmt.Errorf("gateway journal lease file changed")
	}
	return nil
}

func (l *journalLease) Close() error {
	if l == nil {
		return nil
	}
	l.once.Do(func() {
		if l.lock != nil {
			if err := unix.Flock(int(l.lock.Fd()), unix.LOCK_UN); err != nil {
				l.err = err
			}
			if err := l.lock.Close(); l.err == nil && err != nil {
				l.err = err
			}
		}
		if l.directory != nil {
			if err := unix.Flock(int(l.directory.Fd()), unix.LOCK_UN); l.err == nil && err != nil {
				l.err = err
			}
			if err := l.directory.Close(); l.err == nil && err != nil {
				l.err = err
			}
		}
		if l.parentLock != nil {
			if err := unix.Flock(int(l.parentLock.Fd()), unix.LOCK_UN); l.err == nil && err != nil {
				l.err = err
			}
			if err := l.parentLock.Close(); l.err == nil && err != nil {
				l.err = err
			}
		}
		if l.parent != nil {
			if err := l.parent.Close(); l.err == nil && err != nil {
				l.err = err
			}
		}
		if l.namespaceLock != nil {
			if err := unix.Flock(int(l.namespaceLock.Fd()), unix.LOCK_UN); l.err == nil && err != nil {
				l.err = err
			}
			if err := l.namespaceLock.Close(); l.err == nil && err != nil {
				l.err = err
			}
		}
		if l.namespace != nil {
			if err := l.namespace.Close(); l.err == nil && err != nil {
				l.err = err
			}
		}
		if l.ancestor != nil {
			if err := l.ancestor.Close(); l.err == nil && err != nil {
				l.err = err
			}
		}
	})
	return l.err
}

func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	c.lifecycleMu.Lock()
	c.closed = true
	cancel := c.runCancel
	done := c.runDone
	c.lifecycleMu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
		return c.closeErr
	}
	return c.closeJournalLease()
}

func (c *Client) closeJournalLease() error {
	c.closeOnce.Do(func() { c.closeErr = c.journalLease.Close() })
	return c.closeErr
}

func removeCapability(features []*agentv1.Capability, name agentv1.CapabilityName) []*agentv1.Capability {
	filtered := features[:0]
	for _, feature := range features {
		if feature == nil || feature.Name != name {
			filtered = append(filtered, feature)
		}
	}
	return filtered
}

func (c *Client) Run(ctx context.Context) error {
	if c == nil || ctx == nil {
		return fmt.Errorf("%w: gateway client Run context is required", ErrInvalidConfiguration)
	}
	c.lifecycleMu.Lock()
	if c.closed || c.running {
		c.lifecycleMu.Unlock()
		return fmt.Errorf("%w: gateway client is closed or already running", ErrInvalidConfiguration)
	}
	if err := c.journalLease.Verify(); err != nil {
		c.closed = true
		c.lifecycleMu.Unlock()
		_ = c.closeJournalLease()
		return err
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	c.running = true
	c.runCancel = cancel
	c.runDone = done
	c.lifecycleMu.Unlock()
	defer func() {
		cancel()
		c.lifecycleMu.Lock()
		c.running = false
		c.closed = true
		c.runCancel = nil
		c.lifecycleMu.Unlock()
		_ = c.closeJournalLease()
		close(done)
		c.lifecycleMu.Lock()
		if c.runDone == done {
			c.runDone = nil
		}
		c.lifecycleMu.Unlock()
	}()
	ctx = runCtx
	var nodeMonitoringErrors <-chan error
	if c.nodeMonitoring != nil {
		monitorErrors := make(chan error, 1)
		nodeMonitoringErrors = monitorErrors
		go func() {
			err := c.nodeMonitoring.Run(ctx)
			monitorErrors <- err
			if err != nil && !errors.Is(err, context.Canceled) {
				cancel()
			}
		}()
	}
	nodeMonitoringFailure := func() error {
		select {
		case err := <-nodeMonitoringErrors:
			if err == nil {
				return fmt.Errorf("node monitoring runtime stopped")
			}
			if errors.Is(err, context.Canceled) && ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("node monitoring runtime failed: %w", err)
		default:
			return nil
		}
	}
	backoff := c.config.InitialBackoff
	for {
		if err := nodeMonitoringFailure(); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			if monitoringErr := nodeMonitoringFailure(); monitoringErr != nil {
				return monitoringErr
			}
			return err
		}
		if c.recoverer != nil && c.recoverer.RecoveryDue() {
			if err := c.recoverCertificate(ctx); err != nil {
				return err
			}
			continue
		}
		sessionStarted := time.Now()
		// Bound each blocking dial so a long gateway outage cannot leave the
		// agent inside gRPC's growing internal backoff; MaximumBackoff then
		// bounds reconnect latency once the gateway is reachable again.
		dialCtx, cancelDial := context.WithTimeout(ctx, c.config.HandshakeTimeout)
		connection, err := c.dialer.Dial(dialCtx)
		cancelDial()
		established := false
		if err == nil && connection == nil {
			err = fmt.Errorf("dialer returned a nil connection")
		}
		if err == nil {
			established, err = c.runSession(ctx, connection.Client())
			_ = connection.Close()
			if !established && err != nil {
				if migrator, ok := c.dialer.(endpointMigrator); ok {
					migrator.SessionRefused()
				}
			}
		}
		if ctx.Err() != nil {
			if monitoringErr := nodeMonitoringFailure(); monitoringErr != nil {
				return monitoringErr
			}
			return ctx.Err()
		}
		if errors.Is(err, errGatewayEndpointSwitched) || errors.Is(err, errCertificateRenewed) ||
			errors.Is(err, errCapabilitiesLearned) || errors.Is(err, errArtifactCapabilitiesChanged) ||
			errors.Is(err, errLiveCapabilityChanged) {
			backoff = c.config.InitialBackoff
			continue
		}
		if errors.Is(err, ErrInvalidMessage) || errors.Is(err, ErrCommandConflict) || errors.Is(err, ErrPermanentProtocol) {
			return err
		}
		stableSession := established && time.Since(sessionStarted) >= c.config.MaximumBackoff
		if stableSession {
			backoff = c.config.InitialBackoff
		}
		delay := c.jitter(backoff)
		if delay < 0 || delay > c.config.MaximumBackoff {
			delay = c.config.MaximumBackoff
		}
		slog.Warn("gateway session ended; reconnecting", "established", established, "retry_in", delay.String(), "error", err)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			if monitoringErr := nodeMonitoringFailure(); monitoringErr != nil {
				return monitoringErr
			}
			return ctx.Err()
		case <-timer.C:
		}
		if !stableSession && backoff < c.config.MaximumBackoff {
			backoff *= 2
			if backoff > c.config.MaximumBackoff {
				backoff = c.config.MaximumBackoff
			}
		}
	}
}

// recoveryPollInterval: how often Run re-checks recovery while the recoverer backs off.
const recoveryPollInterval = 5 * time.Second

// recoverCertificate runs one recovery attempt and waits before the next
// check. Only context cancellation ends Run: a refused recovery (manual
// re-enrollment needed) keeps retrying with the recoverer's backoff, so the
// node recovers once an operator fixes the cause.
func (c *Client) recoverCertificate(ctx context.Context) error {
	recovered, certificateSHA, err := c.recoverer.Recover(ctx)
	if err != nil {
		slog.Warn("expired client certificate not recovered yet", "error", err)
	}
	if recovered {
		slog.Info("expired client certificate recovered", "certificate_sha256", certificateSHA)
		if validAgentPortTransitionSHA(certificateSHA) {
			if c.portTransition != nil {
				c.portTransition.certificateSHA = certificateSHA
			}
			if c.onRenewed != nil {
				c.onRenewed(certificateSHA)
			}
		}
		return nil
	}
	timer := time.NewTimer(recoveryPollInterval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (c *Client) renewCertificate(ctx context.Context, gateway agentv1.AgentGatewayServiceClient) (bool, error) {
	if c.renewer == nil {
		return false, nil
	}
	renewed, certificateSHA, err := c.renewer.Renew(ctx, gateway)
	if err != nil || !renewed {
		return false, err
	}
	if !validAgentPortTransitionSHA(certificateSHA) {
		return false, fmt.Errorf("%w: renewed certificate digest is invalid", ErrInvalidMessage)
	}
	if c.portTransition != nil {
		c.portTransition.certificateSHA = certificateSHA
	}
	if c.onRenewed != nil {
		c.onRenewed(certificateSHA)
	}
	return true, nil
}

// benchmarkConfigured reports whether the market probe executor runs
// benchmark downloads (edge-agent market_probe.benchmark).
func (c *Client) benchmarkConfigured() bool {
	b, ok := c.marketProbe.(interface{ BenchmarkEnabled() bool })
	return ok && b.BenchmarkEnabled()
}

func (c *Client) runSession(parent context.Context, gateway agentv1.AgentGatewayServiceClient) (bool, error) {
	if err := c.verifyJournalLease(); err != nil {
		return false, err
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	stream, err := gateway.Connect(ctx, grpc.WaitForReady(false))
	if err != nil {
		return false, err
	}
	var sendSequence uint64 = 1
	hello, err := c.agentHello()
	if err != nil {
		return false, err
	}
	if err := stream.Send(&agentv1.ConnectRequest{
		Stream:  streamMetadata(sendSequence, c.now()),
		Payload: &agentv1.ConnectRequest_Hello{Hello: hello},
	}); err != nil {
		return false, err
	}
	handshake := make(chan receiveResult, 1)
	go func() {
		response, receiveErr := stream.Recv()
		handshake <- receiveResult{response: response, err: receiveErr}
	}()
	handshakeTimer := time.NewTimer(c.config.HandshakeTimeout)
	defer handshakeTimer.Stop()
	var first *agentv1.ConnectResponse
	select {
	case received := <-handshake:
		if received.err != nil {
			return false, received.err
		}
		first = received.response
	case <-handshakeTimer.C:
		return false, context.DeadlineExceeded
	case <-ctx.Done():
		return false, ctx.Err()
	}
	if err := validateResponseEnvelope(first, 1); err != nil {
		return false, err
	}
	gatewayHello := first.GetHello()
	if err := validateGatewayHello(gatewayHello, c.config); err != nil {
		return false, err
	}
	if c.learnEndpoints != nil {
		c.learnEndpoints(gatewayHello.GetGatewayEndpoints(), gatewayHello.GetGatewayEndpointsVersion())
	}
	if c.learnNodeOwner != nil {
		// The owner gate holds from here on; a purge that fails (nftables)
		// is retried with the next session rather than taking the node off.
		if err := c.learnNodeOwner(ctx, gatewayHello.GetNodeOwnerScopeId()); err != nil {
			slog.Warn("host firewall did not drop the rules of scopes that do not own the node", "error", err)
		}
	}
	if renewed, err := c.renewCertificate(ctx, gateway); err != nil {
		return true, err
	} else if renewed {
		return true, errCertificateRenewed
	}
	if c.l4Live != nil && !c.gatewayKnowsL4Live.Load() &&
		slices.Contains(gatewayHello.GetKnownCapabilities(), agentv1.CapabilityName_CAPABILITY_NAME_L4_LIVE_CONNECTIONS) {
		c.gatewayKnowsL4Live.Store(true)
		return true, errCapabilitiesLearned
	}
	if c.nodeInventory != nil {
		done := make(chan struct{})
		observed := gatewayHello.GetObservedPeerIp()
		go func() { defer close(done); c.runNodeInventory(ctx, gateway, observed) }()
		defer func() { cancel(); <-done }()
	}
	activeIdentityEnabled := gatewayHelloHasActiveIdentityV1(gatewayHello)
	ackReceiptEnabled := gatewayHelloHasDeploymentStatusAckReceiptV1(gatewayHello)
	_, scopedRuntime := c.scopedManager()
	multiTenantEnabled := activeIdentityEnabled && scopedRuntime &&
		hasCapability(hello.Capabilities, agentv1.CapabilityName_CAPABILITY_NAME_MULTI_TENANT_RUNTIME) &&
		gatewayHelloHasMultiTenantRuntimeV1(gatewayHello)
	firewallEnabled, err := negotiateFirewallControlV1(gatewayHello, hello.Capabilities)
	if err != nil {
		return false, err
	}
	drainEnabled, err := negotiateDrainControlV1(gatewayHello, hello.Capabilities)
	if err != nil {
		return false, err
	}
	nodeMonitoringEnabled, err := negotiateNodeMonitoringV1(gatewayHello, hello.Capabilities)
	if err != nil {
		return false, err
	}
	portTransitionEnabled, err := negotiateGatewayPortTransitionV1(gatewayHello, hello.Capabilities)
	if err != nil {
		return false, err
	}
	endpointMigrationEnabled, err := negotiateEndpointMigrationV1(gatewayHello, hello.Capabilities)
	if err != nil {
		return false, err
	}
	signerTrustEnabled, err := negotiateSignerTrustV1(gatewayHello, c.signerTrust)
	if err != nil {
		return false, err
	}
	installationBanEnabled, err := negotiateInstallationBanV1(gatewayHello, c.installationBan)
	if err != nil {
		return false, err
	}
	siteDropEnabled, err := negotiateSiteDropV1(gatewayHello, c.siteDrop)
	if err != nil {
		return false, err
	}
	gatewayAddressEnabled, err := negotiateGatewayAddressChangeV1(gatewayHello, c.gatewayAddress)
	if err != nil {
		return false, err
	}
	cacheCancelEnabled, err := negotiateCacheControlCancelV1(gatewayHello, c.cacheTasks)
	if err != nil {
		return false, err
	}
	sched302Enabled, err := negotiateSched302V1(gatewayHello, c.sched302)
	if err != nil {
		return false, err
	}
	autoDefenseEnabled, err := negotiateAutoDefenseV1(gatewayHello, c.autoDefense)
	if err != nil {
		return false, err
	}
	autoDefenseReports := c.autoDefenseReports(autoDefenseEnabled)
	marketProbeEnabled, err := negotiateMarketProbe(gatewayHello, c.marketProbe)
	if err != nil {
		return false, err
	}
	marketProbeDone := make(chan *agentv1.MarketProbeResult, 1)
	marketProbeBusy := false
	l4LiveEnabled, err := negotiateL4LiveConnections(gatewayHello, c.l4Live,
		hasCapability(hello.Capabilities, agentv1.CapabilityName_CAPABILITY_NAME_L4_LIVE_CONNECTIONS))
	if err != nil {
		return false, err
	}
	l4LiveDone := make(chan *agentv1.L4LiveConnectionsResult, 1)
	l4LiveBusy := false
	upgradeEnabled, upgradeStatusPubAckEnabled, upgradeStatusAckReceiptEnabled, _, err :=
		gatewayHelloEdgeUpgradeExtendedCapabilities(gatewayHello, hello.Capabilities)
	if err != nil {
		return false, err
	}
	if ackReceiptEnabled && !activeIdentityEnabled {
		return false, fmt.Errorf("%w: deployment status acknowledgement receipt requires active config identity", ErrInvalidMessage)
	}
	if err := c.verifyJournalLease(); err != nil {
		return true, err
	}
	if !ackReceiptEnabled {
		if err := c.store.disableDeploymentStatusAckReceipts(); err != nil {
			return true, err
		}
	}

	history, err := c.refreshDeploymentHistory()
	if err != nil {
		return true, err
	}
	records := history.records
	overlayRecords, err := c.overlayStore.records()
	if err != nil {
		return true, err
	}
	cacheRecords, err := c.cacheStore.records()
	if err != nil {
		return true, err
	}
	sentStatuses := make(map[string]struct{})
	authoritativeDeploymentRecords := make(map[string]struct{})
	if ackReceiptEnabled {
		pendingReceipts, err := c.pendingDeploymentStatusAckReceipts()
		if err != nil {
			return true, err
		}
		for _, pendingReceipt := range pendingReceipts {
			sendSequence++
			if err := c.store.markDeploymentStatusAckReceiptSent(pendingReceipt.recordKey, gatewayHello.SessionEpoch, sendSequence); err != nil {
				return true, err
			}
			if err := sendDeploymentStatusAckReceipt(stream, sendSequence, pendingReceipt.receipt, c.now()); err != nil {
				return true, err
			}
		}
	}
	for _, record := range history.replay {
		statuses, err := statusesFromRecord(record)
		if err != nil {
			return true, err
		}
		for _, status := range statuses {
			sendSequence++
			if err := sendStatus(stream, sendSequence, deploymentStatusForSession(status, false), c.now()); err != nil {
				return true, err
			}
			sentStatuses[status.Event.EventId] = struct{}{}
		}
	}
	sendSequence, err = c.replayUnacknowledgedTerminalStatuses(
		stream, sendSequence, sentStatuses, activeIdentityEnabled,
	)
	if err != nil {
		return true, err
	}
	for _, record := range overlayRecords {
		statuses, err := overlayStatusesFromRecord(record)
		if err != nil {
			return true, err
		}
		for _, status := range statuses {
			sendSequence++
			if err := sendACMEHTTP01OverlayStatus(stream, sendSequence, status, c.now()); err != nil {
				return true, err
			}
			sentStatuses[status.Event.EventId] = struct{}{}
		}
	}
	for _, record := range cacheRecords {
		statuses, err := cacheControlStatusesFromRecord(record)
		if err != nil {
			return true, err
		}
		for _, status := range statuses {
			sendSequence++
			if err := sendCacheControlStatus(stream, sendSequence, status, c.now()); err != nil {
				return true, err
			}
			sentStatuses[status.Event.EventId] = struct{}{}
		}
	}
	sentUpgradeStatuses := make(map[string][sha256.Size]byte)
	if upgradeEnabled {
		if upgradeStatusAckReceiptEnabled {
			pendingReceipts, err := c.pendingUpgradeStatusAcknowledgements(ctx)
			if err != nil {
				return true, err
			}
			for _, receipt := range pendingReceipts {
				sendSequence++
				if err := sendUpgradeStatusAckReceipt(stream, sendSequence, receipt, c.now()); err != nil {
					return true, err
				}
			}
		}
		sendSequence, err = c.sendPendingUpgradeStatuses(ctx, stream, sendSequence, sentUpgradeStatuses)
		if err != nil {
			return true, err
		}
	}
	if nodeMonitoringEnabled {
		sendSequence, err = c.sendPendingNodeMonitoringReports(stream, sendSequence)
		if err != nil {
			return true, err
		}
	}

	receive := make(chan receiveResult, 1)
	go pumpResponses(ctx, stream, receive)
	work := make(chan workItem)
	workResults := make(chan workResult, 1)
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		for {
			select {
			case <-ctx.Done():
				return
			case item := <-work:
				err := c.verifyJournalLease()
				if err != nil {
					select {
					case workResults <- workResult{item: item, err: err}:
					case <-ctx.Done():
					}
					return
				}
				switch item.kind {
				case workDeployment:
					err = c.executeRecord(ctx, gateway, item.key, gatewayHello.MaximumArtifactChunkBytes, activeIdentityEnabled)
				case workACMEHTTP01Overlay:
					err = c.executeACMEHTTP01OverlayRecord(ctx, gateway, item.key, gatewayHello.MaximumArtifactChunkBytes)
				default:
					err = ErrInvalidMessage
				}
				select {
				case workResults <- workResult{item: item, err: err}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	cacheWork := make(chan workItem)
	cacheWorkResults := make(chan workResult, 1)
	cacheWorkerDone := make(chan struct{})
	go func() {
		defer close(cacheWorkerDone)
		for {
			select {
			case <-ctx.Done():
				return
			case item := <-cacheWork:
				err := c.verifyJournalLease()
				if err == nil {
					err = c.executeCacheControlRecord(ctx, item.key)
				}
				select {
				case cacheWorkResults <- workResult{item: item, err: err}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	upgradeWork := make(chan upgradeWorkItem)
	upgradeWorkResults := make(chan upgradeWorkResult, 1)
	upgradeWorkerDone := make(chan struct{})
	go func() {
		defer close(upgradeWorkerDone)
		for {
			select {
			case <-ctx.Done():
				return
			case item := <-upgradeWork:
				err := c.verifyJournalLease()
				if err == nil {
					err = c.runUpgradeWork(ctx, item)
				}
				select {
				case upgradeWorkResults <- upgradeWorkResult{item: item, err: err}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	defer func() {
		cancel()
		_ = stream.CloseSend()
		<-workerDone
		<-cacheWorkerDone
		<-upgradeWorkerDone
	}()

	pending := make([]workItem, 0, len(records)+len(overlayRecords))
	// pendingScopeKeys marks deployments queued on a multi-tenant session
	// (value: supersede key, "" when the command never supersedes).
	pendingScopeKeys := make(map[workItem]string)
	cachePending := make([]workItem, 0, len(cacheRecords))
	inFlight := make(map[workItem]bool)
	cacheInFlight := make(map[workItem]bool)
	// cacheCancelWaiting: cancels whose task is still running, answered once
	// the cache worker settles the task (CACHE-ADD-07).
	cacheCancelWaiting := make(map[string][]*agentv1.CacheControlCancel)
	upgradePending := make([]upgradeWorkItem, 0, c.config.CommandQueueSize)
	upgradeInFlight := make(map[[sha256.Size]byte]bool)
	if upgradeEnabled && c.upgrades != nil {
		upgradePending = append(upgradePending, upgradeWorkItem{recover: true})
	}
	for _, record := range records {
		if !record.ExecutionDone {
			item := workItem{kind: workDeployment, key: record.RecordKey}
			pending = append(pending, item)
			inFlight[item] = true
			if recordIsScoped(record) {
				pendingScopeKeys[item] = supersedeKey(commandFromBytes(record.Command))
			}
		}
	}
	for _, record := range overlayRecords {
		if !record.ExecutionDone {
			item := workItem{kind: workACMEHTTP01Overlay, key: record.RecordKey}
			pending = append(pending, item)
			inFlight[item] = true
		}
	}
	for _, record := range cacheRecords {
		if !record.ExecutionDone {
			item := workItem{kind: workCacheControl, key: record.RecordKey}
			cachePending = append(cachePending, item)
			cacheInFlight[item] = true
		}
	}
	heartbeatTicker := time.NewTicker(gatewayHello.HeartbeatIntervalDuration.AsDuration())
	defer heartbeatTicker.Stop()
	var heartbeatSequence uint64
	var responseSequence uint64 = 1
	type heartbeatEvent struct {
		sentAt         time.Time
		streamSequence uint64
	}
	heartbeatEvents := make(map[string]heartbeatEvent)
	var heartbeatCausationID string
	for {
		var nextWork chan workItem
		var nextItem workItem
		if len(pending) > 0 {
			nextWork = work
			nextItem = pending[0]
		}
		var nextCacheWork chan workItem
		var nextCacheItem workItem
		if len(cachePending) > 0 {
			nextCacheWork = cacheWork
			nextCacheItem = cachePending[0]
		}
		var nextUpgradeWork chan upgradeWorkItem
		var nextUpgradeItem upgradeWorkItem
		if len(upgradePending) > 0 {
			nextUpgradeWork = upgradeWork
			nextUpgradeItem = upgradePending[0]
		}
		select {
		case <-ctx.Done():
			return true, ctx.Err()
		case <-c.liveCapabilityChanged():
			if c.liveCapabilityStale() {
				// The hello no longer says what the node runs: reconnect now
				// (unfinished work stays in the journal and is resumed).
				return true, errLiveCapabilityChanged
			}
		case nextWork <- nextItem:
			pending = pending[1:]
			if _, scoped := pendingScopeKeys[nextItem]; scoped {
				delete(pendingScopeKeys, nextItem)
				// The worker owns the record now; STARTED is recorded and sent
				// before it can append anything else.
				record, err := c.store.record(nextItem.key)
				if err != nil {
					return true, err
				}
				if command := commandFromBytes(record.Command); command != nil && !record.ExecutionDone &&
					!recordHasState(record, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STARTED) {
					if err := c.store.appendStatuses(nextItem.key, []*agentv1.DeploymentStatus{scopedStartedStatus(command, c.now())}, false); err != nil {
						return true, err
					}
				}
			}
		case nextCacheWork <- nextCacheItem:
			cachePending = cachePending[1:]
		case nextUpgradeWork <- nextUpgradeItem:
			upgradePending = upgradePending[1:]
		case result := <-workResults:
			delete(inFlight, result.item)
			if result.err != nil {
				return true, result.err
			}
			switch result.item.kind {
			case workDeployment:
				record, err := c.store.record(result.item.key)
				if err != nil {
					return true, err
				}
				_, authoritative := authoritativeDeploymentRecords[result.item.key]
				sendSequence, err = c.sendRecordStatusesForSession(stream, sendSequence, record, sentStatuses, false, activeIdentityEnabled, ackReceiptEnabled, authoritative, gatewayHello.SessionEpoch)
				if err == nil && c.artifactSets != nil && c.artifactSets.IPIntelReady() != c.declaredIPIntel.Load() {
					// The terminal statuses are durable and the command stays
					// unacknowledged until the Gateway persisted them, so a
					// reconnect cannot lose the result.
					return true, errArtifactCapabilitiesChanged
				}
			case workACMEHTTP01Overlay:
				record, err := c.overlayStore.record(result.item.key)
				if err != nil {
					return true, err
				}
				sendSequence, err = c.sendACMEHTTP01OverlayRecordStatuses(stream, sendSequence, record, sentStatuses, false)
			default:
				err = ErrInvalidMessage
			}
			if err != nil {
				return true, err
			}
		case result := <-cacheWorkResults:
			delete(cacheInFlight, result.item)
			if result.err != nil {
				return true, result.err
			}
			record, err := c.cacheStore.record(result.item.key)
			if err != nil {
				return true, err
			}
			sendSequence, err = c.sendCacheControlRecordStatuses(stream, sendSequence, record, sentStatuses, false)
			if err != nil {
				return true, err
			}
			for _, cancel := range cacheCancelWaiting[result.item.key] {
				sendSequence++
				if err := sendCacheControlCancelReceipt(stream, sendSequence, cacheCancelReceipt(cancel, record, c.now()), c.now()); err != nil {
					return true, err
				}
			}
			if _, waited := cacheCancelWaiting[result.item.key]; waited {
				delete(cacheCancelWaiting, result.item.key)
				c.cacheCancels.forget(result.item.key)
			}
		case result := <-l4LiveDone:
			l4LiveBusy = false
			sendSequence++
			if err := sendL4LiveResult(stream, sendSequence, result, c.now()); err != nil {
				return true, err
			}
		case report := <-autoDefenseReports:
			// Display only: a report too large for the carrier is dropped here.
			if len(report) == 0 || len(report) > autodefense.MaxReportBytes {
				continue
			}
			sendSequence++
			if err := sendAutoDefenseReport(stream, sendSequence, report, c.now()); err != nil {
				return true, err
			}
		case result := <-marketProbeDone:
			marketProbeBusy = false
			sendSequence++
			if err := sendMarketProbeResult(stream, sendSequence, result, c.now()); err != nil {
				return true, err
			}
		case result := <-upgradeWorkResults:
			if !result.item.recover {
				delete(upgradeInFlight, result.item.digest)
			}
			if upgradeEnabled {
				sendSequence, err = c.sendPendingUpgradeStatuses(ctx, stream, sendSequence, sentUpgradeStatuses)
				if err != nil {
					return true, err
				}
			}
			if result.err != nil {
				return true, result.err
			}
		case incoming := <-receive:
			if incoming.err != nil {
				return true, incoming.err
			}
			responseSequence++
			if err := validateResponseEnvelope(incoming.response, responseSequence); err != nil {
				return true, err
			}
			if err := c.verifyJournalLease(); err != nil {
				return true, err
			}
			switch payload := incoming.response.Payload.(type) {
			case *agentv1.ConnectResponse_NodeMonitoringArtifact:
				if !nodeMonitoringEnabled || c.nodeMonitoring == nil || cacheControlMessageHasUnknown(incoming.response.ProtoReflect()) {
					return true, fmt.Errorf("%w: node monitoring artifact was not negotiated or contains unknown fields", ErrInvalidMessage)
				}
				applyErr := c.nodeMonitoring.ApplyArtifact(ctx, payload.NodeMonitoringArtifact)
				sendSequence++
				if err := sendNodeMonitoringApplyStatus(stream, sendSequence,
					c.nodeMonitoring.ApplyStatus(payload.NodeMonitoringArtifact, applyErr, c.now()), c.now()); err != nil {
					return true, err
				}
			case *agentv1.ConnectResponse_L4LiveConnectionsCommand:
				if !l4LiveEnabled || cacheControlMessageHasUnknown(incoming.response.ProtoReflect()) {
					return true, fmt.Errorf("%w: L4 live connections command was not negotiated or contains unknown fields", ErrInvalidMessage)
				}
				started, immediate := c.startL4Live(ctx, payload.L4LiveConnectionsCommand, l4LiveBusy, l4LiveDone)
				l4LiveBusy = l4LiveBusy || started
				if immediate != nil {
					sendSequence++
					if err := sendL4LiveResult(stream, sendSequence, immediate, c.now()); err != nil {
						return true, err
					}
				}
			case *agentv1.ConnectResponse_MarketProbeCommand:
				if !marketProbeEnabled || cacheControlMessageHasUnknown(incoming.response.ProtoReflect()) {
					return true, fmt.Errorf("%w: market probe command was not negotiated or contains unknown fields", ErrInvalidMessage)
				}
				started, immediate := c.startMarketProbe(ctx, payload.MarketProbeCommand, marketProbeBusy, marketProbeDone)
				marketProbeBusy = marketProbeBusy || started
				if immediate != nil {
					sendSequence++
					if err := sendMarketProbeResult(stream, sendSequence, immediate, c.now()); err != nil {
						return true, err
					}
				}
			case *agentv1.ConnectResponse_SecurityBanCommand:
				// Sent to a WAF v2 Agent (no capability of its own).
				if cacheControlMessageHasUnknown(incoming.response.ProtoReflect()) {
					return true, fmt.Errorf("%w: security ban command contains unknown fields", ErrInvalidMessage)
				}
				report, err := c.securityBanStatus(payload.SecurityBanCommand, c.now())
				if err != nil {
					return true, err
				}
				sendSequence++
				if err := sendSecurityBanStatus(stream, sendSequence, report, c.now()); err != nil {
					return true, err
				}
			case *agentv1.ConnectResponse_Sched302Table:
				if !sched302Enabled || cacheControlMessageHasUnknown(incoming.response.ProtoReflect()) {
					return true, fmt.Errorf("%w: schedule302 table was not negotiated or contains unknown fields", ErrInvalidMessage)
				}
				// A table that fails verification is dropped: the node keeps its
				// current table until it goes stale, never a forged one.
				if err := applySched302Table(payload.Sched302Table, c.config.NodeID, c.trust, c.sched302); err != nil {
					slog.Warn("schedule302 table refused", "error", err)
				}
			case *agentv1.ConnectResponse_AutoDefenseCommand:
				if !autoDefenseEnabled || cacheControlMessageHasUnknown(incoming.response.ProtoReflect()) {
					return true, fmt.Errorf("%w: auto defense command was not negotiated or contains unknown fields", ErrInvalidMessage)
				}
				receipt, err := c.autoDefenseReceipt(payload.AutoDefenseCommand, c.now())
				if err != nil {
					return true, err
				}
				sendSequence++
				if err := sendAutoDefenseReceipt(stream, sendSequence, receipt, c.now()); err != nil {
					return true, err
				}
			case *agentv1.ConnectResponse_InstallationBanCommand:
				if !installationBanEnabled || cacheControlMessageHasUnknown(incoming.response.ProtoReflect()) {
					return true, fmt.Errorf("%w: installation ban command was not negotiated or contains unknown fields", ErrInvalidMessage)
				}
				receipt, err := c.installationBanReceipt(ctx, payload.InstallationBanCommand, c.now())
				if err != nil {
					return true, err
				}
				sendSequence++
				if err := sendInstallationBanReceipt(stream, sendSequence, receipt, c.now()); err != nil {
					return true, err
				}
			case *agentv1.ConnectResponse_GatewayAddressChangeCommand:
				if !gatewayAddressEnabled || cacheControlMessageHasUnknown(incoming.response.ProtoReflect()) {
					return true, fmt.Errorf("%w: gateway address change was not negotiated or contains unknown fields", ErrInvalidMessage)
				}
				switched, err := c.gatewayAddress.Handle(ctx, payload.GatewayAddressChangeCommand, func(receipt *agentv1.GatewayAddressChangeReceipt) error {
					sendSequence++
					return sendGatewayAddressChangeReceipt(stream, sendSequence, receipt, c.now())
				})
				if err != nil {
					return true, err
				}
				if switched {
					return true, errGatewayEndpointSwitched
				}
			case *agentv1.ConnectResponse_SiteDropCommand:
				if !siteDropEnabled || cacheControlMessageHasUnknown(incoming.response.ProtoReflect()) {
					return true, fmt.Errorf("%w: site drop command was not negotiated or contains unknown fields", ErrInvalidMessage)
				}
				receipt, err := c.siteDropReceipt(payload.SiteDropCommand, c.now())
				if err != nil {
					return true, err
				}
				sendSequence++
				if err := sendSiteDropReceipt(stream, sendSequence, receipt, c.now()); err != nil {
					return true, err
				}
			case *agentv1.ConnectResponse_EdgeSignerTrustBundle:
				if !signerTrustEnabled || cacheControlMessageHasUnknown(incoming.response.ProtoReflect()) {
					return true, fmt.Errorf("%w: edge signer trust bundle was not negotiated or contains unknown fields", ErrInvalidMessage)
				}
				receipt, err := c.signerTrustReceipt(payload.EdgeSignerTrustBundle, c.now())
				if err != nil {
					return true, err
				}
				sendSequence++
				if err := sendSignerTrustReceipt(stream, sendSequence, receipt, c.now()); err != nil {
					return true, err
				}
			case *agentv1.ConnectResponse_NodeMonitoringAck:
				if !nodeMonitoringEnabled || c.nodeMonitoring == nil || cacheControlMessageHasUnknown(incoming.response.ProtoReflect()) {
					return true, fmt.Errorf("%w: node monitoring acknowledgement was not negotiated or contains unknown fields", ErrInvalidMessage)
				}
				if err := c.nodeMonitoring.Acknowledge(payload.NodeMonitoringAck); err != nil {
					return true, err
				}
			case *agentv1.ConnectResponse_GatewayEndpointMigration:
				migrator, ok := c.dialer.(endpointMigrator)
				if !endpointMigrationEnabled || !ok {
					return true, fmt.Errorf("%w: gateway endpoint migration was not negotiated", ErrInvalidMessage)
				}
				migration := payload.GatewayEndpointMigration
				if migrator.Migrate(ctx, migration.GetEndpoints(), migration.GetEndpointsVersion(), c.config.HandshakeTimeout) {
					return true, errGatewayEndpointSwitched
				}
			case *agentv1.ConnectResponse_GatewayPortTransitionCommand:
				if !portTransitionEnabled || c.portTransition == nil || cacheControlMessageHasUnknown(incoming.response.ProtoReflect()) {
					return true, fmt.Errorf("%w: gateway port transition was not negotiated or contains unknown fields", ErrInvalidMessage)
				}
				statusValue, applyErr := c.portTransition.Apply(ctx, payload.GatewayPortTransitionCommand)
				sendSequence++
				if sendErr := sendGatewayPortTransitionStatus(stream, sendSequence, statusValue, c.now()); sendErr != nil {
					return true, sendErr
				}
				if applyErr != nil {
					continue
				}
				if payload.GatewayPortTransitionCommand.Action != agentv1.GatewayPortTransitionAction_GATEWAY_PORT_TRANSITION_ACTION_FINALIZE {
					return true, errGatewayEndpointSwitched
				}
			case *agentv1.ConnectResponse_DeploymentCommand:
				command := payload.DeploymentCommand
				if err := validateCommandIdentity(command, c.config, activeIdentityEnabled); err != nil {
					return true, err
				}
				scopedCommand := multiTenantEnabled && command.ConfigurationScopeId != nil
				delivered := deliveredStatus(command)
				if scopedCommand {
					delivered = withCommandScope(command, delivered)
				}
				record, created, err := c.store.putCommand(command, delivered)
				if err != nil {
					return true, err
				}
				authoritativeDeploymentRecords[record.RecordKey] = struct{}{}
				item := workItem{kind: workDeployment, key: record.RecordKey}
				if scopedCommand && created {
					if err := c.store.appendStatuses(record.RecordKey, []*agentv1.DeploymentStatus{scopedQueuedStatus(command, c.now())}, false); err != nil {
						return true, err
					}
					var replaced *workItem
					var outcome scopedEnqueueOutcome
					key := supersedeKey(command)
					pending, replaced, outcome = enqueueScopedDeployment(pending, pendingScopeKeys, item, key)
					switch outcome {
					case scopedQueueFull:
						if err := c.store.appendStatuses(record.RecordKey, []*agentv1.DeploymentStatus{scopedQueueFullStatus(command, c.now())}, true); err != nil {
							return true, err
						}
					case scopedEnqueued:
						inFlight[item] = true
						pendingScopeKeys[item] = key
						if replaced != nil {
							delete(inFlight, *replaced)
							delete(pendingScopeKeys, *replaced)
							replacedRecord, err := c.store.record(replaced.key)
							if err != nil {
								return true, err
							}
							if replacedCommand := commandFromBytes(replacedRecord.Command); replacedCommand != nil {
								if err := c.store.appendStatuses(replaced.key, []*agentv1.DeploymentStatus{scopedSupersededStatus(replacedCommand, c.now())}, true); err != nil {
									return true, err
								}
							}
							replacedRecord, err = c.store.record(replaced.key)
							if err != nil {
								return true, err
							}
							_, authoritative := authoritativeDeploymentRecords[replaced.key]
							sendSequence, err = c.sendRecordStatusesForSession(stream, sendSequence, replacedRecord, sentStatuses, false, activeIdentityEnabled, ackReceiptEnabled, authoritative, gatewayHello.SessionEpoch)
							if err != nil {
								return true, err
							}
						}
					}
					record, err = c.store.record(record.RecordKey)
					if err != nil {
						return true, err
					}
				}
				sendSequence, err = c.sendRecordStatusesForSession(stream, sendSequence, record, sentStatuses, !created, activeIdentityEnabled, ackReceiptEnabled, true, gatewayHello.SessionEpoch)
				if err != nil {
					return true, err
				}
				if !record.ExecutionDone && !inFlight[item] {
					if len(pending) >= c.config.CommandQueueSize {
						return true, fmt.Errorf("deployment command queue is full")
					}
					pending = append(pending, item)
					inFlight[item] = true
				}
			case *agentv1.ConnectResponse_AcmeHttp01OverlayCommand:
				command := payload.AcmeHttp01OverlayCommand
				if err := validateACMEHTTP01OverlayCommandIdentity(command, c.config); err != nil {
					return true, err
				}
				active := acmehttp01.Pointer{}
				if c.acmeHTTP01 != nil {
					active, err = c.acmeHTTP01.Current()
					if err != nil {
						return true, err
					}
				}
				record, created, err := c.overlayStore.putCommand(command, acmeHTTP01DeliveredStatus(command, active))
				if err != nil {
					return true, err
				}
				sendSequence, err = c.sendACMEHTTP01OverlayRecordStatuses(stream, sendSequence, record, sentStatuses, !created)
				if err != nil {
					return true, err
				}
				item := workItem{kind: workACMEHTTP01Overlay, key: record.RecordKey}
				if !record.ExecutionDone && !inFlight[item] {
					if len(pending) >= c.config.CommandQueueSize {
						return true, fmt.Errorf("deployment command queue is full")
					}
					pending = append(pending, item)
					inFlight[item] = true
				}
			case *agentv1.ConnectResponse_CacheControlCommand:
				command := payload.CacheControlCommand
				if cacheControlMessageHasUnknown(incoming.response.ProtoReflect()) {
					return true, fmt.Errorf("%w: cache control response contains unknown fields", ErrInvalidMessage)
				}
				record, completed, err := c.cacheStore.completedCommand(command)
				if err != nil {
					return true, err
				}
				created := false
				if !completed {
					if err := validateCacheControlCommand(command, c.config, c.now()); err != nil {
						return true, err
					}
					record, created, err = c.cacheStore.putCommand(command, cacheControlDeliveredStatus(command, c.now()))
					if err != nil {
						return true, err
					}
				}
				sendSequence, err = c.sendCacheControlRecordStatuses(stream, sendSequence, record, sentStatuses, !created)
				if err != nil {
					return true, err
				}
				item := workItem{kind: workCacheControl, key: record.RecordKey}
				if !record.ExecutionDone && !cacheInFlight[item] {
					if len(cachePending) >= c.config.CommandQueueSize {
						return true, fmt.Errorf("cache control command queue is full")
					}
					cachePending = append(cachePending, item)
					cacheInFlight[item] = true
				}
			case *agentv1.ConnectResponse_CacheControlCancel:
				if !cacheCancelEnabled {
					return true, fmt.Errorf("%w: cache cancel was not negotiated", ErrInvalidMessage)
				}
				cancel := payload.CacheControlCancel
				if err := validateCacheControlCancel(cancel, c.config); err != nil {
					return true, err
				}
				key := cacheControlRecordKey(cancel.TaskId)
				record, err := c.cacheStore.recordOrCompletion(key)
				if err != nil {
					return true, err
				}
				item := workItem{kind: workCacheControl, key: key}
				settleNow := true
				if record == nil {
					// The command may still come (a redelivery after a nak
					// can follow the cancel): it is then settled as cancelled
					// without running.
					c.cacheCancels.request(key)
				}
				if record != nil && !record.ExecutionDone && cacheCancelMatches(record, cancel) {
					c.cacheCancels.request(key)
					if cacheInFlight[item] {
						// Queued or running: the worker settles it and the
						// receipt follows its terminal status.
						cacheCancelWaiting[key] = append(cacheCancelWaiting[key], cancel)
						settleNow = false
					} else {
						// Not queued in this session (an unfinished record
						// always is): settle it here.
						if err := c.finishCacheControlCancelled(key, cacheControlCommandFromBytes(record.Command), c.now()); err != nil {
							return true, err
						}
						if record, err = c.cacheStore.record(key); err != nil {
							return true, err
						}
						if sendSequence, err = c.sendCacheControlRecordStatuses(stream, sendSequence, record, sentStatuses, false); err != nil {
							return true, err
						}
						c.cacheCancels.forget(key)
					}
				}
				if settleNow {
					sendSequence++
					if err := sendCacheControlCancelReceipt(stream, sendSequence, cacheCancelReceipt(cancel, record, c.now()), c.now()); err != nil {
						return true, err
					}
				}
			case *agentv1.ConnectResponse_CacheControlStatusAck:
				if cacheControlMessageHasUnknown(incoming.response.ProtoReflect()) {
					return true, fmt.Errorf("%w: cache control acknowledgement contains unknown fields", ErrInvalidMessage)
				}
				if err := c.cacheStore.acknowledge(payload.CacheControlStatusAck); err != nil {
					return true, err
				}
			case *agentv1.ConnectResponse_FirewallCommand:
				if !firewallEnabled || c.firewall == nil || cacheControlMessageHasUnknown(incoming.response.ProtoReflect()) {
					return true, fmt.Errorf("%w: firewall command was not negotiated or contains unknown fields", ErrInvalidMessage)
				}
				status, err := c.dispatchFirewallCommand(ctx, payload.FirewallCommand)
				if err != nil {
					return true, err
				}
				sendSequence++
				if err := sendFirewallStatus(stream, sendSequence, status, c.now()); err != nil {
					return true, err
				}
			case *agentv1.ConnectResponse_DrainCommand:
				if !drainEnabled || c.drain == nil || cacheControlMessageHasUnknown(incoming.response.ProtoReflect()) {
					return true, fmt.Errorf("%w: drain command was not negotiated or contains unknown fields", ErrInvalidMessage)
				}
				status, err := c.dispatchDrainCommand(ctx, payload.DrainCommand)
				if err != nil {
					return true, err
				}
				sendSequence++
				if err := sendDrainStatus(stream, sendSequence, status, c.now()); err != nil {
					return true, err
				}
			case *agentv1.ConnectResponse_UpgradeCommand:
				if !upgradeEnabled || c.upgrades == nil {
					return true, fmt.Errorf("%w: upgrade command was not negotiated", ErrInvalidMessage)
				}
				if cacheControlMessageHasUnknown(incoming.response.ProtoReflect()) {
					return true, fmt.Errorf("%w: upgrade command contains unknown fields", ErrInvalidMessage)
				}
				encoded, err := validateUpgradeCommandEnvelope(payload.UpgradeCommand)
				if err != nil {
					return true, err
				}
				digest := sha256.Sum256(encoded)
				if !upgradeInFlight[digest] {
					if len(upgradePending) >= c.config.CommandQueueSize {
						return true, fmt.Errorf("upgrade command queue is full")
					}
					upgradePending = append(upgradePending, upgradeWorkItem{encoded: encoded, digest: digest})
					upgradeInFlight[digest] = true
				}
			case *agentv1.ConnectResponse_UpgradeStatusAck:
				if !upgradeEnabled || c.upgrades == nil {
					return true, fmt.Errorf("%w: upgrade acknowledgement was not negotiated", ErrInvalidMessage)
				}
				if cacheControlMessageHasUnknown(incoming.response.ProtoReflect()) {
					return true, fmt.Errorf("%w: upgrade acknowledgement contains unknown fields", ErrInvalidMessage)
				}
				accepted := false
				if upgradeStatusAckReceiptEnabled {
					var receipt *agentv1.UpgradeStatusAckReceipt
					accepted, receipt, err = c.persistUpgradeStatusAcknowledgement(ctx, payload.UpgradeStatusAck)
					if err == nil {
						sendSequence++
						err = sendUpgradeStatusAckReceipt(stream, sendSequence, receipt, c.now())
					}
				} else {
					accepted, err = c.acknowledgeUpgradeStatus(ctx, payload.UpgradeStatusAck, upgradeStatusPubAckEnabled)
				}
				if err != nil {
					return true, err
				}
				delete(sentUpgradeStatuses, payload.UpgradeStatusAck.StatusEventId)
				if accepted {
					upgradePending = append(upgradePending, upgradeWorkItem{recover: true})
				}
			case *agentv1.ConnectResponse_UpgradeStatusAckReceipt:
				if !upgradeStatusAckReceiptEnabled || c.upgrades == nil ||
					cacheControlMessageHasUnknown(incoming.response.ProtoReflect()) {
					return true, fmt.Errorf("%w: upgrade acknowledgement receipt was not negotiated or contains unknown fields", ErrInvalidMessage)
				}
				confirmed, err := c.confirmUpgradeStatusAcknowledgement(ctx, payload.UpgradeStatusAckReceipt)
				if err != nil || !confirmed {
					return true, fmt.Errorf("%w: upgrade acknowledgement receipt was not confirmed", ErrInvalidMessage)
				}
			case *agentv1.ConnectResponse_DeploymentStatusAck:
				if !activeIdentityEnabled || cacheControlMessageHasUnknown(incoming.response.ProtoReflect()) {
					return true, fmt.Errorf("%w: deployment status acknowledgement was not negotiated or contains unknown fields", ErrInvalidMessage)
				}
				if ackReceiptEnabled {
					receipt, err := c.persistDeploymentStatusAckReceipt(payload.DeploymentStatusAck)
					if err != nil {
						return true, err
					}
					if receipt == nil {
						continue
					}
					sendSequence++
					key := recordKey(receipt.DeploymentId, receipt.Attempt)
					if err := c.store.markDeploymentStatusAckReceiptSent(key, gatewayHello.SessionEpoch, sendSequence); err != nil {
						return true, err
					}
					if err := sendDeploymentStatusAckReceipt(stream, sendSequence, receipt, c.now()); err != nil {
						return true, err
					}
					continue
				}
				if err := c.acknowledgeDeploymentStatus(payload.DeploymentStatusAck); err != nil {
					return true, err
				}
			case *agentv1.ConnectResponse_HeartbeatAck:
				ack := payload.HeartbeatAck
				if ack == nil || !canonicalUUID(ack.HeartbeatEventId) || ack.SessionEpoch != gatewayHello.SessionEpoch || ack.ReceivedTime == nil || ack.ReceivedTime.CheckValid() != nil {
					return true, fmt.Errorf("%w: invalid heartbeat acknowledgement", ErrInvalidMessage)
				}
				heartbeatEvent, exists := heartbeatEvents[ack.HeartbeatEventId]
				if !exists {
					return true, fmt.Errorf("%w: heartbeat acknowledgement does not match a sent heartbeat", ErrInvalidMessage)
				}
				if !ackReceiptEnabled {
					if err := c.acknowledgeLegacyDeploymentStatuses(gatewayHello.SessionEpoch, heartbeatEvent.streamSequence); err != nil {
						return true, err
					}
				}
				if ackReceiptEnabled {
					if err := c.confirmDeploymentStatusAckReceipts(gatewayHello.SessionEpoch, heartbeatEvent.streamSequence); err != nil {
						return true, err
					}
				}
				heartbeatCausationID = ack.HeartbeatEventId
				delete(heartbeatEvents, ack.HeartbeatEventId)
			case *agentv1.ConnectResponse_Error:
				protocolError := payload.Error.GetError()
				if err := validateStreamProtocolError(protocolError); err != nil {
					return true, err
				}
				if protocolError.Retryable {
					return true, fmt.Errorf("gateway reported a retryable protocol error")
				}
				return true, ErrPermanentProtocol
			default:
				return true, fmt.Errorf("%w: unexpected gateway payload", ErrInvalidMessage)
			}
		case <-heartbeatTicker.C:
			now := time.Now()
			for _, event := range heartbeatEvents {
				if now.Sub(event.sentAt) >= gatewayHello.OfflineAfterDuration.AsDuration() {
					return true, fmt.Errorf("gateway heartbeat acknowledgement timed out")
				}
			}
			if ackReceiptEnabled && len(heartbeatEvents) != 0 {
				continue
			}
			if renewed, err := c.renewCertificate(ctx, gateway); err != nil {
				return true, err
			} else if renewed {
				return true, errCertificateRenewed
			}
			heartbeatSequence++
			heartbeat, err := c.heartbeatWithContext(ctx, gatewayHello.SessionEpoch, heartbeatSequence, activeIdentityEnabled, multiTenantEnabled)
			if err != nil {
				return true, err
			}
			if heartbeatCausationID != "" {
				heartbeat.Event.CausationId = proto.String(heartbeatCausationID)
			}
			sendSequence++
			if err := stream.Send(&agentv1.ConnectRequest{Stream: streamMetadata(sendSequence, c.now()), Payload: &agentv1.ConnectRequest_Heartbeat{Heartbeat: heartbeat}}); err != nil {
				return true, err
			}
			heartbeatEvents[heartbeat.Event.EventId] = heartbeatEvent{sentAt: now, streamSequence: sendSequence}
			if upgradeEnabled {
				sendSequence, err = c.sendPendingUpgradeStatuses(ctx, stream, sendSequence, sentUpgradeStatuses)
				if err != nil {
					return true, err
				}
			}
			if nodeMonitoringEnabled {
				sendSequence, err = c.sendPendingNodeMonitoringReports(stream, sendSequence)
				if err != nil {
					return true, err
				}
			}
		}
	}
}

func (c *Client) verifyJournalLease() error {
	if c == nil || c.journalLease == nil {
		return nil
	}
	return c.journalLease.Verify()
}

func (c *Client) executeRecord(ctx context.Context, gateway agentv1.AgentGatewayServiceClient, key string, maximumChunkBytes uint32, activeIdentityCapability ...bool) error {
	activeIdentityEnabled := len(activeIdentityCapability) == 1 && activeIdentityCapability[0]
	record, err := c.store.record(key)
	if err != nil {
		return fmt.Errorf("load deployment record: %w", err)
	}
	if record == nil {
		return fmt.Errorf("load deployment record: record is missing")
	}
	if record.ExecutionDone {
		return nil
	}
	command := commandFromBytes(record.Command)
	if command == nil {
		return fmt.Errorf("durable deployment command is corrupt")
	}
	certificateCommand := isCertificateCommand(command)
	challengeCommand := isChallengeCommand(command)
	urlAuthCommand := isURLAuthCommand(command)
	errorPageCommand := isErrorPageCommand(command)
	originAuthCommand := isOriginAuthCommand(command)
	if err := validateArtifactSetRoutedCommand(command, c.commandConfig(), c.now()); err != nil {
		summary := err.Error()
		if certificateCommand {
			_, summary = classifyCertificateError(err)
		} else if challengeCommand {
			_, summary = classifyChallengeError(err)
		} else if urlAuthCommand {
			_, summary = classifyURLAuthError(err)
		}
		status := failedStatus(command, 2, c.now(), classifyError(err), summary, false)
		return c.completeDeploymentRecord(key, []*agentv1.DeploymentStatus{status}, activeIdentityEnabled)
	}
	if command.Action == agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY && c.installationFrozen() {
		// Frozen (expired service ticket): existing configuration keeps serving,
		// nothing new is applied; retryable, so it lands once a ticket arrives.
		status := failedStatus(command, 2, c.now(), commonv1.ErrorCode_ERROR_CODE_FAILED_PRECONDITION,
			InstallationFrozenReason+": the node service ticket expired; new publications wait for a renewed ticket", true)
		return c.completeDeploymentRecord(key, []*agentv1.DeploymentStatus{status}, activeIdentityEnabled)
	}
	commandCtx, cancel := context.WithDeadline(ctx, command.DeadlineTime.AsTime())
	defer cancel()
	if command.Action == agentv1.DeploymentAction_DEPLOYMENT_ACTION_ROLLBACK {
		// Never fetch or inspect command artifacts for a local explicit rollback.
		if record.ArtifactOffset != 0 {
			err := fmt.Errorf("%w: rollback record has an artifact offset", ErrInvalidMessage)
			status := failedStatus(command, 2, c.now(), classifyError(err), err.Error(), false)
			return c.completeDeploymentRecord(key, []*agentv1.DeploymentStatus{status}, activeIdentityEnabled)
		}
		result, err := c.manager.Process(commandCtx, deployment.Command{
			DeploymentID:      command.DeploymentId,
			Attempt:           command.Attempt,
			Action:            deployment.ActionRollback,
			ConfigVersionID:   command.ConfigVersionId,
			PreviousVersionID: command.GetPreviousConfigVersionId(),
			ScopeID:           commandScopeID(command),
		})
		if err != nil && ctx.Err() != nil {
			return err
		}
		return c.completeDeploymentProcessResult(key, command, result, err, activeIdentityEnabled)
	}
	if certificateCommand {
		return c.executeCertificateRecord(commandCtx, gateway, record, command, maximumChunkBytes)
	}
	if challengeCommand {
		return c.executeChallengeRecord(commandCtx, gateway, record, command, maximumChunkBytes)
	}
	if urlAuthCommand {
		return c.executeURLAuthRecord(commandCtx, gateway, record, command, maximumChunkBytes)
	}
	if errorPageCommand {
		return c.executeErrorPageRecord(commandCtx, gateway, record, command, maximumChunkBytes)
	}
	if originAuthCommand {
		return c.executeOriginAuthRecord(commandCtx, gateway, record, command, maximumChunkBytes)
	}
	if isArtifactSetCommand(command) {
		return c.executeArtifactSetRecord(commandCtx, gateway, record, command, maximumChunkBytes)
	}
	if isSiteObjectCommand(command) {
		return c.executeSiteObjectRecord(commandCtx, gateway, record, command, maximumChunkBytes, activeIdentityEnabled)
	}
	// Configuration releases are site object roots; validateRoutedCommand
	// rejects every other configuration artifact before execution.
	err = fmt.Errorf("%w: configuration bundle is not supported (site objects only)", ErrUnsupportedCommand)
	status := failedStatus(command, 2, c.now(), classifyError(err), err.Error(), false)
	return c.completeDeploymentRecord(key, []*agentv1.DeploymentStatus{status}, activeIdentityEnabled)
}

func (c *Client) completeDeploymentProcessResult(key string, command *agentv1.DeploymentCommand, result deployment.Result, processErr error, activeIdentityEnabled bool) error {
	if processErr == nil || terminalResultForCommand(command, result) {
		statuses := statusesForResult(command, result)
		appendTerminalChecks(statuses, c.extraChecks)
		if err := c.completeDeploymentRecord(key, statuses, activeIdentityEnabled); err != nil {
			return err
		}
		if processErr != nil {
			return fmt.Errorf("deployment terminal state persisted before maintenance failed: %w", processErr)
		}
		return nil
	}
	status := failedStatus(command, 2, c.now(), classifyError(processErr), processErr.Error(), false)
	return c.completeDeploymentRecord(key, []*agentv1.DeploymentStatus{status}, activeIdentityEnabled)
}

func terminalResultForCommand(command *agentv1.DeploymentCommand, result deployment.Result) bool {
	if command == nil || result.DeploymentID != command.DeploymentId || result.Attempt != command.Attempt ||
		result.ConfigVersionID != command.ConfigVersionId || len(result.Transitions) == 0 {
		return false
	}
	latest := result.Transitions[len(result.Transitions)-1]
	if latest.State != result.State || latest.Sequence != result.Sequence {
		return false
	}
	switch result.State {
	case deployment.StateHealthy, deployment.StateFailed, deployment.StateReverted, deployment.StateRollbackFailed:
		return true
	default:
		return false
	}
}

func (c *Client) sendRecordStatuses(stream grpc.BidiStreamingClient[agentv1.ConnectRequest, agentv1.ConnectResponse], sequence uint64, record *durableRecord, sent map[string]struct{}, force bool, activeIdentityCapability ...bool) (uint64, error) {
	activeIdentityEnabled := len(activeIdentityCapability) == 1 && activeIdentityCapability[0]
	statuses, err := statusesFromRecord(record)
	if err != nil {
		return sequence, err
	}
	for _, status := range statuses {
		if _, exists := sent[status.Event.EventId]; exists && !force {
			continue
		}
		sequence++
		if err := sendStatus(stream, sequence, deploymentStatusForSession(status, activeIdentityEnabled), c.now()); err != nil {
			return sequence, err
		}
		sent[status.Event.EventId] = struct{}{}
	}
	return sequence, nil
}

func (c *Client) sendRecordStatusesForSession(stream grpc.BidiStreamingClient[agentv1.ConnectRequest, agentv1.ConnectResponse], sequence uint64, record *durableRecord, sent map[string]struct{}, force, activeIdentityEnabled, ackReceiptEnabled, authoritative bool, sessionEpoch uint64) (uint64, error) {
	before := sequence
	next, err := c.sendRecordStatuses(stream, sequence, record, sent, force, activeIdentityEnabled)
	if err != nil || ackReceiptEnabled || !authoritative || record == nil || !record.ExecutionDone || next == before {
		return next, err
	}
	if err := c.store.markLegacyDeploymentStatusSent(record, sessionEpoch, next); err != nil {
		return next, err
	}
	return next, nil
}

func (c *Client) replayUnacknowledgedTerminalStatuses(stream grpc.BidiStreamingClient[agentv1.ConnectRequest, agentv1.ConnectResponse], sequence uint64, sent map[string]struct{}, activeIdentityEnabled bool) (uint64, error) {
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	err := c.store.scanDeploymentRecordsLocked(func(record *durableRecord) error {
		ack, err := c.store.loadDeploymentStatusAckLocked(record.RecordKey)
		if err != nil {
			return err
		}
		if ack != nil {
			return validateDeploymentStatusAckRecord(ack, record)
		}
		if !record.ExecutionDone {
			return nil
		}
		statuses, err := statusesFromRecord(record)
		if err != nil || len(statuses) == 0 || !terminalDeploymentState(statuses[len(statuses)-1].State) {
			return fmt.Errorf("gateway journal terminal status is corrupt")
		}
		for _, status := range statuses {
			if _, exists := sent[status.Event.EventId]; exists {
				continue
			}
			sequence++
			if err := sendStatus(stream, sequence, deploymentStatusForSession(status, activeIdentityEnabled), c.now()); err != nil {
				return err
			}
			sent[status.Event.EventId] = struct{}{}
		}
		return nil
	})
	return sequence, err
}

func (c *Client) sendACMEHTTP01OverlayRecordStatuses(stream grpc.BidiStreamingClient[agentv1.ConnectRequest, agentv1.ConnectResponse], sequence uint64, record *overlayDurableRecord, sent map[string]struct{}, force bool) (uint64, error) {
	statuses, err := overlayStatusesFromRecord(record)
	if err != nil {
		return sequence, err
	}
	for _, status := range statuses {
		if _, exists := sent[status.Event.EventId]; exists && !force {
			continue
		}
		sequence++
		if err := sendACMEHTTP01OverlayStatus(stream, sequence, status, c.now()); err != nil {
			return sequence, err
		}
		sent[status.Event.EventId] = struct{}{}
	}
	return sequence, nil
}

func (c *Client) agentHello() (*agentv1.AgentHello, error) {
	snapshot, err := c.stableScopedSnapshot()
	if err != nil {
		return nil, err
	}
	pointers, history := snapshot.pointers, snapshot.history
	records := history.records
	capabilities := proto.Clone(c.config.Capabilities).(*agentv1.AgentCapabilities)
	ensureEdgeUpgradeCapabilities(capabilities, c.upgrades)
	if c.portTransition != nil && !hasCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_GATEWAY_PORT_TRANSITION) {
		capabilities.Features = append(capabilities.Features, &agentv1.Capability{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_GATEWAY_PORT_TRANSITION, ApiVersion: gatewayPortTransitionAPIVersion,
		})
	}
	if c.marketProbe != nil && !hasCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_MARKET_PROBE) {
		capabilities.Features = append(capabilities.Features, &agentv1.Capability{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_MARKET_PROBE, ApiVersion: marketProbeAPIVersion,
		})
	}
	// Host targets may carry a method and headers. Declared
	// only (the gateway does not negotiate it): control reads the session
	// capability snapshot before sending them.
	if c.marketProbe != nil && !hasCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_AGGREGATED_EDGE_PROBE) {
		capabilities.Features = append(capabilities.Features, &agentv1.Capability{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_AGGREGATED_EDGE_PROBE, ApiVersion: aggregatedEdgeProbeAPIVersion,
		})
	}
	if c.l4Live != nil && c.gatewayKnowsL4Live.Load() &&
		!hasCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_L4_LIVE_CONNECTIONS) {
		capabilities.Features = append(capabilities.Features, &agentv1.Capability{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_L4_LIVE_CONNECTIONS, ApiVersion: c.l4Live.APIVersion(),
		})
	}
	if c.benchmarkConfigured() && !hasCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_MARKET_BENCHMARK) {
		capabilities.Features = append(capabilities.Features, &agentv1.Capability{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_MARKET_BENCHMARK, ApiVersion: marketBenchmarkAPIVersion,
		})
	}
	if _, ok := c.dialer.(endpointMigrator); ok && !hasCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_GATEWAY_ENDPOINT_MIGRATION) {
		capabilities.Features = append(capabilities.Features, &agentv1.Capability{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_GATEWAY_ENDPOINT_MIGRATION, ApiVersion: 1,
		})
	}
	if c.sched302 != nil && !hasCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_SCHED302) {
		capabilities.Features = append(capabilities.Features, &agentv1.Capability{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_SCHED302, ApiVersion: sched302.APIVersion,
		})
	}
	if c.autoDefense != nil && !hasCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_AUTO_DEFENSE) {
		capabilities.Features = append(capabilities.Features, &agentv1.Capability{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_AUTO_DEFENSE, ApiVersion: autodefense.APIVersion,
		})
	}
	if c.installationBan != nil && !hasCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_INSTALLATION_BAN_TICKET) {
		capabilities.Features = append(capabilities.Features, &agentv1.Capability{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_INSTALLATION_BAN_TICKET, ApiVersion: installationBanAPIVersion,
		})
	}
	if c.cacheTasks != nil && hasCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_CACHE_CONTROL) &&
		!hasCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_CACHE_CONTROL_CANCEL) {
		capabilities.Features = append(capabilities.Features, &agentv1.Capability{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_CACHE_CONTROL_CANCEL, ApiVersion: cacheControlCancelAPIVersion,
		})
	}
	if c.gatewayAddress != nil && !hasCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_GATEWAY_ADDRESS_CHANGE) {
		capabilities.Features = append(capabilities.Features, &agentv1.Capability{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_GATEWAY_ADDRESS_CHANGE, ApiVersion: gatewayAddressAPIVersion,
		})
	}
	if c.siteDrop != nil && !hasCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_SITE_DROP) {
		capabilities.Features = append(capabilities.Features, &agentv1.Capability{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_DROP, ApiVersion: siteDropAPIVersion,
		})
	}
	if c.signerTrust != nil && !hasCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_EDGE_SIGNER_TRUST) {
		capabilities.Features = append(capabilities.Features, &agentv1.Capability{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_SIGNER_TRUST, ApiVersion: signerTrustAPIVersion,
		})
	}
	_, scopedRuntime := c.scopedManager()
	if scopedRuntime && hasCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_ACTIVE_CONFIG_IDENTITY) &&
		!hasCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_MULTI_TENANT_RUNTIME) {
		capabilities.Features = append(capabilities.Features, &agentv1.Capability{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_MULTI_TENANT_RUNTIME, ApiVersion: multiTenantRuntimeAPIVersion,
		})
	}
	ipIntelDeclared := false
	for _, capability := range c.dynamicCapabilities() {
		if !hasCapability(capabilities, capability.Name) {
			capabilities.Features = append(capabilities.Features, capability)
		}
		ipIntelDeclared = ipIntelDeclared || capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_IP_INTEL
	}
	c.declaredIPIntel.Store(ipIntelDeclared)
	c.declareLiveCapability(capabilities)
	if c.acmeHTTP01 != nil && c.acmeHTTP01.Ready() && !hasCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_ACME_HTTP01_OVERLAY) {
		capabilities.Features = append(capabilities.Features, &agentv1.Capability{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_ACME_HTTP01_OVERLAY, ApiVersion: 1,
		})
	}
	hello := &agentv1.AgentHello{
		NodeId: c.config.NodeID, BootId: c.config.BootID,
		SupportedProtocolVersions: c.config.SupportedVersions,
		Capabilities:              capabilities,
		ArtifactEncryptionKeyId:   c.config.ArtifactEncryptionKeyID,
	}
	if c.portTransition != nil {
		hello.GatewayPortTransitionProof = c.portTransition.Proof()
	}
	if pointers.Current != "" {
		hello.CurrentConfigVersionId = &pointers.Current
	}
	if pointers.Previous != "" {
		hello.PreviousConfigVersionId = &pointers.Previous
	}
	currentIdentity, previousIdentity := c.activeConfigIdentities(pointers, records)
	hello.CurrentConfigIdentity = currentIdentity
	hello.PreviousConfigIdentity = previousIdentity
	if hasCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_MULTI_TENANT_RUNTIME) {
		scoped, err := c.scopedConfigIdentities(snapshot.results, snapshot.scopes, snapshot.sets, records)
		if err != nil {
			return nil, err
		}
		hello.ScopedConfigIdentities = scoped
		mirrorScopedLegacyIdentity(hello)
		currentIdentity = hello.CurrentConfigIdentity
	}
	for _, record := range records {
		if record.ExecutionDone {
			continue
		}
		statuses, err := statusesFromRecord(record)
		if err != nil {
			return nil, err
		}
		latest := statuses[len(statuses)-1]
		var observedIdentity *agentv1.ActiveConfigIdentity
		if currentIdentity != nil && currentIdentity.ConfigVersionId == record.ConfigVersionID {
			observedIdentity = cloneActiveConfigIdentity(currentIdentity)
		}
		hello.ActiveDeployments = append(hello.ActiveDeployments, &agentv1.ActiveDeployment{
			DeploymentId: record.DeploymentID, Attempt: record.Attempt, ConfigVersionId: record.ConfigVersionID, State: latest.State,
			ObservedActiveConfigIdentity: observedIdentity,
		})
		if len(hello.ActiveDeployments) > c.config.MaxActiveDeployments {
			return nil, fmt.Errorf("active deployment count exceeds its limit")
		}
	}
	return hello, nil
}

func (c *Client) heartbeat(epoch, sequence uint64, activeIdentityCapability ...bool) (*agentv1.Heartbeat, error) {
	return c.heartbeatWithContext(context.Background(), epoch, sequence, activeIdentityCapability...)
}

// heartbeatWithContext takes (activeIdentityEnabled, multiTenantEnabled).
func (c *Client) heartbeatWithContext(ctx context.Context, epoch, sequence uint64, activeIdentityCapability ...bool) (*agentv1.Heartbeat, error) {
	activeIdentityEnabled := len(activeIdentityCapability) >= 1 && activeIdentityCapability[0]
	multiTenantEnabled := activeIdentityEnabled && len(activeIdentityCapability) >= 2 && activeIdentityCapability[1]
	hello, err := c.agentHello()
	if err != nil {
		return nil, err
	}
	eventID := uuid.NewString()
	activeDeployments := make([]*agentv1.ActiveDeployment, len(hello.ActiveDeployments))
	for index, active := range hello.ActiveDeployments {
		activeDeployments[index] = proto.Clone(active).(*agentv1.ActiveDeployment)
		if !activeIdentityEnabled {
			activeDeployments[index].ObservedActiveConfigIdentity = nil
		}
	}
	loadedConfigVersionID := hello.CurrentConfigVersionId
	if activeIdentityEnabled && hello.CurrentConfigIdentity == nil {
		loadedConfigVersionID = nil
	}
	heartbeat := &agentv1.Heartbeat{
		Event:        &commonv1.EventMetadata{EventId: eventID, RequestId: uuid.NewString(), OccurredTime: timestamppb.New(c.now().UTC())},
		SessionEpoch: epoch, HeartbeatSequence: sequence,
		AgentVersion:            &hello.Capabilities.AgentVersion,
		CurrentConfigVersionId:  hello.CurrentConfigVersionId,
		PreviousConfigVersionId: hello.PreviousConfigVersionId,
		Runtime:                 c.runtimeStatus(ctx, loadedConfigVersionID),
		Resources:               &agentv1.ResourceUsage{},
		ActiveDeployments:       activeDeployments,
	}
	if activeIdentityEnabled {
		heartbeat.ActiveConfigIdentityCapability = activeConfigIdentityCapability()
		heartbeat.CurrentConfigIdentity = cloneActiveConfigIdentity(hello.CurrentConfigIdentity)
		heartbeat.PreviousConfigIdentity = cloneActiveConfigIdentity(hello.PreviousConfigIdentity)
		heartbeat.Runtime.LoadedConfigIdentity = cloneActiveConfigIdentity(hello.CurrentConfigIdentity)
	}
	if multiTenantEnabled {
		for _, entry := range hello.ScopedConfigIdentities {
			heartbeat.ScopedConfigIdentities = append(heartbeat.ScopedConfigIdentities, proto.Clone(entry).(*agentv1.ScopedConfigIdentity))
		}
	}
	return heartbeat, nil
}

func (c *Client) runtimeStatus(ctx context.Context, loadedConfigVersionID *string) *agentv1.EdgeRuntimeStatus {
	openRestyState := agentv1.RuntimeState_RUNTIME_STATE_STOPPED
	if loadedConfigVersionID != nil {
		openRestyState = agentv1.RuntimeState_RUNTIME_STATE_DEGRADED
		if c.runtimeProbe.OpenResty != nil && c.runtimeProbe.OpenResty(ctx, *loadedConfigVersionID) == nil {
			openRestyState = agentv1.RuntimeState_RUNTIME_STATE_RUNNING
		}
	}
	firewallState := agentv1.RuntimeState_RUNTIME_STATE_STOPPED
	if c.runtimeProbe.Firewall != nil {
		firewallState = agentv1.RuntimeState_RUNTIME_STATE_DEGRADED
		if c.runtimeProbe.Firewall(ctx) == nil {
			firewallState = agentv1.RuntimeState_RUNTIME_STATE_RUNNING
		}
	}
	status := &agentv1.EdgeRuntimeStatus{
		LoadedConfigVersionId: loadedConfigVersionID,
		OpenrestyState:        openRestyState,
		FirewallState:         firewallState,
		MarketProbe:           c.runtimeProbe.MarketProbeRole,
	}
	if c.runtimeProbe.ErrorLog != nil {
		status.ErrorLog = c.runtimeProbe.ErrorLog()
	}
	if c.runtimeProbe.NativeRuntime != nil {
		status.NativeRuntime = c.runtimeProbe.NativeRuntime()
	}
	return status
}

func validateResponseEnvelope(response *agentv1.ConnectResponse, sequence uint64) error {
	if response == nil || response.Stream == nil || !canonicalUUID(response.Stream.MessageId) || response.Stream.Sequence != sequence || response.Stream.SentTime == nil || response.Stream.SentTime.CheckValid() != nil || !boundedMetadata(response.Stream.Traceparent, false) || response.Payload == nil {
		return fmt.Errorf("%w: response stream envelope is invalid", ErrInvalidMessage)
	}
	return nil
}

func sendStatus(stream grpc.BidiStreamingClient[agentv1.ConnectRequest, agentv1.ConnectResponse], sequence uint64, status *agentv1.DeploymentStatus, now time.Time) error {
	return stream.Send(&agentv1.ConnectRequest{Stream: streamMetadata(sequence, now), Payload: &agentv1.ConnectRequest_DeploymentStatus{DeploymentStatus: status}})
}

func sendDeploymentStatusAckReceipt(stream grpc.BidiStreamingClient[agentv1.ConnectRequest, agentv1.ConnectResponse], sequence uint64, receipt *agentv1.DeploymentStatusAckReceipt, now time.Time) error {
	return stream.Send(&agentv1.ConnectRequest{
		Stream: streamMetadata(sequence, now),
		Payload: &agentv1.ConnectRequest_DeploymentStatusAckReceipt{
			DeploymentStatusAckReceipt: receipt,
		},
	})
}

func sendFirewallStatus(stream grpc.BidiStreamingClient[agentv1.ConnectRequest, agentv1.ConnectResponse], sequence uint64, status *agentv1.FirewallStatus, now time.Time) error {
	return stream.Send(&agentv1.ConnectRequest{
		Stream: streamMetadata(sequence, now), Payload: &agentv1.ConnectRequest_FirewallStatus{FirewallStatus: status},
	})
}

func sendACMEHTTP01OverlayStatus(stream grpc.BidiStreamingClient[agentv1.ConnectRequest, agentv1.ConnectResponse], sequence uint64, status *agentv1.AcmeHTTP01OverlayStatus, now time.Time) error {
	return stream.Send(&agentv1.ConnectRequest{Stream: streamMetadata(sequence, now), Payload: &agentv1.ConnectRequest_AcmeHttp01OverlayStatus{AcmeHttp01OverlayStatus: status}})
}

func hasCapability(capabilities *agentv1.AgentCapabilities, name agentv1.CapabilityName) bool {
	if capabilities == nil {
		return false
	}
	for _, capability := range capabilities.Features {
		if capability != nil && capability.Name == name && capability.ApiVersion >= 1 {
			return true
		}
	}
	return false
}

func streamMetadata(sequence uint64, now time.Time) *commonv1.StreamMetadata {
	return &commonv1.StreamMetadata{MessageId: uuid.NewString(), SentTime: timestamppb.New(now.UTC()), Sequence: sequence}
}

func pumpResponses(ctx context.Context, stream grpc.BidiStreamingClient[agentv1.ConnectRequest, agentv1.ConnectResponse], output chan<- receiveResult) {
	for {
		response, err := stream.Recv()
		select {
		case output <- receiveResult{response: response, err: err}:
		case <-ctx.Done():
			return
		}
		if err != nil {
			return
		}
	}
}
