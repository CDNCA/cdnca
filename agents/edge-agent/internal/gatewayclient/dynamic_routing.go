package gatewayclient

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/deployment"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// Dynamic routing delivery (site_runtime 9): a deployment carries a v2 root
// (cdnca.edge.site-root/v2) and this node's key envelope. The node fetches
// the scope, buckets, site objects and the objects they reference, and hands
// them to the dynamic routing runtime as they are: no bundle is assembled
// and the deployment manager is not involved.

// DynamicRoutingRelease is one scope's verified dynamic routing release.
type DynamicRoutingRelease struct {
	ConfigurationScopeID string
	ConfigVersionID      string
	// RootSHA256 is the signed root's digest (the node's active identity).
	RootSHA256 string
	// Sites: site object digest -> plaintext (cdnca.edge.site/v2).
	Sites map[string][]byte
	// Referenced: digest -> plaintext of every object the sites read.
	Referenced map[string][]byte
	// ScopeFiles: release path -> content (CRS rule text, profile packs).
	ScopeFiles map[string][]byte
	// System is the scope's platform system configuration (nil = none).
	System *edgeconfig.SiteRuntimeSystem
	// SourceRevision is the release's source revision; Streams its L4
	// forwards (nil = none).
	SourceRevision int64
	Streams        *edgeconfig.StreamRuntime
	// NodePages are the scope's node pages; their bodies are in Referenced.
	NodePages []siteobject.NodePageV2
	// InstallationID: the scope's telemetry installation ("" = none).
	InstallationID string
	// TrafficStop: the scope's L4 forwards withdrawn for package traffic
	// whose open sessions this node closes (L4_TRAFFIC_STOP, from this
	// node's key document; nil = none: withdrawn forwards drain).
	TrafficStop []string
	// NodeRegion: this node's region code from its key document
	// (NODE_REGION; "" = none or a control plane that did not send it).
	NodeRegion string
	// NodeStorage: this node's storage settings from its key document
	// (NODE_STORAGE; nil = none: the node's defaults).
	NodeStorage *siteobject.NodeStorage
}

// DynamicRoutingApplier activates releases on the node (the daemon's
// dynroute manager, which is also the client's DeploymentManager: it reports
// the scope pointers, looks results up and rolls back). Apply returns the
// deployment's journal (DynamicRoutingResult); a non-nil error is returned
// only when the result could not be recorded.
type DynamicRoutingApplier interface {
	ApplyDynamicRouting(ctx context.Context, deploymentID string, attempt uint32, release DynamicRoutingRelease) (deployment.Result, error)
}

// WithDynamicRouting enables site_runtime 9 deployments.
func WithDynamicRouting(applier DynamicRoutingApplier) ClientOption {
	return func(client *Client) error {
		if applier == nil {
			return fmt.Errorf("%w: dynamic routing applier is required", ErrInvalidConfiguration)
		}
		client.dynamicRouting = applier
		return nil
	}
}

func isDynamicRoutingCommand(command *agentv1.DeploymentCommand) bool {
	return command != nil && len(command.Artifacts) == 2 && command.Artifacts[0] != nil &&
		command.Artifacts[0].MediaType == siteobject.RootMediaTypeV2
}

func (c *Client) executeDynamicRoutingRecord(ctx context.Context, gateway agentv1.AgentGatewayServiceClient,
	record *durableRecord, command *agentv1.DeploymentCommand, maximumChunkBytes uint32, activeIdentityEnabled bool) error {
	fail := func(err error) error {
		status := failedStatus(command, 2, c.now(), classifyError(err), err.Error(), false)
		return c.completeDeploymentRecord(record.RecordKey, []*agentv1.DeploymentStatus{status}, activeIdentityEnabled)
	}
	if c.dynamicRouting == nil {
		return fail(fmt.Errorf("%w: dynamic routing is not enabled on this node", ErrUnsupportedCommand))
	}
	release, digests, unstage, err := c.fetchDynamicRoutingRelease(ctx, gateway, record, command, maximumChunkBytes)
	if err != nil {
		commandExpired := errors.Is(err, context.DeadlineExceeded) && !c.now().Before(command.DeadlineTime.AsTime())
		if ctx.Err() != nil || !errors.Is(err, ErrArtifactIntegrity) && !commandExpired {
			return err
		}
		return fail(err)
	}
	defer unstage()
	result, err := c.dynamicRouting.ApplyDynamicRouting(ctx, command.DeploymentId, command.Attempt, release)
	if err != nil && ctx.Err() != nil {
		return err
	}
	if err == nil && result.State == deployment.StateHealthy {
		if commitErr := c.siteObjects.Commit(siteObjectOwner(command.GetConfigurationScopeId()), digests); commitErr == nil {
			_, _ = c.siteObjects.Collect()
		}
	}
	return c.completeDeploymentProcessResult(record.RecordKey, command, result, err, activeIdentityEnabled)
}

// DynamicRoutingResult is the deployment journal a dynamic routing apply
// or rollback writes: delivered, staged, prechecked, activated and healthy
// (rollback: reverting, reverted), or failed after staging with the running
// state unchanged (dynroute leaves the previous generation active on every
// error before activation). An error after activation
// (DynamicRoutingActivated) keeps the success journal and records the
// failure as MaintenanceFailure: the node serves the new configuration, so
// "running configuration unchanged" would be false (PJ-E02). An apply that
// failed its health check after activation is activated, reverting and
// reverted (DynamicRoutingReverted: the previous generation runs again) or
// rollback_failed (DynamicRoutingRollbackFailed: the running state is
// uncertain; the control plane requires reconciliation), never "unchanged".
func DynamicRoutingResult(deploymentID string, attempt uint32, action deployment.Action, configVersionID string,
	started, now time.Time, err error) deployment.Result {
	result := deployment.Result{DeploymentID: deploymentID, Attempt: attempt, Action: action, ConfigVersionID: configVersionID}
	states := []deployment.State{deployment.StateDelivered, deployment.StateStaged, deployment.StatePrechecked,
		deployment.StateActivated, deployment.StateHealthy}
	if action == deployment.ActionRollback {
		states = []deployment.State{deployment.StateDelivered, deployment.StateStaged, deployment.StatePrechecked,
			deployment.StateReverting, deployment.StateReverted}
	}
	maintenance := ""
	reverted, rollbackFailed := action == deployment.ActionApply && DynamicRoutingReverted(err),
		action == deployment.ActionApply && DynamicRoutingRollbackFailed(err)
	switch {
	case action == deployment.ActionRollback && DynamicRoutingRollbackFailed(err):
		// the rollback target was activated, failed and could not be undone
		states = []deployment.State{deployment.StateDelivered, deployment.StateStaged, deployment.StatePrechecked,
			deployment.StateReverting, deployment.StateRollbackFailed}
	case reverted || rollbackFailed:
		// activated, then failed: compensated (reverted) or not (rollback_failed)
		last := deployment.StateReverted
		if rollbackFailed {
			last = deployment.StateRollbackFailed
		}
		states = []deployment.State{deployment.StateDelivered, deployment.StateStaged, deployment.StatePrechecked,
			deployment.StateActivated, deployment.StateReverting, last}
	case DynamicRoutingActivated(err):
		maintenance = sanitizeSummary(err.Error())
	case err != nil:
		states = []deployment.State{deployment.StateDelivered, deployment.StateStaged, deployment.StateFailed}
	}
	for index, state := range states {
		at := started
		if index > 0 {
			at = now
		}
		transition := deployment.Transition{Sequence: uint64(index + 1), State: state, At: at.UTC()}
		switch {
		case state == deployment.StateReverting && (reverted || rollbackFailed):
			transition.ErrorCode, transition.Summary = "HEALTH_FAILED", err.Error()
		case state == deployment.StateReverted && reverted:
			transition.Summary = err.Error()
		case state == deployment.StateRollbackFailed:
			transition.ErrorCode, transition.Summary = "ROLLBACK_RESTORE_FAILED", err.Error()
		}
		if state == deployment.StateFailed {
			code := "HEALTH_FAILED"
			if action == deployment.ActionRollback {
				code = "ROLLBACK_ACTIVATION_FAILED"
			}
			transition.RunningConfigUnchanged, transition.ErrorCode, transition.Summary = true, code, err.Error()
		}
		if index == len(states)-1 {
			transition.MaintenanceFailure = maintenance
		}
		result.Transitions = append(result.Transitions, transition)
	}
	latest := result.Transitions[len(result.Transitions)-1]
	result.State, result.Sequence = latest.State, latest.Sequence
	result.RunningConfigUnchanged, result.ErrorCode, result.Summary = latest.RunningConfigUnchanged, latest.ErrorCode, latest.Summary
	return result
}

// DynamicRoutingActivated reports an apply error raised after the new
// configuration was activated (dynroute.MaintenanceError).
func DynamicRoutingActivated(err error) bool {
	var activated interface{ ActivatedMaintenanceFailure() bool }
	return errors.As(err, &activated) && activated.ActivatedMaintenanceFailure()
}

// DynamicRoutingReverted reports an apply error raised after activation
// that was compensated: the previous generation runs again
// (dynroute.RevertedError).
func DynamicRoutingReverted(err error) bool {
	var reverted interface{ RevertedAfterActivation() bool }
	return errors.As(err, &reverted) && reverted.RevertedAfterActivation()
}

// DynamicRoutingRollbackFailed reports an apply error raised after
// activation whose compensation failed: the running state is uncertain
// (dynroute.RollbackFailedError).
func DynamicRoutingRollbackFailed(err error) bool {
	var failed interface{ RollbackFailedAfterActivation() bool }
	return errors.As(err, &failed) && failed.RollbackFailedAfterActivation()
}

// fetchDynamicRoutingRelease verifies the v2 root and key and brings the
// object store up to the root.
func (c *Client) fetchDynamicRoutingRelease(ctx context.Context, gateway agentv1.AgentGatewayServiceClient, record *durableRecord,
	command *agentv1.DeploymentCommand, maximumChunkBytes uint32) (release DynamicRoutingRelease, digests []string, unstage func(), err error) {
	started := c.now()
	rootDescriptor, keyDescriptor := command.Artifacts[0], command.Artifacts[1]
	rootWire, err := fetchDurableArtifactWire(ctx, gateway, c.store, record, command, rootDescriptor, maximumChunkBytes, c.config, c.trust, c.now)
	if err != nil {
		return DynamicRoutingRelease{}, nil, nil, err
	}
	root, err := siteobject.ParseRootV2(rootWire)
	if err != nil {
		return DynamicRoutingRelease{}, nil, nil, fmt.Errorf("%w: %v", ErrArtifactIntegrity, err)
	}
	if root.ConfigurationScopeID != command.GetConfigurationScopeId() || root.ConfigVersionID != command.ConfigVersionId {
		return DynamicRoutingRelease{}, nil, nil, fmt.Errorf("%w: site object root does not match command identity", ErrArtifactIntegrity)
	}
	if err := sameSiteObjectCapabilities(root.RequiredCapabilities, command.RequiredCapabilities); err != nil {
		return DynamicRoutingRelease{}, nil, nil, err
	}
	keyWire, err := fetchArtifactWire(ctx, gateway, command, keyDescriptor, maximumChunkBytes, c.config, c.trust, c.now)
	if err != nil {
		return DynamicRoutingRelease{}, nil, nil, err
	}
	keyPlaintext, err := decryptArtifactHPKE(command, keyDescriptor, keyWire, c.config.ArtifactDecryptionPrivateKey)
	if err != nil {
		return DynamicRoutingRelease{}, nil, nil, err
	}
	defer clearPlaintext(keyPlaintext)
	key, err := siteobject.ParseKeyDocument(keyPlaintext)
	if err != nil {
		return DynamicRoutingRelease{}, nil, nil, fmt.Errorf("%w: %v", ErrArtifactIntegrity, err)
	}
	defer clearPlaintext(key.ContentKey)
	rootSHA256 := siteobject.Digest(rootWire)
	if key.ConfigurationScopeID != root.ConfigurationScopeID || key.ConfigVersionID != root.ConfigVersionID ||
		key.RootSHA256 != rootSHA256 || key.KeyEpoch != root.KeyEpoch {
		return DynamicRoutingRelease{}, nil, nil, fmt.Errorf("%w: site object key does not match the root", ErrArtifactIntegrity)
	}
	fetcher := &siteObjectFetcher{
		client: c, gateway: gateway, command: command, rootSHA256: key.RootSHA256, scopeID: root.ConfigurationScopeID,
		contentKey: key.ContentKey, maximumChunkBytes: maximumChunkBytes, plaintext: map[string][]byte{},
	}
	defer func() {
		if err != nil {
			fetcher.unstage()
		}
	}()
	integrity := func(err error) error { return fmt.Errorf("%w: %v", ErrArtifactIntegrity, err) }
	if err := fetcher.ensure(ctx, append([]string{root.ScopeSHA256}, root.Buckets...)); err != nil {
		return DynamicRoutingRelease{}, nil, nil, err
	}
	scope, err := siteobject.ParseScopeV2(fetcher.plaintext[root.ScopeSHA256])
	if err != nil || scope.ConfigurationScopeID != root.ConfigurationScopeID {
		return DynamicRoutingRelease{}, nil, nil, integrity(fmt.Errorf("v2 scope: %v", err))
	}
	indexBytes := len(rootWire)
	var sites []string
	for _, digest := range root.Buckets {
		indexBytes += len(fetcher.plaintext[digest])
		bucket, err := siteobject.ParseBucketV2(fetcher.plaintext[digest])
		if err != nil || bucket.ConfigurationScopeID != root.ConfigurationScopeID || bucket.BucketCount != root.BucketCount {
			return DynamicRoutingRelease{}, nil, nil, integrity(fmt.Errorf("v2 bucket: %v", err))
		}
		sites = append(sites, bucket.SiteDigests()...)
	}
	if indexBytes > siteobject.MaxRootIndexBytes {
		return DynamicRoutingRelease{}, nil, nil, integrity(fmt.Errorf("root index of %d bytes", indexBytes))
	}
	if err := fetcher.ensure(ctx, sites); err != nil {
		return DynamicRoutingRelease{}, nil, nil, err
	}
	if err := fetcher.ensure(ctx, append(siteobject.FileDigests(scope.Files), scope.Objects...)); err != nil {
		return DynamicRoutingRelease{}, nil, nil, err
	}
	release = DynamicRoutingRelease{
		ConfigurationScopeID: root.ConfigurationScopeID, ConfigVersionID: root.ConfigVersionID, RootSHA256: rootSHA256,
		Sites: make(map[string][]byte, len(sites)), Referenced: make(map[string][]byte, len(scope.Objects)),
		ScopeFiles: make(map[string][]byte, len(scope.Files)), System: scope.System,
		SourceRevision: root.SourceRevision, NodePages: scope.NodePages,
		InstallationID: scope.InstallationID, TrafficStop: key.TrafficStopStreams, NodeRegion: key.NodeRegion, NodeStorage: key.NodeStorage,
	}
	// L4_STREAM_SELECTION: this node's key document names the forwards
	// none of whose line groups has it.
	if release.Streams, err = SelectNodeStreams(scope.Streams, key.L4WithheldStreams); err != nil {
		return DynamicRoutingRelease{}, nil, nil, integrity(err)
	}
	for _, digest := range sites {
		release.Sites[digest] = fetcher.plaintext[digest]
	}
	for _, digest := range scope.Objects {
		release.Referenced[digest] = fetcher.plaintext[digest]
	}
	for _, file := range scope.Files {
		release.ScopeFiles[file.Path] = fetcher.plaintext[file.SHA256]
	}
	fetcher.stats.Duration = c.now().Sub(started)
	c.recordSiteObjectStats(fetcher.stats)
	return release, fetcher.referenced, fetcher.unstage, nil
}

// SelectNodeStreams is the scope's L4 forwards this node serves: the root's
// without those its key document withholds (L4_STREAM_SELECTION v1); none
// left = no L4 runtime of the scope. A withheld forward the root does not
// carry is refused: control derives the list from the same release.
func SelectNodeStreams(streams *edgeconfig.StreamRuntime, withheld []string) (*edgeconfig.StreamRuntime, error) {
	if len(withheld) == 0 {
		return streams, nil
	}
	if streams == nil {
		return nil, fmt.Errorf("site object key withholds L4 forwards of a release without any")
	}
	skip := make(map[string]bool, len(withheld))
	for _, id := range withheld {
		skip[id] = false
	}
	selected := &edgeconfig.StreamRuntime{TenantID: streams.TenantID}
	for _, stream := range streams.StreamsV2 {
		if _, found := skip[stream.StreamID]; found {
			skip[stream.StreamID] = true
			continue
		}
		selected.StreamsV2 = append(selected.StreamsV2, stream)
	}
	for id, seen := range skip {
		if !seen {
			return nil, fmt.Errorf("site object key withholds L4 forward %s the release does not carry", id)
		}
	}
	if len(selected.StreamsV2) == 0 {
		return nil, nil
	}
	return selected, nil
}
