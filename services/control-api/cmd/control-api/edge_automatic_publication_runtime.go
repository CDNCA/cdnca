package main

import (
	"context"
	"errors"
	"os"
	"regexp"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	edgeAutomaticPublicationEnabledEnv          = "EDGE_AUTOMATIC_PUBLICATION_ENABLED"
	edgeAutomaticPublicationWorkerIDEnv         = "EDGE_AUTOMATIC_PUBLICATION_WORKER_ID"
	edgeAutomaticPublicationPollIntervalEnv     = "EDGE_AUTOMATIC_PUBLICATION_POLL_INTERVAL"
	edgeAutomaticPublicationErrorBackoffEnv     = "EDGE_AUTOMATIC_PUBLICATION_ERROR_BACKOFF"
	edgeAutomaticPublicationOperationTimeoutEnv = "EDGE_AUTOMATIC_PUBLICATION_OPERATION_TIMEOUT"
	edgeAutomaticPublicationLeaseDurationEnv    = "EDGE_AUTOMATIC_PUBLICATION_LEASE_DURATION"
	edgeAutomaticPublicationRetryDelayEnv       = "EDGE_AUTOMATIC_PUBLICATION_RETRY_DELAY"
)

var edgeAutomaticPublicationWorkerIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type edgeAutomaticPublicationRuntimeConfig struct {
	Enabled bool
	Worker  edgeautopublish.WorkerConfig
	Runtime edgeautopublish.RuntimeConfig

	// LazyCertificateCacheMax overrides edgepublish.Config's when non-zero.
	LazyCertificateCacheMax int64
}

type edgeAutomaticPublicationRuntimeDependencies struct {
	Pool        *pgxpool.Pool
	Signer      edgepublish.ArtifactSigner
	Entitlement edgepublish.EntitlementAuthorizer
	Resolver    edgepublish.TargetResolver
	Clock       func() time.Time
	// ChallengeRedeliverer, when the challenge publication runtime is on,
	// redelivers bound JS challenge policies to joined/recovered nodes.
	ChallengeRedeliverer edgepublish.ChallengeSecretRedeliverer
	// ErrorPageSource, when the error page runtime is on, lets the system
	// republisher deliver theme activations to every tenant's error pages.
	ErrorPageSource edgepublish.ErrorPageProductionSource
	// RenewalDeliverer, when the certificate publication runtime is on,
	// delivers automatic renewals to the nodes and switches them in.
	RenewalDeliverer edgeautopublish.RuntimeWorker
}

type edgeAutomaticPublicationProductionRuntime struct {
	core *edgeautopublish.Runtime
}

func loadEdgeAutomaticPublicationRuntimeConfig() (edgeAutomaticPublicationRuntimeConfig, error) {
	return loadEdgeAutomaticPublicationRuntimeConfigFromEnv(os.Environ())
}

func loadEdgeAutomaticPublicationRuntimeConfigFromEnv(
	environment []string,
) (edgeAutomaticPublicationRuntimeConfig, error) {
	const prefix = "EDGE_AUTOMATIC_PUBLICATION_"
	values, err := runtimeEnvEntries(environment, prefix, map[string]struct{}{
		edgeAutomaticPublicationEnabledEnv:          {},
		edgeAutomaticPublicationWorkerIDEnv:         {},
		edgeAutomaticPublicationPollIntervalEnv:     {},
		edgeAutomaticPublicationErrorBackoffEnv:     {},
		edgeAutomaticPublicationOperationTimeoutEnv: {},
		edgeAutomaticPublicationLeaseDurationEnv:    {},
		edgeAutomaticPublicationRetryDelayEnv:       {},
	})
	if err != nil {
		return edgeAutomaticPublicationRuntimeConfig{}, err
	}
	enabled, err := strictRuntimeBool(values, edgeAutomaticPublicationEnabledEnv)
	if err != nil {
		return edgeAutomaticPublicationRuntimeConfig{}, err
	}
	if !enabled {
		if len(values) > 1 {
			return edgeAutomaticPublicationRuntimeConfig{}, errors.New("automatic edge publication configuration is invalid while disabled")
		}
		return edgeAutomaticPublicationRuntimeConfig{}, nil
	}
	if len(values) != 7 || !edgeAutomaticPublicationWorkerIDPattern.MatchString(values[edgeAutomaticPublicationWorkerIDEnv]) {
		return edgeAutomaticPublicationRuntimeConfig{}, errors.New("automatic edge publication configuration is incomplete")
	}

	pollInterval, err := edgeAutomaticPublicationDuration(
		values, edgeAutomaticPublicationPollIntervalEnv, 10*time.Millisecond, time.Minute,
	)
	if err != nil {
		return edgeAutomaticPublicationRuntimeConfig{}, err
	}
	errorBackoff, err := edgeAutomaticPublicationDuration(
		values, edgeAutomaticPublicationErrorBackoffEnv, 10*time.Millisecond, 5*time.Minute,
	)
	if err != nil {
		return edgeAutomaticPublicationRuntimeConfig{}, err
	}
	operationTimeout, err := edgeAutomaticPublicationDuration(
		values, edgeAutomaticPublicationOperationTimeoutEnv, 100*time.Millisecond, 5*time.Minute,
	)
	if err != nil {
		return edgeAutomaticPublicationRuntimeConfig{}, err
	}
	leaseDuration, err := edgeAutomaticPublicationDuration(
		values, edgeAutomaticPublicationLeaseDurationEnv, time.Second, time.Hour,
	)
	if err != nil {
		return edgeAutomaticPublicationRuntimeConfig{}, err
	}
	retryDelay, err := edgeAutomaticPublicationDuration(
		values, edgeAutomaticPublicationRetryDelayEnv, 0, time.Hour,
	)
	if err != nil {
		return edgeAutomaticPublicationRuntimeConfig{}, err
	}
	if leaseDuration <= operationTimeout {
		return edgeAutomaticPublicationRuntimeConfig{}, errors.New("automatic edge publication lease must exceed the operation timeout")
	}
	return edgeAutomaticPublicationRuntimeConfig{
		Enabled: true,
		Worker: edgeautopublish.WorkerConfig{
			WorkerID: values[edgeAutomaticPublicationWorkerIDEnv], LeaseDuration: leaseDuration, RetryDelay: retryDelay,
		},
		Runtime: edgeautopublish.RuntimeConfig{
			PollInterval: pollInterval, ErrorBackoff: errorBackoff, OperationTimeout: operationTimeout,
		},
	}, nil
}

func edgeAutomaticPublicationDuration(
	values map[string]string,
	name string,
	minimum, maximum time.Duration,
) (time.Duration, error) {
	value, present := values[name]
	if !present || value == "" {
		return 0, errors.New("automatic edge publication duration configuration is incomplete")
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration < minimum || duration > maximum {
		return 0, errors.New("automatic edge publication duration configuration is invalid")
	}
	return duration, nil
}

func validateEdgeAutomaticPublicationShutdownPeriod(
	shutdownPeriod time.Duration,
	config edgeAutomaticPublicationRuntimeConfig,
) error {
	if config.Enabled && shutdownPeriod < config.Runtime.OperationTimeout {
		return errors.New("control API shutdown period is shorter than the automatic publication operation timeout")
	}
	return nil
}

func openEdgeAutomaticPublicationProductionRuntime(
	config edgeAutomaticPublicationRuntimeConfig,
	dependencies edgeAutomaticPublicationRuntimeDependencies,
) (*edgeAutomaticPublicationProductionRuntime, error) {
	if !config.Enabled {
		return nil, nil
	}
	if !configuredRuntimePool(dependencies.Pool) || nilRuntimeDependency(dependencies.Signer) ||
		nilRuntimeDependency(dependencies.Entitlement) || nilRuntimeDependency(dependencies.Resolver) ||
		dependencies.Clock == nil {
		return nil, errors.New("automatic edge publication production dependencies are required")
	}
	deployments, err := edgedeployment.NewStoreWithClock(dependencies.Pool, dependencies.Clock)
	if err != nil {
		return nil, errors.New("initialize automatic edge publication deployment store")
	}
	coordinator := edgeautopublish.NewStore(dependencies.Pool)
	publisherConfig := edgepublish.DefaultConfig()
	if config.LazyCertificateCacheMax != 0 {
		publisherConfig.LazyCertificateCacheMax = config.LazyCertificateCacheMax
	}
	publisherConfig.Clock = dependencies.Clock
	publisherConfig.EntitlementAuthorizer = dependencies.Entitlement
	publisherConfig.TargetResolver = dependencies.Resolver
	publisherConfig.Auditor = audit.New(dependencies.Pool)
	publisher, err := edgepublish.NewAutomaticService(
		dependencies.Pool, deployments, dependencies.Signer, publisherConfig, coordinator,
	)
	if err != nil {
		return nil, errors.New("initialize automatic edge publication service")
	}
	worker, err := edgeautopublish.NewWorker(coordinator, publisher, config.Worker)
	if err != nil {
		return nil, errors.New("initialize automatic edge publication worker")
	}
	// System republication of every other tenant scope, and the
	// capability watcher that queues it, run on the same loop.
	systemService, err := edgepublish.NewService(dependencies.Pool, deployments, dependencies.Signer, publisherConfig)
	if err != nil {
		return nil, errors.New("initialize system edge republication service")
	}
	republisher, err := edgepublish.NewSystemRepublisher(systemService, edgepublish.SystemRepublisherConfig{
		WorkerID: config.Worker.WorkerID, LeaseDuration: config.Worker.LeaseDuration, RetryDelay: config.Worker.RetryDelay,
	})
	if err != nil {
		return nil, errors.New("initialize system edge republication worker")
	}
	if !nilRuntimeDependency(dependencies.ErrorPageSource) {
		errorPages, err := edgepublish.NewErrorPagePublisher(systemService, dependencies.ErrorPageSource)
		if err == nil {
			err = republisher.WithErrorPagePublisher(errorPages)
		}
		if err != nil {
			return nil, errors.New("initialize theme error page republication")
		}
	}
	watcher, err := edgeautopublish.NewCapabilityWatcher(dependencies.Pool, 10*time.Second)
	if err != nil {
		return nil, errors.New("initialize node capability watcher")
	}
	// Node address changes: republish the DDoS node
	// exemption of every scope carrying the old addresses.
	nodeNetworks, err := edgeautopublish.NewNodeNetworksWatcher(dependencies.Pool, publisherConfig.Auditor, 10*time.Second)
	if err != nil {
		return nil, errors.New("initialize node networks watcher")
	}
	// Package expiry and renewal (errpage-4 S3): republish the scope so its
	// sites go out marked package expired, or unmarked again.
	packageExpiry, err := edgeautopublish.NewPackageExpiryWatcher(dependencies.Pool, 30*time.Second)
	if err != nil {
		return nil, errors.New("initialize package expiry watcher")
	}
	chain := edgeautopublish.WorkerChain{worker, republisher, watcher, nodeNetworks, packageExpiry}
	// Module revocation and restore: pending
	// republication marks and the system republication on restore.
	if grants, ok := dependencies.Entitlement.(edgepublish.ModuleGrantReader); ok {
		moduleWatcher, err := edgeautopublish.NewModuleWatcher(dependencies.Pool, grants,
			publisherConfig.ModuleRequirements, publisherConfig.Auditor, 30*time.Second)
		if err != nil {
			return nil, errors.New("initialize module entitlement watcher")
		}
		chain = append(chain, moduleWatcher)
	}
	if !nilRuntimeDependency(dependencies.ChallengeRedeliverer) {
		redeliverer, err := edgepublish.NewChallengeRedeliverer(dependencies.Pool, dependencies.ChallengeRedeliverer,
			edgeautopublish.ChallengeDeliveryPublisher{}, edgepublish.ChallengeRedelivererConfig{RetryDelay: config.Worker.RetryDelay})
		if err != nil {
			return nil, errors.New("initialize challenge policy redelivery worker")
		}
		chain = append(chain, redeliverer)
	}
	if !nilRuntimeDependency(dependencies.RenewalDeliverer) {
		chain = append(chain, dependencies.RenewalDeliverer)
	}
	core, err := edgeautopublish.NewRuntime(chain, coordinator, config.Runtime)
	if err != nil {
		return nil, errors.New("initialize automatic edge publication runtime")
	}
	return &edgeAutomaticPublicationProductionRuntime{core: core}, nil
}

func (runtime *edgeAutomaticPublicationProductionRuntime) Run(ctx context.Context) error {
	if runtime == nil || runtime.core == nil {
		return edgeautopublish.ErrInvalidInput
	}
	return runtime.core.Run(ctx)
}

func (runtime *edgeAutomaticPublicationProductionRuntime) Ready() error {
	if runtime == nil || runtime.core == nil {
		return edgeautopublish.ErrInvalidInput
	}
	return runtime.core.Ready()
}

func (runtime *edgeAutomaticPublicationProductionRuntime) Close(ctx context.Context) error {
	if runtime == nil || runtime.core == nil {
		return edgeautopublish.ErrInvalidInput
	}
	return runtime.core.Close(ctx)
}
