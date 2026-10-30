package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/analytics"
	"github.com/cdnca/cdnca/services/control-api/internal/openrestysecurity"
	"github.com/cdnca/cdnca/services/control-api/internal/sitetrafficlimit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The community edition has no package traffic enforcement (no packages); this
// runtime keeps only the websites' own traffic caps (ge-analytics). The
// PACKAGE_TRAFFIC_ENFORCEMENT_* names stay because native installs set them.
const (
	packageTrafficEnforcementPrefix              = "PACKAGE_TRAFFIC_ENFORCEMENT_"
	packageTrafficEnforcementEnabledEnv          = packageTrafficEnforcementPrefix + "ENABLED"
	packageTrafficEnforcementWorkerIDEnv         = packageTrafficEnforcementPrefix + "WORKER_ID"
	packageTrafficEnforcementPollIntervalEnv     = packageTrafficEnforcementPrefix + "POLL_INTERVAL"
	packageTrafficEnforcementEvaluationEnv       = packageTrafficEnforcementPrefix + "EVALUATION_INTERVAL"
	packageTrafficEnforcementBatchSizeEnv        = packageTrafficEnforcementPrefix + "BATCH_SIZE"
	packageTrafficEnforcementOperationTimeout    = 30 * time.Second
	packageTrafficEnforcementErrorBackoffMaximum = 2 * time.Minute
)

type packageTrafficEnforcementConfig struct {
	Enabled            bool
	WorkerID           string
	PollInterval       time.Duration
	EvaluationInterval time.Duration
	BatchSize          int
}

// Evaluates websites' own traffic caps (ge-analytics) from ClickHouse facts and
// applies the block-page switch through the system republication channel.
type packageTrafficEnforcementRuntime struct {
	siteLimits   *sitetrafficlimit.Evaluator
	pollInterval time.Duration
	logger       *slog.Logger
}

func loadPackageTrafficEnforcementConfig() (packageTrafficEnforcementConfig, error) {
	return loadPackageTrafficEnforcementConfigFromEnv(os.Environ())
}

func loadPackageTrafficEnforcementConfigFromEnv(environment []string) (packageTrafficEnforcementConfig, error) {
	values, err := runtimeEnvEntries(environment, packageTrafficEnforcementPrefix, map[string]struct{}{
		packageTrafficEnforcementEnabledEnv: {}, packageTrafficEnforcementWorkerIDEnv: {},
		packageTrafficEnforcementPollIntervalEnv: {}, packageTrafficEnforcementEvaluationEnv: {},
		packageTrafficEnforcementBatchSizeEnv: {},
	})
	if err != nil {
		return packageTrafficEnforcementConfig{}, err
	}
	enabled, err := strictRuntimeBool(values, packageTrafficEnforcementEnabledEnv)
	if err != nil || !enabled {
		return packageTrafficEnforcementConfig{}, err
	}
	config := packageTrafficEnforcementConfig{Enabled: true, WorkerID: values[packageTrafficEnforcementWorkerIDEnv],
		PollInterval: 15 * time.Second, EvaluationInterval: time.Minute, BatchSize: 100}
	if !validTrafficEnforcementWorkerID(config.WorkerID) {
		return packageTrafficEnforcementConfig{}, errors.New(packageTrafficEnforcementWorkerIDEnv + " is required and invalid")
	}
	for name, target := range map[string]*time.Duration{
		packageTrafficEnforcementPollIntervalEnv: &config.PollInterval,
		packageTrafficEnforcementEvaluationEnv:   &config.EvaluationInterval,
	} {
		if value, present := values[name]; present {
			parsed, parseErr := time.ParseDuration(value)
			if parseErr != nil || parsed <= 0 || strings.TrimSpace(value) != value {
				return packageTrafficEnforcementConfig{}, errors.New(name + " is invalid")
			}
			*target = parsed
		}
	}
	if value, present := values[packageTrafficEnforcementBatchSizeEnv]; present {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 1000 || strconv.Itoa(parsed) != value {
			return packageTrafficEnforcementConfig{}, errors.New(packageTrafficEnforcementBatchSizeEnv + " is invalid")
		}
		config.BatchSize = parsed
	}
	if config.PollInterval < time.Second || config.PollInterval > 5*time.Minute ||
		config.EvaluationInterval < time.Second || config.EvaluationInterval > time.Hour {
		return packageTrafficEnforcementConfig{}, errors.New("package traffic enforcement timing bounds are unsafe")
	}
	return config, nil
}

func validTrafficEnforcementWorkerID(value string) bool {
	if value == "" || strings.TrimSpace(value) != value || !utf8.ValidString(value) || utf8.RuneCountInString(value) > 128 {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || character == '\u2028' || character == '\u2029' {
			return false
		}
	}
	return true
}

func buildPackageTrafficEnforcementRuntime(
	config packageTrafficEnforcementConfig,
	pool *pgxpool.Pool,
	analyticsRuntime *analyticsQueryRuntime,
	logger *slog.Logger,
) (*packageTrafficEnforcementRuntime, error) {
	if !config.Enabled {
		return nil, nil
	}
	if pool == nil || analyticsRuntime == nil || logger == nil {
		return nil, errors.New("package traffic enforcement requires PostgreSQL and ANALYTICS_QUERY_ENABLED=true")
	}
	client, ok := analyticsRuntime.QueryStore().(*analytics.Client)
	if !ok || client == nil {
		return nil, errors.New("package traffic enforcement ClickHouse client is unavailable")
	}
	siteLimits, err := sitetrafficlimit.NewEvaluator(pool, siteTrafficUsage{client: client, pool: pool},
		config.EvaluationInterval, config.BatchSize, time.Now)
	if err != nil {
		return nil, err
	}
	return &packageTrafficEnforcementRuntime{siteLimits: siteLimits, pollInterval: config.PollInterval,
		logger: logger}, nil
}

// Run never stops the server: failures are logged and retried with backoff.
func (runtime *packageTrafficEnforcementRuntime) Run(ctx context.Context) {
	backoff := runtime.pollInterval
	for {
		operationCtx, cancel := context.WithTimeout(ctx, packageTrafficEnforcementOperationTimeout)
		worked, err := runtime.siteLimits.RunOnce(operationCtx)
		cancel()
		if ctx.Err() != nil {
			return
		}
		delay := runtime.pollInterval
		switch {
		case err != nil:
			runtime.logger.Warn("site traffic limit tick failed", "error", err)
			delay, backoff = backoff, min(backoff*2, packageTrafficEnforcementErrorBackoffMaximum)
		case worked:
			delay, backoff = 0, runtime.pollInterval
		default:
			backoff = runtime.pollInterval
		}
		if delay > 0 && !waitPackageTrafficEnforcement(ctx, delay) {
			return
		}
	}
}

// waitPackageTrafficEnforcement waits for delay unless ctx ends first.
func waitPackageTrafficEnforcement(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// siteTrafficUsage reads a site's traffic for its own caps, honouring the
// platform's "block pages are not traffic" switch as package traffic does.
type siteTrafficUsage struct {
	client *analytics.Client
	pool   *pgxpool.Pool
}

func (usage siteTrafficUsage) SiteTraffic(ctx context.Context, tenantScopeID, siteID uuid.UUID, from, to time.Time) (uint64, error) {
	exclude, err := openrestysecurity.BlockPageNotCounted(ctx, usage.pool)
	if err != nil {
		return 0, err
	}
	return usage.client.SiteTraffic(ctx, analytics.SiteTrafficRequest{
		TenantScopeID: tenantScopeID.String(), SiteID: siteID.String(),
		From: from.UTC().Truncate(time.Millisecond), To: to.UTC().Truncate(time.Millisecond), ExcludeBlocked: exclude,
	})
}
