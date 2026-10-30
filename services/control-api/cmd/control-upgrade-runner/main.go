package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/controlplaneupgrade"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
)

var ErrNoVerifiedPlan = errors.New("no verified control upgrade plan is available")

func main() {
	if err := run(context.Background()); err != nil {
		slog.Error("control upgrade runner stopped", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	installationID, err := readRequiredFile("CONTROL_UPGRADE_INSTALLATION_ID_FILE", 4096)
	if err != nil {
		return err
	}
	trustedKeys, err := readRequiredBytes("CONTROL_UPGRADE_TRUST_FILE", 1<<20)
	if err != nil {
		return err
	}
	trust, err := entitlementguard.DecodeTrustedKeys(trustedKeys)
	if err != nil {
		return fmt.Errorf("load upgrade trust: %w", err)
	}
	stateDirectory := requiredEnv("CONTROL_UPGRADE_STATE_DIR")
	store, err := controlplaneupgrade.NewFileStore(stateDirectory)
	if err != nil {
		return err
	}
	target := controlplaneupgrade.Target(requiredEnv("CONTROL_UPGRADE_TARGET"))
	if target == controlplaneupgrade.TargetNativeStandalone {
		return runNativeStandalone(ctx, installationID, trust, store)
	}
	lock, err := acquireRunnerLock(stateDirectory)
	if err != nil {
		return err
	}
	defer lock.Close()
	executor, err := openExecutor(target, installationID)
	if err != nil {
		return err
	}
	runner, err := controlplaneupgrade.New(controlplaneupgrade.Config{InstallationID: installationID,
		Component: "control-api", Target: target}, trust, store, executor, time.Now)
	if err != nil {
		return err
	}
	pollInterval, err := durationEnv("CONTROL_UPGRADE_POLL_INTERVAL", 5*time.Second)
	if err != nil {
		return err
	}
	oneshoot := strings.EqualFold(os.Getenv("CONTROL_UPGRADE_ONESHOT"), "true")
	if usesHTTPPlanSource(target) {
		source, lkg, initial, err := openHTTPPlanRuntime(installationID)
		if err != nil {
			return err
		}
		protocolVersion, err := integerEnv("CONTROL_UPGRADE_PROTOCOL_VERSION", 1)
		if err != nil {
			return err
		}
		verify := newHTTPPlanVerifier(trust, installationID, requiredEnv("CONTROL_UPGRADE_CURRENT_VERSION"),
			protocolVersion, time.Now)
		if initial != nil && verify(initial.Bundle) != nil {
			return ErrNoVerifiedPlan
		}
		return runPlanLoop(ctx, source, lkg, initial, runner, verify, pollInterval, oneshoot, slog.Default())
	}
	return runFilePlanLoop(ctx, runner, pollInterval, oneshoot, slog.Default())
}

func usesHTTPPlanSource(target controlplaneupgrade.Target) bool {
	return target == controlplaneupgrade.TargetSystemd || target == controlplaneupgrade.TargetKubernetes
}

type httpPlanFetcher interface {
	Fetch(context.Context) (HTTPPlan, error)
}

type httpPlanWriter interface {
	Save(HTTPPlan) error
}

type controlUpgradePlanRunner interface {
	Run(context.Context, []byte) (controlplaneupgrade.Receipt, error)
}

type httpPlanVerifier func([]byte) error

func runPlanLoop(ctx context.Context, source httpPlanFetcher, lkg httpPlanWriter, initial *HTTPPlan,
	runner controlUpgradePlanRunner, verify httpPlanVerifier, pollInterval time.Duration, oneshoot bool,
	logger *slog.Logger) error {
	if source == nil || lkg == nil || runner == nil || verify == nil || pollInterval <= 0 || logger == nil {
		return controlplaneupgrade.ErrInvalidConfig
	}
	var lastKnown *HTTPPlan
	if initial != nil {
		cloned := cloneHTTPPlan(*initial)
		lastKnown = &cloned
	}
	for {
		candidate, fetchErr := source.Fetch(ctx)
		if errors.Is(fetchErr, ErrHTTPPlanNotPublished) && lastKnown == nil {
			if oneshoot {
				return ErrNoVerifiedPlan
			}
			if err := waitPlanPoll(ctx, pollInterval); err != nil {
				return err
			}
			continue
		}
		selected, reason := HTTPPlan{}, ""
		if fetchErr != nil {
			reason = "fetch_failed"
		} else if candidate.Replayed {
			if lastKnown == nil || !sameHTTPPlan(candidate, *lastKnown) {
				reason = "replay_binding_failed"
			} else if verify(candidate.Bundle) != nil {
				reason = "replay_verification_failed"
			} else {
				selected = cloneHTTPPlan(candidate)
			}
		} else if verify(candidate.Bundle) != nil {
			reason = "verification_failed"
		} else if err := lkg.Save(candidate); err != nil {
			reason = "persistence_failed"
		} else {
			selected = cloneHTTPPlan(candidate)
			stored := cloneHTTPPlan(candidate)
			stored.Replayed = true
			lastKnown = &stored
		}
		if len(selected.Bundle) == 0 {
			if lastKnown != nil && verify(lastKnown.Bundle) == nil {
				selected = cloneHTTPPlan(*lastKnown)
				selected.Replayed = true
				logger.Warn("control upgrade plan source degraded", "reason", reason,
					"lkg_available", true, "lkg_revision", selected.Revision)
			} else {
				logger.Warn("control upgrade plan source degraded", "reason", reason, "lkg_available", false)
				if oneshoot {
					return ErrNoVerifiedPlan
				}
				if err := waitPlanPoll(ctx, pollInterval); err != nil {
					return err
				}
				continue
			}
		}
		receipt, runErr := runner.Run(ctx, selected.Bundle)
		if receipt.ID != "" {
			output, _ := json.Marshal(receipt)
			logger.Info("control upgrade receipt", "receipt", string(output))
		} else if runErr != nil {
			logger.Warn("control upgrade plan execution degraded", "reason", "execution_failed")
		}
		if oneshoot {
			return runErr
		}
		if err := waitPlanPoll(ctx, pollInterval); err != nil {
			return err
		}
	}
}

func runFilePlanLoop(ctx context.Context, runner controlUpgradePlanRunner, pollInterval time.Duration,
	oneshoot bool, logger *slog.Logger) error {
	for {
		encoded, err := readRequiredBytes("CONTROL_UPGRADE_PLAN_FILE", 1<<20)
		if err == nil {
			receipt, runErr := runner.Run(ctx, encoded)
			if receipt.ID != "" {
				output, _ := json.Marshal(receipt)
				logger.Info("control upgrade receipt", "receipt", string(output))
			}
			if oneshoot {
				return runErr
			}
		} else if oneshoot {
			return err
		} else {
			logger.Warn("control upgrade plan unavailable", "reason", "trusted_file_read_failed")
		}
		if err := waitPlanPoll(ctx, pollInterval); err != nil {
			return err
		}
	}
}

func waitPlanPoll(ctx context.Context, interval time.Duration) error {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func openHTTPPlanRuntime(installationID string) (*HTTPPlanSource, *HTTPLKGStore, *HTTPPlan, error) {
	token, err := readRequiredFile("CONTROL_UPGRADE_INTERNAL_TOKEN_FILE", 256)
	if err != nil {
		return nil, nil, nil, err
	}
	caPEM, err := readRequiredBytes("CONTROL_UPGRADE_PLAN_SOURCE_CA_FILE", 1<<20)
	if err != nil {
		return nil, nil, nil, err
	}
	certificatePEM, err := readRequiredBytes("CONTROL_UPGRADE_PLAN_SOURCE_CERT_FILE", 1<<20)
	if err != nil {
		return nil, nil, nil, err
	}
	keyPEM, err := readRequiredBytes("CONTROL_UPGRADE_PLAN_SOURCE_KEY_FILE", 1<<20)
	if err != nil {
		return nil, nil, nil, err
	}
	roots := x509.NewCertPool()
	certificate, certificateErr := tls.X509KeyPair(certificatePEM, keyPEM)
	if !roots.AppendCertsFromPEM(caPEM) || certificateErr != nil {
		return nil, nil, nil, ErrHTTPPlanSourceInvalid
	}
	timeout, err := durationEnv("CONTROL_UPGRADE_PLAN_SOURCE_TIMEOUT", 10*time.Second)
	if err != nil {
		return nil, nil, nil, err
	}
	maximum, err := integerEnv("CONTROL_UPGRADE_PLAN_SOURCE_MAX_BYTES", 1024)
	if err != nil {
		return nil, nil, nil, err
	}
	rawURL := requiredEnv("CONTROL_UPGRADE_PLAN_SOURCE_URL")
	if invalidProductionPlanAddress(rawURL) {
		return nil, nil, nil, ErrHTTPPlanSourceInvalid
	}
	transport := &http.Transport{ForceAttemptHTTP2: true, MaxIdleConns: 2, MaxIdleConnsPerHost: 2,
		IdleConnTimeout: time.Minute, TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
			RootCAs: roots, Certificates: []tls.Certificate{certificate}}}
	source, err := NewHTTPPlanSource(HTTPPlanSourceConfig{URL: rawURL, InstallationID: installationID,
		Operation: controlplaneupgrade.SystemdControlUpgradeOperation, Token: token,
		HTTPClient: &http.Client{Transport: transport}, Timeout: timeout, MaxBodyBytes: int64(maximum)})
	if err != nil {
		return nil, nil, nil, err
	}
	lkg, err := NewHTTPLKGStore(requiredEnv("CONTROL_UPGRADE_PLAN_LKG_FILE"), installationID,
		controlplaneupgrade.SystemdControlUpgradeOperation, int64(maximum))
	if err != nil {
		return nil, nil, nil, err
	}
	loaded, err := lkg.Load()
	if errors.Is(err, ErrHTTPLKGNotFound) {
		return source, lkg, nil, nil
	}
	if err != nil {
		return nil, nil, nil, err
	}
	cached := cloneHTTPPlan(loaded)
	cached.Replayed = false
	source.cached = &cached
	initial := cloneHTTPPlan(loaded)
	return source, lkg, &initial, nil
}

func invalidProductionPlanAddress(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil {
		return true
	}
	// A native runner may use its host's private mTLS listener. HA targets keep
	// their existing address boundary; TLS, client identity and token checks stay
	// mandatory in openHTTPPlanRuntime even for these two fixed loopback hosts.
	if os.Getenv("CONTROL_UPGRADE_TARGET") == string(controlplaneupgrade.TargetNativeStandalone) &&
		parsed.Scheme == "https" && (parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "::1") {
		return false
	}
	address := net.ParseIP(parsed.Hostname())
	return address != nil && (address.IsPrivate() || address.IsLoopback() || address.IsUnspecified() ||
		address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast())
}

func newHTTPPlanVerifier(trust *entitlementguard.TrustStore, installationID, currentVersion string,
	protocolVersion int, now func() time.Time) httpPlanVerifier {
	return func(encoded []byte) error {
		signed, err := entitlement.DecodeUpgradePlanArtifactBundle(encoded)
		if err != nil {
			return controlplaneupgrade.ErrInvalidPlan
		}
		bundle, err := trust.VerifyUpgradePlanArtifactBundle(encoded,
			entitlement.UpgradePlanArtifactBundleVerifyOptions{Now: now(),
				ExpectedAudience:       entitlement.UpgradePlanArtifactBundleAudience,
				ExpectedInstallationID: installationID, ExpectedPlanID: signed.Bundle.PlanID,
				ExpectedInitialPlanRevision: 1})
		if err != nil || bundle.Component != "control-api" || bundle.CurrentVersion != currentVersion ||
			bundle.ProtocolVersion != protocolVersion || bundle.Rollback.Manifest.Version != currentVersion ||
			bundle.Forward.Manifest.Version != bundle.Version ||
			bundle.Forward.Manifest.ReleaseSequence <= bundle.Rollback.Manifest.ReleaseSequence {
			return controlplaneupgrade.ErrInvalidPlan
		}
		return nil
	}
}

func openExecutor(target controlplaneupgrade.Target, installationID string) (controlplaneupgrade.Executor, error) {
	protocolVersion, err := integerEnv("CONTROL_UPGRADE_PROTOCOL_VERSION", 1)
	if err != nil {
		return nil, err
	}
	internalToken, err := readRequiredFile("CONTROL_UPGRADE_INTERNAL_TOKEN_FILE", 256)
	if err != nil || len(internalToken) < 32 {
		return nil, fmt.Errorf("CONTROL_UPGRADE_INTERNAL_TOKEN_FILE is invalid")
	}
	stepTimeout, err := durationEnv("CONTROL_UPGRADE_STEP_TIMEOUT", 3*time.Minute)
	if err != nil {
		return nil, err
	}
	healthTimeout, err := durationEnv("CONTROL_UPGRADE_HEALTH_TIMEOUT", 10*time.Minute)
	if err != nil {
		return nil, err
	}
	switch target {
	case controlplaneupgrade.TargetKubernetes:
		imagePullSecrets, err := imagePullSecretsEnv("CONTROL_UPGRADE_IMAGE_PULL_SECRETS_JSON")
		if err != nil {
			return nil, err
		}
		return controlplaneupgrade.NewKubernetesExecutor(controlplaneupgrade.KubernetesConfig{
			APIServer:         requiredEnv("CONTROL_UPGRADE_KUBERNETES_API"),
			Namespace:         requiredEnv("CONTROL_UPGRADE_KUBERNETES_NAMESPACE"),
			Deployment:        requiredEnv("CONTROL_UPGRADE_KUBERNETES_DEPLOYMENT"),
			Container:         requiredEnv("CONTROL_UPGRADE_KUBERNETES_CONTAINER"),
			ImageRepository:   requiredEnv("CONTROL_UPGRADE_IMAGE_REPOSITORY"),
			ServiceAccount:    requiredEnv("CONTROL_UPGRADE_SERVICE_ACCOUNT"),
			DatabaseSecret:    requiredEnv("CONTROL_UPGRADE_DATABASE_SECRET"),
			DatabaseSecretKey: requiredEnv("CONTROL_UPGRADE_DATABASE_SECRET_KEY"),
			InstallationID:    installationID, ProtocolVersion: protocolVersion,
			InternalURL:      requiredEnv("CONTROL_UPGRADE_INTERNAL_URL"),
			InternalToken:    internalToken,
			TokenFile:        requiredEnv("CONTROL_UPGRADE_KUBERNETES_TOKEN_FILE"),
			CAFile:           requiredEnv("CONTROL_UPGRADE_KUBERNETES_CA_FILE"),
			PollInterval:     time.Second,
			StepTimeout:      stepTimeout,
			HealthTimeout:    healthTimeout,
			ImagePullSecrets: imagePullSecrets,
		})
	case controlplaneupgrade.TargetSystemd:
		return controlplaneupgrade.NewSystemdExecutor(controlplaneupgrade.SystemdConfig{
			ReleaseRoot: requiredEnv("CONTROL_UPGRADE_RELEASE_ROOT"),
			CurrentLink: requiredEnv("CONTROL_UPGRADE_CURRENT_LINK"),
			UnitName:    requiredEnv("CONTROL_UPGRADE_SYSTEMD_UNIT"),
			DrainURL:    requiredEnv("CONTROL_UPGRADE_DRAIN_URL"), ResumeURL: requiredEnv("CONTROL_UPGRADE_RESUME_URL"),
			HealthURL: requiredEnv("CONTROL_UPGRADE_HEALTH_URL"), InstallationID: installationID,
			CurrentVersion: requiredEnv("CONTROL_UPGRADE_CURRENT_VERSION"), ProtocolVersion: protocolVersion,
			InternalToken: internalToken,
			PollInterval:  time.Second,
			StepTimeout:   stepTimeout,
			HealthTimeout: healthTimeout,
		})
	default:
		return nil, controlplaneupgrade.ErrInvalidConfig
	}
}

func readRequiredFile(environment string, limit int64) (string, error) {
	encoded, err := readRequiredBytes(environment, limit)
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(encoded))
	if value == "" {
		return "", fmt.Errorf("%s is empty", environment)
	}
	return value, nil
}

func readRequiredBytes(environment string, limit int64) ([]byte, error) {
	path := requiredEnv(environment)
	if path == "" || !filepath.IsAbs(path) {
		return nil, fmt.Errorf("%s is required", environment)
	}
	parent := filepath.Dir(filepath.Clean(path))
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || parentInfo.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("%s parent must be a trusted directory", environment)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, fmt.Errorf("%s cannot be resolved", environment)
	}
	relative, err := filepath.Rel(parent, resolved)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("%s resolves outside its trusted directory", environment)
	}
	info, err := os.Lstat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit {
		return nil, fmt.Errorf("%s must name a bounded regular file", environment)
	}
	encoded, err := readStableRegularFile(resolved, info, limit)
	if err != nil {
		return nil, fmt.Errorf("%s must remain a stable regular file", environment)
	}
	return encoded, nil
}

func requiredEnv(name string) string { return strings.TrimSpace(os.Getenv(name)) }

func durationEnv(name string, fallback time.Duration) (time.Duration, error) {
	value := requiredEnv(name)
	if value == "" {
		return fallback, nil
	}
	result, err := time.ParseDuration(value)
	if err != nil || result <= 0 || result > time.Hour {
		return 0, fmt.Errorf("%s is invalid", name)
	}
	return result, nil
}

func imagePullSecretsEnv(name string) ([]string, error) {
	value := requiredEnv(name)
	if value == "" {
		value = "[]"
	}
	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.DisallowUnknownFields()
	var references []struct {
		Name string `json:"name"`
	}
	if decoder.Decode(&references) != nil || decoder.Decode(&struct{}{}) != io.EOF || len(references) > 32 {
		return nil, fmt.Errorf("%s is invalid", name)
	}
	result := make([]string, 0, len(references))
	for _, reference := range references {
		if strings.TrimSpace(reference.Name) == "" {
			return nil, fmt.Errorf("%s is invalid", name)
		}
		result = append(result, reference.Name)
	}
	return result, nil
}

func integerEnv(name string, minimum int) (int, error) {
	value := requiredEnv(name)
	result, err := strconv.Atoi(value)
	if err != nil || result < minimum {
		return 0, fmt.Errorf("%s is invalid", name)
	}
	return result, nil
}
