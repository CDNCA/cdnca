package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/controlupgrade"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/platformpolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

const (
	controlUpgradeEnabledEnv                      = "CONTROL_UPGRADE_RUNTIME_ENABLED"
	controlUpgradeNATSNameEnv                     = "CONTROL_UPGRADE_NATS_NAME"
	controlUpgradeWorkerIDEnv                     = "CONTROL_UPGRADE_WORKER_ID"
	controlUpgradeCommandGrantTrustFileEnv        = "CONTROL_UPGRADE_COMMAND_GRANT_TRUST_FILE"
	controlUpgradeControlSigningKeyIDEnv          = "CONTROL_UPGRADE_CONTROL_SIGNING_KEY_ID"
	controlUpgradeControlSigningPrivateKeyFileEnv = "CONTROL_UPGRADE_CONTROL_SIGNING_PRIVATE_KEY_FILE"
	controlUpgradeEdgeSigningKeyIDEnv             = "CONTROL_UPGRADE_EDGE_SIGNING_KEY_ID"
	controlUpgradeEdgeSigningPrivateKeyFileEnv    = "CONTROL_UPGRADE_EDGE_SIGNING_PRIVATE_KEY_FILE"
	controlUpgradeCommandIssuanceTTLEnv           = "CONTROL_UPGRADE_COMMAND_ISSUANCE_TTL"
	controlUpgradeExecutionTTLEnv                 = "CONTROL_UPGRADE_EXECUTION_TTL"
	controlUpgradeActivationTimeoutEnv            = "CONTROL_UPGRADE_ACTIVATION_TIMEOUT"
	controlUpgradeObservationWindowEnv            = "CONTROL_UPGRADE_OBSERVATION_WINDOW"
	controlUpgradeHealthIntervalEnv               = "CONTROL_UPGRADE_HEALTH_INTERVAL"
	controlUpgradeProbeTimeoutEnv                 = "CONTROL_UPGRADE_PROBE_TIMEOUT"
	controlUpgradeRequiredSuccessesEnv            = "CONTROL_UPGRADE_REQUIRED_CONSECUTIVE_SUCCESSES"
	controlUpgradeNATSConnectTimeoutEnv           = "CONTROL_UPGRADE_NATS_CONNECT_TIMEOUT"
	controlUpgradeNATSReconnectWaitEnv            = "CONTROL_UPGRADE_NATS_RECONNECT_WAIT"
	controlUpgradeNATSDrainTimeoutEnv             = "CONTROL_UPGRADE_NATS_DRAIN_TIMEOUT"
	controlUpgradeShutdownTimeoutEnv              = "CONTROL_UPGRADE_SHUTDOWN_TIMEOUT"
	controlUpgradeArtifactCacheDirEnv             = "CONTROL_UPGRADE_ARTIFACT_CACHE_DIR"
	controlUpgradeArtifactBaseURLEnv              = "CONTROL_UPGRADE_ARTIFACT_BASE_URL"
	// Optional: the private root that verifies the artifact base URL, signed
	// into executions with the current addresses (fix-btenv3). Unset: "system".
	controlUpgradeDownloadRootCAFileEnv = "CONTROL_UPGRADE_DOWNLOAD_ROOT_CA_FILE"

	controlUpgradeCommandStream      = "AGENT_COMMANDS"
	controlUpgradeStatusStream       = "AGENT_DEPLOYMENT_STATUS"
	controlUpgradeCommandSubject     = "cdnca.agent.commands.upgrade"
	controlUpgradeStatusSubject      = "cdnca.agent.deployment-status.upgrade"
	controlUpgradeStatusV2Subject    = "cdnca.agent.deployment-status.upgrade-v2"
	controlUpgradeMaxPrivateKeyBytes = 16 << 10
	controlUpgradeMaxTrustBytes      = 1 << 20
	controlUpgradeMaxCommandBytes    = 1 << 20
	controlUpgradeMaxStatusBytes     = 256 << 10
	controlUpgradeIdlePoll           = 250 * time.Millisecond
	controlUpgradeTransientBackoff   = 500 * time.Millisecond
	controlUpgradeOutboxClaimLease   = 30 * time.Second
	controlUpgradeOutboxClaimBatch   = 32
	controlUpgradeReceiptClaimBatch  = 1
)

var (
	controlUpgradeRuntimeEnvironment = []string{
		controlUpgradeEnabledEnv,
		controlUpgradeNATSNameEnv,
		controlUpgradeWorkerIDEnv,
		controlUpgradeCommandGrantTrustFileEnv,
		controlUpgradeControlSigningKeyIDEnv,
		controlUpgradeControlSigningPrivateKeyFileEnv,
		controlUpgradeEdgeSigningKeyIDEnv,
		controlUpgradeEdgeSigningPrivateKeyFileEnv,
		controlUpgradeControlSignerProviderEnv,
		controlUpgradeControlSigningPublicKeyFileEnv,
		controlUpgradeControlSignerRemoteEndpointEnv,
		controlUpgradeControlSignerRemoteCAFileEnv,
		controlUpgradeControlSignerRemoteBearerTokenFileEnv,
		controlUpgradeControlSignerRemoteTimeoutEnv,
		controlUpgradeEdgeSignerProviderEnv,
		controlUpgradeEdgeSigningPublicKeyFileEnv,
		controlUpgradeEdgeSignerRemoteEndpointEnv,
		controlUpgradeEdgeSignerRemoteCAFileEnv,
		controlUpgradeEdgeSignerRemoteBearerTokenFileEnv,
		controlUpgradeEdgeSignerRemoteTimeoutEnv,
		controlUpgradeCommandIssuanceTTLEnv,
		controlUpgradeExecutionTTLEnv,
		controlUpgradeActivationTimeoutEnv,
		controlUpgradeObservationWindowEnv,
		controlUpgradeHealthIntervalEnv,
		controlUpgradeProbeTimeoutEnv,
		controlUpgradeRequiredSuccessesEnv,
		controlUpgradeNATSConnectTimeoutEnv,
		controlUpgradeNATSReconnectWaitEnv,
		controlUpgradeNATSDrainTimeoutEnv,
		controlUpgradeShutdownTimeoutEnv,
		controlUpgradeArtifactCacheDirEnv,
		controlUpgradeArtifactBaseURLEnv,
		controlUpgradeDownloadRootCAFileEnv,
	}
	controlUpgradeRuntimeRequiredEnvironment = []string{
		controlUpgradeEnabledEnv,
		controlUpgradeNATSNameEnv,
		controlUpgradeWorkerIDEnv,
		controlUpgradeCommandGrantTrustFileEnv,
		controlUpgradeControlSigningKeyIDEnv,
		controlUpgradeEdgeSigningKeyIDEnv,
		controlUpgradeCommandIssuanceTTLEnv,
		controlUpgradeExecutionTTLEnv,
		controlUpgradeActivationTimeoutEnv,
		controlUpgradeObservationWindowEnv,
		controlUpgradeHealthIntervalEnv,
		controlUpgradeProbeTimeoutEnv,
		controlUpgradeRequiredSuccessesEnv,
		controlUpgradeNATSConnectTimeoutEnv,
		controlUpgradeNATSReconnectWaitEnv,
		controlUpgradeNATSDrainTimeoutEnv,
		controlUpgradeShutdownTimeoutEnv,
		controlUpgradeArtifactCacheDirEnv,
		controlUpgradeArtifactBaseURLEnv,
	}
	controlUpgradeRuntimeNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

type controlUpgradeRuntimeConfig struct {
	Enabled                      bool
	NATSName                     string
	WorkerID                     string
	CommandGrantTrustFile        string
	ControlSigningKeyID          string
	ControlSigningPrivateKeyFile string
	EdgeSigningKeyID             string
	EdgeSigningPrivateKeyFile    string
	CommandIssuanceTTL           time.Duration
	ExecutionTTL                 time.Duration
	ActivationTimeout            time.Duration
	ObservationWindow            time.Duration
	HealthInterval               time.Duration
	ProbeTimeout                 time.Duration
	RequiredConsecutiveSuccesses int
	NATSConnectTimeout           time.Duration
	NATSReconnectWait            time.Duration
	NATSDrainTimeout             time.Duration
	ShutdownTimeout              time.Duration
	ArtifactCacheDir             string
	ArtifactBaseURL              string
	DownloadRootCAFile           string
	ControlSigner                controlUpgradeSignerProviderConfig
	EdgeSigner                   controlUpgradeSignerProviderConfig
}

type controlUpgradeEd25519Signer struct {
	keyID      string
	privateKey ed25519.PrivateKey
}

type controlUpgradeProductionRuntime struct {
	connection          *nats.Conn
	dispatcher          *controlupgrade.OutboxDispatcher
	receiptDispatcher   *controlupgrade.LicenseReceiptDispatcher
	status              *controlupgrade.StatusProcessor
	license             *controlupgrade.LicenseClient
	controlSigner       controlUpgradeSigningProvider
	edgeSigner          controlUpgradeSigningProvider
	closed              <-chan struct{}
	shutdownTimeout     time.Duration
	running             atomic.Bool
	closeOnce           sync.Once
	closeErr            error
	healthMu            sync.RWMutex
	dispatchErr         error
	receiptErr          error
	receiptFailed       bool
	receiptHealthLoaded bool
	statusErr           error
}

func loadControlUpgradeRuntimeConfig() (controlUpgradeRuntimeConfig, error) {
	return loadControlUpgradeRuntimeConfigFromEnv(os.Environ())
}

func loadControlUpgradeRuntimeConfigFromEnv(environment []string) (controlUpgradeRuntimeConfig, error) {
	known := make(map[string]struct{}, len(controlUpgradeRuntimeEnvironment))
	for _, name := range controlUpgradeRuntimeEnvironment {
		known[name] = struct{}{}
	}
	values := make(map[string]string, len(known))
	counts := make(map[string]int, len(known))
	unknown := false
	for _, entry := range environment {
		name, value, found := strings.Cut(entry, "=")
		if !found || !strings.HasPrefix(name, "CONTROL_UPGRADE_") {
			continue
		}
		// These exact settings are validated by the sibling control-plane upgrade runtimes.
		switch name {
		case controlUpgradePlanEnabledEnv, controlUpgradePlanTokenFileEnv,
			"CONTROL_UPGRADE_PLAN_WRITER_ENABLED", "CONTROL_UPGRADE_EXPECTED_REPLICAS",
			"CONTROL_UPGRADE_QUORUM", "CONTROL_UPGRADE_PROTOCOL_VERSION",
			"CONTROL_UPGRADE_KUBERNETES_API", "CONTROL_UPGRADE_KUBERNETES_NAMESPACE",
			"CONTROL_UPGRADE_PLAN_SECRET", "CONTROL_UPGRADE_PLAN_SECRET_KEY",
			"CONTROL_UPGRADE_STATE_SECRET_KEY", "CONTROL_UPGRADE_KUBERNETES_TOKEN_FILE",
			"CONTROL_UPGRADE_KUBERNETES_CA_FILE", "CONTROL_UPGRADE_REPLICA_ID":
			continue
		}
		if _, ok := known[name]; !ok {
			unknown = true
			continue
		}
		counts[name]++
		values[name] = value
	}
	if counts[controlUpgradeEnabledEnv] > 1 {
		return controlUpgradeRuntimeConfig{}, controlUpgradeConfigError(controlUpgradeEnabledEnv)
	}
	if values[controlUpgradeEnabledEnv] == "" || values[controlUpgradeEnabledEnv] == "false" {
		return controlUpgradeRuntimeConfig{}, nil
	}
	if values[controlUpgradeEnabledEnv] != "true" {
		return controlUpgradeRuntimeConfig{}, controlUpgradeConfigError(controlUpgradeEnabledEnv)
	}
	for _, name := range controlUpgradeRuntimeEnvironment {
		if counts[name] > 1 {
			return controlUpgradeRuntimeConfig{}, controlUpgradeConfigError(name)
		}
	}
	for _, name := range controlUpgradeRuntimeRequiredEnvironment {
		if counts[name] != 1 {
			return controlUpgradeRuntimeConfig{}, errors.New("control upgrade runtime settings must each be defined exactly once")
		}
	}
	if unknown {
		return controlUpgradeRuntimeConfig{}, errors.New("control upgrade runtime contains an unsupported environment setting")
	}

	config := controlUpgradeRuntimeConfig{Enabled: true}
	var err error
	config.NATSName, err = controlUpgradeRequired(values, controlUpgradeNATSNameEnv)
	if err != nil {
		return controlUpgradeRuntimeConfig{}, err
	}
	config.WorkerID, err = controlUpgradeRequired(values, controlUpgradeWorkerIDEnv)
	if err != nil {
		return controlUpgradeRuntimeConfig{}, err
	}
	config.CommandGrantTrustFile, err = controlUpgradeRequired(values, controlUpgradeCommandGrantTrustFileEnv)
	if err != nil {
		return controlUpgradeRuntimeConfig{}, err
	}
	config.ControlSigningKeyID, err = controlUpgradeRequired(values, controlUpgradeControlSigningKeyIDEnv)
	if err != nil {
		return controlUpgradeRuntimeConfig{}, err
	}
	if counts[controlUpgradeControlSigningPrivateKeyFileEnv] == 1 {
		config.ControlSigningPrivateKeyFile = values[controlUpgradeControlSigningPrivateKeyFileEnv]
	}
	config.EdgeSigningKeyID, err = controlUpgradeRequired(values, controlUpgradeEdgeSigningKeyIDEnv)
	if err != nil {
		return controlUpgradeRuntimeConfig{}, err
	}
	if counts[controlUpgradeEdgeSigningPrivateKeyFileEnv] == 1 {
		config.EdgeSigningPrivateKeyFile = values[controlUpgradeEdgeSigningPrivateKeyFileEnv]
	}
	if !controlUpgradeRuntimeNamePattern.MatchString(config.NATSName) ||
		!controlUpgradeRuntimeNamePattern.MatchString(config.WorkerID) ||
		entitlement.ValidateKeyID(config.ControlSigningKeyID) != nil ||
		entitlement.ValidateKeyID(config.EdgeSigningKeyID) != nil ||
		config.ControlSigningKeyID == config.EdgeSigningKeyID {
		return controlUpgradeRuntimeConfig{}, errors.New("control upgrade runtime identity is invalid")
	}
	if err := controlUpgradeValidateFile(config.CommandGrantTrustFile, controlUpgradeMaxTrustBytes, false); err != nil {
		return controlUpgradeRuntimeConfig{}, controlUpgradeConfigError(controlUpgradeCommandGrantTrustFileEnv)
	}
	config.ControlSigner, err = controlUpgradeLoadSignerProviderConfig(values, counts,
		controlUpgradeSignerProviderEnvironment{
			Provider: controlUpgradeControlSignerProviderEnv, PrivateKey: controlUpgradeControlSigningPrivateKeyFileEnv,
			PublicKey: controlUpgradeControlSigningPublicKeyFileEnv, Endpoint: controlUpgradeControlSignerRemoteEndpointEnv,
			CAFile: controlUpgradeControlSignerRemoteCAFileEnv, BearerToken: controlUpgradeControlSignerRemoteBearerTokenFileEnv,
			Timeout: controlUpgradeControlSignerRemoteTimeoutEnv,
		}, config.ControlSigningKeyID)
	if err != nil {
		return controlUpgradeRuntimeConfig{}, err
	}
	config.EdgeSigner, err = controlUpgradeLoadSignerProviderConfig(values, counts,
		controlUpgradeSignerProviderEnvironment{
			Provider: controlUpgradeEdgeSignerProviderEnv, PrivateKey: controlUpgradeEdgeSigningPrivateKeyFileEnv,
			PublicKey: controlUpgradeEdgeSigningPublicKeyFileEnv, Endpoint: controlUpgradeEdgeSignerRemoteEndpointEnv,
			CAFile: controlUpgradeEdgeSignerRemoteCAFileEnv, BearerToken: controlUpgradeEdgeSignerRemoteBearerTokenFileEnv,
			Timeout: controlUpgradeEdgeSignerRemoteTimeoutEnv,
		}, config.EdgeSigningKeyID)
	if err != nil {
		return controlUpgradeRuntimeConfig{}, err
	}
	if config.ControlSigner.Provider == controlUpgradeSignerProviderFile && config.EdgeSigner.Provider == controlUpgradeSignerProviderFile {
		controlInfo, _ := os.Lstat(config.ControlSigner.PrivateKeyFile)
		edgeInfo, _ := os.Lstat(config.EdgeSigner.PrivateKeyFile)
		if os.SameFile(controlInfo, edgeInfo) {
			return controlUpgradeRuntimeConfig{}, errors.New("control upgrade signing domains require different private key files")
		}
	}

	if config.CommandIssuanceTTL, err = controlUpgradeDuration(values, controlUpgradeCommandIssuanceTTLEnv,
		time.Minute, 7*24*time.Hour); err != nil {
		return controlUpgradeRuntimeConfig{}, err
	}
	if config.ExecutionTTL, err = controlUpgradeDuration(values, controlUpgradeExecutionTTLEnv,
		time.Minute, 24*time.Hour); err != nil {
		return controlUpgradeRuntimeConfig{}, err
	}
	if config.ActivationTimeout, err = controlUpgradeDuration(values, controlUpgradeActivationTimeoutEnv,
		time.Second, 30*time.Minute); err != nil {
		return controlUpgradeRuntimeConfig{}, err
	}
	if config.ObservationWindow, err = controlUpgradeDuration(values, controlUpgradeObservationWindowEnv,
		time.Second, 30*time.Minute); err != nil {
		return controlUpgradeRuntimeConfig{}, err
	}
	if config.HealthInterval, err = controlUpgradeDuration(values, controlUpgradeHealthIntervalEnv,
		time.Second, 30*time.Minute); err != nil {
		return controlUpgradeRuntimeConfig{}, err
	}
	if config.ProbeTimeout, err = controlUpgradeDuration(values, controlUpgradeProbeTimeoutEnv,
		time.Second, 30*time.Minute); err != nil {
		return controlUpgradeRuntimeConfig{}, err
	}
	if config.RequiredConsecutiveSuccesses, err = controlUpgradeInteger(values,
		controlUpgradeRequiredSuccessesEnv, 1, 100); err != nil {
		return controlUpgradeRuntimeConfig{}, err
	}
	if config.NATSConnectTimeout, err = controlUpgradeDuration(values, controlUpgradeNATSConnectTimeoutEnv,
		100*time.Millisecond, 30*time.Second); err != nil {
		return controlUpgradeRuntimeConfig{}, err
	}
	if config.NATSReconnectWait, err = controlUpgradeDuration(values, controlUpgradeNATSReconnectWaitEnv,
		100*time.Millisecond, 30*time.Second); err != nil {
		return controlUpgradeRuntimeConfig{}, err
	}
	if config.NATSDrainTimeout, err = controlUpgradeDuration(values, controlUpgradeNATSDrainTimeoutEnv,
		time.Second, 5*time.Minute); err != nil {
		return controlUpgradeRuntimeConfig{}, err
	}
	if config.ShutdownTimeout, err = controlUpgradeDuration(values, controlUpgradeShutdownTimeoutEnv,
		time.Second, 5*time.Minute); err != nil {
		return controlUpgradeRuntimeConfig{}, err
	}
	if config.ArtifactCacheDir, err = controlUpgradeRequired(values, controlUpgradeArtifactCacheDirEnv); err != nil {
		return controlUpgradeRuntimeConfig{}, err
	}
	if config.ArtifactBaseURL, err = controlUpgradeRequired(values, controlUpgradeArtifactBaseURLEnv); err != nil {
		return controlUpgradeRuntimeConfig{}, err
	}
	if !filepath.IsAbs(config.ArtifactCacheDir) || filepath.Clean(config.ArtifactCacheDir) != config.ArtifactCacheDir ||
		config.ArtifactCacheDir == string(filepath.Separator) {
		return controlUpgradeRuntimeConfig{}, controlUpgradeConfigError(controlUpgradeArtifactCacheDirEnv)
	}
	if parsed, parseErr := url.Parse(config.ArtifactBaseURL); parseErr != nil || parsed.Scheme != "https" ||
		parsed.Host == "" || parsed.Host != strings.ToLower(parsed.Host) || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || strings.HasSuffix(config.ArtifactBaseURL, "/") ||
		parsed.String() != config.ArtifactBaseURL {
		return controlUpgradeRuntimeConfig{}, controlUpgradeConfigError(controlUpgradeArtifactBaseURLEnv)
	}
	if root, ok := values[controlUpgradeDownloadRootCAFileEnv]; ok {
		if !filepath.IsAbs(root) || filepath.Clean(root) != root {
			return controlUpgradeRuntimeConfig{}, controlUpgradeConfigError(controlUpgradeDownloadRootCAFileEnv)
		}
		config.DownloadRootCAFile = root
	}
	if config.ExecutionTTL > config.CommandIssuanceTTL ||
		config.HealthInterval > config.ObservationWindow ||
		config.HealthInterval > config.ActivationTimeout ||
		config.ProbeTimeout > config.ActivationTimeout ||
		config.ShutdownTimeout < config.NATSDrainTimeout {
		return controlUpgradeRuntimeConfig{}, errors.New("control upgrade runtime timing bounds are unsafe")
	}
	return config, nil
}

func controlUpgradeRequired(values map[string]string, name string) (string, error) {
	value := values[name]
	if value == "" || strings.TrimSpace(value) != value {
		return "", controlUpgradeConfigError(name)
	}
	return value, nil
}

func controlUpgradeDuration(values map[string]string, name string,
	minimum, maximum time.Duration) (time.Duration, error) {
	raw, err := controlUpgradeRequired(values, name)
	if err != nil {
		return 0, err
	}
	value, err := time.ParseDuration(raw)
	if err != nil || value < minimum || value > maximum {
		return 0, controlUpgradeConfigError(name)
	}
	return value, nil
}

func controlUpgradeInteger(values map[string]string, name string, minimum, maximum int) (int, error) {
	raw, err := controlUpgradeRequired(values, name)
	if err != nil {
		return 0, err
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < minimum || value > maximum || strconv.Itoa(value) != raw {
		return 0, controlUpgradeConfigError(name)
	}
	return value, nil
}

func controlUpgradeConfigError(name string) error {
	return fmt.Errorf("%s is invalid", name)
}

func controlUpgradeValidateFile(path string, maximum int64, secret bool) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("file path must be absolute and canonical")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Size() < 1 || info.Size() > maximum || secret && info.Mode().Perm()&0o077 != 0 ||
		!secret && info.Mode().Perm()&0o022 != 0 {
		return errors.New("file is not an acceptable regular file")
	}
	return nil
}

func controlUpgradeReadFile(path string, maximum int64, secret bool) ([]byte, error) {
	if err := controlUpgradeValidateFile(path, maximum, secret); err != nil {
		return nil, err
	}
	before, _ := os.Lstat(path)
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, statErr := file.Stat()
	after, lstatErr := os.Lstat(path)
	if statErr != nil || lstatErr != nil || after.Mode()&os.ModeSymlink != 0 ||
		!opened.Mode().IsRegular() || !os.SameFile(before, opened) || !os.SameFile(opened, after) {
		return nil, errors.New("file identity changed while opening")
	}
	encoded, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(encoded) == 0 || int64(len(encoded)) > maximum {
		clear(encoded)
		return nil, errors.New("file content is unavailable")
	}
	return encoded, nil
}

func controlUpgradeLoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	encoded, err := controlUpgradeReadFile(path, controlUpgradeMaxPrivateKeyBytes, true)
	if err != nil {
		return nil, err
	}
	defer clear(encoded)
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("control upgrade private key must be one PKCS#8 PEM block")
	}
	defer clear(block.Bytes)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if err != nil || !ok || len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("control upgrade private key must be Ed25519")
	}
	result := append(ed25519.PrivateKey(nil), privateKey...)
	clear(privateKey)
	return result, nil
}

func controlUpgradeLoadTrust(path string) (*entitlement.KeyRing, error) {
	encoded, err := controlUpgradeReadFile(path, controlUpgradeMaxTrustBytes, false)
	if err != nil {
		return nil, err
	}
	defer clear(encoded)
	trust, err := entitlementguard.DecodeTrustedKeys(encoded)
	if err != nil {
		return nil, err
	}
	ring := entitlement.NewKeyRing()
	keys := trust.PinnedKeys()
	if len(keys) == 0 {
		return nil, errors.New("control upgrade command grant trust is empty")
	}
	for _, key := range keys {
		if err := ring.Add(key.KeyID, key.PublicKey); err != nil {
			return nil, err
		}
	}
	return ring, nil
}

func (signer *controlUpgradeEd25519Signer) KeyID() string {
	if signer == nil {
		return ""
	}
	return signer.keyID
}

func (signer *controlUpgradeEd25519Signer) Sign(ctx context.Context, payload []byte) ([]byte, error) {
	if signer == nil || ctx == nil || ctx.Err() != nil || len(signer.privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("control upgrade signer is unavailable")
	}
	return ed25519.Sign(signer.privateKey, payload), nil
}

func (signer *controlUpgradeEd25519Signer) close() {
	if signer == nil {
		return
	}
	clear(signer.privateKey)
	signer.privateKey = nil
}

func (signer *controlUpgradeEd25519Signer) PublicKey() ed25519.PublicKey {
	if signer == nil || len(signer.privateKey) != ed25519.PrivateKeySize {
		return nil
	}
	return append(ed25519.PublicKey(nil), signer.privateKey.Public().(ed25519.PublicKey)...)
}

func (signer *controlUpgradeEd25519Signer) Close() {
	signer.close()
}

func openControlUpgradeProductionRuntime(ctx context.Context, cfg config.Config,
	runtimeConfig controlUpgradeRuntimeConfig, pool *pgxpool.Pool, trust *entitlementguard.TrustStore,
	policy *platformpolicy.State, connect natsConnector) (_ *controlUpgradeProductionRuntime,
	_ *controlupgrade.Service, returnedErr error) {
	if !runtimeConfig.Enabled {
		return nil, nil, nil
	}
	if ctx == nil || ctx.Err() != nil || pool == nil || trust == nil || policy == nil || connect == nil ||
		cfg.EdgeDeploymentNATSURL == "" || cfg.LicenseServiceURL == "" {
		return nil, nil, errors.New("control upgrade production dependencies are incomplete")
	}
	installationID, err := uuid.Parse(cfg.ControlInstallationID)
	if err != nil || installationID == uuid.Nil || installationID.String() != cfg.ControlInstallationID {
		return nil, nil, errors.New("CONTROL_INSTALLATION_ID must be a canonical UUID")
	}
	if err := controlUpgradeValidateFile(cfg.ControlInstallationKeyFile, controlUpgradeMaxPrivateKeyBytes, true); err != nil {
		return nil, nil, errors.New("CONTROL_INSTALLATION_PRIVATE_KEY_FILE is invalid")
	}

	commandKeys, err := controlUpgradeLoadTrust(runtimeConfig.CommandGrantTrustFile)
	if err != nil {
		return nil, nil, fmt.Errorf("load control upgrade command grant trust: %w", err)
	}
	installationKey, err := controlUpgradeLoadPrivateKey(cfg.ControlInstallationKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("load control upgrade installation key: %w", err)
	}
	defer clear(installationKey)
	controlSigner, err := openControlUpgradeSigningProvider(runtimeConfig.ControlSigner)
	if err != nil {
		return nil, nil, fmt.Errorf("load control upgrade control signing provider: %w", err)
	}
	edgeSigner, err := openControlUpgradeSigningProvider(runtimeConfig.EdgeSigner)
	if err != nil {
		controlSigner.Close()
		return nil, nil, fmt.Errorf("load control upgrade edge signing provider: %w", err)
	}
	controlPublicKey, edgePublicKey := controlSigner.PublicKey(), edgeSigner.PublicKey()
	if len(controlPublicKey) != ed25519.PublicKeySize || len(edgePublicKey) != ed25519.PublicKeySize ||
		bytes.Equal(controlPublicKey, edgePublicKey) {
		clear(controlPublicKey)
		clear(edgePublicKey)
		controlSigner.Close()
		edgeSigner.Close()
		return nil, nil, errors.New("control and edge upgrade signing keys must be distinct")
	}
	clear(controlPublicKey)
	clear(edgePublicKey)

	license, err := controlupgrade.NewLicenseClient(cfg.LicenseServiceURL,
		&http.Client{Timeout: runtimeConfig.NATSConnectTimeout}, installationID, installationKey, time.Now)
	if err != nil {
		controlSigner.Close()
		edgeSigner.Close()
		return nil, nil, err
	}
	cleanupSecrets := true
	defer func() {
		if cleanupSecrets {
			license.Close()
			controlSigner.Close()
			edgeSigner.Close()
		}
	}()

	// The license origin is the artifact source; its integrity is pinned by the
	// license-signed manifest digest, so the system trust store suffices here.
	artifacts, err := controlupgrade.NewArtifactCache(runtimeConfig.ArtifactCacheDir, runtimeConfig.ArtifactBaseURL,
		&http.Client{Timeout: 10 * time.Minute})
	if err != nil {
		return nil, nil, fmt.Errorf("configure control upgrade artifact cache: %w", err)
	}
	rolloutRuntime, err := controlupgrade.NewRolloutRuntime(controlupgrade.RolloutRuntimeConfig{
		License: license, LicenseKeys: commandKeys, CommandGrantKeys: commandKeys, SignerRevocation: trust,
		ControlSigner: controlSigner, EdgeSigner: edgeSigner, InstallationID: installationID,
		CommandIssuanceTTL: runtimeConfig.CommandIssuanceTTL, ExecutionTTL: runtimeConfig.ExecutionTTL,
		Profiles: controlupgrade.RolloutProfilePolicy{
			ActivationTimeout: runtimeConfig.ActivationTimeout, ObservationWindow: runtimeConfig.ObservationWindow,
			HealthInterval: runtimeConfig.HealthInterval, ProbeTimeout: runtimeConfig.ProbeTimeout,
			RequiredConsecutiveSuccesses: runtimeConfig.RequiredConsecutiveSuccesses,
		}, Artifacts: artifacts, Clock: time.Now,
		DownloadPolicy: controlupgrade.DownloadPolicySource{RootCAFile: runtimeConfig.DownloadRootCAFile}.Policy,
	})
	if err != nil {
		return nil, nil, err
	}
	service := controlupgrade.NewService(pool, trust, policy, time.Now)
	if err := service.ConfigureRolloutRuntime(rolloutRuntime); err != nil {
		return nil, nil, err
	}

	closed := make(chan struct{})
	var closedOnce sync.Once
	options := []nats.Option{
		nats.Name(runtimeConfig.NATSName), nats.Timeout(runtimeConfig.NATSConnectTimeout),
		nats.ReconnectWait(runtimeConfig.NATSReconnectWait), nats.MaxReconnects(-1),
		nats.DrainTimeout(runtimeConfig.NATSDrainTimeout),
		nats.ClosedHandler(func(*nats.Conn) { closedOnce.Do(func() { close(closed) }) }),
	}
	if cfg.EdgeDeploymentNATSCredsFile != "" {
		options = append(options, nats.UserCredentials(cfg.EdgeDeploymentNATSCredsFile),
			nats.RootCAs(cfg.EdgeDeploymentNATSCAFile))
	}
	connection, err := connect(cfg.EdgeDeploymentNATSURL, options...)
	if err != nil {
		return nil, nil, fmt.Errorf("connect control upgrade NATS: %w", err)
	}
	if connection == nil {
		return nil, nil, errors.New("connect control upgrade NATS returned no connection")
	}
	failedConnection := true
	defer func() {
		if failedConnection {
			connection.Close()
		}
	}()
	jetstream, err := connection.JetStream(nats.MaxWait(runtimeConfig.NATSConnectTimeout))
	if err != nil {
		return nil, nil, err
	}
	startupCtx, cancel := context.WithTimeout(ctx, runtimeConfig.NATSConnectTimeout)
	err = verifyControlUpgradeJetStream(startupCtx, jetstream)
	cancel()
	if err != nil {
		return nil, nil, err
	}
	commandBus, err := controlupgrade.NewCommandBus(jetstream, controlUpgradeCommandStream)
	if err != nil {
		return nil, nil, err
	}
	statusConfig := controlupgrade.DefaultStatusConsumerConfig()
	statusConsumer, err := controlupgrade.BindUpgradeStatusConsumer(jetstream, statusConfig)
	if err != nil {
		return nil, nil, err
	}
	failedStatus := true
	defer func() {
		if failedStatus {
			_ = statusConsumer.Close()
		}
	}()
	store := controlupgrade.NewStore(pool, entitlementguard.NewGuard(pool, time.Now, trust), policy, time.Now)
	dispatcher, err := controlupgrade.NewOutboxDispatcher(store, commandBus,
		controlupgrade.OutboxDispatcherConfig{WorkerID: runtimeConfig.WorkerID,
			ClaimLease: controlUpgradeOutboxClaimLease, ClaimBatch: controlUpgradeOutboxClaimBatch, Clock: time.Now})
	if err != nil {
		return nil, nil, err
	}
	receiptDispatcher, err := controlupgrade.NewLicenseReceiptDispatcher(store, license,
		controlupgrade.LicenseReceiptDispatcherConfig{WorkerID: runtimeConfig.WorkerID,
			ClaimLease: controlUpgradeOutboxClaimLease, ClaimBatch: controlUpgradeReceiptClaimBatch, Clock: time.Now})
	if err != nil {
		return nil, nil, err
	}
	receiptFailed, err := controlUpgradeLoadInitialReceiptHealth(ctx, receiptDispatcher)
	if err != nil {
		return nil, nil, fmt.Errorf("load persisted control upgrade License receipt health: %w", err)
	}
	if receiptFailed {
		return nil, nil, errors.New("persisted control upgrade License receipt failure blocks startup")
	}
	status, err := controlupgrade.NewStatusProcessor(service, statusConsumer, controlupgrade.DefaultStatusRuntimeConfig())
	if err != nil {
		return nil, nil, err
	}
	runtime := &controlUpgradeProductionRuntime{connection: connection, dispatcher: dispatcher,
		receiptDispatcher: receiptDispatcher, status: status,
		license: license, controlSigner: controlSigner, edgeSigner: edgeSigner, closed: closed,
		shutdownTimeout: runtimeConfig.ShutdownTimeout, receiptHealthLoaded: true}
	failedStatus = false
	failedConnection = false
	cleanupSecrets = false
	return runtime, service, nil
}

func controlUpgradeLoadInitialReceiptHealth(ctx context.Context,
	dispatcher *controlupgrade.LicenseReceiptDispatcher) (bool, error) {
	if ctx == nil || dispatcher == nil {
		return false, errors.New("control upgrade License receipt health is unavailable")
	}
	return dispatcher.HasFailed(ctx)
}

func verifyControlUpgradeJetStream(ctx context.Context, jetstream nats.JetStreamContext) error {
	if ctx == nil || jetstream == nil {
		return errors.New("control upgrade JetStream is unavailable")
	}
	if _, err := jetstream.AccountInfo(nats.Context(ctx)); err != nil {
		return err
	}
	for _, required := range []struct {
		stream   string
		prefix   string
		maxBytes int
	}{
		{controlUpgradeCommandStream, controlUpgradeCommandSubject, controlUpgradeMaxCommandBytes},
		{controlUpgradeStatusStream, controlUpgradeStatusSubject, controlUpgradeMaxStatusBytes},
		{controlUpgradeStatusStream, controlUpgradeStatusV2Subject, controlUpgradeMaxStatusBytes},
	} {
		info, err := jetstream.StreamInfo(required.stream, nats.Context(ctx))
		if err != nil || validateEdgeStreamInfo(info, required.prefix, required.maxBytes) != nil {
			return errors.New("required control upgrade JetStream resource is unavailable")
		}
	}
	return nil
}

func (runtime *controlUpgradeProductionRuntime) Run(ctx context.Context) error {
	if runtime == nil || ctx == nil || !runtime.running.CompareAndSwap(false, true) {
		return errors.New("control upgrade runtime is unavailable or already running")
	}
	defer runtime.running.Store(false)
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan error, 4)
	go func() { results <- runtime.runDispatcher(runCtx) }()
	go func() { results <- runtime.runReceiptDispatcher(runCtx) }()
	go func() { results <- runtime.runStatus(runCtx) }()
	go func() {
		select {
		case <-runCtx.Done():
			results <- runCtx.Err()
		case <-runtime.closed:
			results <- errors.New("control upgrade NATS connection closed")
		}
	}()
	first := <-results
	cancel()
	for remaining := 3; remaining > 0; remaining-- {
		<-results
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if first == nil || errors.Is(first, context.Canceled) {
		return errors.New("control upgrade runtime stopped unexpectedly")
	}
	return first
}

func (runtime *controlUpgradeProductionRuntime) runReceiptDispatcher(ctx context.Context) error {
	for {
		count, dispatchErr := runtime.receiptDispatcher.DispatchOnce(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		failed, healthErr := runtime.receiptDispatcher.HasFailed(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		runtime.setReceiptError(errors.Join(dispatchErr, healthErr), failed)
		delay := controlUpgradeIdlePoll
		if dispatchErr != nil || healthErr != nil {
			delay = controlUpgradeTransientBackoff
		} else if count > 0 {
			continue
		}
		if !controlUpgradeWait(ctx, delay) {
			return ctx.Err()
		}
	}
}

func (runtime *controlUpgradeProductionRuntime) runDispatcher(ctx context.Context) error {
	for {
		count, err := runtime.dispatcher.DispatchOnce(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		runtime.setDispatchError(err)
		delay := controlUpgradeIdlePoll
		if err != nil {
			delay = controlUpgradeTransientBackoff
		} else if count > 0 {
			continue
		}
		if !controlUpgradeWait(ctx, delay) {
			return ctx.Err()
		}
	}
}

func (runtime *controlUpgradeProductionRuntime) runStatus(ctx context.Context) error {
	for {
		disposition, err := runtime.status.ProcessOnce(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(err, nats.ErrTimeout) || errors.Is(err, context.DeadlineExceeded) {
			runtime.setStatusError(nil)
			continue
		}
		runtime.setStatusError(err)
		if err == nil {
			continue
		}
		if disposition != controlupgrade.StatusDispositionNak &&
			disposition != controlupgrade.StatusDispositionAck &&
			disposition != controlupgrade.StatusDispositionTerm {
			return err
		}
		if !controlUpgradeWait(ctx, controlUpgradeTransientBackoff) {
			return ctx.Err()
		}
	}
}

func controlUpgradeWait(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (runtime *controlUpgradeProductionRuntime) setDispatchError(err error) {
	runtime.healthMu.Lock()
	runtime.dispatchErr = err
	runtime.healthMu.Unlock()
}

func (runtime *controlUpgradeProductionRuntime) setStatusError(err error) {
	runtime.healthMu.Lock()
	runtime.statusErr = err
	runtime.healthMu.Unlock()
}

func (runtime *controlUpgradeProductionRuntime) setReceiptError(err error, failed bool) {
	runtime.healthMu.Lock()
	runtime.receiptErr = err
	runtime.receiptFailed = runtime.receiptFailed || failed
	runtime.healthMu.Unlock()
}

func (runtime *controlUpgradeProductionRuntime) Ready() error {
	if runtime == nil || !runtime.receiptHealthLoaded || !runtime.running.Load() ||
		runtime.connection == nil || !runtime.connection.IsConnected() {
		return errors.New("control upgrade runtime is unavailable")
	}
	runtime.healthMu.RLock()
	defer runtime.healthMu.RUnlock()
	if runtime.dispatchErr != nil || runtime.receiptErr != nil || runtime.receiptFailed || runtime.statusErr != nil {
		return errors.New("control upgrade runtime worker is unhealthy")
	}
	return nil
}

func (runtime *controlUpgradeProductionRuntime) Close() error {
	if runtime == nil {
		return nil
	}
	runtime.closeOnce.Do(func() {
		if runtime.status != nil {
			runtime.closeErr = runtime.status.Close()
		}
		if runtime.connection != nil && !runtime.connection.IsClosed() {
			drained := make(chan error, 1)
			go func() { drained <- runtime.connection.Drain() }()
			timer := time.NewTimer(runtime.shutdownTimeout)
			select {
			case err := <-drained:
				if err != nil {
					runtime.closeErr = errors.Join(runtime.closeErr, err)
					runtime.connection.Close()
				}
			case <-timer.C:
				runtime.closeErr = errors.Join(runtime.closeErr,
					errors.New("control upgrade NATS drain timed out"))
				runtime.connection.Close()
			}
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		}
		runtime.license.Close()
		if runtime.controlSigner != nil {
			runtime.controlSigner.Close()
		}
		if runtime.edgeSigner != nil {
			runtime.edgeSigner.Close()
		}
	})
	return runtime.closeErr
}
