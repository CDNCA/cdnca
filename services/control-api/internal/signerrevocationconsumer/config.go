package signerrevocationconsumer

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/google/uuid"
)

const (
	consumerEnvPrefix      = "SIGNER_REVOCATION_CONSUMER_"
	defaultRefreshInterval = 5 * time.Minute
	defaultRequestTimeout  = 10 * time.Second
	defaultStartupTimeout  = 10 * time.Second
	defaultShutdownTimeout = 10 * time.Second
	maximumCAFileBytes     = 1 << 20
)

type Config struct {
	Enabled                    bool
	BaseURL                    string
	InstallationID             uuid.UUID
	InstallationPrivateKeyFile string
	RefreshInterval            time.Duration
	RequestTimeout             time.Duration
	StartupTimeout             time.Duration
	ShutdownTimeout            time.Duration
	TLSConfig                  *tls.Config
	OfflineRootKeyID           string
	OfflineRootGeneration      uint64
	OfflineRootPublicKey       ed25519.PublicKey
}

func LoadConfig() (Config, error) {
	enabledValue, configured := os.LookupEnv(consumerEnvPrefix + "ENABLED")
	if !configured {
		return Config{}, nil
	}
	if enabledValue != "true" && enabledValue != "false" {
		return Config{}, configFieldError(consumerEnvPrefix + "ENABLED")
	}
	if enabledValue == "false" {
		return Config{}, nil
	}

	config := Config{Enabled: true}
	var err error
	config.BaseURL, err = loadBaseURL(os.Getenv("LICENSE_SERVICE_URL"))
	if err != nil {
		return Config{}, err
	}
	config.InstallationID, err = loadInstallationID(os.Getenv("CONTROL_INSTALLATION_ID"))
	if err != nil {
		return Config{}, err
	}
	config.InstallationPrivateKeyFile = os.Getenv("CONTROL_INSTALLATION_PRIVATE_KEY_FILE")
	if config.InstallationPrivateKeyFile == "" {
		return Config{}, configFieldError("CONTROL_INSTALLATION_PRIVATE_KEY_FILE")
	}

	config.RefreshInterval, err = loadDuration(consumerEnvPrefix+"REFRESH_INTERVAL", defaultRefreshInterval, time.Minute, 24*time.Hour)
	if err != nil {
		return Config{}, err
	}
	config.RequestTimeout, err = loadDuration(consumerEnvPrefix+"REQUEST_TIMEOUT", defaultRequestTimeout, time.Second, 30*time.Second)
	if err != nil {
		return Config{}, err
	}
	config.StartupTimeout, err = loadDuration(consumerEnvPrefix+"STARTUP_TIMEOUT", defaultStartupTimeout, time.Second, 30*time.Second)
	if err != nil {
		return Config{}, err
	}
	config.ShutdownTimeout, err = loadDuration(consumerEnvPrefix+"SHUTDOWN_TIMEOUT", defaultShutdownTimeout, time.Second, 30*time.Second)
	if err != nil {
		return Config{}, err
	}

	config.TLSConfig, err = loadTLSConfig(os.Getenv(consumerEnvPrefix + "TLS_CA_FILE"))
	if err != nil {
		return Config{}, err
	}
	config.OfflineRootKeyID = os.Getenv(consumerEnvPrefix + "OFFLINE_ROOT_KEY_ID")
	if entitlement.ValidateKeyID(config.OfflineRootKeyID) != nil {
		return Config{}, configFieldError(consumerEnvPrefix + "OFFLINE_ROOT_KEY_ID")
	}
	config.OfflineRootGeneration, err = loadGeneration(os.Getenv(consumerEnvPrefix + "OFFLINE_ROOT_GENERATION"))
	if err != nil {
		return Config{}, err
	}
	config.OfflineRootPublicKey, err = loadPublicKey(os.Getenv(consumerEnvPrefix + "OFFLINE_ROOT_PUBLIC_KEY_BASE64"))
	if err != nil {
		return Config{}, err
	}
	return config, nil
}

func loadBaseURL(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || raw == "" || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery ||
		parsed.Fragment != "" || parsed.RawFragment != "" || parsed.Opaque != "" {
		return "", configFieldError("LICENSE_SERVICE_URL")
	}
	return raw, nil
}

func loadInstallationID(raw string) (uuid.UUID, error) {
	installationID, err := uuid.Parse(raw)
	if err != nil || installationID == uuid.Nil || installationID.String() != raw {
		return uuid.Nil, configFieldError("CONTROL_INSTALLATION_ID")
	}
	return installationID, nil
}

func loadDuration(name string, fallback, minimum, maximum time.Duration) (time.Duration, error) {
	raw, configured := os.LookupEnv(name)
	if !configured {
		return fallback, nil
	}
	value, err := time.ParseDuration(raw)
	if err != nil || value < minimum || value > maximum {
		return 0, configFieldError(name)
	}
	return value, nil
}

func loadGeneration(raw string) (uint64, error) {
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || value == 0 || strconv.FormatUint(value, 10) != raw {
		return 0, configFieldError(consumerEnvPrefix + "OFFLINE_ROOT_GENERATION")
	}
	return value, nil
}

func loadPublicKey(raw string) (ed25519.PublicKey, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil || len(decoded) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(decoded) != raw {
		return nil, configFieldError(consumerEnvPrefix + "OFFLINE_ROOT_PUBLIC_KEY_BASE64")
	}
	return append(ed25519.PublicKey(nil), decoded...), nil
}

func loadTLSConfig(path string) (*tls.Config, error) {
	result := &tls.Config{MinVersion: tls.VersionTLS12}
	if path == "" {
		return result, nil
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, configFieldError(consumerEnvPrefix + "TLS_CA_FILE")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 1 ||
		info.Size() > maximumCAFileBytes || info.Mode().Perm()&0o022 != 0 {
		return nil, configFieldError(consumerEnvPrefix + "TLS_CA_FILE")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, configFieldError(consumerEnvPrefix + "TLS_CA_FILE")
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) ||
		openedInfo.Size() < 1 || openedInfo.Size() > maximumCAFileBytes || openedInfo.Mode().Perm()&0o022 != 0 {
		return nil, configFieldError(consumerEnvPrefix + "TLS_CA_FILE")
	}
	encoded, err := io.ReadAll(io.LimitReader(file, maximumCAFileBytes+1))
	if err != nil || len(encoded) == 0 || len(encoded) > maximumCAFileBytes {
		return nil, configFieldError(consumerEnvPrefix + "TLS_CA_FILE")
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, configFieldError(consumerEnvPrefix + "TLS_CA_FILE")
	}
	roots = roots.Clone()
	remaining := bytes.TrimSpace(encoded)
	count := 0
	for len(remaining) > 0 {
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, configFieldError(consumerEnvPrefix + "TLS_CA_FILE")
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, configFieldError(consumerEnvPrefix + "TLS_CA_FILE")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, configFieldError(consumerEnvPrefix + "TLS_CA_FILE")
		}
		roots.AddCert(certificate)
		count++
		remaining = bytes.TrimSpace(rest)
	}
	if count == 0 {
		return nil, configFieldError(consumerEnvPrefix + "TLS_CA_FILE")
	}
	result.RootCAs = roots
	return result, nil
}

func configFieldError(name string) error {
	return fmt.Errorf("%s: %w", name, ErrInvalidConfiguration)
}

// OfflineRoot is the independently provisioned offline root pin.
type OfflineRoot struct {
	KeyID      string
	Generation uint64
	PublicKey  ed25519.PublicKey
}

// LoadOfflineRoot reads only the SIGNER_REVOCATION_CONSUMER_OFFLINE_ROOT_*
// pin (for the import commands and the node signer trust fetcher); configured
// reports whether any of the three is set.
func LoadOfflineRoot() (OfflineRoot, bool, error) {
	keyID := os.Getenv(consumerEnvPrefix + "OFFLINE_ROOT_KEY_ID")
	generation := os.Getenv(consumerEnvPrefix + "OFFLINE_ROOT_GENERATION")
	publicKey := os.Getenv(consumerEnvPrefix + "OFFLINE_ROOT_PUBLIC_KEY_BASE64")
	if keyID == "" && generation == "" && publicKey == "" {
		return OfflineRoot{}, false, nil
	}
	if entitlement.ValidateKeyID(keyID) != nil {
		return OfflineRoot{}, true, configFieldError(consumerEnvPrefix + "OFFLINE_ROOT_KEY_ID")
	}
	parsedGeneration, err := loadGeneration(generation)
	if err != nil {
		return OfflineRoot{}, true, err
	}
	parsedKey, err := loadPublicKey(publicKey)
	if err != nil {
		return OfflineRoot{}, true, err
	}
	return OfflineRoot{KeyID: keyID, Generation: parsedGeneration, PublicKey: parsedKey}, true, nil
}

// TrustConfig is the part of Config NewDeploymentTrust reads.
func (root OfflineRoot) TrustConfig() Config {
	return Config{OfflineRootKeyID: root.KeyID, OfflineRootGeneration: root.Generation,
		OfflineRootPublicKey: append(ed25519.PublicKey(nil), root.PublicKey...)}
}

// TLSConfigFromEnv is the consumer's TLS policy (optional
// SIGNER_REVOCATION_CONSUMER_TLS_CA_FILE), shared by the node signer trust fetcher.
func TLSConfigFromEnv() (*tls.Config, error) {
	return loadTLSConfig(os.Getenv(consumerEnvPrefix + "TLS_CA_FILE"))
}
