package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/cdnca/cdnca/services/control-api/internal/artifactsync"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementsync"
	"github.com/cdnca/cdnca/services/control-api/internal/pluginruntimecomposition"
	"github.com/google/uuid"
)

// cdncaCE: the community edition needs no activation. To buy on the node or
// plugin market an installation registers once with the official service
// (a portal account, free): the license service records its public keys and
// answers with a signed community installation identity (30 days, refreshed
// by community-refresh). The same installation key then gets the mTLS
// client certificate the market requires.
const (
	communityRegisterPath       = "/public/v1/community/installations/register"
	communityRefreshPath        = "/public/v1/community/installations/identity:refresh"
	communityRegisterDomain     = "cdnca-community-installation-register/v1"
	communityRefreshDomain      = "cdnca-community-installation-refresh/v1"
	communityDefaultService     = "https://auth.cdnca.com"
	communityIdentityFileEnv    = "COMMUNITY_IDENTITY_FILE"
	communityIdentityMaxBytes   = 64 << 10
	communityRegisterTimeout    = 30 * time.Second
	communityServiceURLEnv      = "COMMUNITY_SERVICE_URL"
	communityIdentityFileMode   = 0o600
	communityIdentityDefaultDir = "/etc/cdnca-control/community"
)

// communityIdentityFile is what register/refresh store: the license
// service's answer, kept verbatim (the market verifies its signature).
type communityIdentityFile struct {
	InstallationID    uuid.UUID       `json:"installation_id"`
	Edition           string          `json:"edition"`
	CommunityIdentity json.RawMessage `json:"community_identity"`
}

// communityDigest is the license service's length-prefixed SHA-256 of the
// proof fields (licensing.digestFields).
func communityDigest(values ...string) []byte {
	hash := sha256.New()
	var size [4]byte
	for _, value := range values {
		binary.BigEndian.PutUint32(size[:], uint32(len(value)))
		_, _ = hash.Write(size[:])
		_, _ = hash.Write([]byte(value))
	}
	return hash.Sum(nil)
}

func communityRegisterProof(key ed25519.PrivateKey, requestID string, installation uuid.UUID, name string,
	publicKey, encryptionPublicKey []byte, account string, requestedAt int64) []byte {
	return ed25519.Sign(key, communityDigest(communityRegisterDomain, requestID, installation.String(), strings.TrimSpace(name),
		base64.RawURLEncoding.EncodeToString(publicKey), base64.RawURLEncoding.EncodeToString(encryptionPublicKey),
		strings.ToLower(strings.TrimSpace(account)), strconv.FormatInt(requestedAt, 10)))
}

func communityRefreshProof(key ed25519.PrivateKey, requestID string, installation uuid.UUID, requestedAt int64) []byte {
	return ed25519.Sign(key, communityDigest(communityRefreshDomain, requestID, installation.String(), strconv.FormatInt(requestedAt, 10)))
}

// communityInstallation is the local facts both commands need.
type communityInstallation struct {
	service      string
	installation uuid.UUID
	name         string
	key          ed25519.PrivateKey
	encryption   []byte // X25519 public key, empty without an encryption key file
	// encryptionFile is CONTROL_INSTALLATION_ENCRYPTION_KEY_FILE; when it is
	// set but the file does not exist yet (an installation older than the
	// key), registration goes without it and the key is registered after.
	encryptionFile string
	identityFile   string
}

func loadCommunityInstallation() (communityInstallation, error) {
	service := strings.TrimSpace(os.Getenv(communityServiceURLEnv))
	if service == "" {
		service = communityDefaultService
	}
	parsed, err := url.Parse(service)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") {
		return communityInstallation{}, fmt.Errorf("%s must be an https origin", communityServiceURLEnv)
	}
	installation, err := uuid.Parse(os.Getenv("CONTROL_INSTALLATION_ID"))
	if err != nil || installation == uuid.Nil {
		return communityInstallation{}, errors.New("CONTROL_INSTALLATION_ID must be the installation UUID")
	}
	key, err := entitlementsync.LoadPrivateKey(os.Getenv("CONTROL_INSTALLATION_PRIVATE_KEY_FILE"))
	if err != nil {
		return communityInstallation{}, err
	}
	result := communityInstallation{service: strings.TrimRight(service, "/"), installation: installation,
		name: strings.TrimSpace(os.Getenv("CONTROL_INSTALLATION_NAME")), key: key,
		identityFile: communityIdentityPath()}
	result.encryptionFile = strings.TrimSpace(os.Getenv("CONTROL_INSTALLATION_ENCRYPTION_KEY_FILE"))
	if result.encryptionFile != "" {
		if _, err := os.Stat(result.encryptionFile); err == nil {
			if result.encryption, err = communityEncryptionPublicKey(result.encryptionFile); err != nil {
				return communityInstallation{}, err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return communityInstallation{}, err
		}
	}
	if result.name == "" {
		result.name = "cdnca-community-" + installation.String()[:8]
	}
	return result, nil
}

func communityEncryptionPublicKey(path string) ([]byte, error) {
	private, err := entitlementsync.LoadEncryptionKey(path)
	if err != nil {
		return nil, err
	}
	defer clear(private)
	parsedKey, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		return nil, fmt.Errorf("installation encryption key: %w", err)
	}
	return parsedKey.PublicKey().Bytes(), nil
}

// registerCommunityEncryptionKey registers the installation encryption key
// after the community registration (RegisterEncryptionKeyPath, signed with
// the installation key): for an installation registered without one, or
// whose key file was replaced. A missing key file is generated (owner-only).
func registerCommunityEncryptionKey(local communityInstallation) (string, error) {
	if local.encryptionFile == "" {
		return "", errors.New("CONTROL_INSTALLATION_ENCRYPTION_KEY_FILE is not set")
	}
	public := local.encryption
	if len(public) == 0 {
		if _, err := os.Stat(local.encryptionFile); err == nil {
			if public, err = communityEncryptionPublicKey(local.encryptionFile); err != nil {
				return "", err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		} else if public, err = entitlementsync.GenerateEncryptionKey(local.encryptionFile); err != nil {
			return "", err
		}
	}
	client, err := artifactsync.NewClient(local.service, nil)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), communityRegisterTimeout)
	defer cancel()
	keyID := rulepack.X25519KeyID(public)
	response, err := client.RegisterEncryptionKey(ctx, local.installation, public, local.key, time.Now().UTC())
	if err != nil {
		return "", artifactsync.EncryptionKeyRegistrationError(keyID, err)
	}
	if response.KeyID != keyID {
		return "", errors.New("official service registered a different encryption key")
	}
	return keyID, nil
}

// runCommunityRegisterEncryptionKey is community-register-encryption-key.
func runCommunityRegisterEncryptionKey(args []string) error {
	if len(args) != 0 {
		return errors.New("usage: control-api community-register-encryption-key")
	}
	local, err := loadCommunityInstallation()
	if err != nil {
		return err
	}
	defer clear(local.key)
	if _, err := os.Stat(local.identityFile); errors.Is(err, os.ErrNotExist) {
		return errors.New("community installation not registered; run community-register first")
	}
	keyID, err := registerCommunityEncryptionKey(local)
	if err != nil {
		return err
	}
	fmt.Printf("installation encryption key registered: key_id=%s\n", keyID)
	return nil
}

func communityIdentityPath() string {
	if path := strings.TrimSpace(os.Getenv(communityIdentityFileEnv)); path != "" {
		return path
	}
	return filepath.Join(communityIdentityDefaultDir, "identity.json")
}

// runCommunityRegister: control-api community-register --account NAME
// [--password-stdin]. The portal password is read from stdin (never argv).
func runCommunityRegister(args []string) error {
	flags := flag.NewFlagSet("community-register", flag.ContinueOnError)
	account := flags.String("account", "", "official portal account (username or email)")
	passwordStdin := flags.Bool("password-stdin", false, "read the portal password from stdin")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || strings.TrimSpace(*account) == "" || !*passwordStdin {
		return errors.New("usage: control-api community-register --account NAME --password-stdin")
	}
	password, err := bufio.NewReader(io.LimitReader(os.Stdin, 4096)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read password: %w", err)
	}
	password = strings.TrimRight(password, "\r\n")
	if password == "" {
		return errors.New("portal password is empty")
	}
	local, err := loadCommunityInstallation()
	if err != nil {
		return err
	}
	defer clear(local.key)
	requestID, requestedAt := uuid.NewString(), time.Now().UTC().Unix()
	public := []byte(local.key.Public().(ed25519.PublicKey))
	body := map[string]any{"request_id": requestID, "installation_id": local.installation, "name": local.name,
		"public_key": base64.RawURLEncoding.EncodeToString(public), "encryption_public_key": base64.RawURLEncoding.EncodeToString(local.encryption),
		"account": *account, "password": password, "requested_at": requestedAt,
		"proof": base64.RawURLEncoding.EncodeToString(communityRegisterProof(local.key, requestID, local.installation, local.name,
			public, local.encryption, *account, requestedAt))}
	answer, err := postCommunity(context.Background(), local.service+communityRegisterPath, body)
	if err != nil {
		return communityRegisterError(err, len(local.encryption) > 0)
	}
	if err := storeCommunityIdentity(local, answer); err != nil {
		return err
	}
	fmt.Printf("community installation registered: installation_id=%s identity=%s\n", local.installation, local.identityFile)
	if len(local.encryption) == 0 && local.encryptionFile != "" {
		// Registered without an encryption key: register it now.
		keyID, err := registerCommunityEncryptionKey(local)
		if err != nil {
			return fmt.Errorf("registered, but the encryption key was not (rerun community-register-encryption-key): %w", err)
		}
		fmt.Printf("installation encryption key registered: key_id=%s\n", keyID)
	}
	// The market needs the installation mTLS client certificate; the official
	// service issues it to any active installation (commercial or community).
	certificate, err := ensureCommunityClientCertificate(local)
	if err != nil {
		return fmt.Errorf("registered, but the market client certificate was not issued (rerun community-register): %w", err)
	}
	fmt.Printf("market client certificate ready: %s\n", certificate)
	if path, err := ensureCommunityTrustedKeys(local); err != nil {
		return fmt.Errorf("registered, but the official signing keyset was not saved (rerun community-register): %w", err)
	} else if path != "" {
		fmt.Printf("official signing keyset: %s (restart control-api to sync market purchases)\n", path)
	}
	return nil
}

// ensureCommunityTrustedKeys saves the official public signing keyset that
// verifies the market purchase catalog, when COMMUNITY_TRUSTED_KEYS_FILE is
// set and the file does not exist yet (the installer fetches it when it can).
func ensureCommunityTrustedKeys(local communityInstallation) (string, error) {
	path := strings.TrimSpace(os.Getenv(communityTrustedKeysFileEnv))
	if path == "" {
		return "", nil
	}
	if _, err := os.Stat(path); err == nil {
		return path, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), communityRegisterTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, local.service+"/public/v1/signing-keyset", nil)
	if err != nil {
		return "", err
	}
	response, err := (&http.Client{Timeout: communityRegisterTimeout}).Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("official service answered %d", response.StatusCode)
	}
	var keyset struct {
		Schema string `json:"schema"`
		Keys   []struct {
			KeyID     string `json:"key_id"`
			PublicKey string `json:"public_key"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, communityIdentityMaxBytes)).Decode(&keyset); err != nil ||
		keyset.Schema != "cdnca.signing-keyset/v2" || len(keyset.Keys) == 0 {
		return "", errors.New("official signing keyset is invalid")
	}
	type pinned struct {
		KeyID     string `json:"key_id"`
		PublicKey string `json:"public_key"`
	}
	pins := struct {
		Keys []pinned `json:"keys"`
	}{}
	for _, key := range keyset.Keys {
		pins.Keys = append(pins.Keys, pinned{KeyID: key.KeyID, PublicKey: key.PublicKey})
	}
	encoded, err := json.Marshal(pins)
	if err != nil {
		return "", err
	}
	if _, err := entitlementguard.DecodeTrustedKeys(encoded); err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, encoded, 0o400); err != nil {
		return "", err
	}
	return path, nil
}

// ensureCommunityClientCertificate issues (or keeps) the installation client
// certificate next to the identity file, through the same certificate
// manager the commercial plugin runtime uses
// (/installation/v1/client-certificates:issue).
func ensureCommunityClientCertificate(local communityInstallation) (string, error) {
	paths := communityClientCertificatePaths(filepath.Dir(local.identityFile))
	manager, err := communityCertificateManager(local)
	if err != nil {
		return "", err
	}
	credential, err := manager.Ensure(context.Background())
	if err != nil {
		return "", err
	}
	clear(credential.PrivateKey)
	return paths.certificate, nil
}

// communityCertificateTimeout is the certificate manager's per-request limit
// (pluginruntimecomposition allows at most 5 s).
const communityCertificateTimeout = 5 * time.Second

func communityCertificateManager(local communityInstallation) (*pluginruntimecomposition.CertificateManager, error) {
	paths := communityClientCertificatePaths(filepath.Dir(local.identityFile))
	return pluginruntimecomposition.NewCertificateManager(pluginruntimecomposition.CertificateManagerConfig{
		BaseURL: local.service, InstallationID: local.installation, ActivationPrivateKey: local.key,
		CertificateFile: paths.certificate, PrivateKeyFile: paths.privateKey, RuntimeCAFile: paths.runtimeCA,
		StateFile: paths.state, Now: func() time.Time { return time.Now().UTC() }, Timeout: communityCertificateTimeout,
		MaxBodyBytes: 64 << 10,
	})
}

// newCommunityCertificateManager is the market runtime's renewing source of
// the client certificate (the official service issues it for minutes). Nil
// when the installation has not registered (community-register) yet.
func newCommunityCertificateManager() (*pluginruntimecomposition.CertificateManager, error) {
	if identity, err := loadCommunityIdentity(); err != nil || identity == nil {
		return nil, err
	}
	local, err := loadCommunityInstallation()
	if err != nil {
		return nil, err
	}
	defer clear(local.key)
	return communityCertificateManager(local)
}

type communityCertificatePaths struct{ certificate, privateKey, runtimeCA, state string }

// communityClientCertificatePaths: MARKET_CLIENT_CERT_FILE / KEY_FILE point
// here (one directory, as the certificate manager requires).
func communityClientCertificatePaths(dir string) communityCertificatePaths {
	return communityCertificatePaths{certificate: filepath.Join(dir, "client-cert.pem"),
		privateKey: filepath.Join(dir, "client-key.pem"), runtimeCA: filepath.Join(dir, "license-ca.pem"),
		state: filepath.Join(dir, "client-state.json")}
}

// runCommunityRefresh renews the stored identity (run daily by the
// community-identity-refresh timer; a stored identity stays valid 30 days).
func runCommunityRefresh(args []string) error {
	if len(args) != 0 {
		return errors.New("usage: control-api community-refresh")
	}
	local, err := loadCommunityInstallation()
	if err != nil {
		return err
	}
	defer clear(local.key)
	if _, err := os.Stat(local.identityFile); errors.Is(err, os.ErrNotExist) {
		fmt.Println("community installation not registered; nothing to refresh")
		return nil
	}
	requestID, requestedAt := uuid.NewString(), time.Now().UTC().Unix()
	answer, err := postCommunity(context.Background(), local.service+communityRefreshPath, map[string]any{
		"request_id": requestID, "installation_id": local.installation, "requested_at": requestedAt,
		"proof": base64.RawURLEncoding.EncodeToString(communityRefreshProof(local.key, requestID, local.installation, requestedAt))})
	if err != nil {
		return err
	}
	if err := storeCommunityIdentity(local, answer); err != nil {
		return err
	}
	fmt.Printf("community identity refreshed: %s\n", local.identityFile)
	return nil
}

// communityServiceError is a non-200 answer of the official service.
type communityServiceError struct {
	status int
	code   string
}

func (err *communityServiceError) Error() string {
	return fmt.Sprintf("official service answered %d %s", err.status, err.code)
}

// communityRegisterError explains installation_taken: the license service
// answers it for an installation id, installation key or encryption key
// already registered elsewhere (one unique constraint, one answer).
func communityRegisterError(err error, withEncryptionKey bool) error {
	var service *communityServiceError
	if !errors.As(err, &service) || service.status != http.StatusConflict || service.code != "installation_taken" {
		return err
	}
	if withEncryptionKey {
		return fmt.Errorf("this installation id, installation key or encryption key is already registered by another "+
			"installation or account (a copied key directory); give this installation its own keys, or register it "+
			"with the account it was first registered with: %w", err)
	}
	return fmt.Errorf("this installation id or installation key is already registered by another installation or "+
		"account; register it with the account it was first registered with: %w", err)
}

func postCommunity(ctx context.Context, target string, body any) ([]byte, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, communityRegisterTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(encoded))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := (&http.Client{Timeout: communityRegisterTimeout}).Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(response.Body, communityIdentityMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		var failure struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(answer, &failure)
		return nil, &communityServiceError{status: response.StatusCode, code: failure.Code}
	}
	if len(answer) > communityIdentityMaxBytes {
		return nil, errors.New("official service answer is too large")
	}
	return answer, nil
}

func storeCommunityIdentity(local communityInstallation, answer []byte) error {
	var stored communityIdentityFile
	if err := json.Unmarshal(answer, &stored); err != nil || stored.InstallationID != local.installation ||
		stored.Edition != "community" || len(stored.CommunityIdentity) == 0 {
		return errors.New("official service answer is not this installation's community identity")
	}
	if err := os.MkdirAll(filepath.Dir(local.identityFile), 0o700); err != nil {
		return err
	}
	temporary := local.identityFile + ".tmp"
	if err := os.WriteFile(temporary, answer, communityIdentityFileMode); err != nil {
		return err
	}
	return os.Rename(temporary, local.identityFile)
}

// loadCommunityIdentity returns the stored community_identity document for
// the market registration, or nil when the installation never registered.
func loadCommunityIdentity() ([]byte, error) {
	encoded, err := os.ReadFile(communityIdentityPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var stored communityIdentityFile
	if err := json.Unmarshal(encoded, &stored); err != nil || len(stored.CommunityIdentity) == 0 {
		return nil, errors.New("stored community identity is invalid")
	}
	return stored.CommunityIdentity, nil
}
