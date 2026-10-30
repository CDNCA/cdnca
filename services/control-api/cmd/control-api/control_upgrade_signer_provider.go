package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
)

const (
	controlUpgradeControlSignerProviderEnv              = "CONTROL_UPGRADE_CONTROL_SIGNER_PROVIDER"
	controlUpgradeControlSigningPublicKeyFileEnv        = "CONTROL_UPGRADE_CONTROL_SIGNING_PUBLIC_KEY_FILE"
	controlUpgradeControlSignerRemoteEndpointEnv        = "CONTROL_UPGRADE_CONTROL_SIGNER_REMOTE_ENDPOINT"
	controlUpgradeControlSignerRemoteCAFileEnv          = "CONTROL_UPGRADE_CONTROL_SIGNER_REMOTE_CA_FILE"
	controlUpgradeControlSignerRemoteBearerTokenFileEnv = "CONTROL_UPGRADE_CONTROL_SIGNER_REMOTE_BEARER_TOKEN_FILE"
	controlUpgradeControlSignerRemoteTimeoutEnv         = "CONTROL_UPGRADE_CONTROL_SIGNER_REMOTE_TIMEOUT"
	controlUpgradeEdgeSignerProviderEnv                 = "CONTROL_UPGRADE_EDGE_SIGNER_PROVIDER"
	controlUpgradeEdgeSigningPublicKeyFileEnv           = "CONTROL_UPGRADE_EDGE_SIGNING_PUBLIC_KEY_FILE"
	controlUpgradeEdgeSignerRemoteEndpointEnv           = "CONTROL_UPGRADE_EDGE_SIGNER_REMOTE_ENDPOINT"
	controlUpgradeEdgeSignerRemoteCAFileEnv             = "CONTROL_UPGRADE_EDGE_SIGNER_REMOTE_CA_FILE"
	controlUpgradeEdgeSignerRemoteBearerTokenFileEnv    = "CONTROL_UPGRADE_EDGE_SIGNER_REMOTE_BEARER_TOKEN_FILE"
	controlUpgradeEdgeSignerRemoteTimeoutEnv            = "CONTROL_UPGRADE_EDGE_SIGNER_REMOTE_TIMEOUT"
	controlUpgradeSignerProviderFile                    = "file"
	controlUpgradeSignerProviderRemote                  = "remote"
	controlUpgradeSignerMaximumResponse                 = 4096
	controlUpgradeSignerMaximumPublicKey                = 16 << 10
	controlUpgradeSignerMaximumCA                       = 1 << 20
	controlUpgradeSignerMaximumToken                    = 4096
	controlUpgradeSignerMinimumTimeout                  = 100 * time.Millisecond
	controlUpgradeSignerMaximumTimeout                  = 10 * time.Second
)

type controlUpgradeSignerProviderConfig struct {
	Provider              string
	KeyID                 string
	PrivateKeyFile        string
	PublicKeyFile         string
	RemoteEndpoint        string
	RemoteCAFile          string
	RemoteBearerTokenFile string
	RemoteTimeout         time.Duration
}

type controlUpgradeSigningProvider interface {
	entitlement.Signer
	PublicKey() ed25519.PublicKey
	Close()
}

type controlUpgradeSignerProviderEnvironment struct {
	Provider, PrivateKey, PublicKey, Endpoint, CAFile, BearerToken, Timeout string
}

func controlUpgradeLoadSignerProviderConfig(values map[string]string, counts map[string]int,
	env controlUpgradeSignerProviderEnvironment, keyID string) (controlUpgradeSignerProviderConfig, error) {
	provider := controlUpgradeSignerProviderFile
	if counts[env.Provider] == 1 {
		provider = values[env.Provider]
	}
	if strings.TrimSpace(provider) != provider || (provider != controlUpgradeSignerProviderFile && provider != controlUpgradeSignerProviderRemote) {
		return controlUpgradeSignerProviderConfig{}, controlUpgradeConfigError(env.Provider)
	}
	result := controlUpgradeSignerProviderConfig{Provider: provider, KeyID: keyID}
	if provider == controlUpgradeSignerProviderFile {
		if counts[env.PrivateKey] != 1 {
			return controlUpgradeSignerProviderConfig{}, controlUpgradeConfigError(env.PrivateKey)
		}
		if controlUpgradeAnyConfigured(counts, env.PublicKey, env.Endpoint, env.CAFile, env.BearerToken, env.Timeout) {
			return controlUpgradeSignerProviderConfig{}, errors.New("file control upgrade signer cannot retain remote settings")
		}
		result.PrivateKeyFile = values[env.PrivateKey]
		if err := controlUpgradeValidateFile(result.PrivateKeyFile, controlUpgradeMaxPrivateKeyBytes, true); err != nil {
			return controlUpgradeSignerProviderConfig{}, controlUpgradeConfigError(env.PrivateKey)
		}
		return result, nil
	}
	if counts[env.PrivateKey] != 0 {
		return controlUpgradeSignerProviderConfig{}, errors.New("remote control upgrade signer cannot configure a private key file")
	}
	for _, name := range []string{env.PublicKey, env.Endpoint, env.CAFile, env.BearerToken, env.Timeout} {
		if counts[name] != 1 {
			return controlUpgradeSignerProviderConfig{}, controlUpgradeConfigError(name)
		}
	}
	result.PublicKeyFile, result.RemoteEndpoint, result.RemoteCAFile, result.RemoteBearerTokenFile =
		values[env.PublicKey], values[env.Endpoint], values[env.CAFile], values[env.BearerToken]
	if err := controlUpgradeValidateFile(result.PublicKeyFile, controlUpgradeSignerMaximumPublicKey, false); err != nil {
		return controlUpgradeSignerProviderConfig{}, controlUpgradeConfigError(env.PublicKey)
	}
	if err := controlUpgradeValidateFile(result.RemoteCAFile, controlUpgradeSignerMaximumCA, false); err != nil {
		return controlUpgradeSignerProviderConfig{}, controlUpgradeConfigError(env.CAFile)
	}
	if err := controlUpgradeValidateFile(result.RemoteBearerTokenFile, controlUpgradeSignerMaximumToken, true); err != nil {
		return controlUpgradeSignerProviderConfig{}, controlUpgradeConfigError(env.BearerToken)
	}
	if _, err := controlUpgradeSignerEndpoint(result.RemoteEndpoint); err != nil {
		return controlUpgradeSignerProviderConfig{}, controlUpgradeConfigError(env.Endpoint)
	}
	var err error
	result.RemoteTimeout, err = controlUpgradeDuration(values, env.Timeout,
		controlUpgradeSignerMinimumTimeout, controlUpgradeSignerMaximumTimeout)
	if err != nil {
		return controlUpgradeSignerProviderConfig{}, err
	}
	return result, nil
}

func controlUpgradeAnyConfigured(counts map[string]int, names ...string) bool {
	for _, name := range names {
		if counts[name] != 0 {
			return true
		}
	}
	return false
}

func openControlUpgradeSigningProvider(config controlUpgradeSignerProviderConfig) (controlUpgradeSigningProvider, error) {
	if entitlement.ValidateKeyID(config.KeyID) != nil {
		return nil, errors.New("control upgrade signer key id is invalid")
	}
	switch config.Provider {
	case "", controlUpgradeSignerProviderFile:
		privateKey, err := controlUpgradeLoadPrivateKey(config.PrivateKeyFile)
		if err != nil {
			return nil, errors.New("load control upgrade signing key")
		}
		return &controlUpgradeEd25519Signer{keyID: config.KeyID, privateKey: privateKey}, nil
	case controlUpgradeSignerProviderRemote:
		return loadControlUpgradeRemoteSigner(config)
	default:
		return nil, errors.New("control upgrade signer provider is invalid")
	}
}

type controlUpgradeRemoteSigner struct {
	keyID     string
	publicKey ed25519.PublicKey
	endpoint  string
	token     []byte
	client    *http.Client
}

type controlUpgradeRemoteSignature struct {
	KeyID              string `json:"key_id"`
	Algorithm          string `json:"algorithm"`
	SignatureBase64URL string `json:"signature_base64url"`
}

func loadControlUpgradeRemoteSigner(config controlUpgradeSignerProviderConfig) (*controlUpgradeRemoteSigner, error) {
	if config.RemoteTimeout < controlUpgradeSignerMinimumTimeout || config.RemoteTimeout > controlUpgradeSignerMaximumTimeout {
		return nil, errors.New("control upgrade remote signer timeout is invalid")
	}
	endpoint, err := controlUpgradeSignerEndpoint(config.RemoteEndpoint)
	if err != nil {
		return nil, err
	}
	publicKey, err := controlUpgradeReadPublicKey(config.PublicKeyFile)
	if err != nil {
		return nil, errors.New("load control upgrade remote signer public key")
	}
	caPEM, err := controlUpgradeReadFile(config.RemoteCAFile, controlUpgradeSignerMaximumCA, false)
	if err != nil {
		clear(publicKey)
		return nil, errors.New("load control upgrade remote signer CA")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		clear(publicKey)
		clear(caPEM)
		return nil, errors.New("control upgrade remote signer CA is invalid")
	}
	clear(caPEM)
	token, err := controlUpgradeReadFile(config.RemoteBearerTokenFile, controlUpgradeSignerMaximumToken, true)
	if err != nil || !controlUpgradeValidRemoteToken(token) {
		clear(publicKey)
		clear(token)
		return nil, errors.New("load control upgrade remote signer credential")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}
	return &controlUpgradeRemoteSigner{
		keyID: config.KeyID, publicKey: publicKey, endpoint: endpoint, token: token,
		client: &http.Client{Timeout: config.RemoteTimeout, Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("control upgrade remote signer redirects are disabled")
			}},
	}, nil
}

func controlUpgradeSignerEndpoint(raw string) (string, error) {
	if raw == "" || strings.TrimSpace(raw) != raw {
		return "", errors.New("control upgrade remote signer endpoint is invalid")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed == nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" || parsed.RawPath != "" ||
		parsed.Path == "" || path.Clean(parsed.Path) != parsed.Path {
		return "", errors.New("control upgrade remote signer endpoint is invalid")
	}
	return parsed.String(), nil
}

func controlUpgradeReadPublicKey(filePath string) (ed25519.PublicKey, error) {
	encoded, err := controlUpgradeReadFile(filePath, controlUpgradeSignerMaximumPublicKey, false)
	if err != nil {
		return nil, err
	}
	defer clear(encoded)
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("control upgrade public key must be one PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	publicKey, ok := parsed.(ed25519.PublicKey)
	if err != nil || !ok || len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("control upgrade public key must be Ed25519")
	}
	return append(ed25519.PublicKey(nil), publicKey...), nil
}

func controlUpgradeValidRemoteToken(token []byte) bool {
	if len(token) < 16 || len(token) > controlUpgradeSignerMaximumToken {
		return false
	}
	for _, character := range token {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func (signer *controlUpgradeRemoteSigner) KeyID() string {
	if signer == nil {
		return ""
	}
	return signer.keyID
}

func (signer *controlUpgradeRemoteSigner) PublicKey() ed25519.PublicKey {
	if signer == nil {
		return nil
	}
	return append(ed25519.PublicKey(nil), signer.publicKey...)
}

func (signer *controlUpgradeRemoteSigner) Sign(ctx context.Context, payload []byte) ([]byte, error) {
	if signer == nil || ctx == nil || ctx.Err() != nil || signer.client == nil || signer.endpoint == "" ||
		entitlement.ValidateKeyID(signer.keyID) != nil || len(signer.publicKey) != ed25519.PublicKeySize ||
		!controlUpgradeValidRemoteToken(signer.token) {
		return nil, errors.New("control upgrade remote signer is unavailable")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, signer.endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, errors.New("create control upgrade remote signer request")
	}
	request.Header.Set("Authorization", "Bearer "+string(signer.token))
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-CDNCA-Signing-Key-ID", signer.keyID)
	request.Header.Set("X-CDNCA-Signature-Algorithm", "ed25519")
	response, err := signer.client.Do(request)
	if err != nil {
		return nil, errors.New("control upgrade remote signer request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("control upgrade remote signer request was rejected")
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil, errors.New("control upgrade remote signer response is invalid")
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, controlUpgradeSignerMaximumResponse+1))
	if err != nil || len(encoded) == 0 || len(encoded) > controlUpgradeSignerMaximumResponse {
		clear(encoded)
		return nil, errors.New("control upgrade remote signer response is invalid")
	}
	defer clear(encoded)
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var result controlUpgradeRemoteSignature
	if err := decoder.Decode(&result); err != nil {
		return nil, errors.New("control upgrade remote signer response is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF || result.KeyID != signer.keyID || result.Algorithm != "ed25519" {
		return nil, errors.New("control upgrade remote signer response identity is invalid")
	}
	signature, err := base64.RawURLEncoding.DecodeString(result.SignatureBase64URL)
	if err != nil || base64.RawURLEncoding.EncodeToString(signature) != result.SignatureBase64URL ||
		len(signature) != ed25519.SignatureSize || !ed25519.Verify(signer.publicKey, payload, signature) {
		clear(signature)
		return nil, errors.New("control upgrade remote signer signature is invalid")
	}
	return signature, nil
}

func (signer *controlUpgradeRemoteSigner) Close() {
	if signer == nil {
		return
	}
	if signer.client != nil {
		if transport, ok := signer.client.Transport.(*http.Transport); ok {
			transport.CloseIdleConnections()
		}
	}
	clear(signer.publicKey)
	clear(signer.token)
	signer.publicKey = nil
	signer.token = nil
	signer.client = nil
	signer.keyID = ""
	signer.endpoint = ""
}
