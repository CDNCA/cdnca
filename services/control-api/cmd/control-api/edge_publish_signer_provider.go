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
	"os"
	"path"
	"strings"
	"time"
)

const (
	edgePublishSignerProviderEnv        = "EDGE_PUBLISH_SIGNER_PROVIDER"
	edgePublishSignerProviderFile       = "file"
	edgePublishSignerProviderRemote     = "remote"
	edgePublishSigningPublicKeyFileEnv  = "EDGE_PUBLISH_SIGNING_PUBLIC_KEY_FILE"
	edgePublishRemoteEndpointEnv        = "EDGE_PUBLISH_SIGNER_REMOTE_ENDPOINT"
	edgePublishRemoteCAFileEnv          = "EDGE_PUBLISH_SIGNER_REMOTE_CA_FILE"
	edgePublishRemoteBearerTokenFileEnv = "EDGE_PUBLISH_SIGNER_REMOTE_BEARER_TOKEN_FILE"
	edgePublishRemoteTimeoutEnv         = "EDGE_PUBLISH_SIGNER_REMOTE_TIMEOUT"
	edgePublishRemoteDefaultTimeout     = 3 * time.Second
	edgePublishRemoteMaximumTimeout     = 10 * time.Second
	edgePublishRemoteMaximumResponse    = 4096
	edgePublishRemoteMaximumFile        = 1 << 20
)

var edgePublishRemoteSignerEnvironment = []string{
	edgePublishSigningPublicKeyFileEnv,
	edgePublishRemoteEndpointEnv,
	edgePublishRemoteCAFileEnv,
	edgePublishRemoteBearerTokenFileEnv,
	edgePublishRemoteTimeoutEnv,
}

type edgePublishArtifactSigningProvider interface {
	Sign(context.Context, []byte) ([]byte, error)
	Close()
}

type edgePublishRemoteArtifactSigner struct {
	keyID     string
	publicKey ed25519.PublicKey
	endpoint  string
	token     []byte
	client    *http.Client
}

type edgePublishRemoteSignature struct {
	KeyID              string `json:"key_id"`
	Algorithm          string `json:"algorithm"`
	SignatureBase64URL string `json:"signature_base64url"`
}

func edgePublishRemoteSignerEnvironmentConfigured() bool {
	for _, name := range edgePublishRemoteSignerEnvironment {
		if strings.TrimSpace(os.Getenv(name)) != "" {
			return true
		}
	}
	return false
}

func loadEdgePublishRemoteArtifactSigner(keyID string) (*edgePublishRemoteArtifactSigner, ed25519.PublicKey, error) {
	endpoint, err := edgePublishRemoteSignerEndpoint(os.Getenv(edgePublishRemoteEndpointEnv))
	if err != nil {
		return nil, nil, err
	}
	publicKey, err := edgePublishRemoteSignerPublicKey(os.Getenv(edgePublishSigningPublicKeyFileEnv))
	if err != nil {
		return nil, nil, errors.New("load remote edge publication signing public key")
	}
	caPEM, err := edgePublishRemoteSignerFile(os.Getenv(edgePublishRemoteCAFileEnv), false, edgePublishRemoteMaximumFile)
	if err != nil {
		return nil, nil, errors.New("load remote edge publication signer CA")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, nil, errors.New("remote edge publication signer CA is invalid")
	}
	token, err := edgePublishRemoteSignerFile(os.Getenv(edgePublishRemoteBearerTokenFileEnv), true, 4096)
	if err != nil || !validEdgePublishRemoteToken(token) {
		clear(token)
		return nil, nil, errors.New("load remote edge publication signer credential")
	}
	timeout, err := edgePublishRemoteSignerTimeout(os.Getenv(edgePublishRemoteTimeoutEnv))
	if err != nil {
		clear(token)
		return nil, nil, err
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}
	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("remote edge publication signer redirects are disabled")
		},
	}
	signer := &edgePublishRemoteArtifactSigner{
		keyID: keyID, publicKey: append(ed25519.PublicKey(nil), publicKey...), endpoint: endpoint,
		token: append([]byte(nil), token...), client: client,
	}
	clear(token)
	return signer, append(ed25519.PublicKey(nil), publicKey...), nil
}

func edgePublishRemoteSignerEndpoint(raw string) (string, error) {
	if raw == "" || strings.TrimSpace(raw) != raw {
		return "", errors.New("EDGE_PUBLISH_SIGNER_REMOTE_ENDPOINT is invalid")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed == nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" || parsed.RawPath != "" ||
		parsed.Path == "" || path.Clean(parsed.Path) != parsed.Path {
		return "", errors.New("EDGE_PUBLISH_SIGNER_REMOTE_ENDPOINT is invalid")
	}
	return parsed.String(), nil
}

func edgePublishRemoteSignerPublicKey(filePath string) (ed25519.PublicKey, error) {
	encoded, err := edgePublishRemoteSignerFile(filePath, false, 16<<10)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("public key must be one PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("public key is invalid")
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("public key must be Ed25519")
	}
	return append(ed25519.PublicKey(nil), publicKey...), nil
}

func edgePublishRemoteSignerFile(filePath string, restricted bool, maximum int64) ([]byte, error) {
	if filePath == "" || strings.TrimSpace(filePath) != filePath || maximum < 1 {
		return nil, errors.New("signer file path is invalid")
	}
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || restricted && info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("signer file permissions are invalid")
	}
	encoded, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(encoded) == 0 || int64(len(encoded)) > maximum {
		clear(encoded)
		return nil, errors.New("signer file size is invalid")
	}
	return encoded, nil
}

func validEdgePublishRemoteToken(token []byte) bool {
	if len(token) < 16 || len(token) > 4096 {
		return false
	}
	for _, character := range token {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func edgePublishRemoteSignerTimeout(raw string) (time.Duration, error) {
	if raw == "" {
		return edgePublishRemoteDefaultTimeout, nil
	}
	if strings.TrimSpace(raw) != raw {
		return 0, errors.New("EDGE_PUBLISH_SIGNER_REMOTE_TIMEOUT is invalid")
	}
	timeout, err := time.ParseDuration(raw)
	if err != nil || timeout < 100*time.Millisecond || timeout > edgePublishRemoteMaximumTimeout {
		return 0, errors.New("EDGE_PUBLISH_SIGNER_REMOTE_TIMEOUT is invalid")
	}
	return timeout, nil
}

func (signer *edgePublishRemoteArtifactSigner) Sign(ctx context.Context, payload []byte) ([]byte, error) {
	if signer == nil || ctx == nil || ctx.Err() != nil || signer.client == nil || signer.endpoint == "" ||
		!validRuntimeKeyID(signer.keyID) || len(signer.publicKey) != ed25519.PublicKeySize ||
		!validEdgePublishRemoteToken(signer.token) {
		return nil, errors.New("remote edge publication signer is unavailable")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, signer.endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, errors.New("create remote edge publication signing request")
	}
	request.Header.Set("Authorization", "Bearer "+string(signer.token))
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-CDNCA-Signing-Key-ID", signer.keyID)
	request.Header.Set("X-CDNCA-Signature-Algorithm", "ed25519")
	response, err := signer.client.Do(request)
	if err != nil {
		return nil, errors.New("remote edge publication signing request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("remote edge publication signing request was rejected")
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil, errors.New("remote edge publication signing response is invalid")
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, edgePublishRemoteMaximumResponse+1))
	decoder.DisallowUnknownFields()
	var result edgePublishRemoteSignature
	if err := decoder.Decode(&result); err != nil {
		return nil, errors.New("remote edge publication signing response is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("remote edge publication signing response is invalid")
	}
	if result.KeyID != signer.keyID || result.Algorithm != "ed25519" {
		return nil, errors.New("remote edge publication signer identity changed")
	}
	signature, err := base64.RawURLEncoding.DecodeString(result.SignatureBase64URL)
	if err != nil || base64.RawURLEncoding.EncodeToString(signature) != result.SignatureBase64URL ||
		len(signature) != ed25519.SignatureSize || !ed25519.Verify(signer.publicKey, payload, signature) {
		return nil, errors.New("remote edge publication signature is invalid")
	}
	return signature, nil
}

func (signer *edgePublishRemoteArtifactSigner) Close() {
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
