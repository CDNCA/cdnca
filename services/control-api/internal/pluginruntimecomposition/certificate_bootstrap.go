package pluginruntimecomposition

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	bootstrapIssuePath      = "/installation/v1/client-certificates:issue"
	bootstrapRequestSchema  = "cdnca.installation-client-certificate-issue/v1"
	bootstrapResponseSchema = "cdnca.installation-client-certificate/v1"
	bootstrapProofDomain    = "cdnca-installation-client-certificate-issue/v1"
	bootstrapStateSchema    = "cdnca.plugin-runtime-client-state/v1"
	bootstrapMaxLifetime    = 15 * time.Minute
	bootstrapRefreshBefore  = 5 * time.Minute
)

var (
	ErrCertificateBootstrapInvalidConfiguration = errors.New("certificate bootstrap invalid configuration")
	ErrCertificateBootstrapInvalidState         = errors.New("certificate bootstrap invalid state")
	ErrCertificateBootstrapDenied               = errors.New("certificate bootstrap denied")
	ErrCertificateBootstrapConflict             = errors.New("certificate bootstrap conflict")
	ErrCertificateBootstrapUnavailable          = errors.New("certificate bootstrap unavailable")
)

type CertificateManagerConfig struct {
	BaseURL               string
	InstallationID        uuid.UUID
	ActivationPrivateKey  ed25519.PrivateKey
	CertificateFile       string
	PrivateKeyFile        string
	RuntimeCAFile         string
	StateFile             string
	BootstrapServerCAFile string
	Now                   func() time.Time
	Timeout               time.Duration
	MaxBodyBytes          int64
}

type CertificateManager struct {
	config     CertificateManagerConfig
	endpoint   string
	mu         sync.Mutex
	credential *RuntimeCredential
	generation uint64
}

type bootstrapRequest struct {
	Schema             string    `json:"schema"`
	RequestID          string    `json:"request_id"`
	InstallationID     uuid.UUID `json:"installation_id"`
	ExpectedGeneration uint64    `json:"expected_generation"`
	CSRDER             string    `json:"csr_der"`
	RequestedAt        time.Time `json:"requested_at"`
	Proof              string    `json:"proof"`
}

type bootstrapProof struct {
	Schema             string    `json:"schema"`
	RequestID          string    `json:"request_id"`
	InstallationID     uuid.UUID `json:"installation_id"`
	ExpectedGeneration uint64    `json:"expected_generation"`
	CSRDER             string    `json:"csr_der"`
	RequestedAt        string    `json:"requested_at"`
}

type bootstrapResponse struct {
	Schema           string     `json:"schema"`
	CertificateID    uuid.UUID  `json:"certificate_id"`
	InstallationID   uuid.UUID  `json:"installation_id"`
	Generation       uint64     `json:"generation"`
	Serial           string     `json:"serial"`
	CertificateDER   string     `json:"certificate_der"`
	CACertificateDER string     `json:"ca_certificate_der"`
	SPIFFEID         string     `json:"spiffe_id"`
	Status           string     `json:"status"`
	IssuedAt         time.Time  `json:"issued_at"`
	NotBefore        time.Time  `json:"not_before"`
	NotAfter         time.Time  `json:"not_after"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	RevocationReason *string    `json:"revocation_reason,omitempty"`
	Revision         uint64     `json:"revision"`
}

type pendingState struct {
	Schema             string `json:"schema"`
	Status             string `json:"status"`
	InstallationID     string `json:"installation_id"`
	RequestID          string `json:"request_id"`
	ExpectedGeneration uint64 `json:"expected_generation"`
	RequestBody        string `json:"request_body"`
	PrivateKeyFile     string `json:"private_key_file"`
	PrivateKeySHA256   string `json:"private_key_sha256"`
	CreatedAt          string `json:"created_at"`
}

type committedState struct {
	Schema            string `json:"schema"`
	Status            string `json:"status"`
	InstallationID    string `json:"installation_id"`
	CertificateID     string `json:"certificate_id"`
	Generation        uint64 `json:"generation"`
	CertificateSHA256 string `json:"certificate_sha256"`
	PrivateKeySHA256  string `json:"private_key_sha256"`
	RuntimeCASHA256   string `json:"runtime_ca_sha256"`
	NotAfter          string `json:"not_after"`
	CommittedAt       string `json:"committed_at"`
}

func NewCertificateManager(config CertificateManagerConfig) (*CertificateManager, error) {
	origin, err := exactHTTPSOrigin(config.BaseURL)
	if err != nil || config.InstallationID == uuid.Nil || len(config.ActivationPrivateKey) != ed25519.PrivateKeySize ||
		config.Now == nil || config.Now().IsZero() || config.Timeout <= 0 || config.Timeout > maximumTimeout ||
		config.MaxBodyBytes <= 0 || config.MaxBodyBytes > maximumBodyBytes {
		return nil, ErrCertificateBootstrapInvalidConfiguration
	}
	paths := []string{config.CertificateFile, config.PrivateKeyFile, config.RuntimeCAFile, config.StateFile}
	if !validBootstrapPaths(paths) || config.BootstrapServerCAFile != "" && !validBootstrapCA(config.BootstrapServerCAFile) {
		return nil, ErrCertificateBootstrapInvalidConfiguration
	}
	key := append(ed25519.PrivateKey(nil), config.ActivationPrivateKey...)
	config.ActivationPrivateKey = key
	return &CertificateManager{config: config, endpoint: origin.String() + bootstrapIssuePath}, nil
}

func validBootstrapPaths(paths []string) bool {
	if len(paths) == 0 {
		return false
	}
	dir := ""
	seen := map[string]bool{}
	for _, path := range paths {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return false
		}
		if seen[path] {
			return false
		}
		seen[path] = true
		if dir == "" {
			dir = filepath.Dir(path)
		} else if filepath.Dir(path) != dir {
			return false
		}
	}
	return true
}

func validBootstrapCA(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular() && info.Size() > 0 && info.Size() <= 4<<20
}

func (manager *CertificateManager) Ensure(ctx context.Context) (RuntimeCredential, error) {
	if manager == nil || ctx == nil {
		return RuntimeCredential{}, ErrCertificateBootstrapInvalidConfiguration
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	now := manager.config.Now().UTC().Truncate(time.Second)
	if manager.credential != nil {
		leaf, err := x509.ParseCertificate(manager.credential.TLSCertificate.Certificate[0])
		if err == nil && now.Before(leaf.NotAfter.Add(-bootstrapRefreshBefore)) {
			return cloneRuntimeCredential(*manager.credential), nil
		}
	}
	if state, ok, err := manager.readCommittedState(); err != nil {
		return RuntimeCredential{}, err
	} else if ok {
		credential, loadErr := manager.loadCommittedCredential(state)
		if loadErr != nil {
			return RuntimeCredential{}, ErrCertificateBootstrapInvalidState
		}
		manager.credential, manager.generation = &credential, state.Generation
		leaf, _ := x509.ParseCertificate(credential.TLSCertificate.Certificate[0])
		if now.Before(leaf.NotAfter.Add(-bootstrapRefreshBefore)) {
			return cloneRuntimeCredential(credential), nil
		}
	}
	requestBytes, privateKey, generation, pendingName, err := manager.prepareRequest(now)
	if err != nil {
		return RuntimeCredential{}, err
	}
	response, err := manager.issue(ctx, requestBytes)
	if err != nil {
		return RuntimeCredential{}, err
	}
	// The issuer stamps NotBefore with its clock when it signs, after this request was prepared; once issuance
	// crosses a second boundary the certificate is "not yet valid" at the preparation time. Check it at arrival.
	received := manager.config.Now().UTC().Truncate(time.Second)
	credential, err := manager.validateResponse(response, privateKey, generation, received)
	if err != nil {
		return RuntimeCredential{}, err
	}
	if err := manager.commitCredential(credential, privateKey, response, pendingName, received); err != nil {
		return RuntimeCredential{}, err
	}
	clear(privateKey)
	manager.credential = &credential
	manager.generation = response.Generation
	return cloneRuntimeCredential(credential), nil
}

func (manager *CertificateManager) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	if manager == nil {
		return nil, ErrCertificateBootstrapInvalidConfiguration
	}
	credential, err := manager.Ensure(context.Background())
	if err != nil {
		return nil, err
	}
	certificate := cloneTLSCertificate(credential.TLSCertificate)
	clearRuntimeCredential(&credential)
	return &certificate, nil
}

func (manager *CertificateManager) prepareRequest(now time.Time) ([]byte, ed25519.PrivateKey, uint64, string, error) {
	if stateBytes, err := os.ReadFile(manager.config.StateFile); err == nil {
		var pending pendingState
		if decodeCanonicalLine(stateBytes, &pending) && pending.Schema == bootstrapStateSchema && pending.Status == "pending" && pending.InstallationID == manager.config.InstallationID.String() {
			path := filepath.Join(filepath.Dir(manager.config.StateFile), pending.PrivateKeyFile)
			encoded, readErr := os.ReadFile(path)
			if readErr != nil || sha256Hex(encoded) != pending.PrivateKeySHA256 {
				return nil, nil, 0, "", ErrCertificateBootstrapInvalidState
			}
			key, parseErr := parseEd25519Private(encoded)
			if parseErr != nil {
				return nil, nil, 0, "", ErrCertificateBootstrapInvalidState
			}
			body, decodeErr := base64.RawURLEncoding.DecodeString(pending.RequestBody)
			if decodeErr != nil {
				clear(key)
				return nil, nil, 0, "", ErrCertificateBootstrapInvalidState
			}
			return body, key, pending.ExpectedGeneration, pending.PrivateKeyFile, nil
		}
		var committed committedState
		if decodeCanonicalLine(stateBytes, &committed) && committed.Schema == bootstrapStateSchema && committed.Status == "committed" && committed.InstallationID == manager.config.InstallationID.String() {
			// A valid committed state is the starting point for a rotation.
		} else if len(stateBytes) > 0 {
			return nil, nil, 0, "", ErrCertificateBootstrapInvalidState
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, 0, "", ErrCertificateBootstrapInvalidState
	} else {
		for _, path := range []string{manager.config.CertificateFile, manager.config.PrivateKeyFile, manager.config.RuntimeCAFile} {
			if _, statErr := os.Lstat(path); statErr == nil {
				return nil, nil, 0, "", ErrCertificateBootstrapInvalidState
			}
		}
	}
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, 0, "", ErrCertificateBootstrapUnavailable
	}
	requestID, err := uuid.NewV7()
	if err != nil {
		clear(privateKey)
		return nil, nil, 0, "", ErrCertificateBootstrapUnavailable
	}
	csrTemplate := &x509.CertificateRequest{URIs: []*url.URL{{Scheme: "spiffe", Host: "cdn-platform", Path: "/installation/" + manager.config.InstallationID.String()}}, Subject: pkix.Name{CommonName: manager.config.InstallationID.String()}}
	csrDER, err := x509.CreateCertificateRequest(nil, csrTemplate, privateKey)
	if err != nil {
		clear(privateKey)
		return nil, nil, 0, "", ErrCertificateBootstrapUnavailable
	}
	csrEncoded := base64.RawURLEncoding.EncodeToString(csrDER)
	generation := manager.generation
	requestedAt := now.UTC().Truncate(time.Second)
	unsigned, _ := json.Marshal(bootstrapProof{bootstrapRequestSchema, requestID.String(), manager.config.InstallationID, generation, csrEncoded, requestedAt.Format(time.RFC3339)})
	proof := ed25519.Sign(manager.config.ActivationPrivateKey, lengthPrefixed(bootstrapProofDomain, unsigned))
	body, _ := json.Marshal(bootstrapRequest{bootstrapRequestSchema, requestID.String(), manager.config.InstallationID, generation, csrEncoded, requestedAt, base64.RawURLEncoding.EncodeToString(proof)})
	clear(proof)
	name := "." + requestID.String() + ".key.pending"
	file, err := os.OpenFile(filepath.Join(filepath.Dir(manager.config.StateFile), name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		clear(privateKey)
		return nil, nil, 0, "", ErrCertificateBootstrapInvalidState
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		clear(privateKey)
		return nil, nil, 0, "", ErrCertificateBootstrapUnavailable
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if _, err = file.Write(keyPEM); err == nil {
		err = file.Sync()
	}
	_ = file.Close()
	if err != nil {
		clear(privateKey)
		return nil, nil, 0, "", ErrCertificateBootstrapInvalidState
	}
	pending := pendingState{bootstrapStateSchema, "pending", manager.config.InstallationID.String(), requestID.String(), generation, base64.RawURLEncoding.EncodeToString(body), name, sha256Hex(keyPEM), now.Format(time.RFC3339)}
	if err := atomicWrite(manager.config.StateFile, pending, 0o600); err != nil {
		clear(privateKey)
		return nil, nil, 0, "", ErrCertificateBootstrapInvalidState
	}
	return body, privateKey, generation, name, nil
}

func (manager *CertificateManager) issue(ctx context.Context, body []byte) (bootstrapResponse, error) {
	var roots *x509.CertPool
	if manager.config.BootstrapServerCAFile != "" {
		caBytes, err := os.ReadFile(manager.config.BootstrapServerCAFile)
		if err != nil {
			return bootstrapResponse{}, ErrCertificateBootstrapUnavailable
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(caBytes) {
			return bootstrapResponse{}, ErrCertificateBootstrapUnavailable
		}
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: roots, Time: func() time.Time { return manager.config.Now().UTC() }}
	client := &http.Client{Timeout: manager.config.Timeout, Transport: &http.Transport{Proxy: nil, TLSClientConfig: tlsConfig, TLSHandshakeTimeout: manager.config.Timeout, ResponseHeaderTimeout: manager.config.Timeout}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect") }}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, manager.endpoint, bytes.NewReader(body))
	if err != nil {
		return bootstrapResponse{}, ErrCertificateBootstrapUnavailable
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return bootstrapResponse{}, ErrCertificateBootstrapUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		switch {
		case resp.StatusCode == 400 || resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 404:
			return bootstrapResponse{}, ErrCertificateBootstrapDenied
		case resp.StatusCode == 409:
			return bootstrapResponse{}, ErrCertificateBootstrapConflict
		default:
			return bootstrapResponse{}, ErrCertificateBootstrapUnavailable
		}
	}
	if resp.Header.Get("Content-Type") != "application/json" || resp.Header.Get("Content-Encoding") != "" {
		return bootstrapResponse{}, ErrCertificateBootstrapInvalidState
	}
	encoded, err := io.ReadAll(io.LimitReader(resp.Body, manager.config.MaxBodyBytes+1))
	if err != nil || int64(len(encoded)) > manager.config.MaxBodyBytes {
		return bootstrapResponse{}, ErrCertificateBootstrapInvalidState
	}
	if len(encoded) == 0 || encoded[len(encoded)-1] != '\n' || bytes.Contains(encoded[:len(encoded)-1], []byte{'\n'}) {
		return bootstrapResponse{}, ErrCertificateBootstrapInvalidState
	}
	var result bootstrapResponse
	if !decodeCanonicalLine(encoded, &result) {
		return bootstrapResponse{}, ErrCertificateBootstrapInvalidState
	}
	return result, nil
}

func (manager *CertificateManager) validateResponse(response bootstrapResponse, privateKey ed25519.PrivateKey, expectedGeneration uint64, now time.Time) (RuntimeCredential, error) {
	if response.Schema != bootstrapResponseSchema || response.CertificateID == uuid.Nil || response.InstallationID != manager.config.InstallationID || response.Generation != expectedGeneration+1 || response.Serial != hex.EncodeToString(response.CertificateID[:]) || response.Status != "active" || response.Revision != 1 || response.RevokedAt != nil || response.RevocationReason != nil {
		return RuntimeCredential{}, ErrCertificateBootstrapInvalidState
	}
	certDER, err := base64.RawURLEncoding.DecodeString(response.CertificateDER)
	if err != nil {
		return RuntimeCredential{}, ErrCertificateBootstrapInvalidState
	}
	caDER, err := base64.RawURLEncoding.DecodeString(response.CACertificateDER)
	if err != nil {
		return RuntimeCredential{}, ErrCertificateBootstrapInvalidState
	}
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		return RuntimeCredential{}, ErrCertificateBootstrapInvalidState
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return RuntimeCredential{}, ErrCertificateBootstrapInvalidState
	}
	spiffe := "spiffe://cdn-platform/installation/" + manager.config.InstallationID.String()
	if response.SPIFFEID != spiffe || leaf.NotBefore.UTC() != response.NotBefore.UTC() || leaf.NotAfter.UTC() != response.NotAfter.UTC() || leaf.NotAfter.Sub(leaf.NotBefore) != bootstrapMaxLifetime || len(leaf.DNSNames) != 0 || leaf.VerifyHostname("invalid") == nil || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		return RuntimeCredential{}, ErrCertificateBootstrapInvalidState
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != spiffe {
		return RuntimeCredential{}, ErrCertificateBootstrapInvalidState
	}
	pub, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok || !bytes.Equal(pub, leaf.PublicKey.(ed25519.PublicKey)) {
		return RuntimeCredential{}, ErrCertificateBootstrapInvalidState
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: x509.NewCertPool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: now}); err != nil {
		return RuntimeCredential{}, ErrCertificateBootstrapInvalidState
	}
	return RuntimeCredential{CertificateID: response.CertificateID, PrivateKey: append(ed25519.PrivateKey(nil), privateKey...), TLSCertificate: tls.Certificate{Certificate: [][]byte{certDER, caDER}, PrivateKey: append(ed25519.PrivateKey(nil), privateKey...)}, RootCAs: pool}, nil
}

func (manager *CertificateManager) commitCredential(credential RuntimeCredential, privateKey ed25519.PrivateKey, response bootstrapResponse, pendingName string, now time.Time) error {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: credential.TLSCertificate.Certificate[0]})
	certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: credential.TLSCertificate.Certificate[1]})...)
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return ErrCertificateBootstrapInvalidState
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: credential.TLSCertificate.Certificate[1]})
	if err := atomicBytes(manager.config.CertificateFile, certPEM, 0o644); err != nil {
		return ErrCertificateBootstrapInvalidState
	}
	if err := atomicBytes(manager.config.PrivateKeyFile, keyPEM, 0o600); err != nil {
		return ErrCertificateBootstrapInvalidState
	}
	if err := atomicBytes(manager.config.RuntimeCAFile, caPEM, 0o644); err != nil {
		return ErrCertificateBootstrapInvalidState
	}
	state := committedState{bootstrapStateSchema, "committed", manager.config.InstallationID.String(), response.CertificateID.String(), response.Generation, sha256Hex(certPEM), sha256Hex(keyPEM), sha256Hex(caPEM), response.NotAfter.UTC().Truncate(time.Second).Format(time.RFC3339), now.UTC().Truncate(time.Second).Format(time.RFC3339)}
	if err := atomicWrite(manager.config.StateFile, state, 0o600); err != nil {
		return ErrCertificateBootstrapInvalidState
	}
	if pendingName != "" {
		_ = os.Remove(filepath.Join(filepath.Dir(manager.config.StateFile), pendingName))
	}
	return nil
}

func (manager *CertificateManager) readCommittedState() (committedState, bool, error) {
	if info, err := os.Lstat(manager.config.StateFile); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600) {
		return committedState{}, true, nil
	}
	encoded, err := os.ReadFile(manager.config.StateFile)
	if errors.Is(err, os.ErrNotExist) {
		return committedState{}, false, nil
	}
	if err != nil {
		return committedState{}, false, ErrCertificateBootstrapInvalidState
	}
	var state committedState
	if !decodeCanonicalLine(encoded, &state) {
		var pending pendingState
		if decodeCanonicalLine(encoded, &pending) && pending.Schema == bootstrapStateSchema && pending.Status == "pending" && pending.InstallationID == manager.config.InstallationID.String() {
			return committedState{}, false, nil
		}
		return committedState{}, true, nil
	}
	if state.Status != "committed" || state.Schema != bootstrapStateSchema || state.InstallationID != manager.config.InstallationID.String() {
		var pending pendingState
		if decodeCanonicalLine(encoded, &pending) && pending.Schema == bootstrapStateSchema && pending.Status == "pending" && pending.InstallationID == manager.config.InstallationID.String() {
			return committedState{}, false, nil
		}
		return committedState{}, true, nil
	}
	return state, true, nil
}

func (manager *CertificateManager) loadCommittedCredential(state committedState) (RuntimeCredential, error) {
	for _, path := range []string{manager.config.CertificateFile, manager.config.PrivateKeyFile, manager.config.RuntimeCAFile} {
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return RuntimeCredential{}, ErrCertificateBootstrapInvalidState
		}
		if path == manager.config.PrivateKeyFile && info.Mode().Perm() != 0o600 {
			return RuntimeCredential{}, ErrCertificateBootstrapInvalidState
		}
		if path != manager.config.PrivateKeyFile && info.Mode().Perm() != 0o644 {
			return RuntimeCredential{}, ErrCertificateBootstrapInvalidState
		}
	}
	certPEM, err := os.ReadFile(manager.config.CertificateFile)
	if err != nil || sha256Hex(certPEM) != state.CertificateSHA256 {
		return RuntimeCredential{}, ErrCertificateBootstrapInvalidState
	}
	keyPEM, err := os.ReadFile(manager.config.PrivateKeyFile)
	if err != nil || sha256Hex(keyPEM) != state.PrivateKeySHA256 {
		return RuntimeCredential{}, ErrCertificateBootstrapInvalidState
	}
	caPEM, err := os.ReadFile(manager.config.RuntimeCAFile)
	if err != nil || sha256Hex(caPEM) != state.RuntimeCASHA256 {
		return RuntimeCredential{}, ErrCertificateBootstrapInvalidState
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil || len(pair.Certificate) != 2 {
		return RuntimeCredential{}, ErrCertificateBootstrapInvalidState
	}
	privateKey, ok := pair.PrivateKey.(ed25519.PrivateKey)
	if !ok {
		return RuntimeCredential{}, ErrCertificateBootstrapInvalidState
	}
	if _, err := x509.ParseCertificate(pair.Certificate[0]); err != nil {
		return RuntimeCredential{}, ErrCertificateBootstrapInvalidState
	}
	id, err := uuid.Parse(state.CertificateID)
	if err != nil {
		return RuntimeCredential{}, ErrCertificateBootstrapInvalidState
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return RuntimeCredential{}, ErrCertificateBootstrapInvalidState
	}
	return RuntimeCredential{CertificateID: id, PrivateKey: append(ed25519.PrivateKey(nil), privateKey...), TLSCertificate: pair, RootCAs: roots}, nil
}

func parseEd25519Private(encoded []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(encoded)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, ErrCertificateBootstrapInvalidState
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	private, ok := key.(ed25519.PrivateKey)
	if err != nil || !ok || len(private) != ed25519.PrivateKeySize {
		return nil, ErrCertificateBootstrapInvalidState
	}
	return private, nil
}
func cloneRuntimeCredential(value RuntimeCredential) RuntimeCredential {
	value.PrivateKey = append(ed25519.PrivateKey(nil), value.PrivateKey...)
	value.TLSCertificate = cloneTLSCertificate(value.TLSCertificate)
	if value.RootCAs != nil {
		value.RootCAs = value.RootCAs.Clone()
	}
	return value
}
func cloneTLSCertificate(value tls.Certificate) tls.Certificate {
	clone := value
	clone.Certificate = make([][]byte, len(value.Certificate))
	for i := range value.Certificate {
		clone.Certificate[i] = append([]byte(nil), value.Certificate[i]...)
	}
	if key, ok := value.PrivateKey.(ed25519.PrivateKey); ok {
		clone.PrivateKey = append(ed25519.PrivateKey(nil), key...)
	}
	return clone
}
func decodeCanonicalLine(encoded []byte, target any) bool {
	if len(encoded) < 2 || encoded[len(encoded)-1] != '\n' || bytes.Contains(encoded[:len(encoded)-1], []byte{'\n'}) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded[:len(encoded)-1]))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return false
	}
	var extra any
	return decoder.Decode(&extra) == io.EOF
}
func sha256Hex(value []byte) string { sum := sha256.Sum256(value); return hex.EncodeToString(sum[:]) }
func atomicBytes(path string, value []byte, mode os.FileMode) error {
	temp := path + ".tmp"
	_ = os.Remove(temp)
	file, err := os.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(value); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Chmod(temp, mode); err != nil {
		return err
	}
	if err := os.Rename(temp, path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	err = directory.Sync()
	closeErr := directory.Close()
	if err != nil {
		return err
	}
	return closeErr
}
func atomicWrite(path string, value any, mode os.FileMode) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	return atomicBytes(path, encoded, mode)
}
