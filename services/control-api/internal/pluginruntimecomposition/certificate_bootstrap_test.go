package pluginruntimecomposition

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
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
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

const (
	bootstrapTestIssuePath       = "/installation/v1/client-certificates:issue"
	bootstrapTestRequestSchema   = "cdnca.installation-client-certificate-issue/v1"
	bootstrapTestResponseSchema  = "cdnca.installation-client-certificate/v1"
	bootstrapTestProofDomain     = "cdnca-installation-client-certificate-issue/v1"
	bootstrapTestStateSchema     = "cdnca.plugin-runtime-client-state/v1"
	bootstrapTestCommittedStatus = "committed"
	bootstrapTestPendingStatus   = "pending"
)

type bootstrapTestIssueBody struct {
	Schema             string    `json:"schema"`
	RequestID          string    `json:"request_id"`
	InstallationID     uuid.UUID `json:"installation_id"`
	ExpectedGeneration uint64    `json:"expected_generation"`
	CSRDER             string    `json:"csr_der"`
	RequestedAt        time.Time `json:"requested_at"`
	Proof              string    `json:"proof"`
}

type bootstrapTestIssueResponse struct {
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

type bootstrapTestPendingState struct {
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

type bootstrapTestCommittedState struct {
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

func TestCertificateManagerIssuesAndPersistsCanonicalRuntimeCredential(t *testing.T) {
	fixture := newCertificateBootstrapFixture(t)
	defer fixture.close()
	manager, err := NewCertificateManager(fixture.config())
	if err != nil {
		t.Fatal(err)
	}
	credential, err := manager.Ensure(t.Context())
	if err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}
	if credential.CertificateID == uuid.Nil || len(credential.PrivateKey) != ed25519.PrivateKeySize ||
		len(credential.TLSCertificate.Certificate) != 2 || credential.TLSCertificate.PrivateKey == nil || credential.RootCAs == nil {
		t.Fatalf("credential = %+v", credential)
	}
	if !bytes.Equal(credential.PrivateKey, credential.TLSCertificate.PrivateKey.(ed25519.PrivateKey)) {
		t.Fatal("RuntimeCredential private keys differ")
	}
	if _, err := manager.GetClientCertificate(&tls.CertificateRequestInfo{}); err != nil {
		t.Fatalf("GetClientCertificate() error = %v", err)
	}
	fixture.mu.Lock()
	requests := append([][]byte(nil), fixture.requests...)
	validRequest := fixture.validRequest
	noCredentials := fixture.sawForbiddenHeaders
	tlsVersion := fixture.tlsVersion
	fixture.mu.Unlock()
	if len(requests) != 1 || !validRequest || !noCredentials || tlsVersion != tls.VersionTLS13 {
		t.Fatalf("requests=%d valid=%t forbidden_headers=%t tls=%d", len(requests), validRequest, noCredentials, tlsVersion)
	}
	if _, err := manager.Ensure(t.Context()); err != nil {
		t.Fatalf("second Ensure() error = %v", err)
	}
	fixture.mu.Lock()
	requestCount := len(fixture.requests)
	fixture.mu.Unlock()
	if requestCount != 1 {
		t.Fatalf("steady-state Ensure issued %d requests", requestCount)
	}
	assertBootstrapFinalFiles(t, fixture, credential)
	assertBootstrapCommittedState(t, fixture, credential)

	credential.PrivateKey[0] ^= 0xff
	private := credential.TLSCertificate.PrivateKey.(ed25519.PrivateKey)
	private[0] ^= 0xff
	if _, err := manager.Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure() after caller clear error = %v", err)
	}
	callback, err := manager.GetClientCertificate(&tls.CertificateRequestInfo{})
	if err != nil || callback == nil || len(callback.Certificate) != 2 {
		t.Fatalf("GetClientCertificate() after caller clear = cert=%v err=%v", callback, err)
	}
	callback.Certificate[0][0] ^= 0xff
	callbackPrivate := callback.PrivateKey.(ed25519.PrivateKey)
	callbackPrivate[0] ^= 0xff
	if next, err := manager.Ensure(t.Context()); err != nil || allZero(next.PrivateKey) {
		t.Fatalf("manager credential was corrupted by caller copy: next=%+v err=%v", next, err)
	}
}

// The issuer stamps NotBefore with its own clock when it signs, which is later than the moment the request was
// prepared whenever issuance crosses a second boundary (slow database, loaded host). The credential must still be
// accepted: it is valid by the time the response arrives.
func TestCertificateManagerAcceptsCertificateIssuedAfterTheRequestSecond(t *testing.T) {
	fixture := newCertificateBootstrapFixture(t)
	defer fixture.close()
	fixture.issueLatency = 2 * time.Second
	manager, err := NewCertificateManager(fixture.config())
	if err != nil {
		t.Fatal(err)
	}
	credential, err := manager.Ensure(t.Context())
	if err != nil {
		t.Fatalf("Ensure() with issuance crossing a second boundary error = %v", err)
	}
	assertBootstrapFinalFiles(t, fixture, credential)
	assertBootstrapCommittedState(t, fixture, credential)
}

func TestCertificateManagerPendingStateReplaysExactRequestAcrossRestart(t *testing.T) {
	fixture := newCertificateBootstrapFixture(t)
	defer fixture.close()
	fixture.status = http.StatusServiceUnavailable
	manager, err := NewCertificateManager(fixture.config())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Ensure(t.Context()); !errors.Is(err, ErrCertificateBootstrapUnavailable) {
		t.Fatalf("first Ensure() error = %v", err)
	}
	pendingBytes := readBootstrapFile(t, fixture.stateFile)
	var pending bootstrapTestPendingState
	assertBootstrapCanonicalLine(t, pendingBytes, &pending)
	if pending.Schema != bootstrapTestStateSchema || pending.Status != bootstrapTestPendingStatus ||
		pending.InstallationID != fixture.installationID.String() || pending.PrivateKeyFile == "" ||
		filepath.Base(pending.PrivateKeyFile) != pending.PrivateKeyFile || pending.ExpectedGeneration != 0 {
		t.Fatalf("pending state = %+v", pending)
	}
	requestBytes, decodeErr := base64.RawURLEncoding.DecodeString(pending.RequestBody)
	if decodeErr != nil || len(requestBytes) == 0 || !bytes.Equal(requestBytes, fixture.requests[0]) {
		t.Fatalf("pending request body does not match POST bytes")
	}
	if got := sha256File(t, filepath.Join(fixture.targetDir, pending.PrivateKeyFile)); got != pending.PrivateKeySHA256 {
		t.Fatalf("pending key digest = %s, state = %s", got, pending.PrivateKeySHA256)
	}
	if mode := fileMode(t, filepath.Join(fixture.targetDir, pending.PrivateKeyFile)); mode != 0o600 {
		t.Fatalf("pending key mode = %o", mode)
	}
	fixture.status = http.StatusCreated
	restarted, err := NewCertificateManager(fixture.config())
	if err != nil {
		t.Fatal(err)
	}
	credential, err := restarted.Ensure(t.Context())
	if err != nil {
		t.Fatalf("restarted Ensure() error = %v", err)
	}
	fixture.mu.Lock()
	requests := append([][]byte(nil), fixture.requests...)
	fixture.mu.Unlock()
	if len(requests) != 2 || !bytes.Equal(requests[0], requests[1]) {
		t.Fatalf("replayed request bytes differ: count=%d equal=%t", len(requests), len(requests) == 2 && bytes.Equal(requests[0], requests[1]))
	}
	if _, err := os.Stat(filepath.Join(fixture.targetDir, pending.PrivateKeyFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending key after commit stat error = %v", err)
	}
	assertBootstrapFinalFiles(t, fixture, credential)
	assertBootstrapCommittedState(t, fixture, credential)
}

func TestCertificateManagerRotatesFiveMinutesEarlyWithSingleFlight(t *testing.T) {
	fixture := newCertificateBootstrapFixture(t)
	defer fixture.close()
	manager, err := NewCertificateManager(fixture.config())
	if err != nil {
		t.Fatal(err)
	}
	first, err := manager.Ensure(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	leaf := parseLeafCertificate(t, first.TLSCertificate)
	fixture.setNow(leaf.NotAfter.Add(-5 * time.Minute))
	fixture.blockResponses = true
	const callers = 8
	results := make(chan RuntimeCredential, callers)
	errorsCh := make(chan error, callers)
	var start sync.WaitGroup
	start.Add(callers)
	for index := 0; index < callers; index++ {
		go func() {
			start.Done()
			start.Wait()
			credential, ensureErr := manager.Ensure(t.Context())
			results <- credential
			errorsCh <- ensureErr
		}()
	}
	<-fixture.responseStarted
	fixture.unblockResponses()
	for index := 0; index < callers; index++ {
		if err := <-errorsCh; err != nil {
			t.Fatalf("rotation Ensure(%d) error = %v", index, err)
		}
	}
	rotated := <-results
	for index := 1; index < callers; index++ {
		credential := <-results
		if credential.CertificateID != rotated.CertificateID || credential.CertificateID == first.CertificateID ||
			!bytes.Equal(credential.PrivateKey, rotated.PrivateKey) {
			t.Fatalf("rotation result %d differs: %+v vs %+v", index, credential, rotated)
		}
	}
	fixture.mu.Lock()
	requestCount := len(fixture.requests)
	fixture.mu.Unlock()
	if requestCount != 2 {
		t.Fatalf("single-flight rotation made %d HTTP requests", requestCount)
	}
}

func TestCertificateManagerMapsBootstrapResponsesAndPreservesPending(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		want   error
	}{
		{name: "bad request", status: http.StatusBadRequest, want: ErrCertificateBootstrapDenied},
		{name: "unauthorized", status: http.StatusUnauthorized, want: ErrCertificateBootstrapDenied},
		{name: "forbidden", status: http.StatusForbidden, want: ErrCertificateBootstrapDenied},
		{name: "not found", status: http.StatusNotFound, want: ErrCertificateBootstrapDenied},
		{name: "conflict", status: http.StatusConflict, want: ErrCertificateBootstrapConflict},
		{name: "rate limited", status: http.StatusTooManyRequests, want: ErrCertificateBootstrapUnavailable},
		{name: "server failure", status: http.StatusInternalServerError, want: ErrCertificateBootstrapUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newCertificateBootstrapFixture(t)
			defer fixture.close()
			fixture.status = test.status
			const secret = "database-password-must-not-escape"
			fixture.errorBody = []byte(`{"code":"` + secret + `"}`)
			manager, err := NewCertificateManager(fixture.config())
			if err != nil {
				t.Fatal(err)
			}
			_, got := manager.Ensure(t.Context())
			if !errors.Is(got, test.want) || strings.Contains(got.Error(), secret) {
				t.Fatalf("Ensure() error = %v, want stable %v without body", got, test.want)
			}
			if test.status == http.StatusConflict || test.status >= 429 {
				if _, statErr := os.Stat(fixture.stateFile); statErr != nil {
					t.Fatalf("pending state was not retained: %v", statErr)
				}
			}
		})
	}
}

func TestCertificateManagerRejectsMalformedSuccessfulResponses(t *testing.T) {
	for _, mode := range []bootstrapTestResponseMode{
		bootstrapResponseMissingLF, bootstrapResponseTrailingBytes, bootstrapResponseUnknownField,
		bootstrapResponseDuplicateField, bootstrapResponseWrongContentType, bootstrapResponseEncoding,
		bootstrapResponseWrongSchema, bootstrapResponseWrongCertificateID, bootstrapResponseWrongInstallationID,
		bootstrapResponseWrongGeneration, bootstrapResponseWrongSerial, bootstrapResponseWrongSPIFFE,
		bootstrapResponseDNSName, bootstrapResponseWrongKey, bootstrapResponseWrongChain,
		bootstrapResponseWrongLifetime, bootstrapResponseWrongStatus, bootstrapResponseWrongRevision,
	} {
		t.Run(mode.String(), func(t *testing.T) {
			fixture := newCertificateBootstrapFixture(t)
			defer fixture.close()
			fixture.responseMode = mode
			manager, err := NewCertificateManager(fixture.config())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := manager.Ensure(t.Context()); !errors.Is(err, ErrCertificateBootstrapInvalidState) {
				t.Fatalf("Ensure() error = %v, want %v", err, ErrCertificateBootstrapInvalidState)
			}
			if _, statErr := os.Stat(fixture.stateFile); statErr != nil {
				t.Fatalf("malformed response did not retain pending journal: %v", statErr)
			}
		})
	}
}

func TestCertificateManagerRejectsUnsafeConfigurationAndLocalState(t *testing.T) {
	fixture := newCertificateBootstrapFixture(t)
	defer fixture.close()
	valid := fixture.config()
	for _, test := range []struct {
		name string
		edit func(*CertificateManagerConfig)
	}{
		{name: "http base URL", edit: func(config *CertificateManagerConfig) {
			config.BaseURL = strings.Replace(config.BaseURL, "https://", "http://", 1)
		}},
		{name: "base path", edit: func(config *CertificateManagerConfig) { config.BaseURL += "/api" }},
		{name: "activation key", edit: func(config *CertificateManagerConfig) { config.ActivationPrivateKey = nil }},
		{name: "installation", edit: func(config *CertificateManagerConfig) { config.InstallationID = uuid.Nil }},
		{name: "clock", edit: func(config *CertificateManagerConfig) { config.Now = nil }},
		{name: "timeout", edit: func(config *CertificateManagerConfig) { config.Timeout = 0 }},
		{name: "body limit", edit: func(config *CertificateManagerConfig) { config.MaxBodyBytes = 0 }},
		{name: "same certificate and key", edit: func(config *CertificateManagerConfig) { config.PrivateKeyFile = config.CertificateFile }},
		{name: "different directories", edit: func(config *CertificateManagerConfig) {
			config.StateFile = filepath.Join(filepath.Dir(config.StateFile), "other", "state.json")
		}},
		{name: "relative certificate", edit: func(config *CertificateManagerConfig) { config.CertificateFile = "certificate.pem" }},
		{name: "unclean path", edit: func(config *CertificateManagerConfig) {
			config.StateFile = filepath.Dir(config.StateFile) + "/sub/../" + filepath.Base(config.StateFile)
		}},
		{name: "bootstrap CA missing", edit: func(config *CertificateManagerConfig) {
			config.BootstrapServerCAFile = filepath.Join(filepath.Dir(config.BootstrapServerCAFile), "missing-ca")
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			test.edit(&candidate)
			if _, err := NewCertificateManager(candidate); !errors.Is(err, ErrCertificateBootstrapInvalidConfiguration) {
				t.Fatalf("NewCertificateManager() error = %v", err)
			}
		})
	}

	manager, err := NewCertificateManager(valid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Ensure(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *certificateBootstrapFixture)
	}{
		{name: "bundle without state", mutate: func(t *testing.T, fixture *certificateBootstrapFixture) {
			if err := os.Remove(fixture.stateFile); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "state symlink", mutate: func(t *testing.T, fixture *certificateBootstrapFixture) { replaceWithSymlink(t, fixture.stateFile) }},
		{name: "certificate symlink", mutate: func(t *testing.T, fixture *certificateBootstrapFixture) {
			replaceWithSymlink(t, fixture.certificateFile)
		}},
		{name: "private mode", mutate: func(t *testing.T, fixture *certificateBootstrapFixture) { chmodFile(t, fixture.privateKeyFile, 0o644) }},
		{name: "certificate mode", mutate: func(t *testing.T, fixture *certificateBootstrapFixture) { chmodFile(t, fixture.certificateFile, 0o600) }},
		{name: "state trailing bytes", mutate: func(t *testing.T, fixture *certificateBootstrapFixture) {
			appendFile(t, fixture.stateFile, []byte("x"))
		}},
		{name: "state digest", mutate: func(t *testing.T, fixture *certificateBootstrapFixture) {
			replaceBytes(t, fixture.stateFile, []byte("0"))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			copyFixture := newCertificateBootstrapFixture(t)
			defer copyFixture.close()
			copyManager, copyErr := NewCertificateManager(copyFixture.config())
			if copyErr != nil {
				t.Fatal(copyErr)
			}
			if _, ensureErr := copyManager.Ensure(t.Context()); ensureErr != nil {
				t.Fatal(ensureErr)
			}
			test.mutate(t, copyFixture)
			reloaded, loadErr := NewCertificateManager(copyFixture.config())
			if loadErr != nil {
				t.Fatalf("NewCertificateManager() error = %v", loadErr)
			}
			if _, ensureErr := reloaded.Ensure(t.Context()); !errors.Is(ensureErr, ErrCertificateBootstrapInvalidState) {
				t.Fatalf("Ensure() error = %v, want %v", ensureErr, ErrCertificateBootstrapInvalidState)
			}
		})
	}
}

type bootstrapTestResponseMode uint8

const (
	bootstrapResponseMissingLF bootstrapTestResponseMode = iota
	bootstrapResponseTrailingBytes
	bootstrapResponseUnknownField
	bootstrapResponseDuplicateField
	bootstrapResponseWrongContentType
	bootstrapResponseEncoding
	bootstrapResponseWrongSchema
	bootstrapResponseWrongCertificateID
	bootstrapResponseWrongInstallationID
	bootstrapResponseWrongGeneration
	bootstrapResponseWrongSerial
	bootstrapResponseWrongSPIFFE
	bootstrapResponseDNSName
	bootstrapResponseWrongKey
	bootstrapResponseWrongChain
	bootstrapResponseWrongLifetime
	bootstrapResponseWrongStatus
	bootstrapResponseWrongRevision
)

func (mode bootstrapTestResponseMode) String() string {
	return [...]string{"missing LF", "trailing bytes", "unknown field", "duplicate field", "content type", "content encoding", "schema", "certificate id", "installation id", "generation", "serial", "SPIFFE", "DNS SAN", "key", "chain", "lifetime", "status", "revision"}[mode]
}

type certificateBootstrapFixture struct {
	t                   *testing.T
	mu                  sync.Mutex
	installationID      uuid.UUID
	activationPrivate   ed25519.PrivateKey
	runtimeCAPrivate    ed25519.PrivateKey
	runtimeCA           *x509.Certificate
	runtimeCADER        []byte
	server              *httptest.Server
	targetDir           string
	bootstrapCADir      string
	bootstrapCAFile     string
	certificateFile     string
	privateKeyFile      string
	runtimeCAFile       string
	stateFile           string
	now                 time.Time
	status              int
	errorBody           []byte
	responseMode        bootstrapTestResponseMode
	issueLatency        time.Duration // the issuer's clock advances by this much before it signs
	blockResponses      bool
	responseStarted     chan struct{}
	responseRelease     chan struct{}
	responseStartOnce   sync.Once
	requests            [][]byte
	validRequest        bool
	sawForbiddenHeaders bool
	tlsVersion          uint16
}

func newCertificateBootstrapFixture(t *testing.T) *certificateBootstrapFixture {
	t.Helper()
	installationID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	activationPublic, activationPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = activationPublic
	runtimeCAPublic, runtimeCAPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 7, 8, 0, 0, 0, time.UTC)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(9001), Subject: pkix.Name{CommonName: "runtime-ca"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, runtimeCAPublic, runtimeCAPrivate)
	if err != nil {
		t.Fatal(err)
	}
	runtimeCA, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	serverCertificate, serverCAFile := bootstrapTestServerCertificate(t, now)
	targetDir := t.TempDir()
	bootstrapCADir := t.TempDir()
	bootstrapCAFile := filepath.Join(bootstrapCADir, "bootstrap-ca.pem")
	if err := os.WriteFile(bootstrapCAFile, serverCAFile, 0o644); err != nil {
		t.Fatal(err)
	}
	fixture := &certificateBootstrapFixture{t: t, installationID: installationID,
		activationPrivate: activationPrivate, runtimeCAPrivate: runtimeCAPrivate, runtimeCA: runtimeCA,
		runtimeCADER: caDER, targetDir: targetDir, bootstrapCADir: bootstrapCADir, bootstrapCAFile: bootstrapCAFile,
		certificateFile: filepath.Join(targetDir, "client-cert.pem"), privateKeyFile: filepath.Join(targetDir, "client-key.pem"),
		runtimeCAFile: filepath.Join(targetDir, "runtime-ca.pem"), stateFile: filepath.Join(targetDir, "client-state.json"), now: now,
		responseStarted: make(chan struct{}), responseRelease: make(chan struct{}), responseMode: bootstrapResponseWrongRevision + 1}
	server := httptest.NewUnstartedServer(http.HandlerFunc(fixture.serveHTTP))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCertificate}}
	server.StartTLS()
	fixture.server = server
	return fixture
}

func (fixture *certificateBootstrapFixture) config() CertificateManagerConfig {
	return CertificateManagerConfig{BaseURL: fixture.server.URL, InstallationID: fixture.installationID,
		ActivationPrivateKey: append(ed25519.PrivateKey(nil), fixture.activationPrivate...), CertificateFile: fixture.certificateFile,
		PrivateKeyFile: fixture.privateKeyFile, RuntimeCAFile: fixture.runtimeCAFile, StateFile: fixture.stateFile,
		BootstrapServerCAFile: fixture.bootstrapCAFile, Now: func() time.Time { fixture.mu.Lock(); defer fixture.mu.Unlock(); return fixture.now },
		Timeout: 2 * time.Second, MaxBodyBytes: 64 << 10}
}

func (fixture *certificateBootstrapFixture) close() {
	if fixture.server != nil {
		fixture.server.Close()
	}
}

func (fixture *certificateBootstrapFixture) setNow(value time.Time) {
	fixture.mu.Lock()
	fixture.now = value.UTC().Truncate(time.Second)
	fixture.mu.Unlock()
}

func (fixture *certificateBootstrapFixture) unblockResponses() {
	select {
	case <-fixture.responseRelease:
	default:
		close(fixture.responseRelease)
	}
}

func (fixture *certificateBootstrapFixture) serveHTTP(response http.ResponseWriter, request *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(request.Body, 1<<20))
	fixture.mu.Lock()
	fixture.requests = append(fixture.requests, append([]byte(nil), body...))
	fixture.tlsVersion = 0
	if request.TLS != nil {
		fixture.tlsVersion = request.TLS.Version
	}
	fixture.sawForbiddenHeaders = request.Header.Get("Authorization") == "" && request.Header.Get("Cookie") == "" &&
		request.Header.Get("Origin") == "" && request.Header.Get("Idempotency-Key") == ""
	fixture.validRequest = fixture.validRequest || fixture.validateRequest(request, body)
	status, errorBody, block := fixture.status, fixture.errorBody, fixture.blockResponses
	mode := fixture.responseMode
	fixture.now = fixture.now.Add(fixture.issueLatency)
	fixture.mu.Unlock()
	if block {
		fixture.responseStartOnce.Do(func() { close(fixture.responseStarted) })
		<-fixture.responseRelease
	}
	if status != 0 && status != http.StatusCreated {
		if len(errorBody) == 0 {
			errorBody = []byte(`{"code":"bootstrap_failure"}`)
		}
		response.WriteHeader(status)
		_, _ = response.Write(errorBody)
		return
	}
	var bodyValue bootstrapTestIssueBody
	if json.Unmarshal(body, &bodyValue) != nil {
		response.WriteHeader(http.StatusBadRequest)
		return
	}
	encoded, err := fixture.responseBytes(bodyValue, mode)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		return
	}
	if mode == bootstrapResponseWrongContentType {
		response.Header().Set("Content-Type", "application/json; charset=utf-8")
	} else {
		response.Header().Set("Content-Type", "application/json")
	}
	if mode == bootstrapResponseEncoding {
		response.Header().Set("Content-Encoding", "gzip")
	}
	response.WriteHeader(http.StatusCreated)
	if mode == bootstrapResponseMissingLF {
		_, _ = response.Write(encoded)
		return
	}
	_, _ = response.Write(append(encoded, '\n'))
	if mode == bootstrapResponseTrailingBytes {
		_, _ = response.Write([]byte("x"))
	}
}

func parseLeafCertificate(t *testing.T, certificate tls.Certificate) *x509.Certificate {
	t.Helper()
	if len(certificate.Certificate) == 0 {
		t.Fatal("certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

func (fixture *certificateBootstrapFixture) validateRequest(request *http.Request, encoded []byte) bool {
	if request.Method != http.MethodPost || request.URL.Path != bootstrapTestIssuePath ||
		request.URL.RawQuery != "" || request.Header.Get("Content-Type") != "application/json" || request.Header.Get("Accept") != "application/json" {
		return false
	}
	var body bootstrapTestIssueBody
	if json.Unmarshal(encoded, &body) != nil {
		return false
	}
	canonical, _ := json.Marshal(body)
	if !bytes.Equal(canonical, encoded) || body.Schema != bootstrapTestRequestSchema || body.InstallationID != fixture.installationID ||
		body.RequestID == "" || body.RequestedAt.Nanosecond() != 0 {
		return false
	}
	csrDER, err := base64.RawURLEncoding.DecodeString(body.CSRDER)
	proof, proofErr := base64.RawURLEncoding.DecodeString(body.Proof)
	if err != nil || proofErr != nil || base64.RawURLEncoding.EncodeToString(csrDER) != body.CSRDER ||
		len(proof) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(proof) != body.Proof {
		return false
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil || csr.CheckSignature() != nil || csr.SignatureAlgorithm != x509.PureEd25519 || len(csr.URIs) != 1 ||
		csr.URIs[0].String() != "spiffe://cdn-platform/installation/"+fixture.installationID.String() || len(csr.DNSNames) != 0 ||
		len(csr.EmailAddresses) != 0 || len(csr.IPAddresses) != 0 {
		return false
	}
	unsigned, _ := json.Marshal(struct {
		Schema             string    `json:"schema"`
		RequestID          string    `json:"request_id"`
		InstallationID     uuid.UUID `json:"installation_id"`
		ExpectedGeneration uint64    `json:"expected_generation"`
		CSRDER             string    `json:"csr_der"`
		RequestedAt        string    `json:"requested_at"`
	}{body.Schema, body.RequestID, body.InstallationID, body.ExpectedGeneration, body.CSRDER, body.RequestedAt.UTC().Format(time.RFC3339)})
	return ed25519.Verify(fixture.activationPrivate.Public().(ed25519.PublicKey), lengthPrefixed(bootstrapTestProofDomain, unsigned), proof)
}

func (fixture *certificateBootstrapFixture) responseBytes(request bootstrapTestIssueBody, mode bootstrapTestResponseMode) ([]byte, error) {
	csrDER, err := base64.RawURLEncoding.DecodeString(request.CSRDER)
	if err != nil {
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, err
	}
	now := fixture.currentNow()
	certificateID := uuid.MustParse("018f47de-0f4a-7c4b-8f3b-f8d51df94b79")
	if request.ExpectedGeneration > 0 {
		certificateID = uuid.MustParse("018f47de-0f4b-7c4b-8f3b-f8d51df94b80")
	}
	publicKey := csr.PublicKey
	if mode == bootstrapResponseWrongKey {
		_, wrongPrivate, _ := ed25519.GenerateKey(rand.Reader)
		publicKey = wrongPrivate.Public()
	}
	spiffeID := "spiffe://cdn-platform/installation/" + fixture.installationID.String()
	if mode == bootstrapResponseWrongSPIFFE {
		spiffeID = "spiffe://cdn-platform/installation/22222222-2222-4222-8222-222222222222"
	}
	leafTemplate := &x509.Certificate{SerialNumber: new(big.Int).SetBytes(certificateID[:]), Subject: pkix.Name{CommonName: spiffeID},
		NotBefore: now, NotAfter: now.Add(15 * time.Minute), URIs: []*url.URL{mustBootstrapURL(spiffeID)},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true}
	if mode == bootstrapResponseDNSName {
		leafTemplate.DNSNames = []string{"wrong.example.test"}
	}
	if mode == bootstrapResponseWrongLifetime {
		leafTemplate.NotAfter = now.Add(14 * time.Minute)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, fixture.runtimeCA, publicKey, fixture.runtimeCAPrivate)
	if err != nil {
		return nil, err
	}
	caDER := fixture.runtimeCADER
	if mode == bootstrapResponseWrongChain {
		_, otherPrivate, _ := ed25519.GenerateKey(rand.Reader)
		otherTemplate := *fixture.runtimeCA
		otherTemplate.SerialNumber = big.NewInt(9002)
		otherTemplate.PublicKey = otherPrivate.Public()
		caDER, err = x509.CreateCertificate(rand.Reader, &otherTemplate, &otherTemplate, otherPrivate.Public(), otherPrivate)
		if err != nil {
			return nil, err
		}
	}
	response := bootstrapTestIssueResponse{Schema: bootstrapTestResponseSchema, CertificateID: certificateID,
		InstallationID: fixture.installationID, Generation: request.ExpectedGeneration + 1, Serial: hex.EncodeToString(certificateID[:]),
		CertificateDER: base64.RawURLEncoding.EncodeToString(leafDER), CACertificateDER: base64.RawURLEncoding.EncodeToString(caDER),
		SPIFFEID: spiffeID, Status: "active", IssuedAt: now, NotBefore: now, NotAfter: now.Add(15 * time.Minute), Revision: 1}
	switch mode {
	case bootstrapResponseWrongSchema:
		response.Schema = "wrong-schema"
	case bootstrapResponseWrongCertificateID:
		response.CertificateID = uuid.MustParse("22222222-2222-4222-8222-222222222222")
	case bootstrapResponseWrongInstallationID:
		response.InstallationID = uuid.MustParse("22222222-2222-4222-8222-222222222222")
	case bootstrapResponseWrongGeneration:
		response.Generation++
	case bootstrapResponseWrongSerial:
		response.Serial = strings.Repeat("0", 32)
	case bootstrapResponseWrongStatus:
		response.Status = "revoked"
	case bootstrapResponseWrongRevision:
		response.Revision = 2
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		return nil, err
	}
	switch mode {
	case bootstrapResponseUnknownField:
		encoded = append(encoded[:len(encoded)-1], []byte(`,"unexpected":true}`)...)
	case bootstrapResponseDuplicateField:
		encoded = append(encoded[:len(encoded)-1], []byte(`,"schema":"duplicate"}`)...)
	}
	return encoded, nil
}

func (fixture *certificateBootstrapFixture) currentNow() time.Time {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return fixture.now
}

func bootstrapTestServerCertificate(t *testing.T, now time.Time) (tls.Certificate, []byte) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(7001), Subject: pkix.Name{CommonName: "bootstrap-server"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), DNSNames: []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func mustBootstrapURL(value string) *url.URL {
	parsed, _ := url.Parse(value)
	return parsed
}

func assertBootstrapFinalFiles(t *testing.T, fixture *certificateBootstrapFixture, credential RuntimeCredential) {
	t.Helper()
	for _, path := range []string{fixture.certificateFile, fixture.privateKeyFile, fixture.runtimeCAFile, fixture.stateFile} {
		if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			t.Fatalf("unsafe final file %s: info=%v err=%v", path, info, err)
		}
	}
	if fileMode(t, fixture.certificateFile) != 0o644 || fileMode(t, fixture.runtimeCAFile) != 0o644 ||
		fileMode(t, fixture.privateKeyFile) != 0o600 || fileMode(t, fixture.stateFile) != 0o600 {
		t.Fatalf("final file modes cert=%o key=%o ca=%o state=%o", fileMode(t, fixture.certificateFile), fileMode(t, fixture.privateKeyFile), fileMode(t, fixture.runtimeCAFile), fileMode(t, fixture.stateFile))
	}
	loaded, err := tls.LoadX509KeyPair(fixture.certificateFile, fixture.privateKeyFile)
	if err != nil || len(loaded.Certificate) != 2 {
		t.Fatalf("stored key pair = certs=%d err=%v", len(loaded.Certificate), err)
	}
	caPool := x509.NewCertPool()
	caBytes := readBootstrapFile(t, fixture.runtimeCAFile)
	if !caPool.AppendCertsFromPEM(caBytes) {
		t.Fatal("stored runtime CA is not PEM")
	}
	if len(credential.TLSCertificate.Certificate) != 2 || !bytes.Equal(credential.TLSCertificate.Certificate[0], loaded.Certificate[0]) {
		t.Fatal("stored certificate differs from returned credential")
	}
}

func assertBootstrapCommittedState(t *testing.T, fixture *certificateBootstrapFixture, credential RuntimeCredential) {
	t.Helper()
	encoded := readBootstrapFile(t, fixture.stateFile)
	var state bootstrapTestCommittedState
	assertBootstrapCanonicalLine(t, encoded, &state)
	leaf := parseLeafCertificate(t, credential.TLSCertificate)
	if state.Schema != bootstrapTestStateSchema || state.Status != bootstrapTestCommittedStatus ||
		state.InstallationID != fixture.installationID.String() || state.CertificateID != credential.CertificateID.String() ||
		state.Generation == 0 || state.CertificateSHA256 != sha256File(t, fixture.certificateFile) ||
		state.PrivateKeySHA256 != sha256File(t, fixture.privateKeyFile) || state.RuntimeCASHA256 != sha256File(t, fixture.runtimeCAFile) ||
		state.NotAfter != leaf.NotAfter.UTC().Truncate(time.Second).Format(time.RFC3339) || state.CommittedAt == "" {
		t.Fatalf("committed state = %+v", state)
	}
}

func assertBootstrapCanonicalLine(t *testing.T, encoded []byte, target any) {
	t.Helper()
	if len(encoded) == 0 || encoded[len(encoded)-1] != '\n' || bytes.Contains(encoded[:len(encoded)-1], []byte("\n")) {
		t.Fatalf("state is not one LF-terminated line: %q", encoded)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded[:len(encoded)-1], &fields); err != nil || fields == nil {
		t.Fatalf("state JSON = %q err=%v", encoded, err)
	}
	if err := json.Unmarshal(encoded[:len(encoded)-1], target); err != nil {
		t.Fatalf("state target = %q err=%v", encoded, err)
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(canonical, encoded[:len(encoded)-1]) {
		t.Fatalf("state is not canonical: %q", encoded)
	}
}

func readBootstrapFile(t *testing.T, path string) []byte {
	t.Helper()
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

func sha256File(t *testing.T, path string) string {
	t.Helper()
	digest := sha256.Sum256(readBootstrapFile(t, path))
	return hex.EncodeToString(digest[:])
}

func chmodFile(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func replaceWithSymlink(t *testing.T, path string) {
	t.Helper()
	backup := path + ".target"
	if err := os.Rename(path, backup); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(backup, path); err != nil {
		t.Fatal(err)
	}
}

func appendFile(t *testing.T, path string, value []byte) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(value); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func replaceBytes(t *testing.T, path string, value []byte) {
	t.Helper()
	if err := os.WriteFile(path, value, 0o600); err != nil {
		t.Fatal(err)
	}
}
