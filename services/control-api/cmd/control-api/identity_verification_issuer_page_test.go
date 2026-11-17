package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identityverificationissuerhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
)

// issuerTestPKI is a CA that signed a 127.0.0.1 server certificate and a
// client certificate, as files (key 0600) and PEM text, plus a key that
// matches neither.
type issuerTestPKI struct {
	certFile, keyFile, caFile string
	certPEM, keyPEM, caPEM    string
	otherKeyPEM               string
	client                    tls.Certificate
	roots                     *x509.CertPool
}

func newIssuerTestPKI(t *testing.T) issuerTestPKI {
	t.Helper()
	now := time.Now()
	key := func() (*ecdsa.PrivateKey, string) {
		value, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(value)
		if err != nil {
			t.Fatal(err)
		}
		return value, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	}
	issue := func(template, parent *x509.Certificate, public, signer any) (*x509.Certificate, string) {
		der, err := x509.CreateCertificate(rand.Reader, template, parent, public, signer)
		if err != nil {
			t.Fatal(err)
		}
		parsed, _ := x509.ParseCertificate(der)
		return parsed, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	caKey, _ := key()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "issuer test ca"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	ca, caPEM := issue(caTemplate, caTemplate, &caKey.PublicKey, caKey)
	serverKey, serverKeyPEM := key()
	_, serverPEM := issue(&x509.Certificate{SerialNumber: big.NewInt(2), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, ca, &serverKey.PublicKey, caKey)
	clientKey, clientKeyPEM := key()
	_, clientPEM := issue(&x509.Certificate{SerialNumber: big.NewInt(3),
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, ca, &clientKey.PublicKey, caKey)
	client, err := tls.X509KeyPair([]byte(clientPEM), []byte(clientKeyPEM))
	if err != nil {
		t.Fatal(err)
	}
	_, otherKeyPEM := key()
	directory := t.TempDir()
	write := func(name, contents string, mode os.FileMode) string {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte(contents), mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	trim := strings.TrimSpace
	return issuerTestPKI{certFile: write("server.crt", serverPEM, 0o644), keyFile: write("server.key", serverKeyPEM, 0o600),
		caFile: write("client-ca.crt", caPEM, 0o644), certPEM: trim(serverPEM), keyPEM: trim(serverKeyPEM), caPEM: trim(caPEM),
		otherKeyPEM: trim(otherKeyPEM), client: client, roots: roots}
}

// issued reports whether an mTLS client gets the issuer handler's answer at address.
func (pki issuerTestPKI) issued(t *testing.T, address string) bool {
	t.Helper()
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: pki.roots, Certificates: []tls.Certificate{pki.client}}}}
	response, err := client.Post("https://"+address+"/issue", "application/json", nil)
	if err != nil {
		return false
	}
	_ = response.Body.Close()
	return response.StatusCode == http.StatusNoContent
}

func issuerTestAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	return address
}

const issuerTestIdentities = "spiffe://control.cdnca.local/workload/kyc/issuer|issuer"

// issuerTestProvider holds the object store values the issuer's KMS client uses.
func issuerTestProvider() identityVerificationProviderEnvironment {
	return identityVerificationProviderEnvironment{ObjectRegion: "us-east-1",
		ObjectAccessKey: []byte("AKIAISSUERTEST"), ObjectSecretKey: []byte("issuer-object-secret")}
}

// issuerTestPage is an issuer saved entirely on the page.
func (pki issuerTestPKI) page(address string) systemusersettings.IdentityVerificationRuntime {
	return systemusersettings.IdentityVerificationRuntime{IssuerEnabled: true, IssuerListenAddress: address,
		IssuerServerCertificate: pki.certPEM, IssuerClientCA: pki.caPEM, IssuerWorkloadIdentities: issuerTestIdentities,
		IssuerServerPrivateKey: []byte(pki.keyPEM)}
}

// issuerTestSettings is a settings store whose revision the test bumps.
type issuerTestSettings struct {
	mu       sync.Mutex
	revision int64
	value    systemusersettings.IdentityVerificationRuntime
}

func (settings *issuerTestSettings) save(value systemusersettings.IdentityVerificationRuntime) {
	settings.mu.Lock()
	defer settings.mu.Unlock()
	settings.revision++
	settings.value = value
}

func (settings *issuerTestSettings) revisionOf(context.Context) (int64, error) {
	settings.mu.Lock()
	defer settings.mu.Unlock()
	return settings.revision, nil
}

func (settings *issuerTestSettings) read(context.Context) (systemusersettings.IdentityVerificationRuntime, error) {
	settings.mu.Lock()
	defer settings.mu.Unlock()
	value := settings.value
	value.IssuerServerPrivateKey = append([]byte(nil), value.IssuerServerPrivateKey...)
	return value, nil
}

// newIssuerTestSupervisor serves a 204 handler in place of the KMS-backed
// issuer handler.
func newIssuerTestSupervisor(t *testing.T, environment identityVerificationIssuerEnvironment,
	settings *issuerTestSettings) *identityVerificationIssuerSupervisor {
	t.Helper()
	supervisor := newIdentityVerificationIssuerSupervisor(environment, issuerTestProvider(), settings.revisionOf, settings.read, time.Now,
		func(identityVerificationIssuerConfig) (http.Handler, error) {
			return http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusNoContent) }), nil
		})
	t.Cleanup(supervisor.Close)
	return supervisor
}

// With IDENTITY_VERIFICATION_ISSUER_ENABLED off the
// other issuer variables are kept as the fallback of the page and the values
// present are still checked.
func TestLoadIdentityVerificationIssuerEnvironmentKeepsFallbackWhenDisabled(t *testing.T) {
	fallback := []string{
		identityVerificationIssuerEnabledEnv + "=false",
		identityVerificationIssuerServerCertEnv + "=/run/identity/server.crt",
		identityVerificationIssuerIdentitiesEnv + "=" + issuerTestIdentities,
	}
	config, err := loadIdentityVerificationIssuerEnvironment(fallback)
	if err != nil || config.Enabled || config.ServerCertificate != "/run/identity/server.crt" ||
		len(config.WorkloadIdentities) != 1 || config.ListenAddress != "" {
		t.Fatalf("disabled issuer environment = %#v, %v", config, err)
	}
	for name, environment := range map[string][]string{
		"malformed identity": replaceIdentityVerificationEnv(fallback, identityVerificationIssuerIdentitiesEnv, "spiffe://a.local/w"),
		"untrimmed path":     replaceIdentityVerificationEnv(fallback, identityVerificationIssuerServerCertEnv, " /run/identity/server.crt"),
		"insecure KMS":       append(append([]string(nil), fallback...), identityVerificationIssuerKMSEndpointEnv+"=http://kms.example.test"),
	} {
		if config, err := loadIdentityVerificationIssuerEnvironment(environment); err == nil {
			t.Errorf("%s: accepted %#v", name, config)
		}
	}
}

// Every issuer value saved on the page wins, the rest comes from the
// environment; the issuer is on when either side turns it on and runs only
// with everything present (including the object store keys KMS uses).
func TestMergeKYCIssuerConfigPageFirstEnvironmentFallback(t *testing.T) {
	pki := newIssuerTestPKI(t)
	environment := identityVerificationIssuerEnvironment{ListenAddress: "127.0.0.1:19443", ServerCertificate: pki.certFile,
		ServerPrivateKey: pki.keyFile, ClientCA: pki.caFile, KMSEndpoint: "https://kms.env.example"}
	page := systemusersettings.IdentityVerificationRuntime{IssuerEnabled: true, IssuerListenAddress: "127.0.0.1:29443",
		IssuerClientCA: pki.caPEM, IssuerWorkloadIdentities: issuerTestIdentities, IssuerServerPrivateKey: []byte(pki.keyPEM)}
	config, enabled, err := mergeKYCIssuerConfig(environment, page, issuerTestProvider())
	if err != nil || !enabled || !config.complete() || !config.pageOverrides {
		t.Fatalf("merged = %v %v %v", enabled, config.complete(), err)
	}
	listener := config.listener
	if listener.ListenAddress != "127.0.0.1:29443" || listener.ServerCertificateFile != pki.certFile || listener.ServerCertificatePEM != nil ||
		string(listener.ServerPrivateKeyPEM) != pki.keyPEM || listener.ServerPrivateKeyFile != "" ||
		string(listener.ClientCAPEM) != pki.caPEM || listener.ClientCAFile != "" || len(config.identities) != 1 ||
		config.kmsEndpoint != "https://kms.env.example" || config.region != "us-east-1" || config.credentials.AccessKeyID != "AKIAISSUERTEST" {
		t.Fatalf("merged config = %+v", config)
	}
	// the page key is a copy: clearing the page leaves the merged key
	clear(page.IssuerServerPrivateKey)
	if string(config.listener.ServerPrivateKeyPEM) != pki.keyPEM {
		t.Fatal("merge aliased the page private key")
	}
	if _, enabled, _ := mergeKYCIssuerConfig(identityVerificationIssuerEnvironment{Enabled: true}, systemusersettings.IdentityVerificationRuntime{}, issuerTestProvider()); !enabled {
		t.Fatal("the environment turned the issuer on, the page must not turn it off")
	}
	if config, enabled, err := mergeKYCIssuerConfig(identityVerificationIssuerEnvironment{}, systemusersettings.IdentityVerificationRuntime{}, issuerTestProvider()); err != nil || enabled || config.complete() {
		t.Fatalf("nothing configured = %v %v %v", enabled, config.complete(), err)
	}
	if config, _, err := mergeKYCIssuerConfig(environment, page, identityVerificationProviderEnvironment{ObjectRegion: "us-east-1"}); err != nil || config.complete() {
		t.Fatalf("without object store keys = %v %v", config.complete(), err)
	}
	page.IssuerWorkloadIdentities = "spiffe://a.local/w"
	if _, _, err := mergeKYCIssuerConfig(environment, page, issuerTestProvider()); err == nil {
		t.Fatal("malformed page workload identities accepted")
	}
}

// A save applies without a restart: a new listen address moves the
// listener, a configuration that cannot be built keeps the running one, and
// turning the page issuer off stops issuing.
func TestIdentityVerificationIssuerSupervisorRebuildsOnSettingsRevision(t *testing.T) {
	pki := newIssuerTestPKI(t)
	settings := &issuerTestSettings{}
	supervisor := newIssuerTestSupervisor(t, identityVerificationIssuerEnvironment{}, settings)
	ctx := t.Context()
	if supervisor.refresh(ctx); supervisor.address() != "" {
		t.Fatal("issuer runs with nothing configured")
	}
	first := issuerTestAddress(t)
	settings.save(pki.page(first))
	supervisor.refresh(ctx)
	if supervisor.address() != first || !pki.issued(t, first) {
		t.Fatalf("page issuer at %q, want %q", supervisor.address(), first)
	}
	second := issuerTestAddress(t)
	settings.save(pki.page(second))
	supervisor.refresh(ctx)
	if supervisor.address() != second || !pki.issued(t, second) || pki.issued(t, first) {
		t.Fatalf("moved issuer at %q, want %q", supervisor.address(), second)
	}
	broken := pki.page(issuerTestAddress(t))
	broken.IssuerServerPrivateKey = []byte(pki.otherKeyPEM)
	settings.save(broken)
	supervisor.refresh(ctx)
	if supervisor.address() != second || !pki.issued(t, second) {
		t.Fatalf("a broken save replaced the running issuer: %q", supervisor.address())
	}
	if err := supervisor.lastError(); err == nil || strings.Contains(err.Error(), "PRIVATE KEY") {
		t.Fatalf("broken save error = %v", err)
	}
	off := pki.page(second)
	off.IssuerEnabled = false
	settings.save(off)
	supervisor.refresh(ctx)
	if supervisor.address() != "" || pki.issued(t, second) {
		t.Fatal("issuer still serving after the page turned it off")
	}
	if err := supervisor.Ready(); err != nil {
		t.Fatalf("page issuer readiness = %v", err)
	}
}

// An issuer the environment declares must come up: a page override that
// breaks it falls back to the environment alone so control-api still starts
// (and the page can be fixed).
func TestIdentityVerificationIssuerSupervisorEnvironmentFallbackFromBrokenPage(t *testing.T) {
	pki := newIssuerTestPKI(t)
	address := issuerTestAddress(t)
	environment := identityVerificationIssuerEnvironment{Enabled: true, ListenAddress: address, ServerCertificate: pki.certFile,
		ServerPrivateKey: pki.keyFile, ClientCA: pki.caFile, WorkloadIdentities: mustIssuerTestIdentities(t)}
	settings := &issuerTestSettings{}
	settings.save(systemusersettings.IdentityVerificationRuntime{IssuerServerPrivateKey: []byte(pki.otherKeyPEM)})
	supervisor := newIssuerTestSupervisor(t, environment, settings)
	supervisor.refresh(t.Context())
	if supervisor.address() != address || !pki.issued(t, address) {
		t.Fatalf("environment issuer at %q, want %q", supervisor.address(), address)
	}
	if supervisor.lastError() == nil {
		t.Fatal("the broken page override was not reported")
	}
	if err := supervisor.Ready(); err != nil {
		t.Fatalf("environment issuer readiness = %v", err)
	}
}

// Readiness: an issuer the environment declares counts (as before); one only
// the page turns on does not, so a page mistake cannot take control-api out
// of service.
func TestIdentityVerificationIssuerSupervisorReadiness(t *testing.T) {
	pki := newIssuerTestPKI(t)
	settings := &issuerTestSettings{}
	incomplete := pki.page(issuerTestAddress(t))
	incomplete.IssuerClientCA = ""
	settings.save(incomplete)
	pageOnly := newIssuerTestSupervisor(t, identityVerificationIssuerEnvironment{}, settings)
	pageOnly.refresh(t.Context())
	if pageOnly.address() != "" || pageOnly.Ready() != nil {
		t.Fatalf("incomplete page issuer: address %q ready %v", pageOnly.address(), pageOnly.Ready())
	}
	declared := newIssuerTestSupervisor(t, identityVerificationIssuerEnvironment{Enabled: true}, &issuerTestSettings{})
	declared.refresh(t.Context())
	if declared.Ready() == nil {
		t.Fatal("a declared issuer that is not serving reports ready")
	}
}

// Run polls the settings revision, so a save is picked up while it runs.
func TestIdentityVerificationIssuerSupervisorRunPicksUpSaves(t *testing.T) {
	pki := newIssuerTestPKI(t)
	settings := &issuerTestSettings{}
	supervisor := newIssuerTestSupervisor(t, identityVerificationIssuerEnvironment{}, settings)
	supervisor.poll = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() { result <- supervisor.Run(ctx) }()
	address := issuerTestAddress(t)
	settings.save(pki.page(address))
	for deadline := time.Now().Add(3 * time.Second); !pki.issued(t, address) && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	if !pki.issued(t, address) {
		t.Fatal("running issuer did not pick up the save")
	}
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("run = %v", err)
	}
	if pki.issued(t, address) {
		t.Fatal("issuer still serving after shutdown")
	}
}

func mustIssuerTestIdentities(t *testing.T) []identityverificationissuerhttp.WorkloadIdentity {
	t.Helper()
	identities, err := parseIdentityVerificationIssuerIdentities(issuerTestIdentities)
	if err != nil {
		t.Fatal(err)
	}
	return identities
}

// The production runtime clears the provider
// environment's secret bytes when it returns; the issuer's KMS credentials
// must not read those zeroed bytes later.
func TestIdentityVerificationIssuerCredentialsSurviveProviderEnvironmentClear(t *testing.T) {
	pki := newIssuerTestPKI(t)
	settings := &issuerTestSettings{}
	settings.save(pki.page(issuerTestAddress(t)))
	provider := issuerTestProvider()
	provider.ObjectSessionToken = []byte("session-token")
	var built identityVerificationIssuerConfig
	supervisor := newIdentityVerificationIssuerSupervisor(identityVerificationIssuerEnvironment{}, provider, settings.revisionOf, settings.read,
		time.Now, func(config identityVerificationIssuerConfig) (http.Handler, error) {
			built = config
			return http.NotFoundHandler(), nil
		})
	t.Cleanup(supervisor.Close)
	provider.clear()
	supervisor.refresh(t.Context())
	credentials := built.credentials
	if credentials.AccessKeyID != "AKIAISSUERTEST" || credentials.SecretAccessKey != "issuer-object-secret" ||
		credentials.SessionToken != "session-token" || credentials.Source != "identity-verification-issuer" {
		t.Fatalf("credentials after clear = %q/%q/%q (%s)", credentials.AccessKeyID,
			credentials.SecretAccessKey, credentials.SessionToken, credentials.Source)
	}
}
