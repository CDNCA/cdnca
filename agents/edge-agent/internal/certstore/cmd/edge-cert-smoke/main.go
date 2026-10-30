package main

import (
	"bufio"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/certstore"
)

type evidence struct {
	ExactDomains             bool `json:"exact_domains"`
	WildcardSingleLabel      bool `json:"wildcard_single_label"`
	WildcardMultilevelReject bool `json:"wildcard_multilevel_rejected"`
	FullChain                bool `json:"full_chain"`
	SNIUnmatchedRejected     bool `json:"sni_unmatched_rejected"`
	TLS12                    bool `json:"tls_1_2"`
	TLS13                    bool `json:"tls_1_3"`
	ReloadNewCertificate     bool `json:"reload_new_certificate"`
	ExistingKeepalive        bool `json:"existing_keepalive"`
	WrongKeyRejected         bool `json:"wrong_key_rejected"`
	ExpiredRejected          bool `json:"expired_rejected"`
	WeakKeyRejected          bool `json:"weak_key_rejected"`
	WeakSignatureRejected    bool `json:"weak_signature_rejected"`
	BadConfigKeptLKG         bool `json:"bad_config_kept_lkg"`
	HealthRollbackKeptLKG    bool `json:"health_rollback_kept_lkg"`
	RestartRecovered         bool `json:"restart_recovered"`
	OfflineServing           bool `json:"offline_serving"`
	ConcurrentHandshakes     int  `json:"concurrent_handshakes"`
	PrivateMetadataAbsent    bool `json:"private_metadata_absent"`
}

type hierarchy struct {
	root            *x509.Certificate
	rootKey         crypto.Signer
	rootPEM         []byte
	intermediate    *x509.Certificate
	intermediateKey crypto.Signer
	intermediatePEM []byte
	serial          atomic.Int64
}

type material struct {
	chainPEM   string
	privatePEM string
	leaf       *x509.Certificate
}

type smokeRuntime struct {
	inner               certstore.Runtime
	mu                  sync.Mutex
	corruptNextPrecheck bool
	failNextHealth      bool
}

func (runtime *smokeRuntime) Precheck(ctx context.Context, candidate string) error {
	runtime.mu.Lock()
	corrupt := runtime.corruptNextPrecheck
	runtime.corruptNextPrecheck = false
	runtime.mu.Unlock()
	if corrupt {
		config := filepath.Join(candidate, "nginx.conf")
		if err := os.Chmod(config, 0o600); err != nil {
			return err
		}
		file, err := os.OpenFile(config, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		_, writeErr := file.WriteString("this_directive_is_invalid on;\n")
		closeErr := file.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return runtime.inner.Precheck(ctx, candidate)
}

func (runtime *smokeRuntime) Activate(ctx context.Context, current string) error {
	return runtime.inner.Activate(ctx, current)
}

func (runtime *smokeRuntime) Healthy(ctx context.Context, targets []certstore.HealthTarget) error {
	runtime.mu.Lock()
	fail := runtime.failNextHealth
	runtime.failNextHealth = false
	runtime.mu.Unlock()
	if fail {
		return errors.New("injected health failure")
	}
	return runtime.inner.Healthy(ctx, targets)
}

func (runtime *smokeRuntime) Stop(ctx context.Context, current string) error {
	return runtime.inner.Stop(ctx, current)
}

func main() {
	stateRoot := flag.String("state-root", "", "certificate runtime state root")
	openrestyBinary := flag.String("openresty-bin", "/usr/local/openresty/bin/openresty", "OpenResty binary")
	listenPort := flag.Uint("listen-port", 18443, "TLS listener port")
	flag.Parse()
	if *stateRoot == "" || !filepath.IsAbs(*stateRoot) || *listenPort == 0 || *listenPort > 65535 {
		fail(errors.New("invalid smoke arguments"))
	}
	result, err := run(*stateRoot, *openrestyBinary, uint16(*listenPort))
	if err != nil {
		fail(err)
	}
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fail(err)
	}
	fmt.Println(string(encoded))
}

func run(stateRoot, binary string, port uint16) (evidence, error) {
	now := time.Now().UTC()
	ca, err := newHierarchy(now)
	if err != nil {
		return evidence{}, err
	}
	exactA1, err := ca.issue([]string{"exact-a.test"}, now.Add(-time.Hour), now.Add(6*time.Hour), nil)
	if err != nil {
		return evidence{}, err
	}
	exactA2, err := ca.issue([]string{"exact-a.test"}, now.Add(-time.Hour), now.Add(6*time.Hour), nil)
	if err != nil {
		return evidence{}, err
	}
	exactB, err := ca.issue([]string{"exact-b.test"}, now.Add(-time.Hour), now.Add(6*time.Hour), nil)
	if err != nil {
		return evidence{}, err
	}
	wildcard, err := ca.issue([]string{"*.wild.example.test"}, now.Add(-time.Hour), now.Add(6*time.Hour), nil)
	if err != nil {
		return evidence{}, err
	}
	rootPool := x509.NewCertPool()
	rootPool.AddCert(ca.root)

	config := certstore.RuntimeConfig{StateRoot: stateRoot, ListenAddress: "127.0.0.1", ListenPort: port}
	dialAddress := net.JoinHostPort("127.0.0.1", fmt.Sprint(port))
	openresty, err := certstore.NewOpenRestyRuntime(binary, filepath.Join(stateRoot, "shared", "nginx.pid"), dialAddress)
	if err != nil {
		return evidence{}, err
	}
	runtime := &smokeRuntime{inner: openresty}
	manager, err := certstore.NewManager(config, runtime)
	if err != nil {
		return evidence{}, err
	}
	defer func() {
		stopContext, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer stopCancel()
		_ = openresty.Stop(stopContext, filepath.Join(stateRoot, "current"))
	}()

	bundleV1 := makeBundle("cert-v1", exactA1, exactB, wildcard)
	applyContext, cancelApply := context.WithTimeout(context.Background(), 15*time.Second)
	resultV1, err := manager.Apply(applyContext, bundleV1)
	cancelApply()
	if err != nil || !resultV1.Changed {
		return evidence{}, fmt.Errorf("apply v1: %w", err)
	}

	connectionA, stateA, err := dialVerified(dialAddress, "exact-a.test", rootPool, tls.VersionTLS12, tls.VersionTLS13)
	if err != nil {
		return evidence{}, fmt.Errorf("exact A: %w", err)
	}
	if sha256.Sum256(stateA.PeerCertificates[0].Raw) != sha256.Sum256(exactA1.leaf.Raw) {
		_ = connectionA.Close()
		return evidence{}, errors.New("exact A selected the wrong certificate")
	}
	_ = connectionA.Close()
	connectionB, stateB, err := dialVerified(dialAddress, "exact-b.test", rootPool, tls.VersionTLS12, tls.VersionTLS13)
	if err != nil {
		return evidence{}, fmt.Errorf("exact B: %w", err)
	}
	if sha256.Sum256(stateB.PeerCertificates[0].Raw) != sha256.Sum256(exactB.leaf.Raw) {
		_ = connectionB.Close()
		return evidence{}, errors.New("exact B selected the wrong certificate")
	}
	_ = connectionB.Close()
	wildConnection, wildState, err := dialVerified(dialAddress, "one.wild.example.test", rootPool, tls.VersionTLS12, tls.VersionTLS13)
	if err != nil {
		return evidence{}, fmt.Errorf("wildcard: %w", err)
	}
	fullChain := len(wildState.PeerCertificates) == 2 && len(wildState.VerifiedChains) == 1 && len(wildState.VerifiedChains[0]) == 3
	_ = wildConnection.Close()
	if !fullChain {
		return evidence{}, errors.New("server did not present a verifiable leaf and intermediate chain")
	}
	if handshakeSucceeds(dialAddress, "two.one.wild.example.test") || handshakeSucceeds(dialAddress, "unknown.test") || handshakeSucceeds(dialAddress, "") {
		return evidence{}, errors.New("unmatched SNI was accepted")
	}
	tls12Connection, tls12State, err := dialVerified(dialAddress, "exact-a.test", rootPool, tls.VersionTLS12, tls.VersionTLS12)
	if err != nil || tls12State.Version != tls.VersionTLS12 {
		return evidence{}, errors.New("TLS 1.2 negotiation failed")
	}
	_ = tls12Connection.Close()
	tls13Connection, tls13State, err := dialVerified(dialAddress, "exact-a.test", rootPool, tls.VersionTLS13, tls.VersionTLS13)
	if err != nil || tls13State.Version != tls.VersionTLS13 {
		return evidence{}, errors.New("TLS 1.3 negotiation failed")
	}
	_ = tls13Connection.Close()

	keepalive, _, err := dialVerified(dialAddress, "exact-a.test", rootPool, tls.VersionTLS12, tls.VersionTLS13)
	if err != nil {
		return evidence{}, err
	}
	reader := bufio.NewReader(keepalive)
	if body, err := requestOnConnection(keepalive, reader, "exact-a.test"); err != nil || body != "certificate-version:cert-v1\n" {
		_ = keepalive.Close()
		return evidence{}, fmt.Errorf("initial keepalive request body=%q error=%v", body, err)
	}
	if err := beginRequestOnConnection(keepalive, "exact-a.test"); err != nil {
		_ = keepalive.Close()
		return evidence{}, fmt.Errorf("begin active keepalive request: %w", err)
	}
	time.Sleep(50 * time.Millisecond)
	bundleV2 := makeBundle("cert-v2", exactA2, exactB, wildcard)
	applyContext, cancelApply = context.WithTimeout(context.Background(), 15*time.Second)
	resultV2, err := manager.Apply(applyContext, bundleV2)
	cancelApply()
	if err != nil || !resultV2.Changed {
		_ = keepalive.Close()
		return evidence{}, fmt.Errorf("apply v2: %w", err)
	}
	keepaliveBody, keepaliveErr := finishRequestOnConnection(keepalive, reader)
	_ = keepalive.Close()
	if keepaliveErr != nil || keepaliveBody != "certificate-version:cert-v1\n" {
		return evidence{}, fmt.Errorf("existing keepalive failed after reload: body=%q error=%v", keepaliveBody, keepaliveErr)
	}
	newConnection, newState, err := dialVerified(dialAddress, "exact-a.test", rootPool, tls.VersionTLS12, tls.VersionTLS13)
	if err != nil {
		return evidence{}, err
	}
	newFingerprint := sha256.Sum256(newState.PeerCertificates[0].Raw)
	newBody, bodyErr := requestOnConnection(newConnection, bufio.NewReader(newConnection), "exact-a.test")
	_ = newConnection.Close()
	if bodyErr != nil || newFingerprint != sha256.Sum256(exactA2.leaf.Raw) || newBody != "certificate-version:cert-v2\n" {
		return evidence{}, fmt.Errorf("new connection did not switch to v2: body=%q error=%v", newBody, bodyErr)
	}

	wrongKey := makeBundle("wrong-key", exactA2, exactB, wildcard)
	wrongKey.Bindings[0].PrivateKeyPEM = exactB.privatePEM
	if _, err := manager.Apply(context.Background(), wrongKey); !errors.Is(err, certstore.ErrInvalidBundle) {
		return evidence{}, fmt.Errorf("wrong key error=%v", err)
	}
	expired, err := ca.issue([]string{"expired.test"}, now.Add(-2*time.Hour), now.Add(-time.Hour), nil)
	if err != nil {
		return evidence{}, err
	}
	if _, err := manager.Apply(context.Background(), singleBundle("expired", "expired", "expired.test", expired)); !errors.Is(err, certstore.ErrInvalidBundle) {
		return evidence{}, fmt.Errorf("expired certificate error=%v", err)
	}
	weakKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return evidence{}, err
	}
	weak, err := ca.issue([]string{"weak.test"}, now.Add(-time.Hour), now.Add(time.Hour), weakKey)
	if err != nil {
		return evidence{}, err
	}
	if _, err := manager.Apply(context.Background(), singleBundle("weak", "weak", "weak.test", weak)); !errors.Is(err, certstore.ErrInvalidBundle) {
		return evidence{}, fmt.Errorf("weak key error=%v", err)
	}
	weakSignature, err := issueSHA1Material(now, "sha1.test")
	if err != nil {
		return evidence{}, err
	}
	if _, err := manager.Apply(context.Background(), singleBundle("sha1", "sha1", "sha1.test", weakSignature)); !errors.Is(err, certstore.ErrInvalidBundle) {
		return evidence{}, fmt.Errorf("weak signature error=%v", err)
	}
	if err := verifyActive(manager, resultV2.ActiveDigest); err != nil {
		return evidence{}, err
	}

	badConfigMaterial, err := ca.issue([]string{"bad-config.test"}, now.Add(-time.Hour), now.Add(time.Hour), nil)
	if err != nil {
		return evidence{}, err
	}
	runtime.mu.Lock()
	runtime.corruptNextPrecheck = true
	runtime.mu.Unlock()
	if _, err := manager.Apply(context.Background(), singleBundle("bad-config", "bad-config", "bad-config.test", badConfigMaterial)); !errors.Is(err, certstore.ErrPrecheck) {
		return evidence{}, fmt.Errorf("bad config error=%v", err)
	}
	if err := assertLeaf(dialAddress, "exact-a.test", rootPool, exactA2.leaf); err != nil {
		return evidence{}, fmt.Errorf("bad config did not preserve LKG: %w", err)
	}

	healthMaterial, err := ca.issue([]string{"health-failure.test"}, now.Add(-time.Hour), now.Add(time.Hour), nil)
	if err != nil {
		return evidence{}, err
	}
	runtime.mu.Lock()
	runtime.failNextHealth = true
	runtime.mu.Unlock()
	if _, err := manager.Apply(context.Background(), singleBundle("health-failure", "health-failure", "health-failure.test", healthMaterial)); !errors.Is(err, certstore.ErrHealth) {
		return evidence{}, fmt.Errorf("health failure error=%v", err)
	}
	if err := assertLeaf(dialAddress, "exact-a.test", rootPool, exactA2.leaf); err != nil {
		return evidence{}, fmt.Errorf("health rollback did not restore LKG: %w", err)
	}

	statusBytes, err := os.ReadFile(filepath.Join(stateRoot, "status.json"))
	if err != nil || strings.Contains(string(statusBytes), "PRIVATE KEY") || strings.Contains(string(statusBytes), "private_key_pem") {
		return evidence{}, errors.New("private key material appeared in status metadata")
	}
	stopContextNow, stopNowCancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := openresty.Stop(stopContextNow, filepath.Join(stateRoot, "current")); err != nil {
		stopNowCancel()
		return evidence{}, fmt.Errorf("stop before recovery: %w", err)
	}
	stopNowCancel()
	restarted, err := certstore.NewManager(config, runtime)
	if err != nil {
		return evidence{}, err
	}
	recoverContext, recoverCancel := context.WithTimeout(context.Background(), 15*time.Second)
	_, err = restarted.Recover(recoverContext)
	recoverCancel()
	if err != nil {
		return evidence{}, fmt.Errorf("recover: %w", err)
	}
	if err := assertLeaf(dialAddress, "exact-a.test", rootPool, exactA2.leaf); err != nil {
		return evidence{}, err
	}
	time.Sleep(100 * time.Millisecond)
	if err := assertLeaf(dialAddress, "one.wild.example.test", rootPool, wildcard.leaf); err != nil {
		return evidence{}, fmt.Errorf("offline serving: %w", err)
	}

	const concurrent = 96
	errorsChannel := make(chan error, concurrent)
	var wait sync.WaitGroup
	for index := 0; index < concurrent; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			serverName := "exact-a.test"
			expected := exactA2.leaf
			if index%3 == 1 {
				serverName, expected = "exact-b.test", exactB.leaf
			} else if index%3 == 2 {
				serverName, expected = "one.wild.example.test", wildcard.leaf
			}
			if err := assertLeaf(dialAddress, serverName, rootPool, expected); err != nil {
				errorsChannel <- err
			}
		}(index)
	}
	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		return evidence{}, err
	}

	return evidence{
		ExactDomains: true, WildcardSingleLabel: true, WildcardMultilevelReject: true, FullChain: true,
		SNIUnmatchedRejected: true, TLS12: true, TLS13: true, ReloadNewCertificate: true, ExistingKeepalive: true,
		WrongKeyRejected: true, ExpiredRejected: true, WeakKeyRejected: true, WeakSignatureRejected: true,
		BadConfigKeptLKG: true, HealthRollbackKeptLKG: true, RestartRecovered: true, OfflineServing: true,
		ConcurrentHandshakes: concurrent, PrivateMetadataAbsent: true,
	}, nil
}

func makeBundle(version string, exactA, exactB, wildcard material) certstore.Bundle {
	return certstore.Bundle{SchemaVersion: certstore.SchemaVersion, VersionID: version, Bindings: []certstore.Binding{
		{SiteID: "exact-a", Domains: []string{"exact-a.test"}, CertificateChainPEM: exactA.chainPEM, PrivateKeyPEM: exactA.privatePEM},
		{SiteID: "exact-b", Domains: []string{"exact-b.test"}, CertificateChainPEM: exactB.chainPEM, PrivateKeyPEM: exactB.privatePEM},
		{SiteID: "wildcard", Domains: []string{"*.wild.example.test"}, CertificateChainPEM: wildcard.chainPEM, PrivateKeyPEM: wildcard.privatePEM},
	}}
}

func singleBundle(version, siteID, domain string, value material) certstore.Bundle {
	return certstore.Bundle{SchemaVersion: certstore.SchemaVersion, VersionID: version, Bindings: []certstore.Binding{{
		SiteID: siteID, Domains: []string{domain}, CertificateChainPEM: value.chainPEM, PrivateKeyPEM: value.privatePEM,
	}}}
}

func newHierarchy(now time.Time) (*hierarchy, error) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CDNCA smoke root"},
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature, SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	if err != nil {
		return nil, err
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return nil, err
	}
	intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	intermediateTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "CDNCA smoke intermediate"},
		NotBefore: now.Add(-12 * time.Hour), NotAfter: now.Add(12 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature, SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	intermediateDER, err := x509.CreateCertificate(rand.Reader, intermediateTemplate, root, intermediateKey.Public(), rootKey)
	if err != nil {
		return nil, err
	}
	intermediate, err := x509.ParseCertificate(intermediateDER)
	if err != nil {
		return nil, err
	}
	result := &hierarchy{
		root: root, rootKey: rootKey, rootPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}),
		intermediate: intermediate, intermediateKey: intermediateKey,
		intermediatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intermediateDER}),
	}
	result.serial.Store(100)
	return result, nil
}

func (ca *hierarchy) issue(names []string, notBefore, notAfter time.Time, key crypto.Signer) (material, error) {
	var err error
	if key == nil {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return material{}, err
		}
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(ca.serial.Add(1)), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.intermediate, key.Public(), ca.intermediateKey)
	if err != nil {
		return material{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return material{}, err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return material{}, err
	}
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), ca.intermediatePEM...)
	return material{chainPEM: string(chain), privatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})), leaf: leaf}, nil
}

func issueSHA1Material(now time.Time, domain string) (material, error) {
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return material{}, err
	}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1000), Subject: pkix.Name{CommonName: "SHA1 smoke root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, SignatureAlgorithm: x509.SHA256WithRSA}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	if err != nil {
		return material{}, err
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return material{}, err
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return material{}, err
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(1001), DNSNames: []string{domain}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, SignatureAlgorithm: x509.SHA1WithRSA}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, leafKey.Public(), rootKey)
	if err != nil {
		return material{}, err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return material{}, err
	}
	return material{chainPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})), privatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}))}, nil
}

func dialVerified(address, serverName string, roots *x509.CertPool, minimum, maximum uint16) (*tls.Conn, tls.ConnectionState, error) {
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	connection, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
		RootCAs: roots, ServerName: serverName, MinVersion: minimum, MaxVersion: maximum, NextProtos: []string{"http/1.1"},
	})
	if err != nil {
		return nil, tls.ConnectionState{}, err
	}
	return connection, connection.ConnectionState(), nil
}

func handshakeSucceeds(address, serverName string) bool {
	dialer := &net.Dialer{Timeout: time.Second}
	connection, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
		ServerName: serverName, MinVersion: tls.VersionTLS12, InsecureSkipVerify: true,
	})
	if err == nil {
		_ = connection.Close()
		return true
	}
	return false
}

func requestOnConnection(connection *tls.Conn, reader *bufio.Reader, host string) (string, error) {
	if err := connection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return "", err
	}
	if _, err := fmt.Fprintf(connection, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n\r\n", host); err != nil {
		return "", err
	}
	return readResponse(reader)
}

func beginRequestOnConnection(connection *tls.Conn, host string) error {
	if err := connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	_, err := fmt.Fprintf(connection, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\nX-CDNCA-Smoke:", host)
	return err
}

func finishRequestOnConnection(connection *tls.Conn, reader *bufio.Reader) (string, error) {
	if err := connection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return "", err
	}
	if _, err := connection.Write([]byte(" active\r\n\r\n")); err != nil {
		return "", err
	}
	return readResponse(reader)
}

func readResponse(reader *bufio.Reader) (string, error) {
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return "", err
	}
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", response.StatusCode)
	}
	return string(body), nil
}

func assertLeaf(address, serverName string, roots *x509.CertPool, expected *x509.Certificate) error {
	connection, state, err := dialVerified(address, serverName, roots, tls.VersionTLS12, tls.VersionTLS13)
	if err != nil {
		return err
	}
	defer connection.Close()
	if len(state.PeerCertificates) == 0 || sha256.Sum256(state.PeerCertificates[0].Raw) != sha256.Sum256(expected.Raw) {
		return errors.New("unexpected leaf certificate")
	}
	return nil
}

func verifyActive(manager *certstore.Manager, digest string) error {
	status, err := manager.Status(context.Background())
	if err != nil {
		return err
	}
	if !status.Active || status.Digest != digest {
		return errors.New("rejected candidate changed active certificate status")
	}
	return nil
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
