package gatewayregistry

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

func testCA(t *testing.T, name string) CA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, _ := x509.ParseCertificate(der)
	return CA{Certificate: certificate, Key: key}
}

func csr(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "gw"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestBindingTokenRoundTripAndRejections(t *testing.T) {
	id := uuid.New()
	token, digest, err := newBindingToken(id, strings.Repeat("ab", 16))
	if err != nil {
		t.Fatal(err)
	}
	parsed, ok := parseBindingToken(token)
	if !ok || parsed.GatewayID != id || !secretMatches(parsed.Secret, digest[:]) {
		t.Fatalf("round trip failed: %+v %v", parsed, ok)
	}
	if secretMatches(parsed.Secret+"x", digest[:]) {
		t.Fatal("tampered secret matched")
	}
	parts := strings.Split(token, ".")
	for name, bad := range map[string]string{
		"prefix":       strings.Join(append([]string{"gwt2"}, parts[1:]...), "."),
		"upper id":     strings.Join([]string{parts[0], strings.ToUpper(parts[1]), parts[2], parts[3]}, "."),
		"short fp":     strings.Join([]string{parts[0], parts[1], parts[2][:30], parts[3]}, "."),
		"short secret": strings.Join([]string{parts[0], parts[1], parts[2], parts[3][:20]}, "."),
		"extra part":   token + ".x",
		"empty":        "",
	} {
		if _, ok := parseBindingToken(bad); ok {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestParseCSRKeyTypePerKind(t *testing.T) {
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, _, err := parseCSR(csr(t, edKey), KindClient); err != nil {
		t.Fatalf("client Ed25519: %v", err)
	}
	if _, _, err := parseCSR(csr(t, p256), KindServer); err != nil {
		t.Fatalf("server P-256: %v", err)
	}
	for name, test := range map[string]struct {
		der  []byte
		kind string
	}{
		"client P-256":   {csr(t, p256), KindClient},
		"server Ed25519": {csr(t, edKey), KindServer},
		"server P-384":   {csr(t, p384), KindServer},
		"garbage":        {[]byte{1, 2, 3}, KindClient},
	} {
		if _, _, err := parseCSR(test.der, test.kind); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestSignerIssuesPerGatewayIdentity(t *testing.T) {
	signer := Signer{Client: testCA(t, "client CA"), Server: testCA(t, "root CA")}
	id := uuid.New()
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	request, _, err := parseCSR(csr(t, edKey), KindClient)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	client, err := signer.issue(id, KindClient, "gw2.example.com", request, now)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(client.der)
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != WorkloadURIPrefix+id.String() ||
		len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("client certificate identity = %v %v", leaf.URIs, leaf.ExtKeyUsage)
	}
	if leaf.SerialNumber.Text(16) != client.serial {
		t.Fatalf("serial %s stored as %s", leaf.SerialNumber.Text(16), client.serial)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: poolOf(signer.Client.Certificate), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("client certificate does not chain to the Gateway client CA: %v", err)
	}
	if got := leaf.NotAfter.Sub(now); got < ClientCertTTL-time.Minute || got > ClientCertTTL {
		t.Fatalf("client TTL = %s", got)
	}

	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serverRequest, _, _ := parseCSR(csr(t, p256), KindServer)
	server, err := signer.issue(id, KindServer, "203.0.113.7", serverRequest, now)
	if err != nil {
		t.Fatal(err)
	}
	serverLeaf, _ := x509.ParseCertificate(server.der)
	if _, err := serverLeaf.Verify(x509.VerifyOptions{Roots: poolOf(signer.Server.Certificate), DNSName: "203.0.113.7"}); err != nil {
		t.Fatalf("server certificate for the IP host: %v", err)
	}
	if len(serverLeaf.URIs) != 0 {
		t.Fatal("server certificate must not carry a workload URI")
	}
}

func poolOf(certificate *x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(certificate)
	return pool
}

func TestValidHostAndPort(t *testing.T) {
	for _, host := range []string{"gw.example.com", "203.0.113.7", "2001:db8::1"} {
		if !validHost(host) {
			t.Errorf("%s rejected", host)
		}
	}
	for _, host := range []string{"", "localhost", "GW.example.com", "gw_1.example.com", "-a.example.com", " gw.example.com"} {
		if validHost(host) {
			t.Errorf("%q accepted", host)
		}
	}
	for _, port := range []int{443, 1024, 65535} {
		if !validPort(port) {
			t.Errorf("%d rejected", port)
		}
	}
	for _, port := range []int{0, 80, 1023, 65536} {
		if validPort(port) {
			t.Errorf("%d accepted", port)
		}
	}
}

func TestWindowLimiter(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	limiter := &windowLimiter{limit: 2, window: time.Minute, now: func() time.Time { return now }, seen: map[string][]time.Time{}}
	if !limiter.allow("a") || !limiter.allow("a") || limiter.allow("a") {
		t.Fatal("third attempt in the window was allowed")
	}
	if !limiter.allow("b") {
		t.Fatal("limit leaked across keys")
	}
	now = now.Add(time.Minute)
	if !limiter.allow("a") {
		t.Fatal("window did not slide")
	}
}

func TestBindRejectsBeforeTouchingTheDatabase(t *testing.T) {
	// Pool is nil: every case must be refused before any query.
	signer := Signer{Client: testCA(t, "client"), Server: testCA(t, "root")}
	service := &Service{config: Config{Signer: signer, Now: time.Now,
		Endpoints: RemoteEndpoints{ControlInternalAddress: "control.example.com:9446"}},
		rootFingerprint: RootFingerprint(signer.Server.Certificate.Raw)}
	good, _, _ := newBindingToken(uuid.New(), service.rootFingerprint)
	other, _, _ := newBindingToken(uuid.New(), strings.Repeat("00", 16))
	cases := map[string]BindRequest{
		"malformed token":     {Token: "nope", EnrollmentPort: 21443, AgentPort: 21444},
		"other control plane": {Token: other, EnrollmentPort: 21443, AgentPort: 21444},
		"same ports":          {Token: good, EnrollmentPort: 21443, AgentPort: 21443},
		"privileged port":     {Token: good, EnrollmentPort: 80, AgentPort: 21444},
		"missing CSR":         {Token: good, EnrollmentPort: 21443, AgentPort: 21444},
	}
	for name, request := range cases {
		if _, err := service.Bind(t.Context(), request, "198.51.100.1"); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	service.config.Endpoints = RemoteEndpoints{}
	if _, err := service.Bind(t.Context(), BindRequest{Token: good, EnrollmentPort: 21443, AgentPort: 21444}, ""); err != ErrRemoteAccessDisabled {
		t.Fatalf("closed standalone access: %v", err)
	}
}

func TestBindRouteIsRateLimitedAndAdminRoutesNeedASession(t *testing.T) {
	signer := Signer{Client: testCA(t, "client"), Server: testCA(t, "root")}
	service := &Service{config: Config{Signer: signer, Now: time.Now}, rootFingerprint: RootFingerprint(signer.Server.Certificate.Raw)}
	handler, err := NewHandler(service, func(context.Context, string) (identity.AuthenticatedSession, error) {
		return identity.AuthenticatedSession{}, errors.New("no session")
	})
	if err != nil {
		t.Fatal(err)
	}
	codes := []int{}
	for range BindAttemptsPerMinute + 1 {
		request := httptest.NewRequest(http.MethodPost, "/v1/gateway-bindings/complete", strings.NewReader(`{"token":"x"}`))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		codes = append(codes, response.Code)
	}
	if codes[0] != http.StatusUnauthorized || codes[BindAttemptsPerMinute] != http.StatusTooManyRequests {
		t.Fatalf("bind codes = %v", codes)
	}
	for _, route := range [][2]string{{http.MethodGet, "/v1/admin/gateways"}, {http.MethodPost, "/v1/admin/gateways"},
		{http.MethodDelete, "/v1/admin/gateways/" + uuid.NewString()}} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(route[0], route[1], nil))
		if response.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without session = %d", route[0], route[1], response.Code)
		}
	}
}
