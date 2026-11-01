package nativebackup

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const bindNginx = `pid /var/lib/cdnca-control/nginx-runtime/nginx.pid;
http {
    include /etc/cdnca-upgrade/plan-source-nginx.conf;
    keepalive_timeout 65;

    server {
        listen 443 ssl http2;
        server_name _;
        root /data/cdnca-native-root/cdnca/current/static/web;
        ssl_certificate /etc/cdnca-control/keys/pki/public-server.pem;
        ssl_certificate_key /etc/cdnca-control/keys/pki/public-server-key.pem;
        ssl_protocols TLSv1.2 TLSv1.3;

        location = /healthz {
            return 200 "ok\n";
        }
        location ^~ /v1/ {
            proxy_pass http://127.0.0.1:8080;
        }
    }

}
`

type bindPKI struct {
	rootCert, rootKey []byte
	root              *x509.Certificate
	rootSigner        *rsa.PrivateKey
}

func pemKey(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func newBindPKI(t *testing.T) bindPKI {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CDNCA local control root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(3650 * 24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(der)
	der1 := x509.MarshalPKCS1PrivateKey(key)
	return bindPKI{rootCert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		rootKey: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der1}), root: root, rootSigner: key}
}

// leaf issues a server certificate from the root (RSA key in PKCS#1 like openssl genrsa).
func (pki bindPKI) leaf(t *testing.T, dns []string, ips []string, notAfter time.Time) ([]byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter, DNSNames: dns,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	for _, ip := range ips {
		template.IPAddresses = append(template.IPAddresses, net.ParseIP(ip))
	}
	der, err := x509.CreateCertificate(rand.Reader, template, pki.root, &key.PublicKey, pki.rootSigner)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

type bindHost struct {
	fixture  trustFixture
	pki      bindPKI
	env      HostBindEnvironment
	calls    []string
	failOn   string
	resolved []string
}

const bindControlEnv = "PAYMENT_CHANNELS_NOTIFY_BASE=https://203.0.113.10\n" +
	"CDNCA_GATEWAY_LOCAL_ADDRESS=203.0.113.10:19444\n" +
	"CDNCA_GATEWAY_LOCAL_SERVER_NAME=203.0.113.10\n" +
	"CDNCA_GATEWAY_LOCAL_ENROLLMENT_ADDRESS=203.0.113.10:19443\n"

func newBindHost(t *testing.T) *bindHost {
	fixture := newTrustFixture(t, bindControlEnv)
	// A plain (non-BaoTa) host downloading upgrades by IP from the private root.
	fixture.write(ConfigDirectory+"/control.env", strings.Replace(fixture.read(ConfigDirectory+"/control.env"),
		"https://cdnca.com:19445/downloads", "https://203.0.113.10/downloads", 1), 0o600)
	pki := newBindPKI(t)
	fixture.write(PKIDirectory+"/root-ca-cert.pem", string(pki.rootCert), 0o444)
	fixture.write(PKIDirectory+"/root-ca-key.pem", string(pki.rootKey), 0o600)
	fixture.write(DownloadDirectory+"/gateway-ca.pem", string(pki.rootCert), 0o644)
	gatewayCert, gatewayKey := pki.leaf(t, []string{"localhost"}, []string{"203.0.113.10", "127.0.0.1"}, time.Now().Add(800*24*time.Hour))
	fixture.write(PKIDirectory+"/gateway-server.pem", string(gatewayCert), 0o444)
	fixture.write(PKIDirectory+"/gateway-server-key.pem", string(gatewayKey), 0o600)
	fixture.write(ConfigDirectory+"/nginx.conf", bindNginx, 0o644)
	fixture.write(NodeInstallDefaultsFile, "upgrade_trust_sha256="+oldTrustSHA+"\n"+
		"gateway_enrollment_address=203.0.113.10:19443\ngateway_address=203.0.113.10:19444\ngateway_server_name=203.0.113.10\n", 0o644)
	fixture.write(WebRuntimeConfigFile, "window.__CDNCA_GATEWAY_ADDRESS__ = \"203.0.113.10:19444\";\n"+
		"window.__CDNCA_GATEWAY_ENROLLMENT_ADDRESS__ = \"203.0.113.10:19443\";\n"+
		"window.__CDNCA_GATEWAY_SERVER_NAME__ = \"203.0.113.10\";\n"+
		"window.__CDNCA_NODE_UPGRADE_TRUST_SHA256__ = \""+oldTrustSHA+"\";\n"+
		"window.__CDNCA_CONTROL_CA_SHA256__ = \""+sha256Hex(pki.rootCert)+"\";\n", 0o644)
	host := &bindHost{fixture: fixture, pki: pki, resolved: []string{"203.0.113.10"}}
	host.env = HostBindEnvironment{
		Layout: fixture.layout,
		Lookup: func(_ context.Context, name string) ([]string, error) {
			if name != "console.example.com" {
				return nil, errors.New("no such host")
			}
			return host.resolved, nil
		},
		LocalAddresses: func() ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("10.0.0.5")}, nil },
		PortFree:       func(int) bool { return true },
		IssueCertificate: func(_ context.Context, domain, _ string) (string, error) {
			host.calls = append(host.calls, "certbot "+domain)
			cert, key := pki.leaf(t, []string{domain}, nil, time.Now().Add(90*24*time.Hour))
			live := "/etc/letsencrypt/live/" + domain
			fixture.write(live+"/fullchain.pem", string(cert), 0o644)
			fixture.write(live+"/privkey.pem", string(key), 0o600)
			return live, nil
		},
		NginxTest: func(_ context.Context, file string) error {
			host.calls = append(host.calls, "nginx -t")
			if host.failOn == "nginx -t" {
				host.failOn = ""
				return errors.New("emerg")
			}
			return nil
		},
		Service: func(_ context.Context, verb, unit string) error {
			call := verb + " " + unit
			host.calls = append(host.calls, call)
			if call == host.failOn {
				host.failOn = "" // the restored configuration starts again
				return errors.New("failed")
			}
			return nil
		},
		Ready: func(context.Context) error { host.calls = append(host.calls, "ready"); return nil },
		PublishTrust: func(ctx context.Context, layout Layout) (NodeInstallTrust, error) {
			host.calls = append(host.calls, "publish")
			if host.failOn == "publish" {
				return NodeInstallTrust{}, errors.New("publish failed")
			}
			return PublishNodeInstallTrust(ctx, layout, nil)
		},
	}
	return host
}

func (host *bindHost) snapshot() map[string]string {
	files := map[string]string{}
	for _, path := range hostBindFiles() {
		if content, err := os.ReadFile(host.fixture.layout.Path(path)); err == nil {
			files[path] = string(content)
		}
	}
	return files
}

func TestBindDomainRewritesTheInstallation(t *testing.T) {
	host := newBindHost(t)
	result, err := Bind(context.Background(), host.env, HostBindRequest{Domain: "Console.Example.com", GatewayHost: true})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || result.Origin != "https://console.example.com" || result.BackupDir == "" {
		t.Fatalf("result = %+v", result)
	}
	nginx := host.fixture.read(ConfigDirectory + "/nginx.conf")
	// The default server is untouched (IP access, node downloads without SNI).
	if !strings.Contains(nginx, "        server_name _;\n        root /data/cdnca-native-root/cdnca/current/static/web;\n        ssl_certificate /etc/cdnca-control/keys/pki/public-server.pem;") {
		t.Fatalf("default server changed:\n%s", nginx)
	}
	if HostBindDomainFromNginx([]byte(nginx)) != "console.example.com" || strings.Count(nginx, "location ^~ /v1/ {") != 2 ||
		!strings.Contains(nginx, "ssl_certificate "+HostBindCertFile+";") || !strings.Contains(nginx, "ssl_certificate_key "+HostBindKeyFile+";") {
		t.Fatalf("domain server block missing:\n%s", nginx)
	}
	if string(StripHostBindBlock([]byte(nginx))) != bindNginx {
		t.Fatal("stripping the bind block does not give back the installer configuration")
	}
	environment := host.fixture.read(ConfigDirectory + "/control.env")
	for _, want := range []string{"PAYMENT_CHANNELS_NOTIFY_BASE=https://console.example.com\n", "CDNCA_GATEWAY_LOCAL_ADDRESS=console.example.com:19444\n",
		"CDNCA_GATEWAY_LOCAL_SERVER_NAME=console.example.com\n", "CDNCA_GATEWAY_LOCAL_ENROLLMENT_ADDRESS=console.example.com:19443\n",
		// Installed nodes pin the download host: it stays on the IP.
		"CONTROL_UPGRADE_ARTIFACT_BASE_URL=https://203.0.113.10/downloads/edge-agent/upgrades/sha256\n"} {
		if !strings.Contains(environment, want) {
			t.Fatalf("control.env lacks %q:\n%s", want, environment)
		}
	}
	gateway, err := parseCertificatePEM([]byte(host.fixture.read(PKIDirectory + "/gateway-server.pem")))
	if err != nil {
		t.Fatal(err)
	}
	if err := gateway.VerifyHostname("console.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := gateway.VerifyHostname("203.0.113.10"); err != nil {
		t.Fatalf("the Gateway certificate lost its IP SAN: %v", err)
	}
	defaults := host.fixture.read(NodeInstallDefaultsFile)
	if !strings.Contains(defaults, "gateway_address=console.example.com:19444\n") || !strings.Contains(defaults, "gateway_enrollment_address=console.example.com:19443\n") ||
		!strings.Contains(defaults, "gateway_server_name=console.example.com\n") || strings.Contains(defaults, oldTrustSHA) {
		t.Fatalf("node-install-defaults = %s", defaults)
	}
	runtime := host.fixture.read(WebRuntimeConfigFile)
	if !strings.Contains(runtime, `window.__CDNCA_GATEWAY_SERVER_NAME__ = "console.example.com";`) || strings.Contains(runtime, oldTrustSHA) ||
		!strings.Contains(runtime, `window.__CDNCA_NODE_UPGRADE_TRUST_SHA256__ = "`+result.TrustSHA256+`";`) {
		t.Fatalf("runtime-config.js = %s", runtime)
	}
	// The test certificate chains to the private root: the CA pin stays.
	if result.PublicTrusted || !strings.Contains(runtime, `window.__CDNCA_CONTROL_CA_SHA256__ = "`+sha256Hex(host.pki.rootCert)+`";`) {
		t.Fatalf("CA pin wrongly cleared: %s", runtime)
	}
	if hook := host.fixture.read(HostBindRenewalHook); !strings.Contains(hook, `"/etc/letsencrypt/live/console.example.com"`) ||
		!strings.Contains(hook, HostBindCertFile) {
		t.Fatalf("renewal hook = %s", hook)
	}
	want := "certbot console.example.com,nginx -t,reload cdnca-control-web.service,publish,restart cdnca-agent-gateway.service,restart cdnca-control-api.service,ready"
	if got := strings.Join(host.calls, ","); got != want {
		t.Fatalf("calls = %s", got)
	}
	trust := splitWithNodeInstaller(t, host.fixture.layout.Path(NodeInstallTrustFile))
	if trust["host"] != "203.0.113.10" {
		t.Fatalf("the upgrade download host moved: %v", trust)
	}

	// Idempotent: the same domain again changes nothing and requests no certificate.
	before := host.snapshot()
	host.calls = nil
	again, err := Bind(context.Background(), host.env, HostBindRequest{Domain: "console.example.com", GatewayHost: true})
	if err != nil {
		t.Fatal(err)
	}
	if again.Changed || again.BackupDir != "" || strings.Join(host.calls, ",") != "publish" {
		t.Fatalf("second bind = %+v calls %v", again, host.calls)
	}
	after := host.snapshot()
	for path, content := range before {
		if after[path] != content {
			t.Fatalf("second bind changed %s", path)
		}
	}
}

func TestBindDomainRollsBackOnFailure(t *testing.T) {
	for _, step := range []string{"nginx -t", "reload cdnca-control-web.service", "publish", "restart cdnca-agent-gateway.service", "restart cdnca-control-api.service"} {
		t.Run(step, func(t *testing.T) {
			host := newBindHost(t)
			before := host.snapshot()
			host.failOn = step
			_, err := Bind(context.Background(), host.env, HostBindRequest{Domain: "console.example.com", GatewayHost: true})
			if err == nil || !strings.Contains(err.Error(), "rolled back") {
				t.Fatalf("err = %v", err)
			}
			after := host.snapshot()
			for path, content := range before {
				if after[path] != content {
					t.Fatalf("%s was not restored", path)
				}
			}
			for path := range after {
				if _, existed := before[path]; !existed {
					t.Fatalf("%s created by the failed bind was not removed", path)
				}
			}
			// Services touched before the failure are put back on the restored files.
			if step == "restart cdnca-control-api.service" {
				tail := strings.Join(host.calls[len(host.calls)-3:], ",")
				if tail != "reload cdnca-control-web.service,restart cdnca-agent-gateway.service,restart cdnca-control-api.service" {
					t.Fatalf("rollback calls = %v", host.calls)
				}
			}
		})
	}
}

func TestBindDomainPreflight(t *testing.T) {
	host := newBindHost(t)
	before := host.snapshot()
	cases := []struct {
		name    string
		prepare func()
		request HostBindRequest
		want    string
	}{
		{"ip literal", nil, HostBindRequest{Domain: "203.0.113.10"}, "DNS name"},
		{"wildcard", nil, HostBindRequest{Domain: "*.example.com"}, "DNS name"},
		{"not resolving", nil, HostBindRequest{Domain: "other.example.com"}, "does not resolve"},
		{"resolves elsewhere", func() { host.resolved = []string{"203.0.113.10", "198.51.100.9"} }, HostBindRequest{Domain: "console.example.com"}, "not this host"},
		{"port 80 busy", func() { host.env.PortFree = func(int) bool { return false } }, HostBindRequest{Domain: "console.example.com"}, "port 80"},
		{"key without cert", nil, HostBindRequest{Domain: "console.example.com", KeyFile: "/x"}, "together"},
		{"skip dns without cert", nil, HostBindRequest{Domain: "console.example.com", SkipDNSCheck: true}, "needs --cert-file"},
		{"baota", func() { host.fixture.write(HostPortsFile, "ENV=bt\n", 0o644) }, HostBindRequest{Domain: "console.example.com"}, "BaoTa"},
	}
	for _, item := range cases {
		host.resolved = []string{"203.0.113.10"}
		host.env.PortFree = func(int) bool { return true }
		if item.prepare != nil {
			item.prepare()
		}
		_, err := Bind(context.Background(), host.env, item.request)
		if err == nil || !strings.Contains(err.Error(), item.want) {
			t.Fatalf("%s: err = %v", item.name, err)
		}
	}
	// A resolution through a local interface address (NAT: public IP not on the host) is accepted.
	_ = os.Remove(host.fixture.layout.Path(HostPortsFile))
	host.resolved = []string{"10.0.0.5"}
	if _, err := checkResolution(context.Background(), host.env, "console.example.com", "203.0.113.10"); err != nil {
		t.Fatal(err)
	}
	after := host.snapshot()
	for path, content := range before {
		if after[path] != content {
			t.Fatalf("a refused bind changed %s", path)
		}
	}
	if len(host.calls) != 0 {
		t.Fatalf("a refused bind ran %v", host.calls)
	}
}

func TestBindDomainWithCertificateFiles(t *testing.T) {
	host := newBindHost(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "console.example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(30 * 24 * time.Hour), DNSNames: []string{"console.example.com"}}
	der, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	directory := t.TempDir()
	certFile, keyFile := directory+"/cert.pem", directory+"/key.pem"
	_ = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	_ = os.WriteFile(keyFile, pemKey(t, key), 0o600)
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrongKey := directory + "/wrong.pem"
	_ = os.WriteFile(wrongKey, pemKey(t, otherKey), 0o600)
	if _, err := Bind(context.Background(), host.env, HostBindRequest{Domain: "console.example.com", CertFile: certFile, KeyFile: wrongKey}); err == nil ||
		!strings.Contains(err.Error(), "pair") {
		t.Fatalf("mismatched key: %v", err)
	}
	if _, err := Bind(context.Background(), host.env, HostBindRequest{Domain: "admin.example.com", CertFile: certFile, KeyFile: keyFile, SkipDNSCheck: true}); err == nil ||
		!strings.Contains(err.Error(), "does not name") {
		t.Fatalf("wrong SAN: %v", err)
	}
	// Port 80 is not needed with a certificate file; the Gateway stays on the IP when asked.
	host.env.PortFree = func(int) bool { return false }
	result, err := Bind(context.Background(), host.env, HostBindRequest{Domain: "console.example.com", CertFile: certFile, KeyFile: keyFile})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(host.calls, ","), "certbot") || !result.Changed {
		t.Fatalf("calls %v result %+v", host.calls, result)
	}
	if _, err := os.Stat(host.fixture.layout.Path(HostBindRenewalHook)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("an operator certificate outside a certbot lineage must not get a renewal hook")
	}
	if host.fixture.read(HostBindCertFile) != string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) {
		t.Fatal("bind certificate not installed")
	}
}

func TestBindDomainKeepsGatewayWhenAsked(t *testing.T) {
	host := newBindHost(t)
	if _, err := Bind(context.Background(), host.env, HostBindRequest{Domain: "console.example.com", GatewayHost: false}); err != nil {
		t.Fatal(err)
	}
	if environment := host.fixture.read(ConfigDirectory + "/control.env"); !strings.Contains(environment, "CDNCA_GATEWAY_LOCAL_ADDRESS=203.0.113.10:19444\n") ||
		!strings.Contains(environment, "PAYMENT_CHANNELS_NOTIFY_BASE=https://console.example.com\n") {
		t.Fatalf("control.env = %s", environment)
	}
	if defaults := host.fixture.read(NodeInstallDefaultsFile); !strings.Contains(defaults, "gateway_address=203.0.113.10:19444\n") {
		t.Fatalf("defaults = %s", defaults)
	}
}

func TestMergeGatewaySAN(t *testing.T) {
	pki := newBindPKI(t)
	cert, key := pki.leaf(t, []string{"localhost"}, []string{"203.0.113.10", "127.0.0.1"}, time.Now().Add(time.Hour))
	merged, san, err := MergeGatewaySAN(cert, key, pki.rootCert, pki.rootKey, "console.example.com", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(san, ",") != "DNS:localhost,DNS:console.example.com,IP:203.0.113.10,IP:127.0.0.1" {
		t.Fatalf("san = %v", san)
	}
	leaf, _ := parseCertificatePEM(merged)
	if err := leaf.CheckSignatureFrom(pki.root); err != nil {
		t.Fatal(err)
	}
	original, _ := parseCertificatePEM(cert)
	if !leaf.PublicKey.(*rsa.PublicKey).Equal(original.PublicKey) {
		t.Fatal("the Gateway key must not change")
	}
	if again, _, err := MergeGatewaySAN(merged, key, pki.rootCert, pki.rootKey, "console.example.com", time.Now()); err != nil || again != nil {
		t.Fatalf("already covered: %v %v", again != nil, err)
	}
	other := newBindPKI(t)
	if _, _, err := MergeGatewaySAN(cert, key, other.rootCert, other.rootKey, "console.example.com", time.Now()); err == nil {
		t.Fatal("a certificate from another root must be refused")
	}
}

func TestReadHostStatus(t *testing.T) {
	host := newBindHost(t)
	host.fixture.write(PKIDirectory+"/public-server.pem", string(host.fixture.read(PKIDirectory+"/gateway-server.pem")), 0o444)
	status, err := ReadHostStatus(host.fixture.layout)
	if err != nil || status.Origin != "https://203.0.113.10" || status.BoundDomain != "" || status.Default == nil || status.Gateway == nil {
		t.Fatalf("status = %+v err %v", status, err)
	}
	if _, err := Bind(context.Background(), host.env, HostBindRequest{Domain: "console.example.com", GatewayHost: true}); err != nil {
		t.Fatal(err)
	}
	status, err = ReadHostStatus(host.fixture.layout)
	if err != nil || status.BoundDomain != "console.example.com" || status.Public == nil || status.Public.SAN[0] != "DNS:console.example.com" ||
		status.GatewayLocal != "console.example.com:19444" {
		t.Fatalf("status = %+v err %v", status, err)
	}
}

// The domain block Bind writes is the one converge-management-web-nginx.py
// derives again (render_bind), so a later convergence is a no-op for it.
func TestRenderHostBindNginxMatchesTheConvergeScript(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 is not available")
	}
	legacy, err := os.ReadFile("../../../../scripts/native-runtime/testdata/management-web-nginx-631c658a.conf")
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := RenderHostBindNginx(legacy, "console.example.com", HostBindCertFile, HostBindKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	again, err := RenderHostBindNginx(rendered, "console.example.com", HostBindCertFile, HostBindKeyFile)
	if err != nil || string(again) != string(rendered) {
		t.Fatalf("rendering twice differs: %v", err)
	}
	script := `import importlib.util, sys
spec = importlib.util.spec_from_file_location('c', '../../../../scripts/native-runtime/converge-management-web-nginx.py')
c = importlib.util.module_from_spec(spec); spec.loader.exec_module(c)
text = sys.stdin.read()
stripped, bound = c.split_bind(text)
sys.stdout.write(c.render_bind(stripped, bound))`
	command := exec.Command("python3", "-c", script)
	command.Stdin = strings.NewReader(string(rendered))
	output, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	if string(output) != string(rendered) {
		t.Fatalf("converge script renders a different bound block:\n%s", output)
	}
}
