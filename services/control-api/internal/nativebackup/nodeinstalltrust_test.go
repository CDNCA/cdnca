package nativebackup

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testRootPEM      = "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n"
	oldTrustSHA      = "1111111111111111111111111111111111111111111111111111111111111111"
	testInstallation = "00000000-0000-4000-8000-0000000000aa"
)

type trustFixture struct {
	t      *testing.T
	layout Layout
}

func (fixture trustFixture) write(path, content string, mode os.FileMode) {
	fixture.t.Helper()
	target := fixture.layout.Path(path)
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		fixture.t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(content), mode); err != nil {
		fixture.t.Fatal(err)
	}
}

func (fixture trustFixture) read(path string) string {
	fixture.t.Helper()
	content, err := os.ReadFile(fixture.layout.Path(path))
	if err != nil {
		fixture.t.Fatal(err)
	}
	return string(content)
}

func generateExecutionKey(t *testing.T) string {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// newTrustFixture is a restored BaoTa target as btenv3 RetargetPorts leaves
// it: control.env names the direct download port and the private root; the
// trust document, node-install-defaults and runtime-config.js still carry
// the source host's document and digest.
func newTrustFixture(t *testing.T, extraEnvironment string) trustFixture {
	fixture := trustFixture{t: t, layout: Layout{Root: t.TempDir()}}
	fixture.write(ConfigDirectory+"/keys/upgrade/control-execution.pem", generateExecutionKey(t), 0o400)
	fixture.write(ConfigDirectory+"/keys/upgrade/edge-execution.pem", generateExecutionKey(t), 0o400)
	fixture.write(PKIDirectory+"/root-ca-cert.pem", testRootPEM, 0o644)
	fixture.write(ConfigDirectory+"/control.env", "CONTROL_INSTALLATION_ID="+testInstallation+"\n"+
		"CONTROL_UPGRADE_CONTROL_SIGNING_KEY_ID=control-execution-v1\n"+
		"CONTROL_UPGRADE_CONTROL_SIGNING_PRIVATE_KEY_FILE=/etc/cdnca-control/keys/upgrade/control-execution.pem\n"+
		"CONTROL_UPGRADE_EDGE_SIGNING_KEY_ID=edge-execution-v1\n"+
		"CONTROL_UPGRADE_EDGE_SIGNING_PRIVATE_KEY_FILE=/etc/cdnca-control/keys/upgrade/edge-execution.pem\n"+
		"CONTROL_UPGRADE_ARTIFACT_BASE_URL=https://cdnca.com:19445/downloads/edge-agent/upgrades/sha256\n"+
		"CONTROL_UPGRADE_DOWNLOAD_ROOT_CA_FILE=/etc/cdnca-control/keys/pki/root-ca-cert.pem\n"+
		"SIGNER_REVOCATION_CONSUMER_ENABLED=false\n"+extraEnvironment, 0o600)
	fixture.write(DownloadDirectory+"/edge-agent/artifacts.json", `{"version":1,"keys":[`+
		`{"key_id":"release","public_key_pem":"-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----\n"},`+
		`{"key_id":"native-edge-v1","public_key_pem":"-----BEGIN PUBLIC KEY-----\nAQ==\n-----END PUBLIC KEY-----\n"}]}`, 0o644)
	fixture.write(NodeInstallTrustFile, `{"schema":"cdnca.edge-upgrade-trust/v1","download":{"host":"cdnca.com","port":443,"addresses":["198.51.100.7"],"root_ca":"system"}}`+"\n", 0o644)
	fixture.write(NodeInstallDefaultsFile, "upgrade_trust_sha256="+oldTrustSHA+"\n"+
		"gateway_enrollment_address=gateway.cdnca.com:19443\ngateway_address=gateway.cdnca.com:19444\ngateway_server_name=gateway.cdnca.com\n", 0o644)
	fixture.write(WebRuntimeConfigFile, "window.__CDNCA_GATEWAY_ADDRESS__ = \"gateway.cdnca.com:19444\";\n"+
		"window.__CDNCA_NODE_UPGRADE_TRUST_SHA256__ = \""+oldTrustSHA+"\";\n", 0o644)
	return fixture
}

func lookupTable(table map[string][]string) func(context.Context, string) ([]string, error) {
	return func(_ context.Context, name string) ([]string, error) {
		if addresses, ok := table[name]; ok {
			return addresses, nil
		}
		return nil, errors.New("no such host")
	}
}

// splitWithNodeInstaller runs the real install-node.sh split_upgrade_trust
// parser on document, the check every node installer applies.
func splitWithNodeInstaller(t *testing.T, document string) map[string]any {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 is not available")
	}
	source, err := os.ReadFile("../../../../scripts/install-node.sh")
	if err != nil {
		t.Fatal(err)
	}
	_, body, found := strings.Cut(string(source), "<<'PY_UPGRADE_TRUST'\n")
	body, _, closed := strings.Cut(body, "\nPY_UPGRADE_TRUST\n")
	if !found || !closed {
		t.Fatal("cannot extract split_upgrade_trust from install-node.sh")
	}
	output := t.TempDir()
	command := exec.Command("python3", "-", document, output)
	command.Stdin = strings.NewReader(body)
	stdout, err := command.Output()
	if err != nil {
		t.Fatalf("install-node.sh rejected the published trust document: %v", err)
	}
	var facts map[string]any
	if err := json.Unmarshal(stdout, &facts); err != nil {
		t.Fatal(err)
	}
	return facts
}

// fix-btenv4: after a migration restore the new control plane republishes the
// node install trust from its own control.env (port profile and root that
// RetargetPorts wrote) and the current resolution, and the copied install
// command (node-install-defaults, runtime-config.js) pins the new digest.
func TestPublishNodeInstallTrustFollowsTheRestoredHost(t *testing.T) {
	fixture := newTrustFixture(t, "")
	result, err := PublishNodeInstallTrust(context.Background(), fixture.layout,
		lookupTable(map[string][]string{"cdnca.com": {"203.0.113.20", "127.0.0.1", "::1"}}))
	if err != nil {
		t.Fatal(err)
	}
	published := fixture.read(NodeInstallTrustFile)
	sum := sha256.Sum256([]byte(published))
	if digest := hex.EncodeToString(sum[:]); digest != result.SHA256 || !result.Changed || digest == oldTrustSHA {
		t.Fatalf("published digest %s, result %+v", digest, result)
	}
	var document nodeInstallTrustDocument
	if err := json.Unmarshal([]byte(published), &document); err != nil {
		t.Fatal(err)
	}
	if document.Download.Host != "cdnca.com" || document.Download.Port != 19445 || document.Download.RootCA != testRootPEM ||
		strings.Join(document.Download.Addresses, ",") != "203.0.113.20" {
		t.Fatalf("download = %+v", document.Download)
	}
	if document.Schema != nodeInstallTrustSchema || document.InstallationID != testInstallation ||
		document.ControlExecution.Keys[0].KeyID != "control-execution-v1" || document.EdgeExecution.Keys[0].KeyID != "edge-execution-v1" ||
		len(document.ArtifactTrust.Keys) != 2 || document.SignerTrustRoot != nil {
		t.Fatalf("document = %+v", document)
	}
	defaults := fixture.read(NodeInstallDefaultsFile)
	if !strings.HasPrefix(defaults, "upgrade_trust_sha256="+result.SHA256+"\n") || !strings.Contains(defaults, "gateway_address=gateway.cdnca.com:19444\n") {
		t.Fatalf("node-install-defaults = %q", defaults)
	}
	runtime := fixture.read(WebRuntimeConfigFile)
	if !strings.Contains(runtime, `window.__CDNCA_NODE_UPGRADE_TRUST_SHA256__ = "`+result.SHA256+`";`) ||
		!strings.Contains(runtime, `window.__CDNCA_GATEWAY_ADDRESS__ = "gateway.cdnca.com:19444";`) || strings.Contains(runtime, oldTrustSHA) {
		t.Fatalf("runtime-config.js = %q", runtime)
	}
	facts := splitWithNodeInstaller(t, fixture.layout.Path(NodeInstallTrustFile))
	if facts["host"] != "cdnca.com" || facts["port"] != float64(19445) || facts["private_root"] != true || facts["installation_id"] != testInstallation {
		t.Fatalf("install-node.sh facts = %v", facts)
	}
	// Unchanged inputs republish byte for byte (verify-migration may run repeatedly).
	again, err := PublishNodeInstallTrust(context.Background(), fixture.layout, lookupTable(map[string][]string{"cdnca.com": {"203.0.113.20"}}))
	if err != nil || again.SHA256 != result.SHA256 || again.Changed {
		t.Fatalf("republish = %+v, %v", again, err)
	}
	// After the DNS switch a later run picks up the new address.
	moved, err := PublishNodeInstallTrust(context.Background(), fixture.layout, lookupTable(map[string][]string{"cdnca.com": {"203.0.113.30"}}))
	if err != nil || moved.SHA256 == result.SHA256 || !moved.Changed || !strings.Contains(fixture.read(NodeInstallDefaultsFile), moved.SHA256) {
		t.Fatalf("after DNS change = %+v, %v", moved, err)
	}
}

// A plain host with a public certificate keeps the node's system root; the
// fresh installer has not written the defaults yet (it does with the digest).
func TestPublishNodeInstallTrustPlainHostAndSignerRoot(t *testing.T) {
	fixture := newTrustFixture(t, "SIGNER_REVOCATION_CONSUMER_ENABLED=true\n"+
		"SIGNER_REVOCATION_CONSUMER_OFFLINE_ROOT_KEY_ID=cdnca-offline-root\n"+
		"SIGNER_REVOCATION_CONSUMER_OFFLINE_ROOT_GENERATION=1\n"+
		"SIGNER_REVOCATION_CONSUMER_OFFLINE_ROOT_PUBLIC_KEY_BASE64="+strings.Repeat("A", 42)+"E\n")
	environment := strings.NewReplacer(":19445/", "/", "CONTROL_UPGRADE_DOWNLOAD_ROOT_CA_FILE=/etc/cdnca-control/keys/pki/root-ca-cert.pem\n", "").
		Replace(fixture.read(ConfigDirectory + "/control.env"))
	fixture.write(ConfigDirectory+"/control.env", environment, 0o600)
	for _, path := range []string{NodeInstallDefaultsFile, WebRuntimeConfigFile, NodeInstallTrustFile} {
		if err := os.Remove(fixture.layout.Path(path)); err != nil {
			t.Fatal(err)
		}
	}
	result, err := PublishNodeInstallTrust(context.Background(), fixture.layout, lookupTable(map[string][]string{"cdnca.com": {"2001:db8::5", "203.0.113.20"}}))
	if err != nil {
		t.Fatal(err)
	}
	var document nodeInstallTrustDocument
	if err := json.Unmarshal([]byte(fixture.read(NodeInstallTrustFile)), &document); err != nil {
		t.Fatal(err)
	}
	if document.Download.Port != 443 || document.Download.RootCA != "system" || strings.Join(document.Download.Addresses, ",") != "2001:db8::5,203.0.113.20" {
		t.Fatalf("download = %+v", document.Download)
	}
	if document.SignerTrustRoot == nil || *document.SignerTrustRoot != (nodeSignerTrustRoot{KeyID: "cdnca-offline-root", Generation: 1, PublicKey: strings.Repeat("A", 42) + "E"}) {
		t.Fatalf("signer_trust_root = %+v", document.SignerTrustRoot)
	}
	for _, path := range []string{NodeInstallDefaultsFile, WebRuntimeConfigFile} {
		if _, err := os.Lstat(fixture.layout.Path(path)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s was created: %v", path, err)
		}
	}
	facts := splitWithNodeInstaller(t, fixture.layout.Path(NodeInstallTrustFile))
	if facts["private_root"] != false || facts["port"] != float64(443) || facts["signer_trust_root"] == nil || result.SHA256 == "" {
		t.Fatalf("install-node.sh facts = %v", facts)
	}
}

// psqlExecutor answers verify-migration's two psql queries.
type psqlExecutor struct{}

func (psqlExecutor) Run(_ context.Context, command Command) error {
	query := command.Args[len(command.Args)-1]
	answer := "2,2"
	if strings.Contains(query, "schema_migrations") {
		answer = "61"
	}
	_, err := command.Stdout.Write([]byte(answer + "\n"))
	return err
}

type readyTransport struct{}

func (readyTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Request: request}, nil
}

// fix-btenv4: verify-migration (run by migrate-to and install-control.sh
// migrate-from right after the restore, and again after the DNS switch)
// republishes the node install trust once control-api and the Gateway are
// healthy, and reports it for the migration log.
func TestVerifyMigrationRepublishesTheNodeInstallTrust(t *testing.T) {
	fixture := newTrustFixture(t, "CONTROL_VERSION=1.0.35\n")
	fixture.write(NativeRoot+"/current/release.manifest.json", `{"version":"1.0.35","source":{"commit":"abc"}}`, 0o644)
	fixture.write(ConfigDirectory+"/gateway.env", "CDNCA_GATEWAY_AGENT_PUBLIC_ENDPOINT=gateway.cdnca.com:19444\n", 0o600)
	host := &Host{Layout: fixture.layout, Exec: psqlExecutor{}, Database: DefaultDatabaseTarget()}
	// Before the DNS switch the domains still resolve to the old host.
	addresses := map[string][]string{"cdnca.com": {"198.51.100.7"}, "gateway.cdnca.com": {"198.51.100.7"}}
	lookup := func(ctx context.Context, name string) ([]string, error) { return lookupTable(addresses)(ctx, name) }
	verifier := Verifier{Host: host, HTTP: &http.Client{Transport: readyTransport{}}, Lookup: lookup,
		Local: func() ([]string, error) { return []string{"203.0.113.20"}, nil },
		PublishTrust: func(ctx context.Context) (NodeInstallTrust, error) {
			return PublishNodeInstallTrust(ctx, fixture.layout, lookup)
		}}
	manifest := Manifest{Control: ControlFacts{Version: "1.0.35", SchemaVersion: 61}}
	report, err := verifier.Verify(context.Background(), manifest, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	trust := report.NodeInstallTrust
	if trust == nil || trust.Port != 19445 || trust.Host != "cdnca.com" || strings.Join(trust.Addresses, ",") != "198.51.100.7" {
		t.Fatalf("node_install_trust = %+v", trust)
	}
	if !strings.Contains(fixture.read(NodeInstallDefaultsFile), "upgrade_trust_sha256="+trust.SHA256+"\n") ||
		!strings.Contains(fixture.read(WebRuntimeConfigFile), trust.SHA256) {
		t.Fatal("the install command digest does not follow the republished document")
	}
	if message := trust.Message(); !strings.Contains(message, "已重新发布节点安装信任文档") || !strings.Contains(message, trust.SHA256) ||
		!strings.Contains(message, "cdnca.com:19445") {
		t.Fatalf("migration log line = %q", message)
	}
	if !slicesContain(report.Warnings, "切换管理端域名 DNS 后 control-api 最长 10 分钟自动按新地址重新发布") {
		t.Fatalf("warnings = %q", report.Warnings)
	}
	// After the DNS switch the rerun publishes the new host's address.
	addresses = map[string][]string{"cdnca.com": {"203.0.113.20"}, "gateway.cdnca.com": {"203.0.113.20"}}
	again, err := verifier.Verify(context.Background(), manifest, time.Now())
	if err != nil || again.NodeInstallTrust == nil || strings.Join(again.NodeInstallTrust.Addresses, ",") != "203.0.113.20" ||
		again.NodeInstallTrust.SHA256 == trust.SHA256 || slicesContain(again.Warnings, "不是本机") {
		t.Fatalf("after DNS switch = %+v, %v", again, err)
	}
	// A publish failure is a warning; the old document stays.
	verifier.PublishTrust = func(context.Context) (NodeInstallTrust, error) {
		return NodeInstallTrust{}, errors.New("cdnca.com does not resolve")
	}
	failed, err := verifier.Verify(context.Background(), manifest, time.Now())
	if err != nil || failed.NodeInstallTrust != nil || !slicesContain(failed.Warnings, "节点安装信任文档重新发布失败") {
		t.Fatalf("publish failure = %+v, %v", failed, err)
	}
}

func slicesContain(values []string, part string) bool {
	for _, value := range values {
		if strings.Contains(value, part) {
			return true
		}
	}
	return false
}

// Nothing is published when the download policy cannot be built: the old
// document and digests stay as they were.
func TestPublishNodeInstallTrustKeepsTheOldDocumentOnFailure(t *testing.T) {
	cases := map[string]func(trustFixture){
		"unresolvable": func(trustFixture) {},
		"same signing keys": func(fixture trustFixture) {
			fixture.write(ConfigDirectory+"/keys/upgrade/edge-execution.pem", fixture.read(ConfigDirectory+"/keys/upgrade/control-execution.pem"), 0o400)
		},
		"defaults without a digest": func(fixture trustFixture) {
			fixture.write(NodeInstallDefaultsFile, "gateway_address=gateway.cdnca.com:19444\n", 0o644)
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			fixture := newTrustFixture(t, "")
			if err := os.Chmod(fixture.layout.Path(ConfigDirectory+"/keys/upgrade/edge-execution.pem"), 0o600); err != nil {
				t.Fatal(err)
			}
			change(fixture)
			before := fixture.read(NodeInstallTrustFile) + fixture.read(WebRuntimeConfigFile)
			table := map[string][]string{"cdnca.com": {"203.0.113.20"}}
			if name == "unresolvable" {
				table = map[string][]string{"cdnca.com": {"127.0.0.1"}}
			}
			_, err := PublishNodeInstallTrust(context.Background(), fixture.layout, lookupTable(table))
			if err == nil {
				t.Fatal("published without a valid download policy or digest pin")
			}
			if fixture.read(NodeInstallTrustFile)+fixture.read(WebRuntimeConfigFile) != before {
				t.Fatal("a failed publish changed the published files")
			}
		})
	}
}
