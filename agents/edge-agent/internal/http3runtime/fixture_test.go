package http3runtime

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestVersionOneFixtureHasNoGeneratorDrift(t *testing.T) {
	fixtureRoot := filepath.Join("..", "..", "..", "..", "edge", "openresty", "http3", "fixtures")
	policyBytes, err := os.ReadFile(filepath.Join(fixtureRoot, "policy-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var policy Policy
	if err := json.Unmarshal(policyBytes, &policy); err != nil {
		t.Fatal(err)
	}
	compiled, err := Compile(policy)
	if err != nil {
		t.Fatal(err)
	}
	if compiled.Digest != "b9231698bc4cd80f65290af764900297321c10d535050e2ae8b62a839ecf230c" || !bytes.Equal(policyBytes, compiled.CanonicalJSON) {
		t.Fatalf("policy fixture drifted: digest=%s", compiled.Digest)
	}
	if bytes.Contains(compiled.NginxConfig, []byte(policy.TLS.CertificateFile)) ||
		bytes.Contains(compiled.NginxConfig, []byte(policy.TLS.PrivateKeyFile)) ||
		!bytes.Contains(compiled.NginxConfig, []byte("ssl_certificate tls/server.crt;")) ||
		!bytes.Contains(compiled.NginxConfig, []byte("ssl_certificate_key tls/server.key;")) ||
		!bytes.Contains(compiled.NginxConfig, []byte("quic_host_key quic-host.key;")) {
		t.Fatalf("Nginx fixture is not bound exclusively to sealed TLS paths:\n%s", compiled.NginxConfig)
	}
	nginxBytes, err := os.ReadFile(filepath.Join(fixtureRoot, "nginx-v1.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(nginxBytes, compiled.NginxConfig) {
		t.Fatal("Nginx fixture drifted from the deterministic compiler")
	}
}
