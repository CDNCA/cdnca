package pluginruntimecomposition

import (
	"crypto/ed25519"
	"testing"

	"github.com/cdnca/cdnca/libs/mtlstunnel"
	"github.com/cdnca/cdnca/libs/mtlstunnel/mtlstunneltest"
)

// 协议 T1：投影客户端经隧道（外层 wss，内层原 TLS 1.3 双向证书）访问真 mTLS 后端，
// 静态证书与证书管理器两条路径都走同一个拨号函数。
func TestProjectionClientThroughMTLSTunnel(t *testing.T) {
	fixture := newProjectionFixture(t)
	defer fixture.close()
	front := mtlstunneltest.Start(t, map[string]string{mtlstunnel.TargetPluginRuntime: fixture.server.Listener.Addr().String()})
	dial := front.Dialer(t, fixture.server.URL, mtlstunnel.TargetPluginRuntime)

	config := fixture.config()
	config.DialContext = dial
	static, err := NewProjectionClient(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := static.Resolve(t.Context(), fixture.request("tunnel-static")); err != nil {
		t.Fatalf("static credential through tunnel: %v", err)
	}

	config.TLSConfig = nil
	config.Credentials = &recordingRuntimeCredentialSource{credential: RuntimeCredential{CertificateID: fixture.certificateID,
		PrivateKey:     append(ed25519.PrivateKey(nil), fixture.clientPrivate...),
		TLSCertificate: cloneTestTLSCertificate(fixture.clientTLS.Certificates[0]), RootCAs: fixture.clientTLS.RootCAs.Clone()}}
	dynamic, err := NewProjectionClient(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dynamic.Resolve(t.Context(), fixture.request("tunnel-dynamic")); err != nil {
		t.Fatalf("dynamic credential through tunnel: %v", err)
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.requests != 2 || !fixture.sawClientCertificate || front.Upgrades.Load() < 2 {
		t.Fatalf("requests=%d mTLS=%t upgrades=%d", fixture.requests, fixture.sawClientCertificate, front.Upgrades.Load())
	}
}
