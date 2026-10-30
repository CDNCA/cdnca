package marketclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/cdnca/cdnca/libs/marketproto/card"
	"github.com/cdnca/cdnca/libs/mtlstunnel"
	"github.com/cdnca/cdnca/libs/mtlstunnel/mtlstunneltest"
	"github.com/google/uuid"
)

// 协议 T1：MARKET_URL 客户端经隧道注册，市场仍看到安装客户端证书（内层 mTLS 不变）。
func TestRegisterThroughMTLSTunnel(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	f := &fakeMarket{t: t, key: priv, members: map[uuid.UUID]card.Card{}, inbox: map[uuid.UUID][]json.RawMessage{}}
	pool, serverCert, clientCert := pki(t)
	server := httptest.NewUnstartedServer(f.handler())
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}
	server.StartTLS()
	t.Cleanup(server.Close)
	front := mtlstunneltest.Start(t, map[string]string{mtlstunnel.TargetMarketMember: server.Listener.Addr().String()})
	client, err := New(Config{BaseURL: server.URL, RootCAs: pool, MarketKeys: map[string]ed25519.PublicKey{"m1": pub},
		ClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &clientCert, nil },
		DialContext:       front.Dialer(t, server.URL, mtlstunnel.TargetMarketMember)})
	if err != nil {
		t.Fatal(err)
	}
	id, err := client.Register(context.Background(), newIdentity(t), []byte("lease"), "node seller")
	if err != nil || id == uuid.Nil || !f.sawClient || front.Upgrades.Load() == 0 {
		t.Fatalf("id=%s err=%v sawClient=%v upgrades=%d", id, err, f.sawClient, front.Upgrades.Load())
	}
}
