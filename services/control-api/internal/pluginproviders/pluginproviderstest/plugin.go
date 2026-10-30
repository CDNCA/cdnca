// Package pluginproviderstest serves a test third-party provider plugin
// (pluginprovider.FakePlugin behind an httptest TLS server) and seeds its
// materialized declaration, for the PA-22 integration tests.
package pluginproviderstest

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cdnca/cdnca/libs/entitlement/pluginprovider"
	"github.com/cdnca/cdnca/services/control-api/internal/pluginproviders"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// BaseURL is the public base URL the test declarations name; the test HTTP
// client sends every request to the httptest listener instead.
const BaseURL = "https://provider.dnsplus.example/api"

// Plugin is one running test plugin.
type Plugin struct {
	Fake        *pluginprovider.FakePlugin
	Server      *httptest.Server
	Declaration pluginprovider.Declaration
	Content     []byte
	Service     *pluginproviders.Service
}

// Start serves a fake plugin providing kinds, and returns the control plane
// service (signer + test HTTP client) that talks to it.
func Start(t testing.TB, pool *pgxpool.Pool, pluginID string, kinds ...string) *Plugin {
	t.Helper()
	installationPublic, installationPrivate, _ := ed25519.GenerateKey(nil)
	responsePublic, responsePrivate, _ := ed25519.GenerateKey(nil)
	fake := &pluginprovider.FakePlugin{PluginID: pluginID, InstallationKey: installationPublic, ResponseKey: responsePrivate}
	server := httptest.NewTLSServer(fake)
	t.Cleanup(server.Close)
	provides, permissions := []pluginprovider.Provided{}, []string{}
	for _, kind := range kinds {
		provides = append(provides, pluginprovider.Provided{Kind: kind, ProtocolVersion: pluginprovider.ProtocolVersion})
		permissions = append(permissions, pluginprovider.Permission(kind))
	}
	declaration, content, err := pluginprovider.Build(pluginID, "1.0.0", BaseURL,
		base64.RawURLEncoding.EncodeToString(responsePublic), provides, permissions)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := pluginproviders.NewSigner(uuid.New(), installationPrivate)
	if err != nil {
		t.Fatal(err)
	}
	return &Plugin{Fake: fake, Server: server, Declaration: declaration, Content: content,
		Service: &pluginproviders.Service{Store: pluginproviders.NewStore(pool, nil), Signer: signer,
			HTTPClient: TestHTTPClient(server)}}
}

// TestHTTPClient reaches server whatever host the URL names.
func TestHTTPClient(server *httptest.Server) *http.Client {
	base := server.Client().Transport.(*http.Transport)
	transport := base.Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: base.TLSClientConfig.RootCAs, ServerName: "example.com"}
	return &http.Client{Transport: rewrite{base: transport, address: server.Listener.Addr().String()},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

type rewrite struct {
	base    http.RoundTripper
	address string
}

func (r rewrite) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	clone.URL.Host, clone.Host = r.address, r.address
	return r.base.RoundTrip(clone)
}

// Materialize writes the declaration the way artifactsync does (status
// active, contract pending).
func (plugin *Plugin) Materialize(t testing.TB, pool *pgxpool.Pool) {
	t.Helper()
	sum := sha256.Sum256(plugin.Content)
	if _, err := pool.Exec(context.Background(), `INSERT INTO plugin_providers(plugin_id,version,base_url,kinds,declaration,
		declaration_sha256,status,tenant_scope_id,authorization_id,contract_status,materialized_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,'active',$7,$8,'pending',now(),now())`, plugin.Declaration.PluginID,
		plugin.Declaration.Version, plugin.Declaration.BaseURL, plugin.Declaration.Kinds, plugin.Content,
		hex.EncodeToString(sum[:]), uuid.New(), uuid.New()); err != nil {
		t.Fatal(err)
	}
}
