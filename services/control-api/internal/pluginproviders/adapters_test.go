package pluginproviders_test

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/pluginprovider"
	"github.com/cdnca/cdnca/services/control-api/internal/icpquery"
	"github.com/cdnca/cdnca/services/control-api/internal/notificationruntime"
	"github.com/cdnca/cdnca/services/control-api/internal/pluginproviders"
	"github.com/google/uuid"
)

// staticClients serves one plugin client (usability is the store's job,
// covered by the integration tests).
type staticClients struct {
	client *pluginprovider.Client
	usable bool
}

func (clients *staticClients) Client(_ context.Context, _, kind string) (*pluginprovider.Client, error) {
	if !clients.usable || !clients.client.Declaration().Has(kind) {
		return nil, pluginproviders.ErrNotUsable
	}
	return clients.client, nil
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

func startPlugin(t *testing.T, kinds ...string) (*pluginprovider.FakePlugin, *staticClients) {
	t.Helper()
	installationPublic, installationPrivate, _ := ed25519.GenerateKey(nil)
	responsePublic, responsePrivate, _ := ed25519.GenerateKey(nil)
	fake := &pluginprovider.FakePlugin{PluginID: "com.example.notify", InstallationKey: installationPublic, ResponseKey: responsePrivate}
	server := httptest.NewTLSServer(fake)
	t.Cleanup(server.Close)
	provides, permissions := []pluginprovider.Provided{}, []string{}
	for _, kind := range kinds {
		provides = append(provides, pluginprovider.Provided{Kind: kind, ProtocolVersion: "1"})
		permissions = append(permissions, pluginprovider.Permission(kind))
	}
	declaration, _, err := pluginprovider.Build(fake.PluginID, "1.0.0", "https://notify.example.com",
		base64.RawURLEncoding.EncodeToString(responsePublic), provides, permissions)
	if err != nil {
		t.Fatal(err)
	}
	base := server.Client().Transport.(*http.Transport).Clone()
	base.TLSClientConfig = &tls.Config{RootCAs: server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs,
		ServerName: "example.com"}
	signer, _ := pluginproviders.NewSigner(uuid.New(), installationPrivate)
	client, err := pluginprovider.NewClient(declaration, *signer, pluginprovider.Options{HTTPClient: &http.Client{
		Transport: rewrite{base: base, address: server.Listener.Addr().String()}}})
	if err != nil {
		t.Fatal(err)
	}
	return fake, &staticClients{client: client, usable: true}
}

// The SMS plugin is a notificationruntime transport: accepted with the
// plugin's delivery id, idempotent on the outbox key, permanent failure on
// an invalid number, temporary when the plugin is not usable.
func TestSMSTransport(t *testing.T) {
	fake, clients := startPlugin(t, "sms")
	transport := pluginproviders.SMSTransport{Clients: clients, PluginID: fake.PluginID}
	if err := transport.Ready(t.Context()); err != nil {
		t.Fatal(err)
	}
	message := notificationruntime.ProviderMessage{Contact: "+8613900000001", Body: "【cdnca】验证码 654321",
		TemplateID: "verify_code", Params: map[string]string{"code": "654321"}, IdempotencyKey: "outbox-1"}
	first, err := transport.Send(t.Context(), message)
	if err != nil || first.Disposition != notificationruntime.ProviderAccepted || first.ProviderDeliveryID == "" {
		t.Fatalf("send %+v %v", first, err)
	}
	again, _ := transport.Send(t.Context(), message)
	if again.ProviderDeliveryID != first.ProviderDeliveryID || len(fake.Sent) != 1 || fake.Sent[0].Sandbox {
		t.Fatalf("retry sent twice: %+v %+v", again, fake.Sent)
	}
	bad := message
	bad.Contact, bad.IdempotencyKey = "13900000001", "outbox-2"
	if result, _ := transport.Send(t.Context(), bad); result.Disposition != notificationruntime.ProviderPermanentFailure ||
		result.Code != "plugin_invalid_request" {
		t.Fatalf("invalid number %+v", result)
	}
	clients.usable = false
	if result, _ := transport.Send(t.Context(), message); result.Disposition != notificationruntime.ProviderTemporaryFailure {
		t.Fatalf("unusable plugin %+v", result)
	}
	if err := transport.Ready(t.Context()); !errors.Is(err, pluginproviders.ErrNotUsable) {
		t.Fatalf("ready when unusable = %v", err)
	}
}

// The ICP plugin answers like icpquery: filed with licence, unfiled, and a
// plugin that lies about every domain is caught by the contract (see
// libs/entitlement/pluginprovider), not here.
func TestQueryICP(t *testing.T) {
	_, clients := startPlugin(t, "icp")
	now := time.Date(2026, 10, 19, 8, 0, 0, 0, time.UTC)
	filed, err := pluginproviders.QueryICP(t.Context(), clients, "com.example.notify", "www.shop.example.cn", now)
	if err != nil || filed.Status != icpquery.Filed || filed.Licence == "" || filed.Domain != "example.cn" {
		t.Fatalf("filed %+v %v", filed, err)
	}
	unfiled, err := pluginproviders.QueryICP(t.Context(), clients, "com.example.notify", "www.example.com", now)
	if err != nil || unfiled.Status != icpquery.Unfiled || unfiled.Provider != "plugin:com.example.notify" {
		t.Fatalf("unfiled %+v %v", unfiled, err)
	}
	if _, err := pluginproviders.QueryICP(t.Context(), clients, "com.example.notify", "not a host", now); !errors.Is(err, icpquery.ErrInvalidInput) {
		t.Fatalf("invalid host = %v", err)
	}
	clients.usable = false
	if _, err := pluginproviders.QueryICP(t.Context(), clients, "com.example.notify", "www.example.com", now); !errors.Is(err, icpquery.ErrTransport) {
		t.Fatalf("unusable plugin = %v", err)
	}
}

// The mail plugin is the email transport when chosen as the system mail
// sender: accepted with the plugin's message id, idempotent on the outbox
// key, permanent failure on a bad recipient, temporary (never another
// sender) when the plugin is not usable.
func TestMailTransport(t *testing.T) {
	fake, clients := startPlugin(t, "mail")
	transport := pluginproviders.MailTransport{Clients: clients, PluginID: fake.PluginID}
	if err := transport.Ready(t.Context()); err != nil {
		t.Fatal(err)
	}
	message := notificationruntime.ProviderMessage{OutboxID: uuid.New(), Contact: "user@example.com", Subject: "验证码",
		Body: "验证码 654321", ActionURL: "https://console.example.com/reset", IdempotencyKey: "outbox-1", AttemptNumber: 1}
	first, err := transport.Send(t.Context(), message)
	if err != nil || first.Disposition != notificationruntime.ProviderAccepted || first.ProviderDeliveryID == "" {
		t.Fatalf("send %+v %v", first, err)
	}
	again, _ := transport.Send(t.Context(), message)
	if again.ProviderDeliveryID != first.ProviderDeliveryID || len(fake.Mailed) != 1 || fake.Mailed[0].Sandbox ||
		fake.Mailed[0].Text != "验证码 654321\n\nhttps://console.example.com/reset" || fake.Mailed[0].Subject != "验证码" {
		t.Fatalf("retry sent twice or body wrong: %+v %+v", again, fake.Mailed)
	}
	bad := message
	bad.Contact, bad.IdempotencyKey = "not-an-address", "outbox-2"
	if result, _ := transport.Send(t.Context(), bad); result.Disposition != notificationruntime.ProviderPermanentFailure {
		t.Fatalf("bad recipient %+v", result)
	}
	clients.usable = false
	if result, _ := transport.Send(t.Context(), message); result.Disposition != notificationruntime.ProviderTemporaryFailure ||
		result.Code != "plugin_provider_not_usable" {
		t.Fatalf("unusable plugin %+v", result)
	}
	if err := transport.Ready(t.Context()); !errors.Is(err, pluginproviders.ErrNotUsable) {
		t.Fatalf("ready when unusable = %v", err)
	}
}
