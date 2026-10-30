package pluginprovider_test

import (
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/entitlement/pluginprovider"
)

const pluginID = "com.example.dnsplus"

type harness struct {
	fake        *pluginprovider.FakePlugin
	server      *httptest.Server
	declaration pluginprovider.Declaration
	client      *pluginprovider.Client
}

func newHarness(t *testing.T, kinds ...string) *harness {
	t.Helper()
	installationPublic, installationPrivate, _ := ed25519.GenerateKey(nil)
	responsePublic, responsePrivate, _ := ed25519.GenerateKey(nil)
	fake := &pluginprovider.FakePlugin{PluginID: pluginID, InstallationKey: installationPublic, ResponseKey: responsePrivate}
	server := httptest.NewTLSServer(fake)
	t.Cleanup(server.Close)
	provides := []pluginprovider.Provided{}
	permissions := []string{}
	for _, kind := range kinds {
		provides = append(provides, pluginprovider.Provided{Kind: kind, ProtocolVersion: "1"})
		permissions = append(permissions, pluginprovider.Permission(kind))
	}
	declaration, _, err := pluginprovider.Build(pluginID, "1.0.0", "https://provider.example.com/api", base64.RawURLEncoding.EncodeToString(responsePublic),
		provides, permissions)
	if err != nil {
		t.Fatal(err)
	}
	// The declaration names a public host; the test client reaches the
	// httptest server instead (address policy is tested separately).
	served := declaration
	served.BaseURL = "https://provider.example.com/api"
	transport := server.Client().Transport.(*http.Transport).Clone()
	address := server.Listener.Addr().String()
	transport.DialContext = nil
	transport.DialTLSContext = nil
	transport.TLSClientConfig = &tls.Config{RootCAs: server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs,
		ServerName: "example.com"}
	transport.Proxy = nil
	httpClient := &http.Client{Transport: rewriteTransport{base: transport, address: address},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	client, err := pluginprovider.NewClient(served, pluginprovider.Signer{InstallationID: "inst-1", PrivateKey: installationPrivate},
		pluginprovider.Options{HTTPClient: httpClient})
	if err != nil {
		t.Fatal(err)
	}
	return &harness{fake: fake, server: server, declaration: declaration, client: client}
}

// rewriteTransport sends every request to the httptest listener and keeps
// the declared path (the TLS name check uses the test certificate's SAN).
type rewriteTransport struct {
	base    *http.Transport
	address string
}

func (r rewriteTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	clone.URL.Host = r.address
	clone.Host = r.address
	return r.base.RoundTrip(clone)
}

func TestBuildAndParse(t *testing.T) {
	_, public, _ := ed25519.GenerateKey(nil)
	key := base64.RawURLEncoding.EncodeToString(public.Public().(ed25519.PublicKey))
	provides := []pluginprovider.Provided{{Kind: "dns", ProtocolVersion: "1"}, {Kind: "notify", ProtocolVersion: "1"}}
	declaration, encoded, err := pluginprovider.Build(pluginID, "1.2.0", "https://dns.example.com/v1/", key, provides,
		[]string{"providers.dns.provide", "sites.read"})
	if err != nil || declaration.BaseURL != "https://dns.example.com/v1" || len(declaration.Kinds) != 1 {
		t.Fatalf("build %+v %v", declaration, err)
	}
	parsed, err := pluginprovider.Parse(encoded)
	if err != nil || parsed.PluginID != pluginID || !parsed.Has("dns") || parsed.Has("notify") {
		t.Fatalf("parse %+v %v", parsed, err)
	}
	if _, err := pluginprovider.Parse([]byte(strings.Replace(string(encoded), `"kinds":["dns"]`, `"kinds":["dns","sms"]`, 1))); err == nil {
		t.Fatal("kind without permission parsed")
	}
	cases := map[string]struct {
		base, key   string
		provides    []pluginprovider.Provided
		permissions []string
		want        error
	}{
		"no permission":    {"https://dns.example.com", key, provides[:1], []string{"sites.read"}, pluginprovider.ErrPermission},
		"only notify":      {"https://dns.example.com", key, provides[1:], nil, pluginprovider.ErrNoProviders},
		"payment no perm":  {"https://pay.example.com", key, []pluginprovider.Provided{{Kind: "payment", ProtocolVersion: "1"}}, []string{"providers.dns.provide"}, pluginprovider.ErrPermission},
		"http":             {"http://dns.example.com", key, provides[:1], []string{"providers.dns.provide"}, pluginprovider.ErrInvalid},
		"ip literal":       {"https://203.0.113.5", key, provides[:1], []string{"providers.dns.provide"}, pluginprovider.ErrInvalid},
		"port":             {"https://dns.example.com:8443", key, provides[:1], []string{"providers.dns.provide"}, pluginprovider.ErrInvalid},
		"query":            {"https://dns.example.com/?a=1", key, provides[:1], []string{"providers.dns.provide"}, pluginprovider.ErrInvalid},
		"localhost":        {"https://localhost", key, provides[:1], []string{"providers.dns.provide"}, pluginprovider.ErrInvalid},
		"bad key":          {"https://dns.example.com", "AAAA", provides[:1], []string{"providers.dns.provide"}, pluginprovider.ErrInvalid},
		"protocol version": {"https://dns.example.com", key, []pluginprovider.Provided{{Kind: "dns", ProtocolVersion: "2"}}, []string{"providers.dns.provide"}, pluginprovider.ErrInvalid},
	}
	for name, c := range cases {
		if _, _, err := pluginprovider.Build(pluginID, "1.0.0", c.base, c.key, c.provides, c.permissions); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
}

func caseFailures(report pluginprovider.ContractReport) map[string]string {
	failed := map[string]string{}
	for _, result := range report.Cases {
		if !result.Passed {
			failed[result.Kind+"/"+result.ID] = result.Code
		}
	}
	return failed
}

func TestContractPassesForConformingPlugin(t *testing.T) {
	h := newHarness(t, "dns", "sms", "icp", "payment", "mail")
	report := pluginprovider.RunContract(t.Context(), h.client)
	if !report.Passed || report.Version != pluginprovider.ContractVersion {
		t.Fatalf("contract failed: %v", caseFailures(report))
	}
	kinds := map[string]int{}
	for _, result := range report.Cases {
		kinds[result.Kind]++
	}
	if kinds["dns"] < 10 || kinds["sms"] < 7 || kinds["icp"] < 7 || kinds["payment"] < 15 || kinds["mail"] < 8 {
		t.Fatalf("case counts %v", kinds)
	}
	if len(h.fake.Records(pluginprovider.SandboxZone)) != 0 {
		t.Fatalf("contract left sandbox records: %v", h.fake.Records(pluginprovider.SandboxZone))
	}
	if len(h.fake.Sent) != 1 || h.fake.Sent[0].To != pluginprovider.SandboxPhone || !h.fake.Sent[0].Sandbox {
		t.Fatalf("sandbox sends %+v", h.fake.Sent)
	}
	if len(h.fake.Mailed) != 1 || h.fake.Mailed[0].To != pluginprovider.SandboxMailbox || !h.fake.Mailed[0].Sandbox ||
		h.fake.Mailed[0].HTML == "" || h.fake.Mailed[0].ReplyTo == "" {
		t.Fatalf("sandbox mails %+v", h.fake.Mailed)
	}
}

func TestContractFailsForBrokenOrMaliciousPlugins(t *testing.T) {
	cases := map[string]struct {
		kind      string
		misbehave pluginprovider.Misbehavior
		want      map[string]string
	}{
		"accepts forged requests": {"dns", pluginprovider.Misbehavior{AcceptBadSignature: true},
			map[string]string{"dns/rejects_bad_signature": "accepted_forged_request", "dns/rejects_replayed_nonce": "accepted_forged_request"}},
		"wrong response key": {"icp", pluginprovider.Misbehavior{WrongResponseKey: true},
			map[string]string{"icp/verify": pluginprovider.CodeBadResponseSignature, "icp/filed": pluginprovider.CodeBadResponseSignature}},
		"no idempotency":   {"dns", pluginprovider.Misbehavior{NoIdempotency: true}, map[string]string{"dns/create_idempotent": "idempotency_key_created_twice"}},
		"sms sends twice":  {"sms", pluginprovider.Misbehavior{NoIdempotency: true}, map[string]string{"sms/send_idempotent": "idempotency_key_sent_twice"}},
		"ignores delete":   {"dns", pluginprovider.Misbehavior{IgnoreDelete: true}, map[string]string{"dns/delete_a": "delete_not_applied"}},
		"wrong icp":        {"icp", pluginprovider.Misbehavior{WrongICP: true}, map[string]string{"icp/unfiled": "unfiled_domain_wrong"}},
		"unreachable":      {"sms", pluginprovider.Misbehavior{Unreachable: true}, map[string]string{"sms/verify": pluginprovider.CodeUnavailable}},
		"mail sends twice": {"mail", pluginprovider.Misbehavior{NoIdempotency: true}, map[string]string{"mail/send_idempotent": "idempotency_key_sent_twice"}},
		"mail accepts any recipient": {"mail", pluginprovider.Misbehavior{AcceptBadMailbox: true},
			map[string]string{"mail/invalid_recipient": "invalid_recipient_accepted"}},
		"mail no health": {"mail", pluginprovider.Misbehavior{Unreachable: true}, map[string]string{"mail/health": pluginprovider.CodeUnavailable}},
		// PA-23 payment plugins that would fake "paid".
		"forges paid callbacks": {"payment", pluginprovider.Misbehavior{ForgeCallbackPaid: true},
			map[string]string{"payment/rejects_tampered_callback": "tampered_callback_accepted"}},
		"query always paid": {"payment", pluginprovider.Misbehavior{QueryAlwaysPaid: true},
			map[string]string{"payment/query_unpaid": "unpaid_reported_paid"}},
		"wrong amount": {"payment", pluginprovider.Misbehavior{WrongAmount: true},
			map[string]string{"payment/create_checkout": "checkout_not_bound"}},
		"refunds twice": {"payment", pluginprovider.Misbehavior{NoIdempotency: true},
			map[string]string{"payment/refund_idempotent": "idempotency_key_refunded_twice"}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, c.kind)
			h.fake.Misbehave = c.misbehave
			report := pluginprovider.RunContract(t.Context(), h.client)
			if report.Passed {
				t.Fatal("contract passed")
			}
			failed := caseFailures(report)
			for id, code := range c.want {
				if failed[id] != code {
					t.Errorf("%s = %q, want %q (all %v)", id, failed[id], code, failed)
				}
			}
		})
	}
}

func TestClientRejectsUndeclaredKind(t *testing.T) {
	h := newHarness(t, "dns")
	err := h.client.Call(t.Context(), "sms", "send", pluginprovider.SMSSendRequest{}, nil)
	if pluginprovider.CodeOf(err) != pluginprovider.CodeInvalidRequest || h.fake.Calls["sms/send"] != 0 {
		t.Fatalf("undeclared kind call %v %v", err, h.fake.Calls)
	}
}

func TestPublicHTTPClientRefusesInternalAddresses(t *testing.T) {
	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()
	_, private, _ := ed25519.GenerateKey(nil)
	public, _, _ := ed25519.GenerateKey(nil)
	declaration, _, err := pluginprovider.Build(pluginID, "1.0.0", "https://provider.example.com",
		base64.RawURLEncoding.EncodeToString(public), []pluginprovider.Provided{{Kind: "dns", ProtocolVersion: "1"}},
		[]string{"providers.dns.provide"})
	if err != nil {
		t.Fatal(err)
	}
	// Point the production client's dialer at loopback via the URL host.
	base := pluginprovider.PublicHTTPClient(nil)
	inner := base.Transport.(*http.Transport)
	client, _ := pluginprovider.NewClient(declaration, pluginprovider.Signer{InstallationID: "inst", PrivateKey: private},
		pluginprovider.Options{HTTPClient: &http.Client{Transport: rewriteTransport{base: inner, address: server.Listener.Addr().String()}}})
	err = client.Call(t.Context(), "dns", "verify", pluginprovider.RequestHeader{Protocol: pluginprovider.Protocol}, nil)
	if pluginprovider.CodeOf(err) != pluginprovider.CodeBlockedAddress {
		t.Fatalf("loopback call = %v", err)
	}
}
