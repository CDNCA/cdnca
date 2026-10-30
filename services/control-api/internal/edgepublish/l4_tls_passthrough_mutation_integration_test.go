//go:build integration

package edgepublish_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/l4forward"
	"github.com/google/uuid"
)

type passthroughSave struct {
	name, protocol string
	port           uint16
	names          []string
	wantConflict   bool
}

func savePassthroughStreams(t *testing.T, saves edgepublish.L4TLSPassthroughSaves, steps []passthroughSave) {
	t.Helper()
	service := l4forward.NewService(l4forward.NewStore(saves.Pool))
	actor := l4forward.Actor{ScopeID: saves.ScopeID, UserID: saves.UserID, ScopeKind: "tenant"}
	for _, step := range steps {
		fields := l4forward.Fields{PackageSubscriptionID: new(saves.SubscriptionID), Name: step.name,
			Protocol: step.protocol, ListenAddress: "*", ListenPort: step.port, UpstreamAddress: "8.8.8.8", UpstreamPort: 443,
			ConnectTimeoutMS: 1000, ResponseTimeoutMS: 30000, MaxConnectionsPerClient: 100, Enabled: true,
			TLSPassthrough: len(step.names) > 0, ServerNames: step.names}
		result, err := service.Create(t.Context(), actor, l4forward.CreateRequest{Fields: fields,
			IdempotencyKey: "passthrough-" + step.name, RequestID: uuid.NewString()})
		if step.wantConflict != errors.Is(err, l4forward.ErrPortConflict) || (!step.wantConflict && err != nil) {
			t.Fatalf("%s: err=%v want conflict=%t", step.name, err, step.wantConflict)
		}
		if err != nil {
			continue
		}
		stored, err := service.Get(t.Context(), actor, result.Forward.ID)
		if err != nil || stored.TLSPassthrough != (len(step.names) > 0) || len(stored.ServerNames) != len(step.names) ||
			!slices.Equal(stored.ServerNames, result.Forward.ServerNames) ||
			stored.PublishIntent.RuntimeSpec.TLSPassthrough != stored.TLSPassthrough {
			t.Fatalf("%s: saved %+v, read back %+v (%v)", step.name, result.Forward, stored, err)
		}
	}
}

// TestL4TLSPassthroughSavesFollowSharingRules saves streams through the real
// l4forward service in a scope with a plaintext and a TLS website and checks
// the sharing rules of decisions/multitenant-composition-compat-2026-10-16
// (补充 2) on save.
func TestL4TLSPassthroughSavesFollowSharingRules(t *testing.T) {
	saves, _ := edgepublish.NewL4TLSPassthroughScope(t, true)
	savePassthroughStreams(t, saves, []passthroughSave{
		{"sni-a", "tcp", 19443, []string{"A.example.com", "*.example.com"}, false},
		{"sni-b", "tcp", 19443, []string{"b.example.com"}, false},
		{"plain-next-to-sni", "tcp", 19443, nil, false},
		{"second-plain", "tcp", 19443, nil, true},
		{"same-sni", "tcp", 19443, []string{"a.example.com"}, true},
		{"same-wildcard", "tcp", 19443, []string{"*.example.com"}, true},
		{"sni-on-plain-website", "tcp", saves.PlainWebsitePort, []string{"c.example.com"}, false},
		{"plain-on-plain-website", "tcp", saves.PlainWebsitePort, nil, true},
		{"plain-on-tls-website", "tcp", saves.TLSWebsitePort, nil, false},
		{"sni-of-tls-website", "tcp", saves.TLSWebsitePort, []string{"passthrough-site.example.com"}, true},
		{"udp-on-http3", "udp", saves.TLSWebsitePort, nil, true},
		{"udp-on-plain-website", "udp", saves.PlainWebsitePort, nil, false},
	})
	service := l4forward.NewService(l4forward.NewStore(saves.Pool))
	actor := l4forward.Actor{ScopeID: saves.ScopeID, UserID: saves.UserID, ScopeKind: "tenant"}
	// A split port is served behind a dispatcher, so its streams cannot use
	// PROXY; a PROXY stream alone on its port keeps it.
	for _, step := range []struct {
		name          string
		port          uint16
		names         []string
		proxyProtocol bool
		want          error
	}{
		{"proxy-on-split-port", 19443, []string{"e.example.com"}, true, l4forward.ErrSharedPortProxyProtocol},
		{"proxy-alone", 19445, nil, true, nil},
		{"joins-proxy-port", 19445, []string{"f.example.com"}, false, l4forward.ErrSharedPortProxyProtocol},
	} {
		_, err := service.Create(t.Context(), actor, l4forward.CreateRequest{Fields: l4forward.Fields{
			PackageSubscriptionID: new(saves.SubscriptionID), Name: step.name, Protocol: "tcp",
			ListenAddress: "*", ListenPort: step.port, UpstreamAddress: "8.8.8.8", UpstreamPort: 443,
			ConnectTimeoutMS: 1000, ResponseTimeoutMS: 30000, MaxConnectionsPerClient: 100, Enabled: true,
			TLSPassthrough: len(step.names) > 0, ServerNames: step.names, ProxyProtocolV1: step.proxyProtocol},
			IdempotencyKey: "passthrough-" + step.name, RequestID: uuid.NewString()})
		if !errors.Is(err, step.want) || (step.want == nil && err != nil) {
			t.Fatalf("%s: err=%v want %v", step.name, err, step.want)
		}
	}
	_, err := service.Create(t.Context(), actor,
		l4forward.CreateRequest{Fields: l4forward.Fields{PackageSubscriptionID: new(saves.SubscriptionID),
			Name: "udp-passthrough", Protocol: "udp", ListenAddress: "*", ListenPort: 19444, UpstreamAddress: "8.8.8.8",
			UpstreamPort: 443, ConnectTimeoutMS: 1000, ResponseTimeoutMS: 30000, MaxConnectionsPerClient: 100,
			Enabled: true, TLSPassthrough: true, ServerNames: []string{"d.example.com"}},
			IdempotencyKey: "passthrough-udp", RequestID: uuid.NewString()})
	if !errors.Is(err, l4forward.ErrInvalidInput) {
		t.Fatalf("UDP passthrough err=%v", err)
	}
}

// TestL4TLSPassthroughPublicationNeedsL4V4 publishes passthrough streams and
// a UDP stream on the website port: a tcp/udp 3 node is refused, a v12 node
// (1.0.35 baseline; the name predates it) gets the release.
func TestL4TLSPassthroughPublicationNeedsL4V4(t *testing.T) {
	saves, publish := edgepublish.NewL4TLSPassthroughScope(t, false)
	savePassthroughStreams(t, saves, []passthroughSave{
		{"sni-a", "tcp", 19443, []string{"a.example.com", "*.example.com"}, false},
		{"sni-b", "tcp", 19443, []string{"b.example.com"}, false},
		{"sni-on-website", "tcp", saves.PlainWebsitePort, []string{"c.example.com"}, false},
		{"udp-on-website", "udp", saves.PlainWebsitePort, nil, false},
	})
	publish(3)
}
