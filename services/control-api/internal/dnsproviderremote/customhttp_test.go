package dnsproviderremote

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnscustomhttp"
)

const customHTTPTestSecret = "custom-http-secret-0123"

// customHTTPTestAdapter serves the reference endpoint over TLS and lets the
// adapter reach the loopback test server (production refuses loopback).
func customHTTPTestAdapter(t *testing.T, fake *dnscustomhttp.FakeEndpoint) (*Adapter, ProviderConfig) {
	t.Helper()
	server := httptest.NewTLSServer(fake)
	t.Cleanup(server.Close)
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	config := completeTestConfig(ProviderConfig{ProviderType: providerCustomHTTP, ZoneName: testZone,
		Credentials: map[string]string{"endpoint": server.URL + "/dns", "secret": customHTTPTestSecret}})
	adapter, _ := newProviderTestAdapter(t, config, fake, time.Second)
	// The protocol signs the real clock (the reference endpoint checks skew).
	adapter.now = time.Now
	adapter.customHTTP = &dnscustomhttp.Options{
		Blocked: func(address netip.Addr) bool { return !address.IsLoopback() && dnscustomhttp.Blocked(address) },
		TLS:     &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}
	return adapter, config
}

func TestCustomHTTPProviderTXTLifecycle(t *testing.T) {
	fake := &dnscustomhttp.FakeEndpoint{Secret: customHTTPTestSecret, Zone: testZone}
	fake.Seed(dnscustomhttp.Record{Name: "_acme-challenge.example.test", Type: "TXT", Value: testOtherValue, TTL: 600})
	adapter, _ := customHTTPTestAdapter(t, fake)
	ctx := context.Background()
	handle, err := adapter.PresentTXT(ctx, testChallenge())
	if err != nil {
		t.Fatalf("PresentTXT: %v", err)
	}
	if err := adapter.ObserveTXT(ctx, testChallengeWithHandle(handle)); err != nil {
		t.Fatalf("ObserveTXT: %v", err)
	}
	recovered, found, err := adapter.RecoverTXT(ctx, testChallenge())
	if err != nil || !found || recovered.RecordRef == "" {
		t.Fatalf("RecoverTXT: %+v %v %v", recovered, found, err)
	}
	if err := adapter.DeleteTXT(ctx, testChallengeWithHandle(handle)); err != nil {
		t.Fatalf("DeleteTXT: %v", err)
	}
	if err := adapter.DeleteTXT(ctx, testChallengeWithHandle(handle)); err != nil {
		t.Fatalf("idempotent DeleteTXT: %v", err)
	}
	records := fake.Records()
	if len(records) != 1 || records[0].Value != testOtherValue {
		t.Fatalf("unrelated TXT touched or target kept: %+v", records)
	}
}

func TestCustomHTTPProviderReconcileAndList(t *testing.T) {
	fake := &dnscustomhttp.FakeEndpoint{Secret: customHTTPTestSecret, Zone: testZone}
	fake.Seed(dnscustomhttp.Record{Name: "www.example.test", Type: "A", Value: "198.51.100.9", TTL: 300, Line: "默认"},
		dnscustomhttp.Record{Name: "www.example.test", Type: "MX", Value: "mail.example.test", TTL: 300})
	adapter, config := customHTTPTestAdapter(t, fake)
	remote := &providerReconcileRemote{adapter: adapter}
	ctx := context.Background()
	create := dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate, Name: "www.example.test.", Type: dnscheck.RecordA,
		Value: "192.0.2.10", TTL: 300, Line: LineTelecom}
	lookup, err := remote.Lookup(ctx, config, create)
	if err != nil || lookup.TargetComplete || lookup.Conflict {
		t.Fatalf("lookup before create: %+v %v", lookup, err)
	}
	id, err := remote.Mutate(ctx, config, create)
	if err != nil || id == "" {
		t.Fatalf("create: %q %v", id, err)
	}
	lookup, err = remote.Lookup(ctx, config, create)
	if err != nil || !lookup.TargetComplete || lookup.RecordID != id {
		t.Fatalf("lookup after create: %+v %v", lookup, err)
	}
	update := create
	update.Action, update.RecordID, update.Value, update.PreviousValue, update.PreviousTTL, update.PreviousLine =
		dnscheck.ProviderUpdate, id, "192.0.2.11", "192.0.2.10", 300, LineTelecom
	if _, err := remote.Mutate(ctx, config, update); err != nil {
		t.Fatal(err)
	}
	listed, err := remote.ListZoneRecords(ctx, config, "www.example.test.")
	if err != nil {
		t.Fatal(err)
	}
	lines := map[string]string{}
	for _, record := range listed {
		lines[record.Value] = record.Line
	}
	if len(listed) != 2 || lines["192.0.2.11"] != LineTelecom || lines["198.51.100.9"] != LineDefault {
		t.Fatalf("listed = %+v (MX must be dropped)", listed)
	}
	remove := update
	remove.Action = dnscheck.ProviderDelete
	if _, err := remote.Mutate(ctx, config, remove); err != nil {
		t.Fatal(err)
	}
	if _, err := remote.Mutate(ctx, config, remove); err != nil {
		t.Fatalf("idempotent delete: %v", err)
	}
	// Wrong secret: credentials are rejected with the stable code.
	config.Credentials = map[string]string{"endpoint": config.Credentials["endpoint"], "secret": "another-secret-value"}
	if _, err := remote.Lookup(ctx, config, create); !isCode(err, CodeCredentialsRejected) {
		t.Fatalf("wrong secret: %v", err)
	}
}
