package main

import (
	"os"
	"strings"
	"testing"
)

var _ interface {
	Ready() error
	Close() error
} = (*dnsReconcileProductionRuntime)(nil)

func TestDNSReconcilePropagationConfigFailsClosed(t *testing.T) {
	valid := map[string]string{
		"DNS_RECONCILE_ENABLED":                               "true",
		"DNS_RECONCILE_RESOLVER_ENDPOINTS":                    "udp://192.0.2.53:53,tcp://198.51.100.53:53",
		"DNS_RECONCILE_AUTHORITATIVE_RESOLVERS":               "auth-a=udp://192.0.2.53:53",
		"DNS_RECONCILE_PUBLIC_RESOLVERS":                      "public-a=tcp://198.51.100.53:53",
		"DNS_RECONCILE_WORKLOAD_MTLS_LISTEN_ADDR":             "127.0.0.1:9543",
		"DNS_RECONCILE_WORKLOAD_MTLS_SERVER_CERT_FILE":        "/run/dns/server.crt",
		"DNS_RECONCILE_WORKLOAD_MTLS_SERVER_PRIVATE_KEY_FILE": "/run/dns/server.key",
		"DNS_RECONCILE_WORKLOAD_MTLS_CLIENT_CA_FILE":          "/run/dns/client-ca.crt",
		"DNS_RECONCILE_WORKLOAD_IDENTITIES":                   "spiffe://cdnca.local/dns-reconcile/provider-a|provider-a|11111111-1111-4111-8111-111111111111|22222222-2222-4222-8222-222222222222",
		"DNS_RECONCILE_PROPAGATION_BOOTSTRAP_RESOLVERS":       "bootstrap-a=9.9.9.9:53,public-a=1.1.1.1:53,public-b=8.8.8.8:53",
		"DNS_RECONCILE_PROPAGATION_PUBLIC_RESOLVERS":          "public-a=1.1.1.1:53,public-b=8.8.8.8:53",
		"DNS_RECONCILE_PROPAGATION_PUBLIC_QUORUM":             "2",
	}

	for _, name := range []string{
		"DNS_RECONCILE_PROPAGATION_BOOTSTRAP_RESOLVERS",
		"DNS_RECONCILE_PROPAGATION_PUBLIC_RESOLVERS",
		"DNS_RECONCILE_PROPAGATION_PUBLIC_QUORUM",
	} {
		t.Run("missing "+name, func(t *testing.T) {
			environment := cloneDNSPropagationEnvironment(valid)
			delete(environment, name)
			if config, err := loadDNSReconcileRuntimeConfigFromEnv(mapAccountRecoveryEnv(environment)); err == nil || config.Enabled {
				t.Fatalf("configuration=(%+v,%v), want propagation startup failure", config, err)
			}
		})
	}

	for name, value := range map[string]string{
		"hostname bootstrap": "bootstrap-a=dns.example.test:53",
		"duplicate public":   "public-a=1.1.1.1:53,public-b=1.1.1.1:53",
	} {
		t.Run(name, func(t *testing.T) {
			environment := cloneDNSPropagationEnvironment(valid)
			if strings.HasPrefix(name, "hostname") {
				environment["DNS_RECONCILE_PROPAGATION_BOOTSTRAP_RESOLVERS"] = value
			} else {
				environment["DNS_RECONCILE_PROPAGATION_PUBLIC_RESOLVERS"] = value
			}
			if config, err := loadDNSReconcileRuntimeConfigFromEnv(mapAccountRecoveryEnv(environment)); err == nil || config.Enabled {
				t.Fatalf("configuration=(%+v,%v), want propagation resolver rejection", config, err)
			}
		})
	}

	for _, quorum := range []string{"0", "3", "not-a-number"} {
		t.Run("quorum "+quorum, func(t *testing.T) {
			environment := cloneDNSPropagationEnvironment(valid)
			environment["DNS_RECONCILE_PROPAGATION_PUBLIC_QUORUM"] = quorum
			if config, err := loadDNSReconcileRuntimeConfigFromEnv(mapAccountRecoveryEnv(environment)); err == nil || config.Enabled {
				t.Fatalf("configuration=(%+v,%v), want public quorum rejection", config, err)
			}
		})
	}

	if config, err := loadDNSReconcileRuntimeConfigFromEnv(mapAccountRecoveryEnv(valid)); err != nil || !config.Enabled {
		t.Fatalf("valid propagation configuration=(%+v,%v)", config, err)
	}
}

func TestDNSReconcilePropagationProductionCompositionContract(t *testing.T) {
	source, err := os.ReadFile("dns_reconcile_runtime.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, required := range []string{
		"dnspropagation.NewWireSource(",
		"dnspropagation.NewEngine(",
		"dnspropagation.NewPostgresRetryStore(",
		"verifyDNSPropagationSchema(ctx, pool)",
		"dns_provider_retry_states",
		"PropagationEnabled: true",
		"Propagation: dnsreconcile.PropagationDependencies{",
		"Engine: propagationEngine",
		"RetryStates: propagationStore",
		"ContextResolver: &dnsReconcilePropagationContextResolver{pool: pool, apex: providerSource}",
		"COALESCE(zone.provider_zone_apex,'')",
		"resolver.apex.PropagationZoneApex(ctx, tenantID, siteID, zoneID)",
		"func (resolver *dnsReconcilePropagationContextResolver) ResolvePropagationContext(",
		// The anchor $2 is a live site or a live stream (migration 507).
		"FROM `+dnsReconcileAnchorSQL(\"$2\")+` anchor", "WHERE scope.tenant_id=$1 AND zone.id=$3",
		"propagationLifecycle",
		"func (runtime *dnsReconcileProductionRuntime) Ready() error",
		"runtime.propagationLifecycle.Ready()",
		"runtime.propagationLifecycle.Close()",
		"runtime.workloadServer.Close()",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("DNS reconcile propagation composition missing %q", required)
		}
	}
}

func cloneDNSPropagationEnvironment(source map[string]string) map[string]string {
	clone := make(map[string]string, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}
