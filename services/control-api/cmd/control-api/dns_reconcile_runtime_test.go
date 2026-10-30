package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/google/uuid"
)

func TestDNSReconcileRuntimeConfigFailsClosedWithoutStrictResolverAllowlist(t *testing.T) {
	for _, environment := range []map[string]string{
		{"DNS_RECONCILE_ENABLED": "true"},
		{"DNS_RECONCILE_ENABLED": "true", "DNS_RECONCILE_RESOLVER_ENDPOINTS": "udp://resolver.example:53"},
		{"DNS_RECONCILE_ENABLED": "true", "DNS_RECONCILE_RESOLVER_ENDPOINTS": "udp://0.0.0.0:53"},
		{"DNS_RECONCILE_ENABLED": "true", "DNS_RECONCILE_RESOLVER_ENDPOINTS": "udp://192.0.2.53"},
	} {
		if config, err := loadDNSReconcileRuntimeConfigFromEnv(mapAccountRecoveryEnv(environment)); err == nil || config.Enabled {
			t.Fatalf("configuration=(%+v,%v), want startup failure", config, err)
		}
	}
}

func TestDNSReconcileRuntimeConfigBuildsExplicitNetworkIPPortPolicy(t *testing.T) {
	config, err := loadDNSReconcileRuntimeConfigFromEnv(mapAccountRecoveryEnv(map[string]string{
		"DNS_RECONCILE_ENABLED":                               "true",
		"DNS_RECONCILE_RESOLVER_ENDPOINTS":                    "udp://192.0.2.53:53,tcp://[2001:db8::53]:5353",
		"DNS_RECONCILE_AUTHORITATIVE_RESOLVERS":               "auth-a=udp://192.0.2.53:53",
		"DNS_RECONCILE_PUBLIC_RESOLVERS":                      "public-a=tcp://[2001:db8::53]:5353",
		"DNS_RECONCILE_WORKLOAD_MTLS_LISTEN_ADDR":             "127.0.0.1:9543",
		"DNS_RECONCILE_WORKLOAD_MTLS_SERVER_CERT_FILE":        "/run/dns/server.crt",
		"DNS_RECONCILE_WORKLOAD_MTLS_SERVER_PRIVATE_KEY_FILE": "/run/dns/server.key",
		"DNS_RECONCILE_WORKLOAD_MTLS_CLIENT_CA_FILE":          "/run/dns/client-ca.crt",
		"DNS_RECONCILE_WORKLOAD_IDENTITIES":                   "spiffe://cdnca.local/dns-reconcile/provider-a|provider-a|11111111-1111-4111-8111-111111111111|22222222-2222-4222-8222-222222222222",
		"DNS_RECONCILE_PROPAGATION_BOOTSTRAP_RESOLVERS":       "bootstrap-a=9.9.9.9:53,public-a=1.1.1.1:53,public-b=8.8.8.8:53",
		"DNS_RECONCILE_PROPAGATION_PUBLIC_RESOLVERS":          "public-a=1.1.1.1:53,public-b=8.8.8.8:53",
		"DNS_RECONCILE_PROPAGATION_PUBLIC_QUORUM":             "2",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !config.Enabled || config.Resolver == nil || len(config.AuthoritativeResolvers) != 1 || len(config.PublicResolvers) != 1 {
		t.Fatalf("configuration=%+v", config)
	}
}

// Native single-host shape: propagation discovers authorities from the zone's
// NS delegation, no static allowlist and no workload mTLS listener.
func nativeDNSReconcileEnvironment() map[string]string {
	return map[string]string{
		"DNS_RECONCILE_ENABLED":                         "true",
		"DNS_RECONCILE_WORKLOAD_MTLS_ENABLED":           "false",
		"DNS_RECONCILE_PROPAGATION_BOOTSTRAP_RESOLVERS": "cloudflare=1.1.1.1:53,google=8.8.8.8:53,alidns=223.5.5.5:53",
		"DNS_RECONCILE_PROPAGATION_PUBLIC_RESOLVERS":    "cloudflare=1.1.1.1:53,google=8.8.8.8:53,alidns=223.5.5.5:53",
		"DNS_RECONCILE_PROPAGATION_PUBLIC_QUORUM":       "2",
	}
}

func TestDNSReconcileRuntimeConfigNativeWithoutWorkloadListener(t *testing.T) {
	config, err := loadDNSReconcileRuntimeConfigFromEnv(mapAccountRecoveryEnv(nativeDNSReconcileEnvironment()))
	if err != nil {
		t.Fatal(err)
	}
	if !config.Enabled || config.WorkloadMTLS != nil || len(config.WorkloadIdentities) != 0 || config.Checker != nil ||
		len(config.PropagationBootstrap) != 3 || len(config.PropagationPublic) != 3 || config.PropagationPublicQuorum != 2 {
		t.Fatalf("configuration=%+v", config)
	}
}

func TestDNSReconcileRuntimeConfigNativeRejectsAmbiguousSettings(t *testing.T) {
	for name, mutate := range map[string]func(map[string]string){
		"workload settings while disabled": func(environment map[string]string) {
			environment["DNS_RECONCILE_WORKLOAD_IDENTITIES"] = "spiffe://cdnca.local/dns-reconcile/a|a|11111111-1111-4111-8111-111111111111|22222222-2222-4222-8222-222222222222"
		},
		"empty workload listen address while disabled": func(environment map[string]string) {
			environment["DNS_RECONCILE_WORKLOAD_MTLS_LISTEN_ADDR"] = ""
		},
		"workload enabled by default without settings": func(environment map[string]string) {
			delete(environment, "DNS_RECONCILE_WORKLOAD_MTLS_ENABLED")
		},
		"invalid workload flag": func(environment map[string]string) {
			environment["DNS_RECONCILE_WORKLOAD_MTLS_ENABLED"] = "no"
		},
		"partial static allowlist": func(environment map[string]string) {
			environment["DNS_RECONCILE_RESOLVER_ENDPOINTS"] = "udp://1.1.1.1:53"
		},
		"public resolver missing from bootstrap": func(environment map[string]string) {
			environment["DNS_RECONCILE_PROPAGATION_BOOTSTRAP_RESOLVERS"] = "cloudflare=1.1.1.1:53,google=8.8.8.8:53"
		},
		"quorum above resolver count": func(environment map[string]string) {
			environment["DNS_RECONCILE_PROPAGATION_PUBLIC_QUORUM"] = "4"
		},
	} {
		t.Run(name, func(t *testing.T) {
			environment := nativeDNSReconcileEnvironment()
			mutate(environment)
			if config, err := loadDNSReconcileRuntimeConfigFromEnv(mapAccountRecoveryEnv(environment)); err == nil || config.Enabled {
				t.Fatalf("configuration=(%+v,%v), want startup failure", config, err)
			}
		})
	}
}

func TestDNSReconcileRuntimeConfigNativeAcceptsCompleteStaticAllowlist(t *testing.T) {
	environment := nativeDNSReconcileEnvironment()
	environment["DNS_RECONCILE_RESOLVER_ENDPOINTS"] = "udp://192.0.2.53:53,udp://198.51.100.53:53"
	environment["DNS_RECONCILE_AUTHORITATIVE_RESOLVERS"] = "auth-a=udp://192.0.2.53:53"
	environment["DNS_RECONCILE_PUBLIC_RESOLVERS"] = "public-a=udp://198.51.100.53:53"
	config, err := loadDNSReconcileRuntimeConfigFromEnv(mapAccountRecoveryEnv(environment))
	if err != nil || !config.Enabled || config.Checker == nil || config.WorkloadMTLS != nil {
		t.Fatalf("configuration=(%+v,%v)", config, err)
	}
}

func TestCNAMEAllocationKeyringRequiresStableIDAnd32ByteSecret(t *testing.T) {
	t.Setenv("CNAME_ALLOCATION_HMAC_KEY_ID", "cname-v1")
	t.Setenv("CNAME_ALLOCATION_HMAC_KEY", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")
	keyring, err := loadCNAMEAllocationKeyring()
	if err != nil || keyring.active.ID != "cname-v1" || len(keyring.active.Secret) != 32 {
		t.Fatalf("keyring=(%+v,%v)", keyring.active.ID, err)
	}
	t.Setenv("CNAME_ALLOCATION_HMAC_KEY", "AAECAwQFBgcICQoLDA0ODw==")
	if _, err := loadCNAMEAllocationKeyring(); err == nil {
		t.Fatal("16-byte CNAME allocation key was accepted")
	}
}

func TestDNSReconcileRuntimeDisabledIgnoresOwnedConfiguration(t *testing.T) {
	config, err := loadDNSReconcileRuntimeConfigFromEnv(mapAccountRecoveryEnv(map[string]string{
		"DNS_RECONCILE_RESOLVER_ENDPOINTS": "invalid-secret-looking-value",
	}))
	if err != nil || config.Enabled {
		t.Fatalf("configuration=(%+v,%v)", config, err)
	}
}

func TestDNSReconcileRuntimeWiresRestartSafePostgresUncertainRecovery(t *testing.T) {
	source, err := os.ReadFile("dns_reconcile_runtime.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, required := range []string{
		"dnsReconcileRecoveryTenantSource", "requeueDueUncertain", "recovery_not_before",
		"lease_expires_at", "clock_timestamp()", "provider_recovery_pending",
		"dns_reconcile_provider_mutation_claims", "background_jobs", "background_job_items",
		"dns_reconcile_task_events", "source", "control",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("DNS reconcile runtime missing durable recovery contract %q", required)
		}
	}
}

func TestPrepareDNSReconcileRecoveryResultBindsExactApplyOperation(t *testing.T) {
	tenantID, jobID, siteID, zoneID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	operation := dnscheck.ProviderOperation{
		Sequence: 1, Action: dnscheck.ProviderCreate, Name: "www.example.test.",
		Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300, Reason: "missing_record",
	}
	result := dnscheck.ReconcileResult{
		TenantID: tenantID, SiteID: siteID, ZoneID: zoneID, Status: dnscheck.TaskFailed,
		InitialRevision: 7, ProviderRevision: 7, ErrorClass: dnscheck.ProviderErrorTransient,
		ErrorCode: "provider_recovery_pending",
		Operations: []dnscheck.OperationResult{{
			SourceSequence: 1, Operation: operation, ClientRequestID: "apply-recovery-request",
			ProviderRequestID: "dns-reconcile-provider-request", Status: dnscheck.OperationTransientFailed,
			ErrorClass: dnscheck.ProviderErrorTransient, ErrorCode: "provider_recovery_pending", ReportSequence: 2,
			Attempts: 3,
		}},
	}
	candidate := dnsReconcileRecoveryCandidate{
		tenantID: tenantID, jobID: jobID, claimID: uuid.New(), siteID: siteID, zoneID: zoneID,
		clientRequestID: "apply-recovery-request", phase: "apply", ordinal: 1,
		claimState: string(dnsproviderremote.MutationSucceeded), expectedRevision: 7,
		eventSequence: 3, operationJSON: mustDNSRecoveryJSON(t, operation),
		resultSnapshot: mustDNSRecoveryJSON(t, result), serverNow: time.Unix(1_800_000_000, 0).UTC(),
	}
	recovered, err := prepareDNSReconcileRecoveryResult(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Status != dnscheck.TaskApplying || recovered.ErrorCode != "" ||
		recovered.Operations[0].Status != dnscheck.OperationPlanned ||
		recovered.Operations[0].ClientRequestID != "apply-recovery-request" ||
		recovered.Operations[0].ReportSequence != 2 || recovered.Operations[0].Attempts != 3 {
		t.Fatalf("recovered apply result=%+v", recovered)
	}
	candidate.clientRequestID = "another-request"
	if _, err := prepareDNSReconcileRecoveryResult(candidate); err == nil {
		t.Fatal("cross-request recovery snapshot was accepted")
	}
}

func TestPrepareDNSReconcileRecoveryResultProjectsExactCommitSuccess(t *testing.T) {
	tenantID, jobID, siteID, zoneID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	operation := dnscheck.ProviderOperation{
		Sequence: 2, Action: dnscheck.ProviderDelete, RecordID: "record-7",
		Name: "old.example.test.", Type: dnscheck.RecordAAAA, Value: "2001:db8::7", TTL: 300,
		Reason: "unexpected_record",
	}
	result := dnscheck.ReconcileResult{
		TenantID: tenantID, SiteID: siteID, ZoneID: zoneID, Status: dnscheck.TaskCommitFailed,
		InitialRevision: 7, ProviderRevision: 7, ErrorClass: dnscheck.ProviderErrorTransient,
		ErrorCode: "provider_recovery_persistence_failed",
		DeferredDeletes: []dnscheck.OperationResult{{
			SourceSequence: 2, Operation: operation, ClientRequestID: "commit-recovery-request",
			ProviderRequestID: "dns-reconcile-provider-request", Status: dnscheck.OperationTransientFailed,
			ErrorClass: dnscheck.ProviderErrorTransient,
			ErrorCode:  "provider_recovery_persistence_failed", ReportSequence: 4,
		}},
	}
	candidate := dnsReconcileRecoveryCandidate{
		tenantID: tenantID, jobID: jobID, claimID: uuid.New(), siteID: siteID, zoneID: zoneID,
		clientRequestID: "commit-recovery-request", phase: "commit", ordinal: 1,
		claimState: string(dnsproviderremote.MutationSucceeded), expectedRevision: 7,
		providerRequest: "dns-reconcile-provider-request", providerRecord: "record-7", finalRevision: 8,
		eventSequence: 9, operationJSON: mustDNSRecoveryJSON(t, operation),
		resultSnapshot: mustDNSRecoveryJSON(t, result), serverNow: time.Unix(1_800_000_000, 0).UTC(),
	}
	recovered, err := prepareDNSReconcileRecoveryResult(candidate)
	if err != nil {
		t.Fatal(err)
	}
	operationResult := recovered.DeferredDeletes[0]
	if recovered.Status != dnscheck.TaskCommitted || recovered.ProviderRevision != 8 ||
		operationResult.Status != dnscheck.OperationSucceeded ||
		operationResult.ProviderRequestID != "dns-reconcile-provider-request" ||
		operationResult.ProviderRecordID != "record-7" || operationResult.ReportSequence != 5 {
		t.Fatalf("recovered commit result=%+v", recovered)
	}
	candidate.operationJSON = mustDNSRecoveryJSON(t, dnscheck.ProviderOperation{
		Sequence: 2, Action: dnscheck.ProviderDelete, RecordID: "other-record",
		Name: "old.example.test.", Type: dnscheck.RecordAAAA, Value: "2001:db8::7", TTL: 300,
		Reason: "unexpected_record",
	})
	if _, err := prepareDNSReconcileRecoveryResult(candidate); err == nil {
		t.Fatal("cross-operation recovery snapshot was accepted")
	}
}

func mustDNSRecoveryJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
