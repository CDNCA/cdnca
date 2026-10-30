package main

import (
	"os"
	"strings"
	"testing"
)

func TestDNSReconcileHelmUsesIndependentWorkloadPortAndSecretMount(t *testing.T) {
	values, err := os.ReadFile("../../../../infra/helm/cdnca/values.yaml")
	if err != nil {
		t.Fatal(err)
	}
	template, err := os.ReadFile("../../../../infra/helm/cdnca/templates/control-api.yaml")
	if err != nil {
		t.Fatal(err)
	}
	schema, err := os.ReadFile("../../../../infra/helm/cdnca/values.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	requiredByDocument := map[string]struct {
		document string
		required []string
	}{
		"values": {document: string(values), required: []string{
			"dnsReconcile:", "workloadPort", "resolverEndpoints", "authoritativeResolvers", "publicResolvers",
			"workloadIdentities", "workloadMTLSSecret", "cdnca-dns-reconcile-workload-mtls",
		}},
		"schema": {document: string(schema), required: []string{
			`"dnsReconcile"`, `"workloadPort"`, `"resolverEndpoints"`, `"workloadIdentities"`,
			`"workloadMTLSSecret"`, `"minItems": 1`,
		}},
		"template": {document: string(template), required: []string{
			".Values.controlApi.dnsReconcile", "DNS_RECONCILE_ENABLED", "DNS_RECONCILE_RESOLVER_ENDPOINTS",
			"DNS_RECONCILE_WORKLOAD_IDENTITIES", "DNS_RECONCILE_WORKLOAD_MTLS_LISTEN_ADDR",
			"DNS_RECONCILE_WORKLOAD_MTLS_SERVER_CERT_FILE", "dns-reconcile-workload", "type: ClusterIP",
		}},
	}
	for label, contract := range requiredByDocument {
		for _, required := range contract.required {
			if !strings.Contains(contract.document, required) {
				t.Errorf("%s missing %q", label, required)
			}
		}
	}
}
