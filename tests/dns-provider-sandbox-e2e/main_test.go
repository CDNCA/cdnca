package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestProviderInputRequiresAllRecordValues(t *testing.T) {
	input := validTestProviderInput()
	if !validProviderInput(input) {
		t.Fatal("validProviderInput() rejected complete input")
	}

	invalid := []providerInput{
		func() providerInput { value := input; value.InitialIPv6 = "2001:0db8::10"; return value }(),
		func() providerInput { value := input; value.UpdatedIPv6 = input.InitialIPv6; return value }(),
		func() providerInput { value := input; value.CNAMETarget = "target.example.test"; return value }(),
		func() providerInput { value := input; value.UpdatedCNAMETarget = input.CNAMETarget; return value }(),
	}
	for index, value := range invalid {
		if validProviderInput(value) {
			t.Fatalf("validProviderInput() accepted invalid case %d", index)
		}
	}
}

func TestParseEndpointsRequiresTwoIndependentPublicResolvers(t *testing.T) {
	if _, _, err := parseEndpoints([]string{"192.0.2.53:53"}, []string{"198.51.100.53:53"}); err == nil {
		t.Fatal("parseEndpoints() accepted one public resolver")
	}
	if _, _, err := parseEndpoints(
		[]string{"192.0.2.53:53"},
		[]string{"198.51.100.53:53", "203.0.113.53:53"},
	); err != nil {
		t.Fatalf("parseEndpoints() rejected two independent public resolvers: %v", err)
	}
	if _, _, err := parseEndpoints(
		[]string{"192.0.2.53:53"},
		[]string{"198.51.100.53:53", "192.0.2.53:53"},
	); err == nil {
		t.Fatal("parseEndpoints() accepted an authority endpoint as a public resolver")
	}
}

func TestContractDeclaresFourRecordTypesAndSafetyFacts(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("contract.json"))
	if err != nil {
		t.Fatal(err)
	}
	var contract struct {
		Providers []struct {
			RecordTypes []string `json:"record_types"`
		} `json:"providers"`
		Preflight struct {
			MinimumPublicRecursive int  `json:"minimum_public_recursive"`
			BeforeMutation         bool `json:"all_providers_before_mutation"`
		} `json:"preflight"`
		Recovery struct {
			ExactIdentityReadback bool `json:"unknown_outcome_exact_identity_readback"`
		} `json:"recovery"`
	}
	if err := json.Unmarshal(raw, &contract); err != nil {
		t.Fatal(err)
	}
	if len(contract.Providers) != len(exactProviders) {
		t.Fatalf("providers = %d, want %d", len(contract.Providers), len(exactProviders))
	}
	want := []string{"A", "AAAA", "CNAME", "TXT"}
	for index, provider := range contract.Providers {
		if !equalStrings(provider.RecordTypes, want) {
			t.Fatalf("provider %d record_types = %v, want %v", index, provider.RecordTypes, want)
		}
	}
	if contract.Preflight.MinimumPublicRecursive != 2 || !contract.Preflight.BeforeMutation ||
		!contract.Recovery.ExactIdentityReadback {
		t.Fatalf("missing safety facts: %+v %+v", contract.Preflight, contract.Recovery)
	}
}

func validTestProviderInput() providerInput {
	return providerInput{
		Code: "cloudflare", Zone: "sandbox.example.test",
		GuardOwner:      "_cdnca-guard.sandbox.example.test.",
		GuardSHA256:     "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Authoritative:   []string{"192.0.2.53:53"},
		PublicRecursive: []string{"198.51.100.53:53", "203.0.113.53:53"},
		CredentialEnv:   credentialEnvironmentName("cloudflare"),
		InitialIPv4:     "192.0.2.10", UpdatedIPv4: "192.0.2.11",
		InitialIPv6: "2001:db8::10", UpdatedIPv6: "2001:db8::11",
		CNAMETarget: "target.example.test.", UpdatedCNAMETarget: "updated.example.test.",
		TTL: 300, UpdatedTTL: 600, RateLimitMaximumReads: 2,
		RateLimitIntervalMS: 1000, TimeoutSeconds: 60, CleanupTimeoutSeconds: 60,
	}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
