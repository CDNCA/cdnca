package main

import (
	"strings"
	"testing"
)

func TestIdentityVerificationIssuerEnvironmentIsExplicitAndStrict(t *testing.T) {
	valid := []string{
		identityVerificationIssuerEnabledEnv + "=true",
		identityVerificationIssuerListenAddressEnv + "=127.0.0.1:19443",
		identityVerificationIssuerServerCertEnv + "=/run/identity/server.crt",
		identityVerificationIssuerServerKeyEnv + "=/run/identity/server.key",
		identityVerificationIssuerClientCAEnv + "=/run/identity/client-ca.crt",
		identityVerificationIssuerIdentitiesEnv + "=spiffe://control.cdnca.local/workload/kyc/issuer-a|issuer-a,spiffe://control.cdnca.local/workload/kyc/issuer-b|issuer-b",
		identityVerificationIssuerKMSEndpointEnv + "=https://kms.example.test",
	}
	config, err := loadIdentityVerificationIssuerEnvironment(valid)
	if err != nil || !config.Enabled || config.ListenAddress != "127.0.0.1:19443" ||
		len(config.WorkloadIdentities) != 2 || config.WorkloadIdentities[0].WorkloadID != "issuer-a" ||
		config.KMSEndpoint != "https://kms.example.test" {
		t.Fatalf("issuer environment = %#v, %v", config, err)
	}
	if disabled, err := loadIdentityVerificationIssuerEnvironment(nil); err != nil || disabled.Enabled {
		t.Fatalf("disabled issuer environment = %#v, %v", disabled, err)
	}
	for name, environment := range map[string][]string{
		"unknown": append(append([]string(nil), valid...),
			"IDENTITY_VERIFICATION_ISSUER_UNKNOWN=value"),
		"duplicate": append(append([]string(nil), valid...),
			identityVerificationIssuerEnabledEnv+"=true"),
		"missing identity": removeIdentityVerificationEnv(valid, identityVerificationIssuerIdentitiesEnv),
		"malformed identity": replaceIdentityVerificationEnv(valid, identityVerificationIssuerIdentitiesEnv,
			"spiffe://control.cdnca.local/workload/kyc/issuer-a"),
		"insecure remote KMS": replaceIdentityVerificationEnv(valid, identityVerificationIssuerKMSEndpointEnv,
			"http://kms.example.test"),
	} {
		t.Run(name, func(t *testing.T) {
			if config, err := loadIdentityVerificationIssuerEnvironment(environment); err == nil ||
				config.Enabled || strings.Contains(err.Error(), "value") {
				t.Fatalf("invalid issuer environment = %#v, %v", config, err)
			}
		})
	}
}

func TestIdentityVerificationIssuerIdentitiesRejectAmbiguity(t *testing.T) {
	for _, raw := range []string{
		"", "uri|", "|workload", " uri|workload", "uri|workload ", "uri|workload|extra",
		"uri|workload,", "uri|workload,uri|workload",
	} {
		identities, err := parseIdentityVerificationIssuerIdentities(raw)
		if err == nil {
			t.Fatalf("identities %q = %#v, want error", raw, identities)
		}
	}
	identities, err := parseIdentityVerificationIssuerIdentities(
		"spiffe://control.cdnca.local/workload/kyc/issuer|issuer")
	if err != nil || len(identities) != 1 || identities[0].WorkloadID != "issuer" {
		t.Fatalf("valid identities = %#v, %v", identities, err)
	}
}
