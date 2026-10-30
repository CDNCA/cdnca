package main

import (
	"strings"
	"testing"
)

func TestSecurityActivationRequiresWAFV1AndCCV2(t *testing.T) {
	valid := []string{
		"CDNCA_SECURITY_ACTIVATION_ENABLED=true",
		"CDNCA_SECURITY_ACTIVATION_RECONCILE_INTERVAL=2s",
		"CDNCA_SECURITY_ACTIVATION_CANDIDATE_TTL=15m",
		"CDNCA_SECURITY_ACTIVATION_REQUIRED_WAF_API_VERSION=1",
		"CDNCA_SECURITY_ACTIVATION_REQUIRED_CC_API_VERSION=2",
	}
	config, err := loadSecurityActivationRuntimeConfigFromEnvEntries(valid)
	if err != nil || !config.Enabled || config.Core.RequiredWAFAPIVersion != 1 || config.Core.RequiredCCAPIVersion != 2 {
		t.Fatalf("parseSecurityActivationRuntimeConfig = %#v, %v", config, err)
	}
	for _, invalidCC := range []string{"0", "1", "3"} {
		candidate := append([]string(nil), valid...)
		candidate[len(candidate)-1] = "CDNCA_SECURITY_ACTIVATION_REQUIRED_CC_API_VERSION=" + invalidCC
		if _, err := loadSecurityActivationRuntimeConfigFromEnvEntries(candidate); err == nil || !strings.Contains(err.Error(), "API versions") {
			t.Fatalf("CC API version %s accepted: %v", invalidCC, err)
		}
	}
}
