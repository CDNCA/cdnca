package dnsacme

import "testing"

// The DNS.COM plan tier (free/enterprise/flagship) is optional, saved with
// the encrypted credentials and shown back as an identifier.
func TestDNSComCredentialsAcceptOptionalPlan(t *testing.T) {
	for plan, valid := range map[string]bool{"free": true, "enterprise": true, "flagship": true, "": false, "custom": false} {
		credentials := map[string]string{"api_key": "key", "api_secret": "secret", "plan": plan}
		if _, _, err := exactDNSComCredentials(credentials); (err == nil) != valid {
			t.Fatalf("plan %q error = %v, want valid %v", plan, err, valid)
		}
		if validProviderCredentialSchema("dns_com", credentials) != valid {
			t.Fatalf("plan %q schema mismatch", plan)
		}
	}
	if _, _, err := exactDNSComCredentials(map[string]string{"api_key": "key", "api_secret": "secret"}); err != nil {
		t.Fatalf("no plan error = %v", err)
	}
	if _, _, err := exactDNSComCredentials(map[string]string{"api_key": "key", "api_secret": "secret", "region": "x"}); err == nil {
		t.Fatal("unknown third field accepted")
	}
	if fields := identifierFields["dns_com"]; len(fields) != 2 || fields[1] != "plan" {
		t.Fatalf("identifier fields = %v", fields)
	}
}
