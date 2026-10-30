package dnsproviderremotesource

import "testing"

func TestDecodeDNSComCredentialsPlanOptional(t *testing.T) {
	for raw, valid := range map[string]bool{
		`{"api_key":"k","api_secret":"s"}`:                       true,
		`{"api_key":"k","api_secret":"s","plan":"flagship"}`:     true,
		`{"api_key":"k","plan":"free"}`:                          false,
		`{"api_key":"k","api_secret":"s","plan":"x","plan":"y"}`: false,
	} {
		credentials, err := decodeCredentials("dns_com", []byte(raw))
		if (err == nil) != valid {
			t.Fatalf("%s: error = %v, want valid %v", raw, err, valid)
		}
		if valid && credentials["api_secret"] != "s" {
			t.Fatalf("%s: credentials = %v", raw, credentials)
		}
	}
	if _, err := decodeCredentials("dns_la", []byte(`{"api_id":"k"}`)); err == nil {
		t.Fatal("a missing field of another provider must stay refused")
	}
}
