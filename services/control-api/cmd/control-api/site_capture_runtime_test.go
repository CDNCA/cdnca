package main

import (
	"net/http/httptest"
	"testing"
)

func TestSiteCaptureBearerTokenRejectsNonCanonicalAuthorization(t *testing.T) {
	for name, values := range map[string][]string{
		"leading whitespace":  {" Bearer token"},
		"trailing whitespace": {"Bearer token "},
		"double separator":    {"Bearer  token"},
		"embedded whitespace": {"Bearer to\tken"},
		"wrong scheme":        {"Basic token"},
		"duplicate":           {"Bearer token", "Bearer token"},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest("GET", "/", nil)
			for _, value := range values {
				request.Header.Add("Authorization", value)
			}
			if token, ok := siteCaptureBearerToken(request); ok {
				t.Fatalf("accepted token %q", token)
			}
		})
	}

	request := httptest.NewRequest("GET", "/", nil)
	request.Header.Set("Authorization", "bEaReR exact-token")
	if token, ok := siteCaptureBearerToken(request); !ok || token != "exact-token" {
		t.Fatalf("canonical token=(%q,%v)", token, ok)
	}
}
