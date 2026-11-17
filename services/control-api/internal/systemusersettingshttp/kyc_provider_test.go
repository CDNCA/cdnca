package systemusersettingshttp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
)

// The KYC provider fields travel in value, the object store
// keys are write-only body fields; the response never echoes the keys.
func TestHandlerForwardsKYCProviderFieldsAndObjectKeys(t *testing.T) {
	document := settingsDocument(5)
	document.KYCObjectSecretAccessKeyConfigured, document.KYCObjectSecretAccessKeyFingerprint = true, "0123456789abcdef"
	stub := &serviceStub{document: document}
	value := systemusersettings.DefaultSettings()
	value.KYCEndpoint, value.KYCObjectBucket = "https://kyc.example.com", "kyc-bucket"
	response := httptest.NewRecorder()
	newTestHandler(t, stub).ServeHTTP(response, putRequest(t, map[string]any{"value": value,
		"kyc_object_access_key_id": "AKIAEXAMPLEKEY", "kyc_object_secret_access_key": "plain-object-secret",
		"kyc_object_session_token": ""}))
	if response.Code != http.StatusOK || stub.saved == nil || stub.saved.Value.KYCEndpoint != "https://kyc.example.com" ||
		stub.saved.Value.KYCObjectBucket != "kyc-bucket" {
		t.Fatalf("status=%d request=%#v", response.Code, stub.saved)
	}
	secrets := stub.saved.Secrets
	if secrets[systemusersettings.SecretKYCObjectAccessKeyID] == nil || *secrets[systemusersettings.SecretKYCObjectAccessKeyID] != "AKIAEXAMPLEKEY" ||
		secrets[systemusersettings.SecretKYCObjectSecretAccessKey] == nil || *secrets[systemusersettings.SecretKYCObjectSecretAccessKey] != "plain-object-secret" ||
		secrets[systemusersettings.SecretKYCObjectSessionToken] == nil || *secrets[systemusersettings.SecretKYCObjectSessionToken] != "" {
		t.Fatalf("secrets=%#v", secrets)
	}
	if body := response.Body.String(); strings.Contains(body, "plain-object-secret") ||
		!strings.Contains(body, `"kyc_object_secret_access_key_configured":true`) {
		t.Fatalf("response=%s", body)
	}
}

// The issuer fields travel in value, the server
// private key is a write-only body field; the response never echoes it.
func TestHandlerForwardsKYCIssuerFieldsAndPrivateKey(t *testing.T) {
	const privateKey = "-----BEGIN PRIVATE KEY-----\nplain-issuer-key\n-----END PRIVATE KEY-----"
	document := settingsDocument(5)
	document.KYCIssuerServerPrivateKeyConfigured, document.KYCIssuerServerPrivateKeyFingerprint = true, "0123456789abcdef"
	stub := &serviceStub{document: document}
	value := systemusersettings.DefaultSettings()
	value.KYCIssuerEnabled, value.KYCIssuerListenAddress = true, "0.0.0.0:19443"
	response := httptest.NewRecorder()
	newTestHandler(t, stub).ServeHTTP(response, putRequest(t, map[string]any{"value": value,
		"kyc_issuer_server_private_key": privateKey}))
	if response.Code != http.StatusOK || stub.saved == nil || !stub.saved.Value.KYCIssuerEnabled ||
		stub.saved.Value.KYCIssuerListenAddress != "0.0.0.0:19443" {
		t.Fatalf("status=%d request=%#v", response.Code, stub.saved)
	}
	if secret := stub.saved.Secrets[systemusersettings.SecretKYCIssuerServerPrivateKey]; secret == nil || *secret != privateKey {
		t.Fatalf("secrets=%#v", stub.saved.Secrets)
	}
	if body := response.Body.String(); strings.Contains(body, "plain-issuer-key") ||
		!strings.Contains(body, `"kyc_issuer_server_private_key_configured":true`) {
		t.Fatalf("response=%s", body)
	}
}
