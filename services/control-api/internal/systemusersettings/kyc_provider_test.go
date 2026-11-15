package systemusersettings

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
)

// The KYC provider endpoint, callback key ID and private
// object store of the system settings page. Each value is checked on save
// in the form the provider runtime accepts; an empty value means "not set on
// the page" (the runtime then falls back to IDENTITY_VERIFICATION_*).
func TestSettingsFieldErrorKYCProviderFields(t *testing.T) {
	for name, tc := range map[string]struct {
		set    func(*Settings)
		field  string
		reason string
	}{
		"all empty": {set: func(*Settings) {}},
		"complete": {set: func(value *Settings) {
			value.KYCProviderName, value.KYCEndpoint, value.KYCCallbackKeyID = "trusted-kyc", "https://kyc.example.com", "callback-key-1"
			value.KYCObjectEndpoint, value.KYCObjectRegion, value.KYCObjectBucket = "https://s3.example.com", "us-east-1", "kyc-bucket"
			value.KYCObjectPrefix, value.KYCObjectKMSKeyID = "tenant-a", "arn:aws:kms:us-east-1:1:key/abc"
		}},
		"endpoint http":         {set: func(value *Settings) { value.KYCEndpoint = "http://kyc.example.com" }, field: "value.kyc_endpoint", reason: fielderr.InvalidFormat},
		"endpoint path":         {set: func(value *Settings) { value.KYCEndpoint = "https://kyc.example.com/v1" }, field: "value.kyc_endpoint", reason: fielderr.InvalidFormat},
		"endpoint ip":           {set: func(value *Settings) { value.KYCEndpoint = "https://10.0.0.1" }, field: "value.kyc_endpoint", reason: fielderr.InvalidFormat},
		"endpoint port":         {set: func(value *Settings) { value.KYCEndpoint = "https://kyc.example.com:8443" }, field: "value.kyc_endpoint", reason: fielderr.InvalidFormat},
		"endpoint port 443":     {set: func(value *Settings) { value.KYCEndpoint = "https://kyc.example.com:443" }},
		"object endpoint http":  {set: func(value *Settings) { value.KYCObjectEndpoint = "http://s3.example.com" }, field: "value.kyc_object_endpoint", reason: fielderr.InvalidFormat},
		"object endpoint local": {set: func(value *Settings) { value.KYCObjectEndpoint = "https://localhost" }, field: "value.kyc_object_endpoint", reason: fielderr.InvalidFormat},
		"provider name":         {set: func(value *Settings) { value.KYCProviderName = "Trusted KYC" }, field: "value.kyc_provider_name", reason: fielderr.InvalidFormat},
		"callback key id":       {set: func(value *Settings) { value.KYCCallbackKeyID = "-key" }, field: "value.kyc_callback_key_id", reason: fielderr.InvalidFormat},
		"region":                {set: func(value *Settings) { value.KYCObjectRegion = "us_east_1" }, field: "value.kyc_object_region", reason: fielderr.InvalidFormat},
		"bucket":                {set: func(value *Settings) { value.KYCObjectBucket = "KYC" }, field: "value.kyc_object_bucket", reason: fielderr.InvalidFormat},
		"bucket ip":             {set: func(value *Settings) { value.KYCObjectBucket = "10.0.0.1" }, field: "value.kyc_object_bucket", reason: fielderr.InvalidFormat},
		"prefix slash":          {set: func(value *Settings) { value.KYCObjectPrefix = "a/b" }, field: "value.kyc_object_prefix", reason: fielderr.InvalidFormat},
		"prefix dots":           {set: func(value *Settings) { value.KYCObjectPrefix = ".." }, field: "value.kyc_object_prefix", reason: fielderr.InvalidFormat},
		"kms key":               {set: func(value *Settings) { value.KYCObjectKMSKeyID = "key with space" }, field: "value.kyc_object_kms_key_id", reason: fielderr.InvalidFormat},
		"kms key long":          {set: func(value *Settings) { value.KYCObjectKMSKeyID = strings.Repeat("k", 257) }, field: "value.kyc_object_kms_key_id", reason: fielderr.InvalidFormat},
	} {
		value := DefaultSettings()
		tc.set(&value)
		err := settingsFieldError(value)
		located, ok := fielderr.As(err)
		switch {
		case tc.field == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case tc.field != "" && (!errors.Is(err, ErrInvalidInput) || !ok || located.Field != tc.field || located.Reason != tc.reason):
			t.Errorf("%s: %v, want %s %s", name, err, tc.field, tc.reason)
		}
	}
}

// The object store keys are write-only page secrets with the length limits
// of the provider runtime (the session token is optional and up to 4096).
func TestSecretsFieldErrorKYCObjectCredentials(t *testing.T) {
	text := func(value string) *string { return &value }
	for name, tc := range map[string]struct {
		name, secret, reason string
	}{
		"access key":         {name: SecretKYCObjectAccessKeyID, secret: "AKIAEXAMPLE"},
		"access key short":   {name: SecretKYCObjectAccessKeyID, secret: "AK", reason: fielderr.TooShort},
		"access key long":    {name: SecretKYCObjectAccessKeyID, secret: strings.Repeat("a", 257), reason: fielderr.TooLong},
		"secret key":         {name: SecretKYCObjectSecretAccessKey, secret: "object-secret-key"},
		"secret key short":   {name: SecretKYCObjectSecretAccessKey, secret: "short", reason: fielderr.TooShort},
		"secret key long":    {name: SecretKYCObjectSecretAccessKey, secret: strings.Repeat("s", 513), reason: fielderr.TooLong},
		"session token":      {name: SecretKYCObjectSessionToken, secret: strings.Repeat("t", 4096)},
		"session token long": {name: SecretKYCObjectSessionToken, secret: strings.Repeat("t", 4097), reason: fielderr.TooLong},
	} {
		err := secretsFieldError(DefaultSettings(), map[string]*string{tc.name: text(tc.secret)}, nil)
		located, ok := fielderr.As(err)
		switch {
		case tc.reason == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case tc.reason != "" && (!ok || located.Field != tc.name || located.Reason != tc.reason):
			t.Errorf("%s: %v, want %s %s", name, err, tc.name, tc.reason)
		}
	}
}

// Reads return only whether each object store key is set and its
// fingerprint, never the key itself.
func TestDocumentKYCObjectCredentialsAreWriteOnly(t *testing.T) {
	secrets := map[string]string{SecretKYCObjectAccessKeyID: "AKIA-PLAINTEXT-ACCESS", SecretKYCObjectSecretAccessKey: "plaintext-object-secret",
		SecretKYCObjectSessionToken: "plaintext-session-token", SecretKYCAPIKey: "plaintext-kyc-api-key"}
	var document Document
	document.setSecrets(secretFingerprints(secrets))
	if !document.KYCObjectAccessKeyIDConfigured || !document.KYCObjectSecretAccessKeyConfigured || !document.KYCObjectSessionTokenConfigured ||
		len(document.KYCObjectAccessKeyIDFingerprint) != 16 || document.KYCObjectSecretAccessKeyFingerprint == document.KYCObjectAccessKeyIDFingerprint {
		t.Fatalf("document=%+v", document)
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range secrets {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("read echoes a secret: %s", encoded)
		}
	}
	for _, key := range []string{`"kyc_object_access_key_id_configured":true`, `"kyc_object_secret_access_key_configured":true`, `"kyc_object_session_token_configured":true`} {
		if !strings.Contains(string(encoded), key) {
			t.Fatalf("missing %s in %s", key, encoded)
		}
	}
}

// The runtime view carries the page values and the opened page secrets.
func TestKYCProviderRuntimeFromPage(t *testing.T) {
	value := DefaultSettings()
	value.KYCProviderName, value.KYCEndpoint, value.KYCCallbackKeyID = "trusted-kyc", "https://kyc.example.com", "callback-key-1"
	value.KYCObjectEndpoint, value.KYCObjectRegion, value.KYCObjectBucket = "https://s3.example.com", "us-east-1", "kyc-bucket"
	value.KYCObjectPrefix, value.KYCObjectKMSKeyID = "tenant-a", "kms-key-1"
	var runtime IdentityVerificationRuntime
	setKYCProviderRuntime(&runtime, value, map[string]string{SecretKYCAPIKey: "page-kyc-api-key-0001",
		SecretKYCObjectAccessKeyID: "AKIAEXAMPLE", SecretKYCObjectSecretAccessKey: "object-secret-key"})
	if runtime.KYCProviderName != "trusted-kyc" || runtime.KYCEndpoint != "https://kyc.example.com" || runtime.KYCCallbackKeyID != "callback-key-1" ||
		runtime.ObjectEndpoint != "https://s3.example.com" || runtime.ObjectRegion != "us-east-1" || runtime.ObjectBucket != "kyc-bucket" ||
		runtime.ObjectPrefix != "tenant-a" || runtime.ObjectKMSKeyID != "kms-key-1" ||
		string(runtime.KYCAPIKey) != "page-kyc-api-key-0001" || runtime.KYCCallbackHMAC != nil ||
		string(runtime.ObjectAccessKey) != "AKIAEXAMPLE" || string(runtime.ObjectSecretKey) != "object-secret-key" || runtime.ObjectSessionToken != nil {
		t.Fatalf("runtime=%+v", runtime)
	}
}
