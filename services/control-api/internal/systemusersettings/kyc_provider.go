package systemusersettings

import (
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
)

// The KYC provider fields of the page are checked in the form
// identityverificationhttp.NewHTTPSKYCProvider / NewS3PrivateObjectStore
// accept (that package depends on this one, so the rules are repeated here).
var (
	kycProviderNamePattern  = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)
	kycCallbackKeyIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	kycObjectRegionPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,62}$`)
	kycObjectBucketPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	kycKMSKeyIDPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`)
)

// kycProviderFieldError names the first KYC provider field that is set but
// not usable; nil when every set field is valid (unset fields come from the
// environment at runtime).
func kycProviderFieldError(value Settings) error {
	for _, item := range []struct {
		name, value string
		valid       func(string) bool
	}{
		{"kyc_provider_name", value.KYCProviderName, kycProviderNamePattern.MatchString},
		{"kyc_endpoint", value.KYCEndpoint, validKYCEndpoint},
		{"kyc_callback_key_id", value.KYCCallbackKeyID, kycCallbackKeyIDPattern.MatchString},
		{"kyc_object_endpoint", value.KYCObjectEndpoint, validKYCEndpoint},
		{"kyc_object_region", value.KYCObjectRegion, kycObjectRegionPattern.MatchString},
		{"kyc_object_bucket", value.KYCObjectBucket, validKYCObjectBucket},
		{"kyc_object_prefix", value.KYCObjectPrefix, validKYCObjectPrefix},
		{"kyc_object_kms_key_id", value.KYCObjectKMSKeyID, kycKMSKeyIDPattern.MatchString},
	} {
		if item.value != "" && !item.valid(item.value) {
			return fielderr.New(ErrInvalidInput, "value."+item.name, fielderr.InvalidFormat)
		}
	}
	return nil
}

// validKYCEndpoint: an https origin with a DNS host name (no path, query,
// user info, IP literal or localhost; port 443 only).
func validKYCEndpoint(raw string) bool {
	if raw == "" || strings.ContainsAny(raw, "\r\n\t") {
		return false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Opaque != "" || parsed.User != nil || parsed.Host == "" || parsed.Path != "" ||
		parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".localhost") ||
		net.ParseIP(host) != nil || strings.Contains(host, "%") || strings.HasSuffix(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}
	port := parsed.Port()
	return port == "" || port == "443"
}

func validKYCObjectBucket(value string) bool {
	if !kycObjectBucketPattern.MatchString(value) || strings.Contains(value, "..") || net.ParseIP(value) != nil {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}
	return true
}

// validKYCObjectPrefix: one object key segment (the store puts it before
// identity-verification/...).
func validKYCObjectPrefix(value string) bool {
	return len("identity-verification/"+value) <= 512 && !strings.ContainsAny(value, "/\\%?#\x00") &&
		value != "." && value != ".."
}

// setKYCProviderRuntime copies the KYC provider fields of the page and the
// opened page secrets into the runtime view.
func setKYCProviderRuntime(runtime *IdentityVerificationRuntime, value Settings, secrets map[string]string) {
	runtime.KYCProviderName, runtime.KYCEndpoint, runtime.KYCCallbackKeyID = value.KYCProviderName, value.KYCEndpoint, value.KYCCallbackKeyID
	runtime.ObjectEndpoint, runtime.ObjectRegion, runtime.ObjectBucket = value.KYCObjectEndpoint, value.KYCObjectRegion, value.KYCObjectBucket
	runtime.ObjectPrefix, runtime.ObjectKMSKeyID = value.KYCObjectPrefix, value.KYCObjectKMSKeyID
	secret := func(name string) []byte {
		if value := secrets[name]; value != "" {
			return []byte(value)
		}
		return nil
	}
	runtime.KYCAPIKey, runtime.KYCCallbackHMAC = secret(SecretKYCAPIKey), secret(SecretKYCCallbackHMACKey)
	runtime.ObjectAccessKey, runtime.ObjectSecretKey = secret(SecretKYCObjectAccessKeyID), secret(SecretKYCObjectSecretAccessKey)
	runtime.ObjectSessionToken = secret(SecretKYCObjectSessionToken)
}
