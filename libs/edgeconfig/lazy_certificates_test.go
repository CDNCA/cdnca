package edgeconfig

import (
	"strings"
	"testing"
)

func TestLazyCertificateSiteRuntimeVersionIsTheHighestDocumentVersion(t *testing.T) {
	if LazyCertificateSiteRuntimeVersion != 7 || LazyCertificateSiteRuntimeVersion <= ListenerRuntimeSecuritySiteRuntimeVersion ||
		MaxDocumentSiteRuntimeVersion != LazyCertificateSiteRuntimeVersion {
		t.Fatalf("lazy certificates = v%d, runtime security = v%d, document max = v%d", LazyCertificateSiteRuntimeVersion,
			ListenerRuntimeSecuritySiteRuntimeVersion, MaxDocumentSiteRuntimeVersion)
	}
}

// Dynamic routing (v9) is the only version nodes declare; v2 documents
// never require it.
func TestDynamicRoutingSiteRuntimeVersionIsTheHighest(t *testing.T) {
	if DynamicRoutingSiteRuntimeVersion != 9 || MaxSiteRuntimeVersion != DynamicRoutingSiteRuntimeVersion ||
		MaxDocumentSiteRuntimeVersion >= DynamicRoutingSiteRuntimeVersion {
		t.Fatalf("dynamic routing = v%d, max = v%d, document max = v%d", DynamicRoutingSiteRuntimeVersion, MaxSiteRuntimeVersion,
			MaxDocumentSiteRuntimeVersion)
	}
}

func TestSiteRuntimeLazyCertificatesValidate(t *testing.T) {
	for _, value := range []int64{1, DefaultLazyCertificateCacheMax, MaxLazyCertificateCacheMax} {
		if err := (SiteRuntimeLazyCertificates{CacheMax: value}).Validate(); err != nil {
			t.Fatalf("cache_max %d: %v", value, err)
		}
	}
	for _, value := range []int64{0, -1, MaxLazyCertificateCacheMax + 1} {
		if (SiteRuntimeLazyCertificates{CacheMax: value}).Validate() == nil {
			t.Fatalf("cache_max %d accepted", value)
		}
	}
	if DefaultLazyCertificateCacheMax < 1 || DefaultLazyCertificateCacheMax > MaxLazyCertificateCacheMax {
		t.Fatalf("default %d out of bounds", DefaultLazyCertificateCacheMax)
	}
}

func TestLazyCertificateTLSProfile(t *testing.T) {
	for _, protocols := range [][]string{nil, {"TLSv1.2", "TLSv1.3"}} {
		if !LazyCertificateTLSProfile(TLSProfile{Protocols: protocols}) {
			t.Fatalf("%v is the port default", protocols)
		}
	}
	for _, protocols := range [][]string{{}, {"TLSv1.3"}, {"TLSv1.3", "TLSv1.2"}, {"TLSv1.2"}} {
		if LazyCertificateTLSProfile(TLSProfile{Protocols: protocols}) {
			t.Fatalf("%v differs from the port default", protocols)
		}
	}
	// Stapling and client CAs need the site's own SSL_CTX; a non-default
	// cipher preset differs from the default server's.
	for _, profile := range []TLSProfile{
		{OCSPStapling: true}, {CipherPreset: TLSCipherCompatible},
		{ClientAuth: ClientAuthOptional, ClientCARef: "sha256:" + strings.Repeat("a", 64)},
	} {
		if LazyCertificateTLSProfile(profile) {
			t.Fatalf("%+v differs from the port default", profile)
		}
	}
	if !LazyCertificateTLSProfile(TLSProfile{CipherPreset: TLSCipherModern, ClientAuth: ClientAuthOff}) {
		t.Fatal("explicit modern/off is the port default")
	}
}
