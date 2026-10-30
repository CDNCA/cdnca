package edgeconfig

import (
	"fmt"
	"slices"
)

// LazyCertificateSiteRuntimeVersion is the site runtime API version whose
// document may carry lazy_certificates: the node serves the HTTPS sites of a
// port from one default server per socket that picks each site's certificate
// by SNI with nginx variable certificates (a map per port), instead of one
// SSL_CTX per site server. Control writes it only when every target node
// declares this version; otherwise sites keep their own certificates.
const LazyCertificateSiteRuntimeVersion uint32 = 7

// DynamicRoutingSiteRuntimeVersion is the site runtime API version of
// dynamic routing (ADR 0009 section 8.1), the only node runtime: one shared
// server per port, sites are data selected per request (libs/edgeconfig/
// edgeskeleton renders the node skeleton), delivered as a signed v2 site
// object root plus content-addressed objects. Only the root and the rollout
// require it; the v2 document inside keeps 2..MaxDocumentSiteRuntimeVersion.
const DynamicRoutingSiteRuntimeVersion uint32 = 9

// MaxDocumentSiteRuntimeVersion is the highest site_runtime a site runtime
// v2 document may require.
const MaxDocumentSiteRuntimeVersion = LazyCertificateSiteRuntimeVersion

// MaxSiteRuntimeVersion is the highest site runtime API version control
// publishes and nodes accept (and declare).
const MaxSiteRuntimeVersion = DynamicRoutingSiteRuntimeVersion

// MinSiteRuntimeVersion is the lowest: the 1.0.35 compatibility baseline.
// Every site runtime document needs it, whatever it carries (cache, managed
// WAF and JS challenge, which introduced it, are no longer separate gates);
// control publishes nothing below it and nodes refuse anything below it.
const MinSiteRuntimeVersion = ListenerRuntimeSecuritySiteRuntimeVersion

const (
	// DefaultLazyCertificateCacheMax bounds each worker's parsed certificate
	// cache (ssl_certificate_cache max=): ≈4 KiB per P-256 certificate and key.
	DefaultLazyCertificateCacheMax int64 = 10000
	MaxLazyCertificateCacheMax     int64 = 1000000
)

// lazyCertificateProtocols is the TLS protocol set of the lazy default
// server. A site whose listener asks for another set keeps its own
// certificate (its own SSL_CTX), because protocols are a property of the
// SSL_CTX a handshake starts on, not of the site server SNI selects.
var lazyCertificateProtocols = []string{"TLSv1.2", "TLSv1.3"}

// LazyCertificateProtocols returns the lazy default server's protocols.
func LazyCertificateProtocols() []string { return slices.Clone(lazyCertificateProtocols) }

// SiteRuntimeLazyCertificates turns lazy certificates on for a site runtime
// v2 document (site runtime v7).
type SiteRuntimeLazyCertificates struct {
	// CacheMax is ssl_certificate_cache max= on each lazy default server.
	CacheMax int64 `json:"cache_max"`
}

func (value SiteRuntimeLazyCertificates) Validate() error {
	if value.CacheMax < 1 || value.CacheMax > MaxLazyCertificateCacheMax {
		return fmt.Errorf("%w: lazy certificate cache_max must be 1..%d", ErrInvalidConfig, MaxLazyCertificateCacheMax)
	}
	return nil
}

// LazyCertificateTLSProfile reports whether a TLS listener's profile is the
// lazy default server's: the baseline (protocols nil or exactly TLSv1.2
// TLSv1.3, default ciphers, no OCSP stapling, no client certificates).
// Stapling and client CAs belong to a server's own SSL_CTX, which a
// variable-certificate server does not have per site.
func LazyCertificateTLSProfile(profile TLSProfile) bool {
	return profile.Baseline() && (profile.Protocols == nil || slices.Equal(profile.Protocols, lazyCertificateProtocols))
}
