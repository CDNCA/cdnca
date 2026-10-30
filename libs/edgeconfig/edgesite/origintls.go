package edgesite

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
)

// Origin TLS (dynamic routing D5b).
//
// An HTTPS endpoint names its trust anchor:
//   - "sha256:<hex>": a CA set object in the object store, addressed by the
//     SHA-256 of its plaintext (the same bytes v7 publishes as
//     origin-trust/<hex>.pem). The node verifies the origin's whole chain
//     against exactly this set (ADR 0009 PoC section 3): no tenant CA ever
//     enters a node-level trust store.
//   - TrustSystem ("system"): the node's system CA bundle. Reserved for
//     ge-origin (site origins may pick "system CA"); the node accepts it and
//     loads the bundle it was configured with.
//   - TrustNone ("none", fix-originnoverify, 回源 HTTPS 不校验源站证书): the
//     node accepts any origin certificate chain and skips the host name
//     check (native patch 29). Needs CAPABILITY_NAME_ORIGIN_TLS_NO_VERIFY;
//     the site chose it knowing the origin hop has no MITM protection.

// TrustSystem is the node system CA bundle as a trust anchor.
const TrustSystem = "system"

// TrustNone: the origin certificate is not verified.
const TrustNone = "none"

// MaxCASetBytes bounds one CA set object.
const MaxCASetBytes = 256 << 10

// MaxCASetCertificates bounds the certificates of one CA set.
const MaxCASetCertificates = 64

// ValidTrustAnchor reports whether anchor names a CA set object, the
// system bundle or no verification.
func ValidTrustAnchor(anchor string) bool {
	return anchor == TrustSystem || anchor == TrustNone || anchorPattern.MatchString(anchor)
}

// TrustAnchorDigest is the CA set object digest of anchor ("" for the
// system bundle or an invalid anchor).
func TrustAnchorDigest(anchor string) string {
	if !anchorPattern.MatchString(anchor) {
		return ""
	}
	return strings.TrimPrefix(anchor, "sha256:")
}

// ValidateCASet checks a CA set object: PEM CERTIFICATE blocks only (no
// keys, no headers, no trailing text), each parseable, bounded. Every
// certificate is a trust anchor of the pool, as v7's
// proxy_ssl_trusted_certificate file is (the control plane check is
// edgedeployment validOriginTrustPEM): a pinned self-signed origin
// certificate is allowed. The node rejects a set this refuses.
func ValidateCASet(raw []byte) error {
	if len(raw) == 0 || len(raw) > MaxCASetBytes {
		return fmt.Errorf("%w: CA set of %d bytes", ErrInvalid, len(raw))
	}
	rest := raw
	count := 0
	for {
		rest = bytes.TrimLeft(rest, " \t\r\n")
		if len(rest) == 0 {
			break
		}
		block, next := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return fmt.Errorf("%w: CA set holds something other than certificates", ErrInvalid)
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return fmt.Errorf("%w: CA set certificate %d: %v", ErrInvalid, count+1, err)
		}
		count++
		if count > MaxCASetCertificates {
			return fmt.Errorf("%w: CA set holds more than %d certificates", ErrInvalid, MaxCASetCertificates)
		}
		rest = next
	}
	if count == 0 {
		return fmt.Errorf("%w: empty CA set", ErrInvalid)
	}
	return nil
}

// TrustAnchors is the CA set object digests the site's HTTPS endpoints
// reference (sorted, unique): the agent puts these objects in the
// worker-readable object directory with the site object.
func (site Site) TrustAnchors() []string {
	seen := map[string]bool{}
	var digests []string
	for _, pool := range site.Origin.Pools {
		for _, endpoint := range pool.Endpoints {
			if digest := TrustAnchorDigest(endpoint.TrustAnchor); digest != "" && !seen[digest] {
				seen[digest] = true
				digests = append(digests, digest)
			}
		}
	}
	sortStrings(digests)
	return digests
}

// TLSName is the SNI and verified name of an HTTPS endpoint for a request
// whose visitor host ($host) is visitorHost (Lua cdnca_origin tls_name):
//
//	custom        the endpoint's SNI
//	origin_host   the endpoint's Host
//	visitor_host  the visitor's host
//	absent        the SNI when set, else the origin request Host without
//	              its port (v7 poolTLSName)
//
// The control plane writes the mode explicitly (v7 semantics expanded);
// absent stays for objects built without it.
func (pool Pool) TLSName(endpoint Endpoint, visitorHost string) string {
	switch endpoint.SNIMode {
	case SNICustom:
		return endpoint.SNI
	case SNIOriginHost:
		return endpoint.Host
	case SNIVisitorHost:
		return visitorHost
	}
	if endpoint.SNI != "" {
		return endpoint.SNI
	}
	if host := pool.RequestHost; host != nil && host.Mode == RequestHostCustom {
		return requestHostName(host.Value)
	} else if host != nil && host.Mode == RequestHostOrigin {
		return endpoint.Host
	}
	return visitorHost
}

// ExpandSNIModes writes the v7 SNI semantics (poolTLSName) as an explicit
// sni_mode on every HTTPS endpoint without one: a configured SNI is
// custom; else a custom request Host is custom with its name, an origin
// request Host is origin_host, the visitor's Host is visitor_host. TLSName
// gives the same name before and after.
func (pool *Pool) ExpandSNIModes() {
	for index := range pool.Endpoints {
		endpoint := &pool.Endpoints[index]
		if endpoint.Scheme != "https" || endpoint.SNIMode != "" {
			continue
		}
		switch host := pool.RequestHost; {
		case endpoint.SNI != "":
			endpoint.SNIMode = SNICustom
		case host != nil && host.Mode == RequestHostCustom:
			endpoint.SNIMode, endpoint.SNI = SNICustom, requestHostName(host.Value)
		case host != nil && host.Mode == RequestHostOrigin:
			endpoint.SNIMode = SNIOriginHost
		default:
			endpoint.SNIMode = SNIVisitorHost
		}
	}
}

// requestHostName is a request_host value without its port or brackets.
func requestHostName(value string) string {
	if strings.HasPrefix(value, "[") {
		return value[1:strings.Index(value, "]")]
	}
	if index := strings.LastIndex(value, ":"); index >= 0 {
		return value[:index]
	}
	return value
}

// KeepaliveKey is the upstream connection reuse key the node passes to
// balancer.set_current_peer for an endpoint whose SNI is the request's
// resolved name (Pool.TLSName; Lua cdnca_origintls.key builds
// the same bytes; TestKeepaliveKeyMatchesLua pins them). ngx_lua reuses an
// idle connection only when this key, the peer address and the local
// address all match (ngx_http_lua_balancer.c:1477-1486), so the key must
// carry every connection-level property:
//
//	https|<sni>|<trust anchor>|<auth identity>
//	http||-|<auth identity>
//
// Trust anchor: two pools that trust different CAs never share a
// connection verified under one of them (PoC section 3). Auth identity: the
// origin auth secret (id@revision) signing requests on that pool, "-" for
// none, so connections of different signing identities stay apart. The
// separator is "|", not NUL: ngx_strncasecmp stops at NUL, a NUL-separated
// key would compare equal to its prefix. None of the fields can contain "|".
// The real SNI goes to proxy_ssl_name ($cdnca_origin_sni), which nginx
// evaluates after the balancer (ngx_http_upstream.c:1937-1949).
func KeepaliveKey(endpoint Endpoint, auth *OriginAuth) string {
	identity := "-"
	if auth != nil {
		identity = fmt.Sprintf("%s@%d", auth.Secret.ID, auth.Secret.Revision)
	}
	if endpoint.Scheme == "https" {
		return "https|" + endpoint.SNI + "|" + endpoint.TrustAnchor + "|" + identity
	}
	return "http||-|" + identity
}

// AuthForPool is the origin auth binding of poolID, nil when the pool's
// requests are not signed.
func (origin Origin) AuthForPool(poolID string) *OriginAuth {
	for index := range origin.Auth {
		if origin.Auth[index].PoolID == poolID {
			return &origin.Auth[index]
		}
	}
	return nil
}
