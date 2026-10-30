package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"time"
)

// Master release artifacts are only served to a license's registered master IP
// (or a valid 迁移下载 IP IP). The list matches
// apps/operator-console/nginx-master-downloads.conf; entry scripts, the edge
// agent and the release trust root stay public.
var masterDownloadPrefixes = []string{
	"/downloads/control-native/", "/downloads/control-api/", "/downloads/agent-gateway/", "/downloads/control-web/",
}

var publicMasterDownloadFiles = map[string]bool{"/downloads/control-native/artifacts.json": true}

const defaultAuthorizationTimeout = 3 * time.Second

type handlerOptions struct {
	// MasterDownloadAuthorization is license-service's
	// /download-authorization/v1/master; nil disables the gate.
	MasterDownloadAuthorization *url.URL
	AuthorizationTimeout        time.Duration
	// PortalStaticRoot is the customer portal build (apps/license-portal
	// dist, base /console/); empty leaves /console to the operator fallback.
	PortalStaticRoot string
	// ReleaseArtifactRoot holds packages uploaded through the operator console
	// (license-service LICENSE_RELEASE_ARTIFACT_DIR), laid out as
	// <component>/<version>/<file> and served under /downloads/ when the static
	// tree has no such file. Empty disables it.
	ReleaseArtifactRoot string
	// ClientIP resolves the client behind a CDN (protocol T2); the zero
	// value uses the TCP peer only.
	ClientIP clientIPResolver
	// Tunnel serves /mtls/v1/tunnel/<target> (protocol T1); nil disables it.
	Tunnel *mtlsTunnel
}

// masterDownloadPath reports whether a cleaned static path is gated.
func masterDownloadPath(cleaned string) bool {
	if publicMasterDownloadFiles[cleaned] {
		return false
	}
	for _, prefix := range masterDownloadPrefixes {
		if strings.HasPrefix(cleaned, prefix) || cleaned+"/" == prefix {
			return true
		}
	}
	return false
}

// tcpPeer is the address the request arrived from; client-supplied
// forwarding headers are never consulted. Behind a CDN the entry handler has
// already replaced RemoteAddr with the origin-authenticated client address
// (clientIPResolver.apply), so the gate and the proxy see the same client.
func tcpPeer(request *http.Request) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return netip.Addr{}, false
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return address.Unmap(), true
}

type masterDownloadGate struct {
	endpoint *url.URL
	client   *http.Client
	timeout  time.Duration
	// self holds this host's own addresses: license-service on the same host
	// fetches artifacts through the public name (release repository
	// verification), which hairpins back here from the host's public IP.
	self map[netip.Addr]bool
}

func localAddresses() map[netip.Addr]bool {
	result := map[netip.Addr]bool{}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return result
	}
	for _, address := range addresses {
		if prefix, err := netip.ParsePrefix(address.String()); err == nil {
			result[prefix.Addr().Unmap()] = true
		}
	}
	return result
}

func newMasterDownloadGate(endpoint *url.URL, timeout time.Duration) *masterDownloadGate {
	if timeout <= 0 {
		timeout = defaultAuthorizationTimeout
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &masterDownloadGate{endpoint: endpoint, timeout: timeout, self: localAddresses(), client: &http.Client{
		Transport: transport,
		Timeout:   timeout,
		// A redirect is not an authorization decision.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// allow answers the download, or writes the 403/503 response and returns false.
func (gate *masterDownloadGate) allow(response http.ResponseWriter, request *http.Request) bool {
	peer, ok := tcpPeer(request)
	if !ok {
		writeDownloadDenied(response, request, "未知")
		return false
	}
	if gate.self[peer] {
		return true
	}
	ctx, cancel := context.WithTimeout(request.Context(), gate.timeout)
	defer cancel()
	check, err := http.NewRequestWithContext(ctx, http.MethodGet, gate.endpoint.String(), nil)
	if err != nil {
		writeDownloadUnavailable(response)
		return false
	}
	check.Header.Set("X-Real-IP", peer.String())
	check.Header.Set("X-Forwarded-For", peer.String())
	result, err := gate.client.Do(check)
	if err != nil {
		writeDownloadUnavailable(response)
		return false
	}
	_ = result.Body.Close()
	switch {
	case result.StatusCode >= 200 && result.StatusCode < 300:
		return true
	case result.StatusCode == http.StatusForbidden:
		writeDownloadDenied(response, request, peer.String())
	default:
		writeDownloadUnavailable(response)
	}
	return false
}

func writeDownloadDenied(response http.ResponseWriter, request *http.Request, observed string) {
	header := response.Header()
	header.Set("Content-Type", "text/plain; charset=utf-8")
	header.Set("Cache-Control", "no-store")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-CDNCA-Download-Denied", "master-ip")
	response.WriteHeader(http.StatusForbidden)
	if request.Method != http.MethodHead {
		_, _ = fmt.Fprintf(response, "cdnca: 本机公网 IP %s 未登记为主控 IP，无法下载主控安装包。"+
			"请在授权门户确认主控 IP，或在“迁移下载 IP”中填写本机 IP 后重试。\n", observed)
	}
}

func writeDownloadUnavailable(response http.ResponseWriter) {
	header := response.Header()
	header.Set("Content-Type", "text/plain; charset=utf-8")
	header.Set("Cache-Control", "no-store")
	header.Set("Retry-After", "30")
	response.WriteHeader(http.StatusServiceUnavailable)
	_, _ = fmt.Fprint(response, "cdnca: 授权服务暂时无法校验主控 IP，请稍后重试。\n")
}

func cleanStaticPath(staticPath string) string {
	return path.Clean("/" + staticPath)
}
