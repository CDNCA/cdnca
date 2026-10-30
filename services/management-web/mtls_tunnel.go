package main

import (
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/mtlstunnel"
)

// mTLS tunnel (protocol T1): a CDN only proxies 443, so the installation
// mTLS listeners (9448 plugin runtime, 9447 market) are reached as
// wss://<host>:443/mtls/v1/tunnel/<target>. The protocol (subprotocol, frame
// limit, idle timeout, per-source/total limits, byte bridge) is
// libs/mtlstunnel; this file only configures it for the front.
var defaultTunnelTargets = mtlstunnel.TargetPluginRuntime + "=127.0.0.1:9448," +
	mtlstunnel.TargetMarketLicense + "=127.0.0.1:9447"

// parseTunnelTargets reads name=ip:port pairs; an empty value disables the
// tunnel.
func parseTunnelTargets(value string) (map[string]string, error) {
	targets := map[string]string{}
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		name, address, ok := strings.Cut(item, "=")
		if !ok || name == "" || strings.ContainsAny(name, "/ ") {
			return nil, fmt.Errorf("tunnel target %q must be name=host:port", item)
		}
		if _, err := netip.ParseAddrPort(address); err != nil {
			return nil, fmt.Errorf("tunnel target %q must be name=ip:port", item)
		}
		if _, dup := targets[name]; dup {
			return nil, fmt.Errorf("tunnel target %q listed twice", name)
		}
		targets[name] = address
	}
	return targets, nil
}

type mtlsTunnel struct {
	server *mtlstunnel.Server
}

// newMTLSTunnel builds the shared server. The per-source limit counts the T2
// client: the entry handler has already replaced RemoteAddr with the
// origin-authenticated client address (clientIPResolver.apply), so behind a
// CDN every client gets its own 64, not one 64 for the CDN's egress address.
func newMTLSTunnel(targets map[string]string, maxTotal int) *mtlsTunnel {
	return &mtlsTunnel{server: &mtlstunnel.Server{
		Targets:    targets,
		TotalLimit: maxTotal,
		SourceIP:   tunnelSourceIP,
	}}
}

func tunnelSourceIP(request *http.Request) string {
	if address, _, ok := socketPeer(request); ok {
		return address.String()
	}
	return request.RemoteAddr
}

func (tunnel *mtlsTunnel) names() string {
	names := make([]string, 0, len(tunnel.server.Targets))
	for name := range tunnel.server.Targets {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

// serve handles /mtls/v1/tunnel/<target>; source is the T2 resolution
// (tcp|cdn), logged with the client and outcome (the secret never is).
func (tunnel *mtlsTunnel) serve(response http.ResponseWriter, request *http.Request, source string) {
	started := time.Now()
	target := strings.TrimPrefix(request.URL.Path, mtlstunnel.PathPrefix)
	tunnel.server.ServeHTTP(response, request)
	log.Printf("mtls tunnel target=%q client=%s source=%s duration=%s",
		target, tunnelSourceIP(request), source, time.Since(started).Round(time.Millisecond))
}
