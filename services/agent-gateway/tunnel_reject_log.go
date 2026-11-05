package gateway

// Rejected tunnel upgrades are logged with enough to find the node (node ID,
// serial, issuer, validity, real source) and folded per node ID + reason: one
// full line per tunnelRejectLogInterval, the next line carries how many were
// folded. The 401 body stays "unauthenticated"; nothing here reaches the peer.

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	tunnelRejectLogInterval = 10 * time.Minute
	// tunnelRejectLogKeys bounds the fold table; forged certificates with
	// fresh node IDs share one overflow entry once it is full.
	tunnelRejectLogKeys = 1024
)

type tunnelRejectLog struct {
	mu      sync.Mutex
	now     func() time.Time
	logf    func(string, ...any)
	entries map[string]*tunnelRejectEntry
}

type tunnelRejectEntry struct {
	logged     time.Time
	suppressed int
}

func newTunnelRejectLog(now func() time.Time, logf func(string, ...any)) *tunnelRejectLog {
	return &tunnelRejectLog{now: now, logf: logf, entries: map[string]*tunnelRejectEntry{}}
}

// tunnelCertificateFacts reads what the certificate header claims, without
// trusting it: it only labels the log line.
type tunnelCertificateFacts struct {
	nodeID, serial, issuerCN, issuerKeyID, notBefore, notAfter string
}

func certificateFacts(header string) tunnelCertificateFacts {
	facts := tunnelCertificateFacts{nodeID: "unknown", serial: "unknown", issuerCN: "unknown", issuerKeyID: "unknown", notBefore: "unknown", notAfter: "unknown"}
	if len(header) == 0 || len(header) > maxTunnelHeader {
		return facts
	}
	der, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		return facts
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return facts
	}
	if nodeID, err := nodeIDFromCertificate(leaf); err == nil {
		facts.nodeID = nodeID
	}
	if leaf.SerialNumber != nil && leaf.SerialNumber.Sign() > 0 {
		facts.serial = clip(strings.ToLower(leaf.SerialNumber.Text(16)), 40)
	}
	if leaf.Issuer.CommonName != "" {
		facts.issuerCN = clip(leaf.Issuer.CommonName, 64)
	}
	// The authority key ID is the issuer's subject key ID: SHA-1 of the
	// node CA public key (install-control.sh subjectKeyIdentifier = hash).
	if len(leaf.AuthorityKeyId) > 0 {
		facts.issuerKeyID = clip(hex.EncodeToString(leaf.AuthorityKeyId), 16)
	}
	facts.notBefore = leaf.NotBefore.UTC().Format(time.RFC3339)
	facts.notAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
	return facts
}

func clip(value string, limit int) string {
	if len(value) > limit {
		return value[:limit]
	}
	return value
}

// rejectSource is the address the upgrade came from. Forwarding headers are
// read only from a loopback peer (the local nginx reverse proxy): first
// CF-Connecting-IP (Cloudflare in front of nginx), then X-Real-IP (nginx
// $remote_addr), then the leftmost X-Forwarded-For hop. Any other peer is
// reported as itself.
func rejectSource(request *http.Request) (string, string) {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		host = request.RemoteAddr
	}
	peerAddr, err := netip.ParseAddr(host)
	if err != nil || !peerAddr.Unmap().IsLoopback() {
		return clip(host, 64), "peer"
	}
	for _, name := range []string{"Cf-Connecting-Ip", "X-Real-Ip"} {
		if addr, ok := parseHeaderIP(request.Header.Get(name)); ok {
			return addr, name
		}
	}
	if first, _, _ := strings.Cut(request.Header.Get("X-Forwarded-For"), ","); first != "" {
		if addr, ok := parseHeaderIP(first); ok {
			return addr, "X-Forwarded-For"
		}
	}
	return host, "peer"
}

func parseHeaderIP(value string) (string, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return "", false
	}
	return addr.Unmap().WithZone("").String(), true
}

func (l *tunnelRejectLog) record(request *http.Request, err error) {
	facts := certificateFacts(request.Header.Get(TunnelNodeCertificateHeader))
	reason := err.Error()
	key := facts.nodeID + "\n" + reason
	now := l.now()
	l.mu.Lock()
	entry, ok := l.entries[key]
	if !ok && len(l.entries) >= tunnelRejectLogKeys {
		for k, e := range l.entries {
			if now.Sub(e.logged) >= tunnelRejectLogInterval {
				delete(l.entries, k)
			}
		}
		if len(l.entries) >= tunnelRejectLogKeys {
			key = "overflow"
			entry, ok = l.entries[key]
		}
	}
	if ok && now.Sub(entry.logged) < tunnelRejectLogInterval {
		entry.suppressed++
		l.mu.Unlock()
		return
	}
	repeated := 0
	if ok {
		repeated = entry.suppressed
	}
	l.entries[key] = &tunnelRejectEntry{logged: now}
	l.mu.Unlock()
	source, sourceHeader := rejectSource(request)
	l.logf("agent-gateway tunnel rejected peer=%s source=%s source_header=%s host=%q node_id=%s serial=%s issuer_cn=%q issuer_key_id=%s not_before=%s not_after=%s error=%q repeated=%s",
		request.RemoteAddr, source, sourceHeader, clip(request.Host, 128), facts.nodeID, facts.serial, facts.issuerCN, facts.issuerKeyID,
		facts.notBefore, facts.notAfter, reason, strconv.Itoa(repeated))
}
