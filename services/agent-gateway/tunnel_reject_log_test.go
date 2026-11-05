package gateway

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type rejectLogRecorder struct {
	mu    sync.Mutex
	lines []string
}

func (r *rejectLogRecorder) logf(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, fmt.Sprintf(format, args...))
}

func (r *rejectLogRecorder) take() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	lines := r.lines
	r.lines = nil
	return lines
}

func newRejectTestRouter(t *testing.T, pki *testPKI, logs *rejectLogRecorder, clock *time.Time) *TunnelRouter {
	t.Helper()
	router, err := NewTunnelRouter(TunnelRouterConfig{Certificate: pki.server, NodeCAs: pki.rootPool, Audience: testTunnelAudience,
		Nonces: NewMemoryTunnelNonceStore(), Now: func() time.Time { return *clock }, Logf: logs.logf})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = router.Close() })
	return router
}

func rejectedUpgrade(t *testing.T, router *TunnelRouter, remote string, header http.Header) {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "https://cdn.example.net"+TunnelPath, nil)
	request.RemoteAddr = remote
	for name, values := range header {
		request.Header[name] = values
	}
	response := httptest.NewRecorder()
	router.serveTunnel(response, request)
	if response.Code != http.StatusUnauthorized || strings.TrimSpace(response.Body.String()) != "unauthenticated" {
		t.Fatalf("rejected upgrade answered %d %q, want 401 unauthenticated", response.Code, response.Body.String())
	}
}

// An orphan node (certificate of another installation's node CA) behind
// Cloudflare and the local nginx: the line names the node and its real
// source, repeats fold for ten minutes and the 401 body says nothing more.
func TestTunnelRejectLogNamesTheNodeAndFoldsRepeats(t *testing.T) {
	pki := newTestPKI(t)
	clock := time.Now()
	logs := &rejectLogRecorder{}
	router := newRejectTestRouter(t, pki, logs, &clock)
	foreign := newTestPKI(t)
	orphan := foreign.ed25519Node(t, 0x5a17, testNodeID, clock.Add(-time.Hour), clock.Add(time.Hour))
	header := func() http.Header {
		h := orphan.token(testTunnelAudience, TunnelPath, clock, randomNonce(t))
		h.Set("X-Real-IP", "198.51.100.2")
		h.Set("CF-Connecting-IP", "203.0.113.149")
		h.Set("X-Forwarded-For", "203.0.113.149, 198.51.100.2")
		return h
	}
	rejectedUpgrade(t, router, "127.0.0.1:40001", header())
	lines := logs.take()
	if len(lines) != 1 {
		t.Fatalf("first rejection logged %d lines: %q", len(lines), lines)
	}
	t.Log(lines[0])
	want := []string{
		"agent-gateway tunnel rejected peer=127.0.0.1:40001 ",
		"source=203.0.113.149 source_header=Cf-Connecting-Ip ",
		`host="cdn.example.net" `,
		"node_id=" + testNodeID + " ",
		"serial=5a17 ",
		`issuer_cn="test root" `,
		"issuer_key_id=" + hex.EncodeToString(foreign.caCertificate.SubjectKeyId)[:16] + " ",
		"not_before=" + orphan.leaf.NotBefore.UTC().Format(time.RFC3339) + " ",
		"not_after=" + orphan.leaf.NotAfter.UTC().Format(time.RFC3339) + " ",
		`error="tunnel upgrade is not authenticated: node certificate does not chain to the node CA" `,
		"repeated=0",
	}
	for _, part := range want {
		if !strings.Contains(lines[0], part) {
			t.Errorf("log line lacks %q:\n%s", part, lines[0])
		}
	}
	for i := 0; i < 59; i++ {
		clock = clock.Add(10 * time.Second)
		rejectedUpgrade(t, router, "127.0.0.1:40002", header())
	}
	if lines := logs.take(); len(lines) != 0 {
		t.Fatalf("repeats inside ten minutes logged: %q", lines)
	}
	clock = clock.Add(10 * time.Second)
	rejectedUpgrade(t, router, "127.0.0.1:40003", header())
	lines = logs.take()
	if len(lines) != 1 || !strings.HasSuffix(lines[0], "repeated=59") || !strings.Contains(lines[0], "node_id="+testNodeID) {
		t.Fatalf("line after the window = %q, want one line with repeated=59", lines)
	}
	// Another reason of the same node is its own entry.
	rejectedUpgrade(t, router, "127.0.0.1:40004", http.Header{TunnelNodeCertificateHeader: {header().Get(TunnelNodeCertificateHeader)}})
	if lines := logs.take(); len(lines) != 1 || !strings.Contains(lines[0], "headers are missing") {
		t.Fatalf("other reason = %q, want its own line", lines)
	}
}

func TestTunnelRejectLogTrustsForwardingHeadersOnlyFromLoopback(t *testing.T) {
	pki := newTestPKI(t)
	clock := time.Now()
	logs := &rejectLogRecorder{}
	router := newRejectTestRouter(t, pki, logs, &clock)
	spoofed := http.Header{"X-Real-Ip": {"10.9.9.9"}, "Cf-Connecting-Ip": {"10.8.8.8"}, "X-Forwarded-For": {"10.7.7.7"}}
	rejectedUpgrade(t, router, "203.0.113.5:5555", spoofed)
	lines := logs.take()
	if len(lines) != 1 || !strings.Contains(lines[0], "source=203.0.113.5 source_header=peer ") || strings.Contains(lines[0], "10.9.9.9") || strings.Contains(lines[0], "10.8.8.8") || strings.Contains(lines[0], "10.7.7.7") {
		t.Fatalf("direct peer line = %q, want the TCP peer and no header value", lines)
	}
	if !strings.Contains(lines[0], "node_id=unknown serial=unknown issuer_cn=\"unknown\" issuer_key_id=unknown") {
		t.Fatalf("certificateless line = %q, want unknown certificate facts", lines[0])
	}
	cases := []struct {
		header http.Header
		want   string
	}{
		{http.Header{"X-Real-Ip": {"198.51.100.7"}, "X-Forwarded-For": {"192.0.2.1"}}, "source=198.51.100.7 source_header=X-Real-Ip "},
		{http.Header{"X-Forwarded-For": {"192.0.2.1, 198.51.100.7"}}, "source=192.0.2.1 source_header=X-Forwarded-For "},
		{http.Header{"Cf-Connecting-Ip": {"not-an-ip"}, "X-Real-Ip": {"bad"}}, "source=::1 source_header=peer "},
	}
	for i, tc := range cases {
		clock = clock.Add(tunnelRejectLogInterval)
		rejectedUpgrade(t, router, "[::1]:4000"+fmt.Sprint(i), tc.header)
		if lines := logs.take(); len(lines) != 1 || !strings.Contains(lines[0], tc.want) {
			t.Errorf("case %d line = %q, want %q", i, lines, tc.want)
		}
	}
}

func TestTunnelRejectLogTableIsBounded(t *testing.T) {
	clock := time.Now()
	logs := &rejectLogRecorder{}
	rejects := newTunnelRejectLog(func() time.Time { return clock }, logs.logf)
	request := httptest.NewRequest(http.MethodGet, TunnelPath, nil)
	for i := 0; i < tunnelRejectLogKeys+50; i++ {
		rejects.record(request, errors.New("reason "+fmt.Sprint(i)))
	}
	if len(rejects.entries) > tunnelRejectLogKeys+1 {
		t.Fatalf("fold table holds %d entries, limit %d plus overflow", len(rejects.entries), tunnelRejectLogKeys)
	}
	// Past the full table one overflow line, then folded.
	if got := len(logs.take()); got != tunnelRejectLogKeys+1 {
		t.Fatalf("logged %d lines, want %d", got, tunnelRejectLogKeys+1)
	}
	clock = clock.Add(tunnelRejectLogInterval)
	rejects.record(request, errors.New("fresh"))
	if len(rejects.entries) != 1 || len(logs.take()) != 1 {
		t.Fatalf("stale entries were not pruned: %d", len(rejects.entries))
	}
}
