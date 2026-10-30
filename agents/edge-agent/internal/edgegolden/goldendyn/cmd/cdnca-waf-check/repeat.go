package main

// -only repeat (waf-gap6 S2, research §3.9): a source (site x client
// address) with edgeconfig.DynamicWAFRepeatThreshold grey zone
// transactions in a window is a repeated grey zone source; its next grey
// zone request scores strong (403) on a two-level tier, 标准防护 and clean
// requests unchanged. Over TLS the source is site x client address x JA4
// (waf-gap8 J1: a NAT exit's other clients are not held for one scanner);
// plain HTTP (and HTTP/3) has no JA4 and stays site x client address. The count comes from $modsecurity_rule_ids
// (ModSecurity-nginx patch 01): concurrent requests of two sources must
// not mix (each request reads its own transaction).

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dyntls"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgeskeleton"
)

// repeatValue scores one CRS PL2 critical hit (942380, weight 5: not one
// of the learned weights of crs-pl2 1.4.0) and nothing at PL1: grey on
// 严格防护, strong (5, 403) when the source is repeated. greyValue's 941380
// weighs 4 since 1.4.0 (waf-gap7 S1): repeated, it scores the strong
// threshold (max(weak, threshold), waf-gap10).
const repeatValue = "order by price desc"

// The TLS site of the JA4 key (waf-gap8 J1): its own port and certificate.
const (
	repeatTLSPort    = 18313
	repeatTLSHost    = "j.waf.test"
	repeatTLSVersion = "0d110000-0000-4000-8000-0000000000c1"
)

// fromStatus sends a GET from a local source address (127.0.0.x) and
// returns the status; 0 on a transport error.
func fromStatus(source, host, uri string, headers map[string]string) int {
	dialer := net.Dialer{Timeout: 5 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}}
	conn, err := dialer.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", edge))
	if err != nil {
		return 0
	}
	defer conn.Close()
	return exchange(conn, host, uri, headers)
}

// tlsFromStatus is fromStatus over TLS to repeatTLSPort. alpn shapes the
// ClientHello (offered or not: two JA4 fingerprints of the same client).
func tlsFromStatus(source, host, uri string, headers map[string]string, alpn []string) int {
	dialer := &net.Dialer{Timeout: 5 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}}
	conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("127.0.0.1:%d", repeatTLSPort),
		&tls.Config{ServerName: host, InsecureSkipVerify: true, NextProtos: alpn}) // test certificate
	if err != nil {
		return 0
	}
	defer conn.Close()
	return exchange(conn, host, uri, headers)
}

// exchange sends one GET on conn and returns the status (0: no answer).
func exchange(conn net.Conn, host, uri string, headers map[string]string) int {
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	var request strings.Builder
	fmt.Fprintf(&request, "GET %s HTTP/1.1\r\nHost: %s\r\n", uri, host)
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(&request, "%s: %s\r\n", name, headers[name])
	}
	request.WriteString("Connection: close\r\n\r\n")
	if _, err := conn.Write([]byte(request.String())); err != nil {
		return 0
	}
	buffer := make([]byte, 64)
	n, _ := conn.Read(buffer)
	fields := strings.Fields(string(buffer[:n]))
	if len(fields) < 2 {
		return 0
	}
	code, _ := strconv.Atoi(fields[1])
	// read to the end: the log phase (the source count) has run when the
	// connection closes
	for {
		if _, err := conn.Read(buffer); err != nil {
			break
		}
	}
	return code
}

func repeatRun() {
	all := profiles()
	strict, standard := profileNamed(all, "system/crs-pl2"), profileNamed(all, "system/crs-pl1")
	sites := []edgesite.Site{
		makeSite(70, "r.waf.test", &wafSpec{profile: strict}),
		makeSite(71, "q.waf.test", &wafSpec{profile: standard}),
		makeSite(72, "t.waf.test", &wafSpec{profile: strict}),
		makeSite(73, repeatTLSHost, &wafSpec{profile: strict}),
	}
	sites[3].Listeners = append(sites[3].Listeners, edgesite.Listener{Port: repeatTLSPort, AddressFamily: edgesite.FamilyIPv4,
		TLS: &edgesite.TLS{CertificateVersionID: repeatTLSVersion, Protocols: []string{"TLSv1.2", "TLSv1.3"}}})
	if _, err := startNode(sites, true); err != nil {
		check("repeat start", false, "%v", err)
		return
	}
	defer stop()
	if err := installRepeatCertificate(); err != nil {
		check("repeat certificate", false, "%v", err)
		return
	}
	// API-like (JSON Accept): never challenged, the grey zone passes (200)
	api := map[string]string{"Accept": "application/json"}
	grey := "/t?v=" + url.QueryEscape(repeatValue)
	threshold := edgeconfig.DynamicWAFRepeatThreshold
	a, b, c := "127.0.0.2", "127.0.0.3", "127.0.0.4"
	if code := fromStatus(a, "r.waf.test", "/t?v=hello", api); code != 200 {
		check("repeat source address", false, "clean from %s: %d (no 127.0.0.x source?)", a, code)
		return
	}
	// a and b send their grey zone requests at the same time, a threshold
	// of them each, so a mixed up count would show on either
	var wait sync.WaitGroup
	codes := map[string][]int{}
	var mu sync.Mutex
	for _, source := range []string{a, b} {
		for range threshold {
			wait.Add(1)
			go func(source string) {
				defer wait.Done()
				code := fromStatus(source, "r.waf.test", grey, api)
				mu.Lock()
				codes[source] = append(codes[source], code)
				mu.Unlock()
			}(source)
		}
	}
	wait.Wait()
	for _, source := range []string{a, b} {
		passed := 0
		for _, code := range codes[source] {
			if code == 200 {
				passed++
			}
		}
		check("repeat below threshold "+source, passed == threshold, "%d of %d grey zone requests passed: %v", passed, threshold, codes[source])
	}
	// at the threshold: a's next grey zone request scores strong, a clean
	// one still passes; b (also at the threshold) as well; c (no grey zone
	// yet) passes; another site of the same source counts apart; 标准防护
	// never changes
	check("repeat strong a", fromStatus(a, "r.waf.test", grey, api) == 403, "a's grey zone request after %d not 403", threshold)
	check("repeat strong b", fromStatus(b, "r.waf.test", grey, api) == 403, "b's grey zone request after %d not 403", threshold)
	check("repeat clean a", fromStatus(a, "r.waf.test", "/t?v=hello", api) == 200, "a's clean request not 200")
	check("repeat other source", fromStatus(c, "r.waf.test", grey, api) == 200, "c's first grey zone request not 200")
	check("repeat other site", fromStatus(a, "t.waf.test", grey, api) == 200, "a's grey zone request on t not 200")
	for range threshold + 2 {
		fromStatus(c, "q.waf.test", grey, api)
	}
	check("repeat standard", fromStatus(c, "q.waf.test", grey, api) == 200, "标准防护 grey value not 200 after %d", threshold+2)
	// c below the threshold by one: still passes, one more makes it repeated
	for range threshold - 2 {
		fromStatus(c, "r.waf.test", grey, api)
	}
	check("repeat one below", fromStatus(c, "r.waf.test", grey, api) == 200, "c's grey zone request %d not 200", threshold)
	check("repeat at threshold", fromStatus(c, "r.waf.test", grey, api) == 403, "c's grey zone request %d not 403", threshold+1)
	// a learned weight below the strong threshold (greyValue's 941380: 4)
	// blocks once repeated: max(weak, threshold) (waf-gap10)
	weak, d := "/t?v="+url.QueryEscape(greyValue), "127.0.0.6"
	for range threshold {
		fromStatus(d, "r.waf.test", weak, api)
	}
	check("repeat weak weight", fromStatus(d, "r.waf.test", weak, api) == 403, "d's 941380 (weight 4) grey zone request %d not 403", threshold+1)
	repeatJA4(grey, api, threshold)
	for _, line := range errorLines() {
		check("repeat error log", false, "%s", line)
	}
}

// repeatJA4: one source address, two TLS clients (ALPN offered or not: two
// JA4). x reaches the threshold; y on the same address is not repeated
// until its own count does; plain HTTP of that address on the same site
// counts apart (no JA4: site x client address, unchanged).
func repeatJA4(grey string, api map[string]string, threshold int) {
	source := "127.0.0.5"
	x, y := []string{"http/1.1"}, []string(nil)
	if code := tlsFromStatus(source, repeatTLSHost, "/t?v=hello", api, x); code != 200 {
		check("repeat ja4 tls", false, "clean TLS request: %d", code)
		return
	}
	passed := 0
	for range threshold {
		if tlsFromStatus(source, repeatTLSHost, grey, api, x) == 200 {
			passed++
		}
	}
	check("repeat ja4 below threshold", passed == threshold, "%d of %d grey zone requests of JA4 x passed", passed, threshold)
	check("repeat ja4 strong x", tlsFromStatus(source, repeatTLSHost, grey, api, x) == 403, "JA4 x's grey zone request after %d not 403", threshold)
	check("repeat ja4 other fingerprint", tlsFromStatus(source, repeatTLSHost, grey, api, y) == 200,
		"JA4 y (same address) grey zone request not 200: held for JA4 x")
	check("repeat ja4 plain apart", fromStatus(source, repeatTLSHost, grey, api) == 200,
		"plain HTTP grey zone request of the address not 200: held for JA4 x")
	for range threshold - 2 {
		tlsFromStatus(source, repeatTLSHost, grey, api, y)
	}
	check("repeat ja4 y one below", tlsFromStatus(source, repeatTLSHost, grey, api, y) == 200, "JA4 y's grey zone request %d not 200", threshold)
	check("repeat ja4 y at threshold", tlsFromStatus(source, repeatTLSHost, grey, api, y) == 403, "JA4 y's grey zone request %d not 403", threshold+1)
}

// installRepeatCertificate puts the TLS site's self-signed certificate into
// the node's TLS pool (the handshake reads it on first use).
func installRepeatCertificate() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(73), Subject: pkix.Name{CommonName: repeatTLSHost}, DNSNames: []string{repeatTLSHost},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	pool := dyntls.Pool{Root: filepath.Join(*state, edgeskeleton.TLSPoolDirectory), GID: workerGID()}
	return pool.PutCertificate(repeatTLSVersion, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
}
