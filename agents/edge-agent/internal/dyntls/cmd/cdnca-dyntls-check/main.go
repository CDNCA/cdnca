// Command cdnca-dyntls-check is the dynamic routing D4 acceptance run
// against a real OpenResty (tests/dynroute-tls/run.sh starts it in the node
// runtime image, one --rm --network none container): TLS / HTTP/2 / HTTP/3
// handshakes on shared servers, unknown and missing SNI refused, SNI != Host
// routed by Host, per-site protocols and ciphers, h3 only for sites that
// advertise it, certificate switch without interruption, session tickets
// per site, OCSP stapling, client certificates, Alt-Svc, the placeholder
// never served; with -scale N the certificate LRU hit rate and handshake
// times for N sites.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/certstore"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/dyntls"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/siteindex"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgeskeleton"
	"golang.org/x/crypto/ocsp"
	"golang.org/x/net/http2"
)

var (
	luaRoot   = flag.String("lua", "/usr/local/share/cdnca", "node Lua tree")
	confPath  = flag.String("conf", "/d4/nginx.conf", "skeleton template")
	stateRoot = flag.String("state", "/tmp/d4state", "state directory")
	workers   = flag.Int("workers", 2, "worker_processes")
	scale     = flag.Int("scale", 0, "sites for the certificate LRU measurement (0 = skip)")
	certLRU   = flag.Int("cert-lru", 10000, "cdnca_tls certificate LRU items in the scale run")
	only      = flag.String("only", "", "comma-separated checks")
	h3probe   = flag.String("h3probe", "/usr/local/bin/h3probe", "HTTP/3 client")
)

const (
	scope      = "0d4a0000-0000-4000-8000-000000000001"
	tenant     = "0d4a0000-0000-4000-8000-000000000002"
	portH2     = 18443 // TLS, HTTP/2, QUIC
	portH1     = 18444 // TLS, HTTP/1.1 only
	portPlain  = 18080
	originPort = 19400
)

var failures int

func check(name string, ok bool, format string, args ...any) {
	status := "PASS"
	if !ok {
		status = "FAIL"
		failures++
	}
	fmt.Printf("%s %s %s\n", status, name, fmt.Sprintf(format, args...))
}

func uuidOf(kind, number int) string {
	return fmt.Sprintf("0d4a0000-0000-4000-8%03d-%012d", kind, number)
}

// ---------------------------------------------------------------- PKI

type authority struct {
	certificate *x509.Certificate
	key         *ecdsa.PrivateKey
	pem         []byte
}

var serial atomic.Int64

func newAuthority(name string) *authority {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(serial.Add(1)), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	certificate, _ := x509.ParseCertificate(der)
	return &authority{certificate: certificate, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

type issued struct {
	leaf       *x509.Certificate
	chain, key []byte
	tls        tls.Certificate
}

// issue: leaf + issuer chain. client = client auth certificate.
func (ca *authority) issue(cn string, names []string, notBefore, notAfter time.Time, client bool) issued {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	usage := x509.ExtKeyUsageServerAuth
	if client {
		usage = x509.ExtKeyUsageClientAuth
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial.Add(1)), Subject: pkix.Name{CommonName: cn}, DNSNames: names,
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, &key.PublicKey, ca.key)
	if err != nil {
		panic(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), ca.pem...)
	pair, err := tls.X509KeyPair(chain, keyPEM)
	if err != nil {
		panic(err)
	}
	return issued{leaf: leaf, chain: chain, key: keyPEM, tls: pair}
}

func (ca *authority) server(names ...string) issued {
	return ca.issue(names[0], names, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour), false)
}

func (ca *authority) ocspResponse(leaf *x509.Certificate, status int) []byte {
	response, err := ocsp.CreateResponse(ca.certificate, ca.certificate, ocsp.Response{Status: status, SerialNumber: leaf.SerialNumber,
		ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: time.Now().Add(time.Hour)}, crypto.Signer(ca.key))
	if err != nil {
		panic(err)
	}
	return response
}

// ---------------------------------------------------------------- sites

type siteSpec struct {
	number  int
	primary string
	aliases []string
	tls     map[int]*edgesite.TLS // port -> TLS (nil entry = plain listener)
	http3   bool
	plain   bool
	noH2    bool // fp-site5a: HTTP/2 off on the shared h2 port (native patch 27)
}

func makeSite(spec siteSpec, revision int64) edgesite.Site {
	var listeners []edgesite.Listener
	ports := make([]int, 0, len(spec.tls))
	for port := range spec.tls {
		ports = append(ports, port)
	}
	if spec.plain {
		ports = append(ports, portPlain)
	}
	sort.Ints(ports)
	for _, port := range ports {
		listener := edgesite.Listener{Port: port, AddressFamily: edgesite.FamilyIPv4}
		if port == portH2 {
			listener.AddressFamily, listener.HTTP2, listener.HTTP3 = edgesite.FamilyDualStack, !spec.noH2, spec.http3
		}
		listener.TLS = spec.tls[port]
		listeners = append(listeners, listener)
	}
	aliases := append([]string{}, spec.aliases...)
	sort.Strings(aliases)
	return edgesite.Site{
		Schema: edgesite.Schema, ConfigurationScopeID: scope, TenantID: tenant, SiteID: uuidOf(1, spec.number), Revision: revision,
		Hosts: edgesite.Hosts{Primary: spec.primary, Aliases: aliases}, Listeners: listeners,
		Origin: edgesite.Origin{DefaultPoolID: "primary", Routes: []edgesite.Route{}, Auth: []edgesite.OriginAuth{},
			Pools: []edgesite.Pool{{ID: "primary", Kind: edgesite.PoolOrigin, Algorithm: "round_robin",
				Endpoints: []edgesite.Endpoint{{ID: "origin-0", Scheme: "http", Host: "127.0.0.1", Port: originPort, Weight: 1}},
				Retry:     edgesite.Retry{Methods: []string{"GET", "HEAD"}, MaxAttempts: 1, ConnectTimeoutMS: 1000, ReadTimeoutMS: 1000, TotalBudgetMS: 1000}}}},
		Security: edgesite.Security{Rules: edgesite.RulePlan{HeaderOverflow: edgesite.HeaderOverflowNoMatch, Policies: []edgesite.RulePolicy{}}, CC: []edgesite.CCBinding{}},
		Errors:   []edgesite.ErrorPage{},
	}
}

func encode(site edgesite.Site) siteindex.Object {
	raw, err := edgesite.Encode(site)
	if err != nil {
		panic(fmt.Sprintf("site %s: %v", site.Hosts.Primary, err))
	}
	object, err := siteindex.DecodeObject(edgesite.Digest(raw), raw)
	if err != nil {
		panic(err)
	}
	return object
}

func tlsOf(version string, protocols ...string) *edgesite.TLS {
	if len(protocols) == 0 {
		protocols = []string{"TLSv1.2", "TLSv1.3"}
	}
	return &edgesite.TLS{CertificateVersionID: version, Protocols: protocols}
}

// ---------------------------------------------------------------- node

type node struct {
	activator *siteindex.Activator
	control   *siteindex.Control
	pool      dyntls.Pool
	objects   siteindex.ObjectDir
	nobody    int
}

func workerGID() int {
	group, err := user.LookupGroup("nobody")
	if err != nil {
		return -1
	}
	gid, _ := strconv.Atoi(group.Gid)
	return gid
}

func render(indexSize string, lru, certificateLRU int) error {
	template, err := os.ReadFile(*confPath)
	if err != nil {
		return err
	}
	conf := strings.NewReplacer("__WORKERS__", strconv.Itoa(*workers), "__LUA_ROOT__", *luaRoot, "__STATE__", *stateRoot,
		"__INDEX_SIZE__", indexSize, "__LRU_ITEMS__", strconv.Itoa(lru), "__CERT_LRU__", strconv.Itoa(certificateLRU),
		"__ORIGIN_PORT__", strconv.Itoa(originPort)).Replace(string(template))
	if err := os.WriteFile(filepath.Join(*stateRoot, "nginx", "nginx.conf"), []byte(conf), 0o644); err != nil {
		return err
	}
	// The D5 balancer is not D4: one plain mock origin stands in for it,
	// receiving the visitor's Host as v7 sends it.
	proxy := "proxy_http_version 1.1;\nproxy_set_header Host $host;\nproxy_set_header Connection \"\";\n" +
		"proxy_set_header X-Test-Site $cdnca_site_id;\nproxy_set_header X-Test-SNI $ssl_server_name;\n" +
		"proxy_set_header X-Test-Client $ssl_client_verify;\nproxy_pass http://cdnca_test_origin;\n"
	return os.WriteFile(filepath.Join(*stateRoot, "proxy.conf"), []byte(proxy), 0o644)
}

func openresty(args ...string) error {
	command := exec.Command("openresty", append([]string{"-p", filepath.Join(*stateRoot, "nginx") + "/", "-c", "nginx.conf"}, args...)...)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("openresty %v: %v: %s", args, err, output)
	}
	return nil
}

func newNode(indexSize string, lru, certificateLRU int) (*node, error) {
	_ = os.RemoveAll(*stateRoot)
	for _, dir := range []string{"nginx/logs", "run", "site-index", "site-objects"} {
		if err := os.MkdirAll(filepath.Join(*stateRoot, dir), 0o755); err != nil {
			return nil, err
		}
	}
	gid := workerGID()
	if err := dyntls.WritePlaceholder(filepath.Join(*stateRoot, "placeholder.crt"), filepath.Join(*stateRoot, "placeholder.key"), gid); err != nil {
		return nil, err
	}
	if err := render(indexSize, lru, certificateLRU); err != nil {
		return nil, err
	}
	if err := openresty(); err != nil {
		return nil, err
	}
	control := siteindex.NewControl(filepath.Join(*stateRoot, "run", "cdnca-site-admin.sock"))
	objects := siteindex.ObjectDir{Root: filepath.Join(*stateRoot, "site-objects"), Access: siteindex.Access{GID: gid}}
	n := &node{control: control, objects: objects, nobody: gid,
		pool: dyntls.Pool{Root: filepath.Join(*stateRoot, "tls-pool"), GID: gid},
		activator: &siteindex.Activator{Control: control, Objects: objects,
			Files: siteindex.Files{Root: filepath.Join(*stateRoot, "site-index"), Access: siteindex.Access{GID: gid}}}}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := control.Status(context.Background()); err == nil {
			return n, nil
		} else if time.Now().After(deadline) {
			return nil, err
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (n *node) stop() { _ = openresty("-s", "stop"); time.Sleep(300 * time.Millisecond) }

func (n *node) activate(objects []siteindex.Object) error {
	_, err := n.activator.Activate(context.Background(), objects)
	return err
}

func (n *node) put(version string, certificate issued) {
	if err := n.pool.PutCertificate(version, certificate.chain, certificate.key); err != nil {
		panic(err)
	}
}

// putObject stores a referenced object (client CA bundle) in the worker
// readable object directory and returns its digest.
func (n *node) putObject(content []byte) string {
	digest := edgesite.Digest(content)
	if err := n.objects.Put(digest, content); err != nil {
		panic(err)
	}
	return digest
}

func (n *node) stats(reset bool) map[string]float64 {
	path := "/__tls_stats"
	if reset {
		path += "?reset=1"
	}
	raw, err := siteindex.ControlGet(context.Background(), filepath.Join(*stateRoot, "run", "cdnca-site-admin.sock"), path)
	result := map[string]float64{}
	if err == nil {
		_ = json.Unmarshal(raw, &result)
	}
	return result
}

// ---------------------------------------------------------------- origin

func startOrigin() {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", originPort))
	if err != nil {
		panic(err)
	}
	go func() {
		_ = http.Serve(listener, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			writer.Header().Set("X-Origin-Host", request.Host)
			writer.Header().Set("X-Origin-Site", request.Header.Get("X-Test-Site"))
			writer.Header().Set("X-Origin-SNI", request.Header.Get("X-Test-SNI"))
			writer.Header().Set("X-Origin-Client", request.Header.Get("X-Test-Client"))
			writer.Header().Set("X-Origin-Client-Verify", request.Header.Get("X-Client-Verify"))
			writer.Header().Set("X-Origin-Client-Subject", request.Header.Get("X-Client-Cert-Subject"))
			writer.Header().Set("X-Origin-Client-Fingerprint", request.Header.Get("X-Client-Cert-Fingerprint"))
			fmt.Fprintf(writer, "%s %s", request.Host, request.URL.Path)
		}))
	}()
}

// ---------------------------------------------------------------- clients

type answer struct {
	err         string
	status      int
	proto       string
	version     uint16
	cipher      uint16
	alpn        string
	cn          string
	serial      int64
	resumed     bool
	stapled     []byte
	site        string
	host        string
	altSvc      string
	clientInfo  string
	verify      string // X-Client-Verify the origin received
	subject     string
	fingerprint string
	headers     map[string]string // request headers sent
	body        string
	duration    time.Duration
}

type request struct {
	port         int
	address      string
	sni          string // "-" = none
	host         string
	path         string
	alpn         []string
	min, max     uint16
	ciphers      []uint16
	cache        tls.ClientSessionCache
	certificates []tls.Certificate
	handshake    bool // TLS handshake only
	headers      map[string]string
}

func (r request) config() *tls.Config {
	sni := r.sni
	if sni == "-" {
		sni = ""
	} else if sni == "" {
		sni = r.host
	}
	alpn := r.alpn
	if alpn == nil {
		alpn = []string{"h2", "http/1.1"}
	}
	config := &tls.Config{ServerName: sni, InsecureSkipVerify: true, NextProtos: alpn, MinVersion: r.min, MaxVersion: r.max, //nolint:gosec // test edge
		CipherSuites: r.ciphers, ClientSessionCache: r.cache}
	if len(r.certificates) > 0 {
		// Always send it: Go would otherwise skip a certificate whose issuer
		// is not among the server's acceptable CAs.
		certificate := r.certificates[0]
		config.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &certificate, nil }
	}
	return config
}

func describe(state tls.ConnectionState, result *answer) {
	result.version, result.alpn, result.resumed, result.stapled = state.Version, state.NegotiatedProtocol, state.DidResume, state.OCSPResponse
	result.cipher = state.CipherSuite
	if len(state.PeerCertificates) > 0 {
		result.cn, result.serial = state.PeerCertificates[0].Subject.CommonName, state.PeerCertificates[0].SerialNumber.Int64()
	}
}

func classify(err error) string {
	text := err.Error()
	for _, marker := range []string{"internal error", "unrecognized name", "protocol version", "handshake failure", "no application protocol",
		"bad certificate", "certificate required", "unknown certificate authority"} {
		if strings.Contains(text, marker) {
			return strings.ReplaceAll(marker, " ", "_")
		}
	}
	return text
}

// do: a fresh TCP connection, TLS handshake, then (unless handshake only)
// one request over HTTP/1.1 or HTTP/2 as ALPN chose.
func do(r request) answer {
	address := r.address
	if address == "" {
		address = "127.0.0.1"
	}
	started := time.Now()
	raw, err := net.DialTimeout("tcp", net.JoinHostPort(address, strconv.Itoa(r.port)), 3*time.Second)
	if err != nil {
		return answer{err: err.Error()}
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(8 * time.Second))
	connection := tls.Client(raw, r.config())
	if err := connection.Handshake(); err != nil {
		return answer{err: classify(err), duration: time.Since(started)}
	}
	result := answer{duration: time.Since(started)}
	describe(connection.ConnectionState(), &result)
	if r.handshake {
		return result
	}
	path := r.path
	if path == "" {
		path = "/"
	}
	var response *http.Response
	httpRequest, _ := http.NewRequest(http.MethodGet, "https://"+r.host+path, nil)
	httpRequest.Host = r.host
	for name, value := range r.headers {
		httpRequest.Header.Set(name, value)
	}
	if result.alpn == "h2" {
		client, err := (&http2.Transport{}).NewClientConn(connection)
		if err != nil {
			result.err = err.Error()
			return result
		}
		response, err = client.RoundTrip(httpRequest)
		if err != nil {
			result.err = err.Error()
			return result
		}
	} else {
		if err := httpRequest.Write(connection); err != nil {
			result.err = err.Error()
			return result
		}
		response, err = http.ReadResponse(bufio.NewReader(connection), httpRequest)
		if err != nil {
			result.err = err.Error()
			return result
		}
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(response.Body, 1<<16))
	result.status, result.proto, result.body = response.StatusCode, response.Proto, string(body)
	result.site, result.host = response.Header.Get("X-Origin-Site"), response.Header.Get("X-Origin-Host")
	result.altSvc, result.clientInfo = response.Header.Get("Alt-Svc"), response.Header.Get("X-Origin-Client")
	result.verify, result.subject = response.Header.Get("X-Origin-Client-Verify"), response.Header.Get("X-Origin-Client-Subject")
	result.fingerprint = response.Header.Get("X-Origin-Client-Fingerprint")
	return result
}

// h3 runs one HTTP/3 request with the image's h3probe (quic-go).
func h3(sni, host, path string) answer {
	url := fmt.Sprintf("https://%s:%d%s", host, portH2, path)
	output, err := exec.Command(*h3probe, "request", "-url", url, "-server-name", sni, "-timeout", "5s").CombinedOutput()
	text := string(output)
	if err != nil {
		if index := strings.Index(text, "{Protocol:HTTP/3.0 Status:"); index >= 0 {
			status, _ := strconv.Atoi(strings.Fields(text[index+len("{Protocol:HTTP/3.0 Status:"):])[0])
			return answer{status: status, proto: "HTTP/3.0"}
		}
		lines := strings.Split(strings.TrimSpace(text), "\n")
		return answer{err: lines[len(lines)-1]}
	}
	var evidence struct {
		Protocol, Body, TLSVersion string
		Status                     int
		AltSvc                     string `json:"alt_svc"`
	}
	start := strings.Index(text, "{")
	if start < 0 || json.Unmarshal([]byte(text[start:]), &evidence) != nil {
		return answer{err: "h3probe output: " + text}
	}
	return answer{status: evidence.Status, proto: evidence.Protocol, body: evidence.Body, altSvc: evidence.AltSvc}
}

// ---------------------------------------------------------------- checks

type fixture struct {
	ca                                *authority
	shop, blog, legacy, tls12, tls13  issued
	old, modern, rot1, rot2, mtls, h3 issued
	sites                             []siteindex.Object
}

var versions = map[string]string{}

func version(name string) string {
	if v, ok := versions[name]; ok {
		return v
	}
	v := uuidOf(2, len(versions)+1)
	versions[name] = v
	return v
}

func basicSites(n *node, ca *authority, clientCA string) fixture {
	f := fixture{ca: ca}
	f.shop = ca.server("shop.example.test", "*.shop.example.test")
	f.blog = ca.server("blog.example.test")
	f.legacy = ca.server("legacy.example.test")
	f.tls12 = ca.server("tls12.example.test")
	f.tls13 = ca.server("tls13.example.test")
	f.old = ca.server("old.example.test")
	f.modern = ca.server("modern.example.test")
	f.rot1 = ca.server("rot.example.test")
	f.rot2 = ca.server("rot.example.test")
	f.mtls = ca.server("mtls.example.test", "mtlsopt.example.test")
	f.h3 = ca.server("noh3.example.test")
	for name, certificate := range map[string]issued{"shop": f.shop, "blog": f.blog, "legacy": f.legacy, "tls12": f.tls12, "tls13": f.tls13,
		"old": f.old, "modern": f.modern, "rot1": f.rot1, "rot2": f.rot2, "mtls": f.mtls, "noh3": f.h3} {
		n.put(version(name), certificate)
	}
	old := tlsOf(version("old"), "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3")
	old.CipherPreset = edgeconfig.TLSCipherLegacy
	modern := tlsOf(version("modern")) // "" = modern
	mtls := tlsOf(version("mtls"))
	mtls.ClientAuth = edgeconfig.ClientAuthRequired
	mtls.ClientCA = &edgesite.Ref{Kind: edgesite.RefClientCA, ID: uuidOf(1, 9), Revision: 1, SHA256: clientCA}
	mtlsOptional := *mtls
	mtlsOptional.ClientAuth = edgeconfig.ClientAuthOptional
	mtlsOptional.ClientCA = &edgesite.Ref{Kind: edgesite.RefClientCA, ID: uuidOf(1, 10), Revision: 1, SHA256: clientCA}
	specs := []siteSpec{
		{number: 1, primary: "shop.example.test", aliases: []string{"*.shop.example.test"}, http3: true, plain: true,
			tls: map[int]*edgesite.TLS{portH2: tlsOf(version("shop"))}},
		{number: 2, primary: "blog.example.test", http3: true, tls: map[int]*edgesite.TLS{portH2: tlsOf(version("blog"))}},
		{number: 3, primary: "legacy.example.test", tls: map[int]*edgesite.TLS{portH1: tlsOf(version("legacy"))}},
		{number: 4, primary: "tls12.example.test", tls: map[int]*edgesite.TLS{portH2: tlsOf(version("tls12"), "TLSv1.2")}},
		{number: 5, primary: "tls13.example.test", http3: true, tls: map[int]*edgesite.TLS{portH2: tlsOf(version("tls13"), "TLSv1.3")}},
		{number: 6, primary: "old.example.test", tls: map[int]*edgesite.TLS{portH1: old}},
		{number: 7, primary: "modern.example.test", tls: map[int]*edgesite.TLS{portH1: modern}},
		{number: 8, primary: "rot.example.test", http3: true, tls: map[int]*edgesite.TLS{portH2: tlsOf(version("rot1"))}},
		{number: 9, primary: "mtls.example.test", tls: map[int]*edgesite.TLS{portH2: mtls}},
		{number: 10, primary: "mtlsopt.example.test", tls: map[int]*edgesite.TLS{portH2: &mtlsOptional}},
		{number: 11, primary: "noh3.example.test", tls: map[int]*edgesite.TLS{portH2: tlsOf(version("noh3"))}},
	}
	for _, spec := range specs {
		f.sites = append(f.sites, encode(makeSite(spec, 1)))
	}
	return f
}

func checkHandshakes(n *node) {
	ca := newAuthority("d4 site CA")
	clientCA := newAuthority("d4 client CA")
	f := basicSites(n, ca, edgesite.Digest(clientCA.pem))
	// Referenced objects go in before the activation (a first activation is
	// a cold start rebuild whose sweep keeps them: siteindex Retain fix).
	n.putObject(clientCA.pem)
	if err := n.activate(f.sites); err != nil {
		check("activate", false, "%v", err)
		return
	}
	shopSite := f.sites[0].Site.SiteID
	blogSite := f.sites[1].Site.SiteID

	// Certificates by SNI over TCP, h1 and h2, IPv4 and IPv6.
	for _, c := range []struct {
		name, sni, address string
		alpn               []string
		serial             int64
		alpnWant           string
	}{
		{"shop-h2", "shop.example.test", "", nil, f.shop.leaf.SerialNumber.Int64(), "h2"},
		{"shop-h1", "shop.example.test", "", []string{"http/1.1"}, f.shop.leaf.SerialNumber.Int64(), "http/1.1"},
		{"wildcard", "img.shop.example.test", "", nil, f.shop.leaf.SerialNumber.Int64(), "h2"},
		{"wildcard-deep", "a.b.shop.example.test", "", nil, f.shop.leaf.SerialNumber.Int64(), "h2"},
		{"sni-case-and-dot", "SHOP.Example.Test.", "", nil, f.shop.leaf.SerialNumber.Int64(), "h2"},
		{"blog", "blog.example.test", "", nil, f.blog.leaf.SerialNumber.Int64(), "h2"},
		{"ipv6", "blog.example.test", "::1", nil, f.blog.leaf.SerialNumber.Int64(), "h2"},
	} {
		r := do(request{port: portH2, address: c.address, sni: c.sni, host: "shop.example.test", handshake: true, alpn: c.alpn})
		check("cert-"+c.name, r.err == "" && r.serial == c.serial && r.alpn == c.alpnWant, "sni=%s serial=%d want %d alpn=%s err=%s", c.sni, r.serial, c.serial, r.alpn, r.err)
	}
	r := do(request{port: portH1, host: "legacy.example.test", handshake: true})
	check("port-without-h2", r.err == "" && r.alpn == "http/1.1" && r.serial == f.legacy.leaf.SerialNumber.Int64(), "alpn=%s err=%s", r.alpn, r.err)

	// Refused handshakes: fast, a TLS alert, never the placeholder.
	for _, c := range []struct {
		name, sni string
		port      int
	}{
		{"unknown-sni", "unknown.example.test", portH2},
		{"no-sni", "-", portH2},
		{"wildcard-not-bare", "example.test", portH2},
		{"bare-parent", "shop.example.test.example", portH2},
		{"other-port-sni", "legacy.example.test", portH2},
		{"placeholder-name", dyntls.PlaceholderName, portH2},
	} {
		r := do(request{port: c.port, sni: c.sni, host: "shop.example.test", handshake: true})
		check("refuse-"+c.name, r.err != "" && r.cn == "" && r.duration < time.Second, "err=%s cn=%s %s", r.err, r.cn, r.duration.Round(time.Microsecond))
	}

	// SNI and Host naming different sites: routed by Host, no 421 (BATCH-PLUGIN 12).
	for _, alpn := range [][]string{{"http/1.1"}, {"h2"}} {
		r := do(request{port: portH2, sni: "shop.example.test", host: "blog.example.test", alpn: alpn})
		check("sni-shop-host-blog-"+alpn[0], r.status == 200 && r.site == blogSite && r.serial == f.shop.leaf.SerialNumber.Int64(),
			"%s status=%d site=%s cert serial=%d", r.proto, r.status, r.site, r.serial)
	}
	r = do(request{port: portH2, sni: "shop.example.test", host: "unknown.example.test", alpn: []string{"http/1.1"}})
	check("sni-shop-host-unknown-421", r.status == 421, "status %d", r.status)
	r = do(request{port: portH2, sni: "shop.example.test", host: "legacy.example.test", alpn: []string{"http/1.1"}})
	check("sni-shop-host-other-port-421", r.status == 421, "status %d (legacy is on %d only)", r.status, portH1)
	r = do(request{port: portH2, host: "shop.example.test", path: "/x"})
	check("shop-request-h2", r.status == 200 && r.proto == "HTTP/2.0" && r.site == shopSite && r.host == "shop.example.test", "%s %d site=%s host=%s", r.proto, r.status, r.site, r.host)
	check("alt-svc-h3-site", r.altSvc == fmt.Sprintf(`h3=":%d"; ma=86400`, portH2), "%q", r.altSvc)
	r = do(request{port: portH2, host: "noh3.example.test"})
	check("alt-svc-not-advertised", r.status == 200 && r.altSvc == "", "status %d alt-svc %q", r.status, r.altSvc)
	r = do(request{port: portH2, sni: "noh3.example.test", host: "shop.example.test"})
	check("alt-svc-by-host-site", r.status == 200 && r.site == shopSite && r.altSvc != "", "status %d alt-svc %q (Host site advertises h3)", r.status, r.altSvc)
	plain, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", portPlain))
	if err == nil {
		plain.Body.Close()
	}
	plainRequest, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/", portPlain), nil)
	plainRequest.Host = "shop.example.test"
	plainResponse, err := http.DefaultClient.Do(plainRequest)
	altSvc := ""
	if err == nil {
		altSvc = plainResponse.Header.Get("Alt-Svc")
		plainResponse.Body.Close()
	}
	check("alt-svc-not-on-plain", err == nil && plainResponse.StatusCode == 200 && altSvc == "", "plain listener alt-svc %q err=%v", altSvc, err)

	// Per-site protocols and cipher profiles.
	r = do(request{port: portH2, host: "tls12.example.test", handshake: true})
	check("tls12-site-negotiates-12", r.err == "" && r.version == tls.VersionTLS12, "version %x err %s", r.version, r.err)
	r = do(request{port: portH2, host: "tls12.example.test", handshake: true, min: tls.VersionTLS13})
	check("tls12-site-refuses-13-only-client", r.err != "", "err %s", r.err)
	r = do(request{port: portH2, host: "tls13.example.test", handshake: true, max: tls.VersionTLS12})
	check("tls13-site-refuses-12-client", r.err != "", "err %s", r.err)
	r = do(request{port: portH2, host: "shop.example.test", handshake: true, max: tls.VersionTLS12})
	check("default-site-allows-12", r.err == "" && r.version == tls.VersionTLS12, "version %x err %s", r.version, r.err)
	r = do(request{port: portH1, host: "legacy.example.test", handshake: true, min: tls.VersionTLS10, max: tls.VersionTLS11})
	check("default-site-refuses-10-11", r.err != "", "err %s", r.err)
	for _, v := range []uint16{tls.VersionTLS10, tls.VersionTLS11} {
		r = do(request{port: portH1, host: "old.example.test", handshake: true, min: v, max: v,
			ciphers: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA}})
		check(fmt.Sprintf("compatible-site-tls1%d", v-tls.VersionTLS10), r.err == "" && r.version == v, "version %x err %s", r.version, r.err)
	}
	r = do(request{port: portH1, host: "modern.example.test", handshake: true, max: tls.VersionTLS12,
		ciphers: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256}})
	check("modern-site-refuses-cbc", r.err != "", "err %s", r.err)
	r = do(request{port: portH1, host: "legacy.example.test", handshake: true, max: tls.VersionTLS12,
		ciphers: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256}})
	check("default-preset-is-modern", r.err != "", "err %s (no preset = modern, as v7 renders ssl_ciphers)", r.err)
	r = do(request{port: portH1, host: "modern.example.test", handshake: true, max: tls.VersionTLS12,
		ciphers: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}})
	check("modern-site-accepts-gcm", r.err == "", "err %s", r.err)
	r = do(request{port: portH1, host: "shop.example.test", sni: "old.example.test", alpn: []string{"http/1.1"}, min: tls.VersionTLS10, max: tls.VersionTLS10,
		ciphers: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA}})
	check("coalesced-protocol-not-allowed-421", r.status == 421 || r.status == 0 && r.err != "", "status %d err %s (shop not on %d)", r.status, r.err, portH1)
	r = do(request{port: portH2, sni: "shop.example.test", host: "tls13.example.test", max: tls.VersionTLS12, alpn: []string{"http/1.1"}})
	check("coalesced-tls12-into-tls13-site-421", r.status == 421, "status %d", r.status)

	// HTTP/3 (QUIC): only sites that advertise it; same certificate logic.
	h := h3("shop.example.test", "shop.example.test", "/q")
	check("h3-shop", h.status == 200 && h.proto == "HTTP/3.0" && strings.HasPrefix(h.body, "shop.example.test /q") && h.altSvc != "", "%+v", h)
	h = h3("blog.example.test", "blog.example.test", "/q")
	check("h3-blog", h.status == 200 && strings.HasPrefix(h.body, "blog.example.test"), "%+v", h)
	h = h3("x.shop.example.test", "x.shop.example.test", "/")
	check("h3-wildcard", h.status == 200, "%+v", h)
	h = h3("unknown.example.test", "unknown.example.test", "/")
	check("h3-unknown-sni-refused", h.status == 0 && h.err != "", "%s", h.err)
	h = h3("noh3.example.test", "noh3.example.test", "/")
	check("h3-site-without-h3-refused", h.status == 0 && h.err != "", "%s", h.err)
	h = h3("tls13.example.test", "tls13.example.test", "/")
	check("h3-tls13-only-site", h.status == 200, "%+v", h)
	h = h3("shop.example.test", "blog.example.test", "/")
	check("h3-sni-shop-host-blog", h.status == 200 && strings.HasPrefix(h.body, "blog.example.test"), "%+v", h)
	h = h3("shop.example.test", "noh3.example.test", "/")
	check("h3-coalesced-into-site-without-h3-421", h.status == 421, "%+v", h)

	// Session tickets: per site; resumption still goes through client hello.
	cache := &oneSession{}
	first := do(request{port: portH2, host: "shop.example.test", handshake: true, cache: cache, max: tls.VersionTLS12})
	second := do(request{port: portH2, host: "shop.example.test", handshake: true, cache: cache, max: tls.VersionTLS12})
	check("resume-same-site", first.err == "" && !first.resumed && second.resumed, "first %v second %v", first.resumed, second.resumed)
	other := do(request{port: portH2, host: "blog.example.test", handshake: true, cache: cache, max: tls.VersionTLS12})
	check("no-resume-across-sites-tls12", other.err == "" && !other.resumed && other.serial == f.blog.leaf.SerialNumber.Int64(),
		"resumed=%v serial=%d (a.test ticket offered to b.test)", other.resumed, other.serial)
	cache13 := &oneSession{}
	do(request{port: portH2, host: "shop.example.test", path: "/t", cache: cache13})
	other = do(request{port: portH2, host: "blog.example.test", handshake: true, cache: cache13})
	check("no-resume-across-sites-tls13", other.err == "" && !other.resumed && other.serial == f.blog.leaf.SerialNumber.Int64(), "resumed=%v", other.resumed)

	checkClientAuth(n, clientCA, ca)
	checkOCSP(n, f, ca)
	checkRotation(n, f, ca)
	checkValidity(n, ca, f)
}

// oneSession offers its one session to every server name (a client that
// coalesces or replays tickets across names).
type oneSession struct {
	mu      sync.Mutex
	session *tls.ClientSessionState
}

func (c *oneSession) Get(string) (*tls.ClientSessionState, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.session, c.session != nil
}

func (c *oneSession) Put(_ string, session *tls.ClientSessionState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if session != nil {
		c.session = session
	}
}

func checkClientAuth(n *node, clientCA, siteCA *authority) {
	good := clientCA.issue("client-a", nil, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), true)
	stranger := newAuthority("stranger CA").issue("client-b", nil, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), true)
	r := do(request{port: portH2, host: "mtls.example.test", certificates: []tls.Certificate{good.tls}})
	check("mtls-required-good", r.status == 200 && r.clientInfo == "SUCCESS", "status %d verify %q err %s", r.status, r.clientInfo, r.err)
	forged := map[string]string{"X-Client-Verify": "SUCCESS", "X-Client-Cert-Subject": "CN=forged"}
	r = do(request{port: portH2, host: "mtls.example.test", certificates: []tls.Certificate{good.tls}, headers: forged})
	check("mtls-origin-headers", r.status == 200 && r.verify == "SUCCESS" && r.subject == "CN=client-a", "origin got verify %q subject %q", r.verify, r.subject)
	r = do(request{port: portH2, host: "mtlsopt.example.test", headers: forged})
	check("mtls-optional-none-forged-header-replaced", r.status == 200 && r.verify == "NONE" && r.subject == "", "origin got verify %q subject %q", r.verify, r.subject)
	forged["X-Client-Cert-Fingerprint"] = "00"
	r = do(request{port: portH2, host: "shop.example.test", headers: forged})
	check("no-mtls-site-forged-headers-stripped", r.status == 200 && r.verify == "" && r.subject == "" && r.fingerprint == "",
		"origin got verify %q subject %q fingerprint %q (all three removed for a site without mTLS)", r.verify, r.subject, r.fingerprint)
	plainRequest, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/", portPlain), nil)
	plainRequest.Host = "shop.example.test"
	for name, value := range forged {
		plainRequest.Header.Set(name, value)
	}
	plainResponse, err := http.DefaultClient.Do(plainRequest)
	plainVerify := "error"
	if err == nil {
		plainVerify = plainResponse.Header.Get("X-Origin-Client-Verify") + plainResponse.Header.Get("X-Origin-Client-Subject") +
			plainResponse.Header.Get("X-Origin-Client-Fingerprint")
		plainResponse.Body.Close()
	}
	check("plain-listener-forged-headers-stripped", err == nil && plainResponse.StatusCode == 200 && plainVerify == "", "origin got %q", plainVerify)
	r = do(request{port: portH2, host: "mtls.example.test"})
	// nginx answers 496/495 with its own 400 pages, as for ssl_verify_client.
	check("mtls-required-none-400", r.status == 400 && strings.Contains(r.body, "No required SSL certificate was sent"), "status %d body %.60q", r.status, r.body)
	r = do(request{port: portH2, host: "mtls.example.test", certificates: []tls.Certificate{stranger.tls}})
	check("mtls-required-stranger-400", r.status == 400 && strings.Contains(r.body, "The SSL certificate error"), "status %d body %.60q", r.status, r.body)
	r = do(request{port: portH2, host: "mtlsopt.example.test"})
	check("mtls-optional-none", r.status == 200 && r.clientInfo == "NONE", "status %d verify %q", r.status, r.clientInfo)
	r = do(request{port: portH2, host: "mtlsopt.example.test", certificates: []tls.Certificate{good.tls}})
	check("mtls-optional-good", r.status == 200 && r.clientInfo == "SUCCESS", "status %d verify %q", r.status, r.clientInfo)
	r = do(request{port: portH2, sni: "shop.example.test", host: "mtls.example.test", alpn: []string{"http/1.1"}})
	check("mtls-coalesced-from-other-site-421", r.status == 421, "status %d (handshake for shop, no client CA)", r.status)
	r = do(request{port: portH2, sni: "mtls.example.test", host: "mtlsopt.example.test", alpn: []string{"http/1.1"}, certificates: []tls.Certificate{good.tls}})
	check("mtls-coalesced-other-mode-421", r.status == 421, "status %d (required vs optional)", r.status)
	r = do(request{port: portH2, sni: "mtls.example.test", host: "shop.example.test", alpn: []string{"http/1.1"}, certificates: []tls.Certificate{good.tls}})
	check("mtls-connection-to-site-without-auth", r.status == 200, "status %d", r.status)
	_ = siteCA
}

func checkOCSP(n *node, f fixture, ca *authority) {
	stapling := tlsOf(version("ocsp"))
	stapling.OCSPStapling = true
	certificate := ca.server("ocsp.example.test")
	n.put(version("ocsp"), certificate)
	sites := append(append([]siteindex.Object{}, f.sites...), encode(makeSite(siteSpec{number: 20, primary: "ocsp.example.test",
		tls: map[int]*edgesite.TLS{portH2: stapling}}, 1)))
	if err := n.activate(sites); err != nil {
		check("ocsp-activate", false, "%v", err)
		return
	}
	r := do(request{port: portH2, host: "ocsp.example.test", handshake: true})
	check("ocsp-none-yet", r.err == "" && len(r.stapled) == 0, "stapled %d bytes", len(r.stapled))
	response := ca.ocspResponse(certificate.leaf, ocsp.Good)
	if err := n.pool.PutOCSP(version("ocsp"), response, nil, time.Now()); err != nil {
		check("ocsp-put", false, "%v", err)
		return
	}
	time.Sleep(1200 * time.Millisecond) // ocsp_refresh = 1 s in the test skeleton
	r = do(request{port: portH2, host: "ocsp.example.test", handshake: true})
	parsed, err := ocsp.ParseResponseForCert(r.stapled, certificate.leaf, ca.certificate)
	check("ocsp-stapled", r.err == "" && err == nil && parsed.Status == ocsp.Good && bytes.Equal(r.stapled, response), "stapled %d bytes err %v", len(r.stapled), err)
	n.put(version("shop-ocsp"), f.shop)
	r = do(request{port: portH2, host: "shop.example.test", handshake: true})
	check("ocsp-off-site-no-staple", r.err == "" && len(r.stapled) == 0, "stapled %d bytes", len(r.stapled))
	_ = n.pool.RemoveOCSP(version("ocsp"))
}

// checkRotation: a site's certificate version changes while clients hold
// connections and others keep connecting: no failed request, in-flight
// connections keep the old certificate, new ones get the new one at once.
func checkRotation(n *node, f fixture, ca *authority) {
	old, next := f.rot1.leaf.SerialNumber.Int64(), f.rot2.leaf.SerialNumber.Int64()
	transport := &http2.Transport{TLSClientConfig: &tls.Config{ServerName: "rot.example.test", InsecureSkipVerify: true}} //nolint:gosec // test edge
	holder := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	get := func(client *http.Client) (int, int64) {
		response, err := client.Get(fmt.Sprintf("https://rot.example.test:%d/hold", portH2))
		if err != nil {
			return 0, 0
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, response.Body)
		return response.StatusCode, response.TLS.PeerCertificates[0].SerialNumber.Int64()
	}
	status, held := get(holder)
	var stop atomic.Bool
	var ok, failed atomic.Int64
	var mu sync.Mutex
	seen := map[int64]int{}
	var wait sync.WaitGroup
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for !stop.Load() {
				r := do(request{port: portH2, host: "rot.example.test", path: "/new"})
				if r.status == 200 {
					ok.Add(1)
					mu.Lock()
					seen[r.serial]++
					mu.Unlock()
				} else {
					failed.Add(1)
				}
			}
		}()
	}
	time.Sleep(300 * time.Millisecond)
	sites := append([]siteindex.Object{}, f.sites...)
	sites[7] = encode(makeSite(siteSpec{number: 8, primary: "rot.example.test", http3: true, tls: map[int]*edgesite.TLS{portH2: tlsOf(version("rot2"))}}, 2))
	switched := time.Now()
	err := n.activate(sites)
	activateTook := time.Since(switched)
	time.Sleep(300 * time.Millisecond)
	stop.Store(true)
	wait.Wait()
	afterStatus, afterSerial := get(holder)
	fresh := do(request{port: portH2, host: "rot.example.test", handshake: true})
	h := h3("rot.example.test", "rot.example.test", "/")
	check("rotation-activate", err == nil, "%v (%s)", err, activateTook.Round(time.Millisecond))
	check("rotation-no-failed-request", failed.Load() == 0 && ok.Load() > 0, "ok=%d failed=%d serials=%v", ok.Load(), failed.Load(), seen)
	check("rotation-both-certificates-seen", seen[old] > 0 && seen[next] > 0 && len(seen) == 2, "old=%d new=%d", seen[old], seen[next])
	check("rotation-held-connection-keeps-old", status == 200 && held == old && afterStatus == 200 && afterSerial == old, "before %d/%d after %d/%d", status, held, afterStatus, afterSerial)
	check("rotation-new-connection-new-cert", fresh.serial == next, "serial %d want %d", fresh.serial, next)
	check("rotation-h3-new-connection", h.status == 200, "%+v", h)
	transport.CloseIdleConnections()
	_ = ca
}

// checkValidity: a version outside its validity window refuses that site's
// handshake (v7 renders ssl_reject_handshake for it); missing files too.
func checkValidity(n *node, ca *authority, f fixture) {
	expired := ca.issue("expired.example.test", []string{"expired.example.test"}, time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour), false)
	future := ca.issue("future.example.test", []string{"future.example.test"}, time.Now().Add(time.Hour), time.Now().Add(48*time.Hour), false)
	n.put(version("expired"), expired)
	n.put(version("future"), future)
	sites := append([]siteindex.Object{}, f.sites...)
	for index, name := range []string{"expired", "future", "missing"} {
		sites = append(sites, encode(makeSite(siteSpec{number: 30 + index, primary: name + ".example.test",
			tls: map[int]*edgesite.TLS{portH2: tlsOf(version(name))}}, 1)))
	}
	if err := n.activate(sites); err != nil {
		check("validity-activate", false, "%v", err)
		return
	}
	for _, name := range []string{"expired", "future", "missing"} {
		r := do(request{port: portH2, host: name + ".example.test", handshake: true})
		check("refuse-certificate-"+name, r.err != "" && r.cn == "", "err %s cn %s", r.err, r.cn)
	}
	r := do(request{port: portH2, host: "shop.example.test", handshake: true})
	check("other-sites-unaffected", r.err == "" && r.serial == f.shop.leaf.SerialNumber.Int64(), "err %s", r.err)
}

// checkPlaceholder: across every run above the placeholder never went out.
func checkLogs() {
	raw, err := os.ReadFile(filepath.Join(*stateRoot, "nginx", "logs", "error.log"))
	if err != nil {
		return
	}
	bad := 0
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.Contains(line, "[alert]") || strings.Contains(line, "[crit]") || strings.Contains(line, "[emerg]") ||
			strings.Contains(line, "[error]") && !strings.Contains(line, "client SSL certificate verify error") {
			if !strings.Contains(line, "close() socket") { // quic reuseport reload noise (node-skeleton.md §2)
				bad++
				fmt.Println("LOG", line)
			}
		}
	}
	check("error-log-clean", bad == 0, "%d alert/crit/emerg/error lines", bad)
}

// ---------------------------------------------------------------- scale

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	return sorted[min(len(sorted)-1, int(float64(len(sorted))*p))]
}

// checkScale: count sites, each its own certificate version, on one TLS
// port. Handshake latency with the certificate LRU warm, cold, and with a
// working set larger than the LRU, plus the LRU hit rate the node reports.
func checkScale(count int) {
	indexSize := fmt.Sprintf("%dm", max(16, count*128*125/100/(1<<20)+16))
	n, err := newNode(indexSize, max(10000, count), *certLRU)
	if err != nil {
		check("scale-start", false, "%v", err)
		return
	}
	defer n.stop()
	ca := newAuthority("d4 scale CA")
	started := time.Now()
	objects := make([]siteindex.Object, 0, count)
	certificates := make([]issued, count)
	var wait sync.WaitGroup
	for worker := range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for index := worker; index < count; index += 8 {
				certificates[index] = ca.server(fmt.Sprintf("s%d.scale.test", index))
			}
		}()
	}
	wait.Wait()
	issueTime := time.Since(started)
	started = time.Now()
	for index := range count {
		v := uuidOf(4, index)
		n.put(v, certificates[index])
		objects = append(objects, encode(makeSite(siteSpec{number: 100000 + index, primary: fmt.Sprintf("s%d.scale.test", index),
			tls: map[int]*edgesite.TLS{portH2: tlsOf(v)}}, 1)))
	}
	poolTime := time.Since(started)
	started = time.Now()
	if err := n.activate(objects); err != nil {
		check("scale-activate", false, "%v", err)
		return
	}
	fmt.Printf("SCALE sites=%d certificates issued %s, pool written %s, index activated %s, cert LRU %d/worker, %d workers\n",
		count, issueTime.Round(time.Millisecond), poolTime.Round(time.Millisecond), time.Since(started).Round(time.Millisecond), *certLRU, *workers)

	// handshakes: sequential, one fresh connection each, by name list
	// Counters are per worker; the control socket lands on any worker, so a
	// snapshot asks until every worker answered and runs are measured as
	// differences of snapshots.
	snapshot := func() map[float64]map[string]float64 {
		result := map[float64]map[string]float64{}
		for attempt := 0; attempt < 200 && len(result) < *workers; attempt++ {
			s := n.stats(false)
			result[s["pid"]] = s
		}
		return result
	}
	run := func(label string, names []int, parallel int) {
		before := snapshot()
		durations := make([]float64, len(names))
		var failed atomic.Int64
		var next atomic.Int64
		var group sync.WaitGroup
		begin := time.Now()
		for range parallel {
			group.Add(1)
			go func() {
				defer group.Done()
				for {
					position := int(next.Add(1)) - 1
					if position >= len(names) {
						return
					}
					index := names[position]
					r := do(request{port: portH2, host: fmt.Sprintf("s%d.scale.test", index), handshake: true, alpn: []string{"http/1.1"}})
					durations[position] = float64(r.duration.Microseconds())
					if r.err != "" || r.serial != certificates[index].leaf.SerialNumber.Int64() {
						failed.Add(1)
					}
				}
			}()
		}
		group.Wait()
		wall := time.Since(begin)
		sort.Float64s(durations)
		after := snapshot()
		stats := map[string]float64{}
		for pid, values := range after {
			for key, value := range values {
				if key == "pid" || key == "lru_items" {
					continue
				}
				if key == "cached" {
					stats[key] += value
				} else {
					stats[key] += value - before[pid][key]
				}
			}
		}
		hits, misses := stats["cert_hit"], stats["cert_miss"]
		rate := 0.0
		if hits+misses > 0 {
			rate = 100 * hits / (hits + misses)
		}
		loadUS := 0.0
		if misses > 0 {
			loadUS = stats["cert_load_us"] / misses
		}
		fmt.Printf("SCALE %-34s handshakes=%d parallel=%d wall=%s (%.0f/s) p50=%.0fus p90=%.0fus p99=%.0fus max=%.0fus | LRU hit=%.0f miss=%.0f rate=%.1f%% load=%.0fus/miss cached=%.0f failed=%d\n",
			label, len(names), parallel, wall.Round(time.Millisecond), float64(len(names))/wall.Seconds(), percentile(durations, 0.5), percentile(durations, 0.9),
			percentile(durations, 0.99), durations[len(durations)-1], hits, misses, rate, loadUS, stats["cached"], failed.Load())
		check("scale-"+strings.Fields(label)[0], failed.Load() == 0, "%d failed", failed.Load())
	}
	all := make([]int, count)
	for index := range all {
		all[index] = (index * 7919) % count
	}
	run("cold (every site once)", all, 8)
	run("warm (every site again)", all, 8)
	hot := make([]int, 20000)
	for index := range hot {
		hot[index] = (index * 31) % 1000
	}
	run("hot-1000 (1000 sites, 20000)", hot, 8)
	sequential := all[:min(2000, count)]
	run("sequential-warm (1 client)", sequential, 1)
}

// checkSkeleton runs the node skeleton itself (edgeskeleton.Render, not the
// test template): D2 shared servers wired to the D3 contract, the D4 TLS
// entry and the D5a origin selection (cdnca_origin): a routed request goes
// through the balancer to the mock origin. Checked: readiness, routing,
// unknown Host 421, TLS by SNI over h1/h2/h3, SNI != Host, Alt-Svc, the
// origin request (Host, path, site), forged X-Client-* removed, reload
// keeping the index.
func checkSkeleton() {
	ctx := context.Background()
	_ = os.RemoveAll(*stateRoot)
	shared, state := filepath.Join(*stateRoot, "shared"), filepath.Join(*stateRoot, "state")
	for _, dir := range []string{filepath.Join(shared, "logs"), filepath.Join(shared, "cache"), filepath.Join(state, "run"),
		filepath.Join(state, "site-index"), filepath.Join(state, "site-objects")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			check("skeleton-dirs", false, "%v", err)
			return
		}
	}
	gid := workerGID()
	placeholder, placeholderKey := filepath.Join(state, "placeholder.crt"), filepath.Join(state, "placeholder.key")
	if err := dyntls.WritePlaceholder(placeholder, placeholderKey, gid); err != nil {
		check("skeleton-placeholder", false, "%v", err)
		return
	}
	trust := filepath.Join(state, "origin-trust-placeholder.crt")
	if err := os.WriteFile(trust, newAuthority("placeholder origin trust").pem, 0o644); err != nil {
		check("skeleton-trust", false, "%v", err)
		return
	}
	ca := newAuthority("d4 skeleton CA")
	pool := dyntls.Pool{Root: filepath.Join(state, edgeskeleton.TLSPoolDirectory), GID: gid}
	shop, blog, legacy := ca.server("shop.example.test", "*.shop.example.test"), ca.server("blog.example.test"), ca.server("legacy.example.test")
	sites := []edgesite.Site{
		makeSite(siteSpec{number: 201, primary: "shop.example.test", aliases: []string{"*.shop.example.test"}, http3: true, plain: true,
			tls: map[int]*edgesite.TLS{portH2: tlsOf(version("sk-shop"))}}, 1),
		makeSite(siteSpec{number: 202, primary: "blog.example.test", tls: map[int]*edgesite.TLS{portH2: tlsOf(version("sk-blog"))}}, 1),
		makeSite(siteSpec{number: 203, primary: "legacy.example.test", tls: map[int]*edgesite.TLS{portH1: tlsOf(version("sk-legacy"))}}, 1),
	}
	// Certificates the agent's way: activated in the certificate store
	// (private), then copied into the worker pool by Pool.Sync.
	certificateRoot := filepath.Join(*stateRoot, "certificates")
	if err := os.MkdirAll(certificateRoot, 0o700); err != nil {
		check("skeleton-certstore", false, "%v", err)
		return
	}
	store, err := certstore.NewManager(certstore.RuntimeConfig{StateRoot: certificateRoot, ListenAddress: "127.0.0.1", ListenPort: portH2}, noCertificateRuntime{})
	if err != nil {
		check("skeleton-certstore", false, "%v", err)
		return
	}
	for index, item := range []struct {
		site        edgesite.Site
		certificate issued
	}{{sites[0], shop}, {sites[1], blog}, {sites[2], legacy}} {
		command := fmt.Sprintf("d4-certificate-%d", index+1)
		names := append([]string{item.site.Hosts.Primary}, item.site.Hosts.Aliases...)
		listenerVersion := ""
		for _, listener := range item.site.Listeners {
			if listener.TLS != nil {
				listenerVersion = listener.TLS.CertificateVersionID
			}
		}
		_, err := store.ApplyWithActivation(ctx, certstore.Bundle{SchemaVersion: certstore.SchemaVersion, VersionID: command,
			Bindings: []certstore.Binding{{SiteID: item.site.SiteID, Domains: names, CertificateChainPEM: string(item.certificate.chain), PrivateKeyPEM: string(item.certificate.key)}},
		}, certstore.ActivationMetadata{SchemaVersion: certstore.ActivationSchemaVersion, ConfigVersionID: command, RecipientKeyID: "x25519:d4",
			CommandEventID: "event-" + command, DeploymentID: "deployment-" + command, Attempt: 1, ArtifactID: "artifact-" + command,
			Certificates: []certstore.CertificateRevision{{TenantID: tenant, TenantScopeID: scope, SiteID: item.site.SiteID,
				CertificateID: "certificate-" + item.site.SiteID, CertificateVersionID: listenerVersion, Version: 1, BindingRevision: 1}}})
		if err != nil {
			check("skeleton-certstore-apply", false, "%v", err)
			return
		}
	}
	synced, err := pool.Sync(ctx, store, sites)
	check("skeleton-pool-sync", err == nil && synced.Copied == 3 && len(synced.Unavailable) == 0, "copied %d unavailable %v err %v", synced.Copied, synced.Unavailable, err)
	if again, err := pool.Sync(ctx, store, sites); err != nil || again.Copied != 0 {
		check("skeleton-pool-sync-idempotent", false, "copied %d %v", again.Copied, err)
	}
	ports, keys, err := edgeskeleton.FromSites(sites)
	if err != nil {
		check("skeleton-ports", false, "%v", err)
		return
	}
	conf, err := edgeskeleton.Render(edgeskeleton.Input{Ports: ports, IndexKeys: keys,
		Paths: edgeskeleton.Paths{SharedRoot: shared, LuaRoot: *luaRoot, StateRoot: state,
			PlaceholderCertificate: placeholder, PlaceholderKey: placeholderKey, OriginTrustPlaceholder: trust}})
	if err != nil {
		check("skeleton-render", false, "%v", err)
		return
	}
	// The 10 000-site port table renders the same small skeleton (it only
	// depends on ports): nginx -t on it too.
	var many []edgesite.Site
	for index := range 10000 {
		many = append(many, makeSite(siteSpec{number: 300000 + index, primary: fmt.Sprintf("s%d.example.test", index),
			aliases: []string{fmt.Sprintf("*.s%d.example.test", index)}, http3: index%2 == 0, plain: index%10 == 0,
			tls: map[int]*edgesite.TLS{portH2: tlsOf(version("sk-shop"))}}, 1))
	}
	manyPorts, manyKeys, err := edgeskeleton.FromSites(many)
	if err == nil {
		var tenk []byte
		tenk, err = edgeskeleton.Render(edgeskeleton.Input{Ports: manyPorts, IndexKeys: manyKeys,
			Paths: edgeskeleton.Paths{SharedRoot: shared, LuaRoot: *luaRoot, StateRoot: state,
				PlaceholderCertificate: placeholder, PlaceholderKey: placeholderKey, OriginTrustPlaceholder: trust}})
		if err == nil {
			tenkPath := filepath.Join(shared, "tenk.conf")
			_ = os.WriteFile(tenkPath, tenk, 0o644)
			started := time.Now()
			output, testErr := exec.Command("openresty", "-t", "-q", "-p", shared+"/", "-c", tenkPath).CombinedOutput()
			check("skeleton-tenk-nginx-t", testErr == nil, "10000 sites, %d index keys, %d bytes, nginx -t %s %s", manyKeys, len(tenk),
				time.Since(started).Round(time.Millisecond), output)
		}
	}
	if err != nil {
		check("skeleton-tenk", false, "%v", err)
	}
	conf = bytes.Replace(conf, []byte("worker_processes auto;"), []byte("worker_processes "+strconv.Itoa(*workers)+";"), 1)
	confPath := filepath.Join(shared, "nginx.conf")
	if err := os.WriteFile(confPath, conf, 0o644); err != nil {
		check("skeleton-write", false, "%v", err)
		return
	}
	run := func(args ...string) error {
		output, err := exec.Command("openresty", append([]string{"-p", shared + "/", "-c", confPath}, args...)...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%v: %s", err, output)
		}
		return nil
	}
	err = run("-t", "-q")
	check("skeleton-nginx-t", err == nil, "%d bytes %v", len(conf), err)
	if err != nil {
		fmt.Println(string(conf))
		return
	}
	if err := run(); err != nil {
		check("skeleton-start", false, "%v", err)
		return
	}
	defer func() { _ = run("-s", "stop"); time.Sleep(300 * time.Millisecond) }()
	control := siteindex.NewControl(filepath.Join(state, edgeskeleton.ControlSocket))
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if _, err := control.Status(ctx); err == nil {
			break
		} else if time.Now().After(deadline) {
			check("skeleton-control", false, "%v", err)
			return
		}
	}
	plainGet := func(host, path string) (int, string) {
		request, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d%s", portPlain, path), nil)
		request.Host = host
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			return 0, err.Error()
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		return response.StatusCode, string(body)
	}
	status, body := plainGet("shop.example.test", "/")
	check("skeleton-not-ready-503", status == 503 && strings.Contains(body, "index not ready"), "%d %q", status, body)
	r := do(request{port: portH2, host: "shop.example.test", handshake: true})
	check("skeleton-not-ready-tls-refused", r.err != "", "err %s", r.err)

	objects := make([]siteindex.Object, 0, len(sites))
	for _, site := range sites {
		objects = append(objects, encode(site))
	}
	activator := &siteindex.Activator{Control: control,
		Files:   siteindex.Files{Root: filepath.Join(state, "site-index"), Access: siteindex.Access{GID: gid}},
		Objects: siteindex.ObjectDir{Root: filepath.Join(state, "site-objects"), Access: siteindex.Access{GID: gid}}}
	activation, err := activator.Activate(ctx, objects)
	if err == nil {
		_, err = activator.WaitHealthy(ctx, activation.Generation, siteindex.ProbesFor(objects), 10*time.Second)
	}
	check("skeleton-activate", err == nil, "%v", err)

	status, body = plainGet("shop.example.test", "/plain")
	check("skeleton-routed-to-origin", status == 200 && body == "shop.example.test /plain", "%d %q (cdnca_origin balancer -> mock origin)", status, body)
	status, _ = plainGet("unknown.example.test", "/")
	check("skeleton-unknown-host-421", status == 421, "%d", status)
	status, _ = plainGet("unknown.example.test", "/.well-known/acme-challenge/x")
	check("skeleton-unknown-host-any-path-421", status == 421, "%d (no node location in the skeleton yet)", status)
	for _, c := range []struct {
		name, sni string
		alpn      []string
		serial    int64
	}{
		{"h2", "shop.example.test", nil, shop.leaf.SerialNumber.Int64()},
		{"h1", "shop.example.test", []string{"http/1.1"}, shop.leaf.SerialNumber.Int64()},
		{"wildcard", "x.shop.example.test", nil, shop.leaf.SerialNumber.Int64()},
		{"blog", "blog.example.test", nil, blog.leaf.SerialNumber.Int64()},
	} {
		r := do(request{port: portH2, host: c.sni, alpn: c.alpn})
		check("skeleton-tls-"+c.name, r.serial == c.serial && r.status == 200 && strings.HasPrefix(r.body, c.sni+" /"), "serial %d status %d %s err %s", r.serial, r.status, r.proto, r.err)
	}
	r = do(request{port: portH2, address: "::1", host: "shop.example.test"})
	check("skeleton-ipv6", r.status == 200 && r.serial == shop.leaf.SerialNumber.Int64(), "status %d err %s", r.status, r.err)
	r = do(request{port: portH1, host: "legacy.example.test"})
	check("skeleton-port-without-h2", r.status == 200 && r.alpn == "http/1.1", "status %d alpn %s err %s", r.status, r.alpn, r.err)
	r = do(request{port: portH1, address: "::1", host: "legacy.example.test", handshake: true})
	check("skeleton-ipv4-only-port", r.err != "", "err %s", r.err)
	r = do(request{port: portH1, host: "shop.example.test", handshake: true})
	check("skeleton-other-port-sni-refused", r.err != "", "err %s (shop is not on %d)", r.err, portH1)
	r = do(request{port: portH2, host: "shop.example.test", headers: map[string]string{"X-Client-Verify": "SUCCESS",
		"X-Client-Cert-Subject": "CN=forged", "X-Client-Cert-Fingerprint": "00"}})
	check("skeleton-forged-client-headers-stripped", r.status == 200 && r.verify == "" && r.subject == "" && r.fingerprint == "",
		"origin got verify %q subject %q fingerprint %q", r.verify, r.subject, r.fingerprint)
	r = do(request{port: portH2, sni: "unknown.example.test", host: "shop.example.test", handshake: true})
	check("skeleton-unknown-sni-refused", r.err != "" && r.cn == "", "err %s", r.err)
	r = do(request{port: portH2, sni: "-", host: "shop.example.test", handshake: true})
	check("skeleton-no-sni-refused", r.err != "" && r.cn == "", "err %s", r.err)
	r = do(request{port: portH2, sni: "blog.example.test", host: "shop.example.test"})
	check("skeleton-sni-blog-host-shop", r.status == 200 && strings.HasPrefix(r.body, "shop.example.test /") && r.serial == blog.leaf.SerialNumber.Int64() && r.altSvc != "",
		"status %d serial %d alt-svc %q (routed by Host: shop, which advertises h3)", r.status, r.serial, r.altSvc)
	r = do(request{port: portH2, host: "blog.example.test"})
	check("skeleton-no-alt-svc-for-blog", r.status == 200 && r.altSvc == "", "alt-svc %q", r.altSvc)
	h := h3("shop.example.test", "shop.example.test", "/")
	check("skeleton-h3", h.status == 200 && h.proto == "HTTP/3.0" && strings.HasPrefix(h.body, "shop.example.test /"), "%+v", h)
	h = h3("blog.example.test", "blog.example.test", "/")
	check("skeleton-h3-not-advertised-refused", h.status == 0 && h.err != "", "%s", h.err)
	connections := func(count int) int {
		output, _ := exec.Command(*h3probe, "connections", "-url", fmt.Sprintf("https://shop.example.test:%d/", portH2),
			"-server-name", "shop.example.test", "-count", strconv.Itoa(count), "-timeout", "10s").CombinedOutput()
		var result struct {
			StatusCounts map[string]int `json:"status_counts"`
		}
		if start := bytes.IndexByte(output, '{'); start >= 0 {
			_ = json.Unmarshal(output[start:], &result)
		}
		return result.StatusCounts["200"]
	}
	total := 0
	for range 4 {
		total += connections(50)
	}
	check("skeleton-h3-multiworker", total == 200, "%d/200 new QUIC connections (quic reuseport, %d workers)", total, *workers)
	if err := run("-s", "reload"); err != nil {
		check("skeleton-reload", false, "%v", err)
		return
	}
	// As tests/edge-skeleton (D2): 1 s after the reload signal, while the old
	// workers are still shutting down. A batch counts only when every
	// connection of it succeeded (h3probe connections fails as a whole).
	time.Sleep(time.Second)
	total = connections(50) + connections(50)
	check("skeleton-h3-after-reload", total == 100, "%d/100 new QUIC connections 1 s after reload", total)
	time.Sleep(500 * time.Millisecond)
	r = do(request{port: portH2, host: "shop.example.test"})
	check("skeleton-reload-keeps-index", r.status == 200 && r.serial == shop.leaf.SerialNumber.Int64(), "status %d err %s", r.status, r.err)
	checkSiteDrop(filepath.Join(state, edgeskeleton.ControlSocket), run, plainGet, shop.leaf.SerialNumber.Int64(), blog.leaf.SerialNumber.Int64())
	raw, _ := os.ReadFile(filepath.Join(shared, "error.log"))
	bad := 0
	for _, line := range strings.Split(string(raw), "\n") {
		if (strings.Contains(line, "[alert]") || strings.Contains(line, "[crit]") || strings.Contains(line, "[emerg]") || strings.Contains(line, "[error]")) &&
			!strings.Contains(line, "Bad file descriptor") {
			bad++
			fmt.Println("LOG", line)
		}
	}
	check("skeleton-error-log-clean", bad == 0, "%d lines (quic reuseport reload EBADF noise excluded)", bad)
}

// siteDrop sends one request to the control socket's /site-drop (攻击自动升级
// D 级, esc-node §4; the agent's controlSocketHostPusher sends the same).
func siteDrop(socket, method, body string) (int, string) {
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}}
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	request, _ := http.NewRequest(method, "http://cdnca-control/site-drop", reader)
	response, err := client.Do(request)
	if err != nil {
		return 0, err.Error()
	}
	defer response.Body.Close()
	answer, _ := io.ReadAll(response.Body)
	return response.StatusCode, strings.TrimSpace(string(answer))
}

// checkSiteDrop: a level D site (shop: primary and wildcard alias) is closed
// on the shared plain port (444: no response), its TLS and QUIC handshakes
// are refused, a coalesced request into it is closed; other sites answer;
// the set survives a reload; clearing it restores the site.
func checkSiteDrop(socket string, run func(...string) error, plainGet func(string, string) (int, string), shopSerial, blogSerial int64) {
	status, body := siteDrop(socket, http.MethodPut, `{"hosts":"shop.example.test"}`)
	check("site-drop-bad-body-400", status == 400, "%d %s", status, body)
	status, body = siteDrop(socket, http.MethodPut, `{"hosts":["shop..example.test"]}`)
	check("site-drop-bad-host-400", status == 400, "%d %s", status, body)
	status, body = siteDrop(socket, http.MethodPut, `{"hosts":["Shop.Example.Test.","*.shop.example.test","blog.example.test"]}`)
	check("site-drop-put", status == 200 && body == `{"hosts":3}`, "%d %s", status, body)
	// replace: blog leaves the set
	status, body = siteDrop(socket, http.MethodPut, `{"hosts":["shop.example.test","*.shop.example.test"]}`)
	check("site-drop-replace", status == 200 && body == `{"hosts":2}`, "%d %s", status, body)
	status, body = siteDrop(socket, http.MethodGet, "")
	check("site-drop-get", status == 200 && body == `{"hosts":2}`, "%d %s", status, body)

	dropped := func(phase string) {
		status, body := plainGet("shop.example.test", "/plain")
		check("site-drop-plain-444"+phase, status == 0, "status %d %q (444 closes without a response)", status, body)
		status, body = plainGet("x.shop.example.test", "/plain")
		check("site-drop-plain-wildcard-444"+phase, status == 0, "status %d %q", status, body)
		r := do(request{port: portH2, host: "shop.example.test", handshake: true})
		check("site-drop-tls-refused"+phase, r.err != "" && r.cn == "", "err %s cn %s", r.err, r.cn)
		r = do(request{port: portH2, host: "x.shop.example.test", handshake: true})
		check("site-drop-tls-wildcard-refused"+phase, r.err != "" && r.cn == "", "err %s cn %s", r.err, r.cn)
		h := h3("shop.example.test", "shop.example.test", "/")
		check("site-drop-h3-refused"+phase, h.status == 0 && h.err != "", "%+v", h)
		r = do(request{port: portH2, sni: "blog.example.test", host: "shop.example.test"})
		check("site-drop-coalesced-444"+phase, r.serial == blogSerial && r.status == 0 && r.err != "", "serial %d status %d err %s", r.serial, r.status, r.err)
		r = do(request{port: portH2, host: "blog.example.test"})
		check("site-drop-other-site-200"+phase, r.status == 200 && r.serial == blogSerial, "status %d err %s", r.status, r.err)
		r = do(request{port: portH1, host: "legacy.example.test"})
		check("site-drop-other-port-200"+phase, r.status == 200, "status %d err %s", r.status, r.err)
	}
	dropped("")
	// the set is in a shared dictionary: a reload (HUP) keeps it
	if err := run("-s", "reload"); err != nil {
		check("site-drop-reload", false, "%v", err)
		return
	}
	time.Sleep(1500 * time.Millisecond)
	dropped("-after-reload")

	status, body = siteDrop(socket, http.MethodDelete, "")
	check("site-drop-clear", status == 200 && body == `{"hosts":0}`, "%d %s", status, body)
	status, body = plainGet("shop.example.test", "/plain")
	check("site-drop-cleared-plain-200", status == 200 && body == "shop.example.test /plain", "%d %q", status, body)
	status, body = plainGet("x.shop.example.test", "/plain")
	check("site-drop-cleared-wildcard-200", status == 200, "%d %q", status, body)
	r := do(request{port: portH2, host: "shop.example.test"})
	check("site-drop-cleared-tls-200", r.status == 200 && r.serial == shopSerial, "status %d err %s", r.status, r.err)
	h := h3("shop.example.test", "shop.example.test", "/")
	check("site-drop-cleared-h3-200", h.status == 200 && h.proto == "HTTP/3.0", "%+v", h)
	// an empty PUT clears as well
	status, body = siteDrop(socket, http.MethodPut, `{"hosts":[]}`)
	check("site-drop-empty-put", status == 200 && body == `{"hosts":0}`, "%d %s", status, body)
}

// checkHTTP2Off (fp-site5a, 待出包前全量跑): two sites on the one shared
// h2 port, one with HTTP/2 off. The h2 client gets h2 for the first and
// http/1.1 for the second (native patch 27, ALPN marked in the client
// hello); an h2 connection coalesced into the h2-off site answers 421; an
// explicit prefer_server_ciphers loads. The port's server keeps http2 on.
func checkHTTP2Off(n *node) {
	ca := newAuthority("h2off site CA")
	on, off := ca.server("h2on.example.test"), ca.server("h2off.example.test")
	n.put(version("h2on"), on)
	n.put(version("h2off"), off)
	prefer := true
	offTLS := tlsOf(version("h2off"))
	offTLS.PreferServerCiphers = &prefer // modern preset with server order
	sites := []siteindex.Object{
		encode(makeSite(siteSpec{number: 21, primary: "h2on.example.test", tls: map[int]*edgesite.TLS{portH2: tlsOf(version("h2on"))}}, 1)),
		encode(makeSite(siteSpec{number: 22, primary: "h2off.example.test", noH2: true, tls: map[int]*edgesite.TLS{portH2: offTLS}}, 1)),
	}
	if err := n.activate(sites); err != nil {
		check("h2off-activate", false, "%v", err)
		return
	}
	offSite := sites[1].Site.SiteID
	r := do(request{port: portH2, host: "h2on.example.test", handshake: true})
	check("h2off-other-site-keeps-h2", r.err == "" && r.alpn == "h2", "alpn=%s err=%s", r.alpn, r.err)
	r = do(request{port: portH2, host: "h2off.example.test", handshake: true})
	check("h2off-site-negotiates-http11", r.err == "" && r.alpn == "http/1.1" && r.serial == off.leaf.SerialNumber.Int64(),
		"alpn=%s err=%s", r.alpn, r.err)
	r = do(request{port: portH2, host: "h2off.example.test", handshake: true, alpn: []string{"h2"}})
	check("h2off-site-refuses-h2-only-client", r.err != "" || r.alpn == "", "alpn=%s err=%s (h2 only offer)", r.alpn, r.err)
	r = do(request{port: portH2, host: "h2off.example.test", path: "/p"})
	check("h2off-site-serves-http11", r.status == 200 && r.proto == "HTTP/1.1" && r.site == offSite, "%s %d site=%s", r.proto, r.status, r.site)
	r = do(request{port: portH2, host: "h2off.example.test", handshake: true, max: tls.VersionTLS12})
	check("h2off-prefer-server-ciphers-tls12", r.err == "" && r.version == tls.VersionTLS12 && r.alpn == "http/1.1", "version %x alpn=%s err %s", r.version, r.alpn, r.err)
	// coalescing: an h2 connection made for h2on, a request for h2off
	r = do(request{port: portH2, sni: "h2on.example.test", host: "h2off.example.test", alpn: []string{"h2"}})
	check("h2off-coalesced-h2-421", r.status == 421 && r.proto == "HTTP/2.0", "%s status=%d err=%s", r.proto, r.status, r.err)
	r = do(request{port: portH2, sni: "h2on.example.test", host: "h2off.example.test", alpn: []string{"http/1.1"}})
	check("h2off-coalesced-http11-served", r.status == 200 && r.site == offSite, "status=%d site=%s", r.status, r.site)
	// The same with curl --http2 (what an operator runs): %{http_version}.
	curl, err := exec.LookPath("curl")
	if err != nil {
		fmt.Println("SKIP h2off-curl: no curl in the image")
		return
	}
	for name, want := range map[string]string{"h2on.example.test": "2", "h2off.example.test": "1.1"} {
		output, err := exec.Command(curl, "--silent", "--insecure", "--http2", "--max-time", "5", "--output", "/dev/null",
			"--write-out", "%{http_version}", "--resolve", fmt.Sprintf("%s:%d:127.0.0.1", name, portH2),
			fmt.Sprintf("https://%s:%d/", name, portH2)).Output()
		check("h2off-curl-"+name, err == nil && string(output) == want, "curl --http2 http_version=%q want %q err=%v", output, want, err)
	}
}

type noCertificateRuntime struct{}

func (noCertificateRuntime) Precheck(context.Context, string) error                  { return nil }
func (noCertificateRuntime) Activate(context.Context, string) error                  { return nil }
func (noCertificateRuntime) Healthy(context.Context, []certstore.HealthTarget) error { return nil }
func (noCertificateRuntime) Stop(context.Context, string) error                      { return nil }

// checkTLSCustom (待出包前全量跑): two sites on one shared
// TLS port, "custom" with the site's own whitelisted TLS 1.2 list and
// "modern" with the preset. openssl s_client -cipher (what an operator runs)
// and the Go client agree: a suite only in the custom list is served for
// custom and refused for modern, a modern-only suite the other way round,
// the server's order wins for custom (prefer on), TLS 1.3 is untouched.
func checkTLSCustom(n *node) {
	ca := newAuthority("tls-custom site CA")
	custom, modern := ca.server("custom.example.test"), ca.server("modern.example.test")
	n.put(version("custom"), custom)
	n.put(version("modern"), modern)
	customTLS := tlsOf(version("custom"))
	customTLS.CipherPreset = edgeconfig.TLSCipherCustom
	// ECDSA certificates here: the CBC suite first, then the AEAD ones the
	// whitelist rule needs (one ECDHE-ECDSA and one ECDHE-RSA AEAD).
	customTLS.CipherSuites = []string{"ECDHE-ECDSA-AES128-SHA", "ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE-RSA-AES128-GCM-SHA256"}
	sites := []siteindex.Object{
		encode(makeSite(siteSpec{number: 31, primary: "custom.example.test", tls: map[int]*edgesite.TLS{portH1: customTLS}}, 1)),
		encode(makeSite(siteSpec{number: 32, primary: "modern.example.test", tls: map[int]*edgesite.TLS{portH1: tlsOf(version("modern"))}}, 1)),
	}
	if err := n.activate(sites); err != nil {
		check("tlscustom-activate", false, "%v", err)
		return
	}
	cbc, gcm256, gcm128 := tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	tls12 := func(host string, ciphers ...uint16) answer {
		return do(request{port: portH1, host: host, handshake: true, max: tls.VersionTLS12, ciphers: ciphers})
	}
	r := tls12("custom.example.test", cbc)
	check("tlscustom-go-cbc-served", r.err == "" && r.cipher == cbc && r.serial == custom.leaf.SerialNumber.Int64(), "cipher %x err %s", r.cipher, r.err)
	r = tls12("modern.example.test", cbc)
	check("tlscustom-go-cbc-refused-by-modern", r.err != "", "cipher %x err %s (modern has no CBC)", r.cipher, r.err)
	r = tls12("custom.example.test", gcm128)
	check("tlscustom-go-modern-only-refused", r.err != "", "cipher %x err %s (ECDHE-ECDSA-AES128-GCM not in the custom list)", r.cipher, r.err)
	r = tls12("modern.example.test", gcm128)
	check("tlscustom-go-modern-served", r.err == "" && r.cipher == gcm128, "cipher %x err %s", r.cipher, r.err)
	r = tls12("custom.example.test", gcm256, cbc)
	check("tlscustom-go-server-order", r.err == "" && r.cipher == cbc, "cipher %x err %s (prefer on: the site's first suite)", r.cipher, r.err)
	r = do(request{port: portH1, host: "custom.example.test", handshake: true, min: tls.VersionTLS13})
	check("tlscustom-go-tls13-default", r.err == "" && r.version == tls.VersionTLS13, "version %x err %s", r.version, r.err)

	openssl, err := exec.LookPath("openssl")
	if err != nil {
		fmt.Println("SKIP tlscustom-openssl: no openssl in the image (the Go checks above cover the same handshakes)")
		return
	}
	sclient := func(host, cipher string) (string, bool) {
		command := exec.Command(openssl, "s_client", "-connect", fmt.Sprintf("127.0.0.1:%d", portH1), "-servername", host,
			"-tls1_2", "-cipher", cipher, "-brief")
		command.Stdin = strings.NewReader("")
		output, err := command.CombinedOutput()
		return string(output), err == nil && strings.Contains(string(output), "Ciphersuite: "+cipher)
	}
	for _, test := range []struct {
		host, cipher string
		want         bool
	}{
		{"custom.example.test", "ECDHE-ECDSA-AES128-SHA", true},
		{"modern.example.test", "ECDHE-ECDSA-AES128-SHA", false},
		{"custom.example.test", "ECDHE-ECDSA-AES128-GCM-SHA256", false},
		{"modern.example.test", "ECDHE-ECDSA-AES128-GCM-SHA256", true},
		{"custom.example.test", "ECDHE-ECDSA-AES256-GCM-SHA384", true},
	} {
		output, ok := sclient(test.host, test.cipher)
		check("tlscustom-openssl-"+strings.Split(test.host, ".")[0]+"-"+test.cipher, ok == test.want,
			"s_client -cipher %s: served=%t want %t\n%s", test.cipher, ok, test.want, output)
	}
}

func main() {
	flag.Parse()
	selected := map[string]bool{}
	for _, name := range strings.Split(*only, ",") {
		if name != "" {
			selected[name] = true
		}
	}
	startOrigin()
	if len(selected) == 0 || selected["handshakes"] {
		n, err := newNode("32m", 10000, 10000)
		if err != nil {
			check("start", false, "%v", err)
		} else {
			fmt.Println("== handshakes")
			checkHandshakes(n)
			checkLogs()
			n.stop()
		}
	}
	if len(selected) == 0 || selected["h2off"] {
		n, err := newNode("32m", 10000, 10000)
		if err != nil {
			check("start", false, "%v", err)
		} else {
			fmt.Println("== h2off")
			checkHTTP2Off(n)
			n.stop()
		}
	}
	if len(selected) == 0 || selected["tlscustom"] {
		n, err := newNode("32m", 10000, 10000)
		if err != nil {
			check("start", false, "%v", err)
		} else {
			fmt.Println("== tlscustom")
			checkTLSCustom(n)
			n.stop()
		}
	}
	if len(selected) == 0 || selected["skeleton"] {
		fmt.Println("== skeleton")
		checkSkeleton()
	}
	if *scale > 0 && (len(selected) == 0 || selected["scale"]) {
		fmt.Println("== scale")
		checkScale(*scale)
	}
	fmt.Printf("RESULT failures=%d\n", failures)
	if failures > 0 {
		os.Exit(1)
	}
}
