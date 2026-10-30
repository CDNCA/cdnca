// Command cdnca-dynroute-agent-check is the dynamic routing D13-a acceptance
// run on a real OpenResty (tests/dynroute-agent/run.sh, the node runtime
// image, one --rm --network none container). It drives the agent runtime
// (internal/dynroute.Runtime) exactly as the daemon does and checks:
//   - cold start: skeleton rendered, OpenResty started, index rebuilt, 200;
//   - incremental: a site edit activates as a change set without a reload;
//     an added site and port reloads; a removed site answers 421;
//   - rollback to the previous generation;
//   - certificates: a TLS site served with its version, rotated to a new
//     version without a reload, the old version dropped after two
//     generations; OCSP stapling refresh through the runtime;
//   - cache: MISS/HIT, purge_site (generation bump, files removed), soft
//     quota cleaning;
//   - managed WAF: a CRS tier blocks an attack, a site edit to another
//     tier takes effect; the grey zone repeat threshold per site and the
//     20/60 default for a node without capability 64 (wafrepeat.go);
//   - agent restart: a new Runtime over the same state recovers without
//     touching OpenResty; a node restart (OpenResty stopped) is started and
//     rebuilt from the index file;
//   - system (D13-c0): the scopes' system configuration rendered (Server
//     header), the DDoS table over the site ports, CC kernel ban ports by
//     mode, kept by Rollback, removed with the system;
//   - L4 (D13-c0): two scopes' v2 streams in the node's L4 runtime: an
//     exclusive TCP and a UDP forward, a TLS passthrough stream sharing the
//     TLS site's port (by SNI: the site is handed over to the skeleton's
//     internal socket and keeps the client address), the DDoS table over
//     the stream ports, CC exclusive ports, and the streams removed (the port given back to the skeleton);
//   - per-node L4 (L4_STREAM_SELECTION): two nodes of
//     one release on different line groups, each listening only on its
//     group's forward (key document l4_withheld_streams);
//   - error.log: counts and recent lines, the reuseport reload noise
//     filtered.
package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/cachetask"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/certstore"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/ddos"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynroute"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynwaf"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/edgegolden/goldenrelease"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/objectstore"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/siteindex"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	"golang.org/x/crypto/ocsp"
)

var (
	luaRoot     = flag.String("lua", "/usr/local/share/cdnca", "node Lua tree")
	state       = flag.String("state", "/tmp/d13", "state root")
	modSecurity = flag.String("modsecurity", "", "engine extension directory (\"\" = skip the managed WAF part)")
	official    = flag.String("official", "", "official rule pack sources (scripts/security/datasets/rulepacks; \"\" = skip)")
	workers     = flag.Int("workers", 2, "worker_processes")
	binary      = flag.String("openresty", "/usr/local/openresty/bin/openresty", "OpenResty binary")
	suite       = flag.String("suite", "", "\"\" = every check; node-storage = only the node storage checks (nodestorage.go)")
)

const (
	scope      = "0d130000-0000-4000-8000-000000000001"
	tenant     = "0d130000-0000-4000-8000-000000000002"
	portPlain  = 18380
	portExtra  = 18381
	portTLS    = 18443
	originPort = 19813
	sqli       = "/q?id=1%27%20OR%20%271%27%3D%271"
	// sqliPlain: a SQLi only CRS 942140 (PL1, critical) sees and the node's
	// sqli detector does not (eval corpus crs-942140-1). The detector signal
	// (waf-strict-algo 2b) scores the sqli set on two-level tiers and the
	// site's rule exclusions do not remove it, so the narrowing checks of a
	// modsecurity pack (XSS only) use this one.
	sqliPlain = "/q?sql_table=pg_catalog"
	// several CRS PL2 command injection rules and no PL1 one (the
	// cdnca-waf-check probe): one PL2 heuristic alone no longer blocks on
	// 严格防护 since two-level scoring (waf-strict-algo 2a).
	pl2Probe = "/q?host=www.google.com;c%24-at%2B%2Fet%24-c%2Fpas%24-swd"
	xss      = "/q?a=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
	// retest N3: the site's block page and the origin's own 403
	brandBlock403 = "cdnca brand block page 403\n"
	origin403Body = "origin says forbidden"
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

// ---------------------------------------------------------------- origin

type originServer struct {
	mu     sync.Mutex
	counts map[string]int
}

func (o *originServer) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	_, _ = io.Copy(io.Discard, request.Body)
	o.mu.Lock()
	o.counts[request.Host+request.URL.Path]++
	o.mu.Unlock()
	writer.Header().Set("Cache-Control", "max-age=3600")
	if strings.HasPrefix(request.URL.Path, "/missing-") {
		// official cc-404-burst pack: 404s the origin answers
		writer.Header().Set("Cache-Control", "no-store")
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	if request.URL.Path == "/origin-403" {
		// retest N3: the origin's own 403 is never the site's block page
		writer.Header().Set("Cache-Control", "no-store")
		writer.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(writer, origin403Body)
		return
	}
	if strings.HasPrefix(request.URL.Path, "/slice/") {
		// CACHEFLOW-E01: a 768 KiB object the node fetches in 256 KiB slices
		http.ServeContent(writer, request, "slice.bin", time.Time{}, strings.NewReader(strings.Repeat("s", 768<<10)))
		return
	}
	if request.URL.Path == "/whoami" {
		// site access: whether the basic auth credential reached the origin
		auth := request.Header.Get("Authorization")
		if auth == "" {
			auth = "-"
		}
		writer.Header().Set("Cache-Control", "no-store")
		fmt.Fprintf(writer, "origin %s auth=%s", request.Host, auth)
		return
	}
	fmt.Fprintf(writer, "origin %s %s %s", request.Host, request.URL.Path, strings.Repeat("x", 4096))
}

func (o *originServer) count(host, path string) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.counts[host+path]
}

// ---------------------------------------------------------------- PKI

type authority struct {
	certificate *x509.Certificate
	key         *ecdsa.PrivateKey
	pem         []byte
}

func newAuthority() *authority {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "d13 CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	certificate, _ := x509.ParseCertificate(der)
	return &authority{certificate: certificate, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

var serial int64 = 100

func (ca *authority) issue(names ...string) (chain, keyPEM []byte, leaf *x509.Certificate) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial++
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		OCSPServer: []string{"http://ocsp.d13.invalid/"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, template, ca.certificate, &key.PublicKey, ca.key)
	leaf, _ = x509.ParseCertificate(der)
	keyDER, _ := x509.MarshalECPrivateKey(key)
	chain = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), ca.pem...)
	return chain, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), leaf
}

// ocspFetcher signs "good" for every leaf of the CA (the agent's Fetcher).
type ocspFetcher struct {
	ca    *authority
	calls int
}

func (f *ocspFetcher) Fetch(_ context.Context, leaf, issuer *x509.Certificate) ([]byte, error) {
	f.calls++
	return ocsp.CreateResponse(f.ca.certificate, f.ca.certificate, ocsp.Response{Status: ocsp.Good, SerialNumber: leaf.SerialNumber,
		ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: time.Now().Add(time.Hour)}, crypto.Signer(f.ca.key))
}

type noCertificateRuntime struct{}

func (noCertificateRuntime) Precheck(context.Context, string) error                  { return nil }
func (noCertificateRuntime) Activate(context.Context, string) error                  { return nil }
func (noCertificateRuntime) Healthy(context.Context, []certstore.HealthTarget) error { return nil }
func (noCertificateRuntime) Stop(context.Context, string) error                      { return nil }

var certificateCommand = 0

// deliver puts a certificate version into the certificate store as the
// gateway's certificate deployment would.
func deliver(store *certstore.Manager, site edgesite.Site, versionID string, chain, key []byte) error {
	certificateCommand++
	command := fmt.Sprintf("0d130000-0000-4000-8000-%012d", 900+certificateCommand)
	names := append([]string{site.Hosts.Primary}, site.Hosts.Aliases...)
	_, err := store.ApplyWithActivation(context.Background(), certstore.Bundle{SchemaVersion: certstore.SchemaVersion, VersionID: command,
		Bindings: []certstore.Binding{{SiteID: site.SiteID, Domains: names, CertificateChainPEM: string(chain), PrivateKeyPEM: string(key)}},
	}, certstore.ActivationMetadata{SchemaVersion: certstore.ActivationSchemaVersion, ConfigVersionID: command, RecipientKeyID: "x25519:d13",
		CommandEventID: "event-" + command, DeploymentID: "deployment-" + command, Attempt: 1, ArtifactID: "artifact-" + command,
		Certificates: []certstore.CertificateRevision{{TenantID: tenant, TenantScopeID: scope, SiteID: site.SiteID,
			CertificateID: "certificate-" + site.SiteID, CertificateVersionID: versionID, Version: uint64(certificateCommand), BindingRevision: uint64(certificateCommand)}}})
	return err
}

// ---------------------------------------------------------------- sites

func siteID(number int) string { return fmt.Sprintf("0d130000-0000-4000-8000-%012d", number) }

func makeSite(number int, host string, revision int64, port int) edgesite.Site {
	return edgesite.Site{
		Schema: edgesite.Schema, ConfigurationScopeID: scope, TenantID: tenant, SiteID: siteID(number), Revision: revision,
		Hosts:     edgesite.Hosts{Primary: host, Aliases: []string{}},
		Listeners: []edgesite.Listener{{Port: port, AddressFamily: edgesite.FamilyIPv4}},
		Origin: edgesite.Origin{DefaultPoolID: "primary", Routes: []edgesite.Route{}, Auth: []edgesite.OriginAuth{},
			Pools: []edgesite.Pool{{ID: "primary", Kind: edgesite.PoolOrigin, Algorithm: "round_robin",
				Endpoints: []edgesite.Endpoint{{ID: "o", Scheme: "http", Host: "127.0.0.1", Port: originPort, Weight: 1}},
				Retry:     edgesite.Retry{Methods: []string{"GET", "HEAD"}, MaxAttempts: 1, ConnectTimeoutMS: 2000, ReadTimeoutMS: 30000, TotalBudgetMS: 40000}}}},
		Security: edgesite.Security{Rules: edgesite.RulePlan{HeaderOverflow: edgesite.HeaderOverflowNoMatch, Policies: []edgesite.RulePolicy{}}, CC: []edgesite.CCBinding{}},
		Errors:   []edgesite.ErrorPage{},
		Limits:   edgesite.Limits{MaxBodyBytes: 64 << 20},
	}
}

func withCache(site edgesite.Site, quota int64) edgesite.Site {
	document := edgeconfig.CachePolicyDocument{Revision: 1, Mode: edgeconfig.CacheOverride, Rules: []edgeconfig.CacheRuleDocument{},
		QueryMode: edgeconfig.CacheQueryPreserve, QueryNames: []string{}, VaryHeaders: []string{}, DiskQuotaBytes: quota}
	cache := &edgesite.Cache{KeyPrefix: edgesite.CacheKeyPrefix(tenant, site.SiteID), Domain: site.Hosts.Primary, KeyByHost: true, Policy: document}
	cache.Generation, _ = edgesite.CacheGeneration(*cache)
	site.Cache = cache
	site.CacheStatusHeader = true // the checks read X-CDN-Cache
	return site
}

func withTLS(site edgesite.Site, version string, ocspStapling bool) edgesite.Site {
	site.Listeners = []edgesite.Listener{{Port: portTLS, AddressFamily: edgesite.FamilyIPv4, HTTP2: true,
		TLS: &edgesite.TLS{CertificateVersionID: version, Protocols: []string{"TLSv1.2", "TLSv1.3"}, OCSPStapling: ocspStapling}}}
	return site
}

func withWAF(site edgesite.Site, profile edgeconfig.CRSProfile) edgesite.Site {
	site.Security.ManagedWAF = &edgesite.ManagedWAF{PolicyID: "0d130000-0000-4000-8000-0000000000d1", PolicyVersion: 1,
		Profile: edgesite.ManagedWAFProfile{RequestBodyLimit: 1 << 20, RequestBodyNoFilesLimit: 1 << 20,
			RequestBodyLimitAction: "reject", ArgumentsLimit: 1000, JSONDepthLimit: 512, PCREMatchLimit: 100000, InspectionLimitAction: "log"},
		CRSProfile: profile.Ref, Exclusions: []int{}, AllowCIDRs: []string{}}
	return site
}

// siteObjects is the agent's object store opened shared with the worker
// group, as a dynamic routing node runs it (F13): the gateway client stores
// fetched site objects there and the workers read them in place.
var siteObjects *objectstore.Store

func objects(sites ...edgesite.Site) []siteindex.Object {
	result := make([]siteindex.Object, 0, len(sites))
	for _, site := range sites {
		raw, err := edgesite.Encode(site)
		if err != nil {
			panic(fmt.Sprintf("site %s: %v", site.Hosts.Primary, err))
		}
		if err := siteObjects.Put(edgesite.Digest(raw), raw); err != nil {
			panic(err)
		}
		object, err := siteindex.DecodeObject(edgesite.Digest(raw), raw)
		if err != nil {
			panic(err)
		}
		result = append(result, object)
	}
	return result
}

// ---------------------------------------------------------------- clients

type answer struct {
	status int
	cache  string
	body   string
	serial int64
	staple bool
	server string
	err    string
}

func get(port int, host, path string) answer {
	request, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d%s", port, path), nil)
	request.Host = host
	// a new connection per request: after a reload it reaches a new worker
	timeout := 10 * time.Second
	if strings.HasPrefix(path, "/slow/") {
		timeout = 40 * time.Second
	}
	client := &http.Client{Timeout: timeout, Transport: &http.Transport{DisableKeepAlives: true}}
	response, err := client.Do(request)
	if err != nil {
		return answer{err: err.Error()}
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	return answer{status: response.StatusCode, cache: response.Header.Get("X-CDN-Cache"), body: string(body),
		server: response.Header.Get("Server")}
}

func getTLS(host, path string, roots *x509.CertPool) answer {
	var state tls.ConnectionState
	transport := &http.Transport{DialTLSContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		connection, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", portTLS), &tls.Config{ServerName: host, RootCAs: roots, MinVersion: tls.VersionTLS12})
		if err == nil {
			state = connection.ConnectionState()
		}
		return connection, err
	}}
	defer transport.CloseIdleConnections()
	request, _ := http.NewRequest(http.MethodGet, "https://"+host+path, nil)
	response, err := (&http.Client{Transport: transport, Timeout: 10 * time.Second}).Do(request)
	if err != nil {
		return answer{err: err.Error()}
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	result := answer{status: response.StatusCode, body: string(body), staple: len(state.OCSPResponse) > 0}
	if len(state.PeerCertificates) > 0 {
		result.serial = state.PeerCertificates[0].SerialNumber.Int64()
	}
	return result
}

func masterPID() string {
	raw, _ := os.ReadFile(filepath.Join(*state, "shared", "nginx.pid"))
	return strings.TrimSpace(string(raw))
}

func workerGID() int {
	group, err := user.LookupGroup("nobody")
	if err != nil {
		return -1
	}
	gid, _ := strconv.Atoi(group.Gid)
	return gid
}

func cacheFiles(root string) int {
	count := 0
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err == nil && info.Mode().IsRegular() {
			count++
		}
		return nil
	})
	return count
}

// ---------------------------------------------------------------- run

type harness struct {
	ctx     context.Context
	config  dynroute.Config
	runtime *dynroute.Runtime
	input   dynroute.Input
}

func (h *harness) apply(name string, sites ...edgesite.Site) dynroute.Result {
	h.input.Objects = objects(sites...)
	result, err := h.runtime.Apply(h.ctx, h.input)
	check(name, err == nil, "generation %d changes %d sets %d reloaded %v started %v copied %d %s %v", result.Activation.Generation,
		result.Activation.Changes, result.Activation.ChangeSets, result.Reloaded, result.Started, result.Certificates.Copied,
		result.Duration.Round(time.Millisecond), err)
	return result
}

func main() {
	flag.Parse()
	ctx := context.Background()
	origin := &originServer{counts: map[string]int{}}
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", originPort))
	if err != nil {
		fmt.Println("FAIL origin", err)
		os.Exit(1)
	}
	go func() {
		_ = http.Serve(listener, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if strings.HasPrefix(request.URL.Path, "/slow/") {
				time.Sleep(10 * time.Second) // in flight across a reload (drain)
			}
			if strings.HasPrefix(request.URL.Path, "/hold/") {
				time.Sleep(2 * time.Second) // in flight (site access connections_per_ip)
			}
			if strings.HasPrefix(request.URL.Path, "/big/") {
				writer.Header().Set("Cache-Control", "max-age=3600")
				_, _ = writer.Write(make([]byte, 1<<20))
				return
			}
			origin.ServeHTTP(writer, request)
		}))
	}()
	if *suite == "node-storage" {
		runNodeStorage(ctx)
		return
	}
	_ = os.RemoveAll(*state)
	if err := os.MkdirAll(*state, 0o755); err != nil {
		fmt.Println("FAIL state", err)
		os.Exit(1)
	}
	certificateRoot := filepath.Join(*state, "certificates")
	store, err := certstore.NewManager(certstore.RuntimeConfig{StateRoot: certificateRoot, ListenAddress: "127.0.0.1", ListenPort: portTLS}, noCertificateRuntime{})
	if err != nil {
		fmt.Println("FAIL certstore", err)
		os.Exit(1)
	}
	ca := newAuthority()
	roots := x509.NewCertPool()
	roots.AddCert(ca.certificate)
	fetcher := &ocspFetcher{ca: ca}
	if err := os.MkdirAll(filepath.Join(*state, "node"), 0o750); err != nil {
		fmt.Println("FAIL state", err)
		os.Exit(1)
	}
	objectsRoot := filepath.Join(*state, "node", "objects")
	if siteObjects, err = objectstore.OpenShared(objectsRoot, max(workerGID(), 0)); err != nil {
		fmt.Println("FAIL object store", err)
		os.Exit(1)
	}
	config := dynroute.Config{StateRoot: filepath.Join(*state, "node"), SharedRoot: filepath.Join(*state, "shared"), ObjectsRoot: objectsRoot, LuaRoot: *luaRoot,
		OpenResty: *binary, WorkerGID: workerGID(), CacheMaxBytes: 512 << 20, Workers: *workers, Certificates: store, OCSP: fetcher,
		HealthTimeout: 20 * time.Second, AutoDefense: true,
		// Telemetry on, as install-node.sh writes it (tele-reliab): node-level
		// logs and the security aggregate flush directory run/secagg (B9).
		Telemetry: true}
	var crs *edgeconfig.CRSRuleText
	var profiles map[string]edgeconfig.CRSProfile
	engineRoot := *modSecurity // the installed engine version (CRS engine change: another directory)
	if *modSecurity != "" {
		config.WAFEngine = func() (*dynwaf.Engine, error) {
			return &dynwaf.Engine{ModulePath: filepath.Join(engineRoot, "modules", "ngx_http_modsecurity_module.so"),
				UnicodeMapPath: filepath.Join(engineRoot, "unicode.mapping")}, nil
		}
		files, err := rulecatalog.DecodeWAFEngineBundle(*rulecatalog.CRSRulesBundle())
		if err != nil {
			fmt.Println("FAIL crs", err)
			os.Exit(1)
		}
		crs = &edgeconfig.CRSRuleText{Version: rulecatalog.CRSRulesBundle().Version, Files: files}
		if profiles, err = goldenrelease.CRSProfiles(); err != nil {
			fmt.Println("FAIL profiles", err)
			os.Exit(1)
		}
	}
	runtime, err := dynroute.New(config)
	if err != nil {
		fmt.Println("FAIL runtime", err)
		os.Exit(1)
	}
	h := &harness{ctx: ctx, config: config, runtime: runtime, input: dynroute.Input{CRSText: crs, Profiles: profiles,
		ScopeVersions: map[string]string{scope: "0d130000-0000-4000-8000-0000000000a1"}}}

	// -------------------------------------------------------- cold start
	shop := withCache(makeSite(1, "shop.d13.test", 1, portPlain), 64<<20)
	// as every published site carries it (edgepublish site_objects_v2_source.go)
	shop.Telemetry = &edgesite.Telemetry{Capture: siteobject.TelemetryCapture{Methods: []string{}, URIPrefixes: []string{},
		RequestHeaderAllowlist: []string{}, ResponseHeaderAllowlist: []string{}, RequestBodyFieldAllowlist: []string{},
		ResponseBodyFieldAllowlist: []string{}}}
	blog := makeSite(2, "blog.d13.test", 1, portPlain)
	first := h.apply("cold-start-apply", shop, blog)
	check("cold-start-started", first.Started && first.Reloaded && first.Activation.Rebuilt, "%+v", first)
	a := get(portPlain, "shop.d13.test", "/index.html")
	check("cold-start-200", a.status == 200 && strings.HasPrefix(a.body, "origin shop.d13.test /index.html"), "%d %.40q %s", a.status, a.body, a.err)
	a = get(portPlain, "unknown.d13.test", "/")
	check("unknown-host-421", a.status == 421, "%d", a.status)
	telemetryChecks(config)

	// -------------------------------------------------------- incremental
	pid := masterPID()
	blog2 := makeSite(2, "blog.d13.test", 2, portPlain)
	blog2.Hosts.Aliases = []string{"www.blog.d13.test"}
	edit := h.apply("incremental-apply", shop, blog2)
	check("incremental-no-reload", !edit.Reloaded && !edit.Activation.Rebuilt && edit.Activation.ChangeSets == 1 && masterPID() == pid,
		"reloaded %v rebuilt %v sets %d", edit.Reloaded, edit.Activation.Rebuilt, edit.Activation.ChangeSets)
	a = get(portPlain, "www.blog.d13.test", "/x")
	check("incremental-alias-200", a.status == 200 && strings.HasPrefix(a.body, "origin www.blog.d13.test /x"), "%d %.40q", a.status, a.body)
	extra := makeSite(3, "extra.d13.test", 1, portExtra)
	// drain (D13-b): a request in flight across the reload keeps its old
	// worker running; the drain plan waits for RemainingWorkers to reach 0
	inflight := make(chan answer, 1)
	go func() { inflight <- get(portPlain, "blog.d13.test", "/slow/drain") }()
	time.Sleep(500 * time.Millisecond)
	added := h.apply("new-port-apply", shop, blog2, extra)
	check("new-port-reloads", added.Reloaded && !added.Started && masterPID() == pid, "reloaded %v master %s -> %s", added.Reloaded, pid, masterPID())
	during := runtime.RemainingWorkers(added.OldWorkers)
	slow := <-inflight
	drained := -1
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if drained = runtime.RemainingWorkers(added.OldWorkers); drained == 0 {
			break
		}
	}
	check("drain-old-workers", len(added.OldWorkers) == *workers && during >= 1 && slow.status == 200 && drained == 0,
		"old %v remaining during %d after %d in-flight %d %s", added.OldWorkers, during, drained, slow.status, slow.err)
	check("drain-no-reload-no-old", len(edit.OldWorkers) == 0, "index-only activation replaced %v", edit.OldWorkers)
	a = get(portExtra, "extra.d13.test", "/")
	check("new-port-200", a.status == 200, "%d %s", a.status, a.err)
	removed := h.apply("remove-site-apply", shop, blog2)
	a = get(portPlain, "www.blog.d13.test", "/x")
	b := get(portExtra, "extra.d13.test", "/")
	check("removed-site", b.status == 0 || b.status == 421 || b.status == 503, "extra after removal: %d %s (reloaded %v)", b.status, b.err, removed.Reloaded)
	check("kept-site-200", a.status == 200, "%d", a.status)

	// -------------------------------------------------------- rollback
	generation, err := runtime.Rollback(ctx)
	a = get(portExtra, "extra.d13.test", "/")
	check("rollback", err == nil && generation > 0 && a.status == 200, "generation %d extra %d %v", generation, a.status, err)
	h.apply("after-rollback-apply", shop, blog2)

	// -------------------------------------------------------- certificates
	secure := withTLS(makeSite(4, "secure.d13.test", 1, portTLS), "0d130000-0000-4000-8000-0000000c0001", true)
	chain1, key1, leaf1 := ca.issue("secure.d13.test")
	if err := deliver(store, secure, "0d130000-0000-4000-8000-0000000c0001", chain1, key1); err != nil {
		check("certificate-deliver-1", false, "%v", err)
	}
	tlsApply := h.apply("tls-apply", shop, blog2, secure)
	statuses := runtime.RefreshOCSP(ctx)
	check("ocsp-refresh", len(statuses) == 1 && statuses[0].Stapled && fetcher.calls == 1, "%+v calls %d", statuses, fetcher.calls)
	a = getTLS("secure.d13.test", "/s", roots)
	check("tls-200", a.status == 200 && a.serial == leaf1.SerialNumber.Int64() && tlsApply.Certificates.Copied == 1, "%d serial %d want %d copied %d %s",
		a.status, a.serial, leaf1.SerialNumber.Int64(), tlsApply.Certificates.Copied, a.err)
	check("tls-ocsp-stapled", a.staple, "stapled %v", a.staple)
	pid = masterPID()
	chain2, key2, leaf2 := ca.issue("secure.d13.test")
	rotated := withTLS(makeSite(4, "secure.d13.test", 2, portTLS), "0d130000-0000-4000-8000-0000000c0002", true)
	if err := deliver(store, rotated, "0d130000-0000-4000-8000-0000000c0002", chain2, key2); err != nil {
		check("certificate-deliver-2", false, "%v", err)
	}
	rotation := h.apply("rotation-apply", shop, blog2, rotated)
	a = getTLS("secure.d13.test", "/s", roots)
	check("rotation-serves-new", a.status == 200 && a.serial == leaf2.SerialNumber.Int64(), "serial %d want %d", a.serial, leaf2.SerialNumber.Int64())
	check("rotation-no-reload", !rotation.Reloaded && masterPID() == pid && rotation.Certificates.Copied == 1, "reloaded %v copied %d", rotation.Reloaded, rotation.Certificates.Copied)
	pool := filepath.Join(config.StateRoot, "tls-pool")
	_, oldKept := os.Stat(filepath.Join(pool, "0d130000-0000-4000-8000-0000000c0001.crt"))
	check("rotation-keeps-previous", oldKept == nil, "old version kept for rollback: %v", oldKept)
	h.apply("rotation-settle-apply", shop, blog2, rotated)
	_, oldKept = os.Stat(filepath.Join(pool, "0d130000-0000-4000-8000-0000000c0001.crt"))
	check("rotation-drops-old", os.IsNotExist(oldKept), "old version after two generations: %v", oldKept)

	// -------------------------------------------------------- cache
	a = get(portPlain, "shop.d13.test", "/a.css")
	b = get(portPlain, "shop.d13.test", "/a.css")
	check("cache-miss-hit", a.cache == "MISS" && b.cache == "HIT" && origin.count("shop.d13.test", "/a.css") == 1, "%s/%s origin %d",
		a.cache, b.cache, origin.count("shop.d13.test", "/a.css"))
	cacheRoot := filepath.Join(config.SharedRoot, "cache")
	before := cacheFiles(cacheRoot)
	// cachecontrol purge_site, as the gateway client hands it over
	tasks := dynroute.CacheTasks{Runtime: runtime}
	task := cachetask.Task{SchemaVersion: cachetask.SchemaVersion, TaskID: "0d130000-0000-4000-8000-0000000000f1",
		OperationID: "0d130000-0000-4000-8000-0000000000f1", TenantID: tenant, SiteID: shop.SiteID, Scope: cachetask.ScopeSite,
		ConfigVersionID: "0d130000-0000-4000-8000-0000000000a1", ConfigRevision: 1, DeliveryAttempt: 1, Action: cachetask.ActionPurgeSite}
	purged, err := tasks.Execute(ctx, task)
	c := get(portPlain, "shop.d13.test", "/a.css")
	check("purge-site-task", err == nil && purged.State == cachetask.StateSucceeded && len(purged.Items) == 1 && purged.Items[0].Affected >= 1 &&
		len(purged.Digest) == 64 && c.cache == "MISS" && origin.count("shop.d13.test", "/a.css") == 2,
		"%s affected %d files %d -> %d then %s %v", purged.State, itemsAffected(purged), before, cacheFiles(cacheRoot), c.cache, err)
	get(portPlain, "shop.d13.test", "/b.css")
	exact := task
	exact.TaskID, exact.Action, exact.Scope, exact.Targets = "0d130000-0000-4000-8000-0000000000f2", cachetask.ActionPurgeExact, cachetask.ScopeURL,
		[]string{fmt.Sprintf("http://shop.d13.test:%d/b.css", portPlain)}
	exactResult, err := tasks.Execute(ctx, exact)
	c = get(portPlain, "shop.d13.test", "/b.css")
	check("purge-exact-task", err == nil && itemsAffected(exactResult) == 1 && c.cache == "MISS", "affected %d then %s %v", itemsAffected(exactResult), c.cache, err)
	warm := task
	warm.TaskID, warm.Action, warm.Scope, warm.Targets = "0d130000-0000-4000-8000-0000000000f3", cachetask.ActionPrewarm, cachetask.ScopeURL,
		[]string{fmt.Sprintf("http://shop.d13.test:%d/warm.css", portPlain)}
	warmed, err := tasks.Execute(ctx, warm)
	c = get(portPlain, "shop.d13.test", "/warm.css")
	check("prewarm-task", err == nil && warmed.State == cachetask.StateSucceeded && c.cache == "HIT", "%s %v then %s %v", warmed.State, itemCodes(warmed), c.cache, err)
	other := task
	other.SiteID = blog2.SiteID
	_, err = tasks.Execute(ctx, other)
	check("purge-site-without-cache", errors.Is(err, cachetask.ErrSiteNotFound), "%v", err)
	for index := range 72 {
		get(portPlain, "shop.d13.test", fmt.Sprintf("/big/%d", index))
	}
	cleaned, err := runtime.CleanQuota(ctx)
	check("soft-quota-clean", err == nil && cleaned.Sites == 1 && cleaned.Removed > 0, "%+v %v", cleaned, err)

	// CACHEFLOW-E01: an exact purge of a sliced object removes every slice
	// (the site's policy slice_bytes; a whole-object key finds nothing)
	sliced := withCache(makeSite(9, "slice.d13.test", 1, portPlain), 64<<20)
	sliced.Cache.Policy.SliceBytes = 256 << 10
	sliced.Cache.Generation, _ = edgesite.CacheGeneration(*sliced.Cache)
	h.apply("sliced-apply", shop, blog2, rotated, sliced)
	a = get(portPlain, "slice.d13.test", "/slice/v.bin")
	b = get(portPlain, "slice.d13.test", "/slice/v.bin")
	sliceExact := task
	sliceExact.TaskID, sliceExact.SiteID, sliceExact.Action, sliceExact.Scope, sliceExact.Targets = "0d130000-0000-4000-8000-0000000000f4",
		sliced.SiteID, cachetask.ActionPurgeExact, cachetask.ScopeURL, []string{fmt.Sprintf("http://slice.d13.test:%d/slice/v.bin", portPlain)}
	sliceResult, err := tasks.Execute(ctx, sliceExact)
	c = get(portPlain, "slice.d13.test", "/slice/v.bin")
	check("purge-exact-sliced", b.cache == "HIT" && err == nil && sliceResult.State == cachetask.StateSucceeded &&
		itemsAffected(sliceResult) == 3 && c.cache == "MISS" && len(c.body) == 768<<10,
		"seed %s/%s affected %d then %s (%d bytes) %v", a.cache, b.cache, itemsAffected(sliceResult), c.cache, len(c.body), err)
	h.apply("sliced-remove-apply", shop, blog2, rotated)

	// CACHEFLOW-E03: a task past its deadline (queued too long) asks the
	// origin nothing
	late := warm
	late.TaskID, late.Targets = "0d130000-0000-4000-8000-0000000000f5", []string{fmt.Sprintf("http://shop.d13.test:%d/late.css", portPlain)}
	late.Deadline = time.Now().Add(-time.Second)
	// CACHEFLOW-E02: the task's per-object limit (node cache_task) stops a
	// larger object (the origin answers 4 KiB+)
	small := warm
	small.TaskID, small.Targets = "0d130000-0000-4000-8000-0000000000f6", []string{fmt.Sprintf("http://shop.d13.test:%d/limit.css", portPlain)}
	small.Budget = cachetask.ResourceBudget{MaxAttempts: 1, MaxConcurrency: 1, MaxResourceBytes: 1024, MaxTotalBytes: 1 << 20,
		RequestsPerSecond: 10, Burst: 2}
	smallResult, err := tasks.Execute(ctx, small)
	check("prewarm-object-limit", err == nil && smallResult.State == cachetask.StateFailed &&
		slices.Equal(itemCodes(smallResult), []string{cachetask.CodePrewarmResponseTooLarge}), "%s %v %v", smallResult.State, itemCodes(smallResult), err)
	lateResult, err := tasks.Execute(ctx, late)
	check("prewarm-expired-deadline", err == nil && lateResult.State == cachetask.StateFailed &&
		slices.Equal(itemCodes(lateResult), []string{cachetask.CodeTaskDeadlineExceeded}) && origin.count("shop.d13.test", "/late.css") == 0,
		"%s %v origin %d %v", lateResult.State, itemCodes(lateResult), origin.count("shop.d13.test", "/late.css"), err)

	// -------------------------------------------------------- managed WAF
	if *modSecurity != "" {
		pl1, pl2 := profileNamed(profiles, "system/crs-pl1"), profileNamed(profiles, "system/crs-pl2")
		guarded := withWAF(makeSite(5, "waf.d13.test", 1, portPlain), pl1)
		wafApply := h.apply("waf-apply", shop, blog2, rotated, guarded)
		a = get(portPlain, "waf.d13.test", sqli)
		b = get(portPlain, "waf.d13.test", pl2Probe)
		c = get(portPlain, "blog.d13.test", sqli)
		check("waf-pl1-blocks", a.status == 403 && b.status == 200 && c.status == 200 && wafApply.Reloaded && wafApply.WAFDigest != "",
			"attack %d pl2-probe %d unguarded %d reloaded %v", a.status, b.status, c.status, wafApply.Reloaded)
		pid = masterPID()
		stricter := withWAF(makeSite(5, "waf.d13.test", 2, portPlain), pl2)
		tier := h.apply("waf-tier-apply", shop, blog2, rotated, stricter)
		b = get(portPlain, "waf.d13.test", pl2Probe)
		check("waf-tier-switch", b.status == 403 && tier.WAFDigest != wafApply.WAFDigest, "pl2-probe %d digest changed %v reloaded %v",
			b.status, tier.WAFDigest != wafApply.WAFDigest, tier.Reloaded)
		// CRS engine change (D13-b): the artifact set installs another engine
		// version; the agent applies the same node state again, the skeleton's
		// load_module names the new module: nginx -t and a reload, still blocking
		next := filepath.Join(*state, "engine-v2")
		if err := copyTree(*modSecurity, next); err != nil {
			check("engine-copy", false, "%v", err)
		}
		engineRoot = next
		pid = masterPID()
		swapped := h.apply("engine-change-apply", shop, blog2, rotated, stricter)
		conf, _ := os.ReadFile(filepath.Join(config.SharedRoot, "nginx.conf"))
		b = get(portPlain, "waf.d13.test", pl2Probe)
		check("engine-change-reloads", swapped.Reloaded && masterPID() == pid && strings.Contains(string(conf), next) && b.status == 403,
			"reloaded %v master kept %v new path %v pl2-probe %d", swapped.Reloaded, masterPID() == pid, strings.Contains(string(conf), next), b.status)
		same := h.apply("engine-unchanged-apply", shop, blog2, rotated, stricter)
		check("engine-unchanged-no-reload", !same.Reloaded, "reloaded %v", same.Reloaded)
		// retest N3: a CRS deny gets the site's block page (a theme's
		// edge_route 403, as the built-in/theme pages are delivered), not
		// nginx's default 403; an origin 403 passes through untouched
		branded := stricter
		branded.Revision = 3
		if err := siteObjects.Put(edgesite.Digest([]byte(brandBlock403)), []byte(brandBlock403)); err != nil {
			check("managed-waf-block-page-asset", false, "%v", err)
		}
		branded.Errors, err = edgesite.ErrorPagesFor([]edgesite.ErrorPageRule{{ID: "theme.edge_route.403", Category: edgesite.ErrorEdgeRoute,
			Codes: []int{403}, MIMEType: "text/plain", Asset: edgesite.Ref{Kind: edgesite.RefErrorPageAsset,
				ID: "0d130000-0000-4000-8000-0000000000e3", Revision: 1, SHA256: edgesite.Digest([]byte(brandBlock403))}}}, nil)
		check("managed-waf-block-page-fixture", err == nil, "%v", err)
		h.apply("managed-waf-block-page-apply", shop, blog2, rotated, branded)
		a = get(portPlain, "waf.d13.test", sqli)
		check("managed-waf-block-brand-page", a.status == 403 && a.body == brandBlock403 && !strings.Contains(a.body, "openresty"),
			"status %d body %.120q", a.status, a.body)
		b = get(portPlain, "waf.d13.test", "/origin-403")
		check("managed-waf-origin-403-untouched", b.status == 403 && b.body == origin403Body, "status %d body %.120q", b.status, b.body)
		// WAF grey zone repeat threshold per site (migration 512, capability 64; gap-tests)
		h.input.Objects = objects(shop, blog2, rotated, branded)
	}

	// -------------------------------------------------------- rule pack mounts (F1/F2)
	{
		node := x25519()
		packs, err := newRulePackFixture(filepath.Join(*state, "rule-packs"), "/run/cdnca/rule-packs", node.PublicKey(), node)
		check("rulepack-fixture", err == nil, "%v", err)
		if err == nil {
			mounted := withMounts(makeSite(6, "packs.d13.test", 1, portPlain), packs.security)
			before := h.input.Objects
			// No rule pack runtime: a mounting site is refused, nothing changes.
			_, refused := h.runtime.Apply(h.ctx, dynroute.Input{Objects: objects(shop, blog2, rotated, mounted),
				ScopeVersions: h.input.ScopeVersions, CRSText: h.input.CRSText, Profiles: h.input.Profiles})
			check("rulepack-no-runtime-refused", refused != nil, "%v", refused)
			withPacks := h.config
			withPacks.RulePlans = packs.plans()
			packRuntime, err := dynroute.New(withPacks)
			check("rulepack-runtime", err == nil, "%v", err)
			if err == nil {
				kept := h.runtime
				h.runtime = packRuntime
				var sites []edgesite.Site
				for _, object := range before {
					sites = append(sites, object.Site)
				}
				h.apply("rulepack-apply", append(sites, mounted)...)
				a = get(portPlain, "packs.d13.test", "/wp-admin/login")
				b = get(portPlain, "packs.d13.test", sqli)
				c = get(portPlain, "packs.d13.test", "/index.html")
				d := get(portPlain, "blog.d13.test", "/wp-admin/login")
				check("rulepack-rules-enforced", a.status == 403 && b.status == 403 && c.status == 200 && d.status == 200,
					"admin %d sqli %d plain %d other-site %d", a.status, b.status, c.status, d.status)
				// A vault whose wrap is for another node key cannot open the pack.
				stranger, err := newRulePackFixture(filepath.Join(*state, "rule-packs-other"), "/run/cdnca/rule-packs-other", x25519().PublicKey(), node)
				check("rulepack-wrong-key-fixture", err == nil, "%v", err)
				if err == nil {
					strangerConfig := h.config
					strangerConfig.RulePlans = stranger.plans()
					strangerRuntime, err := dynroute.New(strangerConfig)
					if err == nil {
						_, err = strangerRuntime.Apply(h.ctx, dynroute.Input{Objects: objects(append(sites,
							withMounts(makeSite(6, "packs.d13.test", 2, portPlain), stranger.security))...),
							ScopeVersions: h.input.ScopeVersions, CRSText: h.input.CRSText, Profiles: h.input.Profiles})
					}
					check("rulepack-wrong-key-refused", err != nil, "%v", err)
					a = get(portPlain, "packs.d13.test", "/wp-admin/login")
					check("rulepack-wrong-key-keeps-previous", a.status == 403, "%d", a.status)
				}
				// ri-wire (4115a5448): an official intelligence pack's mark
				// (log, continue) writes its segment policy ID, so the auto
				// defense sample of the request carries the pack's label
				// cc_v2 packs: the user pack's log+stop exception runs before
				// the system pack's limit (one CC pack policy, published order).
				ccSecurity, err := packs.addCCPacks()
				check("rulepack-cc-fixture", err == nil, "%v", err)
				if err == nil {
					ccSite := withMounts(makeSite(7, "ccpacks.d13.test", 1, portPlain), ccSecurity)
					h.apply("rulepack-cc-apply", append(sites, mounted, ccSite)...)
					// /limited/open: 1st counted by the system rule, then the
					// user rule stops before it (no 429 although over 2).
					var open, limited []int
					for range 3 {
						open = append(open, get(portPlain, "ccpacks.d13.test", "/limited/open").status)
					}
					for range 2 {
						limited = append(limited, get(portPlain, "ccpacks.d13.test", "/limited/x").status)
					}
					other := get(portPlain, "packs.d13.test", "/limited/x")
					check("rulepack-cc-enforced", slices.Equal(open, []int{200, 200, 200}) && slices.Equal(limited, []int{200, 429}) &&
						other.status == 200, "open %v limited %v other-site %d", open, limited, other.status)
				}
				// Official system packs (license migration 097): bad UA and 404 burst.
				if *official != "" {
					officialChecks(h, packs, sites, mounted)
					// ML-25: a market site without the paid pack's plugin.
					marketPluginChecks(h, packs, sites)
				}
				// modsecurity pack (方案 A): narrows the site's crs-pl2 (the
				// tier the WAF part left in use, so the WAF digest stays) to
				// its XSS set through managed_waf.exclusions; the node-wide
				// CRS configuration is not changed for the pack.
				if *modSecurity != "" {
					profile := profileNamed(h.input.Profiles, "system/crs-pl2")
					manifest, err := edgeconfig.DeriveCRSManifest(h.input.CRSText)
					check("rulepack-modsec-manifest", err == nil, "%v", err)
					narrowSecurity, exclusions, err := packs.addModSecurityPack(2, manifest, profile)
					check("rulepack-modsec-fixture", err == nil && len(exclusions) > 0, "%d exclusions %v", len(exclusions), err)
					if err == nil && len(exclusions) > 0 {
						plain := withWAF(makeSite(8, "modsec.d13.test", 1, portPlain), profile)
						baseline := h.apply("rulepack-modsec-baseline", append(sites, mounted, plain)...)
						a = get(portPlain, "modsec.d13.test", sqliPlain)
						b = get(portPlain, "modsec.d13.test", xss)
						check("rulepack-modsec-baseline", a.status == 403 && b.status == 403, "sqli %d xss %d", a.status, b.status)
						narrowed := withMounts(withWAF(makeSite(8, "modsec.d13.test", 2, portPlain), profile), narrowSecurity)
						narrowed.Security.ManagedWAF.Exclusions = exclusions
						applied := h.apply("rulepack-modsec-apply", append(sites, mounted, narrowed)...)
						a = get(portPlain, "modsec.d13.test", sqliPlain)
						b = get(portPlain, "modsec.d13.test", xss)
						c = get(portPlain, "packs.d13.test", "/index.html")
						check("rulepack-modsec-narrowed", a.status == 200 && b.status == 403 && c.status == 200 &&
							applied.WAFDigest == baseline.WAFDigest, "sqli %d xss %d other %d waf digest same %v",
							a.status, b.status, c.status, applied.WAFDigest == baseline.WAFDigest)
						// The site's exclusions miss what the pack switches off: refused.
						short := withMounts(withWAF(makeSite(8, "modsec.d13.test", 3, portPlain), profile), narrowSecurity)
						short.Security.ManagedWAF.Exclusions = exclusions[1:]
						_, err := h.runtime.Apply(h.ctx, dynroute.Input{Objects: objects(append(sites, mounted, short)...),
							ScopeVersions: h.input.ScopeVersions, CRSText: h.input.CRSText, Profiles: h.input.Profiles})
						check("rulepack-modsec-missing-exclusion-refused", err != nil, "%v", err)
						// Paranoia 3 is outside crs-pl2: refused by the node too.
						wide, none, err := packs.addModSecurityPack(3, manifest, profile)
						if err == nil {
							over := withMounts(withWAF(makeSite(8, "modsec.d13.test", 4, portPlain), profile), wide)
							over.Security.ManagedWAF.Exclusions = exclusions
							_, err = h.runtime.Apply(h.ctx, dynroute.Input{Objects: objects(append(sites, mounted, over)...),
								ScopeVersions: h.input.ScopeVersions, CRSText: h.input.CRSText, Profiles: h.input.Profiles})
						}
						a = get(portPlain, "modsec.d13.test", sqliPlain)
						check("rulepack-modsec-out-of-profile-refused", err != nil && none == nil && a.status == 200,
							"%v exclusions %v previous kept sqli %d", err, none, a.status)
						// Sealed modsecurity pack: the control
						// plane narrows by the crs_rule_ids the license service
						// computed into the manifest; the node opens the pack,
						// checks the rules evaluate exactly the list, then
						// applies it (same effect as the plaintext pack).
						sealedSecurity, sealedExclusions, err := packs.addSealedModSecurityPack("system/xss-sealed", nil, manifest, profile)
						check("rulepack-modsec-sealed-fixture", err == nil && slices.Equal(sealedExclusions, exclusions),
							"exclusions %d (plaintext %d) %v", len(sealedExclusions), len(exclusions), err)
						if err == nil {
							sealedSite := withMounts(withWAF(makeSite(8, "modsec.d13.test", 5, portPlain), profile), sealedSecurity)
							sealedSite.Security.ManagedWAF.Exclusions = sealedExclusions
							h.apply("rulepack-modsec-sealed-apply", append(sites, mounted, sealedSite)...)
							a = get(portPlain, "modsec.d13.test", sqliPlain)
							b = get(portPlain, "modsec.d13.test", xss)
							check("rulepack-modsec-sealed-enforced", a.status == 200 && b.status == 403, "sqli %d xss %d", a.status, b.status)
							// A list the rules do not evaluate (one rule dropped,
							// what a forged manifest would carry): the node
							// refuses the apply and keeps the previous generation.
							forged, forgedExclusions, err := packs.addSealedModSecurityPack("system/xss-forged", xssRuleIDs(manifest)[1:],
								manifest, profile)
							check("rulepack-modsec-forged-fixture", err == nil, "%v", err)
							if err == nil {
								forgedSite := withMounts(withWAF(makeSite(8, "modsec.d13.test", 6, portPlain), profile), forged)
								forgedSite.Security.ManagedWAF.Exclusions = forgedExclusions
								_, err = h.runtime.Apply(h.ctx, dynroute.Input{Objects: objects(append(sites, mounted, forgedSite)...),
									ScopeVersions: h.input.ScopeVersions, CRSText: h.input.CRSText, Profiles: h.input.Profiles})
								a = get(portPlain, "modsec.d13.test", sqliPlain)
								b = get(portPlain, "modsec.d13.test", xss)
								check("rulepack-modsec-forged-list-refused", err != nil &&
									strings.Contains(err.Error(), "do not match its listed CRS rule IDs") && a.status == 200 && b.status == 403,
									"%v previous kept sqli %d xss %d", err, a.status, b.status)
							}
						}
					}
				}
				h.runtime = kept
				h.apply("rulepack-remove", sites...)
				h.input.Objects = before
				_ = packRuntime
			}
		}
	}

	// -------------------------------------------------------- agent restart
	pid = masterPID()
	generation = runtime.Generation()
	restarted, err := dynroute.New(config)
	if err == nil {
		err = restarted.Recover(ctx)
	}
	a = get(portPlain, "shop.d13.test", "/index.html")
	check("agent-restart", err == nil && masterPID() == pid && restarted.Generation() == generation && a.status == 200 && len(restarted.Sites()) == len(h.input.Objects),
		"generation %d/%d master %s/%s sites %d status %d %v", restarted.Generation(), generation, masterPID(), pid, len(restarted.Sites()), a.status, err)
	_, _, err = restarted.PurgeSite(ctx, tenant, shop.SiteID)
	check("agent-restart-purge", err == nil, "%v", err)

	// -------------------------------------------------------- node restart
	if err := restarted.Stop(ctx); err != nil {
		check("node-stop", false, "%v", err)
	}
	again, err := dynroute.New(config)
	if err == nil {
		err = again.Recover(ctx)
	}
	a = get(portPlain, "shop.d13.test", "/index.html")
	d := getTLS("secure.d13.test", "/s", roots)
	check("node-restart", err == nil && a.status == 200 && d.status == 200 && d.serial == leaf2.SerialNumber.Int64() && masterPID() != pid,
		"shop %d secure %d serial %d master %s %v", a.status, d.status, d.serial, masterPID(), err)
	e := get(portPlain, "shop.d13.test", "/a.css")
	f := get(portPlain, "shop.d13.test", "/a.css")
	check("node-restart-cache", f.cache == "HIT", "%s/%s (purge generations pushed after start)", e.cache, f.cache)
	h.runtime = again
	h.apply("after-restart-apply", objectsSites(h.input.Objects)...)

	// -------------------------------------------------------- system (D13-c0)
	// The scopes' platform system configuration: the skeleton renders its
	// nginx base (Server header), the DDoS table covers the site ports and
	// the CC kernel ban ports follow its cc_kernel_ban mode.
	table := &recordedDDoS{}
	systemConfig := config
	systemConfig.DDoS = table
	withSystem, err := dynroute.New(systemConfig)
	if err == nil {
		err = withSystem.Recover(ctx)
	}
	check("system-runtime", err == nil, "%v", err)
	h.runtime = withSystem
	h.input.Systems = []*edgeconfig.SiteRuntimeSystem{testSystem(1, edgeconfig.CCKernelBanExclusivePorts)}
	sys := h.apply("system-apply", objectsSites(h.input.Objects)...)
	a = get(portPlain, "shop.d13.test", "/index.html")
	ports := withSystem.CCKernelBanPorts(scope, shop.SiteID)
	check("system-renders", sys.Reloaded && a.status == 200 && a.server == "cdnca-d13", "reloaded %v status %d server %q", sys.Reloaded, a.status, a.server)
	check("system-ddos-table", len(table.specs) == 1 && table.specs[0] != nil && table.specs[0].Protection.MaxConnectionsPerIP == 64 &&
		len(table.specs[0].Ports) > 0 && table.specs[0].Ports[0].First == portPlain, "specs %d %+v", len(table.specs), table.specs)
	check("system-cc-kernel-exclusive", len(ports) == 0, "shop shares %d: %v", portPlain, ports)
	h.input.Systems = []*edgeconfig.SiteRuntimeSystem{testSystem(2, edgeconfig.CCKernelBanSitePorts)}
	h.apply("system-mode-apply", objectsSites(h.input.Objects)...)
	ports = withSystem.CCKernelBanPorts(scope, shop.SiteID)
	check("system-cc-kernel-site-ports", len(ports) == 1 && ports[0] == portPlain, "%v", ports)
	if _, err := withSystem.Rollback(ctx); err != nil {
		check("system-rollback", false, "%v", err)
	}
	a = get(portPlain, "shop.d13.test", "/index.html")
	check("system-kept-on-rollback", a.server == "cdnca-d13" && len(table.specs) == 3, "server %q tables %d", a.server, len(table.specs))
	h.input.Systems = nil
	plain := h.apply("system-removed-apply", objectsSites(h.input.Objects)...)
	a = get(portPlain, "shop.d13.test", "/index.html")
	check("system-removed", plain.Reloaded && a.server != "cdnca-d13" && table.specs[len(table.specs)-1] == nil,
		"reloaded %v server %q last table %v", plain.Reloaded, a.server, table.specs[len(table.specs)-1])
	again = withSystem

	// -------------------------------------------------------- L4 (D13-c0)
	again = checkStreams(h, config, again, roots)

	// -------------------------------------------- node locations (D13-c0)
	again = checkNodeLocations(h, config, again)

	// -------------------------------------------- site access (D13-c0 ⑥)
	checkSiteAccess(h, rotated, roots, objectsSites(h.input.Objects)...)

	// -------------------------------------------- site connections (D13-b2)
	checkSiteConnections(h)

	// -------------------------------------------- origin auth (D13-b2)
	checkOriginAuth(h, ca, objectsSites(h.input.Objects)...)

	// -------------------------------------------- node pages (D13-b2)
	checkNodePages(h, objectsSites(h.input.Objects)...)

	// -------------------------------------------- error page slot pages (errpage-5, 待出包前全量跑)
	again = checkSlotPages(h, config, again, origin, objectsSites(h.input.Objects)...)

	// -------------------------------------------------------- error.log
	stats, err := again.ReadErrorLog()
	check("error-log-read", err == nil, "severe %d noise %d recent %d %v", stats.SevereTotal, stats.NoiseTotal, len(stats.Recent), err)
	for _, line := range stats.Recent {
		fmt.Println("LOG", line)
	}
	logPath := filepath.Join(config.SharedRoot, "error.log")
	appendLog(logPath, "[emerg] 1#1: close() socket 0.0.0.0:443 failed (9: Bad file descriptor)")
	appendLog(logPath, "[crit] 1#1: *1 d13 synthetic critical line")
	next, err := again.ReadErrorLog()
	check("error-log-filter", err == nil && next.NoiseTotal == stats.NoiseTotal+1 && next.SevereTotal == stats.SevereTotal+1 &&
		len(next.Recent) > 0 && strings.Contains(next.Recent[len(next.Recent)-1], "d13 synthetic critical line"),
		"noise %d->%d severe %d->%d", stats.NoiseTotal, next.NoiseTotal, stats.SevereTotal, next.SevereTotal)
	_ = again.Stop(ctx)
	fmt.Printf("RESULT failures=%d\n", failures)
	if failures != 0 {
		os.Exit(1)
	}
}

type recordedDDoS struct{ specs []*ddos.Spec }

func (r *recordedDDoS) Apply(_ context.Context, spec *ddos.Spec) error {
	r.specs = append(r.specs, spec)
	return nil
}

// testSystem is a platform system configuration at revision with the
// cc_kernel_ban mode (Server header cdnca-d13, 64 connections per client).
func testSystem(revision int64, mode string) *edgeconfig.SiteRuntimeSystem {
	system, err := edgeconfig.NewSiteRuntimeSystem("0d130000-0000-4000-8000-0000000000c1", revision, strings.Repeat(strconv.Itoa(int(revision)), 64),
		edgeconfig.NginxSettings{WorkerProcesses: *workers, WorkerRlimitNoFile: 65535, WorkerShutdownTimeout: 30 * time.Second,
			WorkerConnections: 4096, ResolverAddresses: []string{"127.0.0.11"}, ResolverTimeout: 5 * time.Second, GzipLevel: 5,
			GzipMinimumBytes: 1024, ProxyCacheMethods: []string{"GET", "HEAD"}, ProxyCacheMaxBytes: 1 << 30,
			ProxyCacheZoneBytes: 64 << 20, ProxyMaxTempFileBytes: 1 << 20, ProxyConnectTimeout: 10 * time.Second,
			ProxySendTimeout: 60 * time.Second, ProxyReadTimeout: 60 * time.Second, StreamProxyTimeout: 10 * time.Minute,
			ServerHeader: "cdnca-d13", ClientMaxBodyBytes: 100 << 20, DefaultMIMEType: "text/html", KeepaliveRequests: 1000,
			KeepaliveTimeout: 75 * time.Second, ServerNamesHashMaxSize: 4096})
	if err != nil {
		panic(err)
	}
	protection := edgeconfig.DefaultDDoSProtection()
	protection.MaxConnectionsPerIP, protection.CCKernelBan = 64, mode
	value, err := edgeconfig.NewSiteRuntimeDDoS(protection, []string{"198.51.100.0/24"})
	if err != nil {
		panic(err)
	}
	system.DDoS = &value
	return &system
}

func itemsAffected(result cachetask.Result) int {
	total := 0
	for _, item := range result.Items {
		total += item.Affected
	}
	return total
}

func itemCodes(result cachetask.Result) []string {
	var codes []string
	for _, item := range result.Items {
		codes = append(codes, item.Code)
	}
	return codes
}

func objectsSites(objects []siteindex.Object) []edgesite.Site {
	sites := make([]edgesite.Site, len(objects))
	for index, object := range objects {
		sites[index] = object.Site
	}
	sort.Slice(sites, func(i, j int) bool { return sites[i].SiteID < sites[j].SiteID })
	return sites
}

func copyTree(from, to string) error {
	return filepath.Walk(from, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		target := filepath.Join(to, strings.TrimPrefix(path, from))
		if info.Mode()&os.ModeSymlink != 0 {
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			return os.Symlink(link, target)
		}
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, raw, 0o644)
	})
}

func appendLog(path, message string) {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return
	}
	defer file.Close()
	fmt.Fprintf(file, "%s %s\n", time.Now().Format("2006/01/02 15:04:05"), message)
}

func profileNamed(all map[string]edgeconfig.CRSProfile, pack string) edgeconfig.CRSProfile {
	for _, profile := range all {
		if profile.Ref.PackID == pack {
			return profile
		}
	}
	panic("no " + pack)
}
