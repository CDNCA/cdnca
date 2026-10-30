// cdnca-sched302-check: HTTP 302 scheduling on the dynamic
// routing node (the node skeleton + cdnca_dynroute + site objects), inside
// the node runtime image (tests/dynroute-sched302/run.sh). The same cases as
// the v7 renderer's TestRealOpenRestySchedule302*: one OpenResty plays the
// entry node and every candidate (127.0.0.2..4 reach the same listener);
// clients connect from 127.1.0.1 (telecom, Guangdong in the test IP
// library), 127.2.0.1 (unicom, Beijing) and 127.3.0.1 (not in the library).
package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/edgegolden/goldendyn"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/sched302runtime"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/siteindex"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/edgeconfig/sched302"
	"github.com/cdnca/cdnca/libs/entitlement/ipintel"
)

var (
	luaRoot = flag.String("lua", "/usr/local/share/cdnca", "node Lua tree")
	state   = flag.String("state", "/tmp/s302", "state directory")
	workers = flag.Int("workers", 2, "worker_processes")
)

const (
	scope      = "0d302000-0000-4000-8000-000000000001"
	tenant     = "0d302000-0000-4000-8000-000000000002"
	siteID     = "0d302000-0000-4000-8000-000000000101"
	sizedID    = "0d302000-0000-4000-8000-000000000102"
	plainID    = "0d302000-0000-4000-8000-000000000103"
	self       = "0d302000-0000-4000-8000-0000000000a0"
	nodeTel    = "0d302000-0000-4000-8000-0000000000b1"
	nodeUni    = "0d302000-0000-4000-8000-0000000000c2"
	nodeBGP    = "0d302000-0000-4000-8000-0000000000d3"
	port       = 18911
	originAddr = "127.0.0.1:19911"
	domain     = "dl.example.test"
	sized      = "big.example.test"
	plain      = "www.example.test"
	telecom    = "127.1.0.1"
	unicom     = "127.2.0.1"
	unknown    = "127.3.0.1"
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

// origin answers every path with 5000 bytes, /small.bin with 100; it
// echoes the scheduling headers it received.
type origin struct {
	mu       sync.Mutex
	requests []*http.Request
}

func (o *origin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	o.mu.Lock()
	o.requests = append(o.requests, r.Clone(context.Background()))
	o.mu.Unlock()
	w.Header().Set("X-Origin-Saw-S302", r.Header.Get("X-Cdnca-S302")+"|"+r.Header.Get("X-Cdnca-S302-Client"))
	size := 5000
	if r.URL.Path == "/small.bin" {
		size = 100
	}
	_, _ = io.WriteString(w, strings.Repeat("x", size))
}

func (o *origin) last() *http.Request {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.requests) == 0 {
		return nil
	}
	return o.requests[len(o.requests)-1]
}

func listener(id, host string, settings *sched302.Site) edgesite.Site {
	return edgesite.Site{Schema: edgesite.Schema, ConfigurationScopeID: scope, TenantID: tenant, SiteID: id, Revision: 1,
		Hosts:     edgesite.Hosts{Primary: host, Aliases: []string{}},
		Listeners: []edgesite.Listener{{Port: port, AddressFamily: edgesite.FamilyIPv4}},
		Origin: edgesite.Origin{DefaultPoolID: "primary", Routes: []edgesite.Route{}, Auth: []edgesite.OriginAuth{},
			Pools: []edgesite.Pool{{ID: "primary", Kind: "origin", Algorithm: "round_robin",
				Retry:     edgesite.Retry{Methods: []string{"GET", "HEAD"}, MaxAttempts: 1, ConnectTimeoutMS: 2000, ReadTimeoutMS: 5000, TotalBudgetMS: 10000},
				Endpoints: []edgesite.Endpoint{{ID: "o1", Scheme: "http", Host: "127.0.0.1", Port: 19911, Weight: 1}}}}},
		Security: edgesite.Security{Rules: edgesite.RulePlan{HeaderOverflow: edgesite.HeaderOverflowNoMatch, Policies: []edgesite.RulePolicy{}},
			CC: []edgesite.CCBinding{}},
		Errors: []edgesite.ErrorPage{}, Schedule302: settings,
	}
}

func startNode(sites []edgesite.Site) error {
	_ = exec.Command("openresty", "-p", *state+"/", "-c", "nginx.conf", "-s", "stop").Run()
	time.Sleep(200 * time.Millisecond)
	_ = os.RemoveAll(*state)
	for _, dir := range []string{"logs", "run", "site-index", "site-objects", "tls-pool", filepath.Join(goldendyn.SharedDirectory, "cache")} {
		if err := os.MkdirAll(filepath.Join(*state, dir), 0o755); err != nil {
			return err
		}
	}
	for _, name := range []string{"client_body", "proxy", "fastcgi", "uwsgi", "scgi"} {
		if err := os.MkdirAll(filepath.Join(*state, goldendyn.SharedDirectory, name+"-temp"), 0o755); err != nil {
			return err
		}
	}
	ports, err := edgesite.PortProfiles(sites)
	if err != nil {
		return err
	}
	keys := 0
	for _, s := range sites {
		keys += len(s.IndexEntries())
	}
	raw, err := goldendyn.Config(goldendyn.ConfigInput{Root: *state, LuaRoot: *luaRoot, Ports: ports, IndexKeys: keys,
		Workers: *workers, Schedule302: true})
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*state, "nginx.conf"), raw, 0o644); err != nil {
		return err
	}
	if output, err := exec.Command("openresty", "-p", *state+"/", "-c", "nginx.conf").CombinedOutput(); err != nil {
		return fmt.Errorf("start: %v %s", err, output)
	}
	gid := -1
	if group, err := user.LookupGroup("nobody"); err == nil {
		gid, _ = strconv.Atoi(group.Gid)
	}
	control := siteindex.NewControl(filepath.Join(*state, "run", "cdnca-site-admin.sock"))
	activator := &siteindex.Activator{Control: control,
		Files:   siteindex.Files{Root: filepath.Join(*state, "site-index"), Access: siteindex.Access{GID: gid}},
		Objects: siteindex.ObjectDir{Root: filepath.Join(*state, "site-objects"), Access: siteindex.Access{GID: gid}}}
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if _, err := control.Status(context.Background()); err == nil {
			break
		} else if time.Now().After(deadline) {
			return err
		}
	}
	objects := make([]siteindex.Object, 0, len(sites))
	for _, s := range sites {
		raw, err := edgesite.Encode(s)
		if err != nil {
			return err
		}
		object, err := siteindex.DecodeObject(edgesite.Digest(raw), raw)
		if err != nil {
			return err
		}
		objects = append(objects, object)
	}
	_, err = activator.Activate(context.Background(), objects)
	return err
}

func installLibrary() error {
	generated := time.Now().UTC().Truncate(time.Second)
	artifact, err := ipintel.Build(ipintel.BuildInput{Revision: 1, BuildID: "ipintel-sched302-0001", GeneratedAt: generated,
		DataUpdatedAt: generated.Add(-time.Hour), StaleAfter: generated.Add(24 * time.Hour),
		Sources: []ipintel.Source{{ID: "sched302-test", Name: "sched302 test", URL: "https://cdnca.com/test", License: "CC0-1.0"}},
		Regions: map[uint32]string{440000: "广东省", 110000: "北京市"},
		Facts: []ipintel.Fact{
			{Prefix: netip.MustParsePrefix("127.1.0.0/16"), Tags: ipintel.TagCNTelecom, Country: "CN", Province: 440000},
			{Prefix: netip.MustParsePrefix("127.2.0.0/16"), Tags: ipintel.TagCNUnicom, Country: "CN", Province: 110000},
		}})
	if err != nil {
		return err
	}
	directory := "/var/lib/cdnca-edge/ip-intel"
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(directory, "current.ipi"), artifact.Bytes, 0o644)
}

var (
	key = func() []byte {
		k := make([]byte, sched302.KeyBytes)
		for i := range k {
			k[i] = byte(100 + i)
		}
		return k
	}()
	revision uint64
	runtime  *sched302runtime.Runtime
)

func candidates() []sched302.Candidate {
	return []sched302.Candidate{
		{NodeID: nodeTel, Host: "127.0.0.2", HTTPPort: port, Carrier: "telecom", Country: "CN", Province: 440000, Weight: 10, Available: true},
		{NodeID: nodeUni, Host: "127.0.0.3", HTTPPort: port, Carrier: "unicom", Country: "CN", Province: 110000, Weight: 10, Available: true},
		{NodeID: nodeBGP, Host: "127.0.0.4", HTTPPort: port, Carrier: "bgp", Country: "CN", Weight: 10, Available: true},
	}
}

func writeTable(list []sched302.Candidate, generatedAt time.Time) {
	revision++
	encodedKey := base64.RawURLEncoding.EncodeToString(key)
	table := sched302.Table{Schema: sched302.TableSchema, NodeID: self, Revision: revision, GeneratedAt: generatedAt.Unix(),
		Sites: []sched302.TableSite{
			{SiteID: siteID, Hosts: []string{domain}, Key: encodedKey, Candidates: list},
			{SiteID: sizedID, Hosts: []string{sized}, Key: encodedKey, Candidates: list},
		}}
	encoded, err := sched302.Encode(table)
	if err == nil {
		err = runtime.Apply(table, encoded)
	}
	if err != nil {
		check("write table", false, "%v", err)
	}
}

type answer struct {
	status  int
	header  http.Header
	body    string
	failure error
}

func send(method, source, url, host string, header http.Header) answer {
	dialer := &net.Dialer{Timeout: 3 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}}
	client := &http.Client{Timeout: 5 * time.Second,
		Transport:     &http.Transport{DialContext: dialer.DialContext, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var body io.Reader
	if method == http.MethodPost {
		body = strings.NewReader("a=1")
	}
	request, err := http.NewRequest(method, url, body)
	if err != nil {
		return answer{failure: err}
	}
	request.Host = host
	for name, values := range header {
		request.Header[name] = values
	}
	response, err := client.Do(request)
	if err != nil {
		return answer{failure: err}
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)
	return answer{status: response.StatusCode, header: response.Header, body: string(raw)}
}

func entry(path string) string { return fmt.Sprintf("http://127.0.0.1:%d%s", port, path) }

// redirected waits (the table is re-read within a second) for a 302 to host.
func redirected(source, host, path, want string) (string, bool) {
	prefix := fmt.Sprintf("http://%s:%d%s", want, port, sched302.LandingPrefix)
	var last answer
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		last = send(http.MethodGet, source, entry(path), host, nil)
		if location := last.header.Get("Location"); last.status == http.StatusFound && strings.HasPrefix(location, prefix) &&
			last.header.Get("Cache-Control") == "no-store" {
			return location, true
		}
	}
	return fmt.Sprintf("%d %q %v", last.status, last.header.Get("Location"), last.failure), false
}

func servedHere(source, host, path string) bool {
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if got := send(http.MethodGet, source, entry(path), host, nil); got.status == http.StatusOK && len(got.body) == 5000 {
			return true
		}
	}
	return false
}

func functional(origins *origin) {
	location, ok := redirected(telecom, domain, "/v/a.mp4?k=1", "127.0.0.2")
	check("telecom-client", ok, "%s", location)
	got, ok := redirected(unicom, domain, "/v/a.mp4?k=1", "127.0.0.3")
	check("unicom-client", ok, "%s", got)
	want, _ := sched302.Select(candidates(), sched302.Client{Address: netip.MustParseAddr(unknown)})
	got, ok = redirected(unknown, domain, "/v/a.mp4", want.Host)
	check("unknown-client-hash", ok, "%s (want %s)", got, want.Host)

	// landing: served here with the original Host and URI, no scheduling
	// headers at the origin, never redirected again
	check("keeps-path-query", strings.Contains(location, "/"+domain+"/v/a.mp4?k=1"), "%s", location)
	target := strings.TrimPrefix(location, "http://")
	landed := send(http.MethodGet, telecom, "http://"+target, target[:strings.Index(target, "/")], nil)
	check("landing-served", landed.status == http.StatusOK && len(landed.body) == 5000, "%d %d", landed.status, len(landed.body))
	check("origin-no-schedule-headers", landed.header.Get("X-Origin-Saw-S302") == "|", "%q", landed.header.Get("X-Origin-Saw-S302"))
	last := origins.last()
	check("origin-original-request", last != nil && last.Host == domain && last.URL.RequestURI() == "/v/a.mp4?k=1",
		"%v", func() string {
			if last == nil {
				return "none"
			}
			return last.Host + last.URL.RequestURI()
		}())
	check("origin-sees-client", last != nil && last.Header.Get("X-Real-Ip") == telecom, "X-Real-IP=%q",
		func() string {
			if last == nil {
				return ""
			}
			return last.Header.Get("X-Real-Ip")
		}())
	tampered := strings.Replace(target, "/v/a.mp4", "/v/b.mp4", 1)
	got2 := send(http.MethodGet, telecom, "http://"+tampered, "127.0.0.2", nil)
	check("tampered-403", got2.status == http.StatusForbidden && got2.header.Get("X-Cdnca-S302-Reject") == "signature", "%d %v", got2.status, got2.header)
	loop := send(http.MethodGet, "127.0.0.1", "http://"+target, "127.0.0.2", nil)
	check("loopback-never-lands", loop.status == http.StatusMisdirectedRequest, "%d", loop.status)

	expired := sched302.LandingPath(key, siteID, domain, "/v/a.mp4", time.Now().Add(-time.Second).Unix())
	got2 = send(http.MethodGet, telecom, fmt.Sprintf("http://127.0.0.2:%d%s", port, expired), "127.0.0.2", nil)
	check("expired-403", got2.status == http.StatusForbidden && got2.header.Get("X-Cdnca-S302-Reject") == "expired", "%d", got2.status)
	foreign := sched302.LandingPath(key, siteID, "other.example.test", "/v/a.mp4", time.Now().Add(time.Minute).Unix())
	got2 = send(http.MethodGet, telecom, fmt.Sprintf("http://127.0.0.2:%d%s", port, foreign), "127.0.0.2", nil)
	check("foreign-host-403", got2.status == http.StatusForbidden, "%d", got2.status)
	got2 = send(http.MethodGet, telecom, entry("/v/a.mp4"), domain, http.Header{"X-Cdnca-S302": {"1.AAAAAAAAAAAAAAAAAAAAAA"}})
	check("forged-token-403", got2.status == http.StatusForbidden, "%d", got2.status)
	got2 = send(http.MethodGet, telecom, entry("/v/a.mp4"), domain, http.Header{"X-Cdnca-S302-Client": {"203.0.113.9"}})
	check("forged-client-header-ignored", got2.status == http.StatusFound, "%d", got2.status)

	check("other-extension-served", servedHere(telecom, domain, "/index.html"), "")
	post := send(http.MethodPost, telecom, entry("/v/a.mp4"), domain, nil)
	check("post-served", post.status == http.StatusOK, "%d", post.status)
	check("unscheduled-site-served", servedHere(telecom, plain, "/v/a.mp4"), "")

	// node down: moved within seconds; all down / this node / stale: served
	down := candidates()
	down[0].Available = false
	writeTable(down, time.Now())
	started := time.Now()
	got, ok = redirected(telecom, domain, "/v/a.mp4", "127.0.0.4")
	elapsed := time.Since(started)
	check("node-down-moves", ok && elapsed < 2500*time.Millisecond, "%s in %s", got, elapsed.Round(10*time.Millisecond))
	for index := range down {
		down[index].Available = false
	}
	writeTable(down, time.Now())
	check("all-down-served", servedHere(telecom, domain, "/v/a.mp4"), "")
	selfList := candidates()
	selfList[0].NodeID = self
	writeTable(selfList, time.Now())
	check("self-served", servedHere(telecom, domain, "/v/a.mp4"), "")
	writeTable(candidates(), time.Now().Add(-time.Duration(sched302.HoldSeconds+10)*time.Second))
	check("stale-table-served", servedHere(telecom, domain, "/v/a.mp4"), "")
	writeTable(candidates(), time.Now())
	_, ok = redirected(telecom, domain, "/v/a.mp4", "127.0.0.2")
	check("recovered", ok, "")

	// size threshold (learned in the log phase)
	first := send(http.MethodGet, telecom, entry("/big.bin"), sized, nil)
	second := send(http.MethodGet, telecom, entry("/big.bin"), sized, nil)
	check("size-learned-then-redirected", first.status == http.StatusOK && second.status == http.StatusFound, "%d %d", first.status, second.status)
	first = send(http.MethodGet, telecom, entry("/small.bin"), sized, nil)
	second = send(http.MethodGet, telecom, entry("/small.bin"), sized, nil)
	check("small-file-served", first.status == http.StatusOK && second.status == http.StatusOK, "%d %d", first.status, second.status)
}

func main() {
	flag.Parse()
	if err := installLibrary(); err != nil {
		fmt.Printf("FAIL ip-library %v\n", err)
		os.Exit(1)
	}
	origins := &origin{}
	listen, err := net.Listen("tcp4", originAddr)
	if err != nil {
		fmt.Printf("FAIL origin %v\n", err)
		os.Exit(1)
	}
	go func() { _ = http.Serve(listen, origins) }()
	settings := &sched302.Site{Target: sched302.TargetAddress, KeepPath: true, KeepQuery: true, SignatureTTLSeconds: 60,
		Extensions: []string{"bin", "mp4"}, PathPrefixes: []string{}}
	sizedSettings := &sched302.Site{Target: sched302.TargetAddress, KeepPath: true, KeepQuery: true, SignatureTTLSeconds: 60,
		Extensions: []string{}, PathPrefixes: []string{}, MinSizeBytes: 1024}
	sites := []edgesite.Site{listener(siteID, domain, settings), listener(sizedID, sized, sizedSettings), listener(plainID, plain, nil)}
	if err := startNode(sites); err != nil {
		fmt.Printf("FAIL start %v\n", err)
		os.Exit(1)
	}
	if runtime, err = sched302runtime.New(*state, self); err != nil {
		fmt.Printf("FAIL runtime %v\n", err)
		os.Exit(1)
	}
	writeTable(candidates(), time.Now())
	functional(origins)
	if failures != 0 {
		raw, _ := os.ReadFile(filepath.Join(*state, goldendyn.SharedDirectory, "error.log"))
		lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
		fmt.Println(strings.Join(lines[max(0, len(lines)-30):], "\n"))
	}
	_ = exec.Command("openresty", "-p", *state+"/", "-c", "nginx.conf", "-s", "stop").Run()
	fmt.Printf("RESULT failures=%d\n", failures)
	if failures != 0 {
		os.Exit(1)
	}
}
