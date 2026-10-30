// Command cdnca-waf-apptype-check is the real OpenResty acceptance of CRS
// application types (waf-apptype): inside the node runtime image with the
// ModSecurity engine extension mounted, it renders the site runtime 8
// managed WAF of three sites exactly as a node does
// (edgeconfig.RenderListenerRuntimeSecurity, the release gate
// RenderWAFEngineGate): "wp" selects application type WordPress, "plain"
// and "none" select none (plain on a node that carries the WordPress pack
// for wp; none on a node without any application pack, the "not selected"
// baseline). It then sends typical vanilla WordPress admin requests (from
// the plugin's own regression tests) and real attacks, and reads the
// ModSecurity audit log.
//
//	-modsecurity   engine extension directory (module, unicode.mapping)
//	-packs         directory of the CRS profile and application pack goldens
//	-crs           CRS rule bundle (rulecatalog crs/rules.json)
//	-state         scratch directory
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	"github.com/cdnca/cdnca/libs/rulepack"
)

var (
	modSecurity = flag.String("modsecurity", "/usr/local/openresty/modsecurity", "engine extension directory")
	packsDir    = flag.String("packs", "/check/packs", "CRS profile and application pack goldens")
	crsBundle   = flag.String("crs", "/check/rules.json", "CRS rule bundle (rulecatalog crs/rules.json)")
	state       = flag.String("state", "/tmp/apptype", "scratch directory")
	failures    = 0
)

const (
	scopeID   = "0a990000-0000-4000-8000-000000000001"
	policyID  = "0a990000-0000-4000-8000-0000000000d1"
	wpSite    = "0a990000-0000-4000-8000-000000000011"
	plainSite = "0a990000-0000-4000-8000-000000000012"
	noneSite  = "0a990000-0000-4000-8000-000000000013"
	edgePort  = 18080
	noneEdge  = 18081
	origin    = 19811
)

func check(name string, ok bool, format string, args ...any) {
	status := "PASS"
	if !ok {
		status, failures = "FAIL", failures+1
	}
	fmt.Printf("%s %s: %s\n", status, name, fmt.Sprintf(format, args...))
}

func must(err error) {
	if err != nil {
		fmt.Println("FAIL setup:", err)
		os.Exit(1)
	}
}

func load(name string) ([]byte, string) {
	content, err := os.ReadFile(filepath.Join(*packsDir, name))
	must(err)
	sum := sha256.Sum256(content)
	return content, hex.EncodeToString(sum[:])
}

func managed(profile edgeconfig.CRSProfileRef, apps ...edgeconfig.CRSAppRef) *edgeconfig.ManagedWAF {
	value, err := edgeconfig.CanonicalListenerManagedWAF(edgeconfig.ManagedWAF{PolicyID: policyID, PolicyVersion: 1,
		RequestBodyLimit: 1 << 20, RequestBodyNoFilesLimit: 1 << 20, RequestBodyLimitAction: "reject",
		ArgumentsLimit: 1000, JSONDepthLimit: 512, PCREMatchLimit: 100000, Profile: profile, Apps: apps})
	must(err)
	return value
}

// node renders one release (versionID) for listeners into root and returns
// the server-level lines per listener.
func node(root, versionID string, listeners []edgeconfig.SecurityListener, profile edgeconfig.CRSProfile,
	apps map[string]edgeconfig.CRSApp, crs map[string][]byte) []string {
	release := filepath.Join(root, "release", versionID)
	runtime, err := edgeconfig.RenderListenerRuntimeSecurity(scopeID, versionID, listeners, edgeconfig.ListenerSecurityRuntime{
		StateRoot: root, LuaRoot: "/usr/local/share/cdnca",
		CRSFiles: func() (map[string][]byte, error) { return crs, nil },
		CRSProfile: func(ref edgeconfig.CRSProfileRef) (edgeconfig.CRSProfile, error) {
			if ref != profile.Ref {
				return edgeconfig.CRSProfile{}, fmt.Errorf("profile %s", ref.PackID)
			}
			return profile, nil
		},
		CRSApp: func(ref edgeconfig.CRSAppRef) (edgeconfig.CRSApp, error) {
			app, ok := apps[ref.SHA256]
			if !ok {
				return edgeconfig.CRSApp{}, fmt.Errorf("app %s not on this node", ref.PackID)
			}
			return app, nil
		},
	})
	must(err)
	for name, content := range runtime.Files {
		must(os.MkdirAll(filepath.Dir(filepath.Join(release, name)), 0o755))
		must(os.WriteFile(filepath.Join(release, name), content, 0o644))
	}
	for name, content := range crs {
		path := filepath.Join(release, "security/modsecurity/crs", name)
		must(os.MkdirAll(filepath.Dir(path), 0o755))
		must(os.WriteFile(path, content, 0o644))
	}
	manifest, err := edgeconfig.ParseWAFEngineManifest(runtime.Files[edgeconfig.WAFEngineManifestPath])
	must(err)
	gate, err := edgeconfig.RenderWAFEngineGate(manifest, edgeconfig.WAFEngineGate{ReleasePath: release,
		ModulePath: filepath.Join(*modSecurity, "modules", "ngx_http_modsecurity_module.so"),
		UnicodeMapPath: filepath.Join(*modSecurity, "unicode.mapping")})
	must(err)
	dir := edgeconfig.WAFEngineGateDir(root, versionID)
	must(os.MkdirAll(dir, 0o755))
	for name, content := range gate {
		must(os.WriteFile(filepath.Join(dir, name), content, 0o644))
	}
	return append([]string{runtime.Main, runtime.HTTP}, runtime.Server...)
}

func main() {
	flag.Parse()
	_ = os.RemoveAll(*state)
	must(os.MkdirAll(filepath.Join(*state, "logs"), 0o777))
	must(os.MkdirAll(filepath.Join(*state, "shared"), 0o777))
	raw, err := os.ReadFile(*crsBundle)
	must(err)
	var bundle rulecatalog.WAFEngineBundle
	must(json.Unmarshal(raw, &bundle))
	crsAll, err := rulecatalog.DecodeWAFEngineBundle(bundle)
	must(err)
	profileBytes, profileDigest := load("crs-profiles/crs-pl1.json")
	_, profile, err := rulepack.LoadCRSProfile(profileBytes, profileDigest)
	must(err)
	appBytes, appDigest := load("crs-apps/app-wordpress.json")
	_, wordpress, err := rulepack.LoadCRSApp(appBytes, appDigest)
	must(err)

	listener := func(site, host string, port uint16, waf *edgeconfig.ManagedWAF) edgeconfig.SecurityListener {
		return edgeconfig.SecurityListener{SiteID: site, Domain: host, Port: port, Protocol: edgeconfig.ProtocolHTTP,
			Security: edgeconfig.ListenerSecurity{ManagedWAF: waf}}
	}
	crsFiles := func(listeners []edgeconfig.SecurityListener, apps ...edgeconfig.CRSApp) map[string][]byte {
		files, err := edgeconfig.ListenerCRSReleaseFiles(listeners, &edgeconfig.CRSRuleText{Version: bundle.Version, Files: crsAll},
			[]edgeconfig.CRSProfile{profile}, apps...)
		must(err)
		result := map[string][]byte{}
		for path, content := range files {
			result[strings.TrimPrefix(path, edgeconfig.ListenerCRSReleasePath(""))] = content
		}
		return result
	}
	// Node A: wp (WordPress) and plain on one http{} (one main.conf).
	a := []edgeconfig.SecurityListener{listener(wpSite, "wp.test", edgePort, managed(profile.Ref, wordpress.Ref)),
		listener(plainSite, "plain.test", edgePort, managed(profile.Ref))}
	linesA := node(*state, "apptype-a", a, profile, map[string]edgeconfig.CRSApp{wordpress.Ref.SHA256: wordpress}, crsFiles(a, wordpress))
	// Node B: none, without any application pack (behaviour without the feature).
	b := []edgeconfig.SecurityListener{listener(noneSite, "none.test", noneEdge, managed(profile.Ref))}
	stateB := filepath.Join(*state, "b")
	linesB := node(stateB, "apptype-b", b, profile, nil, crsFiles(b))
	mainA, err := os.ReadFile(filepath.Join(*state, "release/apptype-a/security/modsecurity/main.conf"))
	must(err)
	mainB, err := os.ReadFile(filepath.Join(stateB, "release/apptype-b/security/modsecurity/main.conf"))
	must(err)
	check("render", strings.Contains(string(mainA), "|awordpress|") && !strings.Contains(string(mainB), "CDNCA-APP-"),
		"node A main.conf gates WordPress, node B carries no application pack")

	writeConf := func(root string, lines []string, servers []string) {
		conf := lines[0] + "worker_processes 1;\nerror_log " + root + "/logs/error.log info;\npid " + root + "/logs/nginx.pid;\n" +
			"events { worker_connections 256; }\nhttp {\n  access_log off;\n  client_body_temp_path " + root + "/logs;\n" + lines[1]
		conf += strings.Join(servers, "") + "}\n"
		must(os.WriteFile(filepath.Join(root, "nginx.conf"), []byte(conf), 0o644))
	}
	server := func(host string, port int, line string) string {
		return fmt.Sprintf("  server {\n    listen 127.0.0.1:%d;\n    server_name %s;\n%s    location / { proxy_pass http://127.0.0.1:%d; }\n  }\n",
			port, host, line, origin)
	}
	writeConf(*state, linesA, []string{server("wp.test", edgePort, linesA[2]), server("plain.test", edgePort, linesA[3])})
	must(os.MkdirAll(filepath.Join(stateB, "logs"), 0o777))
	writeConf(stateB, linesB, []string{server("none.test", noneEdge, linesB[2])})

	listenerOrigin, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", origin))
	must(err)
	go http.Serve(listenerOrigin, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(200)
	}))
	for _, root := range []string{*state, stateB} {
		if output, err := exec.Command("openresty", "-p", root+"/", "-c", "nginx.conf", "-t").CombinedOutput(); err != nil {
			fmt.Printf("FAIL nginx -t %s: %s\n", root, output)
			os.Exit(1)
		}
		output, err := exec.Command("openresty", "-p", root+"/", "-c", "nginx.conf").CombinedOutput()
		if err != nil {
			fmt.Printf("FAIL start %s: %s\n", root, output)
			os.Exit(1)
		}
	}
	time.Sleep(500 * time.Millisecond)
	cases(stateB)
	for _, root := range []string{*state, stateB} {
		_ = exec.Command("openresty", "-p", root+"/", "-c", "nginx.conf", "-s", "stop").Run()
	}
	if failures != 0 {
		fmt.Printf("RESULT FAIL %d\n", failures)
		os.Exit(1)
	}
	fmt.Println("RESULT PASS")
}

type request struct {
	name, method, path, body string
}

// WordPress admin requests from wordpress-rule-exclusions-plugin v1.2.0
// tests/regression (9507100, 9507410, 9507420): CRS PL1 blocks each on a
// site without the WordPress application type.
var wordpressAdmin = []request{
	{"wp-login (9507100-1)", "POST", "/wp-login.php",
		"log=test&pwd=%3Cscript%3E&wp-submit=Log+In&redirect_to=https%3A%2F%2Fexample.com%2Fwp-admin%2F&testcookie=1"},
	{"setup-config step 2 (9507410-2)", "POST", "/wp-admin/setup-config.php?step=2",
		"dbname=test&uname=test&pwd=%3Cscript%3E&dbhost=localhost&prefix=wp_&language=&submit=Submit"},
	{"install step 2 (9507420-1)", "POST", "/wp-admin/install.php?step=2",
		"weblog_title=test&user_name=test&admin_password=%3Cscript%3E&admin_password2=%3Cscript%3E&pw_weak=on&admin_email=test%40example.com&Submit=Install+WordPress&language=en_US"},
}

// Attacks the WordPress exclusions do not cover: blocked on every site.
var attacks = []request{
	{"sqli in query", "GET", "/?id=1%27%20or%20%271%27%3D%271", ""},
	{"xss in a WordPress form field not excluded", "POST", "/wp-login.php", "log=%3Cscript%3Ealert(1)%3C%2Fscript%3E&wp-submit=Log+In"},
	{"sqli on a wp-admin page", "GET", "/wp-admin/index.php?x=1%20union%20select%20password%20from%20wp_users--", ""},
}

func send(host string, port int, value request) int {
	var body io.Reader
	if value.body != "" {
		body = strings.NewReader(value.body)
	}
	req, err := http.NewRequest(value.method, fmt.Sprintf("http://127.0.0.1:%d%s", port, value.path), body)
	must(err)
	req.Host = host
	req.Header.Set("User-Agent", "OWASP CRS test agent")
	req.Header.Set("Accept", "text/html")
	if value.body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

func cases(stateB string) {
	for _, value := range wordpressAdmin {
		wp, plain, none := send("wp.test", edgePort, value), send("plain.test", edgePort, value), send("none.test", noneEdge, value)
		check("wordpress admin "+value.name, wp == 200 && plain == 403 && none == 403,
			"wp (WordPress) %d, plain (same node, no app type) %d, none (node without app packs) %d", wp, plain, none)
	}
	for _, value := range attacks {
		wp, plain, none := send("wp.test", edgePort, value), send("plain.test", edgePort, value), send("none.test", noneEdge, value)
		check("attack "+value.name, wp == 403 && plain == 403 && none == 403, "wp %d, plain %d, none %d", wp, plain, none)
	}
	// The audit log names the WordPress site's transactions with the app marker
	// and no other site's.
	audit, _ := os.ReadFile(filepath.Join(*state, "shared", "modsecurity-audit.log"))
	wpMarked, plainMarked := 0, 0
	for _, line := range strings.Split(string(audit), "\n") {
		if strings.Contains(line, "|awordpress|") {
			if strings.Contains(line, "wp.test") {
				wpMarked++
			} else {
				plainMarked++
			}
		}
	}
	check("audit marker", wpMarked > 0 && plainMarked == 0, "WordPress-marked transactions: wp %d, other sites %d", wpMarked, plainMarked)
	ids := map[string]bool{}
	for _, line := range strings.Split(string(audit), "\n") {
		if strings.Contains(line, "plain.test") && strings.Contains(line, "wp-login.php") {
			for _, part := range strings.Split(line, `"ruleId":"`)[1:] {
				ids[part[:6]] = true
			}
		}
	}
	keys := make([]string, 0, len(ids))
	for id := range ids {
		keys = append(keys, id)
	}
	sort.Strings(keys)
	fmt.Printf("INFO rules hit on plain.test /wp-login.php: %s\n", strings.Join(keys, ","))
}
