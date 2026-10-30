package main

// -only apps: CRS application types (waf-apptype) on dynamic routing, one
// shared server. Site "wp" selects WordPress, site "plain" has the same
// profile and limits without it: vanilla WordPress admin requests (from the
// plugin's own regression tests, 9507100 / 9507410 / 9507420) pass on wp
// and are blocked on plain; attacks the exclusions do not cover are blocked
// on both, alternating request by request.

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/rulepack"
)

type appRequest struct{ name, method, path, body string }

var wordpressAdmin = []appRequest{
	{"wp-login (9507100-1)", http.MethodPost, "/wp-login.php",
		"log=test&pwd=%3Cscript%3E&wp-submit=Log+In&redirect_to=https%3A%2F%2Fexample.com%2Fwp-admin%2F&testcookie=1"},
	{"setup-config step 2 (9507410-2)", http.MethodPost, "/wp-admin/setup-config.php?step=2",
		"dbname=test&uname=test&pwd=%3Cscript%3E&dbhost=localhost&prefix=wp_&language=&submit=Submit"},
	{"install step 2 (9507420-1)", http.MethodPost, "/wp-admin/install.php?step=2",
		"weblog_title=test&user_name=test&admin_password=%3Cscript%3E&admin_password2=%3Cscript%3E&pw_weak=on&admin_email=test%40example.com&Submit=Install+WordPress&language=en_US"},
}

var appAttacks = []appRequest{
	{"sqli in query", http.MethodGet, "/?id=1%27%20or%20%271%27%3D%271", ""},
	{"xss in a WordPress form field not excluded", http.MethodPost, "/wp-login.php", "log=%3Cscript%3Ealert(1)%3C%2Fscript%3E&wp-submit=Log+In"},
	{"sqli on a wp-admin page", http.MethodGet, "/wp-admin/index.php?x=1%20union%20select%20password%20from%20wp_users--", ""},
}

func sendApp(host string, value appRequest) int {
	var body *strings.Reader
	headers := map[string]string{"User-Agent": "OWASP CRS test agent", "Accept": "text/html"}
	if value.body != "" {
		body = strings.NewReader(value.body)
		headers["Content-Type"] = "application/x-www-form-urlencoded"
		return do(client, value.method, host, value.path, body, headers)
	}
	return do(client, value.method, host, value.path, nil, headers)
}

func appsRun() {
	content, err := os.ReadFile(filepath.Join(*appsDir, "app-wordpress.json"))
	if err != nil {
		check("apps", false, "WordPress pack: %v", err)
		return
	}
	sum := sha256.Sum256(content)
	_, wordpress, err := rulepack.LoadCRSApp(content, hex.EncodeToString(sum[:]))
	if err != nil {
		check("apps", false, "WordPress pack: %v", err)
		return
	}
	pl1 := profileNamed(profiles(), "system/crs-pl1")
	wp := makeSite(31, "wp.waf.test", &wafSpec{profile: pl1})
	wp.Security.ManagedWAF.Apps = []edgeconfig.CRSAppRef{wordpress.Ref}
	plain := makeSite(32, "plain.waf.test", &wafSpec{profile: pl1})
	nodeApps = map[string]edgeconfig.CRSApp{wordpress.Ref.SHA256: wordpress}
	defer func() { nodeApps = nil }()
	n, err := startNode([]edgesite.Site{wp, plain}, true)
	if err != nil {
		check("apps start", false, "%v", err)
		return
	}
	defer stop()
	check("apps tiers", len(n.waf.Skeleton.Tiers) == 2, "tiers=%d (pl1, pl1+wordpress)", len(n.waf.Skeleton.Tiers))
	for round := 0; round < 2; round++ {
		for _, value := range wordpressAdmin {
			a, b := sendApp("wp.waf.test", value), sendApp("plain.waf.test", value)
			check("apps admin "+value.name, a == 200 && b == 403, "round %d: wp %d (want 200), plain %d (want 403)", round, a, b)
		}
		for _, value := range appAttacks {
			a, b := sendApp("wp.waf.test", value), sendApp("plain.waf.test", value)
			check("apps attack "+value.name, a == 403 && b == 403, "round %d: wp %d, plain %d (want 403 both)", round, a, b)
		}
	}
	// removing the application type is a new site object on the next
	// activation: the WordPress admin request is blocked again
	wp.Revision++
	wp.Security.ManagedWAF.Apps = nil
	if err := n.activate([]edgesite.Site{wp, plain}); err != nil {
		check("apps reactivate", false, "%v", err)
		return
	}
	got := sendApp("wp.waf.test", wordpressAdmin[0])
	// same profile and limits as plain: plain's tier, already in the skeleton
	check("apps removed", got == 403, "wp without the application type: %d (want 403, plain's tier)", got)
}
