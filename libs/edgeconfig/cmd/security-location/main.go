// security-location prints the rewrite_by_lua_block the site runtime renders
// for one listener's bound security policies (a JSON []SecurityPolicy on
// stdin), as RenderSecurityFragments does (scripts/security/waf-action-smoke.sh).
//
//	security-location <site-id> < policies.json
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

func main() {
	var policies []edgeconfig.SecurityPolicy
	if len(os.Args) != 2 || json.NewDecoder(os.Stdin).Decode(&policies) != nil {
		fmt.Fprintln(os.Stderr, "usage: security-location <site-id> < policies.json")
		os.Exit(2)
	}
	fragments, err := edgeconfig.RenderSecurityFragments("00000000-0000-4000-8000-0000000000aa", "v-smoke",
		[]edgeconfig.SecurityListener{{SiteID: os.Args[1], Domain: "action.test", Port: 18091, Protocol: edgeconfig.ProtocolHTTP,
			Security: edgeconfig.ListenerSecurity{Policies: policies}, Telemetry: true}})
	if err != nil {
		fmt.Fprintln(os.Stderr, "render:", err)
		os.Exit(1)
	}
	fmt.Print(fragments.HTTP)
	fmt.Print("=====\n")
	fmt.Print(fragments.Location[0])
	// The telemetry http / server directives (security log), for a smoke
	// that checks the logged security events.
	fmt.Print("=====\n")
	fmt.Print(edgeconfig.RenderTelemetryHTTP())
	fmt.Print("=====\n")
	fmt.Print(edgeconfig.RenderTelemetryServer(edgeconfig.TelemetryServer{TenantID: "00000000-0000-4000-8000-0000000000aa",
		SiteID: os.Args[1], ConfigVersionID: "00000000-0000-4000-8000-0000000000bb",
		AccessLogPath: "/w/logs/access.jsonl", SecurityLogPath: "/w/logs/security.jsonl"}))
}
