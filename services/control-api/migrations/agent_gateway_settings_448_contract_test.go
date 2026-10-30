package migrations

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"testing"
)

// Migration 448 (GW-06/GW-07: trusted CDN ranges, per-Gateway
// allowed IPs and extra node entry points), a placeholder number on top of
// 434. Everything that changes with a renumbering is here.
const (
	migration448Version         = 448
	migration448ID              = "448_agent_gateway_settings"
	migration448PreviousID      = "447_agent_gateways"
	migration448PreviousUpSHA   = "3441bdb3855cf1b57c07bb959eac937497c6737711925ccd60a31cf792ab2607"
	migration448PreviousDownSHA = "ef73ed3669c888610b958b794265b40744e53114bff66a6c7df2b1c6b30ebe4b"
	migration448UpSHA           = "c474df5e04ff73f9b95d1c6545aaa1019750ff934f0f61d6fba5d9085222fcef"
	migration448DownSHA         = "904abf00f6c180f56e633ca66f208a5ebbaa7bb02c49450e33b777d5206830ab"
)

func TestAgentGatewaySettings448Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration448ID + ".up.sql", migration448UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration448Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration448Version-1),
			"migration_id='" + migration448PreviousID + "'", migration448PreviousUpSHA, migration448PreviousDownSHA,
			"ERRCODE='P4480'", "CREATE TABLE agent_gateway_trusted_ranges", "CREATE TABLE agent_gateway_allowed_ips",
			"CREATE TABLE agent_gateway_entrypoints", "'CF-Connecting-IP'",
		}},
		{migration448ID + ".down.sql", migration448DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration448Version),
			"migration_id='" + migration448ID + "'", "ERRCODE='P4481'",
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != script.sha {
			t.Fatalf("%s checksum drift: %s", script.name, got)
		}
		for _, required := range script.required {
			if !strings.Contains(string(raw), required) {
				t.Errorf("%s missing %q", script.name, required)
			}
		}
	}
}

// The preset must equal the list shipped inside agent-gateway (one source).
func TestAgentGatewaySettings448CloudflarePresetMatchesGateway(t *testing.T) {
	raw, err := FS.ReadFile(migration448ID + ".up.sql")
	if err != nil {
		t.Fatal(err)
	}
	shippedRaw, err := os.ReadFile("../../agent-gateway/trusted_proxies_cloudflare.txt")
	if err != nil {
		t.Fatal(err)
	}
	position := 0
	for _, line := range strings.Split(string(shippedRaw), "\n") {
		if line = strings.TrimSpace(line); line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		position++
		cidr, header, _ := strings.Cut(line, "=")
		want := fmt.Sprintf("(%d, '%s', '%s')", position, cidr, header)
		if !strings.Contains(string(raw), want) {
			t.Errorf("448 preset missing %s", want)
		}
	}
	if position == 0 || strings.Count(string(raw), "'CF-Connecting-IP')") != position {
		t.Fatalf("448 preset has %d Cloudflare rows, shipped list has %d", strings.Count(string(raw), "'CF-Connecting-IP')"), position)
	}
}
