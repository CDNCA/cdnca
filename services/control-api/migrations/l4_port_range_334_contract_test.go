package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Every number the merge renumbering touches is here.
const (
	l4PortRangeVersion        = 334
	l4PortRangeID             = "334_l4_port_range"
	l4PortRangePreviousID     = "333_security_activation_node_artifacts"
	l4PortRangePreviousUpSHA  = "5e9e7605e6cabc43ff1af6cd38cf0f22849dc07f664d18daeb199cf551b97d36"
	l4PortRangePreviousDownSH = "f5c379562defa2787322ccea73abf03dc44fbca6e181e1f8cac655c21bc08cef"
	l4PortRangeUpSHA          = "8797397e3bb1dfcaebf69422f8ac5dbce8a8e86ccfcabc27f937096c8c5dcbaa"
	l4PortRangeDownSHA        = "a9ff06178c9f888ccd237f73769851bd68bc1ba0e97d1cc1c107216df2965303"
)

func TestL4PortRange334Contract(t *testing.T) {
	previous := l4PortRangeVersion - 1
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{l4PortRangeID + ".up.sql", l4PortRangeUpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", previous),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", previous),
			"migration_id='" + l4PortRangePreviousID + "'",
			"checksum_sha256='" + l4PortRangePreviousUpSHA + "'",
			"down_checksum_sha256='" + l4PortRangePreviousDownSH + "'",
			fmt.Sprintf("ERRCODE='P%d0'", l4PortRangeVersion),
			"ADD COLUMN listen_port_end integer", "ADD COLUMN upstream_follow_port boolean NOT NULL DEFAULT false",
			"ARRAY[80,443,18080,18443]", "port_end - port < 1000",
			"validate_l4_runtime_spec_328(target_stream_id,target_scope_id,target_site_id,stripped)",
			"l4_publish_intents_runtime_spec_334",
			"l4_forward_listeners_tcp_range_334 EXCLUDE USING gist", "l4_forward_listeners_udp_range_334 EXCLUDE USING gist",
		}},
		{l4PortRangeID + ".down.sql", l4PortRangeDownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", l4PortRangeVersion),
			"migration_id='" + l4PortRangeID + "'",
			fmt.Sprintf("ERRCODE='P%d1'", l4PortRangeVersion), fmt.Sprintf("ERRCODE='P%d2'", l4PortRangeVersion),
			"l4_publish_intents_runtime_spec_328", "check_l4_listener_facts_248()",
			"sync_l4_primary_listener_293()", "protect_l4_listener_293()",
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
