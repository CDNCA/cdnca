package gateway

import (
	"encoding/json"
	"os"
	"regexp"
	"strconv"
	"testing"

	"github.com/nats-io/nats.go"
)

// CC-STATS-LIVE-EMPTY-1: the streams the gateway creates at run time reserve their max_bytes in the same fixed
// JetStream budget as the installer's native profile. AUTODEFENSE_REPORTS at 8 GiB on top of the profile's
// 26.07 GiB exceeded max_file_store (32 GiB): NATS refused it (10047), the gateway started without the auto
// defense channel and no cc_stats report ever left a node. The installer test only counts the profile.
func TestGatewayStreamsFitTheNativeJetStreamBudget(t *testing.T) {
	script, err := os.ReadFile("../../scripts/install-control.sh")
	if err != nil {
		t.Fatal(err)
	}
	match := regexp.MustCompile(`max_file_store:(\d+)`).FindSubmatch(script)
	if match == nil {
		t.Fatal("install-control.sh sets no max_file_store")
	}
	capacity, err := strconv.ParseInt(string(match[1]), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../../scripts/native-runtime/native-nats-profile.json")
	if err != nil {
		t.Fatal(err)
	}
	var profile struct {
		Defaults struct {
			MaxBytes *int64 `json:"max_bytes"`
		} `json:"stream_defaults"`
		Streams []struct {
			Name     string `json:"name"`
			MaxBytes *int64 `json:"max_bytes"`
		} `json:"streams"`
	}
	if err := json.Unmarshal(raw, &profile); err != nil {
		t.Fatal(err)
	}
	reserved := int64(0)
	inProfile := map[string]bool{}
	for _, stream := range profile.Streams {
		inProfile[stream.Name] = true
		bytes := stream.MaxBytes
		if bytes == nil {
			bytes = profile.Defaults.MaxBytes
		}
		if bytes != nil && *bytes > 0 {
			reserved += *bytes
		}
	}
	var runtime []*nats.StreamConfig
	for _, configs := range [][]*nats.StreamConfig{
		DefaultNATSAutoDefenseBusConfig().StreamConfigs(), DefaultNATSGatewayAddressBusConfig().StreamConfigs(),
		DefaultNATSSiteDropBusConfig().StreamConfigs(), DefaultNATSSecurityBanBusConfig().StreamConfigs(),
		DefaultNATSInstallationBanBusConfig().StreamConfigs(), DefaultNATSSignerTrustBusConfig().StreamConfigs(),
		DefaultNATSSSHAccessBusConfig().StreamConfigs(),
	} {
		runtime = append(runtime, configs...)
	}
	for _, stream := range runtime {
		if !inProfile[stream.Name] && stream.MaxBytes > 0 {
			reserved += stream.MaxBytes
		}
	}
	// The installer test keeps the profile under 90 %; the gateway's own streams share that margin.
	if limit := capacity / 10 * 9; reserved > limit {
		t.Fatalf("profile and gateway streams reserve %d bytes, more than 90%% of max_file_store %d (%d)", reserved, capacity, limit)
	}
}
