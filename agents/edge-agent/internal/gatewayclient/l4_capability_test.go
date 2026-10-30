package gatewayclient

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

func TestL4LifecycleV2RejectsOldNodesAndRetainsLegacyCompatibility(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []agentv1.CapabilityName{agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY, agentv1.CapabilityName_CAPABILITY_NAME_UDP_PROXY} {
		for _, required := range []uint32{1, 2, 3} {
			for _, available := range []uint32{1, 2, 3} {
				command, _ := signedTestCommand(t, key)
				command.RequiredCapabilities = append(command.RequiredCapabilities, &agentv1.Capability{Name: name, ApiVersion: required})
				config := testClientConfig(t.TempDir())
				config.Capabilities.Features = append(config.Capabilities.Features, &agentv1.Capability{Name: name, ApiVersion: available})
				err := validateRoutedCommand(command, config, time.Now())
				if available < required {
					if !errors.Is(err, ErrUnsupportedCommand) {
						t.Fatalf("%v old %d accepted required %d: %v", name, available, required, err)
					}
				} else if err != nil {
					t.Fatalf("%v compatible %d rejected required %d: %v", name, available, required, err)
				}
			}
		}
	}
}
