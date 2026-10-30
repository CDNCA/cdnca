package edgedeployment

import (
	"sort"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/siteruntimecap"
)

// Every capability name the publisher may write into a site runtime v2
// document passes the rollout validator (rollback and safe activation
// re-validate published documents), both as a document capability and as a
// site object root capability.
func TestSiteRuntimeV2CapabilitiesAcceptEveryPublisherName(t *testing.T) {
	for _, name := range siteruntimecap.Names() {
		values := []struct {
			Name       string `json:"name"`
			APIVersion uint32 `json:"api_version"`
		}{{Name: "site_runtime", APIVersion: edgeconfig.MinSiteRuntimeVersion}}
		if name != "site_runtime" {
			values = append(values, struct {
				Name       string `json:"name"`
				APIVersion uint32 `json:"api_version"`
			}{Name: name, APIVersion: 1})
		}
		sort.Slice(values, func(i, j int) bool { return values[i].Name < values[j].Name })
		if _, err := decodeSiteRuntimeV2Capabilities(values); err != nil {
			t.Errorf("document capability %q refused: %v", name, err)
		}
		if capability, ok := siteruntimecap.Name(name); !ok || capability == agentv1.CapabilityName_CAPABILITY_NAME_UNSPECIFIED {
			t.Errorf("site object root capability %q unknown", name)
		}
	}
}
