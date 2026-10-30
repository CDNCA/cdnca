package edgedeployment

import (
	"encoding/json"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// Site runtime v7 (lazy certificates) is accepted end to end by the rollout
// validator; v8 is not.
func TestSiteRuntimeV2CapabilitiesAcceptLazyCertificateVersion(t *testing.T) {
	decode := func(version uint32) error {
		var values []struct {
			Name       string `json:"name"`
			APIVersion uint32 `json:"api_version"`
		}
		raw, _ := json.Marshal([]map[string]any{{"name": "http1", "api_version": 1}, {"name": "site_runtime", "api_version": version}})
		if err := json.Unmarshal(raw, &values); err != nil {
			t.Fatal(err)
		}
		_, err := decodeSiteRuntimeV2Capabilities(values)
		return err
	}
	if err := decode(edgeconfig.LazyCertificateSiteRuntimeVersion); err != nil {
		t.Fatalf("site_runtime v7 refused: %v", err)
	}
	if decode(edgeconfig.MaxSiteRuntimeVersion+1) == nil {
		t.Fatal("site_runtime above the maximum accepted")
	}
}
