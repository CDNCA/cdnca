package httpapi

import (
	"os"
	"strings"
	"testing"
)

func TestSiteHTTPContractProjectsSubscriptionAndCNAMEState(t *testing.T) {
	source, err := os.ReadFile("sites.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		`json:"package_subscription_id"`, `json:"cname_state"`, `json:"cname_task_id"`,
		`json:"cname_current_revision"`, `json:"cname_lkg_revision"`,
	} {
		if !strings.Contains(string(source), required) {
			t.Errorf("sites.go missing %q", required)
		}
	}
}
