package identity

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPlatformPrincipalIncludesNullTenantID(t *testing.T) {
	encoded, err := json.Marshal(Principal{ScopeKind: "platform", DisplayID: "1"})
	if err != nil {
		t.Fatalf("marshal platform principal: %v", err)
	}
	if !strings.Contains(string(encoded), `"tenant_id":null`) {
		t.Fatalf("platform principal omitted tenant_id: %s", encoded)
	}
	if !strings.Contains(string(encoded), `"display_id":"1"`) {
		t.Fatalf("platform principal omitted display_id: %s", encoded)
	}
}
