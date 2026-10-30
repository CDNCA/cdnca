package httpapi

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/site"
)

func TestAuthorizeBatchSiteActionRequiresDNSManageForCNAMERegeneration(t *testing.T) {
	sitesOnly := identity.Principal{Permissions: []string{"sites.manage"}}
	if err := authorizeBatchSiteAction(sitesOnly, site.BatchActionRegenerateCNAME); !errors.Is(err, identity.ErrPermissionDenied) {
		t.Fatalf("sites-only CNAME regeneration error = %v, want permission denied", err)
	}
	if err := authorizeBatchSiteAction(sitesOnly, site.BatchActionEnable); err != nil {
		t.Fatalf("ordinary site action error = %v", err)
	}

	sitesAndDNS := identity.Principal{Permissions: []string{"sites.manage", "dns.manage"}}
	if err := authorizeBatchSiteAction(sitesAndDNS, site.BatchActionRegenerateCNAME); err != nil {
		t.Fatalf("authorized CNAME regeneration error = %v", err)
	}
}

func TestCNAMEBatchPermissionCheckPrecedesMutation(t *testing.T) {
	raw, err := os.ReadFile("sites.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	guard := strings.Index(source, "authorizeBatchSiteAction(principal, body.Action)")
	mutation := strings.Index(source, "s.sites.BatchAction(r.Context()")
	if guard < 0 || mutation < 0 || guard > mutation {
		t.Fatalf("CNAME batch permission guard must precede persistent BatchAction call: guard=%d mutation=%d", guard, mutation)
	}
}

// Protocols keys left out keep each site's value;
// tls_prefer_server_ciphers null is "by the cipher preset" again.
func TestBatchSiteProtocolsDecoding(t *testing.T) {
	var body batchSiteActionRequest
	if err := json.Unmarshal([]byte(`{"action":"set_protocols","items":[],"protocols":{"http3_enabled":false,"tls_prefer_server_ciphers":null}}`), &body); err != nil {
		t.Fatal(err)
	}
	fields := body.Protocols.fields()
	if fields == nil || fields.HTTP2Enabled != nil || fields.HTTP3Enabled == nil || *fields.HTTP3Enabled ||
		fields.TLSPreferServerCiphers != nil || !fields.TLSPreferServerCiphersReset {
		t.Fatalf("protocols = %+v", fields)
	}
	if err := json.Unmarshal([]byte(`{"action":"set_protocols","items":[],"protocols":{"http2_enabled":true}}`), &body); err != nil {
		t.Fatal(err)
	}
	if fields := body.Protocols.fields(); fields.TLSPreferServerCiphersReset || fields.HTTP2Enabled == nil || !*fields.HTTP2Enabled {
		t.Fatalf("omitted prefer = %+v", fields)
	}
	if err := json.Unmarshal([]byte(`{"protocols":{"http4_enabled":true}}`), &body); err == nil {
		t.Fatal("unknown protocol key accepted")
	}
	var none batchSiteActionRequest
	if none.Protocols.fields() != nil {
		t.Fatal("no protocols must stay nil")
	}
}
