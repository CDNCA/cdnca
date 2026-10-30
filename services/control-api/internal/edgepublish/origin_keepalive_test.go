package edgepublish

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

// NF01: a site with origin keepalive publishes the idle timeout on its origin
// pool. Like every document it needs the 1.0.35 baseline (site_runtime 6);
// older agents are refused with the baseline reason instead of silently
// dropping the setting.
func TestSiteRuntimeV2OriginKeepaliveAtTheBaseline(t *testing.T) {
	idle := 50000
	fact := siteFact{
		id: uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7103"), revision: 9, domain: "keep.example.test",
		httpPorts: []string{"80"}, balance: "round_robin", failoverTries: 1,
		connectTimeoutMS: 3000, readTimeoutMS: 30000, keepaliveIdleTimeoutMS: &idle,
		origins: []snapshotOrigin{{Host: "192.0.2.10", Port: 80, Weight: 100}},
	}
	site, _, err := compileSiteRuntimeV2SiteFact(nil, nil, uuid.New(), fact, time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if idle := site.OriginPools[0].KeepaliveIdleTimeoutMS; idle == nil || *idle != 50000 {
		t.Fatalf("pool keepalive = %v, want 50000", idle)
	}
	document := siteRuntimeV2Document{
		Schema: siteRuntimeV2Schema, ConfigurationScopeID: "018f47a2-5b9c-7d31-8a60-104c9c0b7101", SourceRevision: 3,
		ConfigVersionID: "018f47a2-5b9c-7d31-8a60-104c9c0b7102", Sites: []siteRuntimeV2Site{site},
		RequiredCapabilities: []siteRuntimeV2Capability{{"http1", 1}, {"ipv4", 1}, {"ipv6", 1}, {"site_runtime", 5}, {"websocket", 1}},
	}
	raw, _ := json.Marshal(document)
	if _, _, _, _, err := compileSiteRuntimeV2Document(raw); err == nil {
		t.Fatal("keepalive document declaring site_runtime v5 was accepted")
	}
	document.RequiredCapabilities[3].APIVersion = edgeconfig.MinSiteRuntimeVersion
	raw, _ = json.Marshal(document)
	_, _, capabilities, _, err := compileSiteRuntimeV2Document(raw)
	if err != nil {
		t.Fatalf("baseline keepalive document rejected: %v", err)
	}
	if !strings.Contains(string(raw), `"keepalive_idle_timeout_ms":50000`) {
		t.Fatal("keepalive is not in the published document")
	}
	refusal := targetCapabilityError(uuid.New(), "1.0.34", capabilities, []*agentv1.Capability{
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME, ApiVersion: 5},
	})
	if refusal == nil || !strings.Contains(refusal.Error(), "1.0.35") {
		t.Fatalf("v5 agent refusal = %v", refusal)
	}

	// Off is published as 0; the node default (nil fact) is not published.
	off := 0
	fact.keepaliveIdleTimeoutMS = &off
	site, _, _ = compileSiteRuntimeV2SiteFact(nil, nil, uuid.New(), fact, time.Unix(1, 0).UTC())
	if idle := site.OriginPools[0].KeepaliveIdleTimeoutMS; idle == nil || *idle != 0 {
		t.Fatalf("keepalive off publishes %v, want 0", idle)
	}
	fact.keepaliveIdleTimeoutMS = nil
	site, _, _ = compileSiteRuntimeV2SiteFact(nil, nil, uuid.New(), fact, time.Unix(1, 0).UTC())
	if site.OriginPools[0].KeepaliveIdleTimeoutMS != nil {
		t.Fatal("default keepalive is published; it would override the node default for every site")
	}
}
