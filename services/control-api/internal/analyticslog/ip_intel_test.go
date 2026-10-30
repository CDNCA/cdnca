package analyticslog

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/ipintel"
)

func ipIntelTestTable(t *testing.T) *ipIntelTable {
	t.Helper()
	generated := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	fact := func(prefix string, tags uint64, asn uint32, country string, province, city uint32) ipintel.Fact {
		return ipintel.Fact{Prefix: netip.MustParsePrefix(prefix), Tags: tags, ASN: asn, Country: country,
			Province: province, City: city}
	}
	artifact, err := ipintel.Build(ipintel.BuildInput{Revision: 9, BuildID: "ipintel-test-0009", GeneratedAt: generated,
		DataUpdatedAt: generated.Add(-time.Hour), StaleAfter: generated.Add(30 * 24 * time.Hour),
		Sources: []ipintel.Source{{ID: "fixture", Name: "fixture", URL: "https://example.test", License: "CC0-1.0", Ref: "1", Role: "test"}},
		Facts: []ipintel.Fact{
			fact("1.0.0.0/24", ipintel.TagCNTelecom|ipintel.TagCNUnicom, 4134, "CN", 440000, 440300),
			fact("8.8.8.0/24", ipintel.TagIDCGlobal, 15169, "US", 0, 0),
			fact("2400:3200::/32", ipintel.TagIDCCN, 37963, "CN", 330000, 0),
		},
		Regions: map[uint32]string{440000: "广东省", 440300: "深圳市", 330000: "浙江省"}})
	if err != nil {
		t.Fatal(err)
	}
	table, err := ipintel.Open(artifact.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return &ipIntelTable{revision: 9, table: table}
}

// G3-d: log rows show the client address' carrier (lowest carrier bit),
// IDC tag, ASN, country and province / city names from the library.
func TestIPIntelTableLookup(t *testing.T) {
	library := ipIntelTestTable(t)
	got := library.lookupAll([]string{"1.0.0.7", "8.8.8.8", "2400:3200::1", "::ffff:1.0.0.9", "203.0.113.1", "bogus", "1.0.0.7"})
	if info := got["1.0.0.7"]; info == nil || *info != (IPInfo{Carrier: "carrier:cn-telecom", ASN: 4134, Country: "CN",
		Province: "440000", ProvinceName: "广东省", City: "440300", CityName: "深圳市", Revision: 9}) {
		t.Fatalf("1.0.0.7 = %+v", info)
	}
	if info := got["8.8.8.8"]; info == nil || info.IDC != "idc:global" || info.ASN != 15169 || info.Country != "US" || info.Carrier != "" {
		t.Fatalf("8.8.8.8 = %+v", info)
	}
	if info := got["2400:3200::1"]; info == nil || info.IDC != "idc:cn" || info.ProvinceName != "浙江省" || info.City != "" {
		t.Fatalf("2400:3200::1 = %+v", info)
	}
	if info := got["::ffff:1.0.0.9"]; info == nil || info.Carrier != "carrier:cn-telecom" {
		t.Fatalf("IPv4-mapped = %+v", info)
	}
	if got["203.0.113.1"] != nil || got["bogus"] != nil {
		t.Fatalf("unknown addresses answered: %+v %+v", got["203.0.113.1"], got["bogus"])
	}
	var none *ipIntelTable
	if none.lookup("1.0.0.7") != nil {
		t.Fatal("no library answered")
	}
}

type fixedIPIntel struct{ library *ipIntelTable }

func (lookup fixedIPIntel) Lookup(_ context.Context, addresses []string) map[string]*IPInfo {
	return lookup.library.lookupAll(addresses)
}

func TestHandlerAddsIPIntelToAccessAndBlockRows(t *testing.T) {
	now := time.Date(2026, 10, 17, 4, 0, 0, 0, time.UTC)
	store := &recordingStore{
		accessPage: AccessPage{Items: []AccessLog{
			{EventID: "access-a", OccurredAt: now.Add(-time.Minute), SiteID: siteA, NodeID: nodeA, ConfigVersion: configA,
				Host: "example.test", URIPath: "/", ClientIP: "1.0.0.7", Method: "GET", Protocol: "HTTP/1.1", StatusCode: 200},
			{EventID: "access-b", OccurredAt: now.Add(-2 * time.Minute), SiteID: siteA, NodeID: nodeA, ConfigVersion: configA,
				Host: "example.test", URIPath: "/", ClientIP: "203.0.113.1", Method: "GET", Protocol: "HTTP/1.1", StatusCode: 200},
		}},
		blockPage: BlockEventPage{Items: []BlockEvent{{EventID: "block-a", OccurredAt: now.Add(-time.Minute), SiteID: siteA,
			NodeID: nodeA, ConfigVersion: configA, Host: "example.test", URIPath: "/", ClientIP: "8.8.8.8", EventType: "waf",
			Action: "block", Severity: "high", RuleID: "rule-a", StatusCode: 403}}},
	}
	actor := Actor{ScopeKind: "tenant", TenantID: tenantA, Permissions: []string{ReadPermission}}
	handler := newTestHandler(t, store, actor, HandlerConfig{})
	values := queryValues(now.Add(-time.Hour), now)

	// Without a lookup (no library) rows have no ip_intel.
	plain := doGET(handler, "/v1/analytics/logs/access", values)
	var plainBody struct{ Data []map[string]json.RawMessage }
	if plain.Code != http.StatusOK || json.Unmarshal(plain.Body.Bytes(), &plainBody) != nil || plainBody.Data[0]["ip_intel"] != nil {
		t.Fatalf("access without lookup = %d %s", plain.Code, plain.Body.String())
	}

	handler.SetIPIntelLookup(fixedIPIntel{library: ipIntelTestTable(t)})
	access := doGET(handler, "/v1/analytics/logs/access", values)
	var accessBody struct {
		Data []struct {
			ClientIP string  `json:"client_ip"`
			IPIntel  *IPInfo `json:"ip_intel"`
		}
	}
	if access.Code != http.StatusOK || json.Unmarshal(access.Body.Bytes(), &accessBody) != nil || len(accessBody.Data) != 2 ||
		accessBody.Data[0].IPIntel == nil || accessBody.Data[0].IPIntel.Carrier != "carrier:cn-telecom" ||
		accessBody.Data[0].IPIntel.CityName != "深圳市" || accessBody.Data[1].IPIntel != nil {
		t.Fatalf("access with lookup = %d %s", access.Code, access.Body.String())
	}
	block := doGET(handler, "/v1/analytics/logs/block-events", values)
	var blockBody struct {
		Data []struct {
			IPIntel *IPInfo `json:"ip_intel"`
		}
	}
	if block.Code != http.StatusOK || json.Unmarshal(block.Body.Bytes(), &blockBody) != nil || len(blockBody.Data) != 1 ||
		blockBody.Data[0].IPIntel == nil || blockBody.Data[0].IPIntel.IDC != "idc:global" || blockBody.Data[0].IPIntel.ASN != 15169 {
		t.Fatalf("block with lookup = %d %s", block.Code, block.Body.String())
	}
}
