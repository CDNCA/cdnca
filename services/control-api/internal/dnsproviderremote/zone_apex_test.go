package dnsproviderremote

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
)

// retest-n1: the platform CNAME zone cdn.868yun.com is a subdomain of the
// DNSPod-hosted 868yun.com. The hosted apex is the longest listed domain the
// zone equals or ends with "."+domain.
func TestLongestHostedApexPicksMostSpecificCoveringDomain(t *testing.T) {
	for _, test := range []struct {
		zone    string
		domains []string
		want    string
	}{
		{"cdn.868yun.com", []string{"868yun.com", "other.com"}, "868yun.com"},
		{"cdn.868yun.com", []string{"868yun.com", "cdn.868yun.com"}, "cdn.868yun.com"},
		{"868yun.com", []string{"868yun.com."}, "868yun.com"},
		{"a.cdn.868yun.com", []string{"868YUN.com", "cdn.868yun.com"}, "cdn.868yun.com"},
	} {
		if got, err := longestHostedApex(test.zone, test.domains); err != nil || got != test.want {
			t.Errorf("longestHostedApex(%q, %v) = %q, %v; want %q", test.zone, test.domains, got, err, test.want)
		}
	}
	for _, domains := range [][]string{nil, {"x868yun.com"}, {"yun.com.cn"}, {"a.cdn.868yun.com"}} {
		_, err := longestHostedApex("cdn.868yun.com", domains)
		assertRemoteError(t, err, CodeZoneNotHosted)
	}
}

// Each provider's domain list is read and the apex found; the zone itself
// hosted keeps working (compatible case); nothing matching is
// dns_zone_not_hosted.
func TestResolveZoneApexListsEveryProviderDomains(t *testing.T) {
	for _, test := range []struct {
		provider    string
		credentials map[string]string
		path        string
		body        any
	}{
		{providerCloudflare, map[string]string{"api_token": "cloudflare-token-123"}, "/zones",
			map[string]any{"success": true, "result": []any{map[string]any{"id": "z1", "name": "868yun.com"}},
				"result_info": map[string]any{"page": 1, "per_page": 50, "count": 1, "total_count": 1, "total_pages": 1}}},
		{providerAliyun, map[string]string{"access_key_id": "LTAIexample", "access_key_secret": "aliyun-secret"}, "/",
			map[string]any{"RequestId": "r", "TotalCount": 1, "Domains": map[string]any{"Domain": []any{
				map[string]any{"DomainName": "868yun.com"}}}}},
		{providerHuawei, map[string]string{"access_key": "HUAWEIAK", "secret_key": "huawei-secret", "region": "cn-north-4",
			"project_id": "0123456789abcdef0123456789abcdef"}, "/v2/zones",
			map[string]any{"zones": []any{map[string]any{"id": "z1", "name": "868yun.com."}},
				"metadata": map[string]any{"total_count": 1}, "links": map[string]any{"self": "x"}}},
		{providerDNSPodCN, map[string]string{"dp_id": "123456", "dp_key": "dnspod-secret"}, "/Domain.List",
			map[string]any{"status": map[string]any{"code": "1"}, "info": map[string]any{"domain_total": "1"},
				"domains": []any{map[string]any{"id": 1, "name": "868yun.com"}}}},
		{providerDNSCom, map[string]string{"api_key": "c7722149110b7492a2e5cf1d8f3f966b", "api_secret": "ecb4ff0e877a83292b9f35067e9ae673"},
			"/api/domain/lists/", map[string]any{"code": 0, "data": map[string]any{"total": 1,
				"data": []any{map[string]any{"domain_id": 1, "domain": "868yun.com"}}}}},
		{providerDNSLA, map[string]string{"api_id": "dnsla-id", "api_secret": "dnsla-secret"}, "/api/domainList",
			map[string]any{"code": 200, "data": map[string]any{"total": 1,
				"results": []any{map[string]any{"id": "1", "domain": "868yun.com."}}}}},
		{providerNameCom, map[string]string{"username": "namecom-user", "api_token": "namecom-token"}, "/core/v1/domains",
			map[string]any{"domains": []any{map[string]any{"domainName": "868yun.com"}}}},
	} {
		t.Run(test.provider, func(t *testing.T) {
			var paths []string
			adapter, _ := newProviderTestAdapter(t, ProviderConfig{ProviderType: test.provider, ZoneName: testZone,
				Credentials: test.credentials}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				paths = append(paths, r.URL.Path)
				if test.provider == providerDNSCom || test.provider == providerDNSLA {
					w.Header().Set("Content-Type", "application/json")
				}
				writeTestJSON(t, w, test.body)
			}), time.Second)
			remote := &providerReconcileRemote{adapter: adapter}
			for zone, want := range map[string]string{"cdn.868yun.com": "868yun.com", "868yun.com": "868yun.com"} {
				got, err := remote.ResolveZoneApex(context.Background(), test.provider, test.credentials, zone)
				if err != nil || got != want {
					t.Fatalf("ResolveZoneApex(%q) = %q, %v; want %q", zone, got, err, want)
				}
			}
			_, err := remote.ResolveZoneApex(context.Background(), test.provider, test.credentials, "cdn.other.com")
			assertRemoteError(t, err, CodeZoneNotHosted)
			for _, path := range paths {
				if path != test.path {
					t.Fatalf("domain list path = %q, want %q", path, test.path)
				}
			}
		})
	}
}

func TestResolveZoneApexDNSPodEmptyAccountIsNotHosted(t *testing.T) {
	credentials := map[string]string{"dp_id": "123456", "dp_key": "dnspod-secret"}
	adapter, _ := newProviderTestAdapter(t, ProviderConfig{ProviderType: providerDNSPodCN, ZoneName: testZone,
		Credentials: credentials}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(t, w, map[string]any{"status": map[string]any{"code": "9", "message": "No domains"}})
	}), time.Second)
	_, err := (&providerReconcileRemote{adapter: adapter}).ResolveZoneApex(context.Background(), providerDNSPodCN,
		credentials, "cdn.868yun.com")
	assertRemoteError(t, err, CodeZoneNotHosted)
}

// Record reads and writes of the subdomain zone call DNSPod with the hosted
// apex and an apex-relative record name (5ksukk1m.cdn); a zone that is the
// hosted domain itself keeps domain=zone, sub_domain=label.
func TestSubdomainZoneCallsProviderWithApexAndRelativeName(t *testing.T) {
	for _, test := range []struct {
		zone, apex, owner, domain, subDomain string
	}{
		{"cdn.868yun.com", "868yun.com", "5ksukk1m.cdn.868yun.com.", "868yun.com", "5ksukk1m.cdn"},
		{"868yun.com", "", "5ksukk1m.868yun.com.", "868yun.com", "5ksukk1m"},
		{"868yun.com", "868yun.com", "5ksukk1m.868yun.com.", "868yun.com", "5ksukk1m"},
	} {
		t.Run(test.zone+"/"+test.apex, func(t *testing.T) {
			var forms []url.Values
			config := ProviderConfig{ProviderType: providerDNSPodCN, ZoneName: test.zone, ProviderZoneName: test.apex,
				Credentials: map[string]string{"dp_id": "123456", "dp_key": "dnspod-secret"}}
			adapter, _ := newProviderTestAdapter(t, config, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, _ := io.ReadAll(r.Body)
				form, _ := url.ParseQuery(string(raw))
				forms = append(forms, form)
				switch r.URL.Path {
				case "/Record.List":
					writeTestJSON(t, w, map[string]any{"status": map[string]any{"code": "1"}, "records": []any{
						map[string]any{"id": "7", "name": test.subDomain, "type": "CNAME",
							"value": "edge.example.net.", "line": "默认", "ttl": "600"}}})
				case "/Record.Create":
					writeTestJSON(t, w, map[string]any{"status": map[string]any{"code": "1"},
						"record": map[string]any{"id": "8", "name": test.subDomain, "status": "enable"}})
				default:
					t.Errorf("unexpected path %s", r.URL.Path)
				}
			}), time.Second)
			remote := &providerReconcileRemote{adapter: adapter}
			records, err := remote.ListZoneRecords(context.Background(), completeTestConfig(config), test.owner)
			if err != nil || len(records) != 1 || records[0].Name != test.owner {
				t.Fatalf("ListZoneRecords = %+v, %v", records, err)
			}
			if _, err := remote.Mutate(context.Background(), completeTestConfig(config), dnscheck.ProviderOperation{
				Action: dnscheck.ProviderCreate, Name: test.owner, Type: dnscheck.RecordCNAME,
				Value: "edge.example.net.", TTL: 600}); err != nil {
				t.Fatalf("Mutate create: %v", err)
			}
			for index, form := range forms {
				if form.Get("domain") != test.domain || form.Get("sub_domain") != test.subDomain {
					t.Fatalf("call %d domain=%q sub_domain=%q; want %q %q", index, form.Get("domain"),
						form.Get("sub_domain"), test.domain, test.subDomain)
				}
			}
		})
	}
}

// An owner outside the CNAME zone stays invalid even when it lies under
// the hosted apex, and an apex not covering the zone is rejected.
func TestValidateConfigKeepsZoneBoundaryWithApex(t *testing.T) {
	config := completeTestConfig(ProviderConfig{ProviderType: providerDNSPodCN, ZoneName: "cdn.868yun.com",
		ProviderZoneName: "868yun.com", Credentials: map[string]string{"dp_id": "123456", "dp_key": "dnspod-secret"}})
	if validated, relative, err := validateConfig(config, "a.cdn.868yun.com."); err != nil ||
		validated.ZoneName != "868yun.com" || relative != "a.cdn" {
		t.Fatalf("validateConfig = %q %q %v", validated.ZoneName, relative, err)
	}
	_, _, err := validateConfig(config, "www.868yun.com.")
	assertRemoteError(t, err, CodeInvalidInput)
	config.ProviderZoneName = "other.com"
	_, _, err = validateConfig(config, "a.cdn.868yun.com.")
	assertRemoteError(t, err, CodeInvalidInput)
}
