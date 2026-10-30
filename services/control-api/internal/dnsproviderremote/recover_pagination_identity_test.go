package dnsproviderremote

import (
	"fmt"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/acmeworker"
)

type recoveryIdentityScenario string

const (
	recoveryIdentityCrossPage    recoveryIdentityScenario = "cross-page duplicate"
	recoveryIdentityPayloadDrift recoveryIdentityScenario = "payload drift"
	recoveryIdentityZoneDrift    recoveryIdentityScenario = "zone drift"
	recoveryIdentityPageLocal    recoveryIdentityScenario = "page-local duplicate"
	recoveryIdentityZero         recoveryIdentityScenario = "stable zero"
	recoveryIdentityOne          recoveryIdentityScenario = "stable one"
	recoveryIdentityConflict     recoveryIdentityScenario = "distinct exact conflict"
	recoveryIdentityInvalidLater recoveryIdentityScenario = "duplicate with invalid later candidate"
	recoveryIdentityInvalidLocal recoveryIdentityScenario = "page-local duplicate invalid id"
)

func TestRecoverTXTPaginationRejectsDuplicateRecordIdentity(t *testing.T) {
	providers := []string{
		providerCloudflare, providerAliyun, providerDNSPodCN, providerDNSCom, providerDNSLA,
	}
	for _, provider := range providers {
		rejections := []recoveryIdentityScenario{
			recoveryIdentityCrossPage, recoveryIdentityPayloadDrift, recoveryIdentityPageLocal,
			recoveryIdentityConflict,
		}
		if provider == providerCloudflare || provider == providerDNSCom || provider == providerDNSLA {
			rejections = append(rejections, recoveryIdentityZoneDrift)
		}
		for _, scenario := range rejections {
			t.Run(provider+"/"+string(scenario), func(t *testing.T) {
				adapter, source, fixture := newRecoveryIdentityAdapter(t, provider, scenario)
				handle, found, err := adapter.RecoverTXT(t.Context(), testChallenge())
				if !isCode(err, CodeRecordMismatch) || found || handle != (acmeworker.RemoteTXTHandle{}) {
					t.Fatalf("RecoverTXT() = (%+v, %t, %v)", handle, found, err)
				}
				if fixture.mutations != 0 {
					t.Fatalf("provider mutations = %d", fixture.mutations)
				}
				if !source.credentialsCleared() {
					t.Fatal("recovery retained decrypted credentials")
				}
			})
		}

		for _, scenario := range []recoveryIdentityScenario{
			recoveryIdentityInvalidLater, recoveryIdentityInvalidLocal,
		} {
			t.Run(provider+"/"+string(scenario), func(t *testing.T) {
				adapter, source, fixture := newRecoveryIdentityAdapter(t, provider, scenario)
				handle, found, err := adapter.RecoverTXT(t.Context(), testChallenge())
				if !isCode(err, CodeInvalidResponse) || found || handle != (acmeworker.RemoteTXTHandle{}) {
					t.Fatalf("RecoverTXT() = (%+v, %t, %v)", handle, found, err)
				}
				if fixture.mutations != 0 {
					t.Fatalf("provider mutations = %d", fixture.mutations)
				}
				if !source.credentialsCleared() {
					t.Fatal("recovery retained decrypted credentials")
				}
			})
		}

		for _, scenario := range []recoveryIdentityScenario{recoveryIdentityZero, recoveryIdentityOne} {
			t.Run(provider+"/"+string(scenario), func(t *testing.T) {
				adapter, source, fixture := newRecoveryIdentityAdapter(t, provider, scenario)
				handle, found, err := adapter.RecoverTXT(t.Context(), testChallenge())
				if err != nil {
					t.Fatalf("RecoverTXT() error = %v", err)
				}
				if scenario == recoveryIdentityZero {
					if found || handle != (acmeworker.RemoteTXTHandle{}) {
						t.Fatalf("zero match = (%+v, %t)", handle, found)
					}
				} else {
					if !found {
						t.Fatal("unique exact match was not found")
					}
					requireHandle(t, handle, provider, recoveryZoneID(provider), "target")
				}
				if fixture.pageCalls != 2 || fixture.mutations != 0 {
					t.Fatalf("page calls=%d mutations=%d", fixture.pageCalls, fixture.mutations)
				}
				if !source.credentialsCleared() {
					t.Fatal("recovery retained decrypted credentials")
				}
			})
		}
	}
}

type recoveryIdentityFixture struct {
	t         *testing.T
	provider  string
	pages     map[int][]map[string]any
	pageCalls int
	mutations int
}

func newRecoveryIdentityAdapter(t *testing.T, provider string,
	scenario recoveryIdentityScenario) (*Adapter, *staticSource, *recoveryIdentityFixture) {
	t.Helper()
	fixture := &recoveryIdentityFixture{
		t: t, provider: provider, pages: recoveryIdentityPages(provider, scenario),
	}
	adapter, source := newProviderTestAdapter(t, recoveryIdentityConfig(provider), fixture, time.Second)
	return adapter, source, fixture
}

func recoveryIdentityPages(provider string, scenario recoveryIdentityScenario) map[int][]map[string]any {
	pages := map[int][]map[string]any{
		1: make([]map[string]any, 0, recoveryPageSize),
		2: {recoveryProviderRecord(provider, "unrelated-100", "unrelated-value-100")},
	}
	for index := 0; index < recoveryPageSize; index++ {
		pages[1] = append(pages[1], recoveryProviderRecord(provider,
			fmt.Sprintf("unrelated-%d", index), fmt.Sprintf("unrelated-value-%d", index)))
	}
	switch scenario {
	case recoveryIdentityCrossPage:
		pages[1][0] = recoveryProviderRecord(provider, "repeated", "unrelated-stable")
		pages[2][0] = recoveryProviderRecord(provider, "repeated", "unrelated-stable")
	case recoveryIdentityPayloadDrift:
		pages[1][0] = recoveryProviderRecord(provider, "repeated", "unrelated-before")
		pages[2][0] = recoveryProviderRecord(provider, "repeated", "unrelated-after")
	case recoveryIdentityZoneDrift:
		pages[1][0] = recoveryProviderRecord(provider, "repeated", "unrelated-stable")
		pages[2][0] = recoveryProviderRecord(provider, "repeated", "unrelated-stable")
		switch provider {
		case providerCloudflare:
			pages[2][0]["zone_id"] = "zone-cf-drift"
		case providerDNSCom:
			pages[2][0]["domain_id"] = "zone-dnscom-drift"
		case providerDNSLA:
			pages[2][0]["domainId"] = "zone-dnsla-drift"
		}
	case recoveryIdentityPageLocal:
		pages[1][0] = recoveryProviderRecord(provider, "repeated", "unrelated-stable")
		pages[1][1] = recoveryProviderRecord(provider, "repeated", "unrelated-stable")
	case recoveryIdentityOne:
		pages[2][0] = recoveryProviderRecord(provider, "target", testValue)
	case recoveryIdentityConflict:
		pages[1][0] = recoveryProviderRecord(provider, "target-one", testValue)
		pages[2][0] = recoveryProviderRecord(provider, "target-two", testValue)
	case recoveryIdentityInvalidLater:
		pages[1][0] = recoveryProviderRecord(provider, "repeated", "unrelated-stable")
		pages[2][0] = recoveryProviderRecord(provider, "repeated", "unrelated-stable")
		recoveryIdentityInvalidOwner(provider, pages[2][0])
	case recoveryIdentityInvalidLocal:
		pages[1][0] = recoveryProviderRecord(provider, "", "unrelated-stable")
		pages[1][1] = recoveryProviderRecord(provider, "", "unrelated-stable")
	}
	return pages
}

func recoveryIdentityInvalidOwner(provider string, record map[string]any) {
	switch provider {
	case providerCloudflare:
		record["name"] = "invalid owner"
	case providerAliyun:
		record["RR"] = "invalid owner"
	case providerDNSPodCN:
		record["name"] = "invalid owner"
	case providerDNSCom:
		record["record"] = "invalid owner"
	case providerDNSLA:
		record["host"] = "invalid owner"
	}
}

func recoveryIdentityConfig(provider string) ProviderConfig {
	config := ProviderConfig{ProviderType: provider, ZoneName: testZone}
	switch provider {
	case providerCloudflare:
		config.Credentials = map[string]string{"api_token": "recovery-token"}
	case providerAliyun:
		config.Credentials = map[string]string{
			"access_key_id": "recovery-key", "access_key_secret": "recovery-secret",
		}
	case providerDNSPodCN:
		config.Credentials = map[string]string{"dp_id": "12345", "dp_key": "recovery-secret"}
	case providerDNSCom:
		config.Credentials = map[string]string{"api_key": "recovery-key", "api_secret": "recovery-secret"}
	case providerDNSLA:
		config.Credentials = map[string]string{"api_id": "recovery-id", "api_secret": "recovery-secret"}
	}
	return config
}

func (fixture *recoveryIdentityFixture) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if fixture.serveIdentityLookup(writer, request) {
		return
	}
	page, ok := fixture.identityPage(request)
	if !ok || page < 1 || page > 2 {
		fixture.mutations++
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	fixture.pageCalls++
	fixture.writeIdentityPage(writer, page, fixture.pages[page])
}

func (fixture *recoveryIdentityFixture) serveIdentityLookup(writer http.ResponseWriter, request *http.Request) bool {
	switch fixture.provider {
	case providerCloudflare:
		if request.Method == http.MethodGet && request.URL.Path == "/zones" {
			writeTestJSON(fixture.t, writer, map[string]any{"success": true, "result": []any{
				map[string]any{"id": "zone-cf", "name": testZone},
			}})
			return true
		}
	case providerDNSLA:
		if request.Method == http.MethodGet && request.URL.Path == "/api/domain" {
			writeTestJSON(fixture.t, writer, map[string]any{"code": 200, "data": map[string]any{
				"id": "zone-dnsla", "domain": testZone,
			}})
			return true
		}
	}
	return false
}

func (fixture *recoveryIdentityFixture) identityPage(request *http.Request) (int, bool) {
	switch fixture.provider {
	case providerCloudflare:
		if request.Method == http.MethodGet && request.URL.Path == "/zones/zone-cf/dns_records" {
			page, _ := strconv.Atoi(request.URL.Query().Get("page"))
			return page, true
		}
	case providerAliyun:
		if request.Method == http.MethodGet && request.URL.Path == "/" &&
			request.URL.Query().Get("Action") == "DescribeDomainRecords" {
			page, _ := strconv.Atoi(request.URL.Query().Get("PageNumber"))
			return page, true
		}
	case providerDNSPodCN:
		if request.Method == http.MethodPost && request.URL.Path == "/Record.List" {
			_ = request.ParseForm()
			offset, _ := strconv.Atoi(request.Form.Get("offset"))
			return offset/recoveryPageSize + 1, true
		}
	case providerDNSCom:
		if request.Method == http.MethodGet && request.URL.Path == "/api/record/lists/" {
			page, _ := strconv.Atoi(request.URL.Query().Get("page"))
			return page, true
		}
	case providerDNSLA:
		if request.Method == http.MethodGet && request.URL.Path == "/api/recordList" {
			page, _ := strconv.Atoi(request.URL.Query().Get("pageIndex"))
			return page, true
		}
	}
	return 0, false
}

func (fixture *recoveryIdentityFixture) writeIdentityPage(writer http.ResponseWriter, page int,
	records []map[string]any) {
	const total = recoveryPageSize + 1
	switch fixture.provider {
	case providerCloudflare:
		writeTestJSON(fixture.t, writer, map[string]any{
			"success": true, "result": records,
			"result_info": map[string]any{
				"page": page, "per_page": recoveryPageSize, "count": len(records),
				"total_count": total, "total_pages": 2,
			},
		})
	case providerAliyun:
		writeTestJSON(fixture.t, writer, map[string]any{
			"RequestId": "request-list", "TotalCount": total,
			"PageNumber": page, "PageSize": recoveryPageSize,
			"DomainRecords": map[string]any{"Record": records},
		})
	case providerDNSPodCN:
		writeTestJSON(fixture.t, writer, map[string]any{
			"status": map[string]any{"code": "1"}, "records": records,
			"info": map[string]any{"records_num": strconv.Itoa(len(records))},
		})
	case providerDNSCom:
		writeTestJSON(fixture.t, writer, map[string]any{"code": 0, "data": map[string]any{
			"total": total, "data": records,
		}})
	case providerDNSLA:
		writeTestJSON(fixture.t, writer, map[string]any{"code": 200, "data": map[string]any{
			"total": total, "results": records,
		}})
	}
}
