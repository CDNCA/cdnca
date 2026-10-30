package dnsproviderremote

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
)

// recordListFixture serves a zone of 100 filler A records (page 1) and, on
// page 2, the www target A record plus a TXT record (never listed).
type recordListFixture struct {
	reconcileHTTPFixture
	filters []string
}

func (fixture *recordListFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if fixture.writeZoneResponse(w, r) {
		return
	}
	_ = r.ParseForm()
	page := 1
	switch fixture.provider {
	case providerCloudflare:
		fmt.Sscan(r.Form.Get("page"), &page)
		fixture.filters = append(fixture.filters, r.Form.Get("name"))
	case providerAliyun:
		fmt.Sscan(r.Form.Get("PageNumber"), &page)
		fixture.filters = append(fixture.filters, r.Form.Get("RRKeyWord"))
	case providerHuawei:
		var offset int
		fmt.Sscan(r.Form.Get("offset"), &offset)
		page = offset/recoveryPageSize + 1
		fixture.filters = append(fixture.filters, r.Form.Get("name"))
	case providerDNSPodCN:
		var offset int
		fmt.Sscan(r.Form.Get("offset"), &offset)
		page = offset/recoveryPageSize + 1
		fixture.filters = append(fixture.filters, r.Form.Get("sub_domain"))
	case providerDNSCom:
		fmt.Sscan(r.Form.Get("page"), &page)
		fixture.filters = append(fixture.filters, r.Form.Get("record"))
	case providerDNSLA:
		fmt.Sscan(r.Form.Get("pageIndex"), &page)
		fixture.filters = append(fixture.filters, r.Form.Get("host"))
	}
	owner := len(fixture.filters) > 0 && fixture.filters[len(fixture.filters)-1] != ""
	var records []map[string]any
	total := recoveryPageSize + 2
	switch {
	case owner:
		records, total = []map[string]any{fixture.record("target", 0, true, false), fixture.txt()}, 2
	case page == 1:
		for index := 0; index < recoveryPageSize; index++ {
			records = append(records, fixture.record(fmt.Sprintf("filler-%d", index), index+1, false, false))
		}
	default:
		records = []map[string]any{fixture.record("target", 0, true, false), fixture.txt()}
	}
	fixture.writeListResponse(w, page, total, records, true)
}

func (fixture *recordListFixture) txt() map[string]any {
	record := reconcileHTTPRecordForType(fixture.provider, "txt-1", 0, true, false, "TXT", "v=spf1 -all")
	if fixture.provider == providerDNSLA {
		record["type"] = 16
	}
	return record
}

func TestListZoneRecordsAcrossProviders(t *testing.T) {
	for _, provider := range []string{providerCloudflare, providerAliyun, providerHuawei, providerDNSPodCN, providerDNSCom, providerDNSLA} {
		t.Run(provider, func(t *testing.T) {
			fixture := &recordListFixture{reconcileHTTPFixture: reconcileHTTPFixture{t: t, provider: provider}}
			config := reconcileHTTPProviderConfig(provider)
			adapter, _ := newProviderTestAdapter(t, config, fixture, time.Second)
			remote := &providerReconcileRemote{adapter: adapter}
			config = completeTestConfig(config)

			zone, err := remote.ListZoneRecords(t.Context(), config, "")
			if err != nil {
				t.Fatalf("zone-wide ListZoneRecords() error = %v", err)
			}
			if len(zone) != recoveryPageSize+1 {
				t.Fatalf("zone-wide records = %d, want %d", len(zone), recoveryPageSize+1)
			}
			for _, record := range zone {
				if record.Type != dnscheck.RecordA || record.TTL != 300 || record.ID == "" {
					t.Fatalf("zone record = %+v", record)
				}
			}
			if fixture.filters[0] != "" {
				t.Fatalf("zone-wide listing sent an owner filter %q", fixture.filters[0])
			}

			fixture.filters = nil
			owned, err := remote.ListZoneRecords(t.Context(), config, "www."+testZone+".")
			if err != nil {
				t.Fatalf("owner ListZoneRecords() error = %v", err)
			}
			if len(owned) != 1 || owned[0].ID != "target" || owned[0].Name != "www."+testZone+"." || owned[0].Value != "192.0.2.10" {
				t.Fatalf("owner records = %+v", owned)
			}
			if len(fixture.filters) == 0 || fixture.filters[0] == "" {
				t.Fatalf("owner listing sent no filter: %v", fixture.filters)
			}
		})
	}
}

func TestListZoneRecordsRejectsForeignOwner(t *testing.T) {
	remote := &providerReconcileRemote{adapter: &Adapter{}}
	config := completeTestConfig(reconcileHTTPProviderConfig(providerCloudflare))
	if _, err := remote.ListZoneRecords(t.Context(), config, "www.other.test."); err == nil {
		t.Fatal("foreign owner was accepted")
	}
}
