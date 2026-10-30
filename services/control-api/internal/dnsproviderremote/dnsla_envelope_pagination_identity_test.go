package dnsproviderremote

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	dnsLAPaginationAPIID     = "dnsla-pagination-sensitive-id"
	dnsLAPaginationAPISecret = "dnsla-pagination-sensitive-secret"
	dnsLAPaginationZoneID    = "zone-dnsla-pagination"
	dnsLAPaginationTargetID  = "record-dnsla-pagination-target"
)

func TestDNSLALifecyclePaginatesExactRecordIdentity(t *testing.T) {
	fixture := &dnsLAPaginationLifecycleFixture{t: t}
	config := dnsLAPaginationConfig()
	adapter, source := newProviderTestAdapter(t, config, fixture, time.Second)

	handle, err := adapter.PresentTXT(t.Context(), testChallenge())
	if err != nil {
		t.Fatalf("PresentTXT() error=%v", err)
	}
	requireHandle(t, handle, providerDNSLA, dnsLAPaginationZoneID, dnsLAPaginationTargetID)
	if !source.credentialsCleared() {
		t.Fatal("present retained DNS.LA credentials")
	}
	if err := adapter.DeleteTXT(t.Context(), testChallengeWithHandle(handle)); err != nil {
		t.Fatalf("DeleteTXT() error=%v", err)
	}
	if !source.credentialsCleared() {
		t.Fatal("delete retained DNS.LA credentials")
	}

	wantPages := []int{1, 2, 1, 2, 1}
	if fmt.Sprint(fixture.pages) != fmt.Sprint(wantPages) || fixture.creates != 1 || fixture.deletes != 1 ||
		fixture.deletedID != dnsLAPaginationTargetID || fixture.unexpectedMutations != 0 {
		t.Fatalf("pages=%v creates=%d deletes=%d deleted=%q unexpected mutations=%d",
			fixture.pages, fixture.creates, fixture.deletes, fixture.deletedID, fixture.unexpectedMutations)
	}
}

func TestDNSLAExactRecordPaginationFailsClosedOnDrift(t *testing.T) {
	tests := []struct {
		name      string
		pageOne   []map[string]any
		pageTwo   []map[string]any
		totalOne  int
		totalTwo  int
		want      ErrorCode
		wantPages int
	}{
		{
			name: "total drift", pageOne: dnsLAPaginationRecords(100),
			pageTwo:  append(dnsLAPaginationRecordsFrom(100, 1), dnsLAPaginationRecord(dnsLAPaginationTargetID)),
			totalOne: 101, totalTwo: 102, want: CodeInvalidResponse, wantPages: 2,
		},
		{
			name: "short first page", pageOne: dnsLAPaginationRecords(99),
			totalOne: 101, want: CodeInvalidResponse, wantPages: 1,
		},
		{
			name: "second page identity drift", pageOne: dnsLAPaginationRecords(100),
			pageTwo:  []map[string]any{dnsLAPaginationRecordWith(dnsLAPaginationTargetID, "domainId", "zone-other")},
			totalOne: 101, totalTwo: 101, want: CodeInvalidResponse, wantPages: 2,
		},
		{
			name: "replayed page duplicates identity", pageOne: append(
				dnsLAPaginationRecords(99), dnsLAPaginationRecord(dnsLAPaginationTargetID)),
			pageTwo:  []map[string]any{dnsLAPaginationRecord(dnsLAPaginationTargetID)},
			totalOne: 101, totalTwo: 101, want: CodeRecordMismatch, wantPages: 2,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pages, mutations := 0, 0
			adapter, _ := newProviderTestAdapter(t, dnsLAPaginationConfig(), http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				assertDNSLAPaginationAuth(t, request)
				if request.Method != http.MethodGet || request.URL.Path != "/api/recordList" {
					mutations++
					writer.WriteHeader(http.StatusMethodNotAllowed)
					return
				}
				page, err := strconv.Atoi(request.URL.Query().Get("pageIndex"))
				if err != nil || page < 1 || page > 2 {
					t.Fatalf("page index=%q", request.URL.Query().Get("pageIndex"))
				}
				pages++
				records, total := test.pageOne, test.totalOne
				if page == 2 {
					records, total = test.pageTwo, test.totalTwo
				}
				writeTestJSON(t, writer, map[string]any{"code": 200, "data": map[string]any{
					"total": total, "results": records,
				}})
			}), time.Second)
			_, _, err := (&dnsLAProvider{adapter: adapter}).get(t.Context(), dnsLAPaginationConfig(), recordHandle{
				Provider: providerDNSLA, Zone: testZone, ZoneID: dnsLAPaginationZoneID,
				RecordID: dnsLAPaginationTargetID, Owner: testOwner,
			}, testValue)
			assertRemoteError(t, err, test.want)
			if pages != test.wantPages || mutations != 0 {
				t.Fatalf("pages=%d mutations=%d", pages, mutations)
			}
			assertDNSLAPaginationSecretSafe(t, err)
		})
	}
}

func TestDNSLAKnownEnvelopePrecedesGenericHTTPStatus(t *testing.T) {
	const providerMessage = "dnsla-sensitive-provider-message"
	methods := []string{http.MethodGet, http.MethodPost, http.MethodDelete}
	tests := []struct {
		name       string
		status     int
		body       string
		code       int
		retryAfter string
		want       ErrorCode
		temporary  bool
		wantRetry  time.Duration
	}{
		{name: "known internal over forbidden", status: http.StatusForbidden, code: 500, want: CodeUnavailable, temporary: true},
		{name: "known internal over rate status", status: http.StatusTooManyRequests, code: 500, retryAfter: "37", want: CodeUnavailable, temporary: true},
		{name: "unknown uses rate fallback", status: http.StatusTooManyRequests, code: 7777, retryAfter: "37", want: CodeRateLimited, temporary: true, wantRetry: 37 * time.Second},
		{name: "malformed uses forbidden fallback", status: http.StatusForbidden, body: "{", want: CodeCredentialsRejected},
	}
	for _, method := range methods {
		for _, test := range tests {
			t.Run(method+"/"+test.name, func(t *testing.T) {
				calls := 0
				adapter, _ := newProviderTestAdapter(t, dnsLAPaginationConfig(), http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
					calls++
					assertDNSLAPaginationAuth(t, request)
					if request.Method != method {
						t.Errorf("method=%s want=%s", request.Method, method)
					}
					writer.Header().Set("Retry-After", test.retryAfter)
					writer.WriteHeader(test.status)
					if test.body != "" {
						_, _ = writer.Write([]byte(test.body))
						return
					}
					writeTestJSON(t, writer, map[string]any{
						"code": test.code, "message": providerMessage, "data": nil,
					})
				}), time.Second)
				_, err := (&dnsLAProvider{adapter: adapter}).request(t.Context(), dnsLAPaginationConfig(),
					method, "/api/record", []byte(`{}`))
				var remote *Error
				if !errors.As(err, &remote) || remote.Code != test.want || remote.Temporary != test.temporary ||
					remote.RetryAfter != test.wantRetry {
					t.Fatalf("request() error=%+v want=%s temporary=%t retry=%s",
						err, test.want, test.temporary, test.wantRetry)
				}
				if calls != 1 {
					t.Fatalf("calls=%d", calls)
				}
				assertDNSLAPaginationSecretSafe(t, err)
			})
		}
	}
}

type dnsLAPaginationLifecycleFixture struct {
	t                   *testing.T
	created             bool
	creates             int
	deletes             int
	deletedID           string
	pages               []int
	unexpectedMutations int
}

func (fixture *dnsLAPaginationLifecycleFixture) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	assertDNSLAPaginationAuth(fixture.t, request)
	switch {
	case request.Method == http.MethodGet && request.URL.Path == "/api/domain":
		writeTestJSON(fixture.t, writer, map[string]any{"code": 200, "data": map[string]any{
			"id": dnsLAPaginationZoneID, "domain": testZone,
		}})
	case request.Method == http.MethodPost && request.URL.Path == "/api/record":
		fixture.creates++
		fixture.created = true
		writeTestJSON(fixture.t, writer, map[string]any{"code": 200, "data": map[string]any{
			"id": dnsLAPaginationTargetID,
		}})
	case request.Method == http.MethodGet && request.URL.Path == "/api/recordList":
		page, err := strconv.Atoi(request.URL.Query().Get("pageIndex"))
		wantData := ""
		if fixture.created {
			wantData = testValue
		}
		if err != nil || request.URL.Query().Get("pageSize") != strconv.Itoa(dnsLARecordPageSize) ||
			request.URL.Query().Get("domainId") != dnsLAPaginationZoneID ||
			request.URL.Query().Get("type") != "16" || request.URL.Query().Get("host") != testRelative ||
			request.URL.Query().Get("data") != wantData {
			fixture.t.Errorf("record-list query=%q", request.URL.RawQuery)
		}
		fixture.pages = append(fixture.pages, page)
		records := dnsLAPaginationRecords(100)
		if fixture.created && page == 2 {
			records = []map[string]any{dnsLAPaginationRecord(dnsLAPaginationTargetID)}
		}
		total := 100
		if fixture.created {
			total = 101
		}
		writeTestJSON(fixture.t, writer, map[string]any{"code": 200, "data": map[string]any{
			"total": total, "results": records,
		}})
	case request.Method == http.MethodDelete && request.URL.Path == "/api/record":
		fixture.deletes++
		fixture.deletedID = request.URL.Query().Get("id")
		fixture.created = false
		writeTestJSON(fixture.t, writer, map[string]any{"code": 200, "data": nil})
	default:
		if request.Method != http.MethodGet {
			fixture.unexpectedMutations++
		}
		fixture.t.Errorf("unexpected request %s %s", request.Method, request.URL.String())
		writer.WriteHeader(http.StatusNotFound)
	}
}

func dnsLAPaginationConfig() ProviderConfig {
	return ProviderConfig{
		ProviderType: providerDNSLA, ZoneName: testZone,
		Credentials: map[string]string{"api_id": dnsLAPaginationAPIID, "api_secret": dnsLAPaginationAPISecret},
	}
}

func dnsLAPaginationRecords(count int) []map[string]any {
	return dnsLAPaginationRecordsFrom(0, count)
}

func dnsLAPaginationRecordsFrom(start, count int) []map[string]any {
	records := make([]map[string]any, 0, count)
	for index := start; index < start+count; index++ {
		records = append(records, dnsLAPaginationRecord(fmt.Sprintf("record-dnsla-%03d", index)))
	}
	return records
}

func dnsLAPaginationRecord(id string) map[string]any {
	return map[string]any{
		"id": id, "domainId": dnsLAPaginationZoneID, "host": testRelative,
		"type": 16, "data": testValue, "ttl": 600,
	}
}

func dnsLAPaginationRecordWith(id, field string, value any) map[string]any {
	record := dnsLAPaginationRecord(id)
	record[field] = value
	return record
}

func assertDNSLAPaginationAuth(t *testing.T, request *http.Request) {
	t.Helper()
	username, password, ok := request.BasicAuth()
	if request.Host != "api.dns.la" || !ok || username != dnsLAPaginationAPIID || password != dnsLAPaginationAPISecret {
		t.Errorf("unexpected DNS.LA endpoint or credentials")
	}
}

func assertDNSLAPaginationSecretSafe(t *testing.T, err error) {
	t.Helper()
	formatted := fmt.Sprintf("%+v", err)
	for _, sensitive := range []string{
		dnsLAPaginationAPIID, dnsLAPaginationAPISecret, "dnsla-sensitive-provider-message", "Authorization", "Basic",
	} {
		if strings.Contains(err.Error(), sensitive) || strings.Contains(formatted, sensitive) {
			t.Fatalf("error leaked %q: %v", sensitive, err)
		}
	}
}
