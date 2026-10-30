package dnsproviderremote

import (
	"net/http"
	"testing"
	"time"
)

const (
	dnsLAIdentityZoneID   = "zone-dnsla"
	dnsLAIdentityTargetID = "record-target"
)

type dnsLAListIdentityCase struct {
	name            string
	records         []map[string]any
	wantObserve     ErrorCode
	wantDelete      ErrorCode
	wantDeleteCalls int
}

func TestDNSLAExactListValidatesWholePageIdentity(t *testing.T) {
	for _, test := range dnsLAListIdentityCases() {
		for _, operation := range []string{"observe", "delete"} {
			t.Run(test.name+"/"+operation, func(t *testing.T) {
				fixture := &dnsLAListIdentityFixture{t: t, records: test.records}
				config := ProviderConfig{
					ProviderType: providerDNSLA,
					ZoneName:     testZone,
					Credentials:  map[string]string{"api_id": "identity-id", "api_secret": "identity-secret"},
				}
				adapter, source := newProviderTestAdapter(t, config, fixture, time.Second)
				handle, err := encodeTestHandle(t, testChallenge(), config, recordHandle{
					Provider: providerDNSLA, Zone: testZone, ZoneID: dnsLAIdentityZoneID,
					RecordID: dnsLAIdentityTargetID, Owner: testOwner,
				})
				if err != nil {
					t.Fatalf("encode handle: %v", err)
				}

				challenge := testChallengeWithHandle(handle)
				wantCode := test.wantObserve
				if operation == "observe" {
					err = adapter.ObserveTXT(t.Context(), challenge)
				} else {
					wantCode = test.wantDelete
					err = adapter.DeleteTXT(t.Context(), challenge)
				}
				if wantCode == "" {
					if err != nil {
						t.Fatalf("%s error = %v", operation, err)
					}
				} else {
					assertRemoteError(t, err, wantCode)
				}
				wantDeleteCalls := 0
				if operation == "delete" {
					wantDeleteCalls = test.wantDeleteCalls
				}
				if len(fixture.deletedIDs) != wantDeleteCalls {
					t.Fatalf("DELETE ids = %v, want %d calls", fixture.deletedIDs, wantDeleteCalls)
				}
				if wantDeleteCalls == 1 && fixture.deletedIDs[0] != dnsLAIdentityTargetID {
					t.Fatalf("DELETE id = %q", fixture.deletedIDs[0])
				}
				if !source.credentialsCleared() {
					t.Fatal("operation retained decrypted credentials")
				}
			})
		}
	}
}

func dnsLAListIdentityCases() []dnsLAListIdentityCase {
	var tests []dnsLAListIdentityCase
	orders := []struct {
		name        string
		targetFirst bool
	}{
		{name: "target-first", targetFirst: true},
		{name: "target-last", targetFirst: false},
	}
	drifts := []struct {
		name  string
		field string
		value any
	}{
		{name: "domain drift", field: "domainId", value: "zone-other"},
		{name: "host drift", field: "host", value: "other"},
		{name: "type drift", field: "type", value: 1},
		{name: "data drift", field: "data", value: testOtherValue},
	}
	for _, drift := range drifts {
		for _, order := range orders {
			target := dnsLAIdentityRecord(dnsLAIdentityTargetID)
			other := dnsLAIdentityRecord(dnsLAIdentityTargetID)
			other[drift.field] = drift.value
			tests = append(tests, dnsLAListIdentityCase{
				name:        drift.name + "/same-id/" + order.name,
				records:     dnsLAIdentityOrdered(target, other, order.targetFirst),
				wantObserve: CodeInvalidResponse, wantDelete: CodeInvalidResponse,
			})
		}
	}
	for _, order := range orders {
		tests = append(tests, dnsLAListIdentityCase{
			name: "exact duplicate/" + order.name,
			records: dnsLAIdentityOrdered(
				dnsLAIdentityRecord(dnsLAIdentityTargetID),
				dnsLAIdentityRecord(dnsLAIdentityTargetID),
				order.targetFirst,
			),
			wantObserve: CodeRecordMismatch, wantDelete: CodeRecordMismatch,
		})
	}
	differentIDDrifts := append([]struct {
		name  string
		field string
		value any
	}{
		{name: "invalid id", field: "id", value: ""},
	}, drifts...)
	for _, drift := range differentIDDrifts {
		for _, order := range orders {
			target := dnsLAIdentityRecord(dnsLAIdentityTargetID)
			other := dnsLAIdentityRecord("record-other")
			other[drift.field] = drift.value
			tests = append(tests, dnsLAListIdentityCase{
				name:        drift.name + "/different-id/" + order.name,
				records:     dnsLAIdentityOrdered(target, other, order.targetFirst),
				wantObserve: CodeInvalidResponse, wantDelete: CodeInvalidResponse,
			})
		}
	}
	tests = append(tests,
		dnsLAListIdentityCase{
			name: "single target", records: []map[string]any{dnsLAIdentityRecord(dnsLAIdentityTargetID)},
			wantDeleteCalls: 1,
		},
		dnsLAListIdentityCase{
			name: "target plus distinct legal exact row",
			records: []map[string]any{
				dnsLAIdentityRecord(dnsLAIdentityTargetID), dnsLAIdentityRecord("record-other"),
			},
			wantDeleteCalls: 1,
		},
		dnsLAListIdentityCase{
			name:        "fully valid target absent",
			records:     []map[string]any{dnsLAIdentityRecord("record-other")},
			wantObserve: CodeRecordNotFound,
		},
	)
	return tests
}

func dnsLAIdentityRecord(id string) map[string]any {
	return map[string]any{
		"id": id, "domainId": dnsLAIdentityZoneID, "host": testRelative,
		"type": 16, "data": testValue, "ttl": 600,
	}
}

func dnsLAIdentityOrdered(target, other map[string]any, targetFirst bool) []map[string]any {
	if targetFirst {
		return []map[string]any{target, other}
	}
	return []map[string]any{other, target}
}

type dnsLAListIdentityFixture struct {
	t          *testing.T
	records    []map[string]any
	deletedIDs []string
}

func (fixture *dnsLAListIdentityFixture) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	username, password, ok := request.BasicAuth()
	if !ok || username != "identity-id" || password != "identity-secret" {
		fixture.t.Errorf("unexpected DNS.LA authentication")
	}
	switch {
	case request.Method == http.MethodGet && request.URL.Path == "/api/recordList":
		query := request.URL.Query()
		if query.Get("pageIndex") != "1" || query.Get("pageSize") != "100" ||
			query.Get("domainId") != dnsLAIdentityZoneID || query.Get("host") != testRelative ||
			query.Get("type") != "16" {
			fixture.t.Errorf("record list query = %s", request.URL.RawQuery)
		}
		writeTestJSON(fixture.t, writer, map[string]any{"code": 200, "data": map[string]any{
			"total": len(fixture.records), "results": fixture.records,
		}})
	case request.Method == http.MethodDelete && request.URL.Path == "/api/record":
		deletedID := request.URL.Query().Get("id")
		fixture.deletedIDs = append(fixture.deletedIDs, deletedID)
		remaining := fixture.records[:0]
		for _, record := range fixture.records {
			if record["id"] != deletedID {
				remaining = append(remaining, record)
			}
		}
		fixture.records = remaining
		writeTestJSON(fixture.t, writer, map[string]any{"code": 200, "data": nil})
	default:
		fixture.t.Errorf("unexpected DNS.LA request %s %s", request.Method, request.URL.String())
		writer.WriteHeader(http.StatusNotFound)
	}
}
