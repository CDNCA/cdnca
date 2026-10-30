package dnsproviderremote

import (
	"errors"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/acmeworker"
)

const (
	huaweiAbsenceZoneID   = "zone-hw"
	huaweiAbsenceRecordID = "record-hw-target"
)

func TestHuaweiListAbsenceRequiresDirectIDProof(t *testing.T) {
	for _, operation := range []string{"observe", "delete"} {
		t.Run("empty list direct present/"+operation, func(t *testing.T) {
			fixture := &huaweiListAbsenceFixture{listExists: []bool{false}, directExists: true}
			adapter, source, challenge := newHuaweiListAbsenceAdapter(t, fixture)
			var err error
			if operation == "observe" {
				err = adapter.ObserveTXT(t.Context(), challenge)
			} else {
				err = adapter.DeleteTXT(t.Context(), challenge)
			}
			assertHuaweiAbsenceError(t, err, CodeUnavailable, true)
			if fixture.listCalls != 1 || fixture.directCalls != 1 || len(fixture.deletedIDs) != 0 {
				t.Fatalf("list=%d direct=%d DELETE=%v", fixture.listCalls, fixture.directCalls, fixture.deletedIDs)
			}
			if !source.credentialsCleared() {
				t.Fatal("operation retained decrypted credentials")
			}
		})

		t.Run("empty list direct missing/"+operation, func(t *testing.T) {
			fixture := &huaweiListAbsenceFixture{listExists: []bool{false}}
			adapter, source, challenge := newHuaweiListAbsenceAdapter(t, fixture)
			if operation == "observe" {
				assertHuaweiAbsenceError(t, adapter.ObserveTXT(t.Context(), challenge), CodeRecordNotFound, true)
			} else if err := adapter.DeleteTXT(t.Context(), challenge); err != nil {
				t.Fatalf("idempotent delete error = %v", err)
			}
			if fixture.listCalls != 1 || fixture.directCalls != 1 || len(fixture.deletedIDs) != 0 {
				t.Fatalf("list=%d direct=%d DELETE=%v", fixture.listCalls, fixture.directCalls, fixture.deletedIDs)
			}
			if !source.credentialsCleared() {
				t.Fatal("operation retained decrypted credentials")
			}
		})
	}

	t.Run("delete recheck list absence waits for direct 404", func(t *testing.T) {
		fixture := &huaweiListAbsenceFixture{
			listExists: []bool{true, false, false, false}, directExists: true,
		}
		adapter, source, challenge := newHuaweiListAbsenceAdapter(t, fixture)
		assertHuaweiAbsenceError(t, adapter.DeleteTXT(t.Context(), challenge), CodeUnavailable, true)
		if fixture.listCalls != 3 || fixture.directCalls != 2 || len(fixture.deletedIDs) != 0 {
			t.Fatalf("first attempt list=%d direct=%d DELETE=%v",
				fixture.listCalls, fixture.directCalls, fixture.deletedIDs)
		}
		fixture.directExists = false
		if err := adapter.DeleteTXT(t.Context(), challenge); err != nil {
			t.Fatalf("direct-404 retry error = %v", err)
		}
		if fixture.listCalls != 4 || fixture.directCalls != 3 || len(fixture.deletedIDs) != 0 {
			t.Fatalf("retry list=%d direct=%d DELETE=%v",
				fixture.listCalls, fixture.directCalls, fixture.deletedIDs)
		}
		if !source.credentialsCleared() {
			t.Fatal("retry retained decrypted credentials")
		}
	})

	t.Run("stable exact deletes only persistent id", func(t *testing.T) {
		fixture := &huaweiListAbsenceFixture{
			listExists: []bool{true, true, false}, directExists: true,
		}
		adapter, source, challenge := newHuaweiListAbsenceAdapter(t, fixture)
		if err := adapter.DeleteTXT(t.Context(), challenge); err != nil {
			t.Fatalf("delete error = %v", err)
		}
		if fixture.listCalls != 3 || fixture.directCalls != 2 ||
			len(fixture.deletedIDs) != 1 || fixture.deletedIDs[0] != huaweiAbsenceRecordID {
			t.Fatalf("list=%d direct=%d DELETE=%v", fixture.listCalls, fixture.directCalls, fixture.deletedIDs)
		}
		if !source.credentialsCleared() {
			t.Fatal("delete retained decrypted credentials")
		}
	})
}

func newHuaweiListAbsenceAdapter(t *testing.T,
	fixture *huaweiListAbsenceFixture) (*Adapter, *staticSource, acmeworker.ChallengeIdentity) {
	t.Helper()
	fixture.t = t
	config := ProviderConfig{
		ProviderType: providerHuawei,
		ZoneName:     testZone,
		Credentials: map[string]string{
			"access_key": "absence-access", "secret_key": "absence-secret", "region": "cn-north-4",
			"project_id": "0123456789abcdef0123456789abcdef",
		},
	}
	adapter, source := newProviderTestAdapter(t, config, fixture, time.Second)
	recordID, err := encodeHuaweiRecordID(huaweiAbsenceRecordID, testValue, []string{testValue})
	if err != nil {
		t.Fatalf("encode Huawei record id: %v", err)
	}
	handle, err := encodeTestHandle(t, testChallenge(), config, recordHandle{
		Provider: providerHuawei, Zone: testZone, ZoneID: huaweiAbsenceZoneID,
		RecordID: recordID, Owner: testOwner,
	})
	if err != nil {
		t.Fatalf("encode handle: %v", err)
	}
	return adapter, source, testChallengeWithHandle(handle)
}

func assertHuaweiAbsenceError(t *testing.T, err error, code ErrorCode, temporary bool) {
	t.Helper()
	assertRemoteError(t, err, code)
	var remote *Error
	if !errors.As(err, &remote) || remote.Temporary != temporary {
		t.Fatalf("error = %+v, temporary want %t", err, temporary)
	}
}

type huaweiListAbsenceFixture struct {
	t            *testing.T
	listExists   []bool
	directExists bool
	listCalls    int
	directCalls  int
	deletedIDs   []string
}

func (fixture *huaweiListAbsenceFixture) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Host != "dns.cn-north-4.myhuaweicloud.com" ||
		request.Header.Get("X-Project-Id") != "0123456789abcdef0123456789abcdef" {
		fixture.t.Errorf("unexpected Huawei endpoint or project identity")
	}
	switch {
	case request.Method == http.MethodGet &&
		request.URL.Path == "/v2.1/zones/"+huaweiAbsenceZoneID+"/recordsets":
		query := request.URL.Query()
		if query.Get("name") != testOwner || query.Get("type") != "TXT" ||
			query.Get("limit") != strconv.Itoa(recoveryPageSize) || query.Get("offset") != "0" {
			fixture.t.Errorf("recordset query = %q", request.URL.RawQuery)
		}
		exists := false
		if fixture.listCalls >= len(fixture.listExists) {
			fixture.t.Errorf("unexpected owner-list call %d", fixture.listCalls+1)
		} else {
			exists = fixture.listExists[fixture.listCalls]
		}
		fixture.listCalls++
		recordsets := []any{}
		if exists {
			recordsets = append(recordsets, huaweiAbsenceRecord())
		}
		writeTestJSON(fixture.t, writer, map[string]any{
			"recordsets": recordsets, "metadata": map[string]any{"total_count": len(recordsets)},
			"links": map[string]any{"next": ""},
		})
	case request.Method == http.MethodGet &&
		request.URL.Path == "/v2.1/zones/"+huaweiAbsenceZoneID+"/recordsets/"+huaweiAbsenceRecordID:
		fixture.directCalls++
		if !fixture.directExists {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		writeTestJSON(fixture.t, writer, huaweiAbsenceRecord())
	case request.Method == http.MethodDelete &&
		request.URL.Path == "/v2.1/zones/"+huaweiAbsenceZoneID+"/recordsets/"+huaweiAbsenceRecordID:
		fixture.deletedIDs = append(fixture.deletedIDs, huaweiAbsenceRecordID)
		fixture.directExists = false
		writer.WriteHeader(http.StatusNoContent)
	default:
		fixture.t.Errorf("unexpected Huawei request %s %s", request.Method, request.URL.String())
		writer.WriteHeader(http.StatusNotFound)
	}
}

func huaweiAbsenceRecord() map[string]any {
	return map[string]any{
		"id": huaweiAbsenceRecordID, "zone_id": huaweiAbsenceZoneID, "name": testOwner,
		"type": "TXT", "ttl": 300, "records": []string{strconv.Quote(testValue)},
	}
}
