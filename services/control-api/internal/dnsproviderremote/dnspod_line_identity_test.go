package dnsproviderremote

import (
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/acmeworker"
	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/google/uuid"
)

type dnsPodLineIdentityFixture struct {
	t             *testing.T
	line          string
	omitLine      bool
	value         string
	requestedLine atomic.Value
	mutations     atomic.Int32
}

func (fixture *dnsPodLineIdentityFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		fixture.t.Errorf("parse form: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// Record.List and Record.Info spell the record differently (dnsapi.cn).
	listRecord := map[string]any{"id": "target", "name": "www", "type": "A", "value": fixture.value, "ttl": "300"}
	record := map[string]any{"id": "target", "sub_domain": "www", "record_type": "A", "value": fixture.value, "ttl": "300"}
	if !fixture.omitLine {
		listRecord["line"], record["record_line"] = fixture.line, fixture.line
	}
	switch r.URL.Path {
	case "/Record.List":
		fixture.requestedLine.Store(r.Form.Get("record_line"))
		writeTestJSON(fixture.t, w, map[string]any{
			"status":  map[string]any{"code": "1"},
			"info":    map[string]any{"records_num": "1"},
			"records": []any{listRecord},
		})
	case "/Record.Info":
		writeTestJSON(fixture.t, w, map[string]any{
			"status": map[string]any{"code": "1"}, "record": record,
		})
	case "/Record.Modify", "/Record.Remove":
		fixture.mutations.Add(1)
		writeTestJSON(fixture.t, w, map[string]any{
			"status": map[string]any{"code": "1"},
			"record": map[string]any{"id": "target"},
		})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func TestDNSPodReconcileRecordLineIdentity(t *testing.T) {
	tests := []struct {
		name         string
		action       dnscheck.ProviderAction
		line         string
		omitLine     bool
		throughClaim bool
		wantCode     ErrorCode
	}{
		{name: "create ignores matching foreign line", action: dnscheck.ProviderCreate, line: "境外"},
		{name: "update conflicts on foreign line", action: dnscheck.ProviderUpdate, line: "境外", throughClaim: true},
		{name: "delete conflicts on foreign line", action: dnscheck.ProviderDelete, line: "境外", throughClaim: true},
		{name: "create rejects missing list line", action: dnscheck.ProviderCreate, omitLine: true, wantCode: CodeInvalidResponse},
		{name: "update rejects missing info line", action: dnscheck.ProviderUpdate, omitLine: true, wantCode: CodeInvalidResponse},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			operation := dnscheck.ProviderOperation{
				Action: test.action, RecordID: "target", Name: "www.example.test.",
				Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300,
			}
			if test.action == dnscheck.ProviderUpdate {
				operation.Value = "192.0.2.20"
				operation.PreviousValue = "192.0.2.10"
				operation.PreviousTTL = 300
			}
			fixture := &dnsPodLineIdentityFixture{
				t: t, line: test.line, omitLine: test.omitLine, value: operation.Value,
			}
			config := completeTestConfig(reconcileHTTPProviderConfig(providerDNSPodCN))
			providerAdapter, _ := newProviderTestAdapter(t, config, fixture, time.Second)
			remote := &providerReconcileRemote{adapter: providerAdapter}

			if test.throughClaim {
				authority := newReconcileHTTPAuthority(config, 7)
				adapter, err := NewReconcileAdapter(authority, remote)
				if err != nil {
					t.Fatal(err)
				}
				_, err = adapter.Mutate(t.Context(), dnscheck.ProviderMutation{
					ClientRequestID: "dnspod-line-identity-request",
					TenantID:        uuid.New(), SiteID: uuid.New(), ZoneID: uuid.New(),
					ExpectedRevision: 7, Operation: operation,
				})
				if !errors.Is(err, dnscheck.ErrProviderRevisionConflict) {
					t.Fatalf("Mutate() error=%v, want revision conflict", err)
				}
			} else {
				lookup, err := remote.Lookup(t.Context(), config, operation)
				if test.wantCode != "" {
					if ErrorCodeOf(err) != test.wantCode {
						t.Fatalf("Lookup() error=%v, want %s", err, test.wantCode)
					}
				} else if err != nil || lookup.TargetComplete || lookup.Ambiguous || lookup.Conflict {
					t.Fatalf("Lookup()=(%+v,%v), want independent foreign line", lookup, err)
				}
			}
			if test.action == dnscheck.ProviderCreate {
				requested, _ := fixture.requestedLine.Load().(string)
				if requested != "默认" {
					t.Fatalf("Record.List record_line=%q, want 默认", requested)
				}
			}
			if mutations := fixture.mutations.Load(); mutations != 0 {
				t.Fatalf("provider mutations=%d, want 0", mutations)
			}
		})
	}
}

var _ http.Handler = (*dnsPodLineIdentityFixture)(nil)

type dnsPodPresentIdentityFixture struct {
	t              *testing.T
	infoStatus     string
	infoHTTPStatus int
	infoDomain     string
	infoRecord     map[string]any
	createCalls    atomic.Int32
	infoCalls      atomic.Int32
	listCalls      atomic.Int32
	removeCalls    atomic.Int32
	createdRecord  string
}

func (fixture *dnsPodPresentIdentityFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		fixture.t.Errorf("parse form: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if got := r.Form.Get("login_token"); got != "12345,provider-secret" {
		fixture.t.Errorf("login_token = %q, want test credentials", got)
	}
	switch r.URL.Path {
	case "/Record.Create":
		fixture.createCalls.Add(1)
		if r.Form.Get("domain") != testZone || r.Form.Get("sub_domain") != testRelative ||
			r.Form.Get("record_type") != "TXT" || r.Form.Get("record_line") != "默认" ||
			r.Form.Get("value") != testValue || r.Form.Get("ttl") != "600" {
			fixture.t.Errorf("create form = %v", r.Form)
		}
		writeTestJSON(fixture.t, w, map[string]any{
			"status": map[string]any{"code": "1"},
			"record": map[string]any{"id": fixture.createdRecord, "name": testRelative, "status": "enable"},
		})
	case "/Record.Info":
		fixture.infoCalls.Add(1)
		if r.Form.Get("domain") != testZone || r.Form.Get("record_id") != fixture.createdRecord {
			fixture.t.Errorf("info form = %v", r.Form)
		}
		if fixture.infoHTTPStatus != 0 {
			w.WriteHeader(fixture.infoHTTPStatus)
			return
		}
		switch fixture.infoStatus {
		case "missing":
			writeTestJSON(fixture.t, w, map[string]any{"status": map[string]any{"code": "10"}})
		default:
			domain := fixture.infoDomain
			if domain == "" {
				domain = testZone
			}
			writeTestJSON(fixture.t, w, map[string]any{
				"status": map[string]any{"code": "1"},
				"domain": map[string]any{"id": "zone-dnspod", "domain": domain},
				"record": fixture.infoRecord,
			})
		}
	case "/Record.List":
		fixture.listCalls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	case "/Record.Remove":
		fixture.removeCalls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	default:
		fixture.t.Errorf("unexpected DNSPod path %q", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}
}

func TestDNSPodPresentVerifiesCreatedRecordIdentity(t *testing.T) {
	previousDelay := dnsPodCreatedInfoDelay
	dnsPodCreatedInfoDelay = time.Millisecond
	t.Cleanup(func() { dnsPodCreatedInfoDelay = previousDelay })
	const (
		recordID = "record-dnspod-created"
	)
	createdRecord := func(overrides map[string]any) map[string]any {
		record := map[string]any{
			"id": recordID, "sub_domain": testRelative, "record_type": "TXT",
			"value": testValue, "ttl": "600", "record_line": "默认",
		}
		for name, value := range overrides {
			record[name] = value
		}
		return record
	}
	createdRecordWithout := func(field string) map[string]any {
		record := createdRecord(nil)
		delete(record, field)
		return record
	}
	tests := []struct {
		name           string
		infoStatus     string
		infoHTTPStatus int
		infoDomain     string
		infoRecord     map[string]any
		wantCode       ErrorCode
		wantTemporary  bool
		wantSuccess    bool
	}{
		{name: "matching direct read succeeds", infoRecord: createdRecord(nil), wantSuccess: true},
		{name: "created record absent", infoStatus: "missing", wantCode: CodeUnavailable, wantTemporary: true},
		{name: "created record HTTP 404", infoHTTPStatus: http.StatusNotFound, wantCode: CodeUnavailable, wantTemporary: true},
		{name: "wrong domain", infoDomain: "other.example.test", infoRecord: createdRecord(nil), wantCode: CodeRecordMismatch},
		{name: "wrong record id", infoRecord: createdRecord(map[string]any{"id": "record-dnspod-other"}), wantCode: CodeRecordMismatch},
		{name: "wrong owner", infoRecord: createdRecord(map[string]any{"sub_domain": "other-owner"}), wantCode: CodeRecordMismatch},
		{name: "wrong type", infoRecord: createdRecord(map[string]any{"record_type": "A"}), wantCode: CodeRecordMismatch},
		{name: "omitted line", infoRecord: createdRecordWithout("record_line"), wantCode: CodeRecordMismatch},
		{name: "empty line", infoRecord: createdRecord(map[string]any{"record_line": ""}), wantCode: CodeRecordMismatch},
		{name: "wrong line", infoRecord: createdRecord(map[string]any{"record_line": "境外"}), wantCode: CodeRecordMismatch},
		{name: "wrong value", infoRecord: createdRecord(map[string]any{"value": testOtherValue}), wantCode: CodeRecordMismatch},
		{name: "omitted ttl", infoRecord: createdRecordWithout("ttl"), wantCode: CodeRecordMismatch},
		{name: "zero ttl", infoRecord: createdRecord(map[string]any{"ttl": "0"}), wantCode: CodeRecordMismatch},
		{name: "wrong ttl", infoRecord: createdRecord(map[string]any{"ttl": "300"}), wantCode: CodeRecordMismatch},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := &dnsPodPresentIdentityFixture{
				t: t, infoStatus: test.infoStatus, infoHTTPStatus: test.infoHTTPStatus, infoDomain: test.infoDomain,
				infoRecord: test.infoRecord, createdRecord: recordID,
			}
			config := completeTestConfig(ProviderConfig{
				ProviderType: providerDNSPodCN, ZoneName: testZone,
				Credentials: map[string]string{"dp_id": "12345", "dp_key": "provider-secret"},
			})
			adapter, source := newProviderTestAdapter(t, config, fixture, time.Second)
			handle, err := adapter.PresentTXT(t.Context(), testChallenge())
			if test.wantSuccess {
				if err != nil {
					t.Fatalf("PresentTXT: %v", err)
				}
				requireHandle(t, handle, providerDNSPodCN, testZone, recordID)
			} else {
				if handle != (acmeworker.RemoteTXTHandle{}) {
					t.Fatalf("failed present returned handle %+v", handle)
				}
				assertRemoteError(t, err, test.wantCode)
				var remoteError *Error
				if !errors.As(err, &remoteError) || remoteError.Temporary != test.wantTemporary {
					t.Fatalf("error = %+v, want temporary=%v", err, test.wantTemporary)
				}
			}
			// An absent fresh record is read again before giving up.
			wantInfo := int32(1)
			if test.infoStatus == "missing" {
				wantInfo += int32(dnsPodCreatedInfoRetries)
			}
			if fixture.createCalls.Load() != 1 || fixture.infoCalls.Load() != wantInfo ||
				fixture.listCalls.Load() != 0 || fixture.removeCalls.Load() != 0 {
				t.Fatalf("calls create/info/list/remove=%d/%d/%d/%d, want 1/%d/0/0",
					fixture.createCalls.Load(), fixture.infoCalls.Load(), fixture.listCalls.Load(), fixture.removeCalls.Load(),
					wantInfo)
			}
			if !source.credentialsCleared() {
				t.Fatal("provider credentials were retained")
			}
		})
	}
}
