package dnsreconcilehttp

import (
	"bytes"
	"net/http/httptest"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/google/uuid"
)

func TestDNS02HTTPLineWeightRoundTrip(t *testing.T) {
	tenantID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	siteID := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	body := []byte(`{
		"name":"www.example.test","expected":[{"type":"A","values":["192.0.2.10"]}],
		"authoritative_ns":[],"ttl":300,"line":"境外","weight":80,"propagation_window_seconds":900,
		"provider":{"zone_id":"33333333-3333-4333-8333-333333333333","revision":7,"records":[{
			"record_id":"record-1","name":"www.example.test.","type":"A","value":"192.0.2.10","ttl":300,
			"line":"默认","weight":20
		}]}
	}`)
	request := httptest.NewRequest("POST", "/", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	decoded, err := (&Handler{maxRequestBytes: defaultMaxRequestBytes}).decodeCheck(
		httptest.NewRecorder(), request, tenantID, siteID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Line != "境外" || decoded.Weight != 80 || len(decoded.Provider.Records) != 1 ||
		decoded.Provider.Records[0].Line != "默认" || decoded.Provider.Records[0].Weight != 20 {
		t.Fatalf("decoded = %#v", decoded)
	}

	view := checkViewOf(decoded)
	if view.Line != "境外" || view.Weight != 80 || view.Provider.Records[0].Line != "默认" ||
		view.Provider.Records[0].Weight != 20 {
		t.Fatalf("view = %#v", view)
	}
	operation := dnscheck.ProviderOperation{
		Sequence: 1, Action: dnscheck.ProviderUpdate, RecordID: "record-1", Name: decoded.Name,
		Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300, Line: "境外", Weight: 80,
		PreviousValue: "192.0.2.10", PreviousTTL: 300, PreviousLine: "默认", PreviousWeight: 20,
	}
	operationView := operationsViewOf([]dnscheck.ProviderOperation{operation})[0]
	if operationView.Line != "境外" || operationView.Weight != 80 ||
		operationView.PreviousLine != "默认" || operationView.PreviousWeight != 20 {
		t.Fatalf("operation view = %#v", operationView)
	}
}

func TestDNS02HTTPRejectsInvalidLineWeight(t *testing.T) {
	for _, body := range []string{
		`{"name":"www.example.test","expected":[{"type":"A","values":["192.0.2.10"]}],"authoritative_ns":[],"ttl":300,"line":" bad ","weight":10,"propagation_window_seconds":900,"provider":{"zone_id":"33333333-3333-4333-8333-333333333333","revision":7,"records":[]}}`,
		`{"name":"www.example.test","expected":[{"type":"A","values":["192.0.2.10"]}],"authoritative_ns":[],"ttl":300,"line":"境外","weight":101,"propagation_window_seconds":900,"provider":{"zone_id":"33333333-3333-4333-8333-333333333333","revision":7,"records":[]}}`,
	} {
		request := httptest.NewRequest("POST", "/", bytes.NewBufferString(body))
		request.Header.Set("Content-Type", "application/json")
		_, err := (&Handler{maxRequestBytes: defaultMaxRequestBytes}).decodeCheck(
			httptest.NewRecorder(), request, uuid.New(), uuid.New(),
		)
		if err != ErrInvalidRequest {
			t.Fatalf("decode error = %v", err)
		}
	}
}
