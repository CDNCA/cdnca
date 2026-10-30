package dnscheck

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestNormalizeDNSNameIDNWildcardAndRoot(t *testing.T) {
	tests := []struct {
		name            string
		input           string
		wildcardAllowed bool
		want            string
	}{
		{name: "idn", input: "BÜCHER.Example", want: "xn--bcher-kva.example."},
		{name: "wildcard", input: "*.BÜCHER.Example.", wildcardAllowed: true, want: "*.xn--bcher-kva.example."},
		{name: "root", input: ".", want: "."},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := normalizeDNSName(test.input, test.wildcardAllowed)
			if err != nil || got != test.want {
				t.Fatalf("normalizeDNSName() = (%q, %v), want (%q, nil)", got, err, test.want)
			}
		})
	}
	for _, input := range []string{"*.*.example", "https://example.test", "bad..example", "-bad.example"} {
		if _, err := normalizeDNSName(input, true); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("normalizeDNSName(%q) error = %v", input, err)
		}
	}
	if _, err := normalizeDNSName("*.example.test", false); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("CNAME wildcard error = %v", err)
	}
}

func TestNormalizeRequestRejectsCrossTenantSnapshotAndInvalidRecords(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	valid := baseRequest(now, RecordA, "192.0.2.10")
	tests := []struct {
		name   string
		mutate func(*CheckRequest)
	}{
		{name: "cross tenant", mutate: func(request *CheckRequest) { request.Provider.TenantID = uuid.New() }},
		{name: "cross site", mutate: func(request *CheckRequest) { request.Provider.SiteID = uuid.New() }},
		{name: "record from another owner", mutate: func(request *CheckRequest) { request.Provider.Records[0].Name = "other.example.test" }},
		{name: "invalid provider record id", mutate: func(request *CheckRequest) { request.Provider.Records[0].RecordID = "record?invalid" }},
		{name: "duplicate provider id", mutate: func(request *CheckRequest) {
			request.Provider.Records = append(request.Provider.Records, request.Provider.Records[0])
		}},
		{name: "propagation shorter than ttl", mutate: func(request *CheckRequest) { request.PropagationWindow = 30 * time.Second }},
		{name: "mixed cname and address", mutate: func(request *CheckRequest) {
			request.Expected = append(request.Expected, ExpectedRecord{Type: RecordCNAME, Values: []string{"edge.example.test"}})
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := valid
			request.Expected = append([]ExpectedRecord(nil), valid.Expected...)
			request.Provider.Records = append([]ProviderRecord(nil), valid.Provider.Records...)
			test.mutate(&request)
			if _, err := normalizeRequest(request, now); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("normalizeRequest() error = %v", err)
			}
		})
	}
}

func TestNormalizeRequestPreservesOpaqueProviderRecordID(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name     string
		recordID string
	}{
		{name: "leading space", recordID: " record-1"},
		{name: "trailing space", recordID: "record-1 "},
		{name: "leading tab", recordID: "\trecord-1"},
		{name: "trailing tab", recordID: "record-1\t"},
		{name: "leading newline", recordID: "\nrecord-1"},
		{name: "trailing newline", recordID: "record-1\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := baseRequest(now, RecordA, "192.0.2.10")
			request.Provider.Records[0].RecordID = test.recordID
			normalized, err := normalizeRequest(request, now)
			if !errors.Is(err, ErrInvalidInput) || len(normalized.Provider.Records) != 0 {
				t.Fatalf("normalizeRequest(%q) = (%#v, %v)", test.recordID, normalized, err)
			}
		})
	}

	t.Run("exact preservation", func(t *testing.T) {
		const recordID = "Provider.Record/ID:Ab_C-9"
		request := baseRequest(now, RecordA, "192.0.2.10")
		request.Provider.Records[0].RecordID = recordID
		normalized, err := normalizeRequest(request, now)
		if err != nil || len(normalized.Provider.Records) != 1 || normalized.Provider.Records[0].RecordID != recordID {
			t.Fatalf("normalizeRequest() record = (%#v, %v)", normalized.Provider.Records, err)
		}
	})
}

func TestNormalizeExpectedIPv4AndIPv6(t *testing.T) {
	records, err := normalizeExpected([]ExpectedRecord{
		{Type: RecordAAAA, Values: []string{"2001:0db8:0:0::10"}},
		{Type: RecordA, Values: []string{"192.0.2.10"}},
	})
	if err != nil {
		t.Fatalf("normalizeExpected() error = %v", err)
	}
	if records[0].Type != RecordA || records[1].Values[0] != "2001:db8::10" {
		t.Fatalf("normalizeExpected() = %#v", records)
	}
	for _, invalid := range []ExpectedRecord{
		{Type: RecordA, Values: []string{"2001:db8::1"}},
		{Type: RecordAAAA, Values: []string{"::ffff:192.0.2.1"}},
	} {
		if _, err := normalizeExpected([]ExpectedRecord{invalid}); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("normalizeExpected(%#v) error = %v", invalid, err)
		}
	}
}
