package dnsproviderremotesource

import (
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/google/uuid"
)

func TestValidateHubRecord(t *testing.T) {
	for _, test := range []struct {
		name  string
		input HubRecordInput
		field string
		fqdn  string
		value string
	}{
		{"apex A", HubRecordInput{Name: "@", Type: "a", Value: "192.0.2.1", TTL: 600}, "", "example.com.", "192.0.2.1"},
		{"empty name is apex", HubRecordInput{Type: "AAAA", Value: "2001:DB8::1", TTL: 600}, "", "example.com.", "2001:db8::1"},
		{"cname trailing dot", HubRecordInput{Name: "www", Type: "CNAME", Value: "Edge.Example.NET.", TTL: 600}, "", "www.example.com.", "edge.example.net."},
		{"txt spf", HubRecordInput{Name: "@", Type: "TXT", Value: "v=spf1 -all", TTL: 600}, "", "example.com.", "v=spf1 -all"},
		{"underscore owner", HubRecordInput{Name: "_dmarc", Type: "TXT", Value: "v=DMARC1; p=none", TTL: 600}, "", "_dmarc.example.com.", "v=DMARC1; p=none"},
		{"bad type", HubRecordInput{Name: "www", Type: "MX", Value: "x", TTL: 600}, "type", "", ""},
		{"ipv4 in AAAA", HubRecordInput{Name: "www", Type: "AAAA", Value: "192.0.2.1", TTL: 600}, "value", "", ""},
		{"zero ttl", HubRecordInput{Name: "www", Type: "A", Value: "192.0.2.1"}, "ttl", "", ""},
		{"wildcard", HubRecordInput{Name: "*", Type: "A", Value: "192.0.2.1", TTL: 600}, "name", "", ""},
		{"txt quote", HubRecordInput{Name: "www", Type: "TXT", Value: `a"b`, TTL: 600}, "value", "", ""},
		{"line newline", HubRecordInput{Name: "www", Type: "A", Value: "192.0.2.1", TTL: 600, Line: "a\nb"}, "line", "", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			wanted, err := validateHubRecord("example.com", test.input, "")
			if test.field != "" {
				var field *HubFieldError
				if !errors.As(err, &field) || field.Field != test.field {
					t.Fatalf("error = %v, want field %s", err, test.field)
				}
				return
			}
			if err != nil || wanted.fqdn != test.fqdn || wanted.value != test.value || wanted.line != dnsproviderremote.LineDefault {
				t.Fatalf("wanted = %+v, %v", wanted, err)
			}
		})
	}
	// expected may hold text the page could not write (a quote).
	if _, err := validateHubRecord("example.com", HubRecordInput{Name: "www", Type: "TXT", Value: `a"b`, TTL: 600}, "expected."); err != nil {
		t.Fatalf("expected TXT with a quote: %v", err)
	}
}

func TestValidateHubMutationShape(t *testing.T) {
	ref := encodeHubRecordRef("record-1")
	record := HubRecordInput{Name: "www", Type: "A", Value: "192.0.2.1", TTL: 600}
	other := HubRecordInput{Name: "www", Type: "A", Value: "192.0.2.9", TTL: 600}
	provider := uuid.New()
	for _, test := range []struct {
		name     string
		mutation HubMutation
		want     error
		field    string
	}{
		{"create", HubMutation{ProviderID: provider, Apex: "example.com", Action: "create", Record: record}, nil, ""},
		{"create with expected", HubMutation{ProviderID: provider, Apex: "example.com", Action: "create", Record: record, Expected: &other}, ErrHubInvalid, "expected"},
		{"update", HubMutation{ProviderID: provider, Apex: "example.com", Action: "update", RecordRef: ref, Record: record, Expected: &other}, nil, ""},
		{"update without expected", HubMutation{ProviderID: provider, Apex: "example.com", Action: "update", RecordRef: ref, Record: record}, ErrHubInvalid, "expected"},
		{"update rename", HubMutation{ProviderID: provider, Apex: "example.com", Action: "update", RecordRef: ref,
			Record: HubRecordInput{Name: "api", Type: "A", Value: "192.0.2.1", TTL: 600}, Expected: &other}, ErrHubInvalid, "name"},
		{"update type change", HubMutation{ProviderID: provider, Apex: "example.com", Action: "update", RecordRef: ref,
			Record: HubRecordInput{Name: "www", Type: "AAAA", Value: "2001:db8::1", TTL: 600}, Expected: &other}, ErrHubInvalid, "type"},
		{"delete", HubMutation{ProviderID: provider, Apex: "example.com", Action: "delete", RecordRef: ref, Expected: &other}, nil, ""},
		{"delete with record", HubMutation{ProviderID: provider, Apex: "example.com", Action: "delete", RecordRef: ref, Expected: &other, Record: record}, ErrHubInvalid, "record"},
		{"bad ref", HubMutation{ProviderID: provider, Apex: "example.com", Action: "delete", RecordRef: "x", Expected: &other}, ErrHubNotFound, ""},
		{"bad action", HubMutation{ProviderID: provider, Apex: "example.com", Action: "upsert"}, ErrHubInvalid, "action"},
	} {
		t.Run(test.name, func(t *testing.T) {
			mutation := test.mutation
			_, _, err := validateHubMutation(&mutation)
			if test.want == nil {
				if err != nil {
					t.Fatalf("error = %v", err)
				}
				return
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			var field *HubFieldError
			if test.field != "" && (!errors.As(err, &field) || field.Field != test.field) {
				t.Fatalf("error = %v, want field %s", err, test.field)
			}
		})
	}
}

func TestHubRecordViewAndManagedMarker(t *testing.T) {
	managed := map[string]HubManaged{
		managedKey("CNAME", "www.example.com", "abc.cdn.example.net"): {Kind: "site_cname", SiteID: "s1", SiteDomain: "www.example.com"},
	}
	view := hubRecordView("example.com", dnsproviderremote.ZoneRecord{ID: "r1", Name: "www.example.com.",
		Type: dnscheck.RecordCNAME, Value: "ABC.cdn.example.net.", TTL: 600, Line: "default"}, managed)
	if view.Name != "www" || view.FQDN != "www.example.com" || view.Value != "ABC.cdn.example.net" ||
		view.Line != dnsproviderremote.LineDefault || view.Managed == nil || view.Managed.Kind != "site_cname" {
		t.Fatalf("view = %+v", view)
	}
	if id, ok := decodeHubRecordRef(view.RecordRef); !ok || id != "r1" {
		t.Fatalf("record ref %q -> %q, %v", view.RecordRef, id, ok)
	}
	apex := hubRecordView("example.com", dnsproviderremote.ZoneRecord{ID: "r2", Name: "example.com.",
		Type: dnscheck.RecordTXT, Value: "v=spf1 -all", TTL: 600}, managed)
	if apex.Name != "@" || apex.Managed != nil {
		t.Fatalf("apex view = %+v", apex)
	}
}

func TestHubMutationDigestDistinguishesRequests(t *testing.T) {
	provider := uuid.New()
	base := HubMutation{ProviderID: provider, Apex: "example.com", Action: "create",
		Record: HubRecordInput{Name: "www", Type: "A", Value: "192.0.2.1", TTL: 600}, IdempotencyKey: "k1"}
	first, _ := hubMutationDigest(base)
	again, _ := hubMutationDigest(base)
	changed := base
	changed.Record.Value = "192.0.2.2"
	other, _ := hubMutationDigest(changed)
	keyChanged := base
	keyChanged.IdempotencyKey = "k2"
	sameBody, _ := hubMutationDigest(keyChanged)
	if first != again || first == other || first != sameBody {
		t.Fatalf("digests %s %s %s %s", first, again, other, sameBody)
	}
}

func TestHubCursorRoundTrip(t *testing.T) {
	id := uuid.NewString()
	apex, provider, err := decodeHubCursor(encodeHubCursor("example.com", id))
	if err != nil || apex != "example.com" || provider != id {
		t.Fatalf("cursor = %q %q %v", apex, provider, err)
	}
	if _, _, err := decodeHubCursor("!!"); err == nil {
		t.Fatal("malformed cursor accepted")
	}
}

func TestHubWantedMatchesIgnoresTTLOnlyAfterWrite(t *testing.T) {
	wanted, err := validateHubRecord("example.com", HubRecordInput{Name: "www", Type: "A", Value: "192.0.2.1", TTL: 60}, "")
	if err != nil {
		t.Fatal(err)
	}
	record := dnsproviderremote.ZoneRecord{ID: "r", Name: "www.example.com.", Type: dnscheck.RecordA, Value: "192.0.2.1", TTL: 300}
	if wanted.matches(record) || !wanted.matchesWritten(record) {
		t.Fatal("TTL raised to the provider floor must read back as written, not as the expected value")
	}
}
