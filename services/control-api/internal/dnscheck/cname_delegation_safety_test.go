package dnscheck

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestDNSWireRejectsCNAMEOwnerConflicts(t *testing.T) {
	query, err := buildDNSQuery(91, DNSQuery{Name: "Alias.Example.test.", Type: RecordCNAME})
	if err != nil {
		t.Fatalf("buildDNSQuery() error = %v", err)
	}
	target := wireNamePreservingCase("Target.Example.test.")
	conflictAAAA := netip.MustParseAddr("2001:db8::10").As16()
	cases := []struct {
		name       string
		otherType  RecordType
		otherValue []byte
	}{
		{name: "A", otherType: RecordA, otherValue: []byte{192, 0, 2, 10}},
		{name: "AAAA", otherType: RecordAAAA, otherValue: conflictAAAA[:]},
		{name: "TXT", otherType: RecordTXT, otherValue: []byte{3, 't', 'x', 't'}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			response := wireResponse(query, 0x0400,
				wireAnswer(RecordCNAME, 60, target),
				wireAnswerWithOwner("ALIAS.EXAMPLE.TEST.", test.otherType, 60, test.otherValue),
			)
			if _, err := parseDNSMessage(response, 512); !errors.Is(err, ErrMalformedResponse) {
				t.Fatalf("parseDNSMessage() error = %v, want %v", err, ErrMalformedResponse)
			}
		})
	}
}

func TestDNSWireRejectsConflictingCNAMETargets(t *testing.T) {
	query, err := buildDNSQuery(92, DNSQuery{Name: "alias.example.test.", Type: RecordCNAME})
	if err != nil {
		t.Fatalf("buildDNSQuery() error = %v", err)
	}
	response := wireResponse(query, 0x0400,
		wireAnswer(RecordCNAME, 60, wireNamePreservingCase("one.example.test.")),
		wireAnswerWithOwner("ALIAS.EXAMPLE.TEST.", RecordCNAME, 60, wireNamePreservingCase("two.example.test.")),
	)
	if _, err := parseDNSMessage(response, 512); !errors.Is(err, ErrMalformedResponse) {
		t.Fatalf("parseDNSMessage() error = %v, want %v", err, ErrMalformedResponse)
	}
}

func TestDNSWireParsesCanonicalCNAMEChainAndTerminalTypes(t *testing.T) {
	terminalAAAA := netip.MustParseAddr("2001:db8::42").As16()
	terminals := []struct {
		name  string
		type_ RecordType
		value []byte
	}{
		{name: "A", type_: RecordA, value: []byte{192, 0, 2, 42}},
		{name: "AAAA", type_: RecordAAAA, value: terminalAAAA[:]},
		{name: "TXT", type_: RecordTXT, value: []byte{4, 't', 'e', 's', 't'}},
	}
	for _, terminal := range terminals {
		t.Run(terminal.name, func(t *testing.T) {
			query, err := buildDNSQuery(93, DNSQuery{Name: "Alias.Example.test.", Type: RecordCNAME})
			if err != nil {
				t.Fatalf("buildDNSQuery() error = %v", err)
			}
			response := wireResponse(query, 0x0400,
				wireAnswerWithOwner("ALIAS.EXAMPLE.TEST.", RecordCNAME, 60, wireNamePreservingCase("Mid.Example.test.")),
				wireAnswerWithOwner("mid.example.test.", RecordCNAME, 60, wireNamePreservingCase("Terminal.Example.test.")),
				wireAnswerWithOwner("terminal.example.test.", terminal.type_, 60, terminal.value),
			)
			parsed, err := parseDNSMessage(response, 512)
			if err != nil {
				t.Fatalf("parseDNSMessage() error = %v", err)
			}
			if len(parsed.answers) != 3 {
				t.Fatalf("answers = %#v, want 3 records", parsed.answers)
			}
			for index, want := range []string{"alias.example.test.", "mid.example.test.", "terminal.example.test."} {
				if parsed.answers[index].Name != want {
					t.Fatalf("answers[%d].Name = %q, want %q", index, parsed.answers[index].Name, want)
				}
			}
		})
	}
}

func TestDNSWireIgnoresUnknownRRForCNAMEConflict(t *testing.T) {
	query, err := buildDNSQuery(94, DNSQuery{Name: "alias.example.test.", Type: RecordCNAME})
	if err != nil {
		t.Fatalf("buildDNSQuery() error = %v", err)
	}
	response := wireResponse(query, 0x0400,
		wireAnswerWithOwner("alias.example.test.", RecordCNAME, 60, wireNamePreservingCase("target.example.test.")),
		wireAnswerWithOwner("ALIAS.EXAMPLE.TEST.", RecordType(65280), 60, []byte{1, 2, 3}),
	)
	parsed, err := parseDNSMessage(response, 512)
	if err != nil || len(parsed.answers) != 1 || parsed.answers[0].Type != RecordCNAME {
		t.Fatalf("parseDNSMessage() = (%#v, %v), want one CNAME", parsed, err)
	}
}

func wireAnswerWithOwner(owner string, recordType RecordType, ttl uint32, value []byte) []byte {
	answer := wireNamePreservingCase(owner)
	answer = binary.BigEndian.AppendUint16(answer, uint16(recordType))
	answer = binary.BigEndian.AppendUint16(answer, 1)
	answer = binary.BigEndian.AppendUint32(answer, ttl)
	answer = binary.BigEndian.AppendUint16(answer, uint16(len(value)))
	return append(answer, value...)
}

func wireNamePreservingCase(name string) []byte {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return []byte{0}
	}
	result := make([]byte, 0, len(name)+1)
	for _, label := range strings.Split(name, ".") {
		result = append(result, byte(len(label)))
		result = append(result, label...)
	}
	return append(result, 0)
}
