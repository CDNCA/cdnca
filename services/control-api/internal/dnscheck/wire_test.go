package dnscheck

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

func TestDNSWireParsesAAndAAAA(t *testing.T) {
	query, err := buildDNSQuery(42, DNSQuery{Name: "www.example.test.", Type: RecordA})
	if err != nil {
		t.Fatalf("buildDNSQuery() error = %v", err)
	}
	v6 := netip.MustParseAddr("2001:db8::10").As16()
	response := wireResponse(query, 0x0400,
		wireAnswer(RecordA, 60, []byte{192, 0, 2, 10}),
		wireAnswer(RecordAAAA, 120, v6[:]),
	)
	parsed, err := parseDNSMessage(response, 512)
	if err != nil {
		t.Fatalf("parseDNSMessage() error = %v", err)
	}
	if parsed.id != 42 || !parsed.authoritative || len(parsed.answers) != 2 || parsed.answers[0].Value != "192.0.2.10" || parsed.answers[1].Value != "2001:db8::10" {
		t.Fatalf("parseDNSMessage() = %#v", parsed)
	}
}

func TestDNSWireParsesCompressedCNAME(t *testing.T) {
	query, _ := buildDNSQuery(43, DNSQuery{Name: "www.example.test.", Type: RecordCNAME})
	response := wireResponse(query, 0x0400, wireAnswer(RecordCNAME, 60, []byte{0xc0, 0x0c}))
	parsed, err := parseDNSMessage(response, 512)
	if err != nil {
		t.Fatalf("parseDNSMessage() error = %v", err)
	}
	if len(parsed.answers) != 1 || parsed.answers[0].Value != "www.example.test." {
		t.Fatalf("answers = %#v", parsed.answers)
	}
}

func TestDNSWireRejectsMaliciousBounds(t *testing.T) {
	query, _ := buildDNSQuery(44, DNSQuery{Name: "www.example.test.", Type: RecordA})
	valid := wireResponse(query, 0x0400, wireAnswer(RecordA, 60, []byte{192, 0, 2, 10}))
	tests := []struct {
		name string
		data []byte
		max  int
	}{
		{name: "compression loop", data: append([]byte{0, 44, 0x81, 0, 0, 1, 0, 0, 0, 0, 0, 0}, 0xc0, 0x0c), max: 512},
		{name: "compression out of range", data: append([]byte{0, 44, 0x81, 0, 0, 1, 0, 0, 0, 0, 0, 0}, 0xff, 0xff), max: 512},
		{name: "truncated rdata", data: valid[:len(valid)-1], max: 512},
		{name: "oversized", data: append(valid, make([]byte, 512)...), max: 512},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseDNSMessage(test.data, test.max)
			if err == nil {
				t.Fatal("parseDNSMessage() accepted malicious packet")
			}
		})
	}
	tooMany := append([]byte(nil), valid...)
	binary.BigEndian.PutUint16(tooMany[6:8], maximumDNSRecords+1)
	if _, err := parseDNSMessage(tooMany, 512); !errors.Is(err, ErrMalformedResponse) {
		t.Fatalf("too many records error = %v", err)
	}
}

func TestDNSWireRejectsNonINClasses(t *testing.T) {
	query, err := buildDNSQuery(46, DNSQuery{Name: "www.example.test.", Type: RecordA})
	if err != nil {
		t.Fatalf("buildDNSQuery() error = %v", err)
	}
	withQuestionClass := func(response []byte, class uint16) []byte {
		result := append([]byte(nil), response...)
		end := queryEnd(result)
		binary.BigEndian.PutUint16(result[end-2:end], class)
		return result
	}
	withRecordClass := func(record []byte, class uint16) []byte {
		result := append([]byte(nil), record...)
		binary.BigEndian.PutUint16(result[4:6], class)
		return result
	}
	responseWithSections := func(answers, authority, additional [][]byte) []byte {
		response := wireResponse(query, 0x0400)
		binary.BigEndian.PutUint16(response[6:8], uint16(len(answers)))
		binary.BigEndian.PutUint16(response[8:10], uint16(len(authority)))
		binary.BigEndian.PutUint16(response[10:12], uint16(len(additional)))
		for _, section := range [][][]byte{answers, authority, additional} {
			for _, record := range section {
				response = append(response, record...)
			}
		}
		return response
	}
	soaData := []byte{0xc0, 0x0c, 0xc0, 0x0c}
	for _, value := range []uint32{1, 2, 3, 4, 30} {
		soaData = binary.BigEndian.AppendUint32(soaData, value)
	}
	soa := wireAnswer(RecordSOA, 60, soaData)
	unknown := wireAnswer(RecordType(65280), 60, []byte{1, 2})

	malformed := []struct {
		name     string
		response []byte
	}{
		{
			name:     "question CH",
			response: withQuestionClass(responseWithSections(nil, nil, nil), 3),
		},
		{
			name: "known answer CH",
			response: responseWithSections([][]byte{
				withRecordClass(wireAnswer(RecordA, 60, []byte{192, 0, 2, 10}), 3),
			}, nil, nil),
		},
		{
			name: "unknown answer CH",
			response: responseWithSections([][]byte{
				withRecordClass(unknown, 3),
			}, nil, nil),
		},
		{
			name: "SOA authority CH",
			response: responseWithSections(nil, [][]byte{
				withRecordClass(soa, 3),
			}, nil),
		},
		{
			name: "unknown authority CH",
			response: responseWithSections(nil, [][]byte{
				withRecordClass(unknown, 3),
			}, nil),
		},
	}
	for _, test := range malformed {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseDNSMessage(test.response, 512); !errors.Is(err, ErrMalformedResponse) {
				t.Fatalf("parseDNSMessage() error = %v, want %v", err, ErrMalformedResponse)
			}
		})
	}

	t.Run("unknown IN answer and authority", func(t *testing.T) {
		parsed, err := parseDNSMessage(responseWithSections([][]byte{unknown}, [][]byte{unknown}, nil), 512)
		if err != nil || len(parsed.answers) != 0 || len(parsed.authority) != 0 {
			t.Fatalf("parseDNSMessage() = (%#v, %v)", parsed, err)
		}
	})

	t.Run("additional OPT payload class", func(t *testing.T) {
		opt := []byte{0}
		opt = binary.BigEndian.AppendUint16(opt, 41)
		opt = binary.BigEndian.AppendUint16(opt, 1232)
		opt = binary.BigEndian.AppendUint32(opt, 0)
		opt = binary.BigEndian.AppendUint16(opt, 0)
		parsed, err := parseDNSMessage(responseWithSections(
			[][]byte{wireAnswer(RecordA, 60, []byte{192, 0, 2, 10})},
			[][]byte{soa},
			[][]byte{opt},
		), 512)
		if err != nil || len(parsed.answers) != 1 || len(parsed.authority) != 1 ||
			parsed.answers[0].Value != "192.0.2.10" || !parsed.authority[0].negativeTTLSet {
			t.Fatalf("parseDNSMessage() = (%#v, %v)", parsed, err)
		}
	})
}

func TestDNSWireRootAndWildcardQueries(t *testing.T) {
	for _, name := range []string{".", "*.example.test."} {
		query, err := buildDNSQuery(45, DNSQuery{Name: name, Type: RecordA})
		if err != nil {
			t.Fatalf("buildDNSQuery(%q) error = %v", name, err)
		}
		response := wireResponse(query, 0x0400)
		parsed, err := parseDNSMessage(response, 512)
		if err != nil || parsed.questions[0].Name != name {
			t.Fatalf("parseDNSMessage(%q) = (%#v, %v)", name, parsed, err)
		}
	}
}
