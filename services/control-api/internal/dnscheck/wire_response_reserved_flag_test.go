package dnscheck

import (
	"encoding/binary"
	"errors"
	"testing"
)

func TestDNSWireRejectsReservedHeaderFlag(t *testing.T) {
	query := DNSQuery{Name: "www.example.test.", Type: RecordA}
	payload, err := buildDNSQuery(48, query)
	if err != nil {
		t.Fatal(err)
	}

	withFlags := func(response []byte, flags uint16) []byte {
		result := append([]byte(nil), response...)
		current := binary.BigEndian.Uint16(result[2:4])
		binary.BigEndian.PutUint16(result[2:4], current|flags)
		return result
	}

	t.Run("complete response", func(t *testing.T) {
		response := withFlags(wireResponse(payload, 0, wireAnswer(RecordA, 60, []byte{192, 0, 2, 10})), 0x0040)
		if _, err := parseDNSMessage(response, 512); !errors.Is(err, ErrMalformedResponse) {
			t.Fatalf("parseDNSMessage() error = %v, want %v", err, ErrMalformedResponse)
		}
	})

	t.Run("truncated response", func(t *testing.T) {
		response := withFlags(wireResponse(payload, 0x0200), 0x0040)
		if err := validateTruncatedDNSResponse(response, 512, 48, query); !errors.Is(err, ErrMalformedResponse) {
			t.Fatalf("validateTruncatedDNSResponse() error = %v, want %v", err, ErrMalformedResponse)
		}
	})

	t.Run("authenticated data and checking disabled remain valid", func(t *testing.T) {
		response := withFlags(wireResponse(payload, 0, wireAnswer(RecordA, 60, []byte{192, 0, 2, 10})), 0x0030)
		parsed, err := parseDNSMessage(response, 512)
		if err != nil || len(parsed.answers) != 1 || parsed.answers[0].Value != "192.0.2.10" {
			t.Fatalf("parseDNSMessage() = (%#v,%v), want valid AD/CD response", parsed, err)
		}
	})
}
