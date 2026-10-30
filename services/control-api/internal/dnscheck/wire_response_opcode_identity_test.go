package dnscheck

import (
	"encoding/binary"
	"errors"
	"testing"
)

func TestDNSWireRejectsNonQueryOpcodeResponses(t *testing.T) {
	query := DNSQuery{Name: "www.example.test.", Type: RecordA}
	payload, err := buildDNSQuery(47, query)
	if err != nil {
		t.Fatal(err)
	}

	withStatusOpcode := func(response []byte) []byte {
		result := append([]byte(nil), response...)
		flags := binary.BigEndian.Uint16(result[2:4])
		binary.BigEndian.PutUint16(result[2:4], flags|0x1000)
		return result
	}

	t.Run("complete response", func(t *testing.T) {
		response := withStatusOpcode(wireResponse(payload, 0, wireAnswer(RecordA, 60, []byte{192, 0, 2, 10})))
		if _, err := parseDNSMessage(response, 512); !errors.Is(err, ErrMalformedResponse) {
			t.Fatalf("parseDNSMessage() error = %v, want %v", err, ErrMalformedResponse)
		}
	})

	t.Run("truncated response", func(t *testing.T) {
		response := withStatusOpcode(wireResponse(payload, 0x0200))
		if err := validateTruncatedDNSResponse(response, 512, 47, query); !errors.Is(err, ErrMalformedResponse) {
			t.Fatalf("validateTruncatedDNSResponse() error = %v, want %v", err, ErrMalformedResponse)
		}
	})
}
