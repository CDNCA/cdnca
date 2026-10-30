package dnscheck

import (
	"encoding/binary"
	"errors"
	"testing"
)

func TestDNSWireRejectsNonCanonicalRawLabels(t *testing.T) {
	response := func(id uint16, labels ...string) []byte {
		message := make([]byte, 12)
		binary.BigEndian.PutUint16(message[0:2], id)
		binary.BigEndian.PutUint16(message[2:4], 0x8000)
		binary.BigEndian.PutUint16(message[4:6], 1)
		for _, label := range labels {
			message = append(message, byte(len(label)))
			message = append(message, label...)
		}
		message = append(message, 0)
		message = binary.BigEndian.AppendUint16(message, uint16(RecordA))
		message = binary.BigEndian.AppendUint16(message, 1)
		return message
	}

	t.Run("embedded dot cannot collide with separate labels", func(t *testing.T) {
		const id = 51
		parsed, err := parseDNSMessage(response(id, "www.example", "test"), 512)
		if err == nil {
			query := DNSQuery{Name: "www.example.test.", Type: RecordA}
			if validationErr := validateDNSResponse(parsed, id, query); validationErr != nil {
				t.Fatalf("validateDNSResponse() error = %v; malformed label did not demonstrate the identity collision", validationErr)
			}
			t.Fatalf("parseDNSMessage() accepted a raw label containing a dot as query identity %q", parsed.questions[0].Name)
		}
		if !errors.Is(err, ErrMalformedResponse) {
			t.Fatalf("parseDNSMessage() error = %v, want %v", err, ErrMalformedResponse)
		}
	})

	for _, test := range []struct {
		name  string
		label string
	}{
		{name: "backslash", label: `www\\example`},
		{name: "at sign", label: "www@example"},
		{name: "mixed wildcard", label: "foo*"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseDNSMessage(response(52, test.label, "test"), 512); !errors.Is(err, ErrMalformedResponse) {
				t.Fatalf("parseDNSMessage() error = %v, want %v", err, ErrMalformedResponse)
			}
		})
	}

	t.Run("canonical application labels remain valid", func(t *testing.T) {
		parsed, err := parseDNSMessage(response(53, "_Acme-Challenge", "XN--BCHER-KVA", "Example-1"), 512)
		if err != nil {
			t.Fatalf("parseDNSMessage() error = %v", err)
		}
		if got, want := parsed.questions[0].Name, "_acme-challenge.xn--bcher-kva.example-1."; got != want {
			t.Fatalf("question name = %q, want %q", got, want)
		}
	})

	t.Run("wildcard label remains valid", func(t *testing.T) {
		parsed, err := parseDNSMessage(response(54, "*", "Example", "TEST"), 512)
		if err != nil {
			t.Fatalf("parseDNSMessage() error = %v", err)
		}
		if got, want := parsed.questions[0].Name, "*.example.test."; got != want {
			t.Fatalf("question name = %q, want %q", got, want)
		}
	})
}
