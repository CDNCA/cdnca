package dnscheck

import (
	"errors"
	"testing"
)

func TestParseDNSNameRejectsNonBackwardCompressionPointers(t *testing.T) {
	tests := []struct {
		name     string
		message  []byte
		start    int
		wantName string
		wantNext int
		wantErr  bool
	}{
		{
			name:     "backward pointer",
			message:  []byte{3, 'w', 'w', 'w', 0, 0xc0, 0x00},
			start:    5,
			wantName: "www.",
			wantNext: 7,
		},
		{
			name:    "self pointer",
			message: []byte{0xc0, 0x00},
			wantErr: true,
		},
		{
			name:    "forward pointer",
			message: []byte{0xc0, 0x02, 0},
			wantErr: true,
		},
		{
			name:    "pointer loop",
			message: []byte{0xc0, 0x02, 0xc0, 0x00},
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			name, next, err := parseDNSName(test.message, test.start)
			if test.wantErr {
				if !errors.Is(err, ErrMalformedResponse) {
					t.Fatalf("parseDNSName() error = %v, want %v", err, ErrMalformedResponse)
				}
				return
			}
			if err != nil || name != test.wantName || next != test.wantNext {
				t.Fatalf("parseDNSName() = (%q, %d, %v), want (%q, %d, nil)", name, next, err, test.wantName, test.wantNext)
			}
		})
	}
}
