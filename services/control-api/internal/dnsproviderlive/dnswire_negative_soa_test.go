package dnsproviderlive

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"testing"
)

func TestWireDNSNegativeResponseRequiresAuthoritativeSOA(t *testing.T) {
	t.Parallel()
	const owner = "missing.example.test."
	type soaSpec struct {
		owner      string
		class      uint16
		ttl        uint32
		minimum    uint32
		additional bool
		malformed  bool
	}
	tests := []struct {
		name       string
		rcode      int
		values     [][][]byte
		soa        *soaSpec
		wantErr    bool
		wantValues []string
	}{
		{name: "valid nodata", soa: &soaSpec{owner: "example.test.", class: 1, ttl: 300, minimum: 45}},
		{name: "valid nxdomain", rcode: 3, soa: &soaSpec{owner: "example.test.", class: 1, ttl: 300, minimum: 45}},
		{name: "missing soa", wantErr: true},
		{name: "nxdomain missing soa", rcode: 3, wantErr: true},
		{name: "soa only in additional", soa: &soaSpec{owner: "example.test.", class: 1, ttl: 300, minimum: 45, additional: true}, wantErr: true},
		{name: "wrong owner", soa: &soaSpec{owner: "unrelated.test.", class: 1, ttl: 300, minimum: 45}, wantErr: true},
		{name: "wrong class", soa: &soaSpec{owner: "example.test.", class: 3, ttl: 300, minimum: 45}, wantErr: true},
		{name: "zero rr ttl", soa: &soaSpec{owner: "example.test.", class: 1, minimum: 45}, wantErr: true},
		{name: "zero minimum", soa: &soaSpec{owner: "example.test.", class: 1, ttl: 300}, wantErr: true},
		{name: "negative ttl above bound", soa: &soaSpec{owner: "example.test.", class: 1, ttl: 7*24*60*60 + 1, minimum: 7*24*60*60 + 1}, wantErr: true},
		{name: "malformed soa", soa: &soaSpec{owner: "example.test.", class: 1, ttl: 300, minimum: 45, malformed: true}, wantErr: true},
		{name: "positive txt unchanged", values: [][][]byte{{[]byte("present")}}, wantValues: []string{"present"}},
		{name: "servfail remains non absence", rcode: 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			dns := newWireDNS(func(_ context.Context, _ string, _ Endpoint, request []byte) ([]byte, error) {
				response := txtResponseFlags(request, false, true, test.rcode, test.values)
				if test.soa == nil {
					return response, nil
				}
				soaOwner, err := encodeDNSName(test.soa.owner)
				if err != nil {
					t.Fatal(err)
				}
				primary, err := encodeDNSName("ns1.example.test.")
				if err != nil {
					t.Fatal(err)
				}
				mailbox, err := encodeDNSName("hostmaster.example.test.")
				if err != nil {
					t.Fatal(err)
				}
				rdata := append(append([]byte(nil), primary...), mailbox...)
				for _, value := range []uint32{1, 2, 3, 4, test.soa.minimum} {
					rdata = binary.BigEndian.AppendUint32(rdata, value)
				}
				if test.soa.malformed {
					rdata = rdata[:len(rdata)-1]
				}
				record := append([]byte(nil), soaOwner...)
				record = binary.BigEndian.AppendUint16(record, 6)
				record = binary.BigEndian.AppendUint16(record, test.soa.class)
				record = binary.BigEndian.AppendUint32(record, test.soa.ttl)
				record = binary.BigEndian.AppendUint16(record, uint16(len(rdata)))
				record = append(record, rdata...)
				if test.soa.additional {
					binary.BigEndian.PutUint16(response[10:12], 1)
				} else {
					binary.BigEndian.PutUint16(response[8:10], 1)
				}
				return append(response, record...), nil
			}, bytes.NewReader([]byte{0x61, 0x62}))

			observation, err := dns.LookupTXT(t.Context(), Endpoint{
				Address: netip.MustParseAddrPort("198.51.100.53:53"),
			}, owner)
			if test.wantErr {
				if !errors.Is(err, ErrDNSInvalidResponse) {
					t.Fatalf("LookupTXT() error=%v, want %v", err, ErrDNSInvalidResponse)
				}
				return
			}
			if err != nil || observation.RCode != uint8(test.rcode) ||
				!slices.Equal(observation.Values, test.wantValues) {
				t.Fatalf("LookupTXT()=(%+v,%v)", observation, err)
			}
		})
	}
}
