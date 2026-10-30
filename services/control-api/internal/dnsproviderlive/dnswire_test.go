package dnsproviderlive

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestWireDNSParsesAuthoritativeMultiTXT(t *testing.T) {
	t.Parallel()
	endpoint := Endpoint{Address: netip.MustParseAddrPort("192.0.2.53:53")}
	dns := newWireDNS(func(_ context.Context, network string, got Endpoint, request []byte) ([]byte, error) {
		if network != "udp" || got != endpoint {
			t.Fatalf("exchange=(%q,%v), want udp,%v", network, got, endpoint)
		}
		return txtResponse(request, true, 0, [][][]byte{
			{[]byte("first"), []byte("-joined")},
			{[]byte("second")},
		}), nil
	}, bytes.NewReader([]byte{0x12, 0x34}))

	observation, err := dns.LookupTXT(t.Context(), endpoint, "_live.example.test.")
	if err != nil {
		t.Fatalf("LookupTXT() error=%v", err)
	}
	if !observation.Authoritative || observation.Recursive || observation.RCode != 0 ||
		!slices.Equal(observation.Values, []string{"first-joined", "second"}) {
		t.Fatalf("LookupTXT()=%+v", observation)
	}
}

func TestWireDNSPreservesAuthoritativeAndRecursionAvailableFlags(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		authoritative bool
		recursive     bool
	}{
		{name: "neither"},
		{name: "authoritative only", authoritative: true},
		{name: "public recursive", recursive: true},
		{name: "both", authoritative: true, recursive: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			dns := newWireDNS(func(_ context.Context, _ string, _ Endpoint, request []byte) ([]byte, error) {
				return txtResponseFlags(request, test.authoritative, test.recursive, 0, [][][]byte{{[]byte("value")}}), nil
			}, bytes.NewReader([]byte{0x31, 0x32}))
			observation, err := dns.LookupTXT(t.Context(), Endpoint{Address: netip.MustParseAddrPort("198.51.100.53:53")}, "_live.example.test.")
			if err != nil || observation.Authoritative != test.authoritative || observation.Recursive != test.recursive {
				t.Fatalf("flags=(AA=%v,RA=%v) error=%v", observation.Authoritative, observation.Recursive, err)
			}
		})
	}
}

func TestWireDNSDoesNotAcceptAuthoritativeNonRecursiveResponseAsPublicRole(t *testing.T) {
	t.Parallel()
	dns := newWireDNS(func(_ context.Context, _ string, _ Endpoint, request []byte) ([]byte, error) {
		return txtResponseFlags(request, true, false, 0, [][][]byte{{[]byte("value")}}), nil
	}, bytes.NewReader([]byte{0x41, 0x42}))
	observation, err := dns.LookupTXT(t.Context(), Endpoint{Address: netip.MustParseAddrPort("198.51.100.54:53")}, "_live.example.test.")
	if err != nil {
		t.Fatalf("LookupTXT() error=%v", err)
	}
	if !observation.Authoritative || observation.Recursive {
		t.Fatalf("flags=(AA=%v,RA=%v)", observation.Authoritative, observation.Recursive)
	}
	if !observation.Authoritative && observation.Recursive {
		t.Fatal("authoritative non-recursive response accepted as public role")
	}
}

func TestWireDNSNXDOMAINAndNODATA(t *testing.T) {
	t.Parallel()
	soaOwner, err := encodeDNSName("example.test.")
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
	for _, test := range []struct {
		name  string
		rcode int
	}{
		{name: "nodata", rcode: 0},
		{name: "nxdomain", rcode: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			dns := newWireDNS(func(_ context.Context, _ string, _ Endpoint, request []byte) ([]byte, error) {
				response := txtResponse(request, false, test.rcode, nil)
				binary.BigEndian.PutUint16(response[8:10], 1)
				rdata := append(append([]byte(nil), primary...), mailbox...)
				for _, value := range []uint32{1, 2, 3, 4, 45} {
					rdata = binary.BigEndian.AppendUint32(rdata, value)
				}
				record := append([]byte(nil), soaOwner...)
				record = binary.BigEndian.AppendUint16(record, 6)
				record = binary.BigEndian.AppendUint16(record, 1)
				record = binary.BigEndian.AppendUint32(record, 300)
				record = binary.BigEndian.AppendUint16(record, uint16(len(rdata)))
				return append(append(response, record...), rdata...), nil
			}, bytes.NewReader([]byte{0x01, 0x02}))
			got, err := dns.LookupTXT(t.Context(), Endpoint{Address: netip.MustParseAddrPort("198.51.100.53:53")}, "missing.example.test.")
			if err != nil || got.RCode != uint8(test.rcode) || len(got.Values) != 0 || got.Authoritative {
				t.Fatalf("LookupTXT()=%+v error=%v", got, err)
			}
		})
	}
}

func TestWireDNSFallsBackToTCPOnTruncation(t *testing.T) {
	t.Parallel()
	var networks []string
	dns := newWireDNS(func(_ context.Context, network string, _ Endpoint, request []byte) ([]byte, error) {
		networks = append(networks, network)
		if network == "udp" {
			response := txtResponse(request, true, 0, nil)
			binary.BigEndian.PutUint16(response[2:4], binary.BigEndian.Uint16(response[2:4])|0x0200)
			return response, nil
		}
		return txtResponse(request, true, 0, [][][]byte{{[]byte("tcp-value")}}), nil
	}, bytes.NewReader([]byte{0x22, 0x33}))

	got, err := dns.LookupTXT(t.Context(), Endpoint{Address: netip.MustParseAddrPort("203.0.113.53:53")}, "_live.example.test.")
	if err != nil || !slices.Equal(got.Values, []string{"tcp-value"}) {
		t.Fatalf("LookupTXT()=%+v error=%v", got, err)
	}
	if !slices.Equal(networks, []string{"udp", "tcp"}) {
		t.Fatalf("networks=%v", networks)
	}
}

func TestWireDNSRejectsMalformedResponses(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(request, response []byte) []byte
	}{
		{name: "short", mutate: func(_, _ []byte) []byte { return []byte{1, 2, 3} }},
		{name: "bad id", mutate: func(_, response []byte) []byte { response[0] ^= 0xff; return response }},
		{name: "not response", mutate: func(_, response []byte) []byte { response[2] &^= 0x80; return response }},
		{name: "bad opcode", mutate: func(_, response []byte) []byte { response[2] |= 0x08; return response }},
		{name: "bad question type", mutate: func(request, response []byte) []byte {
			response[12+len(request)-12-4] = 0
			response[12+len(request)-12-3] = 1
			return response
		}},
		{name: "bad question name", mutate: func(_, response []byte) []byte { response[13] ^= 1; return response }},
		{name: "truncated rdata", mutate: func(_, response []byte) []byte { return response[:len(response)-1] }},
		{name: "trailing bytes", mutate: func(_, response []byte) []byte { return append(response, 0) }},
		{name: "duplicate value", mutate: func(request, _ []byte) []byte {
			return txtResponse(request, true, 0, [][][]byte{{[]byte("same")}, {[]byte("same")}})
		}},
		{name: "unexpected answer", mutate: func(request, _ []byte) []byte {
			return answerResponse(request, 1, []byte{192, 0, 2, 1})
		}},
		{name: "compression loop", mutate: func(request, response []byte) []byte {
			answerOffset := 12 + len(request) - 12
			binary.BigEndian.PutUint16(response[answerOffset:answerOffset+2], uint16(0xc000|answerOffset))
			return response
		}},
		{name: "compression pointer into header", mutate: func(request, response []byte) []byte {
			answerOffset := 12 + len(request) - 12
			binary.BigEndian.PutUint16(response[answerOffset:answerOffset+2], 0xc000)
			return response
		}},
		{name: "compression pointer out of bounds", mutate: func(request, response []byte) []byte {
			answerOffset := 12 + len(request) - 12
			binary.BigEndian.PutUint16(response[answerOffset:answerOffset+2], 0xffff)
			return response
		}},
		{name: "oversize", mutate: func(_, response []byte) []byte {
			return append(response, make([]byte, maxDNSMessageSize-len(response)+1)...)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			dns := newWireDNS(func(_ context.Context, _ string, _ Endpoint, request []byte) ([]byte, error) {
				response := txtResponse(request, true, 0, [][][]byte{{[]byte("value")}})
				return test.mutate(request, response), nil
			}, bytes.NewReader([]byte{0xab, 0xcd}))
			if _, err := dns.LookupTXT(t.Context(), Endpoint{Address: netip.MustParseAddrPort("192.0.2.1:53")}, "_live.example.test."); err == nil {
				t.Fatal("LookupTXT() error=nil")
			}
		})
	}
}

func TestWireDNSRejectsInvalidInputAndCancellation(t *testing.T) {
	t.Parallel()
	called := false
	dns := newWireDNS(func(context.Context, string, Endpoint, []byte) ([]byte, error) {
		called = true
		return nil, errors.New("must not be called")
	}, bytes.NewReader([]byte{1, 2}))
	if _, err := dns.LookupTXT(t.Context(), Endpoint{}, "_live.example.test."); err == nil {
		t.Fatal("zero endpoint accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := dns.LookupTXT(ctx, Endpoint{Address: netip.MustParseAddrPort("192.0.2.1:53")}, "_live.example.test."); !errors.Is(err, context.Canceled) {
		t.Fatalf("LookupTXT() error=%v", err)
	}
	if called {
		t.Fatal("exchange called for rejected input")
	}
}

func TestLoadCredentialStrictSchemasAndZeroesRawBuffer(t *testing.T) {
	t.Parallel()
	valid := map[string]struct {
		document      string
		field         string
		expectedValue string
	}{
		"cloudflare": {
			document:      " \n" + `{"api_\u0074oken":"quote\"-slash\/-backslash\\-euro\u20ac-emoji\ud83d\ude00"}` + "\t ",
			field:         "api_token",
			expectedValue: "quote\"-slash/-backslash\\-euro€-emoji😀",
		},
		"aliyun":    {document: `{"access_key_id":"id","access_key_secret":"secret"}`, field: "access_key_secret", expectedValue: "secret"},
		"huawei":    {document: `{"access_key":"id","secret_key":"secret","region":"cn-test-1","project_id":"project"}`, field: "secret_key", expectedValue: "secret"},
		"dnspod_cn": {document: `{"dp_id":"123","dp_key":"secret"}`, field: "dp_key", expectedValue: "secret"},
		"dns_com":   {document: `{"api_key":"id","api_secret":"secret"}`, field: "api_secret", expectedValue: "secret"},
		"dns_la":    {document: `{"api_id":"123","api_secret":"secret"}`, field: "api_secret", expectedValue: "secret"},
	}
	for provider, fixture := range valid {
		provider, fixture := provider, fixture
		t.Run(provider, func(t *testing.T) {
			t.Parallel()
			raw := []byte(fixture.document)
			lease, err := LoadCredential(func(service, account string) ([]byte, error) {
				if service != "service-alias" || account != "account-alias" {
					t.Fatal("alias mismatch")
				}
				return raw, nil
			}, provider, "service-alias", "account-alias")
			if err != nil || lease == nil || lease.Values[fixture.field] != fixture.expectedValue {
				t.Fatalf("LoadCredential() failed: %v", err)
			}
			backing := lease.backing
			retainedView := lease.Values[fixture.field]
			clonedViews := cloneStringHeaders(lease.Values)
			lease.Close()
			lease.Close()
			if !allZero(raw) || !allZero(backing) || len(lease.Values) != 0 {
				t.Fatal("credential lease backing was not zeroed and cleared")
			}
			if !allStringZero(retainedView) || !allStringZero(clonedViews[fixture.field]) {
				t.Fatal("retained credential views did not observe zeroed backing")
			}
		})
	}
}

func TestLoadCredentialRejectsMalformedWithoutLeakingRawError(t *testing.T) {
	t.Parallel()
	tests := []string{
		``,
		`[]`,
		`{"api_token":"one","api_token":"two"}`,
		`{"api_\u0074oken":"one","api_token":"two"}`,
		`{"api_token":"one","extra":"two"}`,
		`{}`,
		`{"api_token":1}`,
		"{\"api_token\":\"line\\nfeed\"}",
		`{"api_token":"bad\xescape"}`,
		`{"api_token":"bad\u12xz"}`,
		`{"api_token":"bad\ud800"}`,
		`{"api_token":"bad\udc00"}`,
		`{"api_token":"one"} trailing`,
		"{\"api_token\":\"" + string([]byte{0xff}) + "\"}",
		strings.Repeat("x", maxDNSMessageSize+1),
	}
	for _, document := range tests {
		document := document
		t.Run(document, func(t *testing.T) {
			t.Parallel()
			raw := []byte(document)
			if _, err := LoadCredential(func(string, string) ([]byte, error) { return raw, nil }, "cloudflare", "service", "account"); !errors.Is(err, ErrCredentialUnavailable) {
				t.Fatalf("LoadCredential() error=%v", err)
			}
			if !allZero(raw) {
				t.Fatal("rejected raw keychain buffer was not zeroed")
			}
		})
	}
	sentinel := "SENTINEL-KEYCHAIN-SECRET"
	raw := []byte(`{"api_token":"must-zero-on-reader-error"}`)
	_, err := LoadCredential(func(string, string) ([]byte, error) { return raw, errors.New(sentinel) }, "cloudflare", "service", "account")
	if !errors.Is(err, ErrCredentialUnavailable) || bytes.Contains([]byte(err.Error()), []byte(sentinel)) {
		t.Fatalf("raw error leaked: %v", err)
	}
	if !allZero(raw) {
		t.Fatal("reader error raw buffer was not zeroed")
	}
	providerRaw := []byte(`{"api_id":"bad:id","api_secret":"secret"}`)
	if _, err := LoadCredential(func(string, string) ([]byte, error) { return providerRaw, nil }, "dns_la", "service", "account"); !errors.Is(err, ErrCredentialUnavailable) {
		t.Fatalf("provider-specific invalid credential error=%v", err)
	}
	if !allZero(providerRaw) {
		t.Fatal("provider-specific rejected buffer was not zeroed")
	}
}

func txtResponse(request []byte, authoritative bool, rcode int, values [][][]byte) []byte {
	return txtResponseFlags(request, authoritative, false, rcode, values)
}

func txtResponseFlags(request []byte, authoritative, recursive bool, rcode int, values [][][]byte) []byte {
	flags := uint16(0x8000 | rcode)
	if authoritative {
		flags |= 0x0400
	}
	if recursive {
		flags |= 0x0080
	}
	response := make([]byte, 12)
	copy(response[0:2], request[0:2])
	binary.BigEndian.PutUint16(response[2:4], flags)
	binary.BigEndian.PutUint16(response[4:6], 1)
	binary.BigEndian.PutUint16(response[6:8], uint16(len(values)))
	response = append(response, request[12:]...)
	for _, strings := range values {
		response = append(response, 0xc0, 0x0c, 0, 16, 0, 1, 0, 0, 0, 30)
		var rdata []byte
		for _, part := range strings {
			rdata = append(rdata, byte(len(part)))
			rdata = append(rdata, part...)
		}
		response = binary.BigEndian.AppendUint16(response, uint16(len(rdata)))
		response = append(response, rdata...)
	}
	return response
}

func cloneStringHeaders(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for name, value := range values {
		result[name] = value
	}
	return result
}

func allStringZero(value string) bool {
	for index := range len(value) {
		if value[index] != 0 {
			return false
		}
	}
	return true
}

func answerResponse(request []byte, recordType uint16, rdata []byte) []byte {
	response := txtResponse(request, true, 0, nil)
	binary.BigEndian.PutUint16(response[6:8], 1)
	response = append(response, 0xc0, 0x0c)
	response = binary.BigEndian.AppendUint16(response, recordType)
	response = binary.BigEndian.AppendUint16(response, 1)
	response = binary.BigEndian.AppendUint32(response, 30)
	response = binary.BigEndian.AppendUint16(response, uint16(len(rdata)))
	return append(response, rdata...)
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
