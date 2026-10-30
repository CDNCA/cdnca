package edgepublish

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
)

func TestSITE15PublicationTLSFactsFailClosed(t *testing.T) {
	for _, protocols := range [][]string{
		nil,
		{},
		{"SSLv2", "TLSv1.2", "TLSv1.3"},
		{"SSLv3", "TLSv1.2", "TLSv1.3"},
		{"TLSv1", "TLSv1.2", "TLSv1.3"}, // a gap
		{"TLSv1.2", "TLSv1.4"},
		{"TLSv1.3", "TLSv1.2"},
	} {
		if _, err := validateSiteTLSProtocols(protocols); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("validateSiteTLSProtocols(%#v) error = %v, want ErrInvalidInput", protocols, err)
		}
	}
	for _, protocols := range [][]string{{"TLSv1.2", "TLSv1.3"}, {"TLSv1.3"}, {"TLSv1.1", "TLSv1.2", "TLSv1.3"}} {
		valid, err := validateSiteTLSProtocols(protocols)
		if err != nil || !slices.Equal(valid, protocols) {
			t.Fatalf("TLS fact %v = %#v, %v", protocols, valid, err)
		}
	}
}

func TestSITE15CanonicalTLSFactEntersSignedSnapshot(t *testing.T) {
	fact := siteFact{
		id: uuid.New(), revision: 7, domain: "tls.example.test", tlsProtocols: []string{"TLSv1.2", "TLSv1.3"},
		balance: string(edgeconfig.BalanceRoundRobin), failoverTries: 1,
		connectTimeoutMS: 3000, readTimeoutMS: 30000,
		origins: []snapshotOrigin{{Host: "192.0.2.10", Port: 8080, Weight: 1}},
	}
	snapshot, _, err := compileSiteFact(uuid.New(), fact, 80, nil, nil, nil)
	if err != nil {
		t.Fatalf("compileSiteFact(, nil) error = %v", err)
	}
	if !slices.Equal(snapshot.TLSProtocols, fact.tlsProtocols) {
		t.Fatalf("snapshot TLSProtocols = %#v, want %#v", snapshot.TLSProtocols, fact.tlsProtocols)
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil || !strings.Contains(string(encoded), `"tls_protocols":["TLSv1.2","TLSv1.3"]`) {
		t.Fatalf("signed snapshot lacks canonical TLS fact: %s, %v", encoded, err)
	}
}

func TestSITE15RuntimeV2TLSProtocolContract(t *testing.T) {
	canonical := strings.Replace(string(siteRuntimeV2DocumentFixture()),
		`"certificate_version_id":"018f47a2-5b9c-7d31-8a60-104c9c0b7104"`,
		`"certificate_version_id":"018f47a2-5b9c-7d31-8a60-104c9c0b7104","protocols":["TLSv1.2","TLSv1.3"]`, 1)
	if _, _, _, _, err := compileSiteRuntimeV2Document([]byte(canonical)); err != nil {
		t.Fatalf("canonical runtime-v2 TLS protocols rejected: %v", err)
	}
	legacy := strings.Replace(canonical, `"TLSv1.2","TLSv1.3"`, `"TLSv1.1","TLSv1.2","TLSv1.3"`, 1)
	if _, _, _, _, err := compileSiteRuntimeV2Document([]byte(legacy)); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("legacy runtime-v2 TLS protocols error = %v, want ErrInvalidInput", err)
	}
}

func TestRuntimeV2TLSProfileContract(t *testing.T) {
	fixture := string(siteRuntimeV2DocumentFixture())
	certificate := `"certificate_version_id":"018f47a2-5b9c-7d31-8a60-104c9c0b7104"`
	ref := `"sha256:` + strings.Repeat("c", 64) + `"`
	for name, test := range map[string]struct {
		tls string
		ok  bool
	}{
		"legacy range with legacy preset": {`"cipher_preset":"legacy","protocols":["TLSv1","TLSv1.1","TLSv1.2","TLSv1.3"]`, true},
		"compatible and stapling":         {`"cipher_preset":"compatible","ocsp_stapling":true,"protocols":["TLSv1.2","TLSv1.3"]`, true},
		"client verification":             {`"client_auth":"required","client_ca_ref":` + ref + `,"protocols":["TLSv1.2","TLSv1.3"]`, true},
		"client verification without CA":  {`"client_auth":"required","protocols":["TLSv1.2","TLSv1.3"]`, false},
		"unknown preset":                  {`"cipher_preset":"custom","protocols":["TLSv1.2","TLSv1.3"]`, false},
		// The fixture listener serves http3: QUIC needs TLSv1.3.
		"http3 without TLSv1.3": {`"protocols":["TLSv1.2"]`, false},
	} {
		t.Run(name, func(t *testing.T) {
			document := strings.Replace(fixture, certificate, certificate+","+test.tls, 1)
			_, _, _, _, err := compileSiteRuntimeV2Document([]byte(document))
			if test.ok != (err == nil) {
				t.Fatalf("compileSiteRuntimeV2Document() error = %v, want ok=%v", err, test.ok)
			}
		})
	}
}

func TestSiteFactTLSProfileLeavesBaselineEmpty(t *testing.T) {
	profile, err := siteFactTLSProfile(siteFact{tlsProtocols: []string{"TLSv1.2", "TLSv1.3"},
		tlsCipherPreset: edgeconfig.TLSCipherModern, tlsClientAuth: edgeconfig.ClientAuthOff})
	if err != nil || profile.CipherPreset != "" || profile.ClientAuth != "" || profile.OCSPStapling || !profile.Baseline() {
		t.Fatalf("baseline profile = %+v, %v", profile, err)
	}
	if _, err := siteFactTLSProfile(siteFact{tlsProtocols: []string{"TLSv1.2", "TLSv1.3"},
		tlsCipherPreset: edgeconfig.TLSCipherModern, tlsClientAuth: edgeconfig.ClientAuthRequired, tlsClientCAPEM: "garbage"}); err == nil {
		t.Fatal("an invalid stored client CA was published")
	}
}
