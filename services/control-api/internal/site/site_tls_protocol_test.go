package site

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestNormalizeFieldsTLSProtocols(t *testing.T) {
	fields := validTLSProtocolFields()
	if err := normalizeFields(&fields); err != nil || !reflect.DeepEqual(fields.TLSProtocols, CanonicalTLSProtocols()) ||
		!fields.tlsProtocolsDefaulted {
		t.Fatalf("nil protocols: %v %#v", err, fields.TLSProtocols)
	}
	for _, protocols := range [][]string{
		{TLSProtocol12, TLSProtocol13}, {TLSProtocol13}, {TLSProtocol12},
		{"TLSv1", "TLSv1.1", TLSProtocol12, TLSProtocol13},
	} {
		fields := validTLSProtocolFields()
		fields.TLSProtocols = slices.Clone(protocols)
		if err := normalizeFields(&fields); err != nil {
			t.Fatalf("normalizeFields(%#v) error = %v", protocols, err)
		}
		if !reflect.DeepEqual(fields.TLSProtocols, protocols) || fields.tlsProtocolsDefaulted {
			t.Fatalf("TLSProtocols = %#v, want %#v", fields.TLSProtocols, protocols)
		}
	}
}

func TestNormalizeFieldsRejectsSSLProtocols(t *testing.T) {
	for _, legacy := range []string{"SSLv2", "SSLv3"} {
		t.Run(legacy, func(t *testing.T) {
			fields := validTLSProtocolFields()
			fields.TLSProtocols = []string{legacy, TLSProtocol12, TLSProtocol13}
			if err := normalizeFields(&fields); !errors.Is(err, ErrTLSLegacyProtocolBlocked) {
				t.Fatalf("normalizeFields() error = %v, want ErrTLSLegacyProtocolBlocked", err)
			}
		})
	}
}

func TestNormalizeFieldsRejectsNonRangeTLSProtocols(t *testing.T) {
	for _, test := range []struct {
		name      string
		protocols []string
	}{
		{name: "empty", protocols: []string{}},
		{name: "gap", protocols: []string{"TLSv1", TLSProtocol13}},
		{name: "reordered", protocols: []string{TLSProtocol13, TLSProtocol12}},
		{name: "duplicate", protocols: []string{TLSProtocol12, TLSProtocol12}},
		{name: "unknown", protocols: []string{TLSProtocol12, "TLSv1.4"}},
		{name: "noncanonical spelling", protocols: []string{"tlsv1.2", TLSProtocol13}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fields := validTLSProtocolFields()
			fields.TLSProtocols = test.protocols
			if err := normalizeFields(&fields); !errors.Is(err, ErrTLSProtocolsInvalid) {
				t.Fatalf("normalizeFields() error = %v, want ErrTLSProtocolsInvalid", err)
			}
		})
	}
}

func TestNormalizeFieldsTLSProfile(t *testing.T) {
	ca := testClientCAPEM(t)
	text := func(value string) *string { return &value }
	for name, test := range map[string]struct {
		mutate func(*SiteFields)
		ok     bool
	}{
		"compatible":          {func(f *SiteFields) { f.TLSCipherPreset = text("compatible") }, true},
		"unknown preset":      {func(f *SiteFields) { f.TLSCipherPreset = text("strong") }, false},
		"custom without list": {func(f *SiteFields) { f.TLSCipherPreset = text("custom") }, false},
		"custom": {func(f *SiteFields) {
			f.TLSCipherPreset, f.TLSCipherSuites = text("custom"), []string{"ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-ECDSA-AES128-GCM-SHA256"}
		}, true},
		"custom off whitelist": {func(f *SiteFields) {
			f.TLSCipherPreset, f.TLSCipherSuites = text("custom"), []string{"ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-ECDSA-AES128-GCM-SHA256", "DES-CBC3-SHA"}
		}, false},
		"custom without TLSv1.2": {func(f *SiteFields) {
			f.TLSProtocols = []string{"TLSv1.3"}
			f.TLSCipherPreset, f.TLSCipherSuites = text("custom"), []string{"ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-ECDSA-AES128-GCM-SHA256"}
		}, false},
		"custom with TLSv1.1": {func(f *SiteFields) {
			f.TLSProtocols = []string{"TLSv1.1", "TLSv1.2"}
			f.TLSCipherPreset, f.TLSCipherSuites = text("custom"), []string{"ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-ECDSA-AES128-GCM-SHA256"}
		}, false},
		"suites with modern": {func(f *SiteFields) {
			f.TLSCipherPreset, f.TLSCipherSuites = text("modern"), []string{"ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-ECDSA-AES128-GCM-SHA256"}
		}, false},
		"suites without preset": {func(f *SiteFields) { f.TLSCipherSuites = []string{"ECDHE-RSA-AES128-GCM-SHA256"} }, false},
		"legacy versions modern": {func(f *SiteFields) {
			f.TLSProtocols = []string{"TLSv1.1", "TLSv1.2"}
			f.TLSCipherPreset = text("modern")
		}, false},
		"legacy versions legacy": {func(f *SiteFields) {
			f.TLSProtocols = []string{"TLSv1.1", "TLSv1.2"}
			f.TLSCipherPreset = text("legacy")
		}, true},
		"required with CA":    {func(f *SiteFields) { f.TLSClientAuth = text("required"); f.TLSClientCAPEM = text(ca) }, true},
		"required without CA": {func(f *SiteFields) { f.TLSClientAuth = text("required") }, false},
		"CA without auth":     {func(f *SiteFields) { f.TLSClientCAPEM = text(ca) }, false},
		"off with CA":         {func(f *SiteFields) { f.TLSClientAuth = text("off"); f.TLSClientCAPEM = text(ca) }, false},
		"bad CA":              {func(f *SiteFields) { f.TLSClientAuth = text("optional"); f.TLSClientCAPEM = text("not pem") }, false},
		"unknown auth":        {func(f *SiteFields) { f.TLSClientAuth = text("sometimes"); f.TLSClientCAPEM = text(ca) }, false},
	} {
		t.Run(name, func(t *testing.T) {
			fields := validTLSProtocolFields()
			test.mutate(&fields)
			err := normalizeFields(&fields)
			if test.ok != (err == nil) || err != nil && !errors.Is(err, ErrTLSProfileInvalid) {
				t.Fatalf("normalizeFields() error = %v, want ok=%v", err, test.ok)
			}
		})
	}
	fields := validTLSProtocolFields()
	fields.TLSClientAuth = text("off")
	if err := normalizeFields(&fields); err != nil || fields.TLSClientCAPEM == nil || *fields.TLSClientCAPEM != "" {
		t.Fatalf("off clears the stored CA: %v %v", err, fields.TLSClientCAPEM)
	}
}

func TestSiteReadProjectionPreservesTLSProtocolFactsForRemediation(t *testing.T) {
	for _, protocols := range [][]string{
		{"SSLv2", TLSProtocol12, TLSProtocol13},
		{"SSLv3", TLSProtocol12, TLSProtocol13},
		{"TLSv1", TLSProtocol12, TLSProtocol13},
		{"TLSv1.1", TLSProtocol12, TLSProtocol13},
		{TLSProtocol12, "TLSv1.4"},
		CanonicalTLSProtocols(),
	} {
		item := Site{TLSProtocols: append([]string(nil), protocols...)}
		redact(&item, "tenant")
		if !reflect.DeepEqual(item.TLSProtocols, protocols) {
			t.Fatalf("redact TLSProtocols = %#v, want durable fact %#v", item.TLSProtocols, protocols)
		}
	}
}

func TestSiteColumnsReadDurableTLSProtocolFact(t *testing.T) {
	columns := siteColumns("s")
	if !strings.Contains(columns, "s.tls_protocols") {
		t.Fatalf("siteColumns() does not read durable TLS fact: %s", columns)
	}
}

func TestSiteWritesRejectTLSProtocolsBeforeStoreAccess(t *testing.T) {
	service := NewService(NewStore(nil))
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"}

	legacy := validTLSProtocolFields()
	legacy.TLSProtocols = []string{"SSLv3", TLSProtocol12, TLSProtocol13}
	if _, err := service.Create(t.Context(), actor, CreateRequest{
		Fields: legacy, IdempotencyKey: "site-tls-create", RequestID: "site-tls-create-request",
	}); !errors.Is(err, ErrTLSLegacyProtocolBlocked) {
		t.Fatalf("Create() error = %v, want ErrTLSLegacyProtocolBlocked before store access", err)
	}

	gap := validTLSProtocolFields()
	gap.TLSProtocols = []string{"TLSv1", TLSProtocol13}
	if _, err := service.Update(t.Context(), actor, UpdateRequest{
		ID: uuid.New(), ExpectedRevision: 1, Fields: gap,
		IdempotencyKey: "site-tls-update", RequestID: "site-tls-update-request",
	}); !errors.Is(err, ErrTLSProtocolsInvalid) {
		t.Fatalf("Update() error = %v, want ErrTLSProtocolsInvalid before store access", err)
	}
}

func testClientCAPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "site client ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func validTLSProtocolFields() SiteFields {
	return SiteFields{
		Domain:       "tls.example",
		HTTPPorts:    []string{"80"},
		HTTPSPorts:   []string{"443"},
		Origins:      []string{"192.0.2.10"},
		HTTPSEnabled: true,
		Enabled:      true,
	}
}
