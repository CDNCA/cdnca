package site

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/google/uuid"
)

// fix-transfer: the new site keeps the old one's basic settings; the package
// is the target user's choice (or none), so the CNAME is allocated again.
func TestTransferFieldsCopyBasicSettings(t *testing.T) {
	force, port, shared, status, prefer := true, 8443, true, false, true
	preset, auth := "custom", "off"
	packageID, subscription, group := uuid.New(), uuid.New(), uuid.New()
	mode, cnameDomain, hostname := "site", "cdn.example", "abc"
	current := Site{
		Domain: "a.example", Domains: []string{"a.example", "www.a.example"},
		HTTPPorts: []string{"80"}, HTTPSPorts: []string{"443"}, Origins: []string{"192.0.2.1:80"},
		TLSProtocols: []string{"TLSv1.2", "TLSv1.3"}, TLSCipherPreset: preset, TLSCipherSuites: []string{"ECDHE-RSA-AES128-GCM-SHA256"},
		TLSOCSPStapling: true, TLSClientAuth: auth, HTTPSEnabled: true, ForceHTTPS: force, HTTPSRedirectPort: port,
		HTTP2Enabled: true, HTTP3Enabled: false, TLSPreferServerCiphers: &prefer,
		CacheSharedAcrossDomains: shared, CacheStatusHeader: status, Enabled: true,
		ListenerState: ListenerState{IPv6DesiredEnabled: true},
		PackageID:     &packageID, PackageSubscriptionID: &subscription, GroupID: &group,
		CNAMEMode: &mode, CNAMEDomain: &cnameDomain, CNAMEHostname: &hostname, IsDefault: true,
	}
	target := uuid.New()
	fields := transferFields(current, &target, true)
	if fields.Domain != "a.example" || !reflect.DeepEqual(fields.Domains, current.Domains) ||
		!reflect.DeepEqual(fields.HTTPSPorts, []string{"443"}) || !reflect.DeepEqual(fields.Origins, current.Origins) ||
		!fields.HTTPSEnabled || !fields.Enabled || !fields.IPv6Enabled || fields.IPv6Omitted {
		t.Fatalf("basic fields not copied: %+v", fields)
	}
	if fields.ForceHTTPS == nil || !*fields.ForceHTTPS || *fields.HTTPSRedirectPort != 8443 ||
		*fields.CacheSharedAcrossDomains != true || *fields.CacheStatusHeader != false ||
		*fields.HTTP2Enabled != true || *fields.HTTP3Enabled != false || *fields.TLSPreferServerCiphers != true ||
		*fields.TLSCipherPreset != "custom" || !reflect.DeepEqual(fields.TLSCipherSuites, current.TLSCipherSuites) ||
		*fields.TLSOCSPStapling != true || *fields.TLSClientAuth != "off" {
		t.Fatalf("site options not copied: %+v", fields)
	}
	if fields.PackageSubscriptionID == nil || *fields.PackageSubscriptionID != target || fields.PackageID != nil {
		t.Fatalf("package must be the target subscription: %+v", fields)
	}
	if fields.CNAMEMode != "" || fields.CNAMEDomain != "" || fields.CNAMEHostname != "" || fields.IsDefault || fields.GroupID != nil {
		t.Fatalf("CNAME / default / group must not be carried over: %+v", fields)
	}
	if none := transferFields(current, nil, true); none.PackageSubscriptionID != nil || none.PackageID != nil {
		t.Fatalf("no package requested: %+v", none)
	}
	// The certificate is not carried: HTTPS, forced HTTPS and HTTP/3 off
	// (normalizeFields refuses forced HTTPS without HTTPS).
	plain := transferFields(current, nil, false)
	if plain.HTTPSEnabled || len(plain.HTTPSPorts) != 0 || *plain.ForceHTTPS || *plain.HTTP3Enabled ||
		plain.HTTPSRedirectPort != nil {
		t.Fatalf("HTTPS without the certificate: %+v", plain)
	}
}

func TestTransferRejectsInvalidRequests(t *testing.T) {
	service := NewService(nil)
	platform := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform"}
	valid := TransferRequest{ID: uuid.New(), ExpectedRevision: 1, TargetUserID: uuid.New(),
		IdempotencyKey: "k", RequestID: "r"}
	tenant := platform
	tenant.ScopeKind = "tenant"
	if _, err := service.Transfer(context.Background(), tenant, valid); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("tenant actor: %v", err)
	}
	for name, mutate := range map[string]func(*TransferRequest){
		"no site":     func(r *TransferRequest) { r.ID = uuid.Nil },
		"no revision": func(r *TransferRequest) { r.ExpectedRevision = 0 },
		"no target":   func(r *TransferRequest) { r.TargetUserID = uuid.Nil },
		"no key":      func(r *TransferRequest) { r.IdempotencyKey = "" },
	} {
		request := valid
		mutate(&request)
		if _, err := service.Transfer(context.Background(), platform, request); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
