package dnsacme

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// fakeApexResolver answers from a fixed hosted-domain list like a provider
// domain list would (retest-n1).
type fakeApexResolver struct {
	hosted []string
	err    error
	calls  int
}

func (resolver *fakeApexResolver) ResolveZoneApex(_ context.Context, _ string, _ map[string]string, zone string) (string, error) {
	resolver.calls++
	if resolver.err != nil {
		return "", resolver.err
	}
	best := ""
	for _, domain := range resolver.hosted {
		if (zone == domain || strings.HasSuffix(zone, "."+domain)) && len(domain) > len(best) {
			best = domain
		}
	}
	if best == "" {
		return "", &dnsproviderremote.Error{Code: dnsproviderremote.CodeZoneNotHosted}
	}
	return best, nil
}

type recordingExecer struct {
	sql  string
	args []any
}

func (execer *recordingExecer) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	execer.sql, execer.args = sql, args
	return pgconn.NewCommandTag("UPDATE 1"), nil
}

// Saving a CNAME zone: a subdomain zone stores its hosted apex, a zone that
// is the hosted domain stores itself, and a zone the account does not host
// is refused with ErrZoneNotHosted (HTTP dns_zone_not_hosted).
func TestSaveZoneApexFromProviderDomainList(t *testing.T) {
	service := NewService(nil, nil)
	service.UseZoneApexResolver(&fakeApexResolver{hosted: []string{"868yun.com"}})
	credentials := map[string]string{"dp_id": "1", "dp_key": "k"}
	for zone, want := range map[string]string{"cdn.868yun.com": "868yun.com", "868yun.com": "868yun.com"} {
		if got, err := service.zoneApex(context.Background(), "dnspod_cn", credentials, zone); err != nil || got != want {
			t.Fatalf("zoneApex(%q) = %q, %v; want %q", zone, got, err, want)
		}
	}
	if _, err := service.zoneApex(context.Background(), "dnspod_cn", credentials, "cdn.other.com"); !errors.Is(err, ErrZoneNotHosted) {
		t.Fatalf("not hosted err = %v, want ErrZoneNotHosted", err)
	}
	for code, want := range map[dnsproviderremote.ErrorCode]error{
		dnsproviderremote.CodeCredentialsRejected: ErrProviderCredentialsRejected,
		dnsproviderremote.CodeUnavailable:         ErrProviderVerificationUnavailable,
	} {
		service.UseZoneApexResolver(&fakeApexResolver{err: &dnsproviderremote.Error{Code: code}})
		if _, err := service.zoneApex(context.Background(), "dnspod_cn", credentials, "cdn.868yun.com"); !errors.Is(err, want) {
			t.Fatalf("%s: err = %v, want %v", code, err, want)
		}
	}
	// A provider without a domain list (dnsdun) saves without an apex.
	service.UseZoneApexResolver(&fakeApexResolver{err: &dnsproviderremote.Error{Code: dnsproviderremote.CodeUnsupported}})
	if got, err := service.zoneApex(context.Background(), "dnsdun", credentials, "cdn.868yun.com"); err != nil || got != "" {
		t.Fatalf("unsupported = %q, %v", got, err)
	}
}

// A zone saved before migration 473 (provider_zone_apex NULL) gets its apex
// on first use and writes it back; a stored apex is used without a provider
// call; a zone not hosted fails with dns_zone_not_hosted and writes nothing.
func TestEnsureZoneApexFillsLegacyZoneOnce(t *testing.T) {
	scopeID, zoneID := uuid.New(), uuid.New()
	resolver := &fakeApexResolver{hosted: []string{"868yun.com"}}
	execer := &recordingExecer{}
	apex, err := EnsureZoneApex(context.Background(), execer, resolver, scopeID, zoneID, "dnspod_cn", nil, "cdn.868yun.com", "")
	if err != nil || apex != "868yun.com" || resolver.calls != 1 {
		t.Fatalf("legacy fill = %q, %v, calls %d", apex, err, resolver.calls)
	}
	if !strings.Contains(execer.sql, "SET provider_zone_apex=$3") || !strings.Contains(execer.sql, "provider_zone_apex IS NULL") ||
		len(execer.args) != 3 || execer.args[0] != scopeID || execer.args[1] != zoneID || execer.args[2] != "868yun.com" {
		t.Fatalf("write-back = %q %v", execer.sql, execer.args)
	}
	execer = &recordingExecer{}
	if apex, err := EnsureZoneApex(context.Background(), execer, resolver, scopeID, zoneID, "dnspod_cn", nil,
		"cdn.868yun.com", "868yun.com"); err != nil || apex != "868yun.com" || resolver.calls != 1 || execer.sql != "" {
		t.Fatalf("stored apex = %q, %v, calls %d, sql %q", apex, err, resolver.calls, execer.sql)
	}
	_, err = EnsureZoneApex(context.Background(), execer, resolver, scopeID, zoneID, "dnspod_cn", nil, "cdn.other.com", "")
	if dnsproviderremote.ErrorCodeOf(err) != dnsproviderremote.CodeZoneNotHosted || execer.sql != "" {
		t.Fatalf("not hosted = %v, sql %q", err, execer.sql)
	}
}
