package dnsproviderremotesource

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/google/uuid"
)

// Stable failure codes of SiteCNAMEWriter (shown to the site owner as the
// reason an automatic change did not happen).
const (
	CNAMECodeWildcard    = "wildcard_domain"     // *.example.com: not written automatically
	CNAMECodeApex        = "apex_domain"         // the zone apex cannot hold a CNAME
	CNAMECodeNotHosted   = "zone_not_hosted"     // no verified provider of the tenant manages the name
	CNAMECodeConflict    = "dns_record_conflict" // A/AAAA, several records or other lines under the name
	CNAMECodeUnconfirmed = "dns_record_unconfirmed"
	// A name outside the CNAME zone itself (only under its hosted domain)
	// whose record does not point into that CNAME zone: not taken over.
	CNAMECodeForeign     = "dns_record_not_platform"
	CNAMECodeUnavailable = "dns_provider_unavailable"
	cnameCodeProvider    = "dns_provider_" // + dnsproviderremote error code
)

// CNAMEError carries one of the codes above.
type CNAMEError struct{ Code string }

func (e *CNAMEError) Error() string { return "site cname: " + e.Code }

// CNAMEFailureCode maps an error of Point to a stable code.
func CNAMEFailureCode(err error) string {
	var own *CNAMEError
	if errors.As(err, &own) {
		return own.Code
	}
	var provider *dnsproviderremote.Error
	if errors.As(err, &provider) && provider.Code != "" {
		return cnameCodeProvider + string(provider.Code)
	}
	if errors.Is(err, ErrNoManagedZone) {
		return CNAMECodeNotHosted
	}
	return CNAMECodeUnavailable
}

// CNAMEChange is what one Point call did to the domain's default-line record.
type CNAMEChange struct {
	Domain  string
	Before  string // previous CNAME target ("" when there was no record)
	After   string
	Changed bool // false: the record already pointed at After
}

// siteCNAMETTL is the TTL of a CNAME the writer creates (an update keeps the
// record's own TTL). 600 is above every provider floor (name.com 300).
const siteCNAMETTL = 600

// SiteCNAMEWriter points a site's own domain at a CNAME through the zone of
// the site tenant's verified DNS provider whose hosted domain covers it
// (ValidationPublisher.withHostedZone: provider_zone_apex, so a platform
// CNAME zone cdn.868yun.com writes cdnca-t1.868yun.com in 868yun.com as
// cdnca-t1; reads and writes as LineRecords). Only the
// default-line record of that one name is touched; anything else under the
// name is a conflict and nothing is deleted (esc-autocname).
type SiteCNAMEWriter struct {
	zones  *ValidationPublisher
	remote LineRemote
}

func NewSiteCNAMEWriter(source *Source, remote LineRemote) (*SiteCNAMEWriter, error) {
	if source == nil || source.pool == nil || remote == nil {
		return nil, ErrUnavailable
	}
	bound, ok := source.cipher.(dnsacme.BoundCredentialCipher)
	if !ok {
		return nil, ErrUnavailable
	}
	// Only the zone lookup of ValidationPublisher is used (no TXT writer).
	return &SiteCNAMEWriter{zones: &ValidationPublisher{pool: source.pool, cipher: bound, apex: source.apex}, remote: remote}, nil
}

// Point makes domain's default-line record a CNAME to target.
func (w *SiteCNAMEWriter) Point(ctx context.Context, siteID uuid.UUID, domain, target string) (CNAMEChange, error) {
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	change := CNAMEChange{Domain: name}
	if strings.HasPrefix(name, "*.") {
		return change, &CNAMEError{Code: CNAMECodeWildcard}
	}
	owner, okOwner := canonicalOwner(name + ".")
	value, okValue := canonicalOwner(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(target)), ".") + ".")
	if w == nil || ctx == nil || siteID == uuid.Nil || !okOwner || !okValue || owner == value {
		return change, &CNAMEError{Code: CNAMECodeUnavailable}
	}
	change.After = strings.TrimSuffix(value, ".")
	callCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	err := w.zones.withHostedZone(callCtx, siteID, name, func(config dnsproviderremote.ProviderConfig, zoneName string) error {
		current, err := w.remote.ListZoneRecords(callCtx, config, owner)
		if err != nil {
			return err
		}
		operation, before, err := siteCNAMEPlan(current, owner, value)
		if err != nil {
			return err
		}
		if !withinZone(name, zoneName) && !withinZone(before, zoneName) {
			// cdnca-t1.868yun.com through the platform CNAME zone
			// cdn.868yun.com: the hosted domain belongs to whoever owns the
			// account, so only a record already pointing into the CNAME zone
			// (the site's package CNAME) is rewritten, never created or taken over.
			return &CNAMEError{Code: CNAMECodeForeign}
		}
		change.Before = before
		if operation == nil {
			return nil
		}
		if _, err := w.remote.Mutate(callCtx, config, *operation); err != nil {
			return err
		}
		change.Changed = true
		after, err := w.remote.ListZoneRecords(callCtx, config, owner)
		if err != nil {
			return err
		}
		if !siteCNAMEConverged(after, value) {
			return &CNAMEError{Code: CNAMECodeUnconfirmed}
		}
		return nil
	})
	if errors.Is(err, ErrNoManagedZone) {
		// withHostedZone matches strict subdomains only: the apex has no managing zone either.
		return change, &CNAMEError{Code: CNAMECodeNotHosted}
	}
	return change, err
}

// withinZone reports whether name is a strict subdomain of zone.
func withinZone(name, zone string) bool {
	return zone != "" && strings.HasSuffix(name, "."+zone)
}

// siteCNAMEPlan: no record → create; one default-line CNAME → update in place
// (nil when it already points at value); anything else → conflict.
func siteCNAMEPlan(current []dnsproviderremote.ZoneRecord, owner, value string) (*dnscheck.ProviderOperation, string, error) {
	switch {
	case len(current) == 0:
		return &dnscheck.ProviderOperation{Sequence: 1, Action: dnscheck.ProviderCreate, Name: owner,
			Type: dnscheck.RecordCNAME, Value: value, TTL: siteCNAMETTL, Reason: "attack_escalation_cname"}, "", nil
	case len(current) > 1 || current[0].Type != dnscheck.RecordCNAME || !defaultUnifiedLine(current[0].Line) ||
		current[0].Weight != 0:
		return nil, "", &CNAMEError{Code: CNAMECodeConflict}
	}
	record := current[0]
	before := strings.TrimSuffix(strings.ToLower(record.Value), ".")
	if before == strings.TrimSuffix(value, ".") {
		return nil, before, nil
	}
	ttl := record.TTL
	if ttl == 0 {
		ttl = siteCNAMETTL
	}
	return &dnscheck.ProviderOperation{Sequence: 1, Action: dnscheck.ProviderUpdate, RecordID: record.ID, Name: owner,
		Type: dnscheck.RecordCNAME, Value: value, TTL: ttl, Line: record.Line, PreviousValue: record.Value,
		PreviousTTL: record.TTL, PreviousLine: record.Line, Reason: "attack_escalation_cname"}, before, nil
}

func siteCNAMEConverged(records []dnsproviderremote.ZoneRecord, value string) bool {
	return len(records) == 1 && records[0].Type == dnscheck.RecordCNAME && defaultUnifiedLine(records[0].Line) &&
		strings.TrimSuffix(strings.ToLower(records[0].Value), ".") == strings.TrimSuffix(value, ".")
}
