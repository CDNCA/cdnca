package dnsproviderremotesource

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// LineRemote is the provider surface LineRecords writes through
// (dnsproviderremote.NewReconcileRemote implements it).
type LineRemote interface {
	dnsproviderremote.ZoneRecordLister
	Mutate(context.Context, dnsproviderremote.ProviderConfig, dnscheck.ProviderOperation) (string, error)
}

// LinePublication is the CNAME one non-default DNS line of a site's CNAME
// owner must hold: CNAME "" means no record on the line (its visitors get
// the default line's answer).
type LinePublication struct {
	TenantID, SiteID, ZoneID uuid.UUID
	Owner                    string // the site CNAME hostname
	Line                     string // unified line (dnsproviderremote.LineOverseas, ...)
	CNAME                    string
	TTL                      uint32
}

// LineRecords writes the aggregated edge's per-line records (ADR 0008 §6.1)
// straight to the zone's DNS provider and reads them back. Resolver checks
// (dnscheck) are not used: from the controller only the answer of its own
// line is visible, so a non-default line cannot be verified by querying.
// The default line is never touched (cnameallocation publishes it).
type LineRecords struct {
	source *Source
	remote LineRemote
}

func NewLineRecords(source *Source, remote LineRemote) (*LineRecords, error) {
	if source == nil || source.pool == nil || source.cipher == nil || remote == nil {
		return nil, ErrUnavailable
	}
	return &LineRecords{source: source, remote: remote}, nil
}

// ErrLineUnconfirmed: the provider accepted the writes but the read-back does
// not show exactly the wanted record.
var ErrLineUnconfirmed = errors.New("dns provider line record not confirmed")

func defaultUnifiedLine(line string) bool {
	return line == "" || line == dnsproviderremote.LineDefault || line == "default"
}

// Publish converges the owner's records on the line to publication, then
// confirms them by listing again. The provider and zone rows are share-locked
// for the call, so a credential replacement waits for it.
func (records *LineRecords) Publish(ctx context.Context, publication LinePublication) error {
	owner, ok := canonicalOwner(strings.ToLower(strings.TrimSuffix(strings.TrimSpace(publication.Owner), ".")) + ".")
	cname := ""
	if publication.CNAME != "" {
		cname, ok = canonicalOwner(strings.ToLower(strings.TrimSuffix(publication.CNAME, ".")) + ".")
	}
	if records == nil || ctx == nil || !ok || publication.TenantID == uuid.Nil || publication.SiteID == uuid.Nil ||
		publication.ZoneID == uuid.Nil || defaultUnifiedLine(publication.Line) || publication.TTL == 0 ||
		publication.TTL > 86400 {
		return ErrUnavailable
	}
	return records.converge(ctx, publication.TenantID, publication.SiteID, publication.ZoneID, owner, publication.Line,
		func(current []dnsproviderremote.ZoneRecord) []dnscheck.ProviderOperation {
			return linePlan(current, owner, publication.Line, cname, publication.TTL)
		}, func(after []dnsproviderremote.ZoneRecord) bool { return lineConverged(after, cname, publication.TTL) })
}

// AddressPublication is the A/AAAA set one non-default DNS line of a site
// CNAME owner must hold (node endpoints published per carrier line). Empty A and AAAA mean no record on the line.
type AddressPublication struct {
	TenantID, SiteID, ZoneID uuid.UUID
	Owner                    string
	Line                     string
	A, AAAA                  []string
	// Weights per address (DNSPod 开启IP权重); absent: no weight.
	Weights map[string]uint32
	TTL     uint32
}

// PublishAddresses converges the owner's records on the line to the A/AAAA
// set of publication (anything else on the line, a CNAME included, goes),
// then confirms by listing again.
func (records *LineRecords) PublishAddresses(ctx context.Context, publication AddressPublication) error {
	owner, ok := canonicalOwner(strings.ToLower(strings.TrimSuffix(strings.TrimSpace(publication.Owner), ".")) + ".")
	desired, valid := desiredAddresses(publication)
	if records == nil || ctx == nil || !ok || !valid || publication.TenantID == uuid.Nil || publication.SiteID == uuid.Nil ||
		publication.ZoneID == uuid.Nil || defaultUnifiedLine(publication.Line) || publication.TTL == 0 ||
		publication.TTL > 86400 {
		return ErrUnavailable
	}
	return records.converge(ctx, publication.TenantID, publication.SiteID, publication.ZoneID, owner, publication.Line,
		func(current []dnsproviderremote.ZoneRecord) []dnscheck.ProviderOperation {
			return addressLinePlan(current, owner, publication.Line, desired, publication.TTL)
		}, func(after []dnsproviderremote.ZoneRecord) bool {
			return addressLineConverged(after, desired, publication.TTL)
		})
}

func (records *LineRecords) converge(ctx context.Context, tenantID, siteID, zoneID uuid.UUID, owner, line string,
	plan func([]dnsproviderremote.ZoneRecord) []dnscheck.ProviderOperation,
	converged func([]dnsproviderremote.ZoneRecord) bool) error {
	publication := struct {
		TenantID, SiteID, ZoneID uuid.UUID
		Line                     string
	}{tenantID, siteID, zoneID, line}
	boundCipher, ok := records.source.cipher.(dnsacme.BoundCredentialCipher)
	if !ok {
		return ErrUnavailable
	}
	callCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	return pgx.BeginFunc(callCtx, records.source.pool, func(tx pgx.Tx) error {
		var (
			revision                      int64
			scopeID, providerID           uuid.UUID
			providerType, zoneName, keyID string
			zoneApex                      string
			ciphertext                    []byte
		)
		err := tx.QueryRow(callCtx, reconcileScopeQuery(false)+" FOR SHARE OF provider,zone", publication.TenantID,
			publication.SiteID, publication.ZoneID).Scan(&revision, &scopeID, &providerID, &providerType, &zoneName,
			&keyID, &ciphertext, &zoneApex)
		defer clear(ciphertext)
		bare := strings.TrimSuffix(owner, ".")
		if err != nil || revision < 1 || !supportedProviderType(providerType) || !validDNSName(zoneName) ||
			bare != zoneName && !strings.HasSuffix(bare, "."+zoneName) {
			return ErrUnavailable
		}
		plaintext, err := boundCipher.DecryptCredential(dnsacme.CredentialBinding{TenantID: publication.TenantID,
			ScopeID: scopeID, ProviderID: providerID}, keyID, ciphertext)
		defer clear(plaintext)
		if err != nil || len(plaintext) == 0 {
			return ErrUnavailable
		}
		credentials, err := decodeCredentials(providerType, plaintext)
		if err != nil {
			return ErrUnavailable
		}
		defer clearCredentials(credentials)
		zoneApex, err = records.source.zoneApex(callCtx, tx, scopeID, publication.ZoneID, providerType, credentials,
			zoneName, zoneApex)
		if err != nil {
			return err
		}
		config := dnsproviderremote.ProviderConfig{TenantID: publication.TenantID, ScopeID: scopeID, TenantScopeID: scopeID,
			ProviderID: providerID, ProviderType: providerType, ZoneID: publication.ZoneID, ZoneName: zoneName,
			ProviderZoneName: zoneApex, Credentials: credentials}
		current, err := records.lineRecords(callCtx, config, owner, publication.Line)
		if err != nil {
			return err
		}
		for _, operation := range plan(current) {
			if _, err := records.remote.Mutate(callCtx, config, operation); err != nil {
				return err
			}
		}
		after, err := records.lineRecords(callCtx, config, owner, publication.Line)
		if err != nil {
			return err
		}
		if !converged(after) {
			return ErrLineUnconfirmed
		}
		return nil
	})
}

func (records *LineRecords) lineRecords(ctx context.Context, config dnsproviderremote.ProviderConfig, owner,
	line string) ([]dnsproviderremote.ZoneRecord, error) {
	listed, err := records.remote.ListZoneRecords(ctx, config, owner)
	if err != nil {
		return nil, err
	}
	var kept []dnsproviderremote.ZoneRecord
	seen := map[string]bool{}
	for _, record := range listed {
		// Huawei lists multi-value sets as <set>/<value>; ids are unique.
		if seen[record.ID] || record.Line != line {
			continue
		}
		seen[record.ID] = true
		kept = append(kept, record)
	}
	return kept, nil
}

// linePlan: deletes first (a CNAME cannot share its owner and line with
// anything else), then the CNAME create or in-place update.
func linePlan(current []dnsproviderremote.ZoneRecord, owner, line, cname string, ttl uint32) []dnscheck.ProviderOperation {
	var deletes []dnscheck.ProviderOperation
	var keep *dnsproviderremote.ZoneRecord
	for index, record := range current {
		if cname != "" && keep == nil && record.Type == dnscheck.RecordCNAME {
			keep = &current[index]
			continue
		}
		deletes = append(deletes, dnscheck.ProviderOperation{Action: dnscheck.ProviderDelete, RecordID: record.ID,
			Name: owner, Type: record.Type, Value: record.Value, TTL: record.TTL, Line: record.Line, Weight: record.Weight,
			Reason: "aggregated_edge_line"})
	}
	operations := deletes
	switch {
	case cname == "":
	case keep == nil:
		operations = append(operations, dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate, Name: owner,
			Type: dnscheck.RecordCNAME, Value: cname, TTL: ttl, Line: line, Reason: "aggregated_edge_line"})
	case keep.Value != cname || keep.TTL != ttl || keep.Weight != 0:
		operations = append(operations, dnscheck.ProviderOperation{Action: dnscheck.ProviderUpdate, RecordID: keep.ID,
			Name: owner, Type: dnscheck.RecordCNAME, Value: cname, TTL: ttl, Line: line, PreviousValue: keep.Value,
			PreviousTTL: keep.TTL, PreviousLine: keep.Line, PreviousWeight: keep.Weight, Reason: "aggregated_edge_line"})
	}
	for index := range operations {
		operations[index].Sequence = index + 1
	}
	return operations
}

func lineConverged(records []dnsproviderremote.ZoneRecord, cname string, ttl uint32) bool {
	if cname == "" {
		return len(records) == 0
	}
	return len(records) == 1 && records[0].Type == dnscheck.RecordCNAME && records[0].Value == cname &&
		records[0].TTL == ttl
}

type addressKey struct {
	recordType dnscheck.RecordType
	value      string
}

// desiredAddresses validates and indexes the wanted A/AAAA values with their
// weights (0 when none).
func desiredAddresses(publication AddressPublication) (map[addressKey]uint32, bool) {
	desired := map[addressKey]uint32{}
	for _, family := range []struct {
		recordType dnscheck.RecordType
		values     []string
		is4        bool
	}{{dnscheck.RecordA, publication.A, true}, {dnscheck.RecordAAAA, publication.AAAA, false}} {
		for _, raw := range family.values {
			address, err := netip.ParseAddr(raw)
			if err != nil || address.Zone() != "" || address.Is4In6() || address.Is4() != family.is4 ||
				address.String() != raw {
				return nil, false
			}
			weight := publication.Weights[raw]
			if weight > 100 {
				return nil, false
			}
			desired[addressKey{family.recordType, raw}] = weight
		}
	}
	return desired, true
}

// addressLinePlan: deletes first (a CNAME, values no longer wanted,
// duplicates), then in-place updates of TTL/weight, then creates.
func addressLinePlan(current []dnsproviderremote.ZoneRecord, owner, line string, desired map[addressKey]uint32,
	ttl uint32) []dnscheck.ProviderOperation {
	var deletes, updates, creates []dnscheck.ProviderOperation
	kept := map[addressKey]bool{}
	for _, record := range current {
		key := addressKey{record.Type, record.Value}
		weight, wanted := desired[key]
		if !wanted || kept[key] {
			deletes = append(deletes, dnscheck.ProviderOperation{Action: dnscheck.ProviderDelete, RecordID: record.ID,
				Name: owner, Type: record.Type, Value: record.Value, TTL: record.TTL, Line: record.Line,
				Weight: record.Weight, Reason: "cname_carrier_line"})
			continue
		}
		kept[key] = true
		if record.TTL != ttl || record.Weight != weight {
			updates = append(updates, dnscheck.ProviderOperation{Action: dnscheck.ProviderUpdate, RecordID: record.ID,
				Name: owner, Type: record.Type, Value: record.Value, TTL: ttl, Line: line, Weight: weight,
				PreviousValue: record.Value, PreviousTTL: record.TTL, PreviousLine: record.Line,
				PreviousWeight: record.Weight, Reason: "cname_carrier_line"})
		}
	}
	keys := make([]addressKey, 0, len(desired))
	for key := range desired {
		if !kept[key] {
			keys = append(keys, key)
		}
	}
	slices.SortFunc(keys, func(left, right addressKey) int {
		if left.recordType != right.recordType {
			return int(left.recordType) - int(right.recordType)
		}
		return strings.Compare(left.value, right.value)
	})
	for _, key := range keys {
		creates = append(creates, dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate, Name: owner,
			Type: key.recordType, Value: key.value, TTL: ttl, Line: line, Weight: desired[key], Reason: "cname_carrier_line"})
	}
	operations := append(append(deletes, updates...), creates...)
	for index := range operations {
		operations[index].Sequence = index + 1
	}
	return operations
}

func addressLineConverged(records []dnsproviderremote.ZoneRecord, desired map[addressKey]uint32, ttl uint32) bool {
	if len(records) != len(desired) {
		return false
	}
	seen := map[addressKey]bool{}
	for _, record := range records {
		key := addressKey{record.Type, record.Value}
		weight, wanted := desired[key]
		if !wanted || seen[key] || record.TTL != ttl || record.Weight != weight {
			return false
		}
		seen[key] = true
	}
	return true
}
