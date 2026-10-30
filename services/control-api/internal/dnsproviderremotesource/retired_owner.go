package dnsproviderremotesource

import (
	"context"
	"errors"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/cnameallocation"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/jackc/pgx/v5"
)

// RetiredOwnerRemote lists and deletes provider records of one owner.
type RetiredOwnerRemote interface {
	dnsproviderremote.ZoneRecordLister
	Mutate(context.Context, dnsproviderremote.ProviderConfig, dnscheck.ProviderOperation) (string, error)
}

// RetiredOwners deletes the records of a retired CNAME owner (migration 476)
// at its zone's provider (cnameallocation.RetiredOwnerCleaner). The site is
// usually deleted, so the reconcile authority (which requires a live site)
// does not apply: the zone, provider and tenant must still be active, and
// only records whose type and value the system wrote under the owner are
// deleted. Anything else under the name (a customer's own record) is kept.
type RetiredOwners struct {
	source *Source
	remote RetiredOwnerRemote
}

func NewRetiredOwners(source *Source, remote RetiredOwnerRemote) (*RetiredOwners, error) {
	if source == nil || source.pool == nil || source.cipher == nil || remote == nil {
		return nil, ErrUnavailable
	}
	return &RetiredOwners{source: source, remote: remote}, nil
}

const retiredOwnerScopeQuery = `
	SELECT provider.provider_type,zone.name,provider.credential_key_id,provider.credential_ciphertext,
	       COALESCE(zone.provider_zone_apex,'')
	FROM dns_zones zone
	JOIN dns_providers provider ON provider.scope_id=zone.scope_id AND provider.id=zone.provider_id
	JOIN access_scopes scope ON scope.id=zone.scope_id AND scope.kind='tenant'
	JOIN tenants tenant ON tenant.id=scope.tenant_id AND tenant.status='active'
	WHERE scope.tenant_id=$1 AND zone.scope_id=$2 AND zone.id=$3 AND provider.id=$4
	  AND provider.status='verified' AND provider.credential_revoked=false AND provider.credential_version>0`

// retiredOwnerFailure is an answer a retry cannot change (the zone or
// provider was removed or revoked, the owner is outside the zone).
type retiredOwnerFailure struct{ code string }

func (failure retiredOwnerFailure) Error() string       { return "retired CNAME owner: " + failure.code }
func (failure retiredOwnerFailure) FailureCode() string { return failure.code }

func (owners *RetiredOwners) CleanRetiredOwner(ctx context.Context, owner cnameallocation.RetiredOwner) (int, int, error) {
	if owners == nil || ctx == nil {
		return 0, 0, ErrUnavailable
	}
	canonical, ok := canonicalOwner(strings.TrimSuffix(owner.Owner, ".") + ".")
	if !ok {
		return 0, 0, retiredOwnerFailure{code: "dns_retire_invalid_owner"}
	}
	boundCipher, ok := owners.source.cipher.(dnsacme.BoundCredentialCipher)
	if !ok {
		return 0, 0, ErrUnavailable
	}
	var providerType, zoneName, keyID, zoneApex string
	var ciphertext []byte
	err := owners.source.pool.QueryRow(ctx, retiredOwnerScopeQuery, owner.TenantID, owner.ScopeID, owner.ZoneID,
		owner.ProviderID).Scan(&providerType, &zoneName, &keyID, &ciphertext, &zoneApex)
	defer clear(ciphertext)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, 0, retiredOwnerFailure{code: "dns_retire_zone_unavailable"}
		}
		return 0, 0, ErrUnavailable
	}
	ownerWithoutDot := strings.TrimSuffix(canonical, ".")
	if !supportedProviderType(providerType) || !validDNSName(zoneName) || !strings.HasSuffix(ownerWithoutDot, "."+zoneName) {
		return 0, 0, retiredOwnerFailure{code: "dns_retire_invalid_owner"}
	}
	plaintext, err := boundCipher.DecryptCredential(dnsacme.CredentialBinding{
		TenantID: owner.TenantID, ScopeID: owner.ScopeID, ProviderID: owner.ProviderID}, keyID, ciphertext)
	defer clear(plaintext)
	if err != nil || len(plaintext) == 0 {
		return 0, 0, ErrUnavailable
	}
	credentials, err := decodeCredentials(providerType, plaintext)
	if err != nil {
		return 0, 0, ErrUnavailable
	}
	defer clearCredentials(credentials)
	zoneApex, err = owners.source.zoneApex(ctx, nil, owner.ScopeID, owner.ZoneID, providerType, credentials, zoneName, zoneApex)
	if err != nil {
		return 0, 0, err
	}
	config := dnsproviderremote.ProviderConfig{TenantID: owner.TenantID, ScopeID: owner.ScopeID,
		TenantScopeID: owner.ScopeID, ProviderID: owner.ProviderID, ProviderType: providerType, ZoneID: owner.ZoneID,
		ZoneName: zoneName, ProviderZoneName: zoneApex, Credentials: credentials}
	records, err := owners.remote.ListZoneRecords(ctx, config, canonical)
	if err != nil {
		return 0, 0, err
	}
	deleted, kept := 0, 0
	for _, operation := range RetiredOwnerDeletes(records, canonical, owner) {
		if operation.Action != dnscheck.ProviderDelete {
			kept++
			continue
		}
		if _, err := owners.remote.Mutate(ctx, config, operation); err != nil {
			return deleted, kept, err
		}
		deleted++
	}
	return deleted, kept, nil
}

// RetiredOwnerDeletes plans the retirement of one owner: a delete for each
// A/AAAA/CNAME record under exactly that name whose value the system wrote
// there; every other record under the name is returned with an empty
// action (kept, counted). The comparison is case-insensitive and ignores the
// trailing dot of CNAME values.
func RetiredOwnerDeletes(records []dnsproviderremote.ZoneRecord, canonical string,
	owner cnameallocation.RetiredOwner) []dnscheck.ProviderOperation {
	written := map[dnscheck.RecordType]map[string]bool{
		dnscheck.RecordA: {}, dnscheck.RecordAAAA: {}, dnscheck.RecordCNAME: {},
	}
	for recordType, values := range map[dnscheck.RecordType][]string{
		dnscheck.RecordA: owner.A, dnscheck.RecordAAAA: owner.AAAA, dnscheck.RecordCNAME: owner.CNAME} {
		for _, value := range values {
			written[recordType][recordValueKey(recordType, value)] = true
		}
	}
	result := make([]dnscheck.ProviderOperation, 0, len(records))
	for _, record := range records {
		if strings.ToLower(strings.TrimSuffix(record.Name, "."))+"." != canonical {
			continue
		}
		operation := dnscheck.ProviderOperation{RecordID: record.ID, Name: record.Name, Type: record.Type,
			Value: record.Value, TTL: record.TTL, Line: record.Line, Weight: record.Weight}
		if values, managed := written[record.Type]; managed && values[recordValueKey(record.Type, record.Value)] {
			operation.Action, operation.Reason = dnscheck.ProviderDelete, "cname_owner_retired"
		}
		result = append(result, operation)
	}
	return result
}

func recordValueKey(recordType dnscheck.RecordType, value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if recordType == dnscheck.RecordCNAME {
		value = strings.TrimSuffix(value, ".")
	}
	return value
}
