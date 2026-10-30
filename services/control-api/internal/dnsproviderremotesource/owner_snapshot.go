package dnsproviderremotesource

import (
	"context"
	"errors"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/google/uuid"
)

// OwnerSnapshot lists the provider records of a CNAME owner for the
// publication reconcile request (cnameallocation.ProviderSnapshotSource). It
// resolves credentials through the same tenant/site/zone authority the
// reconcile mutations use (reconcileScopeQuery).
type OwnerSnapshot struct {
	source *Source
	lister dnsproviderremote.ZoneRecordLister
}

func NewOwnerSnapshot(source *Source, lister dnsproviderremote.ZoneRecordLister) (*OwnerSnapshot, error) {
	if source == nil || source.pool == nil || source.cipher == nil || lister == nil {
		return nil, ErrUnavailable
	}
	return &OwnerSnapshot{source: source, lister: lister}, nil
}

func (snapshot *OwnerSnapshot) OwnerRecords(ctx context.Context, tenantID, siteID, zoneID uuid.UUID,
	owner string) ([]dnscheck.ProviderRecord, error) {
	if snapshot == nil || ctx == nil || tenantID == uuid.Nil || siteID == uuid.Nil || zoneID == uuid.Nil {
		return nil, ErrUnavailable
	}
	// Publication check names carry no trailing dot.
	canonical, ok := canonicalOwner(strings.ToLower(strings.TrimSuffix(strings.TrimSpace(owner), ".")) + ".")
	if !ok {
		return nil, ErrUnavailable
	}
	boundCipher, ok := snapshot.source.cipher.(dnsacme.BoundCredentialCipher)
	if !ok {
		return nil, ErrUnavailable
	}
	var (
		revision                      int64
		scopeID, providerID           uuid.UUID
		providerType, zoneName, keyID string
		zoneApex                      string
		ciphertext                    []byte
	)
	err := snapshot.source.pool.QueryRow(ctx, reconcileScopeQuery(false), tenantID, siteID, zoneID).Scan(
		&revision, &scopeID, &providerID, &providerType, &zoneName, &keyID, &ciphertext, &zoneApex)
	defer clear(ciphertext)
	ownerWithoutDot := strings.TrimSuffix(canonical, ".")
	if err != nil || revision < 1 || !supportedProviderType(providerType) || !validDNSName(zoneName) ||
		ownerWithoutDot != zoneName && !strings.HasSuffix(ownerWithoutDot, "."+zoneName) {
		return nil, ErrUnavailable
	}
	plaintext, err := boundCipher.DecryptCredential(dnsacme.CredentialBinding{
		TenantID: tenantID, ScopeID: scopeID, ProviderID: providerID}, keyID, ciphertext)
	defer clear(plaintext)
	if err != nil || len(plaintext) == 0 {
		return nil, ErrUnavailable
	}
	credentials, err := decodeCredentials(providerType, plaintext)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer clearCredentials(credentials)
	// A zone saved before migration 473 gets its hosted apex here once.
	zoneApex, err = snapshot.source.zoneApex(ctx, nil, scopeID, zoneID, providerType, credentials, zoneName, zoneApex)
	var records []dnsproviderremote.ZoneRecord
	if err == nil {
		records, err = snapshot.lister.ListZoneRecords(ctx, dnsproviderremote.ProviderConfig{
			TenantID: tenantID, ScopeID: scopeID, TenantScopeID: scopeID, ProviderID: providerID,
			ProviderType: providerType, ZoneID: zoneID, ZoneName: zoneName, ProviderZoneName: zoneApex,
			Credentials: credentials,
		}, canonical)
	}
	if err != nil {
		var remote *dnsproviderremote.Error
		if errors.As(err, &remote) && remote.Code == dnsproviderremote.CodeZoneNotHosted {
			return nil, OwnerSnapshotFailure{Code: string(remote.Code)}
		}
		return nil, ErrUnavailable
	}
	return providerRecords(records), nil
}

func providerRecords(records []dnsproviderremote.ZoneRecord) []dnscheck.ProviderRecord {
	result := make([]dnscheck.ProviderRecord, 0, len(records))
	for _, record := range records {
		result = append(result, dnscheck.ProviderRecord{RecordID: record.ID, Name: record.Name, Type: record.Type,
			Value: record.Value, TTL: record.TTL, Line: record.Line, Weight: record.Weight})
	}
	return result
}

// OwnerSnapshotFailure is a provider answer that a retry cannot change (the
// account does not host the zone). It wraps ErrUnavailable for callers that
// only know that error; FailureCode names the reason for the job record.
type OwnerSnapshotFailure struct{ Code string }

func (failure OwnerSnapshotFailure) Error() string {
	return "dns provider snapshot failed: " + failure.Code
}
func (failure OwnerSnapshotFailure) Unwrap() error       { return ErrUnavailable }
func (failure OwnerSnapshotFailure) FailureCode() string { return failure.Code }
