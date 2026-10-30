package dnsproviderremotesource

import (
	"context"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/google/uuid"
)

// PropagationZoneApex returns the hosted domain of a site's CNAME zone for
// the DNS propagation check (N14): the authoritative servers of a subdomain
// zone (cdn.868yun.com) are those of its hosted apex (868yun.com), which
// has the only NS set. A zone saved before migration 473 gets its apex from
// the provider once and written back (dnsacme.EnsureZoneApex), as the
// reconcile mutations do; it resolves through the same tenant/site/zone
// authority (reconcileScopeQuery).
func (s *Source) PropagationZoneApex(ctx context.Context, tenantID, siteID, zoneID uuid.UUID) (string, error) {
	if s == nil || s.pool == nil || s.cipher == nil || ctx == nil ||
		tenantID == uuid.Nil || siteID == uuid.Nil || zoneID == uuid.Nil {
		return "", ErrUnavailable
	}
	boundCipher, ok := s.cipher.(dnsacme.BoundCredentialCipher)
	if !ok {
		return "", ErrUnavailable
	}
	var (
		revision                      int64
		scopeID, providerID           uuid.UUID
		providerType, zoneName, keyID string
		zoneApex                      string
		ciphertext                    []byte
	)
	err := s.pool.QueryRow(ctx, reconcileScopeQuery(false), tenantID, siteID, zoneID).Scan(
		&revision, &scopeID, &providerID, &providerType, &zoneName, &keyID, &ciphertext, &zoneApex)
	defer clear(ciphertext)
	if err != nil || revision < 1 || !supportedProviderType(providerType) || !validDNSName(zoneName) {
		return "", ErrUnavailable
	}
	if zoneApex != "" {
		return zoneApex, nil
	}
	plaintext, err := boundCipher.DecryptCredential(dnsacme.CredentialBinding{
		TenantID: tenantID, ScopeID: scopeID, ProviderID: providerID}, keyID, ciphertext)
	defer clear(plaintext)
	if err != nil || len(plaintext) == 0 {
		return "", ErrUnavailable
	}
	credentials, err := decodeCredentials(providerType, plaintext)
	if err != nil {
		return "", ErrUnavailable
	}
	defer clearCredentials(credentials)
	return s.zoneApex(ctx, nil, scopeID, zoneID, providerType, credentials, zoneName, "")
}
