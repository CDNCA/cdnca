package dnsproviderremotesource

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SiteAutoDNSWriter is 建站「DNS API（自动添加记录）」: a site
// owner's own DNS account (DNS API 标签, no dns_zones row needed) gets a
// CNAME of the site domain to the site CNAME. The account's hosted domain
// covering the name is looked up from the provider's domain list; the record
// is planned, written and read back exactly as SiteCNAMEWriter does (create,
// or rewrite one default-line CNAME; anything else under the name is a
// conflict and nothing is deleted). Repeating a call is a no-op once the
// record points at the CNAME.
type SiteAutoDNSWriter struct {
	source *Source
	cipher dnsacme.BoundCredentialCipher
	remote LineRemote
}

func NewSiteAutoDNSWriter(source *Source, remote LineRemote) (*SiteAutoDNSWriter, error) {
	if source == nil || source.pool == nil || remote == nil {
		return nil, ErrUnavailable
	}
	bound, ok := source.cipher.(dnsacme.BoundCredentialCipher)
	if !ok {
		return nil, ErrUnavailable
	}
	return &SiteAutoDNSWriter{source: source, cipher: bound, remote: remote}, nil
}

// Point makes domain a CNAME to target through providerID, which must be a
// verified, unrevoked account the site's (active) tenant scope entered
// itself: the platform DNS copy only serves the platform-allocated CNAME
// records (SiteCNAMEWriter), never the hosted domains it can reach
// (DNS-SEC-20261027-01; reads as zone_not_hosted).
func (w *SiteAutoDNSWriter) Point(ctx context.Context, scopeID, siteID, providerID uuid.UUID, domain, target string) (CNAMEChange, error) {
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	change := CNAMEChange{Domain: name}
	if strings.HasPrefix(name, "*.") {
		return change, &CNAMEError{Code: CNAMECodeWildcard}
	}
	owner, okOwner := canonicalOwner(name + ".")
	value, okValue := canonicalOwner(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(target)), ".") + ".")
	if w == nil || ctx == nil || scopeID == uuid.Nil || siteID == uuid.Nil || providerID == uuid.Nil ||
		!okOwner || !okValue || owner == value {
		return change, &CNAMEError{Code: CNAMECodeUnavailable}
	}
	change.After = strings.TrimSuffix(value, ".")
	callCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	tx, err := w.source.pool.Begin(callCtx)
	if err != nil {
		return change, ErrUnavailable
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	var (
		tenantID, keyID, providerType string
		ciphertext                    []byte
		version                       int64
	)
	// FOR SHARE: a credential replacement waits for the call (as LineRecords).
	err = tx.QueryRow(callCtx, `SELECT scope.tenant_id::text, provider.provider_type, provider.credential_key_id,
			provider.credential_ciphertext, provider.credential_version
		FROM sites site
		JOIN access_scopes scope ON scope.id=site.scope_id AND scope.kind='tenant'
		JOIN tenants tenant ON tenant.id=scope.tenant_id AND tenant.status='active'
		JOIN dns_providers provider ON provider.scope_id=site.scope_id AND provider.id=$3
		WHERE site.id=$1 AND site.scope_id=$2 AND site.deleted_at IS NULL
		  AND provider.status='verified' AND NOT provider.credential_revoked
		  AND provider.managed_by='tenant' AND provider.id<>$4
		FOR SHARE OF provider`, siteID, scopeID, providerID, dnsacme.PlatformProviderCopyID(scopeID)).
		Scan(&tenantID, &providerType, &keyID, &ciphertext, &version)
	defer clear(ciphertext)
	if errors.Is(err, pgx.ErrNoRows) {
		return change, &CNAMEError{Code: CNAMECodeNotHosted}
	}
	tenant, parseErr := uuid.Parse(tenantID)
	if err != nil || parseErr != nil || !supportedProviderType(providerType) || version <= 0 {
		return change, ErrUnavailable
	}
	plaintext, err := w.cipher.DecryptCredential(dnsacme.CredentialBinding{
		TenantID: tenant, ScopeID: scopeID, ProviderID: providerID}, keyID, ciphertext)
	defer clear(plaintext)
	if err != nil || len(plaintext) == 0 {
		return change, ErrUnavailable
	}
	credentials, err := decodeCredentials(providerType, plaintext)
	if err != nil {
		return change, ErrUnavailable
	}
	defer clearCredentials(credentials)
	// The longest hosted domain equal to the name or a parent of it.
	apex, err := w.source.apex.ResolveZoneApex(callCtx, providerType, credentials, name)
	if err != nil {
		return change, err
	}
	if apex == name {
		return change, &CNAMEError{Code: CNAMECodeApex} // a zone apex cannot hold a CNAME
	}
	// ZoneID only identifies the call internally: this path has no dns_zones row.
	config := dnsproviderremote.ProviderConfig{TenantID: tenant, ScopeID: scopeID, TenantScopeID: scopeID,
		ProviderID: providerID, ProviderType: providerType, ZoneID: providerID, ZoneName: apex, ProviderZoneName: apex,
		Credentials: credentials, CredentialVersion: uint64(version)}
	current, err := w.remote.ListZoneRecords(callCtx, config, owner)
	if err != nil {
		return change, err
	}
	operation, before, err := siteCNAMEPlan(current, owner, value)
	if err != nil {
		return change, err
	}
	change.Before = before
	if operation != nil {
		operation.Reason = "site_auto_dns_cname"
		if _, err := w.remote.Mutate(callCtx, config, *operation); err != nil {
			return change, err
		}
		change.Changed = true
		after, err := w.remote.ListZoneRecords(callCtx, config, owner)
		if err != nil {
			return change, err
		}
		if !siteCNAMEConverged(after, value) {
			return change, &CNAMEError{Code: CNAMECodeUnconfirmed}
		}
	}
	if err := tx.Commit(callCtx); err != nil {
		return change, ErrUnavailable
	}
	return change, nil
}

// AutoDNSFailureTemporary: worth retrying later (provider outage, rate
// limit, our own dependencies); conflicts and unhosted names are not.
func AutoDNSFailureTemporary(err error) bool {
	var own *CNAMEError
	if errors.As(err, &own) {
		return own.Code == CNAMECodeUnavailable || own.Code == CNAMECodeUnconfirmed
	}
	var provider *dnsproviderremote.Error
	if errors.As(err, &provider) {
		return provider.Temporary
	}
	return true
}
