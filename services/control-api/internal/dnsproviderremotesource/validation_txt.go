package dnsproviderremotesource

import (
	"context"
	"errors"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNoManagedZone: no verified DNS provider of the site's tenant manages
// the record name; the member has to add the record by hand.
var ErrNoManagedZone = errors.New("dns provider source: no managed zone for the record")

// TXTWriter is dnsproviderremote.ValidationTXTWriter.
type TXTWriter interface {
	Publish(ctx context.Context, config dnsproviderremote.ProviderConfig, owner, value string) (string, error)
	Remove(ctx context.Context, config dnsproviderremote.ProviderConfig, ref, owner, value string) error
}

// ValidationPublisher writes third-party CDN validation TXT records
// (ADR 0008 §4.1) into the zone of the site tenant's DNS provider that
// manages the record name (longest suffix). The provider row is held FOR
// SHARE for the whole provider call: a credential rotation or disable
// waits for it, and a call never starts on a disabled or revoked one.
type ValidationPublisher struct {
	pool   *pgxpool.Pool
	cipher dnsacme.BoundCredentialCipher
	writer TXTWriter
	apex   dnsproviderremote.ZoneApexResolver
}

func (publisher *ValidationPublisher) zoneApex(ctx context.Context, tx pgx.Tx, scopeID, zoneID uuid.UUID,
	providerType string, credentials map[string]string, zoneName, stored string) (string, error) {
	return dnsacme.EnsureZoneApex(ctx, tx, publisher.apex, scopeID, zoneID, providerType, credentials, zoneName, stored)
}

func NewValidationPublisher(pool *pgxpool.Pool, cipher dnsacme.CredentialCipher, writer TXTWriter) (*ValidationPublisher, error) {
	bound, ok := cipher.(dnsacme.BoundCredentialCipher)
	if pool == nil || !ok || writer == nil {
		return nil, ErrUnavailable
	}
	return &ValidationPublisher{pool: pool, cipher: bound, writer: writer, apex: dnsproviderremote.NewZoneApexResolver()}, nil
}

// Publish returns the record reference, or ErrNoManagedZone.
func (publisher *ValidationPublisher) Publish(ctx context.Context, siteID uuid.UUID, owner, value string) (string, error) {
	var ref string
	err := publisher.withZone(ctx, siteID, owner, func(config dnsproviderremote.ProviderConfig) error {
		var err error
		ref, err = publisher.writer.Publish(ctx, config, owner, value)
		return err
	})
	return ref, err
}

// Remove deletes a record Publish wrote. A zone that is no longer managed
// (provider removed or disabled) returns ErrNoManagedZone.
func (publisher *ValidationPublisher) Remove(ctx context.Context, siteID uuid.UUID, ref, owner, value string) error {
	return publisher.withZone(ctx, siteID, owner, func(config dnsproviderremote.ProviderConfig) error {
		return publisher.writer.Remove(ctx, config, ref, owner, value)
	})
}

func (publisher *ValidationPublisher) withZone(ctx context.Context, siteID uuid.UUID, owner string,
	fn func(dnsproviderremote.ProviderConfig) error) error {
	return publisher.withMatchedZone(ctx, siteID, owner, false, func(config dnsproviderremote.ProviderConfig, _ string) error {
		return fn(config)
	})
}

// withHostedZone is withZone matching owner against each zone's hosted
// domain (provider_zone_apex, migration 473; the zone name until it is
// filled in) instead of the zone name, and calling fn with that hosted
// domain as ZoneName: a site's own record (cdnca-t1.868yun.com) is written
// through the account of the platform CNAME zone cdn.868yun.com that hosts
// 868yun.com, with the relative name cdnca-t1 (n10-dnshosted). fn also gets
// the zone's own name.
func (publisher *ValidationPublisher) withHostedZone(ctx context.Context, siteID uuid.UUID, owner string,
	fn func(config dnsproviderremote.ProviderConfig, zoneName string) error) error {
	return publisher.withMatchedZone(ctx, siteID, owner, true, fn)
}

func (publisher *ValidationPublisher) withMatchedZone(ctx context.Context, siteID uuid.UUID, owner string, hosted bool,
	fn func(config dnsproviderremote.ProviderConfig, zoneName string) error) error {
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(owner)), ".")
	if publisher == nil || ctx == nil || siteID == uuid.Nil || !validDNSName(name) {
		return ErrUnavailable
	}
	tx, err := publisher.pool.Begin(ctx)
	if err != nil {
		return ErrUnavailable
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	var (
		tenantID, scopeID, providerID, zoneID uuid.UUID
		providerType, zoneName, keyID, apex   string
		ciphertext                            []byte
		version                               int64
	)
	err = tx.QueryRow(ctx, `SELECT scope.tenant_id,scope.id,provider.id,provider.provider_type,provider.credential_key_id,
		provider.credential_ciphertext,provider.credential_version,zone.id,zone.name,COALESCE(zone.provider_zone_apex,'')
		FROM sites site
		JOIN access_scopes scope ON scope.id=site.scope_id AND scope.kind='tenant'
		JOIN tenants tenant ON tenant.id=scope.tenant_id AND tenant.status='active'
		JOIN dns_zones zone ON zone.scope_id=site.scope_id
		JOIN dns_providers provider ON provider.scope_id=zone.scope_id AND provider.id=zone.provider_id
		CROSS JOIN LATERAL (SELECT CASE WHEN $3 THEN COALESCE(zone.provider_zone_apex,zone.name) ELSE zone.name END AS name) matched
		WHERE site.id=$1 AND site.deleted_at IS NULL AND provider.status='verified' AND NOT provider.credential_revoked
		  AND char_length($2) > char_length(matched.name) AND right($2, char_length(matched.name)+1) = '.'||matched.name
		ORDER BY char_length(matched.name) DESC, zone.name=matched.name DESC, zone.id LIMIT 1
		FOR SHARE OF provider`, siteID, name, hosted).Scan(&tenantID, &scopeID, &providerID, &providerType, &keyID,
		&ciphertext, &version, &zoneID, &zoneName, &apex)
	defer clear(ciphertext)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNoManagedZone
	}
	if err != nil || !supportedProviderType(providerType) || version <= 0 {
		return ErrUnavailable
	}
	plaintext, err := publisher.cipher.DecryptCredential(dnsacme.CredentialBinding{
		TenantID: tenantID, ScopeID: scopeID, ProviderID: providerID}, keyID, ciphertext)
	defer clear(plaintext)
	if err != nil || len(plaintext) == 0 {
		return ErrUnavailable
	}
	credentials, err := decodeCredentials(providerType, plaintext)
	if err != nil {
		return ErrUnavailable
	}
	defer clearCredentials(credentials)
	apex, err = publisher.zoneApex(ctx, tx, scopeID, zoneID, providerType, credentials, zoneName, apex)
	if err != nil {
		return err
	}
	configZone := zoneName
	if hosted {
		// The owner lies under the hosted domain, not necessarily under the
		// zone name: validateConfig checks owners against ZoneName.
		configZone = apex
	}
	if err := fn(dnsproviderremote.ProviderConfig{TenantID: tenantID, ScopeID: scopeID, TenantScopeID: scopeID,
		ProviderID: providerID, ProviderType: providerType, ZoneID: zoneID, ZoneName: configZone, ProviderZoneName: apex,
		Credentials: credentials, CredentialVersion: uint64(version)}, zoneName); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return ErrUnavailable
	}
	return nil
}
