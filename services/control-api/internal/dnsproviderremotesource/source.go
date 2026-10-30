package dnsproviderremotesource

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/acmeworker"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/cdnca/cdnca/services/control-api/internal/tenantaccess"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrUnavailable = errors.New("dns provider source unavailable")

// The provider creator and the issuance actor act on the tenant: an active
// tenant member or a platform administrator (a platform member creating the
// provider or ordering the certificate for the tenant). "active" otherwise "".
var (
	creatorMemberSQL = memberStatusSQL("provider.created_by_user_id")
	actorMemberSQL   = memberStatusSQL("operation.actor_user_id")
)

func memberStatusSQL(userExpr string) string {
	return "CASE WHEN " + tenantaccess.ActorOnTenantSQL(userExpr, "provider.scope_id") + " THEN 'active' ELSE '' END"
}

type Source struct {
	pool   *pgxpool.Pool
	cipher dnsacme.CredentialCipher
	// apex looks up the hosted domain of a zone saved before migration 473.
	apex dnsproviderremote.ZoneApexResolver
}

// UseZoneApexResolver replaces the provider domain-list lookup (tests).
func (s *Source) UseZoneApexResolver(resolver dnsproviderremote.ZoneApexResolver) { s.apex = resolver }

// zoneApex returns the stored apex or looks it up once and writes it back
// (dnsacme.EnsureZoneApex). db nil writes through the pool.
func (s *Source) zoneApex(ctx context.Context, db dnsacme.ZoneApexExecer, scopeID, zoneID uuid.UUID,
	providerType string, credentials map[string]string, zoneName, stored string) (string, error) {
	if db == nil {
		db = s.pool
	}
	return dnsacme.EnsureZoneApex(ctx, db, s.apex, scopeID, zoneID, providerType, credentials, zoneName, stored)
}

type boundCredentialDecryptor struct {
	cipher  dnsacme.BoundCredentialCipher
	binding dnsacme.CredentialBinding
}

func (decryptor boundCredentialDecryptor) Decrypt(keyID string, ciphertext []byte) ([]byte, error) {
	return decryptor.cipher.DecryptCredential(decryptor.binding, keyID, ciphertext)
}

func New(pool *pgxpool.Pool, cipher dnsacme.CredentialCipher) *Source {
	return &Source{pool: pool, cipher: cipher, apex: dnsproviderremote.NewZoneApexResolver()}
}

func (s *Source) Resolve(
	ctx context.Context,
	lookup dnsproviderremote.ProviderLookup,
) (dnsproviderremote.ProviderConfig, error) {
	if ctx == nil || ctx.Err() != nil ||
		lookup.TenantID == uuid.Nil || lookup.ScopeID == uuid.Nil || lookup.TenantScopeID != lookup.ScopeID ||
		!validOperationID(lookup.OperationID) || lookup.ProviderID == uuid.Nil || lookup.ZoneID == uuid.Nil ||
		s == nil || s.pool == nil || s.cipher == nil {
		return dnsproviderremote.ProviderConfig{}, ErrUnavailable
	}
	boundCipher, ok := s.cipher.(dnsacme.BoundCredentialCipher)
	if !ok {
		return dnsproviderremote.ProviderConfig{}, ErrUnavailable
	}
	owner, ok := canonicalOwner(lookup.OwnerName)
	if !ok {
		return dnsproviderremote.ProviderConfig{}, ErrUnavailable
	}
	ownerWithoutDot := strings.TrimSuffix(owner, ".")
	var result dnsproviderremote.ProviderConfig
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var (
			storedTenantID    uuid.UUID
			storedProviderID  uuid.UUID
			scopeID           uuid.UUID
			zoneID            uuid.UUID
			zoneName          string
			zoneApex          string
			providerType      string
			providerStatus    string
			keyID             string
			ciphertext        []byte
			credentialVersion int64
			credentialRevoked bool
			operationActor    uuid.UUID
			createdActor      uuid.UUID
			frozenTenant      string
			frozenScope       string
			frozenProvider    string
			frozenZone        string
			frozenActor       string
			scopeKind         string
			tenantStatus      string
			actorStatus       string
			membership        string
			operationStatus   string
			operationMember   string
			platformManaged   bool
			platformActor     bool
		)
		err := tx.QueryRow(ctx, `
			SELECT tenant.id,provider.id,provider.scope_id,provider.provider_type,provider.status,
			       provider.credential_key_id,provider.credential_ciphertext,
			       provider.credential_version,provider.credential_revoked,operation.actor_user_id,
			       provider.created_by_user_id,
			       operation.request_snapshot ->> 'TenantID',operation.request_snapshot ->> 'ScopeID',
			       operation.request_snapshot ->> 'ProviderID',operation.request_snapshot ->> 'ZoneID',
			       operation.request_snapshot ->> 'ActorUserID',
			       scope.kind,tenant.status,creator.status,`+creatorMemberSQL+`,
			       actor.status,`+actorMemberSQL+`,zone.id,zone.name,COALESCE(zone.provider_zone_apex,''),
			       provider.managed_by='platform' OR provider.id=$6,
			       `+tenantaccess.PlatformAdminSQL("operation.actor_user_id", "NULL")+`
			FROM dns_providers AS provider
			JOIN access_scopes AS scope ON scope.id=provider.scope_id
			JOIN tenants AS tenant ON tenant.id=scope.tenant_id
			JOIN users AS creator ON creator.id=provider.created_by_user_id
			JOIN acme_issuance_operations AS operation
			  ON operation.tenant_scope_id=provider.scope_id
			 AND operation.operation_id=$5
			 AND operation.dns_provider_id=provider.id
			JOIN users AS actor ON actor.id=operation.actor_user_id
			JOIN dns_zones AS zone
			  ON zone.scope_id=provider.scope_id AND zone.provider_id=provider.id AND zone.id=$4
			WHERE provider.id=$1 AND provider.scope_id=$2 AND tenant.id=$3
			FOR SHARE OF provider,scope,tenant,creator,operation,actor,zone`,
			lookup.ProviderID, lookup.ScopeID, lookup.TenantID, lookup.ZoneID, lookup.OperationID,
			dnsacme.PlatformProviderCopyID(lookup.ScopeID),
		).Scan(
			&storedTenantID, &storedProviderID, &scopeID, &providerType, &providerStatus, &keyID, &ciphertext,
			&credentialVersion, &credentialRevoked, &operationActor, &createdActor,
			&frozenTenant, &frozenScope, &frozenProvider, &frozenZone, &frozenActor, &scopeKind, &tenantStatus,
			&actorStatus, &membership, &operationStatus, &operationMember, &zoneID, &zoneName, &zoneApex,
			&platformManaged, &platformActor,
		)
		if err != nil {
			return ErrUnavailable
		}
		defer clear(ciphertext)
		frozenTenantID, tenantErr := uuid.Parse(frozenTenant)
		frozenScopeID, scopeErr := uuid.Parse(frozenScope)
		frozenProviderID, providerErr := uuid.Parse(frozenProvider)
		frozenZoneID, zoneErr := uuid.Parse(frozenZone)
		frozenActorID, actorErr := uuid.Parse(frozenActor)
		if storedTenantID != lookup.TenantID || storedProviderID != lookup.ProviderID ||
			scopeID != lookup.ScopeID || zoneID != lookup.ZoneID || operationActor == uuid.Nil || createdActor == uuid.Nil ||
			tenantErr != nil || scopeErr != nil || providerErr != nil || zoneErr != nil || actorErr != nil ||
			frozenTenantID != lookup.TenantID || frozenScopeID != lookup.ScopeID ||
			frozenProviderID != lookup.ProviderID || frozenZoneID != lookup.ZoneID ||
			frozenActorID != operationActor ||
			(lookup.ActorUserID != uuid.Nil && lookup.ActorUserID != operationActor) ||
			scopeKind != "tenant" || tenantStatus != "active" || actorStatus != "active" ||
			membership != "active" || operationStatus != "active" || operationMember != "active" ||
			providerStatus != dnsacme.ProviderStatusVerified ||
			// DNS-SEC-20261027-01: the platform DNS copy only for an
			// operation a platform administrator started.
			(platformManaged && !platformActor) ||
			credentialVersion <= 0 || credentialRevoked || keyID == "" ||
			!supportedProviderType(providerType) || !validDNSName(zoneName) ||
			(ownerWithoutDot != zoneName && !strings.HasSuffix(ownerWithoutDot, "."+zoneName)) {
			return ErrUnavailable
		}
		decryptor := boundCredentialDecryptor{cipher: boundCipher, binding: dnsacme.CredentialBinding{
			TenantID: storedTenantID, ScopeID: scopeID, ProviderID: storedProviderID,
		}}
		plaintext, err := decryptor.Decrypt(keyID, ciphertext)
		if err != nil || len(plaintext) == 0 {
			clear(plaintext)
			return ErrUnavailable
		}
		defer clear(plaintext)
		credentials, err := decodeCredentials(providerType, plaintext)
		if err != nil {
			return ErrUnavailable
		}
		result = dnsproviderremote.ProviderConfig{
			TenantID: storedTenantID, ScopeID: scopeID, TenantScopeID: scopeID,
			OperationID: lookup.OperationID, ActorUserID: operationActor,
			ProviderID: storedProviderID, ProviderType: providerType,
			ZoneID: zoneID, ZoneName: zoneName, ProviderZoneName: zoneApex, Credentials: credentials,
			CredentialVersion: uint64(credentialVersion), CredentialRevoked: false,
		}
		return nil
	})
	if err != nil {
		return dnsproviderremote.ProviderConfig{}, ErrUnavailable
	}
	result.ProviderZoneName, err = s.zoneApex(ctx, nil, result.ScopeID, result.ZoneID, result.ProviderType,
		result.Credentials, result.ZoneName, result.ProviderZoneName)
	if err != nil {
		clearCredentials(result.Credentials)
		return dnsproviderremote.ProviderConfig{}, ErrUnavailable
	}
	return result, nil
}

// CheckCredentialFence performs a metadata-only read immediately before or
// after a provider call. It never returns credential material.
func (s *Source) CheckCredentialFence(ctx context.Context, lookup dnsproviderremote.ProviderLookup, version uint64) error {
	lease, err := s.AcquireProviderCredentialLease(ctx, lookup, version)
	if err != nil {
		return err
	}
	releaseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return lease(releaseCtx)
}

func (s *Source) AcquireProviderCredentialLease(
	ctx context.Context,
	lookup dnsproviderremote.ProviderLookup,
	version uint64,
) (dnsproviderremote.ProviderCredentialLease, error) {
	if ctx == nil || ctx.Err() != nil || s == nil || s.pool == nil ||
		lookup.TenantID == uuid.Nil || lookup.ScopeID == uuid.Nil || lookup.TenantScopeID != lookup.ScopeID ||
		!validOperationID(lookup.OperationID) || lookup.ActorUserID == uuid.Nil ||
		lookup.ProviderID == uuid.Nil || lookup.ZoneID == uuid.Nil || version == 0 {
		return nil, ErrUnavailable
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, ErrUnavailable
	}
	keepOpen := false
	defer func() {
		if !keepOpen {
			rollbackCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = tx.Rollback(rollbackCtx)
		}
	}()
	err = func() error {
		var storedTenant, storedScope, storedProvider, storedZone, operationActor, createdActor uuid.UUID
		var frozenTenant, frozenScope, frozenProvider, frozenZone, frozenActor string
		var currentVersion int64
		var revoked bool
		var status, tenantStatus, actorStatus, membership, operationStatus, operationMember string
		err := tx.QueryRow(ctx, `
			SELECT tenant.id,provider.scope_id,provider.id,zone.id,provider.credential_version,
			       provider.credential_revoked,provider.status,tenant.status,
			       operation.actor_user_id,provider.created_by_user_id,
			       operation.request_snapshot ->> 'TenantID',operation.request_snapshot ->> 'ScopeID',
			       operation.request_snapshot ->> 'ProviderID',operation.request_snapshot ->> 'ZoneID',
			       operation.request_snapshot ->> 'ActorUserID',creator.status,`+creatorMemberSQL+`,
			       actor.status,`+actorMemberSQL+`
			FROM dns_providers provider
			JOIN access_scopes scope ON scope.id=provider.scope_id AND scope.kind='tenant'
			JOIN tenants tenant ON tenant.id=scope.tenant_id
			JOIN users AS creator ON creator.id=provider.created_by_user_id
			JOIN acme_issuance_operations AS operation
			  ON operation.tenant_scope_id=provider.scope_id
			 AND operation.operation_id=$5
			 AND operation.dns_provider_id=provider.id
			JOIN users AS actor ON actor.id=operation.actor_user_id
			JOIN dns_zones zone ON zone.scope_id=provider.scope_id AND zone.provider_id=provider.id AND zone.id=$4
			WHERE provider.id=$1 AND provider.scope_id=$2 AND tenant.id=$3
			FOR SHARE OF provider,scope,tenant,creator,operation,actor,zone`,
			lookup.ProviderID, lookup.ScopeID, lookup.TenantID, lookup.ZoneID, lookup.OperationID,
		).Scan(&storedTenant, &storedScope, &storedProvider, &storedZone, &currentVersion, &revoked,
			&status, &tenantStatus, &operationActor, &createdActor, &frozenTenant, &frozenScope, &frozenProvider,
			&frozenZone, &frozenActor, &actorStatus, &membership, &operationStatus, &operationMember)
		frozenTenantID, tenantErr := uuid.Parse(frozenTenant)
		frozenScopeID, scopeErr := uuid.Parse(frozenScope)
		frozenProviderID, providerErr := uuid.Parse(frozenProvider)
		frozenZoneID, zoneErr := uuid.Parse(frozenZone)
		frozenActorID, actorErr := uuid.Parse(frozenActor)
		if err != nil || storedTenant != lookup.TenantID || storedScope != lookup.ScopeID ||
			storedProvider != lookup.ProviderID || storedZone != lookup.ZoneID ||
			tenantErr != nil || scopeErr != nil || providerErr != nil || zoneErr != nil || actorErr != nil ||
			frozenTenantID != lookup.TenantID || frozenScopeID != lookup.ScopeID ||
			frozenProviderID != lookup.ProviderID || frozenZoneID != lookup.ZoneID ||
			operationActor != lookup.ActorUserID || frozenActorID != operationActor ||
			currentVersion <= 0 || uint64(currentVersion) != version || operationActor == uuid.Nil || createdActor == uuid.Nil ||
			revoked || status != dnsacme.ProviderStatusVerified || tenantStatus != "active" ||
			actorStatus != "active" || membership != "active" ||
			operationStatus != "active" || operationMember != "active" {
			return ErrUnavailable
		}
		return nil
	}()
	if err != nil {
		return nil, ErrUnavailable
	}
	keepOpen = true
	released := false
	return func(releaseCtx context.Context) error {
		if released {
			return ErrUnavailable
		}
		released = true
		if releaseCtx == nil || releaseCtx.Err() != nil {
			rollbackCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = tx.Rollback(rollbackCtx)
			return ErrUnavailable
		}
		if err := tx.Commit(releaseCtx); err != nil {
			rollbackCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = tx.Rollback(rollbackCtx)
			return ErrUnavailable
		}
		return nil
	}, nil
}

func validOperationID(value string) bool {
	return value != "" && value == strings.TrimSpace(value) && len(value) <= 200 &&
		strings.IndexFunc(value, unicode.IsControl) < 0
}

func (s *Source) OutstandingRemoteTXTHandles(ctx context.Context) ([]acmeworker.ChallengeIdentity, error) {
	if ctx == nil || ctx.Err() != nil || s == nil || s.pool == nil {
		return nil, ErrUnavailable
	}
	rows, err := s.pool.Query(ctx, `
			SELECT attempt.tenant_scope_id,attempt.operation_id,attempt.attempt_id,
			       attempt.authorization_url,attempt.challenge_url,attempt.challenge_type,
			       attempt.identifier,attempt.wildcard,attempt.record_name,attempt.token,
			       attempt.exact_value,latest.provider_ref,latest.remote_record_ref,
			       latest.exact_value_sha256,operation.request_snapshot ->> 'TenantID',
			       operation.request_snapshot ->> 'ScopeID',operation.request_snapshot ->> 'ProviderID',
			       operation.request_snapshot ->> 'ZoneID',operation.request_snapshot ->> 'ProviderRef'
			FROM acme_issuance_challenge_attempts AS attempt
			JOIN acme_issuance_operations AS operation
			  ON operation.tenant_scope_id=attempt.tenant_scope_id
			 AND operation.operation_id=attempt.operation_id
			JOIN LATERAL (
			    SELECT state,provider_ref,remote_record_ref,exact_value_sha256
			    FROM acme_issuance_challenge_events AS event
			    WHERE event.tenant_scope_id=attempt.tenant_scope_id
		      AND event.operation_id=attempt.operation_id
		      AND event.attempt_id=attempt.attempt_id
		    ORDER BY revision DESC LIMIT 1
		) AS latest ON true
			WHERE latest.state <> 'cleaned'
			  AND (latest.remote_record_ref LIKE 'v1.%' OR latest.remote_record_ref LIKE 'v2.%')
			ORDER BY attempt.tenant_scope_id,attempt.operation_id,attempt.attempt_id`)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer rows.Close()
	var result []acmeworker.ChallengeIdentity
	for rows.Next() {
		var challenge acmeworker.ChallengeIdentity
		var storedScope uuid.UUID
		var exactDigest []byte
		var frozenTenant, frozenScope, frozenProviderID, frozenZone, frozenProviderRef string
		if err := rows.Scan(
			&storedScope, &challenge.OperationID, &challenge.AttemptID,
			&challenge.AuthorizationURL, &challenge.ChallengeURL, &challenge.ChallengeType,
			&challenge.Identifier, &challenge.Wildcard, &challenge.RecordName, &challenge.Token,
			&challenge.ExactValue, &challenge.TXTHandle.ProviderRef, &challenge.TXTHandle.RecordRef,
			&exactDigest, &frozenTenant, &frozenScope, &frozenProviderID, &frozenZone, &frozenProviderRef,
		); err != nil {
			return nil, ErrUnavailable
		}
		tenantID, tenantErr := uuid.Parse(frozenTenant)
		scopeID, scopeErr := uuid.Parse(frozenScope)
		providerID, providerErr := uuid.Parse(frozenProviderID)
		zoneID, zoneErr := uuid.Parse(frozenZone)
		expectedDigest := sha256.Sum256([]byte(challenge.ExactValue))
		if tenantErr != nil || scopeErr != nil || providerErr != nil || zoneErr != nil ||
			tenantID == uuid.Nil || scopeID == uuid.Nil || providerID == uuid.Nil || zoneID == uuid.Nil ||
			storedScope != scopeID || challenge.ChallengeType != acmeworker.ChallengeDNS01 ||
			frozenProviderRef != providerID.String() || challenge.TXTHandle.ProviderRef != frozenProviderRef ||
			len(exactDigest) != sha256.Size || !hmac.Equal(exactDigest, expectedDigest[:]) {
			return nil, ErrUnavailable
		}
		challenge.TenantID = tenantID
		challenge.ScopeID = scopeID
		challenge.ProviderID = providerID
		challenge.ZoneID = zoneID
		challenge.ProviderRef = challenge.TXTHandle.ProviderRef
		result = append(result, challenge)
	}
	if rows.Err() != nil {
		return nil, ErrUnavailable
	}
	return result, nil
}

func canonicalOwner(value string) (string, bool) {
	if value == "" || value != strings.TrimSpace(value) || !strings.HasSuffix(value, ".") ||
		strings.ToLower(value) != value {
		return "", false
	}
	withoutDot := strings.TrimSuffix(value, ".")
	if !validDNSName(withoutDot) {
		return "", false
	}
	return withoutDot + ".", true
}

func validDNSName(value string) bool {
	if value == "" || len(value) > 253 || !utf8.ValidString(value) || strings.ToLower(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for index := range len(label) {
			character := label[index]
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') &&
				character != '-' && character != '_' {
				return false
			}
		}
	}
	return true
}

func supportedProviderType(providerType string) bool {
	switch providerType {
	case "cloudflare", "aliyun", "huawei", "dnspod_cn", "dns_com", "dns_la", "namecom", "custom_http", "plugin":
		return true
	default:
		return false
	}
}

func decodeCredentials(providerType string, raw []byte) (credentials map[string]string, resultErr error) {
	fields, ok := credentialFields(providerType)
	if !ok {
		return nil, ErrUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, ErrUnavailable
	}
	credentials = make(map[string]string, len(fields))
	defer func() {
		if resultErr != nil {
			clearCredentials(credentials)
			credentials = nil
		}
	}()
	for decoder.More() {
		token, err := decoder.Token()
		field, valid := token.(string)
		if err != nil || !valid {
			return nil, ErrUnavailable
		}
		if _, expected := fields[field]; !expected {
			return nil, ErrUnavailable
		}
		if _, duplicate := credentials[field]; duplicate {
			return nil, ErrUnavailable
		}
		var value string
		if err := decoder.Decode(&value); err != nil || !validCredentialValue(field, value) {
			return nil, ErrUnavailable
		}
		credentials[field] = value
	}
	// DNS.COM's plan tier is optional (absent = free).
	_, hasPlan := credentials["plan"]
	complete := len(credentials) == len(fields) || providerType == "dns_com" && !hasPlan && len(credentials) == len(fields)-1
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') || !complete {
		return nil, ErrUnavailable
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, ErrUnavailable
	}
	return credentials, nil
}

func credentialFields(providerType string) (map[string]struct{}, bool) {
	var fields []string
	switch providerType {
	case "cloudflare":
		fields = []string{"api_token"}
	case "aliyun":
		fields = []string{"access_key_id", "access_key_secret"}
	case "huawei":
		fields = []string{"access_key", "secret_key", "region", "project_id"}
	case "dnspod_cn":
		fields = []string{"dp_id", "dp_key"}
	case "dns_com":
		fields = []string{"api_key", "api_secret", "plan"}
	case "dns_la":
		fields = []string{"api_id", "api_secret"}
	case "namecom":
		fields = []string{"username", "api_token"}
	case "custom_http":
		fields = []string{"endpoint", "secret"}
	case "plugin":
		fields = []string{"plugin_id"}
	default:
		return nil, false
	}
	result := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		result[field] = struct{}{}
	}
	return result, true
}

func validCredentialValue(field, value string) bool {
	if value == "" || len(value) > 4096 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return field != "api_id" || !strings.Contains(value, ":")
}

var _ dnsproviderremote.StartupSource = (*Source)(nil)
var _ dnsproviderremote.ProviderCredentialLeaseAuthority = (*Source)(nil)
