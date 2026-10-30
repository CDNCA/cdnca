package dnsproviderremotesource

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Hub is 用户端「域名解析」(ADR 0020 §3): one tenant's own DNS accounts
// (managed_by='tenant'; the platform copy is never visible), their hosted
// domains (a cached list, refreshed at most once a minute per account) and
// the domains' A/AAAA/CNAME/TXT records, read live from the provider and
// written through the reconcile adapters with a read-back.
//
// Every call is authorized here, in the database: an active member of an
// active tenant scope holding dns.read (reads) or dns.manage (writes)
// through the tenant's effective RBAC. Another tenant's account, domain or
// record reads as ErrHubNotFound.
type Hub struct {
	pool    *pgxpool.Pool
	cipher  dnsacme.BoundCredentialCipher
	remote  dnsproviderremote.HubRemote
	auditor HubAuditor
	now     func() time.Time
	// refreshInterval is the shortest time between two domain listings of
	// one account (ADR 0020 §3.1: 60 seconds).
	refreshInterval time.Duration
}

type HubAuditor interface {
	Append(context.Context, pgx.Tx, audit.Event) error
}

const (
	HubRefreshInterval = time.Minute
	hubCallTimeout     = 2 * time.Minute
	// HubMaxDomainsPerAccount bounds one account's cached list.
	HubMaxDomainsPerAccount = 5000
)

// Hub errors the HTTP layer maps (a *dnsproviderremote.Error is a provider
// failure and maps to 502).
var (
	ErrHubPermission  = errors.New("dns hub: permission denied")
	ErrHubNotFound    = errors.New("dns hub: not found")
	ErrHubInvalid     = errors.New("dns hub: invalid input")
	ErrHubUnsupported = errors.New("dns hub: unsupported by the DNS provider")
	ErrHubIdempotency = errors.New("dns hub: idempotency key reused with another request")
)

// HubFieldError is ErrHubInvalid naming the offending field.
type HubFieldError struct{ Field string }

func (e *HubFieldError) Error() string { return "dns hub: invalid " + e.Field }
func (e *HubFieldError) Unwrap() error { return ErrHubInvalid }

// HubActor is the tenant session member.
type HubActor struct {
	UserID, ScopeID uuid.UUID
	ScopeKind       string
	RequestID       string
}

func NewHub(source *Source, remote dnsproviderremote.HubRemote, auditor HubAuditor, now func() time.Time) (*Hub, error) {
	if source == nil || source.pool == nil || remote == nil || auditor == nil {
		return nil, ErrUnavailable
	}
	bound, ok := source.cipher.(dnsacme.BoundCredentialCipher)
	if !ok {
		return nil, ErrUnavailable
	}
	if now == nil {
		now = time.Now
	}
	return &Hub{pool: source.pool, cipher: bound, remote: remote, auditor: auditor, now: now,
		refreshInterval: HubRefreshInterval}, nil
}

// authorize checks the actor inside tx (see Hub).
func (h *Hub) authorize(ctx context.Context, tx pgx.Tx, actor HubActor, permission string) error {
	if actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || actor.ScopeKind != "tenant" {
		return ErrHubPermission
	}
	var allowed bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(
			SELECT 1 FROM access_scopes scope
			JOIN tenants tenant ON tenant.id=scope.tenant_id
			JOIN memberships membership ON membership.scope_id=scope.id AND membership.user_id=$2
			JOIN users account ON account.id=membership.user_id
			WHERE scope.id=$1 AND scope.kind='tenant' AND tenant.status='active' AND
			      membership.status='active' AND account.status='active'
		) AND EXISTS(SELECT 1 FROM custom_rbac_effective_permissions($1,$2) WHERE permission_name=$3)`,
		actor.ScopeID, actor.UserID, permission).Scan(&allowed)
	if err != nil {
		return err
	}
	if !allowed {
		return ErrHubPermission
	}
	return nil
}

// hubAccount is one of the tenant's own DNS accounts.
type hubAccount struct {
	ID           uuid.UUID
	TenantID     uuid.UUID
	Name         string
	ProviderType string
	Status       string
	Revoked      bool
	KeyID        string
	Ciphertext   []byte
	Version      int64
}

func (account hubAccount) usable() bool {
	return account.Status == "verified" && !account.Revoked && supportedProviderType(account.ProviderType)
}

const hubAccountColumns = `provider.id, scope.tenant_id, provider.name, provider.provider_type, provider.status,
	provider.credential_revoked, provider.credential_key_id, provider.credential_ciphertext, provider.credential_version`

// hubAccountsSQL lists the scope's own accounts: tenant scope, entered by
// the tenant (never the platform copy, whatever its managed_by says).
const hubAccountsSQL = `SELECT ` + hubAccountColumns + `
	FROM dns_providers provider
	JOIN access_scopes scope ON scope.id=provider.scope_id AND scope.kind='tenant'
	WHERE provider.scope_id=$1 AND provider.managed_by='tenant' AND provider.id<>$2`

func scanHubAccount(row pgx.Row) (hubAccount, error) {
	var account hubAccount
	err := row.Scan(&account.ID, &account.TenantID, &account.Name, &account.ProviderType, &account.Status,
		&account.Revoked, &account.KeyID, &account.Ciphertext, &account.Version)
	return account, err
}

func (h *Hub) accounts(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, providerID uuid.UUID) ([]hubAccount, error) {
	query := hubAccountsSQL
	args := []any{scopeID, dnsacme.PlatformProviderCopyID(scopeID)}
	if providerID != uuid.Nil {
		query += ` AND provider.id=$3`
		args = append(args, providerID)
	}
	rows, err := tx.Query(ctx, query+` ORDER BY provider.created_at, provider.id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var accounts []hubAccount
	for rows.Next() {
		account, err := scanHubAccount(rows)
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, account)
	}
	return accounts, rows.Err()
}

// account loads one own account; FOR SHARE when lock (a credential
// replacement waits for the provider call, as LineRecords).
func (h *Hub) account(ctx context.Context, tx pgx.Tx, scopeID, providerID uuid.UUID, lock bool) (hubAccount, error) {
	query := hubAccountsSQL + ` AND provider.id=$3`
	if lock {
		query += ` FOR SHARE OF provider`
	}
	account, err := scanHubAccount(tx.QueryRow(ctx, query, scopeID, dnsacme.PlatformProviderCopyID(scopeID), providerID))
	if errors.Is(err, pgx.ErrNoRows) {
		return hubAccount{}, ErrHubNotFound
	}
	return account, err
}

// credentials decrypts the account's credential (caller clears it).
func (h *Hub) credentials(scopeID uuid.UUID, account hubAccount) (map[string]string, error) {
	if account.Version <= 0 {
		return nil, ErrUnavailable
	}
	plaintext, err := h.cipher.DecryptCredential(dnsacme.CredentialBinding{
		TenantID: account.TenantID, ScopeID: scopeID, ProviderID: account.ID}, account.KeyID, account.Ciphertext)
	defer clear(plaintext)
	if err != nil || len(plaintext) == 0 {
		return nil, ErrUnavailable
	}
	return decodeCredentials(account.ProviderType, plaintext)
}

// providerConfig is the adapter config of apex (no dns_zones row: ZoneID only
// identifies the call, as SiteAutoDNSWriter).
func hubProviderConfig(scopeID uuid.UUID, account hubAccount, apex string, credentials map[string]string, operationID string) dnsproviderremote.ProviderConfig {
	return dnsproviderremote.ProviderConfig{TenantID: account.TenantID, ScopeID: scopeID, TenantScopeID: scopeID,
		ProviderID: account.ID, ProviderType: account.ProviderType, ZoneID: account.ID, ZoneName: apex,
		ProviderZoneName: apex, Credentials: credentials, CredentialVersion: uint64(account.Version),
		OperationID: operationID}
}

// HubRecordTypes is the record type order shown to members.
var HubRecordTypes = []string{"A", "AAAA", "CNAME", "TXT"}

func hubRecordType(name string) (dnscheck.RecordType, bool) {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "A":
		return dnscheck.RecordA, true
	case "AAAA":
		return dnscheck.RecordAAAA, true
	case "CNAME":
		return dnscheck.RecordCNAME, true
	case "TXT":
		return dnscheck.RecordTXT, true
	default:
		return 0, false
	}
}

// providerErrorCode is the short code shown for a provider failure.
func providerErrorCode(err error) string {
	if code := dnsproviderremote.ErrorCodeOf(err); code != "" {
		return strings.TrimPrefix(string(code), "dns_provider_remote_")
	}
	return "unavailable"
}
