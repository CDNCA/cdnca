package dnsproviderremotesource

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// HubAccount is one own DNS account as the page shows it.
type HubAccount struct {
	ProviderID     uuid.UUID  `json:"provider_id"`
	Name           string     `json:"name"`
	ProviderType   string     `json:"provider_type"`
	Status         string     `json:"status"`
	LastListedAt   *time.Time `json:"last_listed_at"`
	ListError      string     `json:"list_error"`
	DomainCount    int        `json:"domain_count"`
	SupportedLines []string   `json:"supported_lines"`
	SupportsWeight bool       `json:"supports_weight"`
	RecordTypes    []string   `json:"record_types"`
}

// HubDomain is one hosted domain of an own account.
type HubDomain struct {
	ProviderID   uuid.UUID `json:"provider_id"`
	ProviderName string    `json:"provider_name"`
	ProviderType string    `json:"provider_type"`
	Apex         string    `json:"apex"`
	RecordCount  *int      `json:"record_count"`
	LastListedAt time.Time `json:"last_listed_at"`
	ListError    string    `json:"list_error"`
}

type HubDomainPage struct {
	Accounts   []HubAccount `json:"accounts"`
	Items      []HubDomain  `json:"items"`
	NextCursor string       `json:"next_cursor"`
}

type HubDomainQuery struct {
	ProviderID uuid.UUID
	Query      string
	Cursor     string
	Limit      int
}

const (
	HubDefaultDomainLimit = 100
	HubMaxDomainLimit     = 500
)

// ListDomains returns the own accounts and one page of their cached domains
// (apex order, then account). It never calls a provider: refresh does.
func (h *Hub) ListDomains(ctx context.Context, actor HubActor, query HubDomainQuery) (HubDomainPage, error) {
	if query.Limit == 0 {
		query.Limit = HubDefaultDomainLimit
	}
	query.Query = strings.ToLower(strings.TrimSpace(query.Query))
	if query.Limit < 1 || query.Limit > HubMaxDomainLimit || len(query.Query) > 253 {
		return HubDomainPage{}, &HubFieldError{Field: "limit"}
	}
	afterApex, afterProvider, err := decodeHubCursor(query.Cursor)
	if err != nil {
		return HubDomainPage{}, &HubFieldError{Field: "cursor"}
	}
	page := HubDomainPage{Accounts: []HubAccount{}, Items: []HubDomain{}}
	err = pgx.BeginTxFunc(ctx, h.pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		if err := h.authorize(ctx, tx, actor, "dns.read"); err != nil {
			return err
		}
		accounts, err := h.accounts(ctx, tx, actor.ScopeID, query.ProviderID)
		if err != nil {
			return err
		}
		if query.ProviderID != uuid.Nil && len(accounts) == 0 {
			return ErrHubNotFound
		}
		ids := make([]uuid.UUID, 0, len(accounts))
		names := map[uuid.UUID]hubAccount{}
		for _, account := range accounts {
			clear(account.Ciphertext)
			ids = append(ids, account.ID)
			names[account.ID] = account
		}
		listings, err := h.listingStates(ctx, tx, actor.ScopeID, ids)
		if err != nil {
			return err
		}
		for _, account := range accounts {
			state := listings[account.ID]
			page.Accounts = append(page.Accounts, HubAccount{ProviderID: account.ID, Name: account.Name,
				ProviderType: account.ProviderType, Status: hubAccountStatus(account), LastListedAt: state.listedAt,
				ListError: state.listError, DomainCount: state.domains,
				SupportedLines: nonNilLines(dnsproviderremote.SupportedLines(account.ProviderType)),
				SupportsWeight: dnsproviderremote.HubSupportsWeight(account.ProviderType),
				RecordTypes:    slices.Clone(HubRecordTypes)})
		}
		rows, err := tx.Query(ctx, `SELECT provider_id, apex, record_count, last_listed_at, list_error
			FROM tenant_dns_domains
			WHERE scope_id=$1 AND provider_id = ANY($2) AND ($3='' OR strpos(apex,$3)>0)
			  AND ($4='' OR (apex, provider_id::text) > ($4, $5))
			ORDER BY apex, provider_id::text LIMIT $6`,
			actor.ScopeID, ids, query.Query, afterApex, afterProvider, query.Limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var domain HubDomain
			if err := rows.Scan(&domain.ProviderID, &domain.Apex, &domain.RecordCount, &domain.LastListedAt, &domain.ListError); err != nil {
				return err
			}
			account := names[domain.ProviderID]
			domain.ProviderName, domain.ProviderType = account.Name, account.ProviderType
			page.Items = append(page.Items, domain)
		}
		return rows.Err()
	})
	if err != nil {
		return HubDomainPage{}, err
	}
	if len(page.Items) > query.Limit {
		page.Items = page.Items[:query.Limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor = encodeHubCursor(last.Apex, last.ProviderID.String())
	}
	return page, nil
}

func nonNilLines(lines []string) []string {
	if lines == nil {
		return []string{}
	}
	return lines
}

// hubAccountStatus: verified / unverified / disabled, revoked credentials
// read as disabled.
func hubAccountStatus(account hubAccount) string {
	if account.Revoked {
		return "disabled"
	}
	return account.Status
}

type hubListingState struct {
	listedAt  *time.Time
	listError string
	domains   int
}

func (h *Hub) listingStates(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, ids []uuid.UUID) (map[uuid.UUID]hubListingState, error) {
	rows, err := tx.Query(ctx, `SELECT listing.provider_id, listing.last_listed_at, listing.list_error,
			(SELECT count(*) FROM tenant_dns_domains domain
			 WHERE domain.scope_id=listing.scope_id AND domain.provider_id=listing.provider_id)
		FROM tenant_dns_provider_listings listing WHERE listing.scope_id=$1 AND listing.provider_id = ANY($2)`, scopeID, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	states := map[uuid.UUID]hubListingState{}
	for rows.Next() {
		var id uuid.UUID
		var state hubListingState
		if err := rows.Scan(&id, &state.listedAt, &state.listError, &state.domains); err != nil {
			return nil, err
		}
		states[id] = state
	}
	return states, rows.Err()
}

func encodeHubCursor(apex, provider string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(apex + "\x00" + provider))
}

func decodeHubCursor(cursor string) (string, string, error) {
	if cursor == "" {
		return "", "", nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return "", "", err
	}
	apex, provider, found := strings.Cut(string(raw), "\x00")
	if _, parseErr := uuid.Parse(provider); !found || parseErr != nil || apex == "" {
		return "", "", errors.New("malformed cursor")
	}
	return apex, provider, nil
}

// HubRefreshResult is the outcome of refreshing one account's domain list.
type HubRefreshResult struct {
	ProviderID        uuid.UUID `json:"provider_id"`
	State             string    `json:"state"` // refreshed | throttled | failed | skipped
	DomainCount       int       `json:"domain_count"`
	Error             string    `json:"error"`
	RetryAfterSeconds int       `json:"retry_after_seconds"`
}

// RefreshDomains re-lists the hosted domains of providerID (uuid.Nil = every
// own account). An account listed less than refreshInterval ago is
// throttled; unverified, disabled or revoked accounts are skipped. Custom
// HTTP and plugin providers have no domain list: their domains are the
// zones the member registered for them (dns_zones).
func (h *Hub) RefreshDomains(ctx context.Context, actor HubActor, providerID uuid.UUID) ([]HubRefreshResult, error) {
	var accounts []hubAccount
	err := pgx.BeginTxFunc(ctx, h.pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		if err := h.authorize(ctx, tx, actor, "dns.manage"); err != nil {
			return err
		}
		var err error
		accounts, err = h.accounts(ctx, tx, actor.ScopeID, providerID)
		if err == nil && providerID != uuid.Nil && len(accounts) == 0 {
			return ErrHubNotFound
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	results := make([]HubRefreshResult, 0, len(accounts))
	for _, account := range accounts {
		clear(account.Ciphertext)
		result, err := h.refreshAccount(ctx, actor, account.ID)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}
	return results, nil
}

func (h *Hub) refreshAccount(ctx context.Context, actor HubActor, providerID uuid.UUID) (HubRefreshResult, error) {
	result := HubRefreshResult{ProviderID: providerID}
	callCtx, cancel := context.WithTimeout(ctx, hubCallTimeout)
	defer cancel()
	tx, err := h.pool.Begin(callCtx)
	if err != nil {
		return result, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if err := h.authorize(callCtx, tx, actor, "dns.manage"); err != nil {
		return result, err
	}
	account, err := h.account(callCtx, tx, actor.ScopeID, providerID, true)
	if err != nil {
		return result, err
	}
	defer clear(account.Ciphertext)
	if !account.usable() {
		result.State = "skipped"
		return result, nil
	}
	now := h.now().UTC()
	// Throttle per account; the row lock serialises concurrent refreshes.
	if _, err := tx.Exec(callCtx, `INSERT INTO tenant_dns_provider_listings(scope_id,provider_id,updated_at)
		VALUES($1,$2,$3) ON CONFLICT (scope_id,provider_id) DO NOTHING`, actor.ScopeID, providerID, now); err != nil {
		return result, err
	}
	var lastListed *time.Time
	if err := tx.QueryRow(callCtx, `SELECT last_listed_at FROM tenant_dns_provider_listings
		WHERE scope_id=$1 AND provider_id=$2 FOR UPDATE`, actor.ScopeID, providerID).Scan(&lastListed); err != nil {
		return result, err
	}
	if lastListed != nil && now.Sub(*lastListed) < h.refreshInterval {
		result.State = "throttled"
		result.RetryAfterSeconds = int((h.refreshInterval - now.Sub(*lastListed) + time.Second - 1) / time.Second)
		if err := tx.QueryRow(callCtx, `SELECT count(*) FROM tenant_dns_domains WHERE scope_id=$1 AND provider_id=$2`,
			actor.ScopeID, providerID).Scan(&result.DomainCount); err != nil {
			return result, err
		}
		return result, tx.Commit(callCtx)
	}
	domains, listErr := h.hostedDomains(callCtx, tx, actor.ScopeID, account)
	listError := ""
	if listErr != nil {
		listError = providerErrorCode(listErr)
		result.State, result.Error = "failed", listError
	} else {
		if domains == nil {
			domains = []string{} // apex = ANY(NULL) would keep every stale row
		}
		result.State, result.DomainCount = "refreshed", len(domains)
		if _, err := tx.Exec(callCtx, `DELETE FROM tenant_dns_domains WHERE scope_id=$1 AND provider_id=$2 AND NOT (apex = ANY($3))`,
			actor.ScopeID, providerID, domains); err != nil {
			return result, err
		}
		if _, err := tx.Exec(callCtx, `INSERT INTO tenant_dns_domains(scope_id,provider_id,apex,last_listed_at)
			SELECT $1,$2,apex,$4 FROM unnest($3::text[]) AS apex
			ON CONFLICT (scope_id,provider_id,apex) DO UPDATE SET last_listed_at=EXCLUDED.last_listed_at, list_error=''`,
			actor.ScopeID, providerID, domains, now); err != nil {
			return result, err
		}
	}
	if _, err := tx.Exec(callCtx, `UPDATE tenant_dns_provider_listings SET last_listed_at=$3, list_error=$4, updated_at=$3
		WHERE scope_id=$1 AND provider_id=$2`, actor.ScopeID, providerID, now, listError); err != nil {
		return result, err
	}
	auditResult, reason := "success", ""
	if listErr != nil {
		auditResult, reason = "failure", listError
	}
	if err := h.auditor.Append(callCtx, tx, audit.Event{
		ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: "dns.hub.domain.refresh",
		ResourceType: "dns_provider", ResourceID: providerID.String(), RequestID: actor.RequestID,
		Result: auditResult, ReasonCode: reason,
		Payload: map[string]any{"provider_name": account.Name, "provider_type": account.ProviderType,
			"domain_count": result.DomainCount},
	}); err != nil {
		return result, err
	}
	return result, tx.Commit(callCtx)
}

// hostedDomains lists the account's domains from the provider; custom HTTP
// and plugin accounts use the member's own dns_zones rows for them.
func (h *Hub) hostedDomains(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, account hubAccount) ([]string, error) {
	if account.ProviderType == "custom_http" || account.ProviderType == "plugin" {
		rows, err := tx.Query(ctx, `SELECT DISTINCT COALESCE(NULLIF(provider_zone_apex,''), name) FROM dns_zones
			WHERE scope_id=$1 AND provider_id=$2 ORDER BY 1`, scopeID, account.ID)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var domains []string
		for rows.Next() {
			var domain string
			if err := rows.Scan(&domain); err != nil {
				return nil, err
			}
			domains = append(domains, domain)
		}
		return domains, rows.Err()
	}
	credentials, err := h.credentials(scopeID, account)
	if err != nil {
		return nil, err
	}
	defer clearCredentials(credentials)
	domains, err := h.remote.HostedDomains(ctx, account.ProviderType, credentials)
	if err != nil {
		return nil, err
	}
	if len(domains) > HubMaxDomainsPerAccount {
		return nil, fmt.Errorf("dns hub: %d domains exceed %d: %w", len(domains), HubMaxDomainsPerAccount,
			&dnsproviderremote.Error{Code: dnsproviderremote.CodeInvalidResponse})
	}
	return slices.DeleteFunc(domains, func(domain string) bool { return !hubApexPattern.MatchString(domain) }), nil
}

// hubApexPattern is the tenant_dns_domains.apex CHECK (migration 599): a
// provider listing a name outside it (single label, IDN in another form) is
// left out rather than failing the refresh.
var hubApexPattern = regexp.MustCompile(`^([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
