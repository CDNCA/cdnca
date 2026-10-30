package securityrulecatalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cdnca/cdnca/libs/edgeconfig/crawlerdefaults"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"slices"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrInvalidInput  = errors.New("invalid security system rule request")
	ErrNotFound      = errors.New("security system rule not found")
	ErrWithdrawnRule = errors.New("withdrawn security system rules cannot be enabled")
)

// Viewer identifies who is listing rules. Platform admins see every system
// rule with its visibility overlay; tenants see only rules shown to them.
type Viewer struct {
	UserID   uuid.UUID
	ScopeID  uuid.UUID
	Platform bool
}

// Authorize runs the caller's permission check inside the query transaction.
type Authorize func(context.Context, pgx.Tx) error

type Visibility struct {
	Visible        bool        `json:"visible"`
	ShowToScopeIDs []uuid.UUID `json:"show_to_scope_ids"`
	Revision       uint64      `json:"revision"`
}

// Rule is a system rule as shown in the management UI. Params are read-only;
// tenants may only toggle Enabled. Withdrawn rules stay frozen at their last
// revision ("已下线") and are not selectable for new sites.
type Rule struct {
	SystemKey   string               `json:"system_key"`
	Kind        string               `json:"kind"`
	LegacyID    string               `json:"legacy_id"`
	Name        string               `json:"name"`
	Description string               `json:"description"`
	Sort        int                  `json:"sort"`
	Revision    uint64               `json:"revision"`
	Body        rulecatalog.ItemBody `json:"body"`
	Status      string               `json:"status"`
	Selectable  bool                 `json:"selectable"`
	Enabled     bool                 `json:"enabled"`
	Visibility  *Visibility          `json:"visibility,omitempty"`
	UpdatedAt   time.Time            `json:"updated_at"`
}

type Status struct {
	Synced         bool       `json:"synced"`
	DeliveryID     string     `json:"delivery_id,omitempty"`
	ScopeRevision  uint64     `json:"scope_revision"`
	CatalogSHA256  string     `json:"catalog_sha256,omitempty"`
	AppliedAt      *time.Time `json:"applied_at,omitempty"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	Stale          bool       `json:"stale"`
	LastAttemptAt  *time.Time `json:"last_attempt_at,omitempty"`
	LastSuccessAt  *time.Time `json:"last_success_at,omitempty"`
	LastErrorCode  string     `json:"last_error_code"`
	ActiveCount    int        `json:"active_count"`
	WithdrawnCount int        `json:"withdrawn_count"`
}

func (store *Store) List(ctx context.Context, viewer Viewer, kind string, authorize Authorize) ([]Rule, error) {
	if viewer.UserID == uuid.Nil || viewer.ScopeID == uuid.Nil || authorize == nil || kind != "" && rulecatalog.KindPrefix[kind] == "" {
		return nil, ErrInvalidInput
	}
	result := []Rule{}
	// Not read-only: the IAM authorizer takes FOR SHARE locks in this transaction.
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := authorize(ctx, tx); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT rule.system_key,rule.kind,rule.legacy_id,rule.name,rule.description,rule.sort,rule.hidden,
			rule.revision,rule.body,rule.status,rule.updated_at,visibility.visible,visibility.show_to_scope_ids,visibility.revision,
			state.enabled
			FROM security_system_rules rule
			LEFT JOIN security_system_rule_visibility visibility ON visibility.system_key=rule.system_key
			LEFT JOIN security_system_rule_tenant_states state ON state.system_key=rule.system_key AND state.scope_id=$2
			WHERE ($1='' OR rule.kind=$1) ORDER BY rule.kind,rule.sort,rule.system_key`, kind, viewer.ScopeID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var rule Rule
			var hidden bool
			var body []byte
			var visible, tenantEnabled *bool
			var showTo []uuid.UUID
			var visibilityRevision *uint64
			if err := rows.Scan(&rule.SystemKey, &rule.Kind, &rule.LegacyID, &rule.Name, &rule.Description, &rule.Sort, &hidden,
				&rule.Revision, &body, &rule.Status, &rule.UpdatedAt, &visible, &showTo, &visibilityRevision, &tenantEnabled); err != nil {
				return err
			}
			if err := json.Unmarshal(body, &rule.Body); err != nil {
				return fmt.Errorf("decode system rule %s: %w", rule.SystemKey, err)
			}
			overlay := Visibility{Visible: !hidden, ShowToScopeIDs: []uuid.UUID{}}
			if visible != nil {
				overlay = Visibility{Visible: *visible, ShowToScopeIDs: showTo, Revision: *visibilityRevision}
			}
			rule.Selectable = rule.Status == "active"
			if viewer.Platform {
				rule.Visibility, rule.Enabled = &overlay, overlay.Visible
			} else {
				if !overlay.Visible || len(overlay.ShowToScopeIDs) > 0 && !slices.Contains(overlay.ShowToScopeIDs, viewer.ScopeID) {
					continue
				}
				// Default enabled; a withdrawn rule keeps the tenant's previous
				// choice (frozen in use) but cannot be newly selected.
				rule.Enabled = true
				if tenantEnabled != nil {
					rule.Enabled = *tenantEnabled
				}
			}
			result = append(result, rule)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// SetTenantEnabled is the only tenant mutation of a system rule.
func (store *Store) SetTenantEnabled(ctx context.Context, viewer Viewer, systemKey string, enabled bool, authorize Authorize) (Rule, error) {
	if viewer.Platform || viewer.UserID == uuid.Nil || viewer.ScopeID == uuid.Nil || authorize == nil || systemKey == "" {
		return Rule{}, ErrInvalidInput
	}
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := authorize(ctx, tx); err != nil {
			return err
		}
		visible, status, err := tenantVisibleRule(ctx, tx, viewer.ScopeID, systemKey)
		if err != nil {
			return err
		}
		if !visible {
			return ErrNotFound
		}
		if enabled && status != "active" {
			return ErrWithdrawnRule
		}
		_, err = tx.Exec(ctx, `INSERT INTO security_system_rule_tenant_states(scope_id,system_key,enabled,revision,updated_by_user_id,updated_at)
			VALUES($1,$2,$3,1,$4,$5) ON CONFLICT (scope_id,system_key) DO UPDATE SET enabled=EXCLUDED.enabled,
			revision=security_system_rule_tenant_states.revision+1,updated_by_user_id=EXCLUDED.updated_by_user_id,updated_at=EXCLUDED.updated_at`,
			viewer.ScopeID, systemKey, enabled, viewer.UserID, store.now().UTC())
		return err
	})
	if err != nil {
		return Rule{}, err
	}
	return store.single(ctx, viewer, systemKey)
}

// SetVisibility is the local administrator overlay (competitor is_show/show_to).
func (store *Store) SetVisibility(ctx context.Context, viewer Viewer, systemKey string, visible bool, showTo []uuid.UUID, authorize Authorize) (Rule, error) {
	if !viewer.Platform || viewer.UserID == uuid.Nil || authorize == nil || systemKey == "" || len(showTo) > 1000 {
		return Rule{}, ErrInvalidInput
	}
	if showTo == nil {
		showTo = []uuid.UUID{}
	}
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := authorize(ctx, tx); err != nil {
			return err
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM security_system_rules WHERE system_key=$1)`, systemKey).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrNotFound
		}
		_, err := tx.Exec(ctx, `INSERT INTO security_system_rule_visibility(system_key,visible,show_to_scope_ids,revision,updated_by_user_id,updated_at)
			VALUES($1,$2,$3,1,$4,$5) ON CONFLICT (system_key) DO UPDATE SET visible=EXCLUDED.visible,
			show_to_scope_ids=EXCLUDED.show_to_scope_ids,revision=security_system_rule_visibility.revision+1,
			updated_by_user_id=EXCLUDED.updated_by_user_id,updated_at=EXCLUDED.updated_at`,
			systemKey, visible, showTo, viewer.UserID, store.now().UTC())
		return err
	})
	if err != nil {
		return Rule{}, err
	}
	return store.single(ctx, viewer, systemKey)
}

func tenantVisibleRule(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, systemKey string) (bool, string, error) {
	var hidden bool
	var status string
	var visible *bool
	var showTo []uuid.UUID
	err := tx.QueryRow(ctx, `SELECT rule.hidden,rule.status,visibility.visible,visibility.show_to_scope_ids
		FROM security_system_rules rule LEFT JOIN security_system_rule_visibility visibility ON visibility.system_key=rule.system_key
		WHERE rule.system_key=$1`, systemKey).Scan(&hidden, &status, &visible, &showTo)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, "", ErrNotFound
	}
	if err != nil {
		return false, "", err
	}
	shown := !hidden
	if visible != nil {
		shown = *visible
	}
	return shown && (len(showTo) == 0 || slices.Contains(showTo, scopeID)), status, nil
}

func (store *Store) single(ctx context.Context, viewer Viewer, systemKey string) (Rule, error) {
	rules, err := store.List(ctx, viewer, "", func(context.Context, pgx.Tx) error { return nil })
	if err != nil {
		return Rule{}, err
	}
	for _, rule := range rules {
		if rule.SystemKey == systemKey {
			return rule, nil
		}
	}
	return Rule{}, ErrNotFound
}

func (store *Store) Status(ctx context.Context, authorize Authorize) (Status, error) {
	var status Status
	// Not read-only: the IAM authorizer takes FOR SHARE locks in this transaction.
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if authorize == nil {
			return ErrInvalidInput
		}
		if err := authorize(ctx, tx); err != nil {
			return err
		}
		// The artifact catalog head (artifactsync) the rules come from.
		var deliveryID *uuid.UUID
		var revision *int64
		var digest *string
		var applied, expires *time.Time
		if err := tx.QueryRow(ctx, `SELECT delivery_id,scope_revision,catalog_sha256,applied_at,expires_at,last_attempt_at,
			last_success_at,last_error_code FROM artifact_catalog_state`).Scan(&deliveryID, &revision, &digest, &applied, &expires,
			&status.LastAttemptAt, &status.LastSuccessAt, &status.LastErrorCode); err != nil {
			return err
		}
		if deliveryID != nil && revision != nil && digest != nil && applied != nil && expires != nil {
			status.Synced, status.DeliveryID, status.ScopeRevision, status.CatalogSHA256 = true, deliveryID.String(), uint64(*revision), *digest
			status.AppliedAt, status.ExpiresAt, status.Stale = applied, expires, !store.now().Before(*expires)
		}
		return tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE status='active'),count(*) FILTER (WHERE status='withdrawn')
			FROM security_system_rules`).Scan(&status.ActiveCount, &status.WithdrawnCount)
	})
	return status, err
}

// Republication is the CRS rule text republication in progress: scopes the
// catalog's last CRS change asked to republish (system channel head or
// automatic request with trigger/source rule_catalog) that have not finished.
// A tenant sees its own scope, a platform admin every scope.
type Republication struct {
	Pending       bool `json:"pending"`
	PendingScopes int  `json:"pending_scopes"`
}

func (store *Store) Republication(ctx context.Context, viewer Viewer, authorize Authorize) (Republication, error) {
	if viewer.UserID == uuid.Nil || viewer.ScopeID == uuid.Nil || authorize == nil {
		return Republication{}, ErrInvalidInput
	}
	var result Republication
	// Not read-only: the IAM authorizer takes FOR SHARE locks in this transaction.
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := authorize(ctx, tx); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT count(DISTINCT scope_id) FROM (
				SELECT head.scope_id FROM edge_system_republication_heads head
				WHERE head.state IN ('pending','leased') AND 'rule_catalog'=ANY(head.triggers)
				UNION ALL
				SELECT request.target_scope_id FROM edge_automatic_publication_requests request
				JOIN LATERAL (SELECT state FROM edge_automatic_publication_request_state_facts
				  WHERE request_id=request.id ORDER BY sequence DESC LIMIT 1) latest ON true
				WHERE request.source_kind='rule_catalog'
				  AND latest.state IN ('pending','leased','retry_wait','reconciling')) pending
			WHERE $1 OR scope_id=$2`, viewer.Platform, viewer.ScopeID).Scan(&result.PendingScopes)
	})
	if err != nil {
		return Republication{}, err
	}
	result.Pending = result.PendingScopes > 0
	return result, nil
}

// DefaultCrawler is one entry of the default trusted crawler list the site
// CC page offers ("添加常见爬虫"): the CC trusted crawler (with the official
// IP ranges once the license service's dataset was downloaded) and its
// categories. A crawler that only verifies by fetched ranges is listed
// with Ready false until they arrive (the page cannot add it yet).
type DefaultCrawler struct {
	Name            string   `json:"name"`
	Members         []string `json:"members"`
	Categories      []string `json:"categories"`
	UserAgentTokens []string `json:"user_agent_tokens"`
	Networks        []string `json:"networks"`
	RDNSSuffixes    []string `json:"rdns_suffixes"`
	Ready           bool     `json:"ready"`
}

// DefaultCrawlers is the default list (libs/edgeconfig/crawlerdefaults)
// with the downloaded dataset's networks.
func (store *Store) DefaultCrawlers(ctx context.Context, authorize Authorize) ([]DefaultCrawler, error) {
	if authorize == nil {
		return nil, ErrInvalidInput
	}
	var dataset *crawlerdefaults.Dataset
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := authorize(ctx, tx); err != nil {
			return err
		}
		var err error
		dataset, err = edgepublish.LoadTrustedCrawlerDatasetTx(ctx, tx)
		return err
	})
	if err != nil {
		return nil, err
	}
	official := map[string][]string{}
	if dataset != nil {
		for _, crawler := range dataset.Crawlers {
			official[crawler.Name] = crawler.Networks
		}
	}
	defaults := crawlerdefaults.Defaults()
	result := make([]DefaultCrawler, 0, len(defaults))
	for _, crawler := range defaults {
		networks := official[crawler.Name]
		if networks == nil {
			networks = crawler.Networks
		}
		item := DefaultCrawler{Name: crawler.Name, Members: crawler.Members, Categories: crawler.Categories,
			UserAgentTokens: crawler.UserAgentTokens, Networks: append([]string{}, networks...),
			RDNSSuffixes: append([]string{}, crawler.RDNSSuffixes...)}
		item.Ready = len(item.Networks) != 0 || len(item.RDNSSuffixes) != 0
		result = append(result, item)
	}
	return result, nil
}
