// Package pluginproviders manages third-party provider plugins on the
// control plane (PA-22, ADR 0007 §8.2): the installation contract runner,
// the administrator's enable / disable, and the provider clients the DNS,
// SMS and ICP adapters call. A provider is usable only while its
// declaration is active, its contract passed for exactly these bytes and an
// administrator enabled it.
package pluginproviders

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/pluginprovider"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	ContractPending = "pending"
	ContractPassed  = "passed"
	ContractFailed  = "failed"
)

var (
	ErrNotFound       = errors.New("provider plugin not found")
	ErrNotUsable      = errors.New("provider plugin is not usable")
	ErrContractNeeded = errors.New("provider plugin contract has not passed")
	ErrConflict       = errors.New("provider plugin changed concurrently")
	ErrInvalid        = errors.New("invalid provider plugin request")
	// ErrConfirmationRequired: enabling a payment plugin needs the MFA
	// step-up and the acknowledged risk notice (PA-23).
	ErrConfirmationRequired = errors.New("payment provider plugin needs a high-risk confirmation")
)

// PaymentRiskNotice is the confirmation text an administrator acknowledges
// before enabling a payment provider plugin.
const PaymentRiskNotice = "支付插件属于高风险权限：插件可以为本主控创建收款单并上报支付结果，资金进入插件开发者对接的收款账户。" +
	"主控只在主动向插件查单并核对订单号、金额、币种与签名后才入账；插件伪造的支付结果不会入账并会记录告警。" +
	"请确认已核实插件开发者与收款方，并自行承担资金风险。"

// Provider is one materialized provider plugin as the console shows it.
type Provider struct {
	PluginID          string                         `json:"plugin_id"`
	Version           string                         `json:"version"`
	BaseURL           string                         `json:"base_url"`
	Kinds             []string                       `json:"kinds"`
	Status            string                         `json:"status"`
	ContractStatus    string                         `json:"contract_status"`
	ContractVersion   string                         `json:"contract_version,omitempty"`
	ContractCheckedAt *time.Time                     `json:"contract_checked_at,omitempty"`
	ContractReport    *pluginprovider.ContractReport `json:"contract_report,omitempty"`
	Enabled           bool                           `json:"enabled"`
	Usable            bool                           `json:"usable"`
	UpdatedAt         time.Time                      `json:"updated_at"`
	// HighRisk: the plugin provides payment (PA-23); enabling it needs an
	// MFA step-up bound to TenantID (the installation's tenant) and the
	// acknowledged RiskNotice.
	HighRisk           bool       `json:"high_risk"`
	RiskNotice         string     `json:"risk_notice,omitempty"`
	TenantID           *uuid.UUID `json:"tenant_id,omitempty"`
	PaymentConfirmedAt *time.Time `json:"payment_confirmed_at,omitempty"`

	declaration       pluginprovider.Declaration
	declarationSHA256 string
	contractSHA256    string
}

func (provider Provider) usable() bool {
	return provider.Status == "active" && provider.Enabled && provider.ContractStatus == ContractPassed &&
		provider.contractSHA256 == provider.declarationSHA256 && provider.ContractVersion == pluginprovider.ContractVersion
}

// Store is the plugin_providers repository (migration 397).
type Store struct {
	pool  *pgxpool.Pool
	audit *audit.Log
	now   func() time.Time
}

func NewStore(pool *pgxpool.Pool, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{pool: pool, audit: audit.New(pool), now: now}
}

const providerColumns = `plugin_id,version,base_url,kinds,declaration::text,declaration_sha256,status,contract_status,
	COALESCE(contract_version,''),COALESCE(contract_declaration_sha256,''),contract_report::text,contract_checked_at,enabled,updated_at,
	(SELECT scope.tenant_id FROM access_scopes scope WHERE scope.id=plugin_providers.tenant_scope_id AND scope.kind='tenant'),
	payment_confirmed_at`

func scanProvider(row pgx.Row) (Provider, error) {
	var provider Provider
	var declaration string
	var report *string
	if err := row.Scan(&provider.PluginID, &provider.Version, &provider.BaseURL, &provider.Kinds, &declaration,
		&provider.declarationSHA256, &provider.Status, &provider.ContractStatus, &provider.ContractVersion,
		&provider.contractSHA256, &report, &provider.ContractCheckedAt, &provider.Enabled, &provider.UpdatedAt,
		&provider.TenantID, &provider.PaymentConfirmedAt); err != nil {
		return Provider{}, err
	}
	// jsonb normalizes key order and spacing: decode, then rebuild the
	// canonical form to re-validate what is used.
	var stored pluginprovider.Declaration
	if err := json.Unmarshal([]byte(declaration), &stored); err != nil {
		return Provider{}, err
	}
	provides := make([]pluginprovider.Provided, 0, len(stored.Kinds))
	for _, kind := range stored.Kinds {
		provides = append(provides, pluginprovider.Provided{Kind: kind, ProtocolVersion: pluginprovider.ProtocolVersion})
	}
	rebuilt, _, err := pluginprovider.Build(stored.PluginID, stored.Version, stored.BaseURL, stored.ResponseKey, provides,
		stored.Permissions)
	if err != nil {
		return Provider{}, err
	}
	provider.declaration = rebuilt
	if report != nil {
		var decoded pluginprovider.ContractReport
		if json.Unmarshal([]byte(*report), &decoded) == nil {
			provider.ContractReport = &decoded
		}
	}
	provider.Usable = provider.usable()
	if provider.HighRisk = rebuilt.Has(pluginprovider.KindPayment); provider.HighRisk {
		provider.RiskNotice = PaymentRiskNotice
	}
	return provider, nil
}

// List returns every materialized provider plugin.
func (store *Store) List(ctx context.Context) ([]Provider, error) {
	rows, err := store.pool.Query(ctx, `SELECT `+providerColumns+` FROM plugin_providers ORDER BY plugin_id`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Provider, error) { return scanProvider(row) })
}

// Get returns one provider plugin.
func (store *Store) Get(ctx context.Context, pluginID string) (Provider, error) {
	provider, err := scanProvider(store.pool.QueryRow(ctx, `SELECT `+providerColumns+` FROM plugin_providers WHERE plugin_id=$1`,
		pluginID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Provider{}, ErrNotFound
	}
	return provider, err
}

// Usable returns the declaration of a provider plugin that may be called
// for kind right now.
func (store *Store) Usable(ctx context.Context, pluginID, kind string) (pluginprovider.Declaration, error) {
	provider, err := store.Get(ctx, pluginID)
	if errors.Is(err, ErrNotFound) {
		return pluginprovider.Declaration{}, ErrNotUsable
	}
	if err != nil {
		return pluginprovider.Declaration{}, err
	}
	if !provider.usable() || !provider.declaration.Has(kind) {
		return pluginprovider.Declaration{}, ErrNotUsable
	}
	return provider.declaration, nil
}

// Pending lists active providers whose contract has not been run for their
// current declaration.
func (store *Store) Pending(ctx context.Context) ([]Provider, error) {
	providers, err := store.List(ctx)
	if err != nil {
		return nil, err
	}
	out := providers[:0]
	for _, provider := range providers {
		if provider.Status == "active" && (provider.ContractStatus == ContractPending ||
			provider.ContractVersion != pluginprovider.ContractVersion) {
			out = append(out, provider)
		}
	}
	return out, nil
}

// Actor is who changed a provider (uuid.Nil = the system runner).
type Actor struct {
	UserID    uuid.UUID
	ScopeID   uuid.UUID
	RequestID string
	SourceIP  string
}

// RecordContract stores a contract report for the declaration bytes it ran
// against; a declaration replaced meanwhile keeps its pending state.
func (store *Store) RecordContract(ctx context.Context, actor Actor, provider Provider,
	report pluginprovider.ContractReport) (Provider, error) {
	status := ContractFailed
	if report.Passed {
		status = ContractPassed
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		return Provider{}, err
	}
	failed := []string{}
	for _, result := range report.Cases {
		if !result.Passed {
			failed = append(failed, result.Kind+"/"+result.ID+":"+result.Code)
		}
	}
	err = pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE plugin_providers SET contract_status=$2,contract_version=$3,
			contract_declaration_sha256=declaration_sha256,contract_report=$4,contract_checked_at=$5,updated_at=$5
			WHERE plugin_id=$1 AND declaration_sha256=$6 AND status='active'`,
			provider.PluginID, status, report.Version, encoded, store.now().UTC(), provider.declarationSHA256)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrConflict
		}
		result := "success"
		if !report.Passed {
			result = "failure"
		}
		return store.append(ctx, tx, actor, "plugin.provider.contract", provider.PluginID, result, map[string]any{
			"plugin_id": provider.PluginID, "version": provider.Version, "contract_version": report.Version,
			"cases": len(report.Cases), "failed_cases": failed, "reason_code": map[bool]string{true: "", false: "contract_failed"}[report.Passed],
			"changes": map[string]any{"contract_status": map[string]any{"from": provider.ContractStatus, "to": status}}})
	})
	if err != nil {
		return Provider{}, err
	}
	return store.Get(ctx, provider.PluginID)
}

// SetEnabled turns a provider on or off. Enabling requires a passed
// contract for the current declaration (the 397 trigger refuses it too).
func (store *Store) SetEnabled(ctx context.Context, actor Actor, pluginID string, enabled bool) (Provider, error) {
	return store.setEnabled(ctx, actor, pluginID, enabled, nil)
}

// paymentConfirmation is the high-risk confirmation of a payment plugin
// enable: the consumed step-up proof, checked against the bytes it was
// bound to.
type paymentConfirmation struct {
	proofID           uuid.UUID
	declarationSHA256 string
}

func (store *Store) setEnabled(ctx context.Context, actor Actor, pluginID string, enabled bool,
	confirmation *paymentConfirmation) (Provider, error) {
	if actor.UserID == uuid.Nil {
		return Provider{}, ErrInvalid
	}
	var refused *Provider
	refusedCode := "contract_not_passed"
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		current, err := scanProvider(tx.QueryRow(ctx, `SELECT `+providerColumns+` FROM plugin_providers WHERE plugin_id=$1 FOR UPDATE`,
			pluginID))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		action := "plugin.provider.disable"
		if enabled {
			action = "plugin.provider.enable"
		}
		if enabled && !(current.Status == "active" && current.ContractStatus == ContractPassed &&
			current.contractSHA256 == current.declarationSHA256) {
			refused = &current
			return errContractNeeded
		}
		if current.Enabled == enabled {
			return nil
		}
		highRisk := current.declaration.Has(pluginprovider.KindPayment)
		if enabled && highRisk && (confirmation == nil || confirmation.declarationSHA256 != current.declarationSHA256) {
			if confirmation != nil {
				return ErrConflict
			}
			refused, refusedCode = &current, "confirmation_required"
			return ErrConfirmationRequired
		}
		now := store.now().UTC()
		if enabled && highRisk {
			_, err = tx.Exec(ctx, `UPDATE plugin_providers SET enabled=true,enabled_by_user_id=$2,enabled_at=$3,updated_at=$3,
				payment_confirmed_by_user_id=$2,payment_confirmed_at=$3,payment_step_up_proof_id=$4 WHERE plugin_id=$1`,
				pluginID, actor.UserID, now, confirmation.proofID)
		} else if enabled {
			_, err = tx.Exec(ctx, `UPDATE plugin_providers SET enabled=true,enabled_by_user_id=$2,enabled_at=$3,updated_at=$3
				WHERE plugin_id=$1`, pluginID, actor.UserID, now)
		} else {
			_, err = tx.Exec(ctx, `UPDATE plugin_providers SET enabled=false,updated_at=$2 WHERE plugin_id=$1`, pluginID, now)
		}
		if err != nil {
			return err
		}
		payload := map[string]any{"plugin_id": pluginID, "version": current.Version, "high_risk": highRisk,
			"changes": map[string]any{"enabled": map[string]any{"from": current.Enabled, "to": enabled}}}
		if enabled && highRisk {
			payload["step_up_proof_id"], payload["risk_acknowledged"] = confirmation.proofID.String(), true
		}
		return store.append(ctx, tx, actor, action, pluginID, "success", payload)
	})
	if (errors.Is(err, errContractNeeded) || errors.Is(err, ErrConfirmationRequired)) && refused != nil {
		// The refusal is recorded in its own transaction (the one above rolled back).
		if auditErr := store.refuseEnable(ctx, actor, *refused, refusedCode); auditErr != nil {
			return Provider{}, auditErr
		}
		if errors.Is(err, ErrConfirmationRequired) {
			return Provider{}, ErrConfirmationRequired
		}
		return Provider{}, ErrContractNeeded
	}
	if err != nil {
		return Provider{}, err
	}
	return store.Get(ctx, pluginID)
}

// refuseEnable audits a refused enable in its own transaction.
func (store *Store) refuseEnable(ctx context.Context, actor Actor, provider Provider, reason string) error {
	return pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		return store.append(ctx, tx, actor, "plugin.provider.enable", provider.PluginID, "failure", map[string]any{
			"plugin_id": provider.PluginID, "version": provider.Version, "reason_code": reason,
			"contract_status": provider.ContractStatus, "high_risk": provider.HighRisk})
	})
}

// errContractNeeded aborts the enable transaction; the refusal is audited
// separately.
var errContractNeeded = errors.New("contract needed")

func (store *Store) append(ctx context.Context, tx pgx.Tx, actor Actor, action, pluginID, result string,
	payload map[string]any) error {
	scopeID := actor.ScopeID
	if scopeID == uuid.Nil {
		if err := tx.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL ORDER BY id LIMIT 1`).
			Scan(&scopeID); errors.Is(err, pgx.ErrNoRows) {
			return nil
		} else if err != nil {
			return err
		}
	}
	event := audit.Event{ScopeID: scopeID, Action: action, ResourceType: "plugin_provider", ResourceID: pluginID,
		RequestID: actor.RequestID, Result: result, Payload: payload, SourceIP: actor.SourceIP}
	if event.RequestID == "" {
		event.RequestID = action + "." + uuid.NewString()
	}
	if actor.UserID != uuid.Nil {
		id := actor.UserID
		event.ActorUserID = &id
	} else {
		event.ActorKind, event.ActorRef = "system", "job:plugin_provider_contract"
	}
	if reason, _ := payload["reason_code"].(string); reason == "" {
		delete(payload, "reason_code")
	}
	return store.audit.Append(ctx, tx, event)
}
