package dnspupprobe

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Status is the page view (read with the actor's permission).
func (service *Service) Status(ctx context.Context, actor Actor) (Status, error) {
	var status Status
	now := service.now()
	err := pgx.BeginTxFunc(ctx, service.config.Pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		if err := authenticate(ctx, tx, actor, now); err != nil {
			return err
		}
		var err error
		status, err = service.readStatus(ctx, tx, now)
		return err
	})
	return status, err
}

func (service *Service) readStatus(ctx context.Context, tx pgx.Tx, now time.Time) (Status, error) {
	value, err := readSettings(ctx, tx, false)
	if err != nil {
		return Status{}, err
	}
	status := Status{Enabled: value.Enabled, BaseURL: value.BaseURL, APIKey: value.APIKey,
		SecretConfigured: value.Fingerprint != "", SecretFingerprint: value.Fingerprint, SourceDomain: value.SourceDomain,
		OriginSources: value.OriginSources, EdgeSources: value.EdgeSources, Revision: value.Revision,
		SettingsUpdatedAt: value.UpdatedAt.UTC()}
	if err := tx.QueryRow(ctx, `SELECT account_checked_at,async_capable,monthly_limit,monthly_used,account_error_code,
		paused_until,pause_reason,pause_code FROM probe_dnspup_state WHERE singleton`).Scan(&status.AccountCheckedAt,
		&status.AsyncCapable, &status.MonthlyLimit, &status.MonthlyUsed, &status.AccountErrorCode, &status.PausedUntil,
		&status.PauseReason, &status.PauseCode); err != nil {
		return Status{}, err
	}
	if status.PausedUntil != nil && !status.PausedUntil.After(now) {
		status.PausedUntil, status.PauseReason, status.PauseCode = nil, "", ""
	}
	if status.Licensed, err = service.licensed(ctx, tx); err != nil {
		return Status{}, err
	}
	status.Active = status.Licensed && status.Enabled && status.SecretConfigured && status.PausedUntil == nil
	return status, nil
}

// UpdateSettings saves the form (idempotent per session + key). Enabling
// needs the module in the lease and a complete key pair; a new key or
// secret (换钥) clears a key-related pause.
func (service *Service) UpdateSettings(ctx context.Context, actor Actor, key string, input SettingsInput) (Status, error) {
	result, err := service.updateSettings(ctx, actor, key, input)
	if err != nil {
		service.recordFailure(ctx, actor, ActionSettings, err, map[string]any{"enabled": input.Enabled,
			"base_url": input.BaseURL, "api_key": input.APIKey})
	}
	return result, err
}

func (service *Service) updateSettings(ctx context.Context, actor Actor, key string, input SettingsInput) (Status, error) {
	if !validKey(key) {
		return Status{}, ErrInvalidInput
	}
	if err := normalize(&input); err != nil {
		return Status{}, err
	}
	secretState := "keep"
	if input.APISecret != nil {
		secretState = "clear"
		if *input.APISecret != "" {
			secretState = "set:" + secretDigest(*input.APISecret)
		}
	}
	digest := requestDigest("settings", input.Enabled, input.BaseURL, input.APIKey, secretState, input.SourceDomain,
		input.OriginSources, input.EdgeSources)
	now := service.now()
	var body []byte
	err := pgx.BeginFunc(ctx, service.config.Pool, func(tx pgx.Tx) error {
		if err := authenticate(ctx, tx, actor, now); err != nil {
			return err
		}
		if replayed, found, err := replay(ctx, tx, actor, key, digest); err != nil || found {
			body = replayed
			return err
		}
		current, err := readSettings(ctx, tx, true)
		if err != nil {
			return err
		}
		if input.Enabled {
			licensed, err := service.licensed(ctx, tx)
			if err != nil {
				return err
			}
			if !licensed {
				return ErrFeatureDenied
			}
		}
		keyID, ciphertext, fingerprint := current.KeyID, current.Ciphertext, current.Fingerprint
		secretAction := "unchanged"
		switch {
		case input.APISecret != nil && *input.APISecret != "":
			sealedID, sealed, err := service.seal(*input.APISecret)
			if err != nil {
				return err
			}
			keyID, ciphertext, fingerprint, secretAction = &sealedID, sealed, secretDigest(*input.APISecret)[:16], "replaced"
		case input.APISecret != nil:
			if current.Ciphertext != nil {
				secretAction = "cleared"
			}
			keyID, ciphertext, fingerprint = nil, nil, ""
		case current.Ciphertext != nil && !sameEndpoint(current, input.BaseURL, input.APIKey):
			return ErrSecretRequired
		}
		if input.Enabled && (input.APIKey == "" || ciphertext == nil) {
			return ErrInvalidInput
		}
		if _, err := tx.Exec(ctx, `UPDATE probe_dnspup_settings SET enabled=$1,base_url=$2,api_key=$3,secret_key_id=$4,
			secret_ciphertext=$5,secret_fingerprint=$6,source_domain=$7,origin_sources=$8,edge_sources=$9,revision=revision+1,
			updated_by_user_id=$10,updated_at=$11 WHERE singleton`, input.Enabled, input.BaseURL, input.APIKey, keyID,
			ciphertext, fingerprint, input.SourceDomain, input.OriginSources, input.EdgeSources, actor.UserID, now); err != nil {
			return err
		}
		keyChanged := current.APIKey != input.APIKey || secretAction == "replaced" || current.BaseURL != input.BaseURL ||
			current.SourceDomain != input.SourceDomain
		if keyChanged {
			// A new key pair starts unpaused (quota, rate and refusals were the old key's).
			if _, err := tx.Exec(ctx, `UPDATE probe_dnspup_state SET paused_until=NULL,pause_reason='',pause_code='',
				account_checked_at=NULL,async_capable=false,monthly_limit=0,monthly_used=0,account_error_code='',updated_at=$1
				WHERE singleton`, now); err != nil {
				return err
			}
		}
		changes := map[string]any{}
		addChange := func(name string, before, after any) {
			if !jsonEqual(before, after) {
				changes[name] = map[string]any{"before": before, "after": after}
			}
		}
		addChange("enabled", current.Enabled, input.Enabled)
		addChange("base_url", current.BaseURL, input.BaseURL)
		addChange("api_key", current.APIKey, input.APIKey)
		addChange("source_domain", current.SourceDomain, input.SourceDomain)
		addChange("origin_sources", current.OriginSources, input.OriginSources)
		addChange("edge_sources", current.EdgeSources, input.EdgeSources)
		if secretAction != "unchanged" {
			changes["api_secret"] = secretAction
		}
		if err := service.appendAudit(ctx, tx, &actor, ActionSettings, "success", map[string]any{"changes": changes}); err != nil {
			return err
		}
		status, err := service.readStatus(ctx, tx, now)
		if err != nil {
			return err
		}
		if body, err = json.Marshal(status); err != nil {
			return err
		}
		return recordWrite(ctx, tx, actor, key, "settings", digest, body, now)
	})
	if err != nil {
		return Status{}, err
	}
	var status Status
	return status, json.Unmarshal(body, &status)
}

func jsonEqual(left, right any) bool {
	a, _ := json.Marshal(left)
	b, _ := json.Marshal(right)
	return string(a) == string(b)
}

// TestConnection reads GET /v1/account (not metered) with the typed secret
// or, for the same API key and base URL host only, the stored one, and
// records the capability and quota.
func (service *Service) TestConnection(ctx context.Context, actor Actor, key string, input SettingsInput) (TestResult, error) {
	result, err := service.testConnection(ctx, actor, key, input)
	if err != nil {
		service.recordFailure(ctx, actor, ActionTest, err, map[string]any{"base_url": input.BaseURL, "api_key": input.APIKey})
	}
	return result, err
}

func (service *Service) testConnection(ctx context.Context, actor Actor, key string, input SettingsInput) (TestResult, error) {
	if !validKey(key) {
		return TestResult{}, ErrInvalidInput
	}
	if err := normalize(&input); err != nil || input.APIKey == "" {
		return TestResult{}, ErrInvalidInput
	}
	secretState := "stored"
	if input.APISecret != nil && *input.APISecret != "" {
		secretState = "typed:" + secretDigest(*input.APISecret)
	}
	digest := requestDigest("test", input.BaseURL, input.APIKey, input.SourceDomain, secretState)
	now := service.now()
	var current stored
	var replayed []byte
	err := pgx.BeginTxFunc(ctx, service.config.Pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		if err := authenticate(ctx, tx, actor, now); err != nil {
			return err
		}
		licensed, err := service.licensed(ctx, tx)
		if err != nil {
			return err
		}
		if !licensed {
			return ErrFeatureDenied
		}
		var found bool
		if replayed, found, err = replay(ctx, tx, actor, key, digest); err != nil || found {
			return err
		}
		current, err = readSettings(ctx, tx, false)
		return err
	})
	if err != nil {
		return TestResult{}, err
	}
	if replayed != nil {
		var result TestResult
		return result, json.Unmarshal(replayed, &result)
	}
	secret := ""
	switch {
	case input.APISecret != nil && *input.APISecret != "":
		secret = *input.APISecret
	case current.Ciphertext != nil && current.KeyID != nil && sameEndpoint(current, input.BaseURL, input.APIKey):
		if secret, err = service.open(*current.KeyID, current.Ciphertext); err != nil {
			return TestResult{}, err
		}
	default:
		return TestResult{}, ErrSecretRequired
	}
	client, err := NewClient(Credentials{BaseURL: input.BaseURL, APIKey: input.APIKey, APISecret: secret,
		SourceDomain: input.SourceDomain}, service.config.Transport)
	if err != nil {
		return TestResult{}, ErrInvalidInput
	}
	account, accountErr := client.Account(ctx)
	result := TestResult{OK: accountErr == nil, HTTPStatus: 200, AsyncCapable: account.AsyncProbes(),
		HTTPAllowed: account.Allows("http"), TCPAllowed: account.Allows("tcping"), MonthlyLimit: account.MonthlyLimit,
		MonthlyUsed: account.MonthlyUsed, Tools: account.AllowedTools}
	if result.Tools == nil {
		result.Tools = []string{}
	}
	var apiErr *APIError
	switch {
	case errors.As(accountErr, &apiErr):
		result.HTTPStatus, result.ErrorCode = apiErr.Status, apiErr.Code
	case accountErr != nil:
		result.HTTPStatus, result.ErrorCode = 0, "transport_error"
	case !result.AsyncCapable:
		result.OK, result.ErrorCode = false, "async_unavailable"
	case !result.HTTPAllowed && !result.TCPAllowed:
		result.OK, result.ErrorCode = false, "tool_not_allowed"
	}
	body, err := json.Marshal(result)
	if err != nil {
		return TestResult{}, err
	}
	outcome := map[bool]string{true: "success", false: "failure"}[result.OK]
	err = pgx.BeginFunc(ctx, service.config.Pool, func(tx pgx.Tx) error {
		// The stored key's account facts (only when testing the stored pair).
		if sameEndpoint(current, input.BaseURL, input.APIKey) && current.SourceDomain == input.SourceDomain &&
			(secretState == "stored" || secretDigest(secret)[:16] == current.Fingerprint) {
			if _, err := tx.Exec(ctx, `UPDATE probe_dnspup_state SET account_checked_at=$1,async_capable=$2,monthly_limit=$3,
				monthly_used=$4,account_error_code=$5,updated_at=$1 WHERE singleton`, now, result.AsyncCapable,
				max(result.MonthlyLimit, 0), max(result.MonthlyUsed, 0), result.ErrorCode); err != nil {
				return err
			}
		}
		if err := service.appendAudit(ctx, tx, &actor, ActionTest, outcome, map[string]any{"base_url": input.BaseURL,
			"api_key": input.APIKey, "secret": map[bool]string{true: "typed", false: "stored"}[secretState != "stored"],
			"http_status": result.HTTPStatus, "error_code": result.ErrorCode}); err != nil {
			return err
		}
		return recordWrite(ctx, tx, actor, key, "test", digest, body, now)
	})
	return result, err
}
