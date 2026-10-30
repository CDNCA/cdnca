package ipintelupdate

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/artifactcatalog"
	"github.com/cdnca/cdnca/libs/entitlement/ipintel"
	"github.com/cdnca/cdnca/libs/entitlement/ipintel/builder"
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
	status := Status{Enabled: value.Enabled, URL: value.URL, APIKey: value.APIKey, SecretConfigured: value.Fingerprint != "",
		SecretFingerprint: value.Fingerprint, IntervalMinutes: value.IntervalMinutes, AnchorMinute: value.AnchorMinute,
		TimeZone: value.TimeZone, Revision: value.Revision, SettingsUpdatedAt: value.UpdatedAt.UTC()}
	var requested, runningUntil *time.Time
	if err := tx.QueryRow(ctx, `SELECT last_checked_at,last_success_at,last_outcome,last_release,last_http_status,last_error_code,
		last_error,next_check_at,check_requested_at,running_until FROM ip_intel_update_state WHERE singleton`).Scan(
		&status.LastCheckedAt, &status.LastSuccessAt, &status.LastOutcome, &status.LastRelease, &status.LastHTTPStatus,
		&status.LastErrorCode, &status.LastError, &status.NextCheckAt, &requested, &runningUntil); err != nil {
		return Status{}, err
	}
	status.CheckRequested = requested != nil
	status.Running = runningUntil != nil && runningUntil.After(now)
	features, err := service.config.Features.ReadValidFeatures(ctx, tx)
	if err != nil {
		return Status{}, err
	}
	status.Licensed = features[Feature]
	rows, err := tx.Query(ctx, `SELECT local.artifact_id,local.current_revision,local.current_version,entry.requires_feature,
		entry.status,object.content FROM local_artifacts local
		JOIN artifact_catalog_entries entry ON entry.artifact_id=local.artifact_id
		JOIN artifact_objects object ON object.sha256=local.current_sha256
		WHERE local.artifact_id IN ('ipintel/base','ipintel/local') AND local.current_revision IS NOT NULL`)
	if err != nil {
		return Status{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var library Library
		var revision int64
		var feature, entryStatus string
		var content []byte
		if err := rows.Scan(&library.ArtifactID, &revision, &library.Version, &feature, &entryStatus, &content); err != nil {
			return Status{}, err
		}
		library.Revision = uint64(revision)
		library.Usable = entryStatus == "active" && (feature == "" || features[feature])
		if table, err := ipintel.Open(content); err == nil {
			library.SourceRelease = table.Metadata.SourceRelease
			library.DataUpdatedAt, _ = time.Parse(time.RFC3339, table.Metadata.DataUpdatedAt)
		}
		if library.ArtifactID == artifactcatalog.IPIntelBaseID {
			status.Base = &library
		} else {
			status.Local = &library
		}
	}
	if err := rows.Err(); err != nil {
		return Status{}, err
	}
	status.NodeUses, status.UseReason = choose(status.Base, status.Local)
	return status, nil
}

// choose mirrors artifactsetdist.selectIPIntel for the page.
func choose(base, local *Library) (string, string) {
	if base != nil && !base.Usable {
		base = nil
	}
	if local != nil && !local.Usable {
		local = nil
	}
	switch {
	case base == nil && local == nil:
		return "", ""
	case local == nil:
		return base.ArtifactID, "only_base"
	case local.DataUpdatedAt.IsZero() && base != nil:
		return base.ArtifactID, "local_unreadable"
	case base == nil:
		return local.ArtifactID, "only_local"
	case local.DataUpdatedAt.After(base.DataUpdatedAt):
		return local.ArtifactID, "local_newer"
	default:
		return base.ArtifactID, "base_newer_or_equal"
	}
}

// UpdateSettings saves the form (idempotent per session + key). Enabling
// needs the module in the lease and a complete key pair; enabling or
// changing the endpoint, key, secret or schedule reschedules the next pull.
func (service *Service) UpdateSettings(ctx context.Context, actor Actor, key string, input SettingsInput) (Status, error) {
	result, err := service.updateSettings(ctx, actor, key, input)
	if err != nil {
		service.recordFailure(ctx, actor, ActionSettings, err, map[string]any{"enabled": input.Enabled, "url": input.URL,
			"api_key": input.APIKey})
	}
	return result, err
}

func (service *Service) updateSettings(ctx context.Context, actor Actor, key string, input SettingsInput) (Status, error) {
	if !validKey(key) {
		return Status{}, ErrInvalidInput
	}
	if err := normalize(&input, true); err != nil {
		return Status{}, err
	}
	secretState := "keep"
	if input.APISecret != nil {
		secretState = "clear"
		if *input.APISecret != "" {
			secretState = "set:" + secretDigest(*input.APISecret)
		}
	}
	digest := requestDigest("settings", input.Enabled, input.URL, input.APIKey, secretState, input.IntervalMinutes,
		input.AnchorMinute, input.TimeZone)
	now := service.now()
	var body []byte
	wake := false
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
		case current.Ciphertext != nil && !sameOrigin(current, input.URL, input.APIKey):
			return ErrSecretRequired
		}
		if input.Enabled && (input.URL == "" || input.APIKey == "" || ciphertext == nil) {
			return ErrInvalidInput
		}
		scheduleChanged := current.IntervalMinutes != input.IntervalMinutes || current.AnchorMinute != input.AnchorMinute ||
			current.TimeZone != input.TimeZone
		endpointChanged := current.URL != input.URL || current.APIKey != input.APIKey || secretAction == "replaced"
		if _, err := tx.Exec(ctx, `UPDATE ip_intel_update_settings SET enabled=$1,url=$2,api_key=$3,secret_key_id=$4,
			secret_ciphertext=$5,secret_fingerprint=$6,interval_minutes=$7,anchor_minute=$8,time_zone=$9,revision=revision+1,
			updated_by_user_id=$10,updated_at=$11 WHERE singleton`, input.Enabled, input.URL, input.APIKey, keyID, ciphertext,
			fingerprint, input.IntervalMinutes, input.AnchorMinute, input.TimeZone, actor.UserID, now); err != nil {
			return err
		}
		// Newly enabled or a new endpoint/key pulls at once; a schedule
		// change only moves the next pull.
		var next *time.Time
		switch {
		case !input.Enabled:
		case !current.Enabled || endpointChanged:
		default:
			zone, _ := validSchedule(input.IntervalMinutes, input.AnchorMinute, input.TimeZone)
			at := NextPull(now, input.IntervalMinutes, input.AnchorMinute, zone)
			next = &at
		}
		if !input.Enabled || !current.Enabled || endpointChanged || scheduleChanged {
			if _, err := tx.Exec(ctx, `UPDATE ip_intel_update_state SET next_check_at=$1,updated_at=$2 WHERE singleton`, next, now); err != nil {
				return err
			}
			wake = input.Enabled
		}
		changes := map[string]any{}
		addChange := func(name string, before, after any) {
			if before != after {
				changes[name] = map[string]any{"before": before, "after": after}
			}
		}
		addChange("enabled", current.Enabled, input.Enabled)
		addChange("url", current.URL, input.URL)
		addChange("api_key", current.APIKey, input.APIKey)
		addChange("interval_minutes", current.IntervalMinutes, input.IntervalMinutes)
		addChange("anchor_minute", current.AnchorMinute, input.AnchorMinute)
		addChange("time_zone", current.TimeZone, input.TimeZone)
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
	if wake {
		service.Wake()
	}
	var status Status
	return status, json.Unmarshal(body, &status)
}

// TestConnection probes dnspup with HEAD (not metered) using the typed
// secret or, for the same API key and URL origin only, the stored one.
func (service *Service) TestConnection(ctx context.Context, actor Actor, key string, input SettingsInput) (TestResult, error) {
	result, err := service.testConnection(ctx, actor, key, input)
	if err != nil {
		service.recordFailure(ctx, actor, ActionTest, err, map[string]any{"url": input.URL, "api_key": input.APIKey})
	}
	return result, err
}

func (service *Service) testConnection(ctx context.Context, actor Actor, key string, input SettingsInput) (TestResult, error) {
	if !validKey(key) {
		return TestResult{}, ErrInvalidInput
	}
	if err := normalize(&input, false); err != nil || input.URL == "" || input.APIKey == "" {
		return TestResult{}, ErrInvalidInput
	}
	secretState := "stored"
	if input.APISecret != nil && *input.APISecret != "" {
		secretState = "typed:" + secretDigest(*input.APISecret)
	}
	digest := requestDigest("test", input.URL, input.APIKey, secretState)
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
	case current.Ciphertext != nil && current.KeyID != nil && sameOrigin(current, input.URL, input.APIKey):
		if secret, err = service.open(*current.KeyID, current.Ciphertext); err != nil {
			return TestResult{}, err
		}
	default:
		return TestResult{}, ErrSecretRequired
	}
	source, err := builder.NewHTTPSource(builder.HTTPSourceConfig{URL: input.URL, APIKey: input.APIKey, APISecret: secret,
		Timeout: time.Minute})
	if err != nil {
		return TestResult{}, ErrInvalidInput
	}
	probe, probeErr := source.Probe(ctx)
	result := TestResult{OK: probeErr == nil, HTTPStatus: probe.Status, Release: probe.Release, State: probe.State,
		Bytes: probe.Bytes, SourceError: probe.ErrorCode}
	outcome := "success"
	if probeErr != nil {
		result.ErrorCode, result.Error, outcome = errorCode(probeErr), errorText(probeErr), "failure"
	}
	body, err := json.Marshal(result)
	if err != nil {
		return TestResult{}, err
	}
	err = pgx.BeginFunc(ctx, service.config.Pool, func(tx pgx.Tx) error {
		if err := service.appendAudit(ctx, tx, &actor, ActionTest, outcome, map[string]any{"url": input.URL, "api_key": input.APIKey,
			"secret": map[bool]string{true: "typed", false: "stored"}[secretState != "stored"], "http_status": result.HTTPStatus,
			"error_code": result.ErrorCode}); err != nil {
			return err
		}
		return recordWrite(ctx, tx, actor, key, "test", digest, body, now)
	})
	if err != nil {
		return TestResult{}, err
	}
	return result, nil
}

// CheckNow asks the worker to pull at once.
func (service *Service) CheckNow(ctx context.Context, actor Actor, key string) (Status, error) {
	result, err := service.checkNow(ctx, actor, key)
	if err != nil {
		service.recordFailure(ctx, actor, ActionCheck, err, map[string]any{})
	}
	return result, err
}

func (service *Service) checkNow(ctx context.Context, actor Actor, key string) (Status, error) {
	if !validKey(key) {
		return Status{}, ErrInvalidInput
	}
	digest := requestDigest("check")
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
		licensed, err := service.licensed(ctx, tx)
		if err != nil {
			return err
		}
		if !licensed {
			return ErrFeatureDenied
		}
		current, err := readSettings(ctx, tx, false)
		if err != nil {
			return err
		}
		if !current.Enabled {
			return ErrDisabled
		}
		if _, err := tx.Exec(ctx, `UPDATE ip_intel_update_state SET check_requested_at=$1,updated_at=$1 WHERE singleton`, now); err != nil {
			return err
		}
		if err := service.appendAudit(ctx, tx, &actor, ActionCheck, "success", map[string]any{"url": current.URL}); err != nil {
			return err
		}
		status, err := service.readStatus(ctx, tx, now)
		if err != nil {
			return err
		}
		if body, err = json.Marshal(status); err != nil {
			return err
		}
		return recordWrite(ctx, tx, actor, key, "check", digest, body, now)
	})
	if err != nil {
		return Status{}, err
	}
	service.Wake()
	var status Status
	return status, json.Unmarshal(body, &status)
}

func validKey(key string) bool {
	if key == "" || len(key) > 128 {
		return false
	}
	for index, r := range key {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case index > 0 && (r == '.' || r == '_' || r == '-'):
		default:
			return false
		}
	}
	return true
}

func errorCode(err error) string {
	switch {
	case errors.Is(err, builder.ErrSourceAuth):
		return "credentials_rejected"
	case errors.Is(err, builder.ErrSourceDomainBinding):
		return "key_domain_bound"
	case errors.Is(err, builder.ErrSourceForbidden):
		return "source_ip_forbidden"
	case errors.Is(err, builder.ErrSourceToolNotAllowed):
		return "tool_not_allowed"
	case errors.Is(err, builder.ErrSourceQuota):
		return "quota_exceeded"
	case errors.Is(err, builder.ErrSourceTooLarge):
		return "snapshot_too_large"
	case errors.Is(err, builder.ErrSourcePending):
		return "source_pending"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, builder.ErrSourceUnreachable):
		return "source_unreachable"
	case errors.Is(err, builder.ErrLicense):
		return "license_not_allowed"
	case errors.Is(err, errSnapshotOlder):
		return "snapshot_older"
	case errors.Is(err, ErrSecretUnavailable):
		return "credential_unavailable"
	case errors.Is(err, ErrFeatureDenied):
		return "feature_not_licensed"
	case errors.Is(err, builder.ErrSource):
		return "snapshot_invalid"
	default:
		return "build_failed"
	}
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	text := []rune(err.Error())
	if len(text) > 500 {
		text = text[:500]
	}
	for index, r := range text {
		if r == '\n' {
			text = text[:index]
			break
		}
	}
	return string(text)
}
