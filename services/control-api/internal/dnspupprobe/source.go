package dnspupprobe

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Consumers (idempotency key and round budget namespaces).
const (
	ConsumerOrigin = "origin"
	ConsumerEdge   = "edge"
	// ConsumerNode is node availability monitoring (internal/nodednspupprobe).
	ConsumerNode = "node"
)

// Runtime is what a probe round sees: the configured source orders and,
// when the plugin is usable, a probe function.
type Runtime struct {
	OriginSources, EdgeSources []string
	// Probe is nil when dnspup is not usable this round (no module, disabled,
	// no key pair, paused).
	Probe func(ctx context.Context, consumer, site, target string, round int64, request ProbeRequest) ([]Result, error)
	// Account reads the key's monthly quota and records it (nil with Probe).
	Account func(ctx context.Context) (Account, error)
	// Checkpoints lists the key's dnspup checkpoints (nil with Probe).
	Checkpoints func(ctx context.Context) ([]Checkpoint, error)
}

// Uses reports whether sources contains source and the dnspup source is
// usable when source is dnspup.
func (runtime Runtime) Uses(sources []string, source string) bool {
	for _, value := range sources {
		if value == source {
			return source != SourceDNSPup || runtime.Probe != nil
		}
	}
	return false
}

// Runtime reads the settings, lease and pause once per round; a changed
// revision rebuilds the client.
func (service *Service) Runtime(ctx context.Context) Runtime {
	runtime := Runtime{OriginSources: DefaultOriginSources, EdgeSources: DefaultEdgeSources}
	now := service.now()
	var value stored
	var usable bool
	err := pgx.BeginTxFunc(ctx, service.config.Pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var err error
		if value, err = readSettings(ctx, tx, false); err != nil {
			return err
		}
		runtime.OriginSources, runtime.EdgeSources = value.OriginSources, value.EdgeSources
		var paused *time.Time
		if err := tx.QueryRow(ctx, `SELECT paused_until FROM probe_dnspup_state WHERE singleton`).Scan(&paused); err != nil {
			return err
		}
		licensed, err := service.licensed(ctx, tx)
		if err != nil {
			return err
		}
		usable = licensed && value.Enabled && value.Ciphertext != nil && value.KeyID != nil &&
			(paused == nil || !paused.After(now))
		return nil
	})
	if err != nil {
		if ctx.Err() == nil {
			service.config.Logger.Warn("dnspup probe settings unavailable", "error", err)
		}
		return runtime
	}
	if !usable {
		return runtime
	}
	prober, err := service.proberFor(value)
	if err != nil {
		service.config.Logger.Warn("dnspup probe client unavailable", "error", err)
		return runtime
	}
	runtime.Probe = prober.Run
	runtime.Checkpoints = prober.client.Nodes
	runtime.Account = func(ctx context.Context) (Account, error) {
		account, err := prober.client.Account(ctx)
		if err != nil {
			return account, err
		}
		_, recordErr := service.config.Pool.Exec(ctx, `UPDATE probe_dnspup_state SET account_checked_at=$1,
			async_capable=$2,monthly_limit=$3,monthly_used=$4,account_error_code='',updated_at=$1 WHERE singleton`,
			service.now(), account.AsyncProbes(), max(account.MonthlyLimit, 0), max(account.MonthlyUsed, 0))
		return account, recordErr
	}
	return runtime
}

func (service *Service) proberFor(value stored) (*Prober, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.prober != nil && service.loaded == value.Revision {
		return service.prober, nil
	}
	secret, err := service.open(*value.KeyID, value.Ciphertext)
	if err != nil {
		return nil, err
	}
	client, err := NewClient(Credentials{BaseURL: value.BaseURL, APIKey: value.APIKey, APISecret: secret,
		SourceDomain: value.SourceDomain}, service.config.Transport)
	if err != nil {
		return nil, err
	}
	client.now = service.config.Now
	revision := value.Revision
	service.prober = NewProber(client, func(reason, code string, until time.Time) {
		service.Degrade(context.Background(), revision, reason, code, until)
	})
	service.prober.now = service.config.Now
	service.loaded = revision
	return service.prober, nil
}

var reasonTexts = map[string]string{
	DegradeQuota:        "dnspup 本月额度已用完",
	DegradeRateLimited:  "dnspup 请求频率超限",
	DegradeUnauthorized: "dnspup Key 被拒绝（无效、停用、来源不符或未开通工具）",
	DegradeUnavailable:  "dnspup 服务暂不可用",
}

// Degrade pauses the dnspup source until until (only for the settings
// revision that hit it: a new key is not paused by the old one's errors),
// audits it and, once per pause, alerts the platform members holding
// PermissionManage.
func (service *Service) Degrade(ctx context.Context, revision int64, reason, code string, until time.Time) {
	now := service.now()
	until = until.UTC().Truncate(time.Second)
	err := pgx.BeginFunc(ctx, service.config.Pool, func(tx pgx.Tx) error {
		var current int64
		var paused *time.Time
		if err := tx.QueryRow(ctx, `SELECT settings.revision,state.paused_until FROM probe_dnspup_settings settings,
			probe_dnspup_state state WHERE settings.singleton AND state.singleton FOR UPDATE OF state`).Scan(&current, &paused); err != nil {
			return err
		}
		if current != revision {
			return nil
		}
		fresh := paused == nil || !paused.After(now)
		if !fresh && !until.After(*paused) {
			return nil
		}
		var sequence int64
		if err := tx.QueryRow(ctx, `UPDATE probe_dnspup_state SET paused_until=$1,pause_reason=$2,pause_code=$3,
			degrade_sequence=degrade_sequence+CASE WHEN $4 THEN 1 ELSE 0 END,updated_at=$5 WHERE singleton
			RETURNING degrade_sequence`, until, reason, code, fresh, now).Scan(&sequence); err != nil {
			return err
		}
		if err := service.appendAudit(ctx, tx, nil, ActionDegrade, "success", map[string]any{"reason": reason,
			"code": code, "paused_until": until.Format(time.RFC3339), "revision": revision}); err != nil {
			return err
		}
		if !fresh {
			return nil
		}
		return service.alert(ctx, tx, sequence, reason, code, until)
	})
	if err != nil && ctx.Err() == nil {
		service.config.Logger.Warn("dnspup probe degrade not recorded", "reason", reason, "error", err)
	}
}

func (service *Service) alert(ctx context.Context, tx pgx.Tx, sequence int64, reason, code string, until time.Time) error {
	if service.config.Alerts == nil {
		return nil
	}
	platform, err := platformScope(ctx, tx)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	} else if err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT membership.user_id FROM memberships membership
		JOIN users member ON member.id=membership.user_id AND member.status='active'
		JOIN role_assignments assignment ON assignment.scope_id=membership.scope_id AND assignment.user_id=membership.user_id
		JOIN role_permissions grant_row ON grant_row.role_id=assignment.role_id AND grant_row.permission_name=$2
		WHERE membership.scope_id=$1 AND membership.status='active' ORDER BY membership.user_id`, platform, PermissionManage)
	if err != nil {
		return err
	}
	recipients, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return err
	}
	shanghai := time.FixedZone("CST", 8*3600)
	values := notification.TemplateContext{
		"reason_text": notification.PublicValue(reasonTexts[reason]), "code": notification.PublicValue(code),
		"until": notification.PublicValue(until.In(shanghai).Format("2006-01-02 15:04")),
		"link":  notification.PublicValue(SettingsPagePath),
	}
	templates := map[notification.Channel]notification.TemplateRef{
		notification.ChannelSMS:   {ID: degradedTemplate, Version: 1, Channel: notification.ChannelSMS},
		notification.ChannelEmail: {ID: degradedTemplate, Version: 1, Channel: notification.ChannelEmail},
	}
	source := "probe-dnspup-degraded/" + strconv.FormatInt(sequence, 10)
	// Savepoint: a notification failure never undoes the pause.
	savepoint, err := tx.Begin(ctx)
	if err != nil {
		return err
	}
	for _, recipient := range recipients {
		if _, err := service.config.Alerts.EnqueueTx(ctx, savepoint, notification.EnqueueRequest{ScopeID: platform,
			RecipientID: recipient, SourceEventID: source, EventType: EventTypeDegraded,
			Policy: notification.DeliverySystemRequired, Templates: templates,
			Contexts:       map[notification.Channel]notification.TemplateContext{notification.ChannelSMS: values, notification.ChannelEmail: values},
			AuditRequestID: source}); err != nil {
			_ = savepoint.Rollback(ctx)
			service.config.Logger.Warn("dnspup probe alert not enqueued", "reason", reason, "error", err)
			return nil
		}
	}
	return savepoint.Commit(ctx)
}
