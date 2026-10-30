package notificationcontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"slices"
	"strconv"
	"strings"
	texttemplate "text/template"
	"text/template/parse"
	"time"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/announcement"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock/protocol"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	permissionRead                   = "system_configuration.read"
	permissionManage                 = "system_configuration.manage"
	permissionPlatformAdmin          = "platform.admin"
	announcementPublishedTemplateID  = "announcement_published"
	readOperationSubscriptionGet     = "notification.subscription.get"
	writeOperationChannelsUpdate     = "notification.channels.update"
	writeOperationTemplatePut        = "notification.template.put"
	writeOperationSubscriptionUpdate = "notification.subscription.update"
	readOperationPolicyGet           = "notification.policy.get"
	writeOperationPolicyUpdate       = "notification.policy.update"
)

// deliveryHistoryReadPermissions: 发送记录与前端面板一致，
// platform.admin 或 system_configuration.read 任一即可。
var deliveryHistoryReadPermissions = []string{permissionRead, permissionPlatformAdmin}

var (
	errInvalidNotificationWriteReceipt = errors.New("invalid notification write receipt")
	errInvalidNotificationDenialAudit  = errors.New("invalid notification denial audit")
)

type Store struct {
	pool    *pgxpool.Pool
	auditor AuditAppender
	now     Clock
	// transports: whether an SMS / email transport is configured in this
	// process (main.go always sets it). Unset keeps the earlier contract:
	// both channels supported, no platform switch check.
	transports *ChannelTransports
}

// ChannelTransports reports which delivery transports the runtime built.
type ChannelTransports struct{ SMS, Email bool }

// WithChannelTransports sets the configured transports
// (a channel that is not configured is not offered to customers).
func (s *Store) WithChannelTransports(transports ChannelTransports) *Store {
	s.transports = &transports
	return s
}

func (s *Store) configured() ChannelTransports {
	if s.transports == nil {
		return ChannelTransports{SMS: true, Email: true}
	}
	return *s.transports
}

// channelView fills the administrator view: supported follows the
// transport; a switch that is on without a transport is reported off.
func (s *Store) channelView(result *ChannelSettings) {
	configured := s.configured()
	result.SMSSupported, result.EmailSupported = configured.SMS, configured.Email
	result.SMSEnabled = result.SMSEnabled && configured.SMS
	result.EmailEnabled = result.EmailEnabled && configured.Email
}

// subscriptionSupport is what a customer may subscribe to: the transport is
// configured and the platform switch is on.
func (s *Store) subscriptionSupport(ctx context.Context, tx pgx.Tx, result *Subscription) error {
	if s.transports == nil {
		result.SMSSupported, result.EmailSupported = true, true
		return nil
	}
	var sms, email bool
	if err := tx.QueryRow(ctx, `SELECT sms_enabled,email_enabled FROM notification_channel_settings WHERE singleton`).
		Scan(&sms, &email); err != nil {
		return err
	}
	configured := s.configured()
	result.SMSSupported, result.EmailSupported = sms && configured.SMS, email && configured.Email
	result.SMSEnabled = result.SMSEnabled && result.SMSSupported
	result.EmailEnabled = result.EmailEnabled && result.EmailSupported
	return nil
}

func NewStore(pool *pgxpool.Pool) (*Store, error) {
	return NewStoreWithDependencies(pool, audit.New(pool), time.Now)
}

func NewStoreWithDependencies(pool *pgxpool.Pool, auditor AuditAppender, now Clock) (*Store, error) {
	if pool == nil || auditor == nil || now == nil {
		return nil, ErrInvalidStore
	}
	return &Store{pool: pool, auditor: auditor, now: now}, nil
}

func (s *Store) GetChannels(ctx context.Context, actor Actor) (ChannelSettings, error) {
	var result ChannelSettings
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorizeRead(ctx, tx, actor, permissionRead, s.now()); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT sms_enabled,email_enabled,revision
			FROM notification_channel_settings WHERE singleton`).Scan(&result.SMSEnabled, &result.EmailEnabled, &result.Revision)
	})
	if err != nil {
		return ChannelSettings{}, fmt.Errorf("get notification channels: %w", err)
	}
	s.channelView(&result)
	return result, nil
}

func (s *Store) GetDeliveryPolicy(ctx context.Context, actor Actor) (DeliveryPolicySettings, error) {
	var result DeliveryPolicySettings
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorizeRead(ctx, tx, actor, permissionRead, s.now()); err != nil {
			return err
		}
		return readDeliveryPolicy(ctx, tx, &result)
	})
	if err != nil {
		return DeliveryPolicySettings{}, fmt.Errorf("get notification delivery policy: %w", err)
	}
	return result, nil
}

func (s *Store) UpdateDeliveryPolicy(ctx context.Context, actor Actor, request UpdateDeliveryPolicyRequest) (DeliveryPolicySettings, error) {
	var result DeliveryPolicySettings
	permissionDenied := false
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if authErr := authorize(ctx, tx, actor, permissionManage, s.now()); authErr != nil {
			if !errors.Is(authErr, ErrPermissionDenied) {
				return authErr
			}
			if err := s.recordAuthenticatedAuthorizationDenial(ctx, tx, actor, request.RequestID, writeOperationPolicyUpdate); err != nil {
				return err
			}
			permissionDenied = true
			return nil
		}
		if request.ExpectedRevision < 1 || !validRequestID(request.RequestID) {
			return ErrInvalidInput
		}
		if err := validateDeliveryPolicyRequest(request); err != nil {
			return err
		}
		digest := updateDeliveryPolicyRequestDigest(request)
		receiptID, response, replayed, err := claimNotificationWriteReceipt(ctx, tx, actor, writeOperationPolicyUpdate, request.RequestID, digest, ErrVersionConflict, s.now())
		if err != nil {
			return err
		}
		if replayed {
			if err := decodeNotificationWriteReceipt(response, &result); err != nil {
				return err
			}
			return nil
		}
		var mode, timezone string
		var start, end int
		var revision64 int64
		if err := tx.QueryRow(ctx, `SELECT window_mode,window_start_minute,window_end_minute,timezone,revision FROM notification_delivery_policy WHERE singleton FOR UPDATE`).Scan(&mode, &start, &end, &timezone, &revision64); err != nil {
			return err
		}
		if revision64 != request.ExpectedRevision {
			return ErrVersionConflict
		}
		current := DeliveryPolicySettings{}
		if err := readDeliveryPolicyEvents(ctx, tx, &current); err != nil {
			return err
		}
		if len(request.Events) != len(current.Events) {
			return ErrInvalidInput
		}
		capabilities := make(map[string]bool, len(current.Events))
		for _, event := range current.Events {
			capabilities[event.EventType] = event.Supported
		}
		for _, event := range request.Events {
			if supported, exists := capabilities[event.EventType]; !exists || event.Supported != supported {
				return ErrInvalidInput
			}
		}
		changed := mode != request.WindowMode || start != requestWindowMinute(request.WindowStart) || end != requestWindowMinute(request.WindowEnd) || timezone != request.Timezone || !samePolicyEvents(current.Events, request.Events)
		if changed {
			if _, err := tx.Exec(ctx, `UPDATE notification_delivery_policy SET window_mode=$1,window_start_minute=$2,window_end_minute=$3,timezone=$4,revision=revision+1,updated_at=$5 WHERE singleton`, request.WindowMode, requestWindowMinute(request.WindowStart), requestWindowMinute(request.WindowEnd), request.Timezone, storeTime(s.now())); err != nil {
				return err
			}
			for _, event := range request.Events {
				if _, err := tx.Exec(ctx, `UPDATE notification_event_policies SET enabled=$2,sms_enabled=$3,email_enabled=$4,repeat_count=$5,interval_hours=$6,updated_at=$7 WHERE event_type=$1`, event.EventType, event.Enabled, event.SMSEnabled, event.EmailEnabled, event.RepeatCount, event.IntervalHours, storeTime(s.now())); err != nil {
					return err
				}
			}
		}
		if err := readDeliveryPolicy(ctx, tx, &result); err != nil {
			return err
		}
		result.Changed = changed
		if err := completeNotificationWriteReceipt(ctx, tx, receiptID, digest, result, s.now()); err != nil {
			return err
		}
		if !changed {
			return nil
		}
		return s.auditor.Append(ctx, tx, audit.Event{ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: writeOperationPolicyUpdate, ResourceType: "notification_delivery_policy", ResourceID: "global", RequestID: request.RequestID, Result: "success", Payload: map[string]any{"revision": result.Revision, "event_count": len(result.Events), "window_mode": result.WindowMode}})
	})
	if err != nil {
		return DeliveryPolicySettings{}, fmt.Errorf("update notification delivery policy: %w", err)
	}
	if permissionDenied {
		return DeliveryPolicySettings{}, fmt.Errorf("update notification delivery policy: %w", ErrPermissionDenied)
	}
	return result, nil
}

func readDeliveryPolicy(ctx context.Context, tx pgx.Tx, result *DeliveryPolicySettings) error {
	var start, end int
	if err := tx.QueryRow(ctx, `SELECT window_mode,window_start_minute,window_end_minute,timezone,revision FROM notification_delivery_policy WHERE singleton`).Scan(&result.WindowMode, &start, &end, &result.Timezone, &result.Revision); err != nil {
		return err
	}
	result.Schema, result.WindowStart, result.WindowEnd = "cdnca.notification-delivery-policy/v1", formatPolicyMinute(start), formatPolicyMinute(end)
	return readDeliveryPolicyEvents(ctx, tx, result)
}

func readDeliveryPolicyEvents(ctx context.Context, tx pgx.Tx, result *DeliveryPolicySettings) error {
	rows, err := tx.Query(ctx, `SELECT event_type,enabled,sms_enabled,email_enabled,repeat_count,interval_hours,supported FROM notification_event_policies ORDER BY event_type`)
	if err != nil {
		return err
	}
	defer rows.Close()
	result.Events = make([]DeliveryPolicyEvent, 0, 16)
	for rows.Next() {
		var item DeliveryPolicyEvent
		if err := rows.Scan(&item.EventType, &item.Enabled, &item.SMSEnabled, &item.EmailEnabled, &item.RepeatCount, &item.IntervalHours, &item.Supported); err != nil {
			return err
		}
		result.Events = append(result.Events, item)
	}
	return rows.Err()
}

func samePolicyEvents(left, right []DeliveryPolicyEvent) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// maxDeliveryPolicyEvents 是策略接口单次读写的事件条数上限。策略按事件目录整表
// 读出、整表写回（各迁移写入 notification_event_policies 的事件 ∪
// supportedEventTypes，10-22 为 75 条），所以上限必须大于目录总数并留余量。
// 前端 apps/web/src/api/notifications.ts maxNotificationPolicyEvents 与
// api/control-notifications.openapi.yaml DeliveryPolicyWrite.events.maxItems
// 必须同值；TestNotificationEventCatalogStaysBelowPolicyLimit 守住目录增长。
const maxDeliveryPolicyEvents = 256

// Each refusal names the body field (window_mode, timezone,
// window_start/end, events, events[n].<field>); errors.Is sees ErrInvalidInput.
func validateDeliveryPolicyRequest(request UpdateDeliveryPolicyRequest) error {
	invalid := func(field, reason string) error { return fielderr.New(ErrInvalidInput, field, reason) }
	if request.WindowMode != "all_day" && request.WindowMode != "custom" {
		return invalid("window_mode", fielderr.Invalid)
	}
	switch {
	case request.Timezone == "":
		return invalid("timezone", fielderr.Required)
	case len(request.Timezone) > 64:
		return invalid("timezone", fielderr.TooLong)
	case request.Timezone == "Local":
		return invalid("timezone", fielderr.Invalid)
	}
	if _, err := time.LoadLocation(request.Timezone); err != nil {
		return invalid("timezone", fielderr.Invalid)
	}
	if request.WindowMode == "custom" {
		if _, err := parsePolicyMinute(request.WindowStart); err != nil {
			return invalid("window_start", fielderr.InvalidFormat)
		}
		if _, err := parsePolicyMinute(request.WindowEnd); err != nil {
			return invalid("window_end", fielderr.InvalidFormat)
		}
	} else if request.WindowStart != "00:00" {
		return invalid("window_start", fielderr.Invalid)
	} else if request.WindowEnd != "23:59" {
		return invalid("window_end", fielderr.Invalid)
	}
	if len(request.Events) == 0 {
		return invalid("events", fielderr.Required)
	}
	if len(request.Events) > maxDeliveryPolicyEvents {
		return invalid("events", fielderr.TooLong)
	}
	seen := make(map[string]bool, len(request.Events))
	for index, event := range request.Events {
		field := func(name string) string { return fmt.Sprintf("events[%d].%s", index, name) }
		switch {
		case !validPolicyEventType(event.EventType):
			return invalid(field("event_type"), fielderr.InvalidFormat)
		case seen[event.EventType]:
			return invalid(field("event_type"), fielderr.Duplicate)
		case event.RepeatCount < 1 || event.RepeatCount > 10:
			return invalid(field("repeat_count"), fielderr.OutOfRange)
		case event.IntervalHours < 1 || event.IntervalHours > 168:
			return invalid(field("interval_hours"), fielderr.OutOfRange)
		}
		seen[event.EventType] = true
		if !event.Supported {
			for _, on := range []struct {
				name string
				on   bool
			}{{"enabled", event.Enabled}, {"sms_enabled", event.SMSEnabled}, {"email_enabled", event.EmailEnabled}} {
				if on.on {
					return invalid(field(on.name), fielderr.Invalid)
				}
			}
		}
	}
	return nil
}

func validPolicyEventType(value string) bool {
	if len(value) == 0 || len(value) > 96 {
		return false
	}
	for index, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9' && index > 0) || character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func parsePolicyMinute(value string) (int, error) {
	if len(value) != 5 || value[2] != ':' {
		return 0, ErrInvalidInput
	}
	hour, err1 := strconv.Atoi(value[:2])
	minute, err2 := strconv.Atoi(value[3:])
	if err1 != nil || err2 != nil || hour > 23 || minute > 59 {
		return 0, ErrInvalidInput
	}
	return hour*60 + minute, nil
}
func requestWindowMinute(value string) int { minute, _ := parsePolicyMinute(value); return minute }
func formatPolicyMinute(value int) string  { return fmt.Sprintf("%02d:%02d", value/60, value%60) }

func (s *Store) UpdateChannels(ctx context.Context, actor Actor, request UpdateChannelsRequest) (ChannelSettings, error) {
	var result ChannelSettings
	permissionDenied := false
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if authErr := authorize(ctx, tx, actor, permissionManage, s.now()); authErr != nil {
			if !errors.Is(authErr, ErrPermissionDenied) {
				return authErr
			}
			if err := s.recordAuthenticatedAuthorizationDenial(
				ctx, tx, actor, request.RequestID, writeOperationChannelsUpdate,
			); err != nil {
				return err
			}
			permissionDenied = true
			return nil
		}
		if request.ExpectedRevision < 1 || !validRequestID(request.RequestID) {
			return ErrInvalidInput
		}
		digest := updateChannelsRequestDigest(request)
		receiptID, response, replayed, err := claimNotificationWriteReceipt(
			ctx, tx, actor, writeOperationChannelsUpdate, request.RequestID, digest, ErrVersionConflict, s.now(),
		)
		if err != nil {
			return err
		}
		if replayed {
			if err := decodeNotificationWriteReceipt(response, &result); err != nil {
				return err
			}
			if result.SMSEnabled != request.SMSEnabled || result.EmailEnabled != request.EmailEnabled ||
				result.Revision != request.ExpectedRevision+boolInt64(result.Changed) {
				return errInvalidNotificationWriteReceipt
			}
			return nil
		}
		if err := tx.QueryRow(ctx, `SELECT sms_enabled,email_enabled,revision
			FROM notification_channel_settings WHERE singleton FOR UPDATE`).Scan(
			&result.SMSEnabled, &result.EmailEnabled, &result.Revision,
		); err != nil {
			return err
		}
		if result.Revision != request.ExpectedRevision {
			return ErrVersionConflict
		}
		if configured := s.configured(); request.SMSEnabled && !configured.SMS || request.EmailEnabled && !configured.Email {
			return ErrChannelUnsupported
		}
		if result.SMSEnabled == request.SMSEnabled && result.EmailEnabled == request.EmailEnabled {
			return completeNotificationWriteReceipt(ctx, tx, receiptID, digest, result, s.now())
		}
		now := storeTime(s.now())
		if _, err := tx.Exec(ctx, `UPDATE notification_channel_settings SET
			sms_enabled=$1,email_enabled=$2,revision=revision+1,updated_at=$3 WHERE singleton`,
			request.SMSEnabled, request.EmailEnabled, now); err != nil {
			return err
		}
		result.SMSEnabled, result.EmailEnabled, result.Revision, result.Changed = request.SMSEnabled, request.EmailEnabled, result.Revision+1, true
		if err := completeNotificationWriteReceipt(ctx, tx, receiptID, digest, result, s.now()); err != nil {
			return err
		}
		return s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: "notification.channels.update",
			ResourceType: "notification_channel_settings", ResourceID: "global", RequestID: request.RequestID,
			Result: "success", Payload: map[string]any{
				"revision": result.Revision, "sms_enabled": result.SMSEnabled, "email_enabled": result.EmailEnabled,
			},
		})
	})
	if err != nil {
		return ChannelSettings{}, fmt.Errorf("update notification channels: %w", err)
	}
	if permissionDenied {
		return ChannelSettings{}, fmt.Errorf("update notification channels: %w", ErrPermissionDenied)
	}
	s.channelView(&result)
	return result, nil
}

func (s *Store) ListTemplates(ctx context.Context, actor Actor) ([]Template, error) {
	var result []Template
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorizeRead(ctx, tx, actor, permissionRead, s.now()); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT template_id,version,channel,subject,body,variables,created_at
			FROM notification_templates ORDER BY template_id,version,channel`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item Template
			if err := rows.Scan(&item.TemplateID, &item.Version, &item.Channel, &item.Subject, &item.Body, &item.Variables, &item.CreatedAt); err != nil {
				return err
			}
			result = append(result, item)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list notification templates: %w", err)
	}
	if result == nil {
		result = []Template{}
	}
	return result, nil
}

func ActiveTemplateRefs(ctx context.Context, tx pgx.Tx, templateID string) (map[notification.Channel]notification.TemplateRef, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT ON (channel) template_id,version,channel,subject,body,variables
		FROM notification_templates WHERE template_id=$1 ORDER BY channel,version DESC`, templateID)
	if err != nil {
		return nil, fmt.Errorf("select active notification templates: %w", err)
	}
	defer rows.Close()
	result := make(map[notification.Channel]notification.TemplateRef)
	for rows.Next() {
		var ref notification.TemplateRef
		var version int64
		var subject, body string
		var variables []string
		if err := rows.Scan(&ref.ID, &version, &ref.Channel, &subject, &body, &variables); err != nil {
			return nil, fmt.Errorf("scan active notification template: %w", err)
		}
		ref.Version = uint64(version)
		if err := validateAnnouncementPublishedTemplate(notification.TemplateDefinition{
			Ref: ref, Subject: subject, Body: body, Variables: variables,
		}); err != nil {
			return nil, fmt.Errorf("validate active notification template: %w", err)
		}
		result[ref.Channel] = ref
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("select active notification templates: %w", err)
	}
	return result, nil
}

func (s *Store) PutTemplate(ctx context.Context, actor Actor, templateID string, version int64, channel string, input TemplateInput, requestID string) (Template, error) {
	var result Template
	permissionDenied := false
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if authErr := authorize(ctx, tx, actor, permissionManage, s.now()); authErr != nil {
			if !errors.Is(authErr, ErrPermissionDenied) {
				return authErr
			}
			if err := s.recordAuthenticatedAuthorizationDenial(
				ctx, tx, actor, requestID, writeOperationTemplatePut,
			); err != nil {
				return err
			}
			permissionDenied = true
			return nil
		}
		if !validRequestID(requestID) || version < 1 || (channel != ChannelEmail && channel != ChannelSMS) {
			return ErrInvalidInput
		}
		definition := notification.TemplateDefinition{
			Ref:     notification.TemplateRef{ID: templateID, Version: uint64(version), Channel: notification.Channel(channel)},
			Subject: input.Subject, Body: input.Body, Variables: input.Variables,
		}
		if err := notification.NewCatalog().Register(definition); err != nil {
			return templateRefusal(err)
		}
		if err := validateAnnouncementPublishedTemplate(definition); err != nil {
			return err
		}
		digest := putTemplateRequestDigest(templateID, version, channel, input)
		receiptID, response, replayed, err := claimNotificationWriteReceipt(
			ctx, tx, actor, writeOperationTemplatePut, requestID, digest, ErrTemplateVersionConflict, s.now(),
		)
		if err != nil {
			return err
		}
		if replayed {
			if err := decodeNotificationWriteReceipt(response, &result); err != nil {
				return err
			}
			if result.TemplateID != templateID || result.Version != version || result.Channel != channel ||
				result.Subject != input.Subject || result.Body != input.Body ||
				!slices.Equal(result.Variables, input.Variables) || result.CreatedAt.IsZero() {
				return errInvalidNotificationWriteReceipt
			}
			return nil
		}
		now := storeTime(s.now())
		command, err := tx.Exec(ctx, `INSERT INTO notification_templates(
			template_id,version,channel,subject,body,variables,created_at
		) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(template_id,version,channel) DO NOTHING`,
			templateID, version, channel, input.Subject, input.Body, input.Variables, now)
		if err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT template_id,version,channel,subject,body,variables,created_at
			FROM notification_templates WHERE template_id=$1 AND version=$2 AND channel=$3`,
			templateID, version, channel).Scan(&result.TemplateID, &result.Version, &result.Channel,
			&result.Subject, &result.Body, &result.Variables, &result.CreatedAt); err != nil {
			return err
		}
		if result.Subject != input.Subject || result.Body != input.Body || !slices.Equal(result.Variables, input.Variables) {
			return ErrTemplateVersionConflict
		}
		if command.RowsAffected() == 0 {
			return completeNotificationWriteReceipt(ctx, tx, receiptID, digest, result, s.now())
		}
		result.Changed = true
		if err := completeNotificationWriteReceipt(ctx, tx, receiptID, digest, result, s.now()); err != nil {
			return err
		}
		return s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: "notification.template.create",
			ResourceType: "notification_template", ResourceID: templateID + ":" + fmt.Sprint(version) + ":" + channel,
			RequestID: requestID, Result: "success", Payload: map[string]any{
				"template_id": templateID, "version": version, "channel": channel, "variable_count": len(input.Variables),
			},
		})
	})
	if err != nil {
		return Template{}, fmt.Errorf("put notification template: %w", err)
	}
	if permissionDenied {
		return Template{}, fmt.Errorf("put notification template: %w", ErrPermissionDenied)
	}
	return result, nil
}

func (s *Store) GetSubscription(ctx context.Context, actor Actor, eventType string) (Subscription, error) {
	result := Subscription{EventType: eventType}
	permissionDenied := false
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if authErr := authorizeRead(ctx, tx, actor, "", s.now()); authErr != nil {
			if !errors.Is(authErr, ErrPermissionDenied) {
				return authErr
			}
			if err := s.recordAuthenticatedAuthorizationDenial(
				ctx, tx, actor, actor.SessionID.String(), readOperationSubscriptionGet,
			); err != nil {
				return err
			}
			permissionDenied = true
			return nil
		}
		// 订阅开关按 (scope_id, user_id) 定位，本身就是自身作用域读取，
		// 因此平台作用域（无租户的管理员）同样按自身作用域放行。
		if !selfSubscriptionScope(actor) {
			if err := s.recordAuthenticatedAuthorizationDenial(
				ctx, tx, actor, actor.SessionID.String(), readOperationSubscriptionGet,
			); err != nil {
				return err
			}
			permissionDenied = true
			return nil
		}
		if !SupportedEventType(eventType) {
			return ErrNotFound
		}
		if err := readSubscription(ctx, tx, actor, eventType, false, &result); err != nil {
			return err
		}
		return s.subscriptionSupport(ctx, tx, &result)
	})
	if err != nil {
		return Subscription{}, fmt.Errorf("get notification subscription: %w", err)
	}
	if permissionDenied {
		return Subscription{}, fmt.Errorf("get notification subscription: %w", ErrPermissionDenied)
	}
	return result, nil
}

func (s *Store) UpdateSubscription(ctx context.Context, actor Actor, eventType string, request UpdateSubscriptionRequest) (Subscription, error) {
	result := Subscription{EventType: eventType}
	permissionDenied := false
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if authErr := authorize(ctx, tx, actor, "", s.now()); authErr != nil {
			if !errors.Is(authErr, ErrPermissionDenied) {
				return authErr
			}
			if err := s.recordAuthenticatedAuthorizationDenial(
				ctx, tx, actor, request.RequestID, writeOperationSubscriptionUpdate,
			); err != nil {
				return err
			}
			permissionDenied = true
			return nil
		}
		if !selfSubscriptionScope(actor) {
			if err := s.recordAuthenticatedAuthorizationDenial(
				ctx, tx, actor, request.RequestID, writeOperationSubscriptionUpdate,
			); err != nil {
				return err
			}
			permissionDenied = true
			return nil
		}
		if !SupportedEventType(eventType) {
			return ErrNotFound
		}
		if request.ExpectedRevision < 0 || !validRequestID(request.RequestID) ||
			request.InboxEnabled != nil && !ticketInboxEvent(eventType) {
			return ErrInvalidInput
		}
		digest := updateSubscriptionRequestDigest(eventType, request)
		receiptID, response, replayed, err := claimNotificationWriteReceipt(
			ctx, tx, actor, writeOperationSubscriptionUpdate, request.RequestID, digest, ErrVersionConflict, s.now(),
		)
		if err != nil {
			return err
		}
		if replayed {
			if err := decodeNotificationWriteReceipt(response, &result); err != nil {
				return err
			}
			if result.EventType != eventType || result.SMSEnabled != request.SMSEnabled ||
				result.EmailEnabled != request.EmailEnabled ||
				request.InboxEnabled != nil && (result.InboxEnabled == nil || *result.InboxEnabled != *request.InboxEnabled) ||
				result.Revision != request.ExpectedRevision+boolInt64(result.Changed) {
				return errInvalidNotificationWriteReceipt
			}
			return s.subscriptionSupport(ctx, tx, &result)
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended(
			'notification-subscription:' || $1::text || ':' || $2::text || ':' || $3,0))`,
			actor.ScopeID, actor.UserID, eventType); err != nil {
			return err
		}
		if err := readSubscription(ctx, tx, actor, eventType, true, &result); err != nil {
			return err
		}
		if result.Revision != request.ExpectedRevision {
			return ErrVersionConflict
		}
		if err := s.subscriptionSupport(ctx, tx, &result); err != nil {
			return err
		}
		if request.SMSEnabled && !result.SMSSupported || request.EmailEnabled && !result.EmailSupported {
			return ErrChannelUnsupported
		}
		inbox := true
		if result.InboxEnabled != nil {
			inbox = *result.InboxEnabled
		}
		nextInbox := inbox
		if request.InboxEnabled != nil {
			nextInbox = *request.InboxEnabled
		}
		if result.SMSEnabled == request.SMSEnabled && result.EmailEnabled == request.EmailEnabled && inbox == nextInbox {
			return completeNotificationWriteReceipt(ctx, tx, receiptID, digest, result, s.now())
		}
		now := storeTime(s.now())
		if result.Revision == 0 {
			_, err = tx.Exec(ctx, `INSERT INTO notification_subscriptions(
				scope_id,user_id,event_type,sms_enabled,email_enabled,inbox_enabled,revision,created_at,updated_at
			) VALUES($1,$2,$3,$4,$5,$6,1,$7,$7)`, actor.ScopeID, actor.UserID, eventType,
				request.SMSEnabled, request.EmailEnabled, nextInbox, now)
			result.Revision = 1
		} else {
			_, err = tx.Exec(ctx, `UPDATE notification_subscriptions SET sms_enabled=$4,email_enabled=$5,inbox_enabled=$6,
				revision=revision+1,updated_at=$7 WHERE scope_id=$1 AND user_id=$2 AND event_type=$3`,
				actor.ScopeID, actor.UserID, eventType, request.SMSEnabled, request.EmailEnabled, nextInbox, now)
			result.Revision++
		}
		if err != nil {
			return err
		}
		result.SMSEnabled, result.EmailEnabled, result.Changed = request.SMSEnabled, request.EmailEnabled, true
		if result.InboxEnabled != nil {
			result.InboxEnabled = &nextInbox
		}
		if err := completeNotificationWriteReceipt(ctx, tx, receiptID, digest, result, s.now()); err != nil {
			return err
		}
		return s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: "notification.subscription.update",
			ResourceType: "notification_subscription", ResourceID: eventType, RequestID: request.RequestID,
			Result: "success", Payload: map[string]any{
				"event_type": eventType, "revision": result.Revision,
				"sms_enabled": result.SMSEnabled, "email_enabled": result.EmailEnabled, "inbox_enabled": nextInbox,
			},
		})
	})
	if err != nil {
		return Subscription{}, fmt.Errorf("update notification subscription: %w", err)
	}
	if permissionDenied {
		return Subscription{}, fmt.Errorf("update notification subscription: %w", ErrPermissionDenied)
	}
	return result, nil
}

// identityLock is the row lock an authorization takes on the caller's
// session, account, membership, scope and tenant rows.
type identityLock string

const (
	// identityLockWrite: writes keep the exclusive fence they always had.
	identityLockWrite identityLock = "UPDATE"
	// identityLockRead (notif-sub): reads only need status changes to wait
	// for them. FOR UPDATE made the 23 concurrent GETs of one subscription
	// page queue on the same four rows, so any lock wait limit turned the
	// tail of that queue into random 500s.
	identityLockRead identityLock = "SHARE"
)

func authorize(ctx context.Context, tx pgx.Tx, actor Actor, permission string, now time.Time) error {
	return authorizeLocked(ctx, tx, actor, permission, now, identityLockWrite)
}

func authorizeRead(ctx context.Context, tx pgx.Tx, actor Actor, permission string, now time.Time) error {
	return authorizeLocked(ctx, tx, actor, permission, now, identityLockRead)
}

func authorizeLocked(ctx context.Context, tx pgx.Tx, actor Actor, permission string, now time.Time, lock identityLock) error {
	if permission == "" {
		return authorizeAny(ctx, tx, actor, nil, now, lock)
	}
	return authorizeAny(ctx, tx, actor, []string{permission}, now, lock)
}

// authorizeAny grants when the actor holds any one of permissions; an empty
// set only checks the authenticated session.
func authorizeAny(ctx context.Context, tx pgx.Tx, actor Actor, permissions []string, now time.Time, lock identityLock) error {
	if actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || actor.SessionID == uuid.Nil ||
		(actor.ScopeKind != "platform" && actor.ScopeKind != "tenant") {
		return ErrUnauthenticated
	}
	if err := acquireNotificationAuthorizationLocks(ctx, tx, actor.ScopeID); err != nil {
		return err
	}
	return authorizeNotificationCurrent(ctx, tx, actor, permissions, now, lock)
}

func acquireNotificationAuthorizationLocks(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) error {
	if err := protocol.AcquireShared(ctx, tx); err != nil {
		return fmt.Errorf("acquire notification IAM global lock: %w", err)
	}
	if _, err := protocol.AcquireScopes(ctx, tx, []uuid.UUID{scopeID}); err != nil {
		return fmt.Errorf("acquire notification IAM scope lock: %w", err)
	}
	return nil
}

func authorizeNotificationCurrent(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	permissions []string,
	now time.Time,
	lock identityLock,
) error {
	if lock != identityLockWrite && lock != identityLockRead {
		return ErrInvalidStore
	}
	now = storeTime(now)
	var scopeKind, userStatus, membershipStatus string
	var tenantID *uuid.UUID
	var revokedAt *time.Time
	var expiresAt time.Time
	err := tx.QueryRow(ctx, `SELECT scope.kind,scope.tenant_id,account.status,membership.status,
		session.revoked_at,session.expires_at
		FROM auth_sessions session
		JOIN users account ON account.id=session.user_id
		JOIN memberships membership ON membership.scope_id=session.scope_id AND membership.user_id=session.user_id
		JOIN access_scopes scope ON scope.id=session.scope_id
		WHERE session.id=$1 AND session.user_id=$2 AND session.scope_id=$3
		FOR `+string(lock)+` OF session,account,membership,scope`, actor.SessionID, actor.UserID, actor.ScopeID).
		Scan(&scopeKind, &tenantID, &userStatus, &membershipStatus, &revokedAt, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrUnauthenticated
	}
	if err != nil {
		return err
	}
	if revokedAt != nil || !now.Before(expiresAt) {
		return ErrUnauthenticated
	}
	if scopeKind != actor.ScopeKind {
		return ErrUnauthenticated
	}
	if userStatus != "active" || membershipStatus != "active" ||
		(scopeKind == "platform" && tenantID != nil) || (scopeKind == "tenant" && tenantID == nil) {
		return ErrPermissionDenied
	}
	if tenantID != nil {
		var tenantStatus string
		err = tx.QueryRow(ctx, `SELECT status FROM tenants WHERE id=$1 FOR SHARE`, *tenantID).Scan(&tenantStatus)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrPermissionDenied
		}
		if err != nil {
			return err
		}
		if tenantStatus != "active" {
			return ErrPermissionDenied
		}
	}
	if len(permissions) == 0 {
		return nil
	}
	if scopeKind != "platform" {
		return ErrPermissionDenied
	}
	var granted bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM role_assignments assignment
		JOIN roles role ON role.id=assignment.role_id AND role.scope_id=assignment.scope_id
		JOIN role_permissions grant_row ON grant_row.role_id=role.id
		WHERE assignment.scope_id=$1 AND assignment.user_id=$2 AND grant_row.permission_name=ANY($3::text[] || ARRAY['platform.admin'])
	)`, actor.ScopeID, actor.UserID, permissions).Scan(&granted)
	if err != nil {
		return err
	}
	if !granted {
		return ErrPermissionDenied
	}
	return nil
}

func (s *Store) recordAuthenticatedAuthorizationDenial(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	requestID, operation string,
) error {
	if tx == nil || actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || actor.SessionID == uuid.Nil ||
		(actor.ScopeKind != "platform" && actor.ScopeKind != "tenant") ||
		(operation != readOperationSubscriptionGet && operation != writeOperationChannelsUpdate &&
			operation != writeOperationTemplatePut && operation != writeOperationSubscriptionUpdate &&
			operation != readOperationPolicyGet && operation != writeOperationPolicyUpdate) {
		return errInvalidNotificationDenialAudit
	}
	if !validRequestID(requestID) {
		requestID = actor.SessionID.String()
	}
	lockKey := "notification-control-denial:" + actor.ScopeID.String() + ":" +
		actor.UserID.String() + ":" + operation + ":" + requestID
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, lockKey); err != nil {
		return fmt.Errorf("lock notification denial request: %w", err)
	}
	var exact, occupied bool
	if err := tx.QueryRow(ctx, `SELECT
			EXISTS (SELECT 1 FROM audit_events WHERE scope_id=$1 AND actor_user_id=$2
				AND action=$3 AND request_id=$4 AND result='denied'
				AND resource_type='notification_control' AND resource_id=$3
				AND payload=jsonb_build_object('reason_code','permission_denied','operation',$3::text)),
			EXISTS (SELECT 1 FROM audit_events WHERE scope_id=$1 AND actor_user_id=$2
				AND action=$3 AND request_id=$4 AND result='denied')`, actor.ScopeID, actor.UserID,
		operation, requestID).Scan(&exact, &occupied); err != nil {
		return fmt.Errorf("read notification denial audit: %w", err)
	}
	if exact {
		return nil
	}
	if occupied {
		return errInvalidNotificationDenialAudit
	}
	return s.auditor.Append(ctx, tx, audit.Event{
		ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: operation,
		ResourceType: "notification_control", ResourceID: operation,
		RequestID: requestID, Result: "denied",
		Payload: map[string]any{"reason_code": "permission_denied", "operation": operation},
	})
}

func storeTime(value time.Time) time.Time {
	return value.UTC().Truncate(time.Microsecond)
}

// selfSubscriptionScope reports whether the actor may address its own notification
// subscription row. Those rows are keyed by (scope_id, user_id), so a platform-scope
// administrator manages its own scope rather than a cross-tenant view.
// readSubscription loads the member's choice for eventType, or the event's
// default channels (revision 0) when they never chose (316).
func readSubscription(ctx context.Context, tx pgx.Tx, actor Actor, eventType string, lock bool, result *Subscription) error {
	query := `SELECT sms_enabled,email_enabled,inbox_enabled,revision FROM notification_subscriptions
		WHERE scope_id=$1 AND user_id=$2 AND event_type=$3`
	if lock {
		query += ` FOR UPDATE`
	}
	inbox := true
	err := tx.QueryRow(ctx, query, actor.ScopeID, actor.UserID, eventType).
		Scan(&result.SMSEnabled, &result.EmailEnabled, &inbox, &result.Revision)
	if ticketInboxEvent(eventType) && (err == nil || errors.Is(err, pgx.ErrNoRows)) {
		result.InboxEnabled = &inbox // never chose: the 546 default (on)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	result.Revision = 0
	// tenant events default on (notification.DefaultChannels),
	// the same rule delivery applies, so the page shows what will be sent.
	var supported, defaultSMS, defaultEmail bool
	err = tx.QueryRow(ctx, `SELECT policy.supported, COALESCE((to_jsonb(policy)->>'default_sms')::boolean, false),
		COALESCE((to_jsonb(policy)->>'default_email')::boolean, false)
		FROM notification_event_policies policy WHERE policy.event_type=$1`,
		eventType).Scan(&supported, &defaultSMS, &defaultEmail)
	if errors.Is(err, pgx.ErrNoRows) {
		result.SMSEnabled, result.EmailEnabled = false, false
		return nil
	}
	if err != nil {
		return err
	}
	result.SMSEnabled, result.EmailEnabled = notification.DefaultChannels(eventType, supported, defaultSMS, defaultEmail)
	return nil
}

// ticketInboxEvent: events whose in-app copy the member chooses (546).
func ticketInboxEvent(eventType string) bool {
	return slices.Contains(notification.TicketInboxEventTypes, eventType)
}

func selfSubscriptionScope(actor Actor) bool {
	return actor.ScopeKind == "tenant" || actor.ScopeKind == "platform"
}

func validRequestID(value string) bool {
	if len(value) < 1 || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < ' ' || character == '\u007f' {
			return false
		}
	}
	return true
}

func claimNotificationWriteReceipt(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	operation string,
	requestKey string,
	digest [sha256.Size]byte,
	conflictErr error,
	now time.Time,
) (uuid.UUID, []byte, bool, error) {
	receiptID, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, nil, false, fmt.Errorf("generate notification write receipt ID: %w", err)
	}
	err = tx.QueryRow(ctx, `INSERT INTO notification_control_idempotency_receipts(
		id,actor_scope_id,actor_user_id,operation,request_key,request_digest,created_at
	) VALUES($1,$2,$3,$4,$5,$6,$7)
	ON CONFLICT(actor_scope_id,actor_user_id,operation,request_key) DO NOTHING
	RETURNING id`, receiptID, actor.ScopeID, actor.UserID, operation, requestKey, digest[:], storeTime(now)).Scan(&receiptID)
	if err == nil {
		return receiptID, nil, false, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, nil, false, fmt.Errorf("claim notification write receipt: %w", err)
	}

	var storedDigest, response []byte
	var completedAt *time.Time
	err = tx.QueryRow(ctx, `SELECT id,request_digest,response_body,completed_at
		FROM notification_control_idempotency_receipts
		WHERE actor_scope_id=$1 AND actor_user_id=$2 AND operation=$3 AND request_key=$4
		FOR UPDATE`, actor.ScopeID, actor.UserID, operation, requestKey).
		Scan(&receiptID, &storedDigest, &response, &completedAt)
	if err != nil {
		return uuid.Nil, nil, false, fmt.Errorf("read notification write receipt: %w", err)
	}
	if !bytes.Equal(storedDigest, digest[:]) {
		return uuid.Nil, nil, false, conflictErr
	}
	if completedAt == nil || len(response) == 0 || !json.Valid(response) {
		return uuid.Nil, nil, false, errInvalidNotificationWriteReceipt
	}
	return receiptID, response, true, nil
}

func completeNotificationWriteReceipt(
	ctx context.Context,
	tx pgx.Tx,
	receiptID uuid.UUID,
	digest [sha256.Size]byte,
	response any,
	now time.Time,
) error {
	encoded, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("encode notification write receipt: %w", err)
	}
	command, err := tx.Exec(ctx, `UPDATE notification_control_idempotency_receipts
		SET response_body=$3,completed_at=$4
		WHERE id=$1 AND request_digest=$2 AND completed_at IS NULL`,
		receiptID, digest[:], encoded, storeTime(now))
	if err != nil {
		return fmt.Errorf("complete notification write receipt: %w", err)
	}
	if command.RowsAffected() != 1 {
		return errInvalidNotificationWriteReceipt
	}
	return nil
}

func decodeNotificationWriteReceipt(encoded []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("%w: decode response", errInvalidNotificationWriteReceipt)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing response", errInvalidNotificationWriteReceipt)
	}
	return nil
}

func boolInt64(value bool) int64 {
	if value {
		return 1
	}
	return 0
}

func updateChannelsRequestDigest(request UpdateChannelsRequest) [sha256.Size]byte {
	return notificationControlWriteDigest(
		"notification-control-channels-update-v1",
		[]string{"/v1/admin/notifications/channels"},
		[]int64{request.ExpectedRevision},
		[]bool{request.SMSEnabled, request.EmailEnabled},
	)
}

func putTemplateRequestDigest(templateID string, version int64, channel string, input TemplateInput) [sha256.Size]byte {
	values := []string{
		"/v1/admin/notifications/templates/{template_id}/versions/{version}/{channel}",
		templateID,
		channel,
		input.Subject,
		input.Body,
	}
	values = append(values, input.Variables...)
	return notificationControlWriteDigest(
		"notification-control-template-put-v1",
		values,
		[]int64{version, int64(len(input.Variables))},
		nil,
	)
}

func updateSubscriptionRequestDigest(eventType string, request UpdateSubscriptionRequest) [sha256.Size]byte {
	return notificationControlWriteDigest(
		"notification-control-subscription-update-v1",
		[]string{"/v1/account/notification-subscriptions/{event_type}", eventType},
		[]int64{request.ExpectedRevision},
		subscriptionDigestSwitches(request),
	)
}

// subscriptionDigestSwitches keeps the pre-546 digest of a write without an
// in-app choice, so its receipts still replay.
func subscriptionDigestSwitches(request UpdateSubscriptionRequest) []bool {
	if request.InboxEnabled == nil {
		return []bool{request.SMSEnabled, request.EmailEnabled}
	}
	return []bool{request.SMSEnabled, request.EmailEnabled, true, *request.InboxEnabled}
}

func updateDeliveryPolicyRequestDigest(request UpdateDeliveryPolicyRequest) [sha256.Size]byte {
	values := []string{"/v1/admin/notifications/policy", request.WindowMode, request.WindowStart, request.WindowEnd, request.Timezone}
	integers := []int64{request.ExpectedRevision, int64(len(request.Events))}
	booleans := make([]bool, 0, len(request.Events)*3)
	for _, event := range request.Events {
		values = append(values, event.EventType)
		integers = append(integers, int64(event.RepeatCount), int64(event.IntervalHours))
		booleans = append(booleans, event.Enabled, event.SMSEnabled, event.EmailEnabled, event.Supported)
	}
	return notificationControlWriteDigest("notification-control-policy-update-v1", values, integers, booleans)
}

func notificationControlWriteDigest(
	domain string,
	strings []string,
	integers []int64,
	booleans []bool,
) [sha256.Size]byte {
	digest := sha256.New()
	writeNotificationDigestString(digest, domain)
	var encoded [8]byte
	for _, count := range []int{len(strings), len(integers), len(booleans)} {
		binary.BigEndian.PutUint64(encoded[:], uint64(count))
		_, _ = digest.Write(encoded[:])
	}
	for _, value := range strings {
		writeNotificationDigestString(digest, value)
	}
	for _, value := range integers {
		binary.BigEndian.PutUint64(encoded[:], uint64(value))
		_, _ = digest.Write(encoded[:])
	}
	for _, value := range booleans {
		if value {
			_, _ = digest.Write([]byte{1})
		} else {
			_, _ = digest.Write([]byte{0})
		}
	}
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result
}

func writeNotificationDigestString(digest hash.Hash, value string) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = digest.Write(length[:])
	_, _ = digest.Write([]byte(value))
}

func validateAnnouncementPublishedTemplate(definition notification.TemplateDefinition) error {
	if definition.Ref.ID != announcementPublishedTemplateID {
		return nil
	}
	// the fixed template's refusals name subject / body /
	// variables; the rendered bound (renderAnnouncementTemplatePart) is too_long.
	if len(definition.Variables) != 2 ||
		!slices.Contains(definition.Variables, "title") || !slices.Contains(definition.Variables, "body") {
		return fielderr.New(ErrInvalidInput, "variables", fielderr.Invalid)
	}
	if definition.Ref.Channel == notification.ChannelSMS {
		if definition.Subject != "" {
			return fielderr.New(ErrInvalidInput, "subject", fielderr.Invalid)
		}
		return nil
	}
	if definition.Ref.Channel != notification.ChannelEmail {
		return ErrInvalidInput
	}
	if err := renderAnnouncementTemplatePart(definition.Subject,
		notification.MaxEmailSubjectRunes*utf8.UTFMax, notification.MaxEmailSubjectRunes); err != nil {
		return fielderr.New(ErrInvalidInput, "subject", announcementPartReason(err))
	}
	if err := renderAnnouncementTemplatePart(definition.Body,
		notification.MaxEmailBodyBytes, 0); err != nil {
		return fielderr.New(ErrInvalidInput, "body", announcementPartReason(err))
	}
	return nil
}

// errAnnouncementPartTooLong: the part's rendered bound is over the channel limit.
var errAnnouncementPartTooLong = fmt.Errorf("%w: rendered bound over limit", ErrInvalidInput)

func announcementPartReason(err error) string {
	if errors.Is(err, errAnnouncementPartTooLong) {
		return fielderr.TooLong
	}
	return fielderr.Invalid
}

// templateRefusal maps a catalog refusal of a template write to ErrInvalidInput,
// keeping the field the catalog located.
func templateRefusal(err error) error {
	if located, ok := fielderr.As(err); ok {
		return fielderr.New(ErrInvalidInput, located.Field, located.Reason)
	}
	return ErrInvalidInput
}

func renderAnnouncementTemplatePart(source string, maxBytes, maxRunes int) error {
	if !utf8.ValidString(source) {
		return ErrInvalidInput
	}
	parsed, err := texttemplate.New("announcement").Option("missingkey=error").Parse(source)
	if err != nil || len(parsed.Templates()) != 1 || parsed.Tree == nil || parsed.Tree.Root == nil {
		return ErrInvalidInput
	}
	bytes, runes, err := announcementTemplateOutputBound(parsed.Tree.Root)
	if err != nil {
		return err
	}
	if bytes > maxBytes || (maxRunes > 0 && runes > maxRunes) {
		return errAnnouncementPartTooLong
	}
	return nil
}

func announcementTemplateOutputBound(node parse.Node) (int, int, error) {
	switch current := node.(type) {
	case *parse.ListNode:
		var bytes, runes int
		for _, child := range current.Nodes {
			childBytes, childRunes, err := announcementTemplateOutputBound(child)
			if err != nil {
				return 0, 0, err
			}
			bytes += childBytes
			runes += childRunes
		}
		return bytes, runes, nil
	case *parse.TextNode:
		return len(current.Text), utf8.RuneCount(current.Text), nil
	case *parse.ActionNode:
		if current.Pipe == nil || len(current.Pipe.Decl) != 0 || current.Pipe.IsAssign ||
			len(current.Pipe.Cmds) != 1 || len(current.Pipe.Cmds[0].Args) != 1 {
			return 0, 0, ErrInvalidInput
		}
		field, ok := current.Pipe.Cmds[0].Args[0].(*parse.FieldNode)
		if !ok || len(field.Ident) != 1 {
			return 0, 0, ErrInvalidInput
		}
		switch field.Ident[0] {
		case "title":
			return announcement.MaxTitleRunes * utf8.UTFMax, announcement.MaxTitleRunes, nil
		case "body":
			return announcement.MaxBodyBytes, announcement.MaxBodyBytes, nil
		default:
			return 0, 0, ErrInvalidInput
		}
	default:
		return 0, 0, ErrInvalidInput
	}
}
