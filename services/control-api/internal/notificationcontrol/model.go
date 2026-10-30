package notificationcontrol

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	EventTypeAnnouncementPublished = "announcement.published"
	ChannelSMS                     = "sms"
	ChannelEmail                   = "email"
)

var supportedEventTypes = [...]string{
	EventTypeAnnouncementPublished,
	// 336: CC auto switch engaged on a site (FX65, internal/ccautoswitch).
	"package.monitor.cc_rule_auto_switch",
	// 418: an origin level switch / all origins down,
	// and (manual failback) a recovered higher level (internal/originfailover).
	"site.origin.failover",
	"site.origin.recovered",
	// 405: a site under attack (ge-waf S7, internal/attackalert).
	"security.attack.detected",
	// 415: adaptive WAF automatic exclusions (ADR 0011 RI-06, internal/wafadapt).
	"security.waf.auto_exclusion_active",
	"security.waf.auto_exclusion_revoked",
	"security.waf.auto_exclusion_expired",
	// 370: certificate expiry stages (internal/certificateexpiry); 368:
	// reminders and failed renewals (internal/certnotify) share the first two.
	"certificate.expiring",
	"certificate.expired",
	"certificate.renew_failed",
	"node.availability.offline",
	"node.availability.recovered",
	// 558 (NODE-N03): bandwidth auto-disable (internal/nodeserving bandwidth_alert.go).
	"node.bandwidth.exceeded",
	"node.bandwidth.recovered",
	// 571: line group backup IP (internal/nodeserving line_backup.go).
	"node.line_group.backup_ip_activated",
	"node.line_group.primary_ip_restored",
	// 347: ACME HTTP-01 epoch drift (internal/acmehttp01).
	"acme.http01.epoch_drift",
	// 416: aggregated edge scheduling alerts (internal/aggregatededge).
	"aggregated_edge.schedule.alert",
	// 421: node kernel ban security events (internal/autodefense).
	"node.security.event",
	// 448: WAF automatic bans (internal/securityban waf_ban_alerts.go).
	"node.security.waf_ban",
	// 461: ban / site drop list cut to the contract limit (internal/securityban truncation.go).
	"node.security.list_truncated",
	// 530: a node permanently refused an installation ban revision (internal/installationban).
	"installation_ban.rejected",
	// 555: node install trust check / republication failing (internal/nativebackup).
	"node.install_trust.failed",
	// 427: dnspup probe source paused (internal/dnspupprobe).
	"probe.dnspup.degraded",
	// 460: dnspup node probing (internal/nodednspupprobe).
	"node.dnspup.unreachable",
	"node.dnspup.recovered",
	"probe.dnspup.balance_low",
	"probe.dnspup.balance_exhausted",
	// 429: expired node certificate self-recovery (internal/nodeidentity).
	"node.certificate.recovered",
	// 302_tickets (internal/tickets).
	"ticket.created",
	"ticket.replied",
	"ticket.status_changed",
	// 316: operator side (platform members holding tickets.manage).
	"ticket.staff.created",
	"ticket.staff.replied",
	// 546: tickets past the first-response SLA.
	"ticket.staff.overdue",
	// 431: node market notices (ADR 0012 §8, internal/marketruntime notices.go).
	"market.limit.warn80", "market.limit.warn95", "market.limit.reached", "market.limit.recovered",
	"market.prepaid.low", "market.prepaid.exhausted", "market.prepaid.restored",
	"market.overdraft.warn", "market.overdraft.capped",
	"market.node.overloaded", "market.node.recovered", "market.supply.all_overloaded",
	"market.plugin.unavailable", "market.plugin.restored",
	// 438: reseller notice of a downstream attack (ML-20).
	"market.downstream.attacked",
	// 439: stop complaint outcomes (ADR 0012 §18.3, ML-17).
	"market.complaint.resolved", "market.complaint.actioned",
	// 440: whole-node actions and same-site pause (ML-23/24).
	"market.node.action", "market.site.paused", "market.site.resumed",
	// 441: direct commission prepaid balance (ML-27).
	"market.commission.low", "market.commission.exhausted", "market.commission.restored",
	// 442: ML-31 (ADR 0012 §24): zero online available nodes.
	"market.supply.outage", "market.supply.restored", "market.supply.cancel_available",
	// 565 (internal/marketsubscribe reconcile.go).
	"market.supply.receipt_unconfirmed",
	// 590 (internal/marketsubscribe node_check.go).
	"market.supply.node_delivery_failed",
	// 443: seller changed an offer before the buyer's renewal (C7a).
	"market.terms.changed",
	// 444: direct top-ups (ADR 0015).
	"market.direct_topup.paid", "market.direct_topup.received",
	// 445: anti-abscond seller deposit (ADR 0015 §11).
	"market.seller.deposit_mode", "market.seller.deposit_shortfall", "market.seller.default_compensated", "market.seller.defaulted",
}

var (
	ErrInvalidStore            = errors.New("notification_control_invalid_store")
	ErrInvalidInput            = errors.New("notification_control_invalid_input")
	ErrUnauthenticated         = errors.New("notification_control_unauthenticated")
	ErrPermissionDenied        = errors.New("notification_control_permission_denied")
	ErrNotFound                = errors.New("notification_control_not_found")
	ErrVersionConflict         = errors.New("notification_control_version_conflict")
	ErrTemplateVersionConflict = errors.New("notification_control_template_version_conflict")
	ErrChannelUnsupported      = errors.New("notification_control_channel_unsupported")
)

type Clock func() time.Time

type AuditAppender interface {
	Append(context.Context, pgx.Tx, audit.Event) error
}

type Actor struct {
	UserID    uuid.UUID
	ScopeID   uuid.UUID
	SessionID uuid.UUID
	ScopeKind string
}

type ChannelSettings struct {
	SMSEnabled     bool  `json:"sms_enabled"`
	EmailEnabled   bool  `json:"email_enabled"`
	SMSSupported   bool  `json:"sms_supported"`
	EmailSupported bool  `json:"email_supported"`
	Revision       int64 `json:"revision"`
	Changed        bool  `json:"changed"`
}

type UpdateChannelsRequest struct {
	ExpectedRevision int64
	SMSEnabled       bool
	EmailEnabled     bool
	RequestID        string
}

type TemplateInput struct {
	Subject   string   `json:"subject"`
	Body      string   `json:"body"`
	Variables []string `json:"variables"`
}

type Template struct {
	TemplateID string    `json:"template_id"`
	Version    int64     `json:"version"`
	Channel    string    `json:"channel"`
	Subject    string    `json:"subject"`
	Body       string    `json:"body"`
	Variables  []string  `json:"variables"`
	CreatedAt  time.Time `json:"created_at"`
	Changed    bool      `json:"changed"`
}

type Subscription struct {
	EventType      string `json:"event_type"`
	SMSEnabled     bool   `json:"sms_enabled"`
	EmailEnabled   bool   `json:"email_enabled"`
	SMSSupported   bool   `json:"sms_supported"`
	EmailSupported bool   `json:"email_supported"`
	// InboxEnabled (546): the in-app copy of a ticket event;
	// absent for every other event.
	InboxEnabled *bool `json:"inbox_enabled,omitempty"`
	Revision     int64 `json:"revision"`
	Changed      bool  `json:"changed"`
}

type UpdateSubscriptionRequest struct {
	ExpectedRevision int64
	SMSEnabled       bool
	EmailEnabled     bool
	// InboxEnabled: nil keeps the stored in-app choice; set only for ticket
	// events (notification.TicketInboxEventTypes).
	InboxEnabled *bool
	RequestID    string
}

type DeliveryPolicyEvent struct {
	EventType     string `json:"event_type"`
	Enabled       bool   `json:"enabled"`
	SMSEnabled    bool   `json:"sms_enabled"`
	EmailEnabled  bool   `json:"email_enabled"`
	RepeatCount   int    `json:"repeat_count"`
	IntervalHours int    `json:"interval_hours"`
	Supported     bool   `json:"supported"`
}

type DeliveryPolicySettings struct {
	Schema      string                `json:"schema"`
	WindowMode  string                `json:"window_mode"`
	WindowStart string                `json:"window_start"`
	WindowEnd   string                `json:"window_end"`
	Timezone    string                `json:"timezone"`
	Revision    int64                 `json:"revision"`
	Changed     bool                  `json:"changed"`
	Events      []DeliveryPolicyEvent `json:"events"`
}

type UpdateDeliveryPolicyRequest struct {
	ExpectedRevision int64
	WindowMode       string
	WindowStart      string
	WindowEnd        string
	Timezone         string
	Events           []DeliveryPolicyEvent
	RequestID        string
}

type DeliveryLogQuery struct {
	ScopeID string
	Channel string
	State   string
	Limit   string
	Cursor  string
	Invalid bool
}

type DeliveryLog struct {
	ScopeID          uuid.UUID  `json:"scope_id"`
	OutboxID         uuid.UUID  `json:"outbox_id"`
	EventType        string     `json:"event_type"`
	Channel          string     `json:"channel"`
	TemplateID       string     `json:"template_id"`
	TemplateVersion  int64      `json:"template_version"`
	Generation       int        `json:"generation"`
	State            string     `json:"state"`
	Revision         int        `json:"revision"`
	AttemptCount     int        `json:"attempt_count"`
	Provider         *string    `json:"provider,omitempty"`
	FailureCode      *string    `json:"failure_code,omitempty"`
	RetryAt          *time.Time `json:"retry_at,omitempty"`
	AcceptedAt       *time.Time `json:"accepted_at,omitempty"`
	CompletedAt      *time.Time `json:"completed_at,omitempty"`
	ReplayOfOutboxID *uuid.UUID `json:"replay_of_outbox_id,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

type DeliveryLogPage struct {
	Items      []DeliveryLog `json:"items"`
	NextCursor string        `json:"next_cursor,omitempty"`
}

type DeliveryAttempt struct {
	AttemptNumber  int        `json:"attempt_number"`
	Outcome        string     `json:"outcome"`
	FailureCode    *string    `json:"failure_code,omitempty"`
	NextAttemptAt  *time.Time `json:"next_attempt_at,omitempty"`
	LeaseExpiresAt time.Time  `json:"lease_expires_at"`
	ClaimedAt      time.Time  `json:"claimed_at"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
}

type DeliveryAttemptPage struct {
	OutboxID uuid.UUID         `json:"outbox_id"`
	Items    []DeliveryAttempt `json:"items"`
}

// MessageQuery is the compatibility projection used by the administrator's
// message list.  Unlike DeliveryLogQuery it is event-centric: one row is
// returned per notification event and channel bodies are joined into the
// corresponding nullable fields. Package ownership is read from exact monitor
// transition facts. Site ownership is not inferred from current bindings or
// source_event_id because no event-time site relation is retained.
type MessageQuery struct {
	ScopeID   string
	Type      string
	UserID    string
	PackageID string
	SiteID    string
	// User, Package and Site match by name or exact display ID.
	User, Package, Site string
	Limit               string
	Cursor              string
	Invalid             bool
}

type Message struct {
	ID           uuid.UUID  `json:"id"`
	UserID       *uuid.UUID `json:"user_id"`
	Type         string     `json:"type"`
	Title        *string    `json:"title"`
	PackageID    *string    `json:"package_id"`
	SiteID       *string    `json:"site_id"`
	CreatedAt    time.Time  `json:"created_at"`
	EmailContent *string    `json:"email_content"`
	SMSContent   *string    `json:"sms_content"`
	// Delivery state of the original channel message (settlement state, or
	// pending before the first attempt); null when no message was generated.
	EmailState *string `json:"email_state"`
	SMSState   *string `json:"sms_state"`
	// Current readable names of the recipient, site and package (L1); null
	// when the object is gone.
	UserDisplayID   *int64  `json:"user_display_id"`
	Username        *string `json:"username"`
	UserDisplayName *string `json:"user_display_name"`
	SiteDomain      *string `json:"site_domain"`
	PackageName     *string `json:"package_name"`
}

type MessagePage struct {
	Schema     string    `json:"schema"`
	Items      []Message `json:"items"`
	NextCursor string    `json:"next_cursor,omitempty"`
	Total      int64     `json:"total"`
}

func SupportedEventType(eventType string) bool {
	return slices.Contains(supportedEventTypes[:], eventType)
}
