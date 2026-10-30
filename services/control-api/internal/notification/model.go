package notification

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalidTemplate            = errors.New("invalid notification template")
	ErrTemplateLimit              = errors.New("notification template exceeds resource limits")
	ErrTemplateExists             = errors.New("notification template already exists")
	ErrTemplateNotFound           = errors.New("notification template not found")
	ErrVariableMismatch           = errors.New("notification template variables do not match")
	ErrContextLimit               = errors.New("notification context exceeds resource limits")
	ErrSensitiveContext           = errors.New("sensitive notification context is forbidden")
	ErrRender                     = errors.New("notification template rendering failed")
	ErrRenderLimit                = errors.New("notification rendering exceeds resource limits")
	ErrInvalidPolicy              = errors.New("invalid notification delivery policy")
	ErrInvalidIdentity            = errors.New("invalid notification event identity")
	ErrTemplateSelection          = errors.New("invalid notification template selection")
	ErrInvalidEngine              = errors.New("invalid notification engine")
	ErrInvalidRetryPolicy         = errors.New("invalid notification retry policy")
	ErrInvalidFailure             = errors.New("invalid notification failure")
	ErrInvalidStore               = errors.New("invalid notification store")
	ErrInvalidEnqueue             = errors.New("invalid notification enqueue request")
	ErrInvalidDispatch            = errors.New("invalid anonymous notification dispatch")
	ErrTenantScopeDenied          = errors.New("notification tenant scope denied")
	ErrEventConflict              = errors.New("notification event replay conflicts with the original request")
	ErrClaimLost                  = errors.New("notification outbox lease was lost")
	ErrLeaseUnsafe                = errors.New("notification outbox lease has insufficient safety margin")
	ErrInvalidWorker              = errors.New("invalid notification worker")
	ErrSettlementConflict         = errors.New("notification delivery settlement conflict")
	ErrSettlementUnauthenticated  = errors.New("notification delivery settlement unauthenticated")
	ErrSettlementPermissionDenied = errors.New("notification delivery settlement permission denied")
)

const (
	MaxTemplateVariables       = 32
	MaxVariableValueBytes      = 8 * 1024
	MaxContextBytes            = 64 * 1024
	MaxSMSBodySourceBytes      = 8 * 1024
	MaxEmailSubjectSourceBytes = 2 * 1024
	MaxEmailBodySourceBytes    = 128 * 1024
	MaxSMSBodyBytes            = 2 * 1024
	MaxEmailSubjectRunes       = 200
	MaxEmailBodyBytes          = 64 * 1024
)

type Channel string

const (
	ChannelSMS   Channel = "sms"
	ChannelEmail Channel = "email"
)

const (
	EventTypeAccountRecovery                 = "identity.account_recovery"
	EventTypeAccountRegistrationVerification = "identity.account_registration_verification"
	EventTypeAccountLoginVerification        = "identity.account_login_verification"
	EventTypeAccountRegistrationSuccess      = "identity.account_registration_success"

	// Platform operations alerts, delivered to platform members (FX33).
	EventTypeNodeOffline   = "node.availability.offline"
	EventTypeNodeRecovered = "node.availability.recovered"
	// A node held / released by bandwidth auto-disable (NODE-N03, migration
	// 558), to nodes.manage holders.
	EventTypeNodeBandwidthExceeded  = "node.bandwidth.exceeded"
	EventTypeNodeBandwidthRecovered = "node.bandwidth.recovered"
	// A line group address family starts / stops publishing standby IPs
	// (migration 571), to nodes.manage holders.
	EventTypeLineBackupActivated = "node.line_group.backup_ip_activated"
	EventTypeLineBackupRestored  = "node.line_group.primary_ip_restored"
	// ACME HTTP-01 epoch membership drift (ADR-0003), to node managers.
	EventTypeACMEHTTP01EpochDrift = "acme.http01.epoch_drift"
	// Aggregated edge scheduling alerts needing a decision (ae-fixed,
	// migration 416), to edge.aggregated.manage holders.
	EventTypeAggregatedEdgeScheduleAlert = "aggregated_edge.schedule.alert"
	// Node kernel bans made by the node itself (DDoS rate / empty connection
	// bans, L4 guard bans; migration 421), to nodes.manage
	// holders.
	EventTypeNodeSecurityEvent = "node.security.event"
	// WAF automatic bans folded into the ban list (同 IP 超阈值自动拉黑;
	// migration 448), to nodes.manage holders.
	EventTypeNodeSecurityWAFBan = "node.security.waf_ban"
	// A node's security ban / site drop list was cut to the contract limit
	// before signing (migration 461), to nodes.manage holders.
	EventTypeNodeSecurityListTruncated = "node.security.list_truncated"
	// 530: a node permanently refused an installation ban
	// revision (internal/installationban rejected_alert.go).
	EventTypeInstallationBanRejected = "installation_ban.rejected"
	// 555: the node install trust could not be checked or
	// republished for 3 consecutive checks (internal/nativebackup
	// nodeinstalltrust_alert.go), to nodes.manage holders.
	EventTypeNodeInstallTrustFailed = "node.install_trust.failed"
	// dnspup probe source paused (module.probe.dnspup, migration 427), to
	// system.probe_dnspup.manage holders.
	EventTypeProbeDNSPupDegraded = "probe.dnspup.degraded"
	// dnspup node availability probing (migration 460):
	// node verdicts to nodes.manage holders, balance to
	// system.probe_dnspup.manage holders.
	EventTypeNodeDNSPupUnreachable       = "node.dnspup.unreachable"
	EventTypeNodeDNSPupRecovered         = "node.dnspup.recovered"
	EventTypeProbeDNSPupBalanceLow       = "probe.dnspup.balance_low"
	EventTypeProbeDNSPupBalanceExhausted = "probe.dnspup.balance_exhausted"
	// Expired node certificate recovered with the node's own key (ADR 0013
	// GW-02, migration 432), to nodes.manage holders.
	EventTypeNodeCertificateRecovered = "node.certificate.recovered"
)

// MarketEventTypes are the node market notices (ADR 0012 §8, ML-10,
// migration 431), same names as libs/marketproto/notice kinds, delivered to
// platform members holding marketplace.purchase or marketplace.sell.
var MarketEventTypes = []string{
	"market.limit.warn80", "market.limit.warn95", "market.limit.reached", "market.limit.recovered",
	"market.prepaid.low", "market.prepaid.exhausted", "market.prepaid.restored",
	"market.overdraft.warn", "market.overdraft.capped",
	"market.node.overloaded", "market.node.recovered", "market.supply.all_overloaded",
	"market.plugin.unavailable", "market.plugin.restored",
	// migration 438 (ML-20).
	"market.downstream.attacked",
	// 439 (ML-17): stop complaint outcomes.
	"market.complaint.resolved", "market.complaint.actioned",
	// ADR 0012 §19.3/§19.4 (ML-23/24, migration 440).
	"market.node.action", "market.site.paused", "market.site.resumed",
	// ADR 0012 §21.3/§23.2 (ML-27, migration 441).
	"market.commission.low", "market.commission.exhausted", "market.commission.restored",
	// Zero online available nodes (ADR 0012 §24, ML-31, migration 442).
	"market.supply.outage", "market.supply.restored", "market.supply.cancel_available",
	// 565: a subscription receipt the reconciler gave up on.
	"market.supply.receipt_unconfirmed",
	// 590: an applied leaf whose nodes did not take the revision.
	"market.supply.node_delivery_failed",
	"market.terms.changed", // migration 443
	// 444: direct top-ups (ADR 0015).
	"market.direct_topup.paid", "market.direct_topup.received",
	// 445: anti-abscond seller deposit (ADR 0015 §11).
	"market.seller.deposit_mode", "market.seller.deposit_shortfall", "market.seller.default_compensated", "market.seller.defaulted",
	// 488: renewal stop / resume (MKT-RENEW-FROZEN).
	"market.renewal.stopped", "market.renewal.resumed",
	"market.renewal.compensated", // 558
	// 555 (u4d, C22): subscription feedback tickets.
	"market.feedback.opened", "market.feedback.updated",
	"market.plugin.promo_charge", // 579: 限免转按月收费提醒
}

// TicketInboxEventTypes (546) are the ticket events whose
// in-app copy the member chooses per event (notification_subscriptions
// .inbox_enabled, default on); the tenant ones go to the customer's message
// center, the staff ones to the administrator's.
var TicketInboxEventTypes = []string{"ticket.created", "ticket.replied", "ticket.status_changed",
	"ticket.staff.created", "ticket.staff.replied", "ticket.staff.overdue"}

// InboxEventType reports whether a tenant event gets an in-app copy.
// DefaultChannels is a member's SMS/email choice for an event they never set
// (the account subscription page defaults
// every reminder on). A supported tenant event defaults to both channels;
// platform-side events keep the event policy defaults (316). The platform's
// channel and per-event switches still gate delivery (enqueueTx).
func DefaultChannels(eventType string, supported, defaultSMS, defaultEmail bool) (sms, email bool) {
	if PlatformEventType(eventType) {
		return defaultSMS, defaultEmail
	}
	return supported, supported
}

func InboxEventType(eventType string) bool {
	// Community edition: only the tenant ticket events (attack escalation's
	// in-app notices, N23, are removed with the feature).
	return slices.Contains(TicketInboxEventTypes[:3], eventType)
}

// inboxCopy decides the in-app copy of an event enqueued for a member of a
// platform (or tenant) scope: platform operations events land in the
// administrator message center, InboxEventType events in the tenant's;
// ticket events only while the member keeps the in-app choice.
func inboxCopy(platformScope bool, eventType string, inbox bool) bool {
	if platformScope != PlatformEventType(eventType) || (!platformScope && !InboxEventType(eventType)) {
		return false
	}
	return inbox || !slices.Contains(TicketInboxEventTypes, eventType)
}

// PlatformEventType reports whether eventType may be enqueued for a member of
// the platform scope. Every other event stays tenant-only.
func PlatformEventType(eventType string) bool {
	return eventType == EventTypeNodeOffline || eventType == EventTypeNodeRecovered ||
		eventType == EventTypeNodeBandwidthExceeded || eventType == EventTypeNodeBandwidthRecovered ||
		eventType == EventTypeLineBackupActivated || eventType == EventTypeLineBackupRestored ||
		eventType == EventTypeACMEHTTP01EpochDrift ||
		eventType == EventTypeAggregatedEdgeScheduleAlert || eventType == EventTypeNodeSecurityEvent ||
		eventType == EventTypeNodeSecurityWAFBan || eventType == EventTypeNodeSecurityListTruncated ||
		eventType == EventTypeInstallationBanRejected || eventType == EventTypeNodeInstallTrustFailed ||
		eventType == EventTypeProbeDNSPupDegraded || eventType == EventTypeNodeCertificateRecovered ||
		eventType == EventTypeNodeDNSPupUnreachable || eventType == EventTypeNodeDNSPupRecovered ||
		eventType == EventTypeProbeDNSPupBalanceLow || eventType == EventTypeProbeDNSPupBalanceExhausted ||
		eventType == "ticket.staff.created" || eventType == "ticket.staff.replied" ||
		eventType == "ticket.staff.overdue" ||
		slices.Contains(MarketEventTypes, eventType)
}

type TemplateRef struct {
	ID      string
	Version uint64
	Channel Channel
}

type TemplateDefinition struct {
	Ref       TemplateRef
	Subject   string
	Body      string
	Variables []string
}

type ContextValue struct {
	value     string
	sensitive bool
}

func PublicValue(value string) ContextValue {
	return ContextValue{value: value}
}

func SensitiveValue(value string) ContextValue {
	return ContextValue{value: value, sensitive: true}
}

type TemplateContext map[string]ContextValue

type contextValidationPolicyKind uint8

const contextValidationAnnouncementPublishedEmail contextValidationPolicyKind = 1

type ContextValidationPolicy struct {
	kind     contextValidationPolicyKind
	template TemplateRef
}

type RenderedMessage struct {
	Ref     TemplateRef
	Subject string
	Body    string
}

type ChannelSwitches struct {
	SMS   bool
	Email bool
}

type Subscription struct {
	SMS   bool
	Email bool
	// Inbox (546): the member keeps the in-app copy of a ticket event.
	Inbox bool
}

type DeliveryRuntimePolicy struct {
	Enabled       bool
	SMSEnabled    bool
	EmailEnabled  bool
	RepeatCount   int
	IntervalHours int
	WindowMode    string
	WindowStart   int
	WindowEnd     int
	Timezone      string
}

type DeliveryPolicy string

const (
	DeliveryTenantSubscribed DeliveryPolicy = "tenant_subscribed"
	DeliverySystemRequired   DeliveryPolicy = "system_required"
)

type EventIdentity struct {
	TenantID    string
	RecipientID string
	EventID     string
	EventType   string
}

type PlanRequest struct {
	Identity                  EventIdentity
	Policy                    DeliveryPolicy
	Switches                  ChannelSwitches
	Subscription              Subscription
	Templates                 map[Channel]TemplateRef
	Contexts                  map[Channel]TemplateContext
	ContextValidationPolicies map[Channel]ContextValidationPolicy
}

type Delivery struct {
	Channel  Channel
	Template TemplateRef
	Subject  string
	Body     string
	DedupKey string
}

type Plan struct {
	CreatedAt  time.Time
	Deliveries []Delivery
}

type EnqueueRequest struct {
	ScopeID                   uuid.UUID
	RecipientID               uuid.UUID
	SourceEventID             string
	EventType                 string
	Policy                    DeliveryPolicy
	Templates                 map[Channel]TemplateRef
	Contexts                  map[Channel]TemplateContext
	ContextValidationPolicies map[Channel]ContextValidationPolicy
	ActorUserID               *uuid.UUID
	AuditRequestID            string
	// SubjectSiteID / SubjectPackageID record the site or user package the
	// event was raised for (SEC-ACCOUNT-07, migration 502). They are facts at
	// event time and are kept after the resource is deleted.
	SubjectSiteID    *uuid.UUID
	SubjectPackageID *uuid.UUID
}

type DispatchEnqueueRequest struct {
	ScopeID                    uuid.UUID
	SourceEventID              string
	AnonymousDispatchReference uuid.UUID
	EventType                  string
	SelectedChannel            Channel
	Templates                  map[Channel]TemplateRef
	AuditRequestID             string
}

type EnqueuedDelivery struct {
	OutboxID uuid.UUID
	Channel  Channel
	DedupKey string
	Status   string
}

type EnqueueResult struct {
	EventID    uuid.UUID
	CreatedAt  time.Time
	Deliveries []EnqueuedDelivery
	Replayed   bool
}

const (
	OutboxPending         = "pending"
	OutboxLeased          = "leased"
	OutboxSucceeded       = "succeeded"
	OutboxAccepted        = "accepted"
	OutboxUnknown         = "unknown"
	OutboxCancelled       = "cancelled"
	OutboxPermanentFailed = "permanent_failed"
	OutboxExhausted       = "exhausted"
)

type DeliveryAttempt struct {
	OutboxID       uuid.UUID
	ScopeID        uuid.UUID
	EventID        uuid.UUID
	RecipientID    uuid.UUID
	EventType      string
	SourceEventID  string
	Channel        Channel
	Template       TemplateRef
	Subject        string
	Body           string
	DedupKey       string
	AttemptNumber  int
	LeaseToken     uuid.UUID
	LeaseExpiresAt time.Time
	// Params are the public SMS template variables for template-based providers.
	Params map[string]string
}

type AnonymousDeliveryAttempt struct {
	OutboxID                   uuid.UUID
	ScopeID                    uuid.UUID
	EventID                    uuid.UUID
	AnonymousDispatchReference uuid.UUID
	EventType                  string
	SourceEventID              string
	Channel                    Channel
	Template                   TemplateRef
	Subject                    string
	Body                       string
	DedupKey                   string
	AttemptNumber              int
	LeaseToken                 uuid.UUID
	LeaseExpiresAt             time.Time
}

type notificationRecipient interface {
	notificationRecipient()
}

type memberRecipient struct {
	userID uuid.UUID
}

func (memberRecipient) notificationRecipient() {}

type anonymousRecipient struct {
	reference uuid.UUID
}

func (anonymousRecipient) notificationRecipient() {}

type claimedDelivery struct {
	OutboxID       uuid.UUID
	ScopeID        uuid.UUID
	EventID        uuid.UUID
	Recipient      notificationRecipient
	EventType      string
	SourceEventID  string
	Channel        Channel
	Template       TemplateRef
	Subject        string
	Body           string
	DedupKey       string
	AttemptNumber  int
	LeaseToken     uuid.UUID
	LeaseExpiresAt time.Time
	// Params are the SMS template variables (nil for email and legacy rows).
	Params map[string]string
}

type SendDisposition string

const (
	SendDelivered SendDisposition = "delivered"
	SendAccepted  SendDisposition = "accepted"
	SendUnknown   SendDisposition = "unknown"
)

type SendResult struct {
	Disposition        SendDisposition
	Provider           string
	ProviderDeliveryID string
	Failure            *Failure
	Observation        *DispatchObservation
}

type Sender interface {
	Send(context.Context, DeliveryAttempt) SendResult
}

type AnonymousDispatchDisposition string

const (
	AnonymousDispatchDelivered AnonymousDispatchDisposition = "delivered"
	AnonymousDispatchAccepted  AnonymousDispatchDisposition = "accepted"
	AnonymousDispatchUnknown   AnonymousDispatchDisposition = "unknown"
	AnonymousDispatchNoopACK   AnonymousDispatchDisposition = "noop_ack"
)

type AnonymousDispatchResult struct {
	Disposition        AnonymousDispatchDisposition
	Provider           string
	ProviderDeliveryID string
	Failure            *Failure
	Observation        *DispatchObservation
}

type AnonymousDispatcher interface {
	Dispatch(context.Context, AnonymousDeliveryAttempt) AnonymousDispatchResult
}

type WorkerConfig struct {
	BatchSize         int
	LeaseDuration     time.Duration
	LeaseSafetyMargin time.Duration
	MaxAttempts       int
	BaseDelay         time.Duration
	MaxDelay          time.Duration
}

func DefaultWorkerConfig() WorkerConfig {
	return WorkerConfig{
		BatchSize: 64, LeaseDuration: 30 * time.Second, LeaseSafetyMargin: time.Second, MaxAttempts: 5,
		BaseDelay: time.Second, MaxDelay: 5 * time.Minute,
	}
}

type WorkerBatchResult struct {
	Claimed          int
	Succeeded        int
	Accepted         int
	Unknown          int
	NoopAcknowledged int
	RetryScheduled   int
	PermanentFailed  int
	Exhausted        int
	// Withdrawn counts scheduled repeats cancelled because their source
	// condition no longer holds (see ReplayGuard).
	Withdrawn int
}

type Clock func() time.Time

type FailureClass string

const (
	FailureTemporary FailureClass = "temporary"
	FailurePermanent FailureClass = "permanent"
)

type Failure struct {
	Class      FailureClass
	Code       string
	RetryAfter time.Duration
}

type RetryAction string

const (
	RetryScheduled RetryAction = "scheduled"
	RetryStopped   RetryAction = "stopped"
	RetryExhausted RetryAction = "exhausted"
)

type RetryDecision struct {
	Action      RetryAction
	FailureCode string
	NextAttempt int
	Delay       time.Duration
	RetryAt     time.Time
}
