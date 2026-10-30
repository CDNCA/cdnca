package marketruntime

import (
	"context"
	"fmt"

	"github.com/cdnca/cdnca/libs/marketproto/notice"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Market notices (ADR 0012 §8, ML-10, migration 431). The market signs
// each notice for this member (marketclient.Receive verifies it); the
// controller turns it into the notification center event of the same name for
// the platform members who act for this installation on the market: buyer
// notices to marketplace.purchase holders, seller notices to
// marketplace.sell holders. Members choose channels per event
// (tenant_subscribed); the notice ID is the source event, so a redelivered
// notice is enqueued once.

const noticeTemplateVersion = 1

// noticeTemplateVersions overrides noticeTemplateVersion per kind: migration
// 558 added v2 renewal stop/resume templates explaining the
// upstream_paused reason.
var noticeTemplateVersions = map[string]uint64{
	notice.KindRenewalStopped: 2,
	notice.KindRenewalResumed: 2,
}

func noticeTemplateVersionOf(kind string) uint64 {
	if v, ok := noticeTemplateVersions[kind]; ok {
		return v
	}
	return noticeTemplateVersion
}

var noticePermission = map[string]string{
	notice.RoleBuyer:  "marketplace.purchase",
	notice.RoleSeller: "marketplace.sell",
}

// NoticeEnqueuer is notification.Store's transactional enqueue.
type NoticeEnqueuer interface {
	EnqueueTx(context.Context, pgx.Tx, notification.EnqueueRequest) (notification.EnqueueResult, error)
}

// WithNotices turns relayed market notices into notification center events.
// Without it notices are acknowledged and dropped.
func (r *Runtime) WithNotices(enqueuer NoticeEnqueuer) *Runtime {
	r.notices = enqueuer
	return r
}

// noticeVariables: the template variables of each kind (migration 431).
var noticeVariables = map[string][]string{
	notice.KindLimitWarn80:       {notice.ValueOffer, notice.ValueSubscription, notice.ValueMetric, notice.ValueObserved, notice.ValueCap},
	notice.KindLimitWarn95:       {notice.ValueOffer, notice.ValueSubscription, notice.ValueMetric, notice.ValueObserved, notice.ValueCap},
	notice.KindLimitReached:      {notice.ValueOffer, notice.ValueSubscription, notice.ValueMetric, notice.ValueObserved, notice.ValueCap, notice.ValueAction},
	notice.KindLimitRecovered:    {notice.ValueOffer, notice.ValueSubscription, notice.ValueMetric, notice.ValueAction},
	notice.KindPrepaidLow:        {notice.ValueCurrency, notice.ValueObserved, notice.ValueCap},
	notice.KindPrepaidExhausted:  {notice.ValueOffer, notice.ValueSubscription, notice.ValueAction},
	notice.KindPrepaidRestored:   {notice.ValueOffer, notice.ValueSubscription, notice.ValueAction},
	notice.KindOverdraftWarn:     {notice.ValueOffer, notice.ValueSubscription, notice.ValueCurrency, notice.ValueObserved, notice.ValueCap},
	notice.KindOverdraftCapped:   {notice.ValueOffer, notice.ValueSubscription, notice.ValueObserved, notice.ValueCap, notice.ValueAction},
	notice.KindNodeOverloaded:    {notice.ValueNode, notice.ValuePool, notice.ValueThreshold},
	notice.KindNodeRecovered:     {notice.ValueNode, notice.ValuePool, notice.ValueThreshold},
	notice.KindAllOverloaded:     {notice.ValuePool, notice.ValueThreshold},
	notice.KindPluginUnavailable: {notice.ValueOffer, notice.ValueSubscription, notice.ValuePlugins},
	notice.KindPluginRestored:    {notice.ValueOffer, notice.ValueSubscription, notice.ValuePlugins},
	// migration 438 (ML-20, §18.2 visibility a): the direct seller sees its own
	// subscription, a seller further up only the downstream number.
	notice.KindDownstreamAttacked: {notice.ValueSubscription, notice.ValueDownstream, notice.ValueWindowStart},
	// 439 (ML-17): the filer gets its own target only (U5); actioned also names the recipient's own subscription.
	notice.KindComplaintResolved: {notice.ValueComplaint, notice.ValueTarget, notice.ValueCategory, notice.ValueOutcome, notice.ValueDomain},
	notice.KindComplaintActioned: {notice.ValueComplaint, notice.ValueSubscription, notice.ValueTarget, notice.ValueCategory, notice.ValueOutcome, notice.ValueDomain},
	// Migration 440 (ML-23/24).
	notice.KindNodeAction: {notice.ValueOffer, notice.ValueRegion, notice.ValueCarrier, notice.ValueSource, notice.ValueEvent, notice.ValueAt},
	notice.KindSitePaused: {notice.ValueOffer, notice.ValueSubscription, notice.ValueSite, notice.ValueCount, notice.ValuePool,
		notice.ValueDownstream},
	notice.KindSiteResumed: {notice.ValueOffer, notice.ValueSubscription, notice.ValueSite, notice.ValueCount, notice.ValuePool,
		notice.ValueDownstream},
	// Migration 441 (ML-27): the seller's commission prepaid balance (minor units).
	notice.KindCommissionLow:       {notice.ValueCurrency, notice.ValueObserved, notice.ValueCap},
	notice.KindCommissionExhausted: {notice.ValueCurrency, notice.ValueObserved},
	notice.KindCommissionRestored:  {notice.ValueCurrency, notice.ValueObserved},
	// ADR 0012 §24 (ML-31, migration 442).
	notice.KindSupplyOutage:          {notice.ValueOffer, notice.ValueSubscription},
	notice.KindSupplyRestored:        {notice.ValueOffer, notice.ValueSubscription},
	notice.KindSupplyCancelAvailable: {notice.ValueOffer, notice.ValueSubscription},
	// migration 443 (C7a).
	notice.KindTermsChanged: {notice.ValueOffer, notice.ValueSubscription, notice.ValueAction},
	// 444: direct top-ups.
	notice.KindDirectTopupPaid:     {notice.ValuePeer, notice.ValueTopup, notice.ValueCurrency, notice.ValueObserved},
	notice.KindDirectTopupReceived: {notice.ValuePeer, notice.ValueTopup, notice.ValueCurrency, notice.ValueObserved},
	// 445: anti-abscond seller deposit (ADR 0015 §11).
	notice.KindSellerDepositMode:        {notice.ValueAction},
	notice.KindSellerDepositShortfall:   {notice.ValueCurrency, notice.ValueObserved, notice.ValueCap},
	notice.KindSellerDefaultCompensated: {notice.ValuePeer, notice.ValueCurrency, notice.ValueObserved, notice.ValueCap},
	notice.KindSellerDefaulted:          {notice.ValueCurrency, notice.ValueObserved},
	notice.KindRenewalStopped:           {notice.ValueOffer, notice.ValueSubscription, notice.ValueAction},
	notice.KindRenewalResumed:           {notice.ValueOffer, notice.ValueSubscription, notice.ValueAction},
	notice.KindRenewalCompensated:       {notice.ValueOffer, notice.ValueSubscription, notice.ValueAction, notice.ValueObserved, notice.ValueCurrency, notice.ValueAt}, // 558
	notice.KindFeedbackOpened:           {notice.ValueOffer, notice.ValueSubscription, notice.ValueFeedback, notice.ValueCategory},
	notice.KindFeedbackUpdated:          {notice.ValueOffer, notice.ValueSubscription, notice.ValueFeedback, notice.ValueCategory, notice.ValueAction},
	notice.KindPluginPromoCharge:        {notice.ValuePlugins, notice.ValueAt, notice.ValueObserved, notice.ValueCurrency}, // 579
}

// NoticeContext is the template context of a notice: exactly the kind's
// variables, "-" for a value the market left out.
func NoticeContext(n notice.Notice) (notification.TemplateContext, error) {
	names, ok := noticeVariables[n.Kind]
	if !ok {
		return nil, fmt.Errorf("market notice kind %q has no template", n.Kind)
	}
	values := notification.TemplateContext{}
	for _, name := range names {
		v := n.Values[name]
		if v == "" {
			v = "-"
		}
		values[name] = notification.PublicValue(v)
	}
	return values, nil
}

func enqueueNotice(ctx context.Context, pool *pgxpool.Pool, enqueuer NoticeEnqueuer, n notice.Notice) error {
	values, err := NoticeContext(n)
	if err != nil {
		return err
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var scope uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL`).Scan(&scope); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT membership.user_id FROM memberships membership
		JOIN users member ON member.id=membership.user_id AND member.status='active'
		JOIN role_assignments assignment ON assignment.scope_id=membership.scope_id AND assignment.user_id=membership.user_id
		JOIN role_permissions grant_row ON grant_row.role_id=assignment.role_id AND grant_row.permission_name=$2
		WHERE membership.scope_id=$1 AND membership.status='active' ORDER BY membership.user_id`, scope, noticePermission[n.Role])
	if err != nil {
		return err
	}
	recipients, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return err
	}
	template := n.Kind + ".zh-cn"
	templates := map[notification.Channel]notification.TemplateRef{
		notification.ChannelSMS:   {ID: template, Version: noticeTemplateVersionOf(n.Kind), Channel: notification.ChannelSMS},
		notification.ChannelEmail: {ID: template, Version: noticeTemplateVersionOf(n.Kind), Channel: notification.ChannelEmail},
	}
	source := "market-notice/" + n.ID.String()
	for _, recipient := range recipients {
		if _, err := enqueuer.EnqueueTx(ctx, tx, notification.EnqueueRequest{ScopeID: scope, RecipientID: recipient,
			SourceEventID: source, EventType: n.Kind, Policy: notification.DeliveryTenantSubscribed,
			Templates: templates, AuditRequestID: source,
			Contexts: map[notification.Channel]notification.TemplateContext{notification.ChannelSMS: values, notification.ChannelEmail: values},
		}); err != nil {
			return fmt.Errorf("enqueue market notice %s: %w", n.Kind, err)
		}
	}
	return tx.Commit(ctx)
}
