// Package notice is a market notification to one member controller (ADR 0012
// §8). The market writes it into the member's relay inbox (operation
// market.notice) and signs it with the market key when the member pulls it;
// the controller verifies it with the same key ring as member cards and turns
// it into a notification center event of the same name.
package notice

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	SchemaV1  = "cdnca.market.notice/v1"
	Domain    = SchemaV1 + "\n"
	Operation = "market.notice"
)

// Kinds, also the notification center event types.
const (
	KindLimitWarn80       = "market.limit.warn80"
	KindLimitWarn95       = "market.limit.warn95"
	KindLimitReached      = "market.limit.reached"
	KindLimitRecovered    = "market.limit.recovered"
	KindPrepaidLow        = "market.prepaid.low"
	KindPrepaidExhausted  = "market.prepaid.exhausted"
	KindPrepaidRestored   = "market.prepaid.restored"
	KindOverdraftWarn     = "market.overdraft.warn"
	KindOverdraftCapped   = "market.overdraft.capped"
	KindNodeOverloaded    = "market.node.overloaded"
	KindNodeRecovered     = "market.node.recovered"
	KindAllOverloaded     = "market.supply.all_overloaded"
	KindPluginUnavailable = "market.plugin.unavailable"
	KindPluginRestored    = "market.plugin.restored"
	// KindDownstreamAttacked tells a reseller on the path that a site further
	// down was attacked (ADR 0012 §19.1, ML-20): only the downstream number
	// and the window, never the site or the root subscriber.
	KindDownstreamAttacked = "market.downstream.attacked"
	// Stop complaints (ADR 0012 §18.3, ML-17): the filer learns only the outcome and
	// its own target_ref (U5); the root buyer and the hops between get "actioned".
	KindComplaintResolved = "market.complaint.resolved"
	KindComplaintActioned = "market.complaint.actioned"
	// ADR 0012 §19.3/§19.4 (ML-23/ML-24).
	KindNodeAction  = "market.node.action"
	KindSitePaused  = "market.site.paused"
	KindSiteResumed = "market.site.resumed"
	// Direct commission prepaid (ADR 0012 §21.3/§23.2, ML-27): to every
	// controller of the seller customer; values currency / observed (balance)
	// / cap (alert line), all in minor units.
	KindCommissionLow       = "market.commission.low"
	KindCommissionExhausted = "market.commission.exhausted"
	KindCommissionRestored  = "market.commission.restored"
	// Direct top-ups (ADR 0015): the buyer's balance with a seller was
	// credited from a payment into the seller's own merchant account.
	KindDirectTopupPaid     = "market.direct_topup.paid"     // to the buyer
	KindDirectTopupReceived = "market.direct_topup.received" // to the seller
	// Zero online available nodes (ADR 0012 §24, ML-31).
	KindSupplyOutage          = "market.supply.outage"
	KindSupplyRestored        = "market.supply.restored"
	KindSupplyCancelAvailable = "market.supply.cancel_available"
	// KindTermsChanged tells a buyer, before the renewal, that the seller
	// changed the offer: stage stricter (price up or limits tightened, the
	// same thing for the renewal condition), looser or mixed; action renew
	// or close is what its renewal condition will do.
	KindTermsChanged = "market.terms.changed"
	// Anti-abscond deposit (ADR 0015 §11).
	KindSellerDepositMode        = "market.seller.deposit_mode"        // to the seller: operator set its mode (action)
	KindSellerDepositShortfall   = "market.seller.deposit_shortfall"   // to the seller: deposit below required
	KindSellerDefaultCompensated = "market.seller.default_compensated" // to the buyer: paid from the deposit
	KindSellerDefaulted          = "market.seller.defaulted"           // to the seller: judged absconded
	// Renewal stop (MKT-RENEW-FROZEN, market 058), to both parties: an active
	// subscription stopped renewing future periods because a party was frozen,
	// the upstream path was lost or it has no active grant (action is the
	// reason slug), and resumed once the reason cleared.
	KindRenewalStopped = "market.renewal.stopped"
	KindRenewalResumed = "market.renewal.resumed"
	// KindRenewalCompensated (fix-nm03, upstream-pause/v1): an upstream
	// commercial pause of every supply ended; action extended (observed =
	// seconds added, at = new paid_through) or refunded (observed = minor
	// units in currency, the subscription closed during the pause).
	KindRenewalCompensated = "market.renewal.compensated"
	// Subscription feedback tickets (u4d, C22): KindFeedbackOpened tells the
	// seller a buyer reported a fault on its subscription; KindFeedbackUpdated
	// tells the other party of a reply or state change (action says which).
	KindFeedbackOpened  = "market.feedback.opened"
	KindFeedbackUpdated = "market.feedback.updated"
	// KindPluginPromoCharge tells a plugin buyer that its 限免 (free-for-a-limited-time) licence turns
	// into a monthly subscription: stage d7 / d1 before the first charge at "at" (fix-plugpromo).
	KindPluginPromoCharge = "market.plugin.promo_charge"
)

// Kinds lists every kind this version understands, in display order.
var Kinds = []string{
	KindLimitWarn80, KindLimitWarn95, KindLimitReached, KindLimitRecovered,
	KindPrepaidLow, KindPrepaidExhausted, KindPrepaidRestored, KindOverdraftWarn, KindOverdraftCapped,
	KindNodeOverloaded, KindNodeRecovered, KindAllOverloaded, KindPluginUnavailable, KindPluginRestored,
	KindDownstreamAttacked,
	KindComplaintResolved, KindComplaintActioned,
	KindNodeAction, KindSitePaused, KindSiteResumed,
	KindCommissionLow, KindCommissionExhausted, KindCommissionRestored,
	KindSupplyOutage, KindSupplyRestored, KindSupplyCancelAvailable,
	KindTermsChanged,
	KindDirectTopupPaid, KindDirectTopupReceived,
	KindSellerDepositMode, KindSellerDepositShortfall, KindSellerDefaultCompensated, KindSellerDefaulted,
	KindRenewalStopped, KindRenewalResumed, KindRenewalCompensated,
	KindFeedbackOpened, KindFeedbackUpdated,
	KindPluginPromoCharge,
}

// Recipient roles: the buyer or the seller of the notice's subscription (the
// leaf supplier for node notices).
const (
	RoleBuyer  = "buyer"
	RoleSeller = "seller"
)

// Value keys. Every value is public display data (no secrets, no peer
// identities beyond what the recipient already sees on its own subscription).
const (
	ValueOffer        = "offer"        // offer name
	ValueSubscription = "subscription" // the recipient's own subscription ID
	ValueMetric       = "metric"       // spec.Metric or "" (prepaid, node, plugin)
	ValueObserved     = "observed"     // integer, metric unit or minor currency units
	ValueCap          = "cap"          // integer, same unit
	ValueAction       = "action"       // throttle / pause / stop; renew / close (terms changed)
	ValueCurrency     = "currency"     // ISO 4217 for amounts
	ValueNode         = "node"         // leaf node ID (node notices)
	ValuePool         = "pool"         // node pool reference
	ValuePlugins      = "plugins"      // comma separated plugin codes
	ValueThreshold    = "threshold"    // node load thresholds "cpu/memory" percent
	ValueDownstream   = "downstream"   // grant downstream_ref (opaque per root and leaf; suppliers instead of the owner)
	ValueWindowStart  = "window_start" // unix seconds of a 5-minute window
	ValueComplaint    = "complaint"    // stop complaint ID
	ValueTarget       = "target"       // the filer's own target_ref (subscription ID or downstream_ref)
	ValueCategory     = "category"     // complaint category
	ValueOutcome      = "outcome"      // rejected / warn / pause / stop / blacklist_domain / released
	ValueDomain       = "domain"       // blacklisted domain
	// Whole-node actions (§19.3): where the node is and what it did; never
	// the attacked site, a client address or other subscribers.
	ValueRegion  = "region"  // node region
	ValueCarrier = "carrier" // node carrier
	ValueSource  = "source"  // autodefense / ddos / l4guard / xdp
	ValueEvent   = "event"   // action kind slug (autodefense contract §5)
	ValueAt      = "at"      // RFC 3339 time of the first action
	// Same-site pause (§19.4).
	ValueSite  = "site"  // leaf site ID
	ValueCount = "count" // whole-node actions in the 24 hour window
	ValuePeer  = "peer"  // the other party's market display name (direct top-ups)
	ValueTopup = "topup" // direct top-up ID
	// Feedback tickets: the ticket ID (action is reply / in_progress / resolved /
	// closed / reopened / escalated; category is the ticket category).
	ValueFeedback = "feedback"
)

var valueKeys = []string{ValueOffer, ValueSubscription, ValueMetric, ValueObserved, ValueCap, ValueAction,
	ValueCurrency, ValueNode, ValuePool, ValuePlugins, ValueThreshold, ValueDownstream, ValueWindowStart,
	ValueComplaint, ValueTarget, ValueCategory, ValueOutcome, ValueDomain,
	ValueRegion, ValueCarrier, ValueSource, ValueEvent, ValueAt, ValueSite, ValueCount, ValuePeer, ValueTopup, ValueFeedback}

// ValueKeys returns the value keys in a fixed order.
func ValueKeys() []string { return slices.Clone(valueKeys) }

const maxValueRunes = 256

var (
	ErrInvalid    = errors.New("invalid market notice")
	ErrUnknownKey = errors.New("market notice signing key unknown")
	ErrSignature  = errors.New("market notice signature rejected")
)

type Notice struct {
	Schema         string            `json:"schema"`
	ID             uuid.UUID         `json:"id"`
	MemberID       uuid.UUID         `json:"member_id"`
	SubscriptionID *uuid.UUID        `json:"subscription_id,omitempty"`
	Role           string            `json:"role"`
	Kind           string            `json:"kind"`
	Stage          string            `json:"stage"`
	PeriodKey      string            `json:"period_key"`
	Values         map[string]string `json:"values"`
	CreatedAt      int64             `json:"created_at"`
}

// Validate checks the shape. An unknown kind is invalid: a controller older
// than the market drops it instead of showing an unnamed event.
func (n Notice) Validate() error {
	if n.Schema != SchemaV1 || n.ID == uuid.Nil || n.MemberID == uuid.Nil || n.CreatedAt <= 0 ||
		(n.Role != RoleBuyer && n.Role != RoleSeller) || !slices.Contains(Kinds, n.Kind) ||
		len(n.Stage) > 32 || n.PeriodKey == "" || len(n.PeriodKey) > 128 ||
		(n.SubscriptionID != nil && *n.SubscriptionID == uuid.Nil) {
		return ErrInvalid
	}
	for key, value := range n.Values {
		if !slices.Contains(valueKeys, key) || !utf8.ValidString(value) || utf8.RuneCountInString(value) > maxValueRunes {
			return ErrInvalid
		}
	}
	return nil
}

func (n Notice) Time() time.Time { return time.Unix(n.CreatedAt, 0).UTC() }

type Signed struct {
	KeyID     string `json:"key_id"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

func Sign(n Notice, keyID string, key ed25519.PrivateKey) (Signed, error) {
	if err := n.Validate(); err != nil {
		return Signed{}, err
	}
	if keyID == "" || len(key) != ed25519.PrivateKeySize {
		return Signed{}, ErrInvalid
	}
	payload, err := json.Marshal(n)
	if err != nil {
		return Signed{}, err
	}
	return Signed{KeyID: keyID, Payload: base64.StdEncoding.EncodeToString(payload),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, append([]byte(Domain), payload...)))}, nil
}

// Verify checks the market signature and the shape, and that the notice is
// addressed to self.
func Verify(keys map[string]ed25519.PublicKey, s Signed, self uuid.UUID) (Notice, error) {
	public, ok := keys[s.KeyID]
	if !ok || len(public) != ed25519.PublicKeySize {
		return Notice{}, ErrUnknownKey
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(s.Payload)
	if err != nil {
		return Notice{}, ErrInvalid
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(s.Signature)
	if err != nil || !ed25519.Verify(public, append([]byte(Domain), payload...), signature) {
		return Notice{}, ErrSignature
	}
	var n Notice
	if err := json.Unmarshal(payload, &n); err != nil {
		return Notice{}, ErrInvalid
	}
	if err := n.Validate(); err != nil {
		return Notice{}, err
	}
	if n.MemberID != self {
		return Notice{}, ErrInvalid
	}
	return n, nil
}
