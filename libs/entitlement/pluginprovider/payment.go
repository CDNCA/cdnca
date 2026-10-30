package pluginprovider

// Payment (PA-23, ADR 0007 §8.2): a third-party collection channel. The
// plugin only reports facts; the control plane binds every fact to its own
// order (order number, merchant, exact integer amount, currency), confirms
// a notified payment by asking the plugin itself (query_payment) before
// crediting, and keeps the state machine, idempotency and reconciliation.
//
// Actions (POST {base_url}/cdnca-provider/v1/payment/{action}):
//
//	create_checkout  start a payment; returns a redirect URL or QR content
//	query_payment    the current state of one order (the confirmation query)
//	verify_callback  verify a gateway notification the control plane received
//	                 at its notify URL (raw bytes forwarded) and return the fact
//	refund           refund part or all of a paid order (idempotent)
//	reconcile        the statement of one UTC day (reconciliation)
//	sandbox_settle   sandbox only: mark a sandbox order paid and return the
//	                 notification the gateway would send, so the contract can
//	                 drive verify_callback with real signed bytes

// Payment statuses (PaymentFact.Status, PaymentRefundResponse.Status).
const (
	PaymentSucceeded = "succeeded"
	PaymentFailed    = "failed"
	PaymentPending   = "pending"
)

// Checkout action kinds.
const (
	PaymentActionRedirect = "redirect"
	PaymentActionQRCode   = "qr_code"
)

// SandboxMerchant is the merchant a payment plugin serves in sandbox mode.
const SandboxMerchant = "cdnca-sandbox-merchant"

type PaymentCheckoutRequest struct {
	RequestHeader
	MerchantID string `json:"merchant_id"`
	// OrderRef is the control plane order number; the plugin must echo it
	// in every fact about this payment.
	OrderRef    string `json:"order_ref"`
	AmountMinor int64  `json:"amount_minor"`
	Currency    string `json:"currency"`
	// Method is what the payer picked (alipay / wxpay).
	Method    string `json:"method"`
	Subject   string `json:"subject"`
	NotifyURL string `json:"notify_url"`
	ReturnURL string `json:"return_url,omitempty"`
	// ExpiresAt is unix seconds.
	ExpiresAt      int64  `json:"expires_at"`
	IdempotencyKey string `json:"idempotency_key"`
}

type PaymentCheckoutResponse struct {
	MerchantID  string `json:"merchant_id"`
	OrderRef    string `json:"order_ref"`
	AmountMinor int64  `json:"amount_minor"`
	Currency    string `json:"currency"`
	Action      string `json:"action"`
	URL         string `json:"url,omitempty"`
	QRContent   string `json:"qr_content,omitempty"`
}

type PaymentQueryRequest struct {
	RequestHeader
	MerchantID        string `json:"merchant_id"`
	OrderRef          string `json:"order_ref"`
	ExternalPaymentID string `json:"external_payment_id,omitempty"`
}

// PaymentFact is the plugin's statement about one payment.
type PaymentFact struct {
	MerchantID        string `json:"merchant_id"`
	OrderRef          string `json:"order_ref"`
	ExternalPaymentID string `json:"external_payment_id,omitempty"`
	Status            string `json:"status"`
	AmountMinor       int64  `json:"amount_minor"`
	Currency          string `json:"currency"`
	// PaidAt is unix seconds (0 when not paid).
	PaidAt int64 `json:"paid_at,omitempty"`
}

// PaymentCallback is a gateway notification as received at the control
// plane notify URL (exact bytes).
type PaymentCallback struct {
	Method      string `json:"method"`
	ContentType string `json:"content_type,omitempty"`
	Query       string `json:"query,omitempty"`
	Body        []byte `json:"body,omitempty"`
}

type PaymentCallbackRequest struct {
	RequestHeader
	MerchantID string          `json:"merchant_id"`
	Callback   PaymentCallback `json:"callback"`
}

type PaymentRefundRequest struct {
	RequestHeader
	MerchantID        string `json:"merchant_id"`
	OrderRef          string `json:"order_ref"`
	ExternalPaymentID string `json:"external_payment_id"`
	// RefundRef is the control plane refund number (idempotent per value).
	RefundRef      string `json:"refund_ref"`
	AmountMinor    int64  `json:"amount_minor"`
	Currency       string `json:"currency"`
	IdempotencyKey string `json:"idempotency_key"`
}

type PaymentRefundResponse struct {
	RefundRef        string `json:"refund_ref"`
	ExternalRefundID string `json:"external_refund_id"`
	Status           string `json:"status"`
	AmountMinor      int64  `json:"amount_minor"`
	Currency         string `json:"currency"`
}

type PaymentReconcileRequest struct {
	RequestHeader
	MerchantID string `json:"merchant_id"`
	// Date is a UTC day, YYYY-MM-DD.
	Date string `json:"date"`
}

type PaymentStatement struct {
	Date    string        `json:"date"`
	Entries []PaymentFact `json:"entries"`
}

type PaymentSettleRequest struct {
	RequestHeader
	MerchantID string `json:"merchant_id"`
	OrderRef   string `json:"order_ref"`
}

type PaymentSettleResponse struct {
	Callback PaymentCallback `json:"callback"`
}
