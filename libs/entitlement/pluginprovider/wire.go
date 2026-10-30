package pluginprovider

// Request and response payloads of cdnca.provider/v1. Every request body is
// a JSON object with "protocol" and "sandbox" plus the action fields below;
// write actions carry an idempotency_key: a repeated key must return the
// first result and must not apply the write twice.
//
// sandbox=true is set by the control plane's installation contract runner:
// the plugin must answer from its own test data (a sandbox zone, no real
// SMS, a fixed ICP answer) and must never touch a customer's account.

// RequestHeader is embedded in every request body.
type RequestHeader struct {
	Protocol string `json:"protocol"`
	Sandbox  bool   `json:"sandbox"`
}

// DNS -------------------------------------------------------------------

// DNSRecord is one record. Name is the fully qualified owner without the
// trailing dot; Line is a unified line name (默认/电信/联通/移动/境外).
type DNSRecord struct {
	ID    string `json:"id,omitempty"`
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl"`
	Line  string `json:"line,omitempty"`
}

type DNSListRequest struct {
	RequestHeader
	Zone string `json:"zone"`
	Name string `json:"name,omitempty"`
}

type DNSListResponse struct {
	Records []DNSRecord `json:"records"`
}

type DNSWriteRequest struct {
	RequestHeader
	Zone           string    `json:"zone"`
	Record         DNSRecord `json:"record"`
	IdempotencyKey string    `json:"idempotency_key"`
}

type DNSCreateResponse struct {
	ID string `json:"id"`
}

type DNSDeleteRequest struct {
	RequestHeader
	Zone           string `json:"zone"`
	ID             string `json:"id"`
	IdempotencyKey string `json:"idempotency_key"`
}

// SandboxZone is the zone a DNS plugin serves in sandbox mode.
const SandboxZone = "contract.cdnca-sandbox.test"

// SMS -------------------------------------------------------------------

type SMSSendRequest struct {
	RequestHeader
	// To is an E.164 number.
	To         string            `json:"to"`
	TemplateID string            `json:"template_id,omitempty"`
	Params     map[string]string `json:"params,omitempty"`
	Body       string            `json:"body"`
	// IdempotencyKey: a repeat returns the first delivery_id, sends nothing.
	IdempotencyKey string `json:"idempotency_key"`
}

type SMSSendResponse struct {
	DeliveryID string `json:"delivery_id"`
}

// SandboxPhone is the number a sandbox send targets (never delivered).
const SandboxPhone = "+8613800000000"

// Mail ------------------------------------------------------------------

// MailSendRequest is one message to one recipient. From is the plugin's own
// configured sender (the control plane never chooses it). Text is always
// present; HTML is an optional alternative of the same content.
type MailSendRequest struct {
	RequestHeader
	// To is one address (RFC 5321 mailbox, no display name).
	To      string `json:"to"`
	Subject string `json:"subject"`
	Text    string `json:"text"`
	HTML    string `json:"html,omitempty"`
	ReplyTo string `json:"reply_to,omitempty"`
	// IdempotencyKey: a repeat returns the first message_id, sends nothing.
	IdempotencyKey string `json:"idempotency_key"`
}

type MailSendResponse struct {
	MessageID string `json:"message_id"`
}

// SandboxMailbox is the address a sandbox send targets (never delivered).
const SandboxMailbox = "contract@cdnca-sandbox.test"

// ICP -------------------------------------------------------------------

type ICPQueryRequest struct {
	RequestHeader
	// Domain is a registrable domain (lowercase, punycode).
	Domain string `json:"domain"`
}

const (
	ICPFiled   = "filed"
	ICPUnfiled = "unfiled"
)

type ICPQueryResponse struct {
	Status  string `json:"status"`
	Licence string `json:"licence,omitempty"`
	Subject string `json:"subject,omitempty"`
}

// Sandbox ICP answers: SandboxFiledDomain is filed, SandboxUnfiledDomain is not.
const (
	SandboxFiledDomain   = "filed.cdnca-sandbox.test"
	SandboxUnfiledDomain = "unfiled.cdnca-sandbox.test"
)
