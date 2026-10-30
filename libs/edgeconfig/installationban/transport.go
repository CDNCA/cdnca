// Package installationban names the NATS transport of InstallationBanCommand
// and InstallationBanReceipt (ADR 0014 LIC-BAN-05) shared by control-api and
// agent-gateway.
package installationban

const (
	CommandStream        = "INSTALLATION_BAN_COMMANDS"
	StatusStream         = "INSTALLATION_BAN_STATUS"
	CommandSubjectPrefix = "cdnca.agent.installation-ban.commands"
	StatusSubjectPrefix  = "cdnca.agent.installation-ban.status"
	// GatewayConsumerPrefix names the gateway's durable per-node command
	// consumer; ReceiptConsumer is control-api's.
	GatewayConsumerPrefix = "installation_ban"
	ReceiptConsumer       = "control_api_installation_ban_receipts"
	// APIVersion is the CAPABILITY_NAME_INSTALLATION_BAN_TICKET version.
	APIVersion = 1
	// MaxDocumentBytes equals libs/entitlement/installationban.MaxDocumentBytes.
	MaxDocumentBytes = 16 << 10
	// MaxCarrierBytes bounds one command or receipt protobuf message.
	MaxCarrierBytes = 2*MaxDocumentBytes + 4<<10
	MaxReasonBytes  = 256
)

// Node status values of InstallationBanReceipt.status.
var Statuses = map[string]bool{"serving": true, "banned": true, "service_ticket_expired": true, "no_ticket": true}

// Reasons of an InstallationBanReceipt with applied false (edge-agent
// internal/installationban.Runtime.Apply sets them; control-api classifies them).
const (
	ReasonInvalid      = "invalid_document"
	ReasonUntrusted    = "untrusted_signature"
	ReasonInstallation = "installation_mismatch"
	ReasonStale        = "stale_revision"
	ReasonConflict     = "revision_conflict"
	ReasonExpired      = "ticket_expired"
	ReasonPersistence  = "persistence_failed"
	ReasonEnforce      = "enforce_failed"
)

// permanentReasons are refusals the same command bytes always get again: the
// documents themselves are malformed, for another installation, older than or
// conflicting with what the node keeps, or an already ended ticket. Only a new
// revision can change them. Every other reason (the node could not write its
// state, could not stop/resume serving, does not yet hold the installation-ban
// key that a later signer trust push brings, or a reason this version does not
// know) may pass when the same revision is delivered again.
var permanentReasons = map[string]bool{ReasonInvalid: true, ReasonInstallation: true, ReasonStale: true,
	ReasonConflict: true, ReasonExpired: true}

// PermanentReason reports whether a refusal must not be retried with the same revision.
func PermanentReason(reason string) bool { return permanentReasons[reason] }
