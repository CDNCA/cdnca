// Package sshaccess is the "only the controller may SSH" carrier contract
// (node-ssh-tab, CAPABILITY_NAME_SSH_ACCESS v1, ConnectResponse 32 /
// ConnectRequest 29) shared by control-api (publishes the wanted state and
// the confirmation), agent-gateway (routes, never interprets the policy)
// and edge-agent (applies with a rollback timer, answers).
package sshaccess

import (
	"regexp"
	"time"
)

const (
	APIVersion = 1

	// OperationApply carries the whole policy of a revision; OperationConfirm
	// keeps the applied revision (the controller reached sshd through it).
	OperationApply   = "apply"
	OperationConfirm = "confirm"

	// Receipt states.
	StateApplied   = "applied"
	StateConfirmed = "confirmed"
	StateReverted  = "reverted"
	StateFailed    = "failed"

	// Failure codes the node (or the Gateway) answers.
	FailureNotSupported        = "not_supported" // the Gateway: the node did not declare SSH_ACCESS v1
	FailureInvalidPolicy       = "invalid_policy"
	FailureStaleRevision       = "stale_revision"
	FailureUnknownRevision     = "unknown_revision" // a confirm for a revision the node does not hold
	FailureConfirmationTimeout = "confirmation_timeout"

	// RollbackWindow is how long the node keeps an unconfirmed revision.
	RollbackWindow = 5 * time.Minute

	MaxCIDRs        = 80
	MaxCarrierBytes = 8 << 10

	// NATS names (agent-gateway owns the streams).
	CommandStream        = "SSH_ACCESS_COMMANDS"
	ReceiptStream        = "SSH_ACCESS_RECEIPTS"
	CommandSubjectPrefix = "cdnca.agent.ssh-access.commands"
	ReceiptSubjectPrefix = "cdnca.agent.ssh-access.receipts"
	ReceiptConsumer      = "control_api_ssh_access_receipts"
)

var failureCode = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// ValidOperation reports a known command operation.
func ValidOperation(operation string) bool {
	return operation == OperationApply || operation == OperationConfirm
}

// ValidState reports a known receipt state.
func ValidState(state string) bool {
	return state == StateApplied || state == StateConfirmed || state == StateReverted || state == StateFailed
}

// ValidFailureCode: empty, or a lower-case code of at most 64 characters.
func ValidFailureCode(code string) bool { return code == "" || failureCode.MatchString(code) }
