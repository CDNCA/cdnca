// Package nodesshinstall installs edge nodes over SSH from the controller:
// the operator gives a host (or a list of IPs)
// and an SSH login; the controller pins the host key the operator confirms,
// logs in and runs the same one-line install command the console shows
// (install-node.sh with the scope's registration key). The node then
// registers itself and appears as pending like any other.
//
// The host key is fetched first and must be confirmed before credentials are
// ever sent; the SSH secret is encrypted with the DNS credential keyring
// (AES-GCM, bound to the job row) and wiped when the job ends; progress keeps
// only the installer's own log lines, never the command or the secret.
package nodesshinstall

import (
	"errors"
	"regexp"
	"time"

	"github.com/google/uuid"
)

const (
	StateAwaitingHostKey = "awaiting_host_key"
	StatePending         = "pending"
	StateRunning         = "running"
	StateSucceeded       = "succeeded"
	StateFailed          = "failed"
	StateCancelled       = "cancelled"

	AuthPassword   = "password"
	AuthPrivateKey = "private_key"

	// MaxBatch hosts in one request.
	MaxBatch = 100
	// MaxProgressLines kept per job (the newest).
	MaxProgressLines = 200
	maxProgressBytes = 512
	maxAttempts      = 3
)

// Failure codes.
const (
	FailHostKeyMismatch = "host_key_mismatch"
	FailUnreachable     = "ssh_unreachable"
	FailAuth            = "ssh_auth_failed"
	FailInstall         = "install_failed"
	FailTimeout         = "install_timeout"
	FailCredential      = "credential_unavailable"
	FailRegistration    = "registration_unavailable"
	// ResultPendingTicket is the failure_code of a succeeded job whose node
	// is installed but waits for its first license ticket (no failure).
	ResultPendingTicket = "installed_pending_ticket"
	// ResultPendingInitialization: installed and connected, but the node was
	// registered as pending and is not initialized yet, so no ticket can reach
	// it; install-node.sh reports it at once instead of waiting for the ticket.
	ResultPendingInitialization = "installed_pending_initialization"
	// ResultBanned / ResultTicketExpired: installed and connected, but the
	// node does not serve because this installation is banned by the license
	// side, or the license ticket it holds has expired (install-node.sh
	// wait_first_ticket). Not install failures: the Agent keeps running and
	// the node serves again once the cause is fixed.
	ResultBanned        = "installed_banned"
	ResultTicketExpired = "installed_ticket_expired"
	// ResultResumeFailed: the ticket is valid but the Agent could not resume
	// the site servers (state.json status=serving with stopped=true); it
	// retries every minute, the node still answers 503 meanwhile.
	ResultResumeFailed = "installed_resume_failed"
)

var (
	ErrInvalidInput = errors.New("invalid SSH install request")
	ErrNotFound     = errors.New("SSH install job not found")
	ErrConflict     = errors.New("SSH install job state conflict")
	ErrDuplicate    = errors.New("a live SSH install job already targets this host")
	ErrPermission   = errors.New("SSH install requires a platform scope")
)

var (
	usernamePattern = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)
	hostKeyPattern  = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)
)

// Actor is the platform operator.
type Actor struct {
	UserID    uuid.UUID
	ScopeID   uuid.UUID
	RequestID string
	IP        string
}

// Credential is the SSH login (one of Password / PrivateKey).
type Credential struct {
	Username   string
	Password   string
	PrivateKey string
}

// Target is one host of a request.
type Target struct {
	Host string
	Port int
	Name string
}

// CreateRequest starts one job per target. ControlPlane is the console origin
// the node downloads install-node.sh from (https only).
type CreateRequest struct {
	Targets      []Target
	Credential   Credential
	ControlPlane string
}

// Job is the API view; it never carries the secret.
type Job struct {
	ID               uuid.UUID  `json:"id"`
	BatchID          uuid.UUID  `json:"batch_id"`
	Host             string     `json:"host"`
	Port             int        `json:"port"`
	Username         string     `json:"username"`
	AuthKind         string     `json:"auth_kind"`
	NodeName         string     `json:"node_name"`
	HostKeySHA256    string     `json:"host_key_sha256"`
	HostKeyConfirmed bool       `json:"host_key_confirmed"`
	State            string     `json:"state"`
	FailureCode      string     `json:"failure_code"`
	Progress         []string   `json:"progress"`
	NodeID           *uuid.UUID `json:"node_id"`
	Attempts         int        `json:"attempts"`
	CreatedAt        time.Time  `json:"created_at"`
	StartedAt        *time.Time `json:"started_at"`
	FinishedAt       *time.Time `json:"finished_at"`
}
