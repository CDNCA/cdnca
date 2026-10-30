// Package nodeserving decides and records system serving holds: a held node
// stays enrolled (session, monitoring and configuration are untouched) but its
// line endpoints leave what customers resolve to, see the
// node_line_endpoint_serving view (migration 280).
package nodeserving

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

const (
	SourceAvailabilityMonitor = "availability_monitor"
	SourceAutoDisable         = "auto_disable"

	EventHeld              = "held"
	EventReleased          = "released"
	EventProtected         = "protected"
	EventProtectionCleared = "protection_cleared"

	ReasonProbeUnhealthy  = "probe_unhealthy"
	ReasonProbeStale      = "probe_stale"
	ReasonProbeRecovered  = "probe_recovered"
	ReasonActionNone      = "action_none"
	ReasonMonitorDisabled = "monitor_disabled"
	ReasonPolicyInactive  = "policy_inactive"
	ReasonNodeInactive    = "node_inactive"
	ReasonLastEndpoint    = "last_serving_endpoint"
)

var (
	ErrInvalidInput = errors.New("invalid node serving request")
	ErrNotFound     = errors.New("node serving resource not found")
)

// Decision is the desired state of one node and source.
type Decision struct {
	Held   bool
	Reason string
	Detail map[string]any
}

// Hold is the persisted state of one node and source.
type Hold struct {
	NodeID          uuid.UUID  `json:"node_id"`
	Source          string     `json:"source"`
	Held            bool       `json:"held"`
	ReasonCode      string     `json:"reason_code"`
	Revision        int64      `json:"revision"`
	HeldSince       *time.Time `json:"held_since"`
	ProtectedGroups int        `json:"protected_groups"`
	ChangedAt       time.Time  `json:"changed_at"`
}

// Event is one transition in a node's serving log.
type Event struct {
	ID           uuid.UUID      `json:"id"`
	Source       string         `json:"source"`
	Event        string         `json:"event"`
	ReasonCode   string         `json:"reason_code"`
	HoldRevision int64          `json:"hold_revision"`
	Detail       map[string]any `json:"detail"`
	OccurredAt   time.Time      `json:"occurred_at"`
}

type EventPage struct {
	SchemaVersion int       `json:"schema_version"`
	NodeID        uuid.UUID `json:"node_id"`
	From          time.Time `json:"from"`
	To            time.Time `json:"to"`
	Page          int       `json:"page"`
	Limit         int       `json:"limit"`
	Total         int64     `json:"total"`
	Items         []Event   `json:"items"`
}
