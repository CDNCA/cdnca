// Package nodemonitoringoverride stores per-node monitoring overrides. Delivery
// stays on the node monitoring outbox: the reconciliation backfill enqueues the
// effective artifact (platform policy overlaid by the override) for serving
// nodes only (nodemonitoringoutbox.ServingNodePredicate), so an override saved
// for a blank node is delivered once it starts serving.
package nodemonitoringoverride

import (
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
	"github.com/google/uuid"
)

const Operation = "node.monitoring_override"

var (
	ErrInvalidInput        = errors.New("invalid node monitoring override")
	ErrNotFound            = errors.New("node not found")
	ErrRevisionConflict    = errors.New("node monitoring override revision conflict")
	ErrIdempotencyConflict = errors.New("node monitoring override idempotency conflict")
	ErrTimeoutTooLong      = errors.New("node monitoring timeout exceeds the platform probe interval")
	ErrRevisionExhausted   = errors.New("node monitoring override revision limit reached")
)

type Actor struct {
	UserID  uuid.UUID
	ScopeID uuid.UUID
}

// Fields are the override values; null inherits the platform policy.
type Fields struct {
	MonitorEnabled *bool   `json:"monitor_enabled"`
	Protocol       *string `json:"protocol"`
	ProbeTimeoutMS *int    `json:"probe_timeout_ms"`
	MonitorPort    *int    `json:"monitor_port"`
	MonitorAction  *string `json:"monitor_action"`
}

type PutRequest struct {
	NodeID           uuid.UUID
	ExpectedRevision int64
	Fields           Fields
	IdempotencyKey   string
	RequestID        string
}

type View struct {
	SchemaVersion int        `json:"schema_version"`
	NodeID        uuid.UUID  `json:"node_id"`
	Revision      int64      `json:"revision"`
	UpdatedAt     *time.Time `json:"updated_at"`
	Override      Fields     `json:"override"`
	// PlatformState is the platform policy state; Effective* are present only
	// for an active platform policy.
	PlatformState     string                         `json:"platform_state"`
	PlatformRevision  *int64                         `json:"platform_revision"`
	EffectiveRevision *int64                         `json:"effective_revision"`
	EffectivePolicy   *systemconfig.MonitoringPolicy `json:"effective_policy"`
	EffectiveAction   string                         `json:"effective_action"`
	DeliveryState     string                         `json:"delivery_state"`
}
