package systemconfig

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type MonitoringConfiguration struct {
	State          string            `json:"state"`
	HeadRevision   int64             `json:"head_revision"`
	ActiveRevision *int64            `json:"active_revision"`
	ActivatedAt    *time.Time        `json:"activated_at"`
	Policy         *MonitoringPolicy `json:"policy"`
}

type MonitoringPolicy struct {
	Enabled            bool    `json:"enabled"`
	RequestedProtocol  string  `json:"requested_protocol"`
	RequestedPort      *uint16 `json:"requested_port"`
	ProbeIntervalMS    int     `json:"probe_interval_ms"`
	ProbeTimeoutMS     int     `json:"probe_timeout_ms"`
	FailureThreshold   int     `json:"failure_threshold"`
	RecoveryThreshold  int     `json:"recovery_threshold"`
	FailureDebounceMS  int     `json:"failure_debounce_ms"`
	RecoveryDebounceMS int     `json:"recovery_debounce_ms"`
}

// ReadNodeMonitoringConfiguration is a projection for an already authorized
// platform reader. The caller supplies the same read-only repeatable snapshot
// used for node membership and probe evidence. Unlike reconciliation, this read
// must not lock or create a stream, or promote the head to active configuration.
func ReadNodeMonitoringConfiguration(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) (MonitoringConfiguration, error) {
	result, _, err := ReadActiveNodeMonitoring(ctx, tx, scopeID)
	return result, err
}

// ReadActiveNodeMonitoring is ReadNodeMonitoringConfiguration that also returns
// the full active value (including the failure action), which the policy
// projection omits. The value is the zero value unless State is "active".
func ReadActiveNodeMonitoring(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) (MonitoringConfiguration, NodeMonitoringConfiguration, error) {
	return readNodeMonitoring(ctx, tx, scopeID)
}

func readNodeMonitoring(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) (MonitoringConfiguration, NodeMonitoringConfiguration, error) {
	var none NodeMonitoringConfiguration
	if ctx == nil || tx == nil || scopeID == uuid.Nil {
		return MonitoringConfiguration{}, none, ErrInvalidStore
	}
	var kind string
	var tenantID *uuid.UUID
	var head, active *int64
	err := tx.QueryRow(ctx, `SELECT scope.kind,scope.tenant_id,stream.head_revision,stream.active_revision
		FROM access_scopes scope LEFT JOIN system_configuration_streams stream ON stream.platform_scope_id=scope.id
		WHERE scope.id=$1`, scopeID).Scan(&kind, &tenantID, &head, &active)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (kind != "platform" || tenantID != nil) {
		return MonitoringConfiguration{}, none, ErrPermissionDenied
	}
	if err != nil {
		return MonitoringConfiguration{}, none, err
	}
	const maxSafeRevision = 1<<53 - 1
	if head != nil && (*head < 0 || *head > maxSafeRevision) || active != nil &&
		(head == nil || *active < 1 || *active > maxSafeRevision || *active > *head) {
		return MonitoringConfiguration{}, none, ErrInvalidInput
	}
	result := MonitoringConfiguration{State: "unconfigured"}
	if head == nil || *head == 0 {
		return result, none, nil
	}
	headItem, err := loadRevision(ctx, tx, scopeID, *head)
	if err != nil {
		return MonitoringConfiguration{}, none, err
	}
	if headItem.ScopeID != scopeID || headItem.Revision != *head ||
		(headItem.Status != StatusDraft && headItem.Status != StatusValidated && headItem.Status != StatusActive &&
			headItem.Status != StatusSuperseded && headItem.Status != StatusRejected) {
		return MonitoringConfiguration{}, none, ErrInvalidInput
	}
	result.State, result.HeadRevision = "not_activated", *head
	if active == nil {
		if headItem.Status == StatusActive {
			return MonitoringConfiguration{}, none, ErrInvalidInput
		}
		return result, none, nil
	}
	activeItem := headItem
	if *active != *head {
		activeItem, err = loadRevision(ctx, tx, scopeID, *active)
		if err != nil {
			return MonitoringConfiguration{}, none, err
		}
	}
	if activeItem.ScopeID != scopeID || activeItem.Revision != *active || activeItem.Status != StatusActive ||
		activeItem.StateChangedAt.IsZero() || activeItem.StateChangedAt.Year() < 1 || activeItem.StateChangedAt.Year() > 9999 {
		return MonitoringConfiguration{}, none, ErrInvalidInput
	}
	activatedAt := activeItem.StateChangedAt.UTC()
	value := EffectiveNodeMonitoring(activeItem.Configuration.NodeMonitoring)
	policy := monitoringPolicyFromActive(value)
	result.State, result.ActiveRevision, result.ActivatedAt, result.Policy = "active", active, &activatedAt, &policy
	return result, value, nil
}

func monitoringPolicyFromActive(value NodeMonitoringConfiguration) MonitoringPolicy {
	policy := MonitoringPolicy{
		Enabled:           value.MonitorEnabled == nil || *value.MonitorEnabled,
		RequestedProtocol: value.Protocol, RequestedPort: value.MonitorPort,
		ProbeIntervalMS: value.ProbeIntervalMS, ProbeTimeoutMS: value.ProbeTimeoutMS,
		FailureThreshold: value.FailureThreshold, RecoveryThreshold: value.RecoveryThreshold,
		FailureDebounceMS: value.FailureDebounceMS, RecoveryDebounceMS: value.RecoveryDebounceMS,
	}
	if policy.RequestedProtocol == "" {
		policy.RequestedProtocol = "tcp"
	}
	if policy.RequestedPort == nil && value.PortMode == PortModeCustom {
		policy.RequestedPort = value.CustomPort
	}
	return policy
}

// MonitoringPolicyFor projects an effective node monitoring value (for example
// the platform policy overlaid by a node override) like the active policy.
func MonitoringPolicyFor(value NodeMonitoringConfiguration) MonitoringPolicy {
	return monitoringPolicyFromActive(value)
}
