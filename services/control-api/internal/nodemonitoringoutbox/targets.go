package nodemonitoringoutbox

import (
	"fmt"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/nodemonitoringconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/nodemonitoringpublication"
	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TargetColumns and TargetJoin select a serving node (aliased "node") together
// with its optional monitoring override, for ScanTargets. Activation and the
// reconciliation backfill share them so both build the same artifact.
const (
	TargetColumns = `node.id,node_override.revision,node_override.monitor_enabled,node_override.protocol,
		node_override.probe_timeout_ms,node_override.monitor_port,node_override.monitor_action,node_override.updated_at`
	TargetJoin = `LEFT JOIN node_monitoring_overrides node_override ON node_override.node_id=node.id`
	// TargetRevision is the effective revision of a target row for platform
	// revision $1 (nodemonitoringconfig.EffectiveRevision).
	TargetRevision = `$1+COALESCE(node_override.revision,0)`
)

type Target struct {
	NodeID            uuid.UUID
	Override          nodemonitoringconfig.Override
	OverrideUpdatedAt time.Time
}

func ScanTargets(rows pgx.Rows) ([]Target, error) {
	defer rows.Close()
	targets := make([]Target, 0)
	for rows.Next() {
		var target Target
		var revision *int64
		var timeout, port *int32
		var protocol, action *string
		var updatedAt *time.Time
		if err := rows.Scan(&target.NodeID, &revision, &target.Override.MonitorEnabled, &protocol, &timeout, &port,
			&action, &updatedAt); err != nil || target.NodeID == uuid.Nil {
			return nil, fmt.Errorf("scan node monitoring target: %w", err)
		}
		if revision != nil {
			if updatedAt == nil {
				return nil, ErrInvalidInput
			}
			target.Override.Revision, target.OverrideUpdatedAt = *revision, updatedAt.UTC()
		}
		if protocol != nil {
			target.Override.Protocol = *protocol
		}
		if action != nil {
			target.Override.MonitorAction = *action
		}
		if timeout != nil {
			value := int(*timeout)
			target.Override.ProbeTimeoutMS = &value
		}
		if port != nil {
			if *port < 1 || *port > 65535 {
				return nil, ErrInvalidInput
			}
			value := uint16(*port)
			target.Override.MonitorPort = &value
		}
		targets = append(targets, target)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate node monitoring targets: %w", err)
	}
	return targets, nil
}

// Artifact builds the target's effective artifact. Its occurrence time is the
// later of the platform activation and the override change, a pure function
// of the effective revision, so activation and backfill stay idempotent.
func (target Target) Artifact(document systemconfig.CategoryDocument, activatedAt time.Time) (*agentv1.NodeMonitoringArtifact, error) {
	occurredAt := activatedAt
	if target.OverrideUpdatedAt.After(occurredAt) {
		occurredAt = target.OverrideUpdatedAt
	}
	return nodemonitoringpublication.BuildNodeArtifact(target.NodeID.String(), document, target.Override, occurredAt)
}
