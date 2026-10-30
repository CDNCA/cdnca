package nodemetrics

import (
	"context"
	"math"
	"strconv"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/nodemonitoringconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/nodeserving"
	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type MonitoringSnapshot struct {
	SchemaVersion int                                  `json:"schema_version"`
	ObservedAt    time.Time                            `json:"observed_at"`
	Configuration systemconfig.MonitoringConfiguration `json:"configuration"`
	Items         []MonitoringItem                     `json:"items"`
}

type MonitoringItem struct {
	NodeID        uuid.UUID               `json:"node_id"`
	Freshness     string                  `json:"freshness"`
	RevisionState string                  `json:"revision_state"`
	StaleAfterMS  *int                    `json:"stale_after_ms"`
	Sample        *MonitoringProbeSample  `json:"sample"`
	ApplyReceipt  *MonitoringApplyReceipt `json:"apply_receipt,omitempty"`
	// DeliveryState says whether the active policy can reach this node at all:
	// artifacts are only delivered to active nodes serving a signed edge
	// configuration (nodemonitoringoutbox.ServingNodePredicate).
	DeliveryState string `json:"delivery_state"`
	// EffectiveRevision/EffectivePolicy are present only for a node with a
	// monitoring override under an active policy: the node then runs the
	// platform policy overlaid by its override, at revision active+override.
	EffectiveRevision *int64                         `json:"effective_revision,omitempty"`
	EffectivePolicy   *systemconfig.MonitoringPolicy `json:"effective_policy,omitempty"`
	// ServingHolds lists active system holds (monitoring pause, auto-disable)
	// that keep this node out of customer DNS; omitted when there are none.
	ServingHolds []MonitoringServingHold `json:"serving_holds,omitempty"`
}

type MonitoringServingHold struct {
	Source          string    `json:"source"`
	ReasonCode      string    `json:"reason_code"`
	HeldSince       time.Time `json:"held_since"`
	ProtectedGroups int       `json:"protected_groups"`
}

const (
	DeliveryServing               = "serving"
	DeliveryAwaitingConfiguration = "awaiting_configuration"
	DeliveryInactive              = "inactive"
)

type MonitoringApplyReceipt struct {
	State          string    `json:"state"`
	ConfigRevision uint64    `json:"config_revision,string"`
	ObservedAt     time.Time `json:"observed_at"`
}

type MonitoringProbeSample struct {
	Source               string    `json:"source"`
	ConfigRevision       uint64    `json:"config_revision"`
	ActiveConfigRevision uint64    `json:"active_config_revision"`
	PublicationSequence  uint64    `json:"publication_sequence,string"`
	ObservedAt           time.Time `json:"observed_at"`
	IngestedAt           time.Time `json:"ingested_at"`
	ProbePort            uint16    `json:"probe_port"`
	Healthy              bool      `json:"healthy"`
	ProbeSucceeded       bool      `json:"probe_succeeded"`
	ConsecutiveFailures  uint8     `json:"consecutive_failures"`
	ConsecutiveSuccesses uint8     `json:"consecutive_successes"`
	ProbesTotal          uint64    `json:"probes_total,string"`
	ProbeFailuresTotal   uint64    `json:"probe_failures_total,string"`
	Recovered            bool      `json:"recovered"`
	RecoveryNotified     bool      `json:"recovery_notified"`
	RolledBack           bool      `json:"rolled_back"`
}

// MonitoringLatest reads scope membership, active configuration and actual
// local TCP samples in one read-only snapshot. Host metrics are deliberately
// excluded: their NULL probe fields are not a negative monitoring result.
func (reader *PostgresReader) MonitoringLatest(ctx context.Context, scopeID uuid.UUID, nodeIDs []uuid.UUID) (MonitoringSnapshot, error) {
	if reader == nil || reader.pool == nil || ctx == nil || scopeID == uuid.Nil || len(nodeIDs) < 1 || len(nodeIDs) > MaxLatestBatch {
		return MonitoringSnapshot{}, ErrInvalidConfiguration
	}
	seen := make(map[uuid.UUID]struct{}, len(nodeIDs))
	for _, id := range nodeIDs {
		if _, duplicate := seen[id]; id == uuid.Nil || duplicate {
			return MonitoringSnapshot{}, ErrInvalidConfiguration
		}
		seen[id] = struct{}{}
	}
	tx, err := reader.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return MonitoringSnapshot{}, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	result := MonitoringSnapshot{SchemaVersion: 1, ObservedAt: time.Now().UTC(), Items: make([]MonitoringItem, 0, len(nodeIDs))}
	// delivery_state mirrors nodemonitoringoutbox.ServingNodePredicate.
	rows, err := tx.Query(ctx, `WITH scoped_nodes AS (
		SELECT node.id,requested.position,CASE
			WHEN node.admin_state<>'active' THEN 'inactive'
			WHEN EXISTS (SELECT 1 FROM node_config_state serving
				WHERE serving.node_id=node.id AND serving.current_config_version_id IS NOT NULL) THEN 'serving'
			ELSE 'awaiting_configuration' END AS delivery_state
		FROM unnest($2::uuid[]) WITH ORDINALITY AS requested(id,position)
		JOIN nodes node ON node.id=requested.id AND node.scope_id=$1
	)
	SELECT node.id,metric.config_revision,metric.active_config_revision,metric.publication_sequence,
		metric.observed_at,metric.ingested_at,metric.probe_port,metric.healthy,metric.probe_succeeded,
		metric.consecutive_failures,metric.consecutive_successes,metric.probes_total,metric.probe_failures_total,
		metric.recovered,metric.recovery_notified,metric.rolled_back,
		metric.record_kind,metric.schema_version,metric.puback_stream,metric.puback_sequence,
		metric.consumer_durable,metric.consumer_sequence,metric.num_delivered,metric.wire_sha256,
		metric.event_id,metric.request_id,metric.node_id,node.delivery_state
	FROM scoped_nodes node LEFT JOIN node_metric_latest metric ON metric.node_id=node.id
	WHERE (SELECT count(*) FROM scoped_nodes)=cardinality($2::uuid[]) ORDER BY node.position`, scopeID, nodeIDs)
	if err != nil {
		return MonitoringSnapshot{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var item MonitoringItem
		if rows.RawValues()[26] == nil {
			// A missing joined identity means no probe; a NULL required field on
			// a present probe must instead fail scanning below.
			targets := make([]any, len(rows.FieldDescriptions()))
			targets[0] = &item.NodeID
			targets[len(targets)-1] = &item.DeliveryState
			if err := rows.Scan(targets...); err != nil {
				return MonitoringSnapshot{}, err
			}
		} else {
			sample := MonitoringProbeSample{Source: "agent_local_tcp"}
			var kind, stream, durable string
			var schema uint8
			var pubAck, consumed, delivered uint64
			var wire []byte
			var eventID, requestID, sampleNodeID uuid.UUID
			if err := rows.Scan(&item.NodeID, &sample.ConfigRevision, &sample.ActiveConfigRevision, &sample.PublicationSequence,
				&sample.ObservedAt, &sample.IngestedAt, &sample.ProbePort, &sample.Healthy, &sample.ProbeSucceeded,
				&sample.ConsecutiveFailures, &sample.ConsecutiveSuccesses, &sample.ProbesTotal, &sample.ProbeFailuresTotal,
				&sample.Recovered, &sample.RecoveryNotified, &sample.RolledBack,
				&kind, &schema, &stream, &pubAck, &durable, &consumed, &delivered, &wire, &eventID, &requestID, &sampleNodeID,
				&item.DeliveryState); err != nil {
				return MonitoringSnapshot{}, err
			}
			if !validMonitoringSample(sample) || kind != RecordMetric || schema != 1 || stream != NodeMonitoringStatusStream ||
				durable != DefaultConsumerDurable || pubAck < 1 || pubAck > math.MaxInt64 || consumed < 1 || consumed > math.MaxInt64 ||
				delivered < 1 || delivered > math.MaxInt64 || len(wire) != 32 || eventID == uuid.Nil || requestID == uuid.Nil || sampleNodeID != item.NodeID {
				return MonitoringSnapshot{}, ErrInvalidSample
			}
			sample.ObservedAt, sample.IngestedAt = sample.ObservedAt.UTC(), sample.IngestedAt.UTC()
			item.Sample = &sample
		}
		if item.DeliveryState != DeliveryServing && item.DeliveryState != DeliveryAwaitingConfiguration &&
			item.DeliveryState != DeliveryInactive {
			return MonitoringSnapshot{}, ErrInvalidSample
		}
		result.Items = append(result.Items, item)
	}
	if err := rows.Err(); err != nil {
		return MonitoringSnapshot{}, err
	}
	rows.Close()
	if len(result.Items) != len(nodeIDs) {
		return MonitoringSnapshot{}, ErrNotFound
	}
	holds, err := nodeserving.ActiveHolds(ctx, tx, nodeIDs)
	if err != nil {
		return MonitoringSnapshot{}, err
	}
	for index := range result.Items {
		for _, hold := range holds[result.Items[index].NodeID] {
			if hold.HeldSince == nil {
				return MonitoringSnapshot{}, ErrInvalidSample
			}
			result.Items[index].ServingHolds = append(result.Items[index].ServingHolds, MonitoringServingHold{
				Source: hold.Source, ReasonCode: hold.ReasonCode, HeldSince: *hold.HeldSince, ProtectedGroups: hold.ProtectedGroups})
		}
	}
	result.Configuration, err = systemconfig.ReadNodeMonitoringConfiguration(ctx, tx, scopeID)
	if err != nil {
		return MonitoringSnapshot{}, err
	}
	if result.Configuration.ActiveRevision != nil {
		if *result.Configuration.ActiveRevision < 1 || uint64(*result.Configuration.ActiveRevision) > math.MaxInt64 {
			return MonitoringSnapshot{}, ErrInvalidConfiguration
		}
		if err := applyMonitoringOverrides(ctx, tx, scopeID, nodeIDs, result); err != nil {
			return MonitoringSnapshot{}, err
		}
		receiptRequests := make([]uuid.UUID, 0, len(nodeIDs))
		receiptNodes := make(map[uuid.UUID]uuid.UUID, len(nodeIDs))
		for index, nodeID := range nodeIDs {
			revision := itemRevision(result.Items[index], result.Configuration)
			requestID := uuid.NewSHA1(nodeID, []byte("node-monitoring-stop-receipt/"+strconv.FormatUint(revision, 10)))
			receiptRequests = append(receiptRequests, requestID)
			receiptNodes[requestID] = nodeID
		}
		receiptRows, receiptErr := tx.Query(ctx, `
			SELECT DISTINCT ON (sample.node_id) sample.node_id,sample.observed_at,sample.request_id
			FROM node_metric_samples sample
			JOIN nodes node ON node.id=sample.node_id AND node.scope_id=$1
			WHERE sample.node_id=ANY($2::uuid[]) AND sample.request_id=ANY($3::uuid[]) AND sample.record_kind='host_metric'
			ORDER BY sample.node_id,sample.observed_at DESC,sample.publication_sequence DESC`, scopeID, nodeIDs, receiptRequests)
		if receiptErr != nil {
			return MonitoringSnapshot{}, receiptErr
		}
		for receiptRows.Next() {
			var nodeID, requestID uuid.UUID
			var receipt MonitoringApplyReceipt
			if scanErr := receiptRows.Scan(&nodeID, &receipt.ObservedAt, &requestID); scanErr != nil {
				receiptRows.Close()
				return MonitoringSnapshot{}, scanErr
			}
			expectedNode, ok := receiptNodes[requestID]
			if nodeID == uuid.Nil || !ok || expectedNode != nodeID || receipt.ObservedAt.IsZero() {
				receiptRows.Close()
				return MonitoringSnapshot{}, ErrInvalidSample
			}
			receipt.State = "applied"
			for index := range result.Items {
				if result.Items[index].NodeID == nodeID {
					receipt.ConfigRevision = itemRevision(result.Items[index], result.Configuration)
					result.Items[index].ApplyReceipt = &receipt
					break
				}
			}
		}
		if receiptErr := receiptRows.Err(); receiptErr != nil {
			receiptRows.Close()
			return MonitoringSnapshot{}, receiptErr
		}
		receiptRows.Close()
	}
	for index := range result.Items {
		item := &result.Items[index]
		policy := result.Configuration.Policy
		if item.EffectivePolicy != nil {
			policy = item.EffectivePolicy
		}
		if item.Sample != nil {
			item.Sample.Source = "agent_local_tcp"
			if policy != nil && policy.RequestedProtocol == "http" {
				item.Sample.Source = "agent_local_http"
			} else if policy != nil && policy.RequestedProtocol == "ping" {
				item.Sample.Source = "agent_local_ping"
			}
		}
		classifyMonitoringSample(item, result.Configuration, result.ObservedAt)
	}
	if err := tx.Commit(ctx); err != nil {
		return MonitoringSnapshot{}, err
	}
	return result, nil
}

func validMonitoringSample(sample MonitoringProbeSample) bool {
	const maxSafeRevision = 1<<53 - 1
	return (sample.Source == "agent_local_tcp" || sample.Source == "agent_local_http" || sample.Source == "agent_local_ping") && sample.ConfigRevision > 0 && sample.ConfigRevision <= maxSafeRevision &&
		sample.ActiveConfigRevision > 0 && sample.ActiveConfigRevision <= maxSafeRevision &&
		sample.PublicationSequence > 0 && sample.PublicationSequence <= math.MaxInt64 &&
		!sample.ObservedAt.IsZero() && sample.ObservedAt.Year() >= 1 && sample.ObservedAt.Year() <= 9999 &&
		!sample.IngestedAt.IsZero() && sample.IngestedAt.Year() >= 1 && sample.IngestedAt.Year() <= 9999 &&
		sample.ProbePort > 0 && sample.ConsecutiveFailures <= 20 && sample.ConsecutiveSuccesses <= 20 &&
		!(sample.ConsecutiveFailures > 0 && sample.ConsecutiveSuccesses > 0) &&
		sample.ProbesTotal <= math.MaxInt64 && sample.ProbeFailuresTotal <= sample.ProbesTotal &&
		(!sample.Recovered || sample.Healthy && sample.ProbeSucceeded) &&
		(!sample.RolledBack || sample.ActiveConfigRevision < sample.ConfigRevision && !sample.ProbeSucceeded)
}

func classifyMonitoringSample(item *MonitoringItem, configuration systemconfig.MonitoringConfiguration, now time.Time) {
	item.Freshness, item.RevisionState = "not_reported", "unknown"
	item.StaleAfterMS = nil
	policy := configuration.Policy
	if item.EffectivePolicy != nil {
		policy = item.EffectivePolicy
	}
	if policy != nil {
		staleAfter := min(policy.ProbeIntervalMS+policy.ProbeTimeoutMS+30000, 390000)
		item.StaleAfterMS = &staleAfter
	}
	if item.Sample == nil {
		return
	}
	sample := item.Sample
	item.Freshness = "stale"
	if sample.ObservedAt.After(now.Add(5 * time.Second)) {
		item.Freshness = "clock_skew"
	} else if item.StaleAfterMS != nil && now.Sub(sample.ObservedAt) <= time.Duration(*item.StaleAfterMS)*time.Millisecond {
		item.Freshness = "fresh"
	}
	if sample.RolledBack {
		item.RevisionState = "rolled_back"
	} else if configuration.ActiveRevision != nil {
		item.RevisionState = "different"
		active := itemRevision(*item, configuration)
		if sample.ConfigRevision == active && sample.ActiveConfigRevision == active &&
			configuration.ActivatedAt != nil && !sample.ObservedAt.Before(*configuration.ActivatedAt) {
			item.RevisionState = "current"
		}
	}
}

// itemRevision is the revision the node is expected to run: the active
// platform revision, or its effective revision with a monitoring override.
func itemRevision(item MonitoringItem, configuration systemconfig.MonitoringConfiguration) uint64 {
	if item.EffectiveRevision != nil {
		return uint64(*item.EffectiveRevision)
	}
	return uint64(*configuration.ActiveRevision)
}

func applyMonitoringOverrides(
	ctx context.Context,
	tx pgx.Tx,
	scopeID uuid.UUID,
	nodeIDs []uuid.UUID,
	result MonitoringSnapshot,
) error {
	if result.Configuration.Policy == nil {
		return ErrInvalidConfiguration
	}
	rows, err := tx.Query(ctx, `SELECT node_id,revision,monitor_enabled,protocol,probe_timeout_ms,monitor_port,monitor_action
		FROM node_monitoring_overrides WHERE scope_id=$1 AND node_id=ANY($2::uuid[])`, scopeID, nodeIDs)
	if err != nil {
		return err
	}
	defer rows.Close()
	positions := make(map[uuid.UUID]int, len(nodeIDs))
	for index, nodeID := range nodeIDs {
		positions[nodeID] = index
	}
	for rows.Next() {
		var nodeID uuid.UUID
		var override nodemonitoringconfig.Override
		var protocol, action *string
		var timeout, port *int32
		if err := rows.Scan(&nodeID, &override.Revision, &override.MonitorEnabled, &protocol, &timeout, &port, &action); err != nil {
			return err
		}
		index, ok := positions[nodeID]
		if !ok || port != nil && (*port < 1 || *port > 65535) {
			return ErrInvalidSample
		}
		if protocol != nil {
			override.Protocol = *protocol
		}
		if action != nil {
			override.MonitorAction = *action
		}
		if timeout != nil {
			value := int(*timeout)
			override.ProbeTimeoutMS = &value
		}
		if port != nil {
			value := uint16(*port)
			override.MonitorPort = &value
		}
		if !nodemonitoringconfig.ValidOverride(override) || override.Revision < 1 {
			return ErrInvalidSample
		}
		revision := nodemonitoringconfig.EffectiveRevision(*result.Configuration.ActiveRevision, override.Revision)
		policy := nodemonitoringconfig.ApplyOverrideToPolicy(*result.Configuration.Policy, override)
		result.Items[index].EffectiveRevision, result.Items[index].EffectivePolicy = &revision, &policy
	}
	return rows.Err()
}
