package nodemetrics

import (
	"context"
	"math/bits"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// TopView is the node-level projection used by the observed realtime ranking
// endpoint. Values are float64 so load and disk percentages do not lose
// precision while bandwidth and connection counts remain exact integers.
type TopView struct {
	NodeID   uuid.UUID
	NodeName string
	NIC      string
	Inbound  float64
	Outbound float64
}

type RealtimePoint struct {
	ObservedAt time.Time
	Value      float64
}

type RealtimeSeries struct {
	Name   string
	Points []RealtimePoint
}

type RealtimeView struct {
	Data map[string][]RealtimeSeries
}

type TrafficPoint struct {
	ObservedAt    time.Time
	BytesReceived uint64
	BytesSent     uint64
}

type NodeMetricsAnalyticsReader interface {
	Top(context.Context, uuid.UUID, time.Time, time.Time, string, int, bool) ([]TopView, error)
	Realtime(context.Context, uuid.UUID, uuid.UUID, time.Time, time.Time, string, int, bool) (RealtimeView, error)
	Traffic(context.Context, uuid.UUID, uuid.UUID, time.Time, time.Time, []string, int, bool) ([]TrafficPoint, error)
}

func (reader *PostgresReader) Top(
	ctx context.Context,
	scopeID uuid.UUID,
	from, to time.Time,
	metric string,
	limit int,
	externalOnly bool,
) ([]TopView, error) {
	if reader == nil || reader.pool == nil || ctx == nil || scopeID == uuid.Nil ||
		from.IsZero() || to.IsZero() || to.Before(from) || limit < 1 || limit > 300 {
		return nil, ErrInvalidConfiguration
	}
	rows, err := reader.pool.Query(ctx, `
		SELECT node.id, node.name, metric.metrics_known,
		       metric.cpu_percent, metric.active_connections,
		       metric.rx_bandwidth_bps, metric.tx_bandwidth_bps,
		       metric.telemetry_json
		FROM nodes node
		JOIN node_load_latest metric ON metric.node_id = node.id
		WHERE node.scope_id=$1 AND metric.observed_at >= $2 AND metric.observed_at <= $3
		ORDER BY metric.observed_at DESC, node.id ASC`, scopeID, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]TopView, 0, limit)
	for rows.Next() {
		var nodeID uuid.UUID
		var nodeName string
		var known bool
		var cpu *float64
		var connections *uint64
		var rxBandwidth, txBandwidth *uint64
		var telemetryJSON []byte
		if err := rows.Scan(&nodeID, &nodeName, &known, &cpu, &connections, &rxBandwidth, &txBandwidth, &telemetryJSON); err != nil {
			return nil, err
		}
		if !known {
			continue
		}
		var telemetry *Telemetry
		if len(telemetryJSON) > 0 {
			if err := decodeStoredTelemetry(telemetryJSON, &telemetry); err != nil {
				return nil, err
			}
		}
		candidate := topViewsForSample(nodeID, nodeName, metric, cpu, connections, rxBandwidth, txBandwidth, telemetry)
		if externalOnly && metric == "bandwidth" {
			filtered := candidate[:0]
			for _, item := range candidate {
				if externalInterface(telemetry, item.NIC) {
					filtered = append(filtered, item)
				}
			}
			candidate = filtered
		}
		items = append(items, candidate...)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.SliceStable(items, func(i, j int) bool {
		left := items[i].Inbound + items[i].Outbound
		right := items[j].Inbound + items[j].Outbound
		if left != right {
			return left > right
		}
		if items[i].NodeName != items[j].NodeName {
			return items[i].NodeName < items[j].NodeName
		}
		return items[i].NIC < items[j].NIC
	})
	if len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}

func topViewsForSample(
	nodeID uuid.UUID,
	nodeName, metric string,
	cpu *float64,
	connections *uint64,
	rxBandwidth, txBandwidth *uint64,
	telemetry *Telemetry,
) []TopView {
	if telemetry == nil {
		telemetry = &Telemetry{}
	}
	switch metric {
	case "bandwidth":
		items := make([]TopView, 0, len(telemetry.NetworkInterfaces))
		for _, network := range telemetry.NetworkInterfaces {
			items = append(items, TopView{NodeID: nodeID, NodeName: nodeName, NIC: network.Name,
				Inbound: float64(network.RXBandwidthBPS), Outbound: float64(network.TXBandwidthBPS)})
		}
		if len(items) == 0 {
			var inbound, outbound float64
			if rxBandwidth != nil {
				inbound = float64(*rxBandwidth)
			}
			if txBandwidth != nil {
				outbound = float64(*txBandwidth)
			}
			if rxBandwidth != nil || txBandwidth != nil {
				items = append(items, TopView{NodeID: nodeID, NodeName: nodeName, NIC: "",
					Inbound: inbound, Outbound: outbound})
			}
		}
		return items
	case "connections":
		if connections == nil {
			return nil
		}
		return []TopView{{NodeID: nodeID, NodeName: nodeName, Inbound: float64(*connections)}}
	case "load":
		if cpu == nil {
			return nil
		}
		return []TopView{{NodeID: nodeID, NodeName: nodeName, Inbound: *cpu}}
	case "disk":
		items := make([]TopView, 0, len(telemetry.Disks))
		for _, disk := range telemetry.Disks {
			items = append(items, TopView{NodeID: nodeID, NodeName: nodeName, NIC: disk.Path,
				Inbound: disk.SpacePercent})
		}
		return items
	default:
		return nil
	}
}

func (reader *PostgresReader) Realtime(
	ctx context.Context,
	scopeID, nodeID uuid.UUID,
	from, to time.Time,
	metric string,
	limit int,
	externalOnly bool,
) (RealtimeView, error) {
	if reader == nil || reader.pool == nil || ctx == nil || scopeID == uuid.Nil || nodeID == uuid.Nil ||
		from.IsZero() || to.IsZero() || to.Before(from) || limit < 1 || limit > 2000 {
		return RealtimeView{}, ErrInvalidConfiguration
	}
	history, err := reader.History(ctx, scopeID, nodeID, from, to, limit)
	if err != nil {
		return RealtimeView{}, err
	}
	if externalOnly && metric == "bandwidth" {
		for index := range history {
			point := &history[index]
			if point.Telemetry == nil {
				point.Known = false
				continue
			}
			copyTelemetry := *point.Telemetry
			copyTelemetry.NetworkInterfaces = nil
			for _, network := range point.Telemetry.NetworkInterfaces {
				if externalInterface(point.Telemetry, network.Name) {
					copyTelemetry.NetworkInterfaces = append(copyTelemetry.NetworkInterfaces, network)
				}
			}
			point.Telemetry = &copyTelemetry
			if len(copyTelemetry.NetworkInterfaces) == 0 {
				point.Known = false
			}
		}
	}
	return realtimeViewFromHistory(history, metric), nil
}

func realtimeViewFromHistory(history []HistoryView, metric string) RealtimeView {
	result := RealtimeView{Data: make(map[string][]RealtimeSeries)}
	series := make(map[string]map[string][]RealtimePoint)
	for _, point := range history {
		if !point.Known {
			continue
		}
		if metric == "bandwidth" {
			if point.Telemetry == nil || len(point.Telemetry.NetworkInterfaces) == 0 {
				appendOptionalRealtimePoint(series, "all", "inbound", point.ObservedAt, point.RXBandwidthBPS)
				appendOptionalRealtimePoint(series, "all", "outbound", point.ObservedAt, point.TXBandwidthBPS)
				continue
			}
			for _, network := range point.Telemetry.NetworkInterfaces {
				appendRealtimePoint(series, network.Name, "inbound", point.ObservedAt, float64(network.RXBandwidthBPS))
				appendRealtimePoint(series, network.Name, "outbound", point.ObservedAt, float64(network.TXBandwidthBPS))
			}
			continue
		}
		switch metric {
		case "connections":
			appendOptionalRealtimePoint(series, "all", "connections", point.ObservedAt, point.ActiveConnections)
		case "load":
			appendOptionalRealtimePoint(series, "all", "cpu", point.ObservedAt, point.CPUPercent)
			if point.Telemetry != nil && point.Telemetry.SystemLoad != nil {
				appendRealtimePoint(series, "all", "system_load", point.ObservedAt, point.Telemetry.SystemLoad.OneMinute)
			}
			if point.MemoryUsedBytes != nil && point.MemoryTotalBytes != nil && *point.MemoryTotalBytes > 0 {
				appendRealtimePoint(series, "all", "memory", point.ObservedAt,
					100*float64(*point.MemoryUsedBytes)/float64(*point.MemoryTotalBytes))
			}
		case "disk":
			if point.Telemetry != nil {
				for _, disk := range point.Telemetry.Disks {
					appendRealtimePoint(series, disk.Path, "space", point.ObservedAt, disk.SpacePercent)
					appendRealtimePoint(series, disk.Path, "inode", point.ObservedAt, disk.InodePercent)
				}
			}
		}
	}
	seriesOrder := map[string][]string{
		"bandwidth": {"inbound", "outbound"},
		"load":      {"cpu", "system_load", "memory"},
		"disk":      {"space", "inode"},
	}
	for nic, named := range series {
		keys := make([]string, 0, len(named))
		seen := make(map[string]struct{}, len(named))
		for _, name := range seriesOrder[metric] {
			if _, ok := named[name]; ok {
				keys = append(keys, name)
				seen[name] = struct{}{}
			}
		}
		orderedCount := len(keys)
		for name := range named {
			if _, ok := seen[name]; !ok {
				keys = append(keys, name)
			}
		}
		sort.Strings(keys[orderedCount:])
		for _, name := range keys {
			points := named[name]
			sort.SliceStable(points, func(i, j int) bool { return points[i].ObservedAt.Before(points[j].ObservedAt) })
			result.Data[nic] = append(result.Data[nic], RealtimeSeries{Name: name, Points: points})
		}
	}
	return result
}

func appendRealtimePoint(series map[string]map[string][]RealtimePoint, nic, name string, observedAt time.Time, value float64) {
	if series[nic] == nil {
		series[nic] = make(map[string][]RealtimePoint)
	}
	series[nic][name] = append(series[nic][name], RealtimePoint{ObservedAt: observedAt, Value: value})
}

func appendOptionalRealtimePoint[T ~float64 | ~uint64](series map[string]map[string][]RealtimePoint, nic, name string, observedAt time.Time, value *T) {
	if value != nil {
		appendRealtimePoint(series, nic, name, observedAt, float64(*value))
	}
}

func (reader *PostgresReader) Traffic(
	ctx context.Context,
	scopeID, nodeID uuid.UUID,
	from, to time.Time,
	excludedNICs []string,
	limit int,
	externalOnly bool,
) ([]TrafficPoint, error) {
	if reader == nil || reader.pool == nil || ctx == nil || scopeID == uuid.Nil || nodeID == uuid.Nil ||
		from.IsZero() || to.IsZero() || to.Before(from) || limit < 1 || limit > 2000 {
		return nil, ErrInvalidConfiguration
	}
	history, err := reader.History(ctx, scopeID, nodeID, from, to, limit)
	if err != nil {
		return nil, err
	}
	excluded := make(map[string]struct{}, len(excludedNICs))
	for _, nic := range excludedNICs {
		if nic = strings.TrimSpace(nic); nic != "" {
			excluded[nic] = struct{}{}
		}
	}
	if externalOnly {
		return externalTrafficIntervals(history, excluded)
	}
	items := make([]TrafficPoint, 0, len(history))
	for _, point := range history {
		if !point.Known || point.Telemetry == nil {
			if len(excluded) == 0 && point.Known && point.TotalRXBytes != nil && point.TotalTXBytes != nil {
				items = append(items, TrafficPoint{ObservedAt: point.ObservedAt, BytesReceived: *point.TotalRXBytes, BytesSent: *point.TotalTXBytes})
			}
			continue
		}
		var received, sent uint64
		for _, network := range point.Telemetry.NetworkInterfaces {
			if _, skip := excluded[network.Name]; skip {
				continue
			}
			var carry uint64
			received, carry = bits.Add64(received, network.RXBytes, 0)
			if carry != 0 {
				return nil, ErrInvalidSample
			}
			sent, carry = bits.Add64(sent, network.TXBytes, 0)
			if carry != 0 {
				return nil, ErrInvalidSample
			}
		}
		if len(point.Telemetry.NetworkInterfaces) == 0 && len(excluded) == 0 {
			received, sent = point.Telemetry.TotalRXBytes, point.Telemetry.TotalTXBytes
		}
		items = append(items, TrafficPoint{ObservedAt: point.ObservedAt, BytesReceived: received, BytesSent: sent})
	}
	return trafficIntervals(items), nil
}

func trafficIntervals(items []TrafficPoint) []TrafficPoint {
	if len(items) < 2 {
		return nil
	}
	intervals := make([]TrafficPoint, len(items))
	intervals[0].ObservedAt = items[0].ObservedAt
	for index := 1; index < len(items); index++ {
		previous, current := items[index-1], items[index]
		intervals[index] = TrafficPoint{ObservedAt: current.ObservedAt,
			BytesReceived: counterDelta(previous.BytesReceived, current.BytesReceived),
			BytesSent:     counterDelta(previous.BytesSent, current.BytesSent)}
	}
	return intervals
}

func counterDelta(previous, current uint64) uint64 {
	if current < previous {
		return current
	}
	return current - previous
}

var _ NodeMetricsAnalyticsReader = (*PostgresReader)(nil)
