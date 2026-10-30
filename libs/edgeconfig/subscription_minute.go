package edgeconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
)

// Per subscription minute statistics (ADR 0012 §6.2, ML-07): cdnca_limits
// counts them per (subscription, minute) on a dynamic routing node, the agent
// takes the finished minutes from the control socket and sends each one as a
// telemetry record (TELEMETRY_KIND_SUBSCRIPTION_MINUTE_V1) bound to one site
// of the subscription; the leaf control plane stores them in ClickHouse
// (subscription_minutes_v1) and aggregates them per subscription (ML-08).
const (
	SubscriptionMinuteType = "subscription_minute.v1"
	// SubscriptionMinuteNodeSchema is what cdnca_limits answers on
	// GET /subscription-minutes.
	SubscriptionMinuteNodeSchema = "cdnca.edge.subscription-minute/v1"
	// SubscriptionMinuteMaxValue bounds every counter (2^53-1: exact in the
	// node's Lua numbers and in JSON).
	SubscriptionMinuteMaxValue = 1<<53 - 1
)

// SubscriptionMinuteCounters are one subscription's maxima of a minute on one
// node: requests in flight (concurrent_requests), TCP connections
// (concurrent_connections), new connections per second, requests per
// second, and the bytes sent with their peak bit/s (bytes are counted in the
// second a response ends).
type SubscriptionMinuteCounters struct {
	MaxRequests    int64 `json:"max_requests"`
	MaxConnections int64 `json:"max_connections"`
	MaxNewCPS      int64 `json:"max_new_cps"`
	MaxQPS         int64 `json:"max_qps"`
	BytesOut       int64 `json:"bytes_out"`
	PeakBPS        int64 `json:"peak_bps"`
}

// SubscriptionMinuteEvent is one record. SiteID / ConfigVersionID name the
// site the record is bound to (any active site of the subscription: the
// gateway checks the subscription against that site's authorization);
// PackageSubscriptionID always equals SubscriptionID once the gateway bound
// it, InstallationID is the gateway's.
type SubscriptionMinuteEvent struct {
	MetricVersion         uint16    `json:"metric_version"`
	EventID               string    `json:"event_id"`
	Minute                time.Time `json:"minute"`
	TenantID              string    `json:"tenant_id"`
	SubscriptionID        string    `json:"subscription_id"`
	PackageSubscriptionID string    `json:"package_subscription_id"`
	SiteID                string    `json:"site_id"`
	NodeID                string    `json:"node_id"`
	InstallationID        string    `json:"installation_id"`
	ConfigVersionID       string    `json:"config_version_id"`
	SubscriptionMinuteCounters
}

type SubscriptionMinuteEnvelope struct {
	SchemaVersion         uint16                    `json:"schema_version"`
	Type                  string                    `json:"type"`
	MessageID             string                    `json:"message_id"`
	ProducedAt            time.Time                 `json:"produced_at"`
	TenantID              string                    `json:"tenant_id"`
	InstallationID        string                    `json:"installation_id"`
	NodeID                string                    `json:"node_id"`
	PackageSubscriptionID string                    `json:"package_subscription_id"`
	Events                []SubscriptionMinuteEvent `json:"events"`
}

// SubscriptionMinuteEventID is deterministic per (node, subscription,
// minute): a minute read twice (agent restart before the spool write) is
// one record everywhere.
func SubscriptionMinuteEventID(nodeID, subscriptionID string, minute time.Time) string {
	encoded, _ := json.Marshal([]any{strings.ToLower(nodeID), strings.ToLower(subscriptionID), minute.UTC().Unix()})
	digest := sha256.Sum256(append([]byte("cdnca.subscription-minute.event/v1\x00"), encoded...))
	return "subscription_minute_" + hex.EncodeToString(digest[:])
}

// SubscriptionMinuteMessageID covers everything but the gateway's binding.
func SubscriptionMinuteMessageID(envelope SubscriptionMinuteEnvelope) string {
	envelope.MessageID, envelope.InstallationID, envelope.PackageSubscriptionID = "", "", ""
	envelope.Events = append([]SubscriptionMinuteEvent(nil), envelope.Events...)
	for i := range envelope.Events {
		envelope.Events[i].InstallationID, envelope.Events[i].PackageSubscriptionID = "", ""
	}
	encoded, _ := json.Marshal(envelope)
	digest := sha256.Sum256(append([]byte("cdnca.subscription-minute.message/v1\x00"), encoded...))
	return "subscription_minute_message_" + hex.EncodeToString(digest[:])
}

// ValidSubscriptionMinuteEvent checks the node's fields (not the binding).
func ValidSubscriptionMinuteEvent(event SubscriptionMinuteEvent) bool {
	if event.MetricVersion != 1 || event.Minute.IsZero() || event.Minute.Location() != time.UTC ||
		!event.Minute.Equal(event.Minute.Truncate(time.Minute)) ||
		event.EventID != SubscriptionMinuteEventID(event.NodeID, event.SubscriptionID, event.Minute) {
		return false
	}
	for _, value := range []string{event.TenantID, event.SubscriptionID, event.SiteID, event.NodeID, event.ConfigVersionID} {
		if !uuidPattern.MatchString(value) || value == "00000000-0000-0000-0000-000000000000" || value != strings.ToLower(value) {
			return false
		}
	}
	return event.SubscriptionMinuteCounters.Valid()
}

func (c SubscriptionMinuteCounters) Valid() bool {
	for _, value := range []int64{c.MaxRequests, c.MaxConnections, c.MaxNewCPS, c.MaxQPS, c.BytesOut, c.PeakBPS} {
		if value < 0 || value > SubscriptionMinuteMaxValue {
			return false
		}
	}
	return true
}
