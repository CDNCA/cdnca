package analytics

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// subscription_minute.v1 (ADR 0012 §6.2, ML-07): one market subscription's
// minute counters on one node, bound by the gateway to the subscription and
// installation. Stored in ClickHouse subscription_minutes_v1 (migration 024);
// the per subscription aggregation is ML-08's.

const (
	SubscriptionMinuteEnvelopeType = edgeconfig.SubscriptionMinuteType
	insertSubscriptionMinutesSQL   = "INSERT INTO subscription_minutes_v1 FORMAT JSONEachRow"
)

// SubscriptionMinute is a decoded record.
type SubscriptionMinute struct {
	EventID         string
	Minute          time.Time
	TenantID        string
	SubscriptionID  string
	SiteID          string
	NodeID          string
	InstallationID  string
	ConfigVersionID string
	edgeconfig.SubscriptionMinuteCounters
}

// SubscriptionMinuteWriter is implemented by the ClickHouse client; the
// ingest writer need not implement it (then subscription minutes fail
// permanently and are isolated).
type SubscriptionMinuteWriter interface {
	WriteSubscriptionMinutes(context.Context, string, []SubscriptionMinute) error
}

func (decoder *IngestDecoder) decodeSubscriptionMinute(payload []byte, nodeID, brokerMessageID string) (DecodedIngest, error) {
	var envelope edgeconfig.SubscriptionMinuteEnvelope
	if err := decodeStrictJSON(payload, &envelope); err != nil {
		return DecodedIngest{}, rejection(RejectInvalidJSON)
	}
	if envelope.SchemaVersion != IngestSchemaVersion || len(envelope.Events) != 1 {
		return DecodedIngest{}, rejection(RejectBatchLimit)
	}
	event := envelope.Events[0]
	decoded := DecodedIngest{
		SchemaVersion: envelope.SchemaVersion, Kind: envelope.Type, MessageID: envelope.MessageID,
		ProducedAt: envelope.ProducedAt, TenantID: envelope.TenantID, InstallationID: envelope.InstallationID,
		PackageSubscriptionID: envelope.PackageSubscriptionID, NodeID: envelope.NodeID, PayloadDigest: sha256Payload(payload),
		SubscriptionMinutes: []SubscriptionMinute{{EventID: event.EventID, Minute: event.Minute, TenantID: event.TenantID,
			SubscriptionID: event.SubscriptionID, SiteID: event.SiteID, NodeID: event.NodeID, InstallationID: event.InstallationID,
			ConfigVersionID: event.ConfigVersionID, SubscriptionMinuteCounters: event.SubscriptionMinuteCounters}},
	}
	if err := decoder.validate(decoded, nodeID, brokerMessageID); err != nil {
		return DecodedIngest{}, err
	}
	// Bound by the gateway: the subscription is the package subscription,
	// the installation the envelope's.
	if !edgeconfig.ValidSubscriptionMinuteEvent(event) || event.PackageSubscriptionID != event.SubscriptionID ||
		event.InstallationID != envelope.InstallationID || !sameClaim(decoded, event.TenantID, event.PackageSubscriptionID, event.NodeID) ||
		envelope.MessageID != edgeconfig.SubscriptionMinuteMessageID(envelope) || !envelope.ProducedAt.Equal(event.Minute) ||
		!validEventTime(event.Minute, decoded.ProducedAt, decoder.now().UTC(), decoder.maxFutureSkew, 30*24*time.Hour) {
		return DecodedIngest{}, rejection(RejectInvalidEvent)
	}
	return decoded, nil
}

func canonicalSubscriptionMinutesV1(minutes []SubscriptionMinute) []any {
	values := make([]any, 0, len(minutes))
	for _, m := range minutes {
		values = append(values, map[string]any{
			"event_id": m.EventID, "minute": m.Minute.UTC().Format(time.RFC3339Nano), "tenant_id": m.TenantID,
			"subscription_id": m.SubscriptionID, "site_id": m.SiteID, "node_id": m.NodeID, "installation_id": m.InstallationID,
			"config_version_id": m.ConfigVersionID, "max_requests": m.MaxRequests, "max_connections": m.MaxConnections,
			"max_new_cps": m.MaxNewCPS, "max_qps": m.MaxQPS, "bytes_out": m.BytesOut, "peak_bps": m.PeakBPS,
		})
	}
	return values
}

type subscriptionMinuteRow struct {
	SubscriptionID  string `json:"package_subscription_id"`
	Minute          string `json:"minute"`
	NodeID          string `json:"node_id"`
	TenantID        string `json:"tenant_id"`
	SiteID          string `json:"site_id"`
	InstallationID  string `json:"installation_id"`
	ConfigVersionID string `json:"config_version_id"`
	EventID         string `json:"event_id"`
	MaxRequests     int64  `json:"max_requests"`
	MaxConnections  int64  `json:"max_connections"`
	MaxNewCPS       int64  `json:"max_new_cps"`
	MaxQPS          int64  `json:"max_qps"`
	BytesOut        int64  `json:"bytes_out"`
	PeakBPS         int64  `json:"peak_bps"`
}

// WriteSubscriptionMinutes inserts with the receipt's deduplication token;
// the table (ReplacingMergeTree on subscription, minute, node) also keeps
// one row per event however often it is delivered.
func (client *Client) WriteSubscriptionMinutes(ctx context.Context, batchID string, minutes []SubscriptionMinute) error {
	if client == nil || !validBatchID(batchID) || len(minutes) == 0 || len(minutes) > client.maxBatchEvents {
		return ErrInvalidInput
	}
	var body bytes.Buffer
	body.WriteString(insertSubscriptionMinutesSQL)
	body.WriteByte('\n')
	encoder := json.NewEncoder(&body)
	for _, m := range minutes {
		if !validUUID(m.SubscriptionID) || !validUUID(m.NodeID) || !validBatchID(m.InstallationID) || !m.SubscriptionMinuteCounters.Valid() {
			return ErrInvalidInput
		}
		row := subscriptionMinuteRow{SubscriptionID: strings.ToLower(m.SubscriptionID), Minute: m.Minute.UTC().Format("2006-01-02 15:04:05"),
			NodeID: m.NodeID, TenantID: m.TenantID, SiteID: m.SiteID, InstallationID: m.InstallationID, ConfigVersionID: m.ConfigVersionID,
			EventID: m.EventID, MaxRequests: m.MaxRequests, MaxConnections: m.MaxConnections, MaxNewCPS: m.MaxNewCPS,
			MaxQPS: m.MaxQPS, BytesOut: m.BytesOut, PeakBPS: m.PeakBPS}
		if encoder.Encode(row) != nil {
			return ErrInvalidInput
		}
	}
	parameters := url.Values{
		"insert_deduplicate":               {"1"},
		"insert_deduplication_token":       {batchID},
		"input_format_skip_unknown_fields": {"0"},
	}
	err := client.execute(ctx, client.writeTimeout, body.Bytes(), parameters, false, nil)
	if errors.Is(err, ErrTransport) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return errors.Join(ErrIngestWriteOutcomeUnknown, err)
	}
	return err
}
