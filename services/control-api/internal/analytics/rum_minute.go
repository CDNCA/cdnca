package analytics

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// rum_minute.v1: one site's real user monitoring minute on
// one node, bound by the gateway to the installation (and the site's package
// subscription when it has one). Stored in ClickHouse rum_minutes_v1 /
// rum_errors_v1 (migration 034); read by the 真实用户体验 report.

const (
	RUMMinuteEnvelopeType = edgeconfig.RUMMinuteType
	insertRUMMinutesSQL   = "INSERT INTO rum_minutes_v1 FORMAT JSONEachRow"
	insertRUMErrorsSQL    = "INSERT INTO rum_errors_v1 FORMAT JSONEachRow"
)

// RUMMinute is a decoded record.
type RUMMinute struct {
	EventID, TenantID, SiteID, NodeID, InstallationID, ConfigVersionID, PackageSubscriptionID string
	Minute                                                                                    time.Time
	edgeconfig.RUMMinuteData
}

// RUMMinuteWriter is implemented by the ClickHouse client; an ingest writer
// without it fails RUM minutes permanently (isolated).
type RUMMinuteWriter interface {
	WriteRUMMinutes(context.Context, string, []RUMMinute) error
}

func (decoder *IngestDecoder) decodeRUMMinute(payload []byte, nodeID, brokerMessageID string) (DecodedIngest, error) {
	var envelope edgeconfig.RUMMinuteEnvelope
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
		RUMMinutes: []RUMMinute{{EventID: event.EventID, Minute: event.Minute, TenantID: event.TenantID, SiteID: event.SiteID,
			NodeID: event.NodeID, InstallationID: event.InstallationID, ConfigVersionID: event.ConfigVersionID,
			PackageSubscriptionID: event.PackageSubscriptionID, RUMMinuteData: event.RUMMinuteData}},
	}
	if err := decoder.validate(decoded, nodeID, brokerMessageID); err != nil {
		return DecodedIngest{}, err
	}
	if !edgeconfig.ValidRUMMinuteEvent(event) || event.InstallationID != envelope.InstallationID ||
		!sameClaim(decoded, event.TenantID, event.PackageSubscriptionID, event.NodeID) ||
		envelope.MessageID != edgeconfig.RUMMinuteMessageID(envelope) || !envelope.ProducedAt.Equal(event.Minute) ||
		!validEventTime(event.Minute, decoded.ProducedAt, decoder.now().UTC(), decoder.maxFutureSkew, 30*24*time.Hour) {
		return DecodedIngest{}, rejection(RejectInvalidEvent)
	}
	return decoded, nil
}

// canonicalRUMMinutesV1 is the history digest form (generic JSON values).
func canonicalRUMMinutesV1(minutes []RUMMinute) []any {
	values := make([]any, 0, len(minutes))
	for _, m := range minutes {
		var data any
		encoded, _ := json.Marshal(m.RUMMinuteData)
		decoder := json.NewDecoder(bytes.NewReader(encoded))
		decoder.UseNumber()
		_ = decoder.Decode(&data)
		values = append(values, map[string]any{
			"event_id": m.EventID, "minute": m.Minute.UTC().Format(time.RFC3339Nano), "tenant_id": m.TenantID,
			"site_id": m.SiteID, "node_id": m.NodeID, "installation_id": m.InstallationID,
			"config_version_id": m.ConfigVersionID, "package_subscription_id": m.PackageSubscriptionID, "data": data,
		})
	}
	return values
}

type rumMinuteRow struct {
	TenantID        string                  `json:"tenant_id"`
	SiteID          string                  `json:"site_id"`
	Minute          string                  `json:"minute"`
	NodeID          string                  `json:"node_id"`
	Dimension       string                  `json:"dimension"`
	Value           string                  `json:"value"`
	Views           int64                   `json:"views"`
	LCP             edgeconfig.RUMHistogram `json:"lcp"`
	INP             edgeconfig.RUMHistogram `json:"inp"`
	CLS             edgeconfig.RUMHistogram `json:"cls"`
	FCP             edgeconfig.RUMHistogram `json:"fcp"`
	TTFB            edgeconfig.RUMHistogram `json:"ttfb"`
	Dropped         int64                   `json:"dropped"`
	EventID         string                  `json:"event_id"`
	InstallationID  string                  `json:"installation_id"`
	ConfigVersionID string                  `json:"config_version_id"`
}

type rumErrorRow struct {
	TenantID string `json:"tenant_id"`
	SiteID   string `json:"site_id"`
	Minute   string `json:"minute"`
	NodeID   string `json:"node_id"`
	Kind     string `json:"kind"`
	Element  string `json:"element"`
	Target   string `json:"target"`
	Status   int    `json:"status"`
	Count    int64  `json:"count"`
	EventID  string `json:"event_id"`
}

func histogramOrEmpty(histogram edgeconfig.RUMHistogram) edgeconfig.RUMHistogram {
	if histogram == nil {
		return edgeconfig.RUMHistogram{}
	}
	return histogram
}

// WriteRUMMinutes inserts the series rows, then the error rows, each with
// the receipt's deduplication token (per table, so a retry after a partial
// write inserts the missing table only); the ReplacingMergeTree keys keep
// one row per event however often it is delivered. The minute's dropped
// count goes on its "all" row.
func (client *Client) WriteRUMMinutes(ctx context.Context, batchID string, minutes []RUMMinute) error {
	if client == nil || !validBatchID(batchID) || len(minutes) == 0 || len(minutes) > client.maxBatchEvents {
		return ErrInvalidInput
	}
	var series, errorsBody bytes.Buffer
	series.WriteString(insertRUMMinutesSQL + "\n")
	errorsBody.WriteString(insertRUMErrorsSQL + "\n")
	seriesEncoder, errorEncoder := json.NewEncoder(&series), json.NewEncoder(&errorsBody)
	errorRows := 0
	for _, m := range minutes {
		if !validUUID(m.SiteID) || !validUUID(m.NodeID) || !validBatchID(m.InstallationID) || !m.RUMMinuteData.Valid() {
			return ErrInvalidInput
		}
		minute := m.Minute.UTC().Format("2006-01-02 15:04:05")
		for _, item := range m.Series {
			row := rumMinuteRow{TenantID: m.TenantID, SiteID: m.SiteID, Minute: minute, NodeID: m.NodeID,
				Dimension: item.Dimension, Value: item.Value, Views: item.Views,
				LCP: histogramOrEmpty(item.Histograms["lcp"]), INP: histogramOrEmpty(item.Histograms["inp"]),
				CLS: histogramOrEmpty(item.Histograms["cls"]), FCP: histogramOrEmpty(item.Histograms["fcp"]),
				TTFB: histogramOrEmpty(item.Histograms["ttfb"]), EventID: m.EventID, InstallationID: m.InstallationID,
				ConfigVersionID: m.ConfigVersionID}
			if item.Dimension == "all" {
				row.Dropped = m.Dropped
			}
			if seriesEncoder.Encode(row) != nil {
				return ErrInvalidInput
			}
		}
		for _, item := range m.Errors {
			if errorEncoder.Encode(rumErrorRow{TenantID: m.TenantID, SiteID: m.SiteID, Minute: minute, NodeID: m.NodeID,
				Kind: item.Kind, Element: item.Element, Target: item.Target, Status: item.Status, Count: item.Count,
				EventID: m.EventID}) != nil {
				return ErrInvalidInput
			}
			errorRows++
		}
	}
	parameters := url.Values{
		"insert_deduplicate":               {"1"},
		"insert_deduplication_token":       {batchID},
		"input_format_skip_unknown_fields": {"0"},
	}
	bodies := [][]byte{series.Bytes()}
	if errorRows > 0 {
		bodies = append(bodies, errorsBody.Bytes())
	}
	for _, body := range bodies {
		err := client.execute(ctx, client.writeTimeout, body, parameters, false, nil)
		if errors.Is(err, ErrTransport) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return errors.Join(ErrIngestWriteOutcomeUnknown, err)
		}
		if err != nil {
			return err
		}
	}
	return nil
}
