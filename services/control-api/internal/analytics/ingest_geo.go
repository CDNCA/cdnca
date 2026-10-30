package analytics

import (
	"context"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// ClientGeo is what the control plane's IP library says about a client
// address: ISO country, GB/T 2260 province code and the carrier tag
// (carrier:cn-telecom ...). Empty fields are unknown.
type ClientGeo struct {
	Country, Province, Carrier string
}

// ClientGeoLookup answers client addresses (missing entries are unknown).
type ClientGeoLookup interface {
	LookupClientGeo(ctx context.Context, addresses []string) map[string]ClientGeo
}

// GeoEnrichingWriter fills the country, province and carrier of access and
// security events from the control plane's IP library before they are
// written, so region/province/carrier reports have data for every node (nodes
// do not send them). Values a node did send are kept. A lookup failure leaves
// the fields empty; it never fails the write.
//
// Fields (system configuration access_log_fields, fix-logfields) clears the
// optional scalar fields of access events the platform does not record, so
// ClickHouse does not store them; nil records every field. Header fields are
// already limited on the node (the capture allowlist).
type GeoEnrichingWriter struct {
	Writer IngestWriter
	Lookup ClientGeoLookup
	Fields AccessLogFieldSource
}

// AccessLogFieldSource answers the platform's effective access log fields.
type AccessLogFieldSource interface {
	AccessLogFields(ctx context.Context) edgeconfig.AccessLogFields
}

// clearUnrecordedAccessFields empties the optional scalar fields not in
// fields (headers are the node's to limit).
func clearUnrecordedAccessFields(fields edgeconfig.AccessLogFields, event *AccessEvent) {
	if !fields.Has(edgeconfig.AccessLogFieldClientFamily) {
		event.ClientBrowser, event.ClientOS = "", ""
	}
	if !fields.Has(edgeconfig.AccessLogFieldClientGeo) {
		event.CountryCode, event.Province, event.Carrier = "", "", ""
	}
	if !fields.Has(edgeconfig.AccessLogFieldOriginTiming) {
		event.OriginConnectUS, event.OriginFirstByteUS, event.OriginTotalUS = nil, nil, nil
	}
	if !fields.Has(edgeconfig.AccessLogFieldJA4) {
		event.JA4 = nil
	}
	if !fields.Has(edgeconfig.AccessLogFieldUpstreamAddr) {
		event.UpstreamAddr = ""
	}
	// Not recorded: package billing counts the block page as traffic.
	if !fields.Has(edgeconfig.AccessLogFieldBlockPage) {
		event.Blocked = false
	}
}

// WriteSubscriptionMinutes passes through (no client addresses).
func (writer GeoEnrichingWriter) WriteSubscriptionMinutes(ctx context.Context, batchID string, minutes []SubscriptionMinute) error {
	inner, ok := writer.Writer.(SubscriptionMinuteWriter)
	if !ok {
		return ErrInvalidInput
	}
	return inner.WriteSubscriptionMinutes(ctx, batchID, minutes)
}

func (writer GeoEnrichingWriter) WriteAccessEvents(ctx context.Context, batchID string, events []AccessEvent) error {
	var fields *edgeconfig.AccessLogFields
	if writer.Fields != nil && len(events) > 0 {
		value := writer.Fields.AccessLogFields(ctx)
		fields = &value
		cleared := make([]AccessEvent, len(events))
		copy(cleared, events)
		for index := range cleared {
			clearUnrecordedAccessFields(value, &cleared[index])
		}
		events = cleared
	}
	if writer.Lookup != nil && len(events) > 0 && (fields == nil || fields.Has(edgeconfig.AccessLogFieldClientGeo)) {
		addresses := make([]string, len(events))
		for index := range events {
			addresses[index] = events[index].ClientIP
		}
		geo := writer.Lookup.LookupClientGeo(ctx, addresses)
		enriched := make([]AccessEvent, len(events))
		copy(enriched, events)
		for index := range enriched {
			fillClientGeo(geo[enriched[index].ClientIP], &enriched[index].CountryCode, &enriched[index].Province, &enriched[index].Carrier)
		}
		events = enriched
	}
	return writer.Writer.WriteAccessEvents(ctx, batchID, events)
}

func (writer GeoEnrichingWriter) WriteSecurityEvents(ctx context.Context, batchID string, events []SecurityEvent) error {
	if writer.Lookup != nil && len(events) > 0 {
		addresses := make([]string, len(events))
		for index := range events {
			addresses[index] = events[index].ClientIP
		}
		geo := writer.Lookup.LookupClientGeo(ctx, addresses)
		enriched := make([]SecurityEvent, len(events))
		copy(enriched, events)
		for index := range enriched {
			fillClientGeo(geo[enriched[index].ClientIP], &enriched[index].CountryCode, &enriched[index].Province, &enriched[index].Carrier)
		}
		events = enriched
	}
	return writer.Writer.WriteSecurityEvents(ctx, batchID, events)
}

func fillClientGeo(geo ClientGeo, country, province, carrier *string) {
	if *country == "" && len(geo.Country) <= 8 {
		*country = geo.Country
	}
	if *province == "" && validProvince(geo.Province) {
		*province = geo.Province
	}
	if *carrier == "" && len(geo.Carrier) <= 128 {
		*carrier = geo.Carrier
	}
}
