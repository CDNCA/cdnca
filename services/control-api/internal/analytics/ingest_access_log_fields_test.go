package analytics

import (
	"context"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

type accessFieldRecorder struct {
	IngestWriter
	access []AccessEvent
}

func (recorder *accessFieldRecorder) WriteAccessEvents(_ context.Context, _ string, events []AccessEvent) error {
	recorder.access = events
	return nil
}

type fixedAccessLogFields edgeconfig.AccessLogFields

func (value fixedAccessLogFields) AccessLogFields(context.Context) edgeconfig.AccessLogFields {
	return edgeconfig.AccessLogFields(value)
}

type countingGeo struct{ calls int }

func (geo *countingGeo) LookupClientGeo(_ context.Context, addresses []string) map[string]ClientGeo {
	geo.calls++
	result := map[string]ClientGeo{}
	for _, address := range addresses {
		result[address] = ClientGeo{Country: "CN", Province: "110000", Carrier: "carrier:cn-telecom"}
	}
	return result
}

// fix-logfields: an optional scalar field the platform does not record is
// not written to ClickHouse; the basic fields and the headers pass through.
func TestGeoEnrichingWriterClearsUnrecordedFields(t *testing.T) {
	timing, ja4 := uint64(1200), "t13d1516h2_8daaf6152771_02713d6af862"
	event := validAccessEvent("fields")
	event.ClientBrowser, event.ClientOS = "chrome", "windows"
	event.OriginConnectUS, event.OriginFirstByteUS, event.OriginTotalUS = &timing, &timing, &timing
	event.JA4 = &ja4
	event.RequestHeaders = map[string]string{"Referer": "https://example.test/"}

	recorder, geo := &accessFieldRecorder{}, &countingGeo{}
	writer := GeoEnrichingWriter{Writer: recorder, Lookup: geo, Fields: fixedAccessLogFields{Fields: []string{"referer"}}}
	if err := writer.WriteAccessEvents(t.Context(), "batch", []AccessEvent{event}); err != nil {
		t.Fatal(err)
	}
	got := recorder.access[0]
	if got.ClientBrowser != "" || got.ClientOS != "" || got.CountryCode != "" || got.Province != "" || got.Carrier != "" ||
		got.OriginTotalUS != nil || got.JA4 != nil || geo.calls != 0 {
		t.Fatalf("unrecorded fields written: %+v (geo lookups %d)", got, geo.calls)
	}
	if got.Host != event.Host || got.StatusCode != event.StatusCode || got.RequestHeaders["Referer"] == "" {
		t.Fatalf("basic fields or headers lost: %+v", got)
	}
	if event.ClientBrowser != "chrome" || event.JA4 == nil {
		t.Fatal("the caller's events were modified")
	}

	writer.Fields = fixedAccessLogFields(edgeconfig.EffectiveAccessLogFields(nil))
	if err := writer.WriteAccessEvents(t.Context(), "batch", []AccessEvent{event}); err != nil {
		t.Fatal(err)
	}
	got = recorder.access[0]
	if got.ClientBrowser != "chrome" || got.CountryCode != "CN" || got.OriginTotalUS == nil || got.JA4 == nil || geo.calls != 1 {
		t.Fatalf("the default selection lost a field: %+v", got)
	}
}

// fix-decide1027b 第1项：拦截页标记是可选字段 block_page。未勾选时入库前
// 把 Blocked 清成 false，套餐计费（NOT (exclude_blocked AND blocked)）
// 因而把拦截页流量计入套餐；勾选（默认）时原样保留。
func TestGeoEnrichingWriterBlockPageField(t *testing.T) {
	event := validAccessEvent("block-page")
	event.Blocked = true
	recorder := &accessFieldRecorder{}
	writer := GeoEnrichingWriter{Writer: recorder, Fields: fixedAccessLogFields{Fields: []string{edgeconfig.AccessLogFieldReferer}}}
	if err := writer.WriteAccessEvents(t.Context(), "batch", []AccessEvent{event}); err != nil {
		t.Fatal(err)
	}
	if recorder.access[0].Blocked {
		t.Fatal("block_page not selected but blocked kept")
	}
	writer.Fields = fixedAccessLogFields(edgeconfig.EffectiveAccessLogFields(nil))
	if err := writer.WriteAccessEvents(t.Context(), "batch", []AccessEvent{event}); err != nil {
		t.Fatal(err)
	}
	if !recorder.access[0].Blocked {
		t.Fatal("default selection cleared blocked")
	}
}
