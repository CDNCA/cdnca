package eventspool

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseSourceLineBindsTrustedIdentity(t *testing.T) {
	event := sourceAccess(tenantTwo)
	event.NodeID = "55555555-5555-4555-8555-555555555555"
	event.SiteID = "66666666-6666-4666-8666-666666666666"
	event.ConfigVersionID = "forged-config"
	bound, err := ParseSourceLineBound(sourceLine(t, event), CapturePolicy{}, TrustedIdentity{
		EnrollmentNodeID: nodeOne,
		TenantID:         tenantOne,
		SiteID:           siteOne,
		ConfigVersionID:  "cfg-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if bound.TenantID != tenantOne || bound.SiteID != siteOne || bound.NodeID != nodeOne || bound.ConfigVersionID != "cfg-1" {
		t.Fatalf("bound identity = tenant %q site %q node %q config %q", bound.TenantID, bound.SiteID, bound.NodeID, bound.ConfigVersionID)
	}
	if _, err := ParseSourceLineBound(sourceLine(t, event), CapturePolicy{}, TrustedIdentity{
		EnrollmentNodeID: nodeOne, TenantID: tenantOne, ConfigVersionID: "cfg-1",
	}); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("incomplete trusted identity error = %v", err)
	}
}

func TestBuildPublicationsMatchesAnalyticsV2Contract(t *testing.T) {
	config := testConfig(t.TempDir())
	spool := newTestSpool(t, config)
	access := pendingAccess("evt-access", tenantOne)
	access.RequestHeaders = map[string]string{"Authorization": redactedValue, "X-Request-ID": "request-123"}
	access.ResponseHeaders = map[string]string{"Set-Cookie": redactedValue, "X-Cache": "HIT"}
	access.RequestBody = map[string]any{"password": redactedValue, "profile": map[string]any{"name": "alice"}}
	access.ResponseBody = map[string]any{"token": redactedValue, "result": []any{"one", "two"}}
	security := pendingAccess("evt-security", tenantOne)
	security.Type = EventSecurity
	security.ListenPort, security.Protocol, security.RequestClass = 443, "https", "standard"
	security.CacheStatus = ""
	security.DurationUS = 0
	security.SecurityType, security.Action, security.Severity = "waf", "block", "high"
	security.RequestHeaders = map[string]string{"Authorization": redactedValue, "X-WAF-Request": "observed"}
	security.ResponseHeaders = map[string]string{"Set-Cookie": redactedValue, "X-WAF-Response": "blocked"}
	security.RequestBody = map[string]any{"api_key": redactedValue, "attack": map[string]any{"kind": "sqli"}}
	security.ResponseBody = map[string]any{"secret": redactedValue, "decision": []any{"block", "audit"}}
	if _, err := spool.AppendBatch(context.Background(), []Envelope{access, security}); err != nil {
		t.Fatal(err)
	}
	records, err := spool.nextBatch(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	publications, err := buildPublications(records)
	if err != nil || len(publications) != 2 {
		t.Fatalf("publications = %#v, %v", publications, err)
	}
	if publications[0].Subject != analyticsSubjectPrefix+"."+nodeOne || publications[0].MessageID == "" ||
		publications[0].FirstSequence != 1 || publications[0].LastSequence != 1 {
		t.Fatalf("access publication metadata = %#v", publications[0])
	}
	var accessEnvelope analyticsAccessEnvelope
	if err := json.Unmarshal(publications[0].Payload, &accessEnvelope); err != nil {
		t.Fatal(err)
	}
	if accessEnvelope.SchemaVersion != 2 || accessEnvelope.Type != "access.v2" || accessEnvelope.MessageID != publications[0].MessageID ||
		accessEnvelope.InstallationID != "" ||
		accessEnvelope.TenantID != tenantOne || accessEnvelope.NodeID != nodeOne || len(accessEnvelope.Events) != 1 ||
		accessEnvelope.Events[0].MetricVersion != 1 || accessEnvelope.Events[0].EventID != "evt-access" ||
		accessEnvelope.Events[0].InstallationID != "" {
		t.Fatalf("access envelope = %#v", accessEnvelope)
	}
	accessEvent := accessEnvelope.Events[0]
	if !reflect.DeepEqual(accessEvent.RequestHeaders, access.RequestHeaders) ||
		!reflect.DeepEqual(accessEvent.ResponseHeaders, access.ResponseHeaders) ||
		!reflect.DeepEqual(accessEvent.RequestBody, access.RequestBody) ||
		!reflect.DeepEqual(accessEvent.ResponseBody, access.ResponseBody) {
		t.Fatalf("access capture changed: got %#v want %#v", accessEvent, access)
	}
	var securityEnvelope analyticsSecurityEnvelope
	if err := json.Unmarshal(publications[1].Payload, &securityEnvelope); err != nil {
		t.Fatal(err)
	}
	if securityEnvelope.SchemaVersion != 2 || securityEnvelope.Type != "security.v2" || securityEnvelope.InstallationID != "" ||
		len(securityEnvelope.Events) != 1 || securityEnvelope.Events[0].InstallationID != "" ||
		securityEnvelope.Events[0].EventType != "waf" || securityEnvelope.Events[0].EventID != "evt-security" ||
		securityEnvelope.Events[0].ListenPort != 443 || securityEnvelope.Events[0].Protocol != "https" ||
		securityEnvelope.Events[0].Method != "GET" || securityEnvelope.Events[0].RequestClass != "standard" {
		t.Fatalf("security envelope = %#v", securityEnvelope)
	}
	securityEvent := securityEnvelope.Events[0]
	if !reflect.DeepEqual(securityEvent.RequestHeaders, security.RequestHeaders) ||
		!reflect.DeepEqual(securityEvent.ResponseHeaders, security.ResponseHeaders) ||
		!reflect.DeepEqual(securityEvent.RequestBody, security.RequestBody) ||
		!reflect.DeepEqual(securityEvent.ResponseBody, security.ResponseBody) {
		t.Fatalf("security capture changed: got %#v want %#v", securityEvent, security)
	}
	rebuilt, err := buildPublications(records)
	if err != nil || !reflect.DeepEqual(publications, rebuilt) {
		t.Fatal("publication retry must preserve subject, message ID, boundaries, and payload bytes")
	}
}

func TestBuildPublicationsPreservesAccessListenPortAndDimension(t *testing.T) {
	spool := newTestSpool(t, testConfig(t.TempDir()))
	first := pendingAccess("evt-port-443", tenantOne)
	first.ListenPort = 443
	second := pendingAccess("evt-port-8443", tenantOne)
	second.ListenPort = 8443
	if _, err := spool.AppendBatch(context.Background(), []Envelope{first, second}); err != nil {
		t.Fatal(err)
	}
	records, err := spool.nextBatch(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	publications, err := buildPublications(records)
	if err != nil {
		t.Fatal(err)
	}
	if len(publications) != 2 {
		t.Fatalf("publication count = %d, want one per listen-port dimension", len(publications))
	}
	for index, want := range []uint16{443, 8443} {
		var payload struct {
			Events []struct {
				ListenPort uint16 `json:"listen_port"`
			} `json:"events"`
		}
		if err := json.Unmarshal(publications[index].Payload, &payload); err != nil {
			t.Fatal(err)
		}
		if len(payload.Events) != 1 || payload.Events[0].ListenPort != want {
			t.Fatalf("publication %d listen port = %#v, want %d", index, payload.Events, want)
		}
	}
}

func TestBuildPublicationsKeepsEventAndPayloadLimits(t *testing.T) {
	records := make([]Record, maxAnalyticsEnvelopeEvents+1)
	for index := range records {
		records[index] = publicationRecord(index, 0)
	}
	publications, err := buildPublications(records)
	if err != nil {
		t.Fatal(err)
	}
	if len(publications) != 2 || publications[0].EventCount != maxAnalyticsEnvelopeEvents || publications[1].EventCount != 1 {
		t.Fatalf("event-limit publications = %#v", publications)
	}

	largeRecords := []Record{publicationRecord(0, 600<<10), publicationRecord(1, 600<<10)}
	publications, err = buildPublications(largeRecords)
	if err != nil {
		t.Fatal(err)
	}
	if len(publications) != 2 {
		t.Fatalf("payload-limit publication count = %d, want 2", len(publications))
	}
	for index, publication := range publications {
		if len(publication.Payload) > maxAnalyticsEnvelopeBytes || publication.EventCount != 1 ||
			!ValidPublicationMessageID(publication) {
			t.Fatalf("payload-limit publication %d = %#v", index, publication)
		}
	}
}

func TestBuildPublicationsMessageIDBindsEveryEventFact(t *testing.T) {
	first := publicationRecord(0, 0)
	middle := publicationRecord(1, 0)
	last := publicationRecord(2, 0)
	changedMiddle := middle
	changedMiddle.envelope.StatusCode = 201

	baseline, err := encodePublication([]Record{first, middle, last})
	if err != nil {
		t.Fatal(err)
	}
	changed, err := encodePublication([]Record{first, changedMiddle, last})
	if err != nil {
		t.Fatal(err)
	}
	if string(baseline.Payload) == string(changed.Payload) {
		t.Fatal("changed event fact must change publication payload")
	}
	if baseline.MessageID == changed.MessageID {
		t.Fatalf("publication message ID ignored middle event fact: %q", baseline.MessageID)
	}
}

func publicationRecord(index, bodyBytes int) Record {
	event := pendingAccess(fmt.Sprintf("evt-publication-%04d", index), tenantOne)
	event.Sequence = uint64(index + 1)
	if bodyBytes > 0 {
		event.RequestBody = map[string]any{"payload": strings.Repeat("x", bodyBytes)}
	}
	return Record{
		Sequence: event.Sequence, EventID: event.EventID, TenantID: event.TenantID, NodeID: event.NodeID,
		Type: event.Type, OccurredAt: event.OccurredAt, envelope: event,
	}
}

func TestBuildPublicationsSplitsSiteAndConfigAuthorityTuples(t *testing.T) {
	spool := newTestSpool(t, testConfig(t.TempDir()))
	first := pendingAccess("evt-site-config-one", tenantOne)
	second := pendingAccess("evt-site-config-two", tenantOne)
	second.SiteID = "55555555-5555-4555-8555-555555555555"
	second.ConfigVersionID = "cfg-2"
	if _, err := spool.AppendBatch(context.Background(), []Envelope{first, second}); err != nil {
		t.Fatal(err)
	}
	records, err := spool.nextBatch(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	publications, err := buildPublications(records)
	if err != nil {
		t.Fatal(err)
	}
	if len(publications) != 2 {
		t.Fatalf("site/config tuples produced %d publications, want 2", len(publications))
	}
	want := []struct{ siteID, configID string }{{first.SiteID, first.ConfigVersionID}, {second.SiteID, second.ConfigVersionID}}
	for index, publication := range publications {
		var envelope analyticsAccessEnvelope
		if err := json.Unmarshal(publication.Payload, &envelope); err != nil {
			t.Fatal(err)
		}
		if len(envelope.Events) != 1 || envelope.Events[0].SiteID != want[index].siteID ||
			envelope.Events[0].ConfigVersion != want[index].configID {
			t.Fatalf("publication %d authority = %+v", index, envelope.Events)
		}
	}
	base := records[0]
	sameBoundary := base
	original, err := encodePublication([]Record{base})
	if err != nil {
		t.Fatal(err)
	}
	sameBoundary.envelope.SiteID = second.SiteID
	changed, err := encodePublication([]Record{sameBoundary})
	if err != nil {
		t.Fatal(err)
	}
	if original.MessageID == changed.MessageID {
		t.Fatal("site authority was not bound into the stable message ID")
	}
	sameBoundary = base
	sameBoundary.envelope.ConfigVersionID = second.ConfigVersionID
	changed, err = encodePublication([]Record{sameBoundary})
	if err != nil {
		t.Fatal(err)
	}
	if original.MessageID == changed.MessageID {
		t.Fatal("config authority was not bound into the stable message ID")
	}
}

type scriptedPublisher struct {
	responses []struct {
		ack int
		err error
	}
	calls int
}

func (publisher *scriptedPublisher) Publish(_ context.Context, publications []Publication) (PublishAck, error) {
	index := publisher.calls
	publisher.calls++
	if index >= len(publisher.responses) {
		return PublishAck{Acknowledged: len(publications)}, nil
	}
	response := publisher.responses[index]
	return PublishAck{Acknowledged: response.ack}, response.err
}

func TestFlushPersistsPartialAcknowledgement(t *testing.T) {
	spool := newTestSpool(t, testConfig(t.TempDir()))
	access := pendingAccess("evt-access", tenantOne)
	security := pendingAccess("evt-security", tenantOne)
	security.Type = EventSecurity
	security.ListenPort, security.Protocol, security.RequestClass = 443, "https", "standard"
	security.CacheStatus = ""
	security.SecurityType, security.Action, security.Severity = "waf", "block", "high"
	if _, err := spool.AppendBatch(context.Background(), []Envelope{access, security}); err != nil {
		t.Fatal(err)
	}
	publisher := &scriptedPublisher{responses: []struct {
		ack int
		err error
	}{{ack: 1, err: errors.New("connection lost after first durable ack")}}}
	result, err := spool.Flush(context.Background(), publisher, 10)
	if err == nil || result.Published != 1 || result.PublishedMessages != 1 || result.LastSequence != 1 {
		t.Fatalf("partial flush = %#v, %v", result, err)
	}
	stats, err := spool.Stats()
	if err != nil || stats.AckedSequence != 1 || stats.PendingEvents != 1 {
		t.Fatalf("partial ack stats = %#v, %v", stats, err)
	}
	if result, err = spool.Flush(context.Background(), publisher, 10); err != nil || result.Published != 1 || result.LastSequence != 2 {
		t.Fatalf("remaining flush = %#v, %v", result, err)
	}
}

func TestDrainUsesBoundedExponentialBackoff(t *testing.T) {
	spool := newTestSpool(t, testConfig(t.TempDir()))
	if _, err := spool.AppendBatch(context.Background(), []Envelope{pendingAccess("evt-retry", tenantOne)}); err != nil {
		t.Fatal(err)
	}
	publisher := &scriptedPublisher{responses: []struct {
		ack int
		err error
	}{
		{err: errors.New("offline")},
		{err: errors.New("still offline")},
	}}
	var delays []time.Duration
	result, err := spool.Drain(context.Background(), publisher, 10, RetryConfig{
		InitialBackoff: 100 * time.Millisecond, MaximumBackoff: 150 * time.Millisecond, MaximumAttempts: 3,
		Sleep: func(_ context.Context, delay time.Duration) error {
			delays = append(delays, delay)
			return nil
		},
	})
	if err != nil || result.Published != 1 || result.Attempts != 3 || !reflect.DeepEqual(delays, []time.Duration{100 * time.Millisecond, 150 * time.Millisecond}) {
		t.Fatalf("drain = %#v, delays=%v, err=%v", result, delays, err)
	}
}

func TestSpoolAgeWatermarksFailClosed(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).UTC()
	now := base.Add(time.Hour)
	config := testConfig(t.TempDir())
	config.Now = func() time.Time { return now }
	spool := newTestSpool(t, config)
	if _, err := spool.AppendBatch(context.Background(), []Envelope{pendingAccess("evt-oldest", tenantOne)}); err != nil {
		t.Fatal(err)
	}
	now = base.Add(25 * time.Hour)
	newer := pendingAccess("evt-soft", tenantOne)
	newer.OccurredAt = now
	if _, err := spool.AppendBatch(context.Background(), []Envelope{newer}); !errors.Is(err, ErrBackpressure) {
		t.Fatalf("soft age error = %v", err)
	}
	stats, _ := spool.Stats()
	if stats.AgePressure != "soft" || stats.PendingEvents != 1 {
		t.Fatalf("soft age stats = %#v", stats)
	}
	now = base.Add(8 * 24 * time.Hour)
	newer.EventID = "evt-hard"
	newer.OccurredAt = now
	if _, err := spool.AppendBatch(context.Background(), []Envelope{newer}); !errors.Is(err, ErrAgeLimit) {
		t.Fatalf("hard age error = %v", err)
	}
	stats, _ = spool.Stats()
	if stats.AgePressure != "hard" || stats.LastAlertCode != "SPOOL_AGE_HARD_WATERMARK" || stats.PendingEvents != 1 {
		t.Fatalf("hard age stats = %#v", stats)
	}
}
