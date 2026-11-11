package eventspool

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// the per-event hot path of the telemetry tail. Each test fails on
// the code before its change and pins that the result did not change.

var referenceUUID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func referenceValidUUID(value string) bool {
	return referenceUUID.MatchString(value) && !strings.EqualFold(value, "00000000-0000-0000-0000-000000000000")
}

func uuidCorpus() []string {
	corpus := []string{"", "00000000-0000-0000-0000-000000000000", "00000000-0000-0000-0000-000000000001",
		tenantOne, siteOne, nodeOne, strings.ToUpper(tenantOne), "11111111-1111-4111-8111-11111111111", "11111111-1111-4111-8111-1111111111111",
		"11111111_1111-4111-8111-111111111111", "1111111-11111-4111-8111-111111111111", "g1111111-1111-4111-8111-111111111111",
		"11111111-1111-4111-8111-11111111111\n", "１1111111-1111-4111-8111-11111111111"}
	random := rand.New(rand.NewSource(7))
	alphabet := "0123456789abcdefABCDEFgG-_ \x00\xff"
	for i := 0; i < 20000; i++ {
		value := []byte(tenantOne)
		for j := random.Intn(3); j >= 0; j-- {
			value[random.Intn(len(value))] = alphabet[random.Intn(len(alphabet))]
		}
		corpus = append(corpus, string(value))
	}
	return corpus
}

func TestValidUUIDMatchesTheRegexpAndIsCheaper(t *testing.T) {
	corpus := uuidCorpus()
	for _, value := range corpus {
		if validUUID(value) != referenceValidUUID(value) {
			t.Fatalf("validUUID(%q) = %v, regexp says %v", value, validUUID(value), referenceValidUUID(value))
		}
	}
	measure := func(check func(string) bool) time.Duration {
		best := time.Duration(1 << 62)
		for round := 0; round < 5; round++ {
			started := time.Now()
			for _, value := range corpus {
				_ = check(value)
			}
			best = min(best, time.Since(started))
		}
		return best
	}
	regexpTime, handTime := measure(referenceValidUUID), measure(validUUID)
	// it runs several times per event: at least 3x cheaper than the regexp
	if handTime*3 > regexpTime {
		t.Fatalf("validUUID %s vs regexp %s over %d values: want at least 3x cheaper", handTime, regexpTime, len(corpus))
	}
}

func hotpathEvents(prefix string, n int) []Envelope {
	events := make([]Envelope, n)
	for i := range events {
		event := pendingAccess(fmt.Sprintf("%s-%d", prefix, i), tenantOne)
		event.RequestID = fmt.Sprintf("request-%d", i)
		event.Host = fmt.Sprintf("h%d.example.test", i%3)
		event.RequestHeaders = map[string]string{"User-Agent": "Mozilla/5.0 é <b>&", "Accept": "*/*"}
		event.ResponseHeaders = map[string]string{"Content-Type": "text/html"}
		events[i] = event
	}
	return events
}

func hotpathConfig(t *testing.T) Config {
	config := testConfig(t.TempDir())
	config.MaxEventBytes, config.MaxSegmentBytes = 64<<10, 16<<20
	config.SoftLimitBytes, config.HardLimitBytes, config.MaxTenantBytes = 1<<30, 2<<30, 1<<30
	return config
}

// AppendBatch keeps the records it wrote decoded for the publisher; they
// must be what reading the segment back gives, and must not cost a second
// duplicate-key scan and validation of bytes this process just encoded.
func TestAppendBatchRecentRecordsAreTheStoredOnesWithoutRescan(t *testing.T) {
	spool := newTestSpool(t, hotpathConfig(t))
	if _, err := spool.AppendBatch(context.Background(), hotpathEvents("evt-same", 200)); err != nil {
		t.Fatal(err)
	}
	if len(spool.recent) != 200 {
		t.Fatalf("recent %d", len(spool.recent))
	}
	var fromDisk []Record
	for _, meta := range spool.metas {
		var entries []pendingRecord
		for _, entry := range spool.pending {
			if entry.sequence >= meta.start && entry.sequence <= meta.max {
				entries = append(entries, entry)
			}
		}
		if len(entries) == 0 {
			continue
		}
		records, err := spool.readSegmentRecordsLocked(meta, entries)
		if err != nil {
			t.Fatal(err)
		}
		fromDisk = append(fromDisk, records...)
	}
	if !reflect.DeepEqual(fromDisk, spool.recent) {
		t.Fatal("records kept after append differ from the segment's")
	}

	batch := 0
	allocations := testing.AllocsPerRun(5, func() {
		batch++
		if _, err := spool.AppendBatch(context.Background(), hotpathEvents(fmt.Sprintf("evt-alloc-%d", batch), 100)); err != nil {
			t.Fatal(err)
		}
	}) / 100
	if allocations > appendAllocationsPerEvent {
		t.Fatalf("AppendBatch %.0f allocations per event, want at most %d", allocations, appendAllocationsPerEvent)
	}
}

// sortBySiteDimension: same stable order as comparing the joined keys, each
// key computed once per event instead of twice per comparison.
func TestSortBySiteDimensionKeysOnce(t *testing.T) {
	random := rand.New(rand.NewSource(11))
	events := make([]Envelope, 2000)
	for i := range events {
		event := pendingAccess(strconv.Itoa(i), tenantOne)
		event.SiteID = fmt.Sprintf("site-%d", random.Intn(7))
		event.Host = fmt.Sprintf("h%d", random.Intn(3))
		event.ListenPort = uint16(80 + random.Intn(2)*363)
		if random.Intn(4) == 0 {
			event.Type = EventSecurity
		}
		events[i] = event
	}
	want := append([]Envelope(nil), events...)
	key := func(envelope Envelope) string {
		return strings.Join([]string{string(envelope.Type), envelope.TenantID, envelope.SiteID, envelope.ConfigVersionID,
			envelope.CapturePolicyDigest, strconv.FormatUint(envelope.CapturePolicyRevision, 10), envelope.Host,
			strconv.Itoa(int(envelope.ListenPort))}, "\x00")
	}
	sort.SliceStable(want, func(i, j int) bool { return key(want[i]) < key(want[j]) })
	got := append([]Envelope(nil), events...)
	sortBySiteDimension(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatal("order differs from the joined-key stable sort")
	}
	work := make([]Envelope, len(events))
	allocations := testing.AllocsPerRun(3, func() {
		copy(work, events)
		sortBySiteDimension(work)
	}) / float64(len(events))
	if allocations > 8 {
		t.Fatalf("sortBySiteDimension %.1f allocations per event, want at most 8", allocations)
	}
}

// 203 per event before this change (second duplicate-key scan and validation of
// the frame just encoded), 61 after.
const appendAllocationsPerEvent = 100

// referenceEncodeV2 is encodePublication's v2 envelope before this change:
// marshal, canonicalize the marshalled bytes, marshal again with the id.
func referenceEncodeV2(t *testing.T, records []Record) ([]byte, string) {
	first, last := records[0], records[len(records)-1]
	producedAt := first.OccurredAt
	var candidate any
	accessEvents, securityEvents := []analyticsAccessEvent{}, []analyticsSecurityEvent{}
	for _, record := range records {
		if record.envelope.OccurredAt.After(producedAt) {
			producedAt = record.envelope.OccurredAt
		}
		if first.Type == EventAccess {
			accessEvents = append(accessEvents, analyticsAccessFrom(record.envelope))
		} else {
			securityEvents = append(securityEvents, analyticsSecurityFrom(record.envelope))
		}
	}
	if first.Type == EventAccess {
		candidate = &analyticsAccessEnvelope{SchemaVersion: analyticsIngestVersionV2, Type: analyticsAccessTypeV2,
			ProducedAt: producedAt, TenantID: first.TenantID, NodeID: first.NodeID, Events: accessEvents}
	} else {
		candidate = &analyticsSecurityEnvelope{SchemaVersion: analyticsIngestVersionV2, Type: analyticsSecurityTypeV2,
			ProducedAt: producedAt, TenantID: first.TenantID, NodeID: first.NodeID, Events: securityEvents}
	}
	unsigned, err := json.Marshal(candidate)
	if err != nil {
		t.Fatal(err)
	}
	canonical, ok := canonicalPublicationV2Envelope(unsigned)
	if !ok {
		t.Fatal("canonical")
	}
	messageID := publicationV2MessageID(first.Sequence, last.Sequence, canonical)
	switch envelope := candidate.(type) {
	case *analyticsAccessEnvelope:
		envelope.MessageID = messageID
	case *analyticsSecurityEnvelope:
		envelope.MessageID = messageID
	}
	payload, err := json.Marshal(candidate)
	if err != nil {
		t.Fatal(err)
	}
	return payload, messageID
}

func publicationRecords(t *testing.T) [][]Record {
	spool := newTestSpool(t, hotpathConfig(t))
	access := hotpathEvents("evt-pub", 120)
	access[3].Path, access[4].TraceID = "/a?<b>&c= é", "t\"\\x"
	security := hotpathEvents("evt-pub-sec", 40)
	for index := range security {
		security[index].Type, security[index].SecurityType, security[index].Action, security[index].Severity = EventSecurity, "waf", "log", "info"
		security[index].RequestClass, security[index].CacheStatus, security[index].Protocol = "standard", "", "http"
		security[index].RuleID, security[index].Matched, security[index].UserAgent = "rule-1", "<script>&", "k6/2.3.0 é"
		security[index].DurationUS, security[index].ListenPort = 0, 80
		security[index].OccurredAt = security[index].OccurredAt.Add(time.Duration(index) * time.Second)
	}
	if _, err := spool.AppendBatch(context.Background(), append(access, security...)); err != nil {
		t.Fatal(err)
	}
	records, err := spool.nextBatch(context.Background(), 160)
	if err != nil {
		t.Fatal(err)
	}
	var groups [][]Record
	for start := 0; start < len(records); {
		end := start + 1
		for end < len(records) && samePublicationDimension(records[start], records[end]) {
			end++
		}
		groups = append(groups, records[start:end])
		start = end
	}
	return groups
}

// The v2 envelope and its content-bound message id are byte for byte the
// marshal-canonicalize-marshal ones, without re-reading the marshalled bytes.
func TestEncodePublicationIsTheCanonicalizedEnvelope(t *testing.T) {
	groups := publicationRecords(t)
	if len(groups) < 3 {
		t.Fatalf("groups %d", len(groups))
	}
	events := 0
	for _, group := range groups {
		publication, err := encodePublication(group)
		if err != nil {
			t.Fatal(err)
		}
		payload, messageID := referenceEncodeV2(t, group)
		if publication.MessageID != messageID || !bytes.Equal(publication.Payload, payload) {
			t.Fatalf("group of %d %s: publication differs\n got %s %s\nwant %s %s", len(group), group[0].Type,
				publication.MessageID, publication.Payload, messageID, payload)
		}
		if !ValidPublicationMessageID(publication) {
			t.Fatal("message id does not verify")
		}
		events += len(group)
	}
	allocations := testing.AllocsPerRun(5, func() {
		for _, group := range groups {
			if _, err := encodePublication(group); err != nil {
				t.Fatal(err)
			}
		}
	}) / float64(events)
	t.Logf("encodePublication %.1f allocations per event", allocations)
	if allocations > encodeAllocationsPerEvent {
		t.Fatalf("encodePublication %.1f allocations per event, want at most %d", allocations, encodeAllocationsPerEvent)
	}
}

// 194.9 per event before this change (marshal, canonicalize the marshalled
// bytes, marshal again), 27.3 after.
const encodeAllocationsPerEvent = 60
