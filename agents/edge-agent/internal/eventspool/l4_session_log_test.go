package eventspool

import (
	"context"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/proto"
)

func l4LogIdentity() TrustedIdentity {
	return TrustedIdentity{
		EnrollmentNodeID: nodeOne, TenantID: tenantOne, SiteID: siteOne,
		ConfigVersionID: "55555555-5555-4555-8555-555555555555",
		StreamID:        "66666666-6666-4666-8666-666666666666",
		ListenerID:      "77777777-7777-4777-8777-777777777777", ConfigRevision: 9,
	}
}

func l4LogLine(fields string) []byte {
	return []byte(`{"time":"2026-08-08T12:00:05Z","connection":"42","protocol":"TCP","server_port":"18080","status":"200",` +
		`"bytes_sent":1200,"bytes_received":300,"session_time":5.25,` + fields + `}`)
}

// l4_session_v2 lines (session_log) carry the client, peer, upstream and end
// reason into L4SessionEventV1.session_log; v1 lines carry none.
func TestL4SessionLogLineIsParsedAndPublished(t *testing.T) {
	for name, test := range map[string]struct {
		fields string
		want   L4SessionLog
	}{
		"direct": {`"client":"198.51.100.7","remote_addr":"198.51.100.7","remote_port":"40001","proxy_protocol_port":"",` +
			`"upstream_addr":"10.0.0.9:443","upstream_connect_time":"0.012","end_reason":""`,
			L4SessionLog{ClientIP: "198.51.100.7", ClientPort: 40001, UpstreamAddr: "10.0.0.9:443", UpstreamConnectMS: ptr(uint32(12)), EndReason: "closed"}},
		"trusted proxy, retried upstream": {`"client":"203.0.113.10","remote_addr":"192.0.2.9","remote_port":"50000","proxy_protocol_port":"61000",` +
			`"upstream_addr":"10.0.0.8:443, 10.0.0.9:443","upstream_connect_time":"-, 0.003","end_reason":"killed"`,
			L4SessionLog{ClientIP: "203.0.113.10", ClientPort: 61000, PeerIP: "192.0.2.9", UpstreamAddr: "10.0.0.9:443", UpstreamConnectMS: ptr(uint32(3)), EndReason: "killed"}},
		"refused before preread": {`"client":"","remote_addr":"2001:db8::5","remote_port":"40002","proxy_protocol_port":"",` +
			`"upstream_addr":"","upstream_connect_time":"","end_reason":""`,
			L4SessionLog{ClientIP: "2001:db8::5", ClientPort: 40002, EndReason: "conn_limited"}},
		"rate limited": {`"client":"198.51.100.7","remote_addr":"198.51.100.7","remote_port":"40003","proxy_protocol_port":"",` +
			`"upstream_addr":"","upstream_connect_time":"","end_reason":"rate_limited"`,
			L4SessionLog{ClientIP: "198.51.100.7", ClientPort: 40003, EndReason: "rate_limited"}},
		"guard rule": {`"client":"198.51.100.7","remote_addr":"198.51.100.7","remote_port":"40004","proxy_protocol_port":"",` +
			`"upstream_addr":"","upstream_connect_time":"","end_reason":"guard_blocked"`,
			L4SessionLog{ClientIP: "198.51.100.7", ClientPort: 40004, EndReason: "guard_blocked"}},
	} {
		line := l4LogLine(test.fields)
		if test.want.EndReason == "conn_limited" {
			line = []byte(strings.Replace(string(line), `"status":"200"`, `"status":"503"`, 1))
		}
		event, err := ParseL4SourceLineBound(line, l4LogIdentity())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if event.L4Log == nil || (event.L4Log.UpstreamConnectMS == nil) != (test.want.UpstreamConnectMS == nil) ||
			event.L4Log.UpstreamConnectMS != nil && *event.L4Log.UpstreamConnectMS != *test.want.UpstreamConnectMS {
			t.Fatalf("%s: L4Log = %+v", name, event.L4Log)
		}
		got := *event.L4Log
		got.UpstreamConnectMS, test.want.UpstreamConnectMS = nil, nil
		if got != test.want {
			t.Fatalf("%s: L4Log = %+v, want %+v", name, got, test.want)
		}
	}
	// v1 lines have no session log; a half-v2 line or a bad client is refused.
	plain := []byte(`{"time":"2026-08-08T12:00:05Z","connection":"42","protocol":"TCP","server_port":"18080","status":"200","bytes_sent":1,"bytes_received":1,"session_time":1}`)
	if event, err := ParseL4SourceLineBound(plain, l4LogIdentity()); err != nil || event.L4Log != nil {
		t.Fatalf("v1 line: %+v %v", event.L4Log, err)
	}
	for _, bad := range []string{
		`"client":"198.51.100.7"`,
		`"client":"not-an-ip","remote_addr":"198.51.100.7","remote_port":"1","proxy_protocol_port":"","upstream_addr":"","upstream_connect_time":"","end_reason":""`,
		`"client":"198.51.100.7","remote_addr":"198.51.100.7","remote_port":"1","proxy_protocol_port":"","upstream_addr":"","upstream_connect_time":"","end_reason":"bogus"`,
	} {
		if _, err := ParseL4SourceLineBound(l4LogLine(bad), l4LogIdentity()); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}

	// The session log reaches the published protobuf event.
	event, err := ParseL4SourceLineBound(l4LogLine(`"client":"203.0.113.10","remote_addr":"192.0.2.9","remote_port":"50000",`+
		`"proxy_protocol_port":"61000","upstream_addr":"10.0.0.9:443","upstream_connect_time":"0.003","end_reason":""`), l4LogIdentity())
	if err != nil {
		t.Fatal(err)
	}
	event.EventID = "l4evt_log"
	config := testConfig(t.TempDir())
	config.Now = func() time.Time { return time.Date(2026, 8, 8, 12, 1, 0, 0, time.UTC) }
	spool := newTestSpool(t, config)
	if _, err := spool.AppendBatch(context.Background(), []Envelope{event}); err != nil {
		t.Fatal(err)
	}
	records, err := spool.nextBatch(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	publications, err := buildPublications(records)
	if err != nil || len(publications) != 1 || !ValidL4Publication(publications[0]) {
		t.Fatalf("publications = %v, %v", publications, err)
	}
	var envelope agentv1.L4SessionEnvelopeV1
	if err := proto.Unmarshal(publications[0].Payload, &envelope); err != nil {
		t.Fatal(err)
	}
	log := envelope.GetEvents()[0].GetSessionLog()
	if log.GetClientIp() != "203.0.113.10" || log.GetClientPort() != 61000 || log.GetPeerIp() != "192.0.2.9" ||
		log.GetUpstreamAddr() != "10.0.0.9:443" || log.GetUpstreamConnectMs() != 3 || log.GetEndReason() != "closed" {
		t.Fatalf("published session log = %v", log)
	}
}

func ptr[T any](value T) *T { return &value }
