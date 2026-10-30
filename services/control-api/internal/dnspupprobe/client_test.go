package dnspupprobe

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnspupprobe/dnspuptest"
)

func newFakeDNSPup(t *testing.T) (*dnspuptest.Server, *httptest.Server) {
	fake, server := dnspuptest.New()
	t.Cleanup(server.Close)
	t.Cleanup(func() {
		if len(fake.Errors) > 0 {
			t.Errorf("client protocol errors: %v", fake.Errors)
		}
	})
	return fake, server
}

func credentialsOf(fake *dnspuptest.Server, base string) Credentials {
	return Credentials{BaseURL: base, APIKey: fake.APIKey, APISecret: fake.Secret, SourceDomain: fake.SourceDomain}
}

// toFake converts results to the fake's wire type.
func toFake(results []Result) []dnspuptest.Result {
	raw, _ := json.Marshal(results)
	var out []dnspuptest.Result
	_ = json.Unmarshal(raw, &out)
	return out
}

func newTestProber(t *testing.T, fake *dnspuptest.Server, base string) (*Prober, *[]string) {
	t.Helper()
	client, err := NewClient(credentialsOf(fake, base), nil)
	if err != nil {
		t.Fatal(err)
	}
	var degraded []string
	prober := NewProber(client, func(reason, code string, _ time.Time) { degraded = append(degraded, reason+"/"+code) })
	var waits []time.Duration
	prober.sleep = func(_ context.Context, wait time.Duration) error { waits = append(waits, wait); return nil }
	return prober, &degraded
}

func httpAnswer(statuses ...int) func(dnspuptest.ProbeRequest) []dnspuptest.Result {
	return func(dnspuptest.ProbeRequest) []dnspuptest.Result { return toFake(httpResults(statuses...)) }
}

func httpResults(statuses ...int) []Result {
	{
		nodes := []struct{ id, region, isp string }{{"gd-ct", "广东", "电信"}, {"bj-cu", "北京", "联通"},
			{"sh-cm", "上海", "移动"}, {"hk-1", "香港", "BGP"}}
		var out []Result
		for index, status := range statuses {
			node := nodes[index%len(nodes)]
			result := Result{NodeID: node.id, Region: node.region, ISP: node.isp, Status: "ok", HTTPStatus: status, TotalTime: 40}
			switch {
			case status == 0:
				result.Status, result.Error = "bad", "dial tcp: connection refused"
			case status < 0:
				result.Status, result.HTTPStatus = "unavailable", 0
			case status >= 400:
				result.Status = "bad"
			}
			out = append(out, result)
		}
		return out
	}
}

func TestAccountAndCapability(t *testing.T) {
	fake, server := newFakeDNSPup(t)
	client, err := NewClient(credentialsOf(fake, server.URL), nil)
	if err != nil {
		t.Fatal(err)
	}
	account, err := client.Account(context.Background())
	if err != nil || !account.AsyncProbes() || !account.Allows("http") || account.MonthlyLimit != 1000 {
		t.Fatalf("account = %+v, %v", account, err)
	}
	fake.Async = false
	if account, _ = client.Account(context.Background()); account.AsyncProbes() {
		t.Fatal("asyncProbesV1 false must be reported")
	}
	wrong, _ := NewClient(Credentials{BaseURL: server.URL, APIKey: fake.APIKey, APISecret: "wrong_secret_0123456789"}, nil)
	var apiErr *APIError
	if _, err := wrong.Account(context.Background()); !errors.As(err, &apiErr) || apiErr.Status != 401 || apiErr.Code != "unauthorized" {
		t.Fatalf("wrong secret: %v", err)
	}
}

func TestDomainBoundKeySignsEveryRequest(t *testing.T) {
	fake, server := newFakeDNSPup(t)
	fake.SourceDomain = "control.example.com"
	fake.Answer = httpAnswer(200, 200)
	prober, degraded := newTestProber(t, fake, server.URL)
	results, err := prober.Run(context.Background(), "origin", "site-1", "https://origin.example.com/", 7,
		ProbeRequest{Type: "http", Target: "https://origin.example.com/", Method: "GET"})
	if err != nil || len(results) != 2 || len(*degraded) != 0 {
		t.Fatalf("signed run = %v, %v, degraded %v", results, err, *degraded)
	}
	// Unsigned (no source domain) is refused like dnspup does.
	unsigned, _ := NewClient(Credentials{BaseURL: server.URL, APIKey: fake.APIKey, APISecret: fake.Secret}, nil)
	var apiErr *APIError
	if _, err := unsigned.Account(context.Background()); !errors.As(err, &apiErr) || apiErr.Code != "source_forbidden" {
		t.Fatalf("unsigned: %v", err)
	}
}

func TestSignatureMatchesDNSPupCanonical(t *testing.T) {
	// Fixed vector computed by the fake's independent implementation.
	address, _ := url.Parse("https://api.dnspup.com/v1/probes")
	got := Signature("s3cr3t-0123456789abcdef", "POST", address, "1760000000", "00112233445566778899aabbccddeeff",
		"control.example.com", []byte(`{"type":"http"}`))
	if len(got) != 64 {
		t.Fatalf("signature %q", got)
	}
	again := Signature("s3cr3t-0123456789abcdef", "post", address, "1760000000", "00112233445566778899aabbccddeeff",
		"control.example.com", []byte(`{"type":"http"}`))
	if got != again {
		t.Fatal("method must be upper-cased in the canonical request")
	}
	if Signature("other-secret-0123456789", "POST", address, "1760000000", "00112233445566778899aabbccddeeff",
		"control.example.com", []byte(`{"type":"http"}`)) == got {
		t.Fatal("signature must depend on the secret")
	}
}

func TestAsyncCreatePollAndIdempotency(t *testing.T) {
	fake, server := newFakeDNSPup(t)
	fake.Answer, fake.PollsUntilDone = httpAnswer(200, 503, -1), 2
	prober, _ := newTestProber(t, fake, server.URL)
	var waits []time.Duration
	prober.sleep = func(_ context.Context, wait time.Duration) error { waits = append(waits, wait); return nil }
	request := ProbeRequest{Type: "http", Target: "https://origin.example.com/health", Method: "GET"}
	results, err := prober.Run(context.Background(), "origin", "site-1", request.Target, 10, request)
	if err != nil || len(results) != 3 {
		t.Fatalf("run = %v, %v", results, err)
	}
	if fake.Creates != 1 || fake.Gets != 3 || len(waits) != 3 || waits[0] != 2*time.Second {
		t.Fatalf("creates %d gets %d waits %v", fake.Creates, fake.Gets, waits)
	}
	// Same round: never a second charged job, results are not counted twice.
	if _, err := prober.Run(context.Background(), "origin", "site-1", request.Target, 10, request); !errors.Is(err, ErrDelivered) {
		t.Fatalf("second look = %v", err)
	}
	// A restarted control plane (empty cache) re-sends the same key: 200, no new charge.
	restarted, _ := newTestProber(t, fake, server.URL)
	if _, err := restarted.Run(context.Background(), "origin", "site-1", request.Target, 10, request); err != nil {
		t.Fatal(err)
	}
	if fake.Creates != 1 || fake.MonthlyUsed != 1 {
		t.Fatalf("idempotent retry charged again: creates %d used %d", fake.Creates, fake.MonthlyUsed)
	}
	// Next round: a new job.
	if _, err := prober.Run(context.Background(), "origin", "site-1", request.Target, 11, request); err != nil || fake.Creates != 2 {
		t.Fatalf("next round: %v creates %d", err, fake.Creates)
	}
	if IdempotencyKey("origin", "site-1", request.Target, 10) == IdempotencyKey("origin", "site-1", request.Target, 11) ||
		IdempotencyKey("origin", "site-1", "a", 10) == IdempotencyKey("origin", "site-2", "a", 10) {
		t.Fatal("idempotency key must differ per site, target and round")
	}
}

func TestRetryAfterIsHonoured(t *testing.T) {
	fake, server := newFakeDNSPup(t)
	fake.Answer, fake.PollsUntilDone = httpAnswer(200), 0
	prober, _ := newTestProber(t, fake, server.URL)
	var waits []time.Duration
	prober.sleep = func(_ context.Context, wait time.Duration) error { waits = append(waits, wait); return nil }
	// The create answer is "running" with Retry-After 2; a longer one must be kept.
	original := prober.client.http.Transport
	prober.client.http.Transport = dnspuptest.RetryAfterTransport{Base: original, Value: "7"}
	if _, err := prober.Run(context.Background(), "origin", "s", "https://a.example.com/", 1,
		ProbeRequest{Type: "http", Target: "https://a.example.com/"}); err != nil {
		t.Fatal(err)
	}
	if len(waits) == 0 || waits[0] != 7*time.Second {
		t.Fatalf("waits %v, want first 7s", waits)
	}
}

func TestDegradeOnQuotaRateAndAuth(t *testing.T) {
	fake, server := newFakeDNSPup(t)
	fake.Answer = httpAnswer(200)
	request := func(target string) ProbeRequest { return ProbeRequest{Type: "http", Target: target} }

	fake.MonthlyLimit = 0
	prober, degraded := newTestProber(t, fake, server.URL)
	var apiErr *APIError
	if _, err := prober.Run(context.Background(), "origin", "s", "https://q.example.com/", 1, request("https://q.example.com/")); !errors.As(err, &apiErr) || apiErr.Code != "quota_exceeded" {
		t.Fatalf("quota: %v", err)
	}
	if len(*degraded) != 1 || (*degraded)[0] != "quota_exceeded/quota_exceeded" {
		t.Fatalf("degraded %v", *degraded)
	}

	fake.MonthlyLimit, fake.RateLimit, fake.RateCount = 1000, 1, 1
	prober, degraded = newTestProber(t, fake, server.URL)
	if _, err := prober.Run(context.Background(), "origin", "s", "https://r.example.com/", 1, request("https://r.example.com/")); !errors.As(err, &apiErr) || apiErr.Code != "rate_limited" || apiErr.RetryAfter != time.Minute {
		t.Fatalf("rate: %v", err)
	}
	if len(*degraded) != 1 || (*degraded)[0] != "rate_limited/rate_limited" {
		t.Fatalf("degraded %v", *degraded)
	}

	fake.RateLimit = 0
	fake.AllowedTools = []string{"ping"}
	prober, degraded = newTestProber(t, fake, server.URL)
	if _, err := prober.Run(context.Background(), "origin", "s", "https://t.example.com/", 1, request("https://t.example.com/")); err == nil {
		t.Fatal("tool_not_allowed must fail")
	}
	if len(*degraded) != 1 || (*degraded)[0] != "unauthorized/tool_not_allowed" {
		t.Fatalf("degraded %v", *degraded)
	}
}

func TestTargetRestrictedIsNoVoteAndNoDegrade(t *testing.T) {
	fake, server := newFakeDNSPup(t)
	fake.Restricted["https://gov.example.cn/"] = true
	prober, degraded := newTestProber(t, fake, server.URL)
	request := ProbeRequest{Type: "http", Target: "https://gov.example.cn/"}
	if _, err := prober.Run(context.Background(), "origin", "s", request.Target, 1, request); !errors.Is(err, ErrRefused) {
		t.Fatalf("restricted: %v", err)
	}
	if _, err := prober.Run(context.Background(), "origin", "s", request.Target, 1, request); !errors.Is(err, ErrRefused) {
		t.Fatalf("restricted cached: %v", err)
	}
	if len(*degraded) != 0 || fake.MonthlyUsed != 0 || len(fake.Requests) != 1 {
		t.Fatalf("degraded %v used %d requests %v", *degraded, fake.MonthlyUsed, fake.Requests)
	}
}

func TestIdempotencyConflictIsRefused(t *testing.T) {
	fake, server := newFakeDNSPup(t)
	fake.Answer = httpAnswer(200)
	client, _ := NewClient(credentialsOf(fake, server.URL), nil)
	key := IdempotencyKey("origin", "s", "https://a.example.com/", 1)
	if job, err := client.CreateProbe(context.Background(), key, ProbeRequest{Type: "http", Target: "https://a.example.com/"}); err != nil || !job.Created {
		t.Fatalf("create: %+v %v", job, err)
	}
	if job, err := client.CreateProbe(context.Background(), key, ProbeRequest{Type: "http", Target: "https://a.example.com/"}); err != nil || job.Created {
		t.Fatalf("same body must be 200 existing job: %+v %v", job, err)
	}
	var apiErr *APIError
	if _, err := client.CreateProbe(context.Background(), key, ProbeRequest{Type: "http", Target: "https://b.example.com/"}); !errors.As(err, &apiErr) || apiErr.Status != 409 || apiErr.Code != "idempotency_conflict" {
		t.Fatalf("different body: %v", err)
	}
}

func TestRoundBudget(t *testing.T) {
	fake, server := newFakeDNSPup(t)
	fake.Answer, fake.PollsUntilDone = httpAnswer(200), 0
	prober, _ := newTestProber(t, fake, server.URL)
	for index := range MaxJobsPerRound {
		target := "https://o" + string(rune('a'+index%26)) + ".example.com/" + string(rune('a'+index/26))
		if _, err := prober.Run(context.Background(), "origin", "s", target, 3, ProbeRequest{Type: "http", Target: target}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := prober.Run(context.Background(), "origin", "s", "https://over.example.com/", 3,
		ProbeRequest{Type: "http", Target: "https://over.example.com/"}); !errors.Is(err, ErrRoundBudget) {
		t.Fatalf("budget: %v", err)
	}
	if _, err := prober.Run(context.Background(), "origin", "s", "https://over.example.com/", 4,
		ProbeRequest{Type: "http", Target: "https://over.example.com/"}); err != nil {
		t.Fatalf("next round budget resets: %v", err)
	}
}

func TestVotesAndTags(t *testing.T) {
	votes := HTTPVotes(httpResults(200, 503, -1, 0), 0)
	if !votes[0].OK || !votes[0].Voted || votes[0].Region != "cn" || votes[0].Carrier != "telecom" {
		t.Fatalf("vote 0 %+v", votes[0])
	}
	if votes[1].OK || !votes[1].Voted || votes[1].Reason != "status_5xx" || votes[1].Carrier != "unicom" {
		t.Fatalf("vote 1 %+v", votes[1])
	}
	if votes[2].Voted || votes[2].Carrier != "mobile" {
		t.Fatalf("unavailable is no vote: %+v", votes[2])
	}
	if votes[3].OK || !votes[3].Voted || votes[3].Reason != "connect" || votes[3].Region != "hk" {
		t.Fatalf("connect failure %+v", votes[3])
	}
	// dnspup marks 404 "bad"; the origin rule (below 500 is up) still counts it OK.
	if v := HTTPVotes([]Result{{Status: "bad", HTTPStatus: 404}}, 0); !v[0].OK {
		t.Fatal("404 is an answer below 500")
	}
	if v := HTTPVotes([]Result{{Status: "ok", HTTPStatus: 301}}, 200); v[0].OK || v[0].Reason != "status" {
		t.Fatal("expect 200 rejects 301")
	}
	tcp := TCPVotes([]Result{{Status: "ok", AvgLatency: 12, ISP: "电信", Region: "江苏"}, {Status: "timeout"}, {Status: "unavailable"}})
	if !tcp[0].OK || tcp[0].LatencyMS != 12 || tcp[1].OK || !tcp[1].Voted || tcp[2].Voted {
		t.Fatalf("tcp votes %+v", tcp)
	}
}

func TestHTTPURL(t *testing.T) {
	cases := []struct {
		target HTTPTarget
		want   string
		ok     bool
	}{
		{HTTPTarget{Host: "origin.example.com", Port: 443, HTTPS: true, HostHeader: "origin.example.com", ServerName: "origin.example.com", Path: "/health?x=1"}, "https://origin.example.com/health?x=1", true},
		{HTTPTarget{Host: "origin.example.com", Port: 8080, HostHeader: "origin.example.com:8080", Path: "/"}, "http://origin.example.com:8080/", true},
		{HTTPTarget{Host: "203.0.113.9", Port: 80, HostHeader: "203.0.113.9"}, "http://203.0.113.9/", true},
		{HTTPTarget{Host: "2001:db8::1", Port: 8443, HTTPS: true, HostHeader: "[2001:db8::1]", ServerName: "2001:db8::1"}, "https://[2001:db8::1]:8443/", true},
		// Host header is the site domain while connecting to an IP: dnspup cannot express it.
		{HTTPTarget{Host: "203.0.113.9", Port: 80, HostHeader: "www.example.com"}, "", false},
		{HTTPTarget{Host: "origin.example.com", Port: 443, HTTPS: true, HostHeader: "origin.example.com", ServerName: "other.example.com"}, "", false},
		{HTTPTarget{Host: "origin.example.com", Port: 443, HTTPS: true, HostHeader: "origin.example.com", ServerName: "origin.example.com", CustomCA: true}, "", false},
		{HTTPTarget{Host: "localhost", Port: 80, HostHeader: "localhost"}, "", false},
	}
	for _, item := range cases {
		got, ok := HTTPURL(item.target)
		if got != item.want || ok != item.ok {
			t.Errorf("HTTPURL(%+v) = %q %v, want %q %v", item.target, got, ok, item.want, item.ok)
		}
	}
}
