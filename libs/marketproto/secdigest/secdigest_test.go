package secdigest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
)

const start = 1_800_000_000 // multiple of 300

func key(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return public, private
}

func valid() Digest {
	return Digest{
		Schema: SchemaV1, LeafMemberID: uuid.New(), GrantID: uuid.New(), LeafSiteID: uuid.New(),
		WindowStart: start, WindowSeconds: WindowSeconds,
		Summary: Summary{Events: 12, Blocked: 10, Challenged: 2, Clients: 3, TopDetector: "sqli",
			TopClientIP: "203.0.113.7", FirstMS: start * 1000, LastMS: start*1000 + 299_999},
		Actions: []Action{{At: start + 10, Source: "autodefense", Level: 3, Kind: "cidr", Target: "203.0.113.0/24",
			Until: start + 3600, Reason: "rate over baseline"}},
		Logs: []Log{{AtMS: start*1000 + 5, ClientIP: "2001:db8::1", Host: "www.example.test", Path: "/login?x=1",
			Action: "block", Detector: "sqli", RuleID: "942100"}},
		Adjustments: []Adjustment{{Module: "cc", Field: "cc.per_ip_requests", Value: 50, At: start + 20}},
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	public, private := key(t)
	d := valid()
	signed, err := Sign(d, private)
	if err != nil {
		t.Fatal(err)
	}
	got, raw, err := Verify(public, signed)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, d) || len(raw) == 0 {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, d)
	}
	if Operation != "supply.secdigest" {
		t.Fatalf("relay op %q", Operation)
	}
}

func TestVerifyRejectsTamperWrongKeyAndUnknownField(t *testing.T) {
	public, private := key(t)
	signed, err := Sign(valid(), private)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(signed.Payload)
	tampered := signed
	tampered.Payload = base64.StdEncoding.EncodeToString([]byte(strings.Replace(string(raw), `"blocked":10`, `"blocked":11`, 1)))
	if _, _, err := Verify(public, tampered); !errors.Is(err, ErrSignature) {
		t.Fatalf("tampered payload: %v", err)
	}
	other, _ := key(t)
	if _, _, err := Verify(other, signed); !errors.Is(err, ErrSignature) {
		t.Fatalf("wrong key: %v", err)
	}
	if _, _, err := Verify(public[:10], signed); !errors.Is(err, ErrSignature) {
		t.Fatalf("short key: %v", err)
	}
	// A correctly signed payload with an unknown field is still rejected.
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	m["request_body"] = "x"
	extra, _ := json.Marshal(m)
	forged := Signed{Payload: base64.StdEncoding.EncodeToString(extra),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, append([]byte(Domain), extra...)))}
	if _, _, err := Verify(public, forged); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown field: %v", err)
	}
	// Signed under another domain (usage report) must not verify here.
	cross := Signed{Payload: signed.Payload,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, append([]byte("cdnca.market.usage-report/v2\n"), raw...)))}
	if _, _, err := Verify(public, cross); !errors.Is(err, ErrSignature) {
		t.Fatalf("cross-domain signature: %v", err)
	}
}

func TestValidateBoundaries(t *testing.T) {
	for name, mutate := range map[string]func(*Digest){
		"schema":            func(d *Digest) { d.Schema = "cdnca.market.secdigest/v2" },
		"nil grant":         func(d *Digest) { d.GrantID = uuid.Nil },
		"nil site":          func(d *Digest) { d.LeafSiteID = uuid.Nil },
		"unaligned window":  func(d *Digest) { d.WindowStart++ },
		"window seconds":    func(d *Digest) { d.WindowSeconds = 60 },
		"empty":             func(d *Digest) { d.Summary = Summary{}; d.Actions, d.Logs = nil, nil },
		"too many actions":  func(d *Digest) { d.Actions = make([]Action, MaxActions+1); fill(d) },
		"too many logs":     func(d *Digest) { d.Logs = make([]Log, MaxLogs+1); fill(d) },
		"negative count":    func(d *Digest) { d.Summary.Blocked = -1 },
		"negative dropped":  func(d *Digest) { d.Dropped.Logs = -1 },
		"top ip not canon":  func(d *Digest) { d.Summary.TopClientIP = "2001:DB8::1" },
		"last before first": func(d *Digest) { d.Summary.LastMS = d.Summary.FirstMS - 1 },
		"first out window":  func(d *Digest) { d.Summary.FirstMS = (start - 1) * 1000 },
		"action after":      func(d *Digest) { d.Actions[0].At = start + WindowSeconds },
		"action level 6":    func(d *Digest) { d.Actions[0].Level = 6 },
		"action source":     func(d *Digest) { d.Actions[0].Source = "ddos" },
		"cidr not masked":   func(d *Digest) { d.Actions[0].Target = "203.0.113.7/24" },
		"site target":       func(d *Digest) { d.Actions[0].Kind, d.Actions[0].Target = "site", "a" },
		"until before at":   func(d *Digest) { d.Actions[0].Until = start },
		"reason newline":    func(d *Digest) { d.Actions[0].Reason = "a\nb" },
		"reason too long":   func(d *Digest) { d.Actions[0].Reason = strings.Repeat("a", maxText+1) },
		"log before window": func(d *Digest) { d.Logs[0].AtMS = start*1000 - 1 },
		"log bad ip":        func(d *Digest) { d.Logs[0].ClientIP = "" },
		"log path relative": func(d *Digest) { d.Logs[0].Path = "login" },
		"log path long":     func(d *Digest) { d.Logs[0].Path = "/" + strings.Repeat("a", maxPath) },
		"log empty action":  func(d *Digest) { d.Logs[0].Action = "" },
		"log empty host":    func(d *Digest) { d.Logs[0].Host = "" },
		"adjust l4":         func(d *Digest) { d.Adjustments[0].Module, d.Adjustments[0].Field = "l4", "l4.idle_seconds" },
		"adjust foreign":    func(d *Digest) { d.Adjustments[0].Field = "waf.tier" },
		"adjust duplicate":  func(d *Digest) { d.Adjustments = append(d.Adjustments, d.Adjustments[0]) },
		"adjust too many":   func(d *Digest) { d.Adjustments = make([]Adjustment, MaxAdjustments+1) },
		"adjust future":     func(d *Digest) { d.Adjustments[0].At = start + WindowSeconds },
	} {
		d := valid()
		mutate(&d)
		if err := d.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: accepted", name)
		}
	}
	d := valid()
	d.Actions = make([]Action, MaxActions)
	d.Logs = make([]Log, MaxLogs)
	fill(&d)
	d.Adjustments = nil
	if err := d.Validate(); err != nil {
		t.Fatalf("limits exactly at maximum rejected: %v", err)
	}
	_, private := key(t)
	if _, err := Sign(d, private); err != nil {
		t.Fatalf("full digest exceeds payload bound: %v", err)
	}
	// Only drops, no events: still worth sending (the window was not quiet).
	d = valid()
	d.Summary, d.Actions, d.Logs, d.Adjustments = Summary{}, nil, nil, nil
	d.Dropped.Logs = 5
	if err := d.Validate(); err != nil {
		t.Fatalf("drop-only digest rejected: %v", err)
	}
}

func fill(d *Digest) {
	for i := range d.Actions {
		d.Actions[i] = Action{At: start + int64(i%WindowSeconds), Source: "waf", Level: 1, Kind: "ip", Target: "198.51.100.1"}
	}
	for i := range d.Logs {
		d.Logs[i] = Log{AtMS: start*1000 + int64(i), ClientIP: "198.51.100.1", Host: "a.example.test",
			Path: "/" + strings.Repeat("p", 1000), Action: "block", Detector: "xss", RuleID: "941100"}
	}
}

func TestTruncateKeepsNewestAndCountsDropped(t *testing.T) {
	d := valid()
	d.Actions = make([]Action, MaxActions+6)
	d.Logs = make([]Log, MaxLogs+9)
	fill(&d)
	d.Dropped.Logs = 1
	d.Truncate()
	if len(d.Actions) != MaxActions || len(d.Logs) != MaxLogs || d.Dropped.Actions != 6 || d.Dropped.Logs != 10 {
		t.Fatalf("truncate: %d %d %+v", len(d.Actions), len(d.Logs), d.Dropped)
	}
	if d.Logs[0].AtMS != start*1000+MaxLogs+8 || d.Logs[MaxLogs-1].AtMS != start*1000+9 {
		t.Fatalf("logs not newest first: %d .. %d", d.Logs[0].AtMS, d.Logs[MaxLogs-1].AtMS)
	}
	if err := d.Validate(); err != nil {
		t.Fatalf("truncated digest invalid: %v", err)
	}
}

func TestIdempotencyKey(t *testing.T) {
	site := uuid.New()
	key := IdempotencyKey(site, 1800000000)
	if len(key) > 128 || key != IdempotencyKey(site, 1800000000) || key == IdempotencyKey(uuid.New(), 1800000000) ||
		strings.Contains(key, site.String()) {
		t.Fatalf("key %q", key)
	}
	if w, ok := WindowOfKey(key); !ok || w != 1800000000 {
		t.Fatalf("window %d %v", w, ok)
	}
	for _, bad := range []string{"", "secdigest-1800000001-0123456789abcdef", "secdigest-x-0123456789abcdef", "reply-1", "secdigest-1800000000-zz"} {
		if _, ok := WindowOfKey(bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}
