package clientip

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func header(pairs ...string) http.Header {
	result := http.Header{}
	for index := 0; index+1 < len(pairs); index += 2 {
		result.Add(pairs[index], pairs[index+1])
	}
	return result
}

// Each 源IP请求头 value reads its own header; X-Real-IP and X-Forwarded-For
// come from the console nginx's copies of the client's values (nginx
// rewrites the originals with its TCP peer).
func TestFromHeaderReadsEachSetting(t *testing.T) {
	for name, check := range map[string]struct {
		setting string
		header  http.Header
		want    string
	}{
		"cloudflare":            {HeaderCFConnectingIP, header("CF-Connecting-IP", "203.0.113.9"), "203.0.113.9"},
		"cloudflare ipv6":       {HeaderCFConnectingIP, header("CF-Connecting-IP", " 2001:db8::9 "), "2001:db8::9"},
		"true client ip":        {HeaderTrueClientIP, header("True-Client-IP", "198.51.100.7"), "198.51.100.7"},
		"mapped ipv4":           {HeaderTrueClientIP, header("True-Client-IP", "::ffff:198.51.100.7"), "198.51.100.7"},
		"x-real-ip copy":        {HeaderXRealIP, header("X-Real-IP", "127.0.0.1", ForwardedXRealIP, "203.0.113.20"), "203.0.113.20"},
		"xff leftmost":          {HeaderXForwardedFor, header(ForwardedXForwardedFor, "203.0.113.30, 198.51.100.1, 192.0.2.4"), "203.0.113.30"},
		"xff single":            {HeaderXForwardedFor, header(ForwardedXForwardedFor, "203.0.113.31"), "203.0.113.31"},
		"xff first line":        {HeaderXForwardedFor, header(ForwardedXForwardedFor, "203.0.113.32", ForwardedXForwardedFor, "192.0.2.5"), "203.0.113.32"},
		"canonical key casing":  {HeaderCFConnectingIP, http.Header{"Cf-Connecting-Ip": {"203.0.113.40"}}, "203.0.113.40"},
		"other headers ignored": {HeaderCFConnectingIP, header("True-Client-IP", "203.0.113.41", ForwardedXRealIP, "203.0.113.42"), ""},
	} {
		got, ok := FromHeader(check.header, check.setting)
		if check.want == "" {
			if ok {
				t.Errorf("%s: got %s, want none", name, got)
			}
			continue
		}
		if !ok || got != netip.MustParseAddr(check.want) {
			t.Errorf("%s: got %s %v, want %s", name, got, ok, check.want)
		}
	}
}

// An empty setting reads no header at all: the direct connection's address stays.
func TestFromHeaderEmptySettingIsDirect(t *testing.T) {
	all := header("CF-Connecting-IP", "203.0.113.9", "True-Client-IP", "203.0.113.9",
		ForwardedXRealIP, "203.0.113.9", ForwardedXForwardedFor, "203.0.113.9")
	for _, setting := range []string{"", "X-Client-IP", "cf-connecting-ip"} {
		if got, ok := FromHeader(all, setting); ok {
			t.Errorf("setting %q gave %s", setting, got)
		}
	}
}

// A missing, repeated or invalid value is no visitor: the caller falls back
// to the connection's address. The originals nginx rewrites are never read.
func TestFromHeaderRefusesInvalidValues(t *testing.T) {
	for name, check := range map[string]struct {
		setting string
		header  http.Header
	}{
		"missing":             {HeaderCFConnectingIP, header()},
		"empty":               {HeaderCFConnectingIP, header("CF-Connecting-IP", "")},
		"two lines":           {HeaderCFConnectingIP, header("CF-Connecting-IP", "203.0.113.9", "CF-Connecting-IP", "203.0.113.10")},
		"list":                {HeaderTrueClientIP, header("True-Client-IP", "203.0.113.9, 203.0.113.10")},
		"port":                {HeaderCFConnectingIP, header("CF-Connecting-IP", "203.0.113.9:443")},
		"bracketed":           {HeaderCFConnectingIP, header("CF-Connecting-IP", "[2001:db8::1]")},
		"zone":                {HeaderCFConnectingIP, header("CF-Connecting-IP", "fe80::1%eth0")},
		"hostname":            {HeaderCFConnectingIP, header("CF-Connecting-IP", "example.com")},
		"unknown":             {HeaderTrueClientIP, header("True-Client-IP", "unknown")},
		"unspecified":         {HeaderCFConnectingIP, header("CF-Connecting-IP", "0.0.0.0")},
		"loopback":            {HeaderCFConnectingIP, header("CF-Connecting-IP", "127.0.0.1")},
		"loopback v6":         {HeaderCFConnectingIP, header("CF-Connecting-IP", "::1")},
		"multicast":           {HeaderCFConnectingIP, header("CF-Connecting-IP", "224.0.0.1")},
		"x-real-ip original":  {HeaderXRealIP, header("X-Real-IP", "203.0.113.9")},
		"xff original":        {HeaderXForwardedFor, header("X-Forwarded-For", "203.0.113.9")},
		"xff leftmost broken": {HeaderXForwardedFor, header(ForwardedXForwardedFor, "unknown, 203.0.113.9")},
		"xff empty first":     {HeaderXForwardedFor, header(ForwardedXForwardedFor, ", 203.0.113.9")},
		"x-real-ip two lines": {HeaderXRealIP, header(ForwardedXRealIP, "203.0.113.9", ForwardedXRealIP, "203.0.113.10")},
	} {
		if got, ok := FromHeader(check.header, check.setting); ok {
			t.Errorf("%s: got %s, want fallback", name, got)
		}
	}
}

func TestValidSetting(t *testing.T) {
	for _, value := range append([]string{""}, Headers...) {
		if !ValidSetting(value) {
			t.Errorf("%q refused", value)
		}
	}
	for _, value := range []string{"x-real-ip", "X-Client-IP", "Forwarded", " X-Real-IP"} {
		if ValidSetting(value) {
			t.Errorf("%q accepted", value)
		}
	}
}

func TestVisitorContext(t *testing.T) {
	ctx := context.Background()
	if _, ok := Visitor(ctx); ok {
		t.Fatal("visitor without WithVisitor")
	}
	if _, ok := Visitor(WithVisitor(ctx, netip.Addr{})); ok {
		t.Fatal("invalid address recorded")
	}
	address := netip.MustParseAddr("203.0.113.9")
	if got, ok := Visitor(WithVisitor(ctx, address)); !ok || got != address {
		t.Fatalf("got %s %v", got, ok)
	}
}

// The setting is read again after ttl; Store applies a save at once; a
// failed read keeps the last value, and an invalid stored value is direct.
func TestSettingRefreshAndStore(t *testing.T) {
	now := time.Date(2026, 11, 23, 8, 0, 0, 0, time.UTC)
	stored, failing := HeaderCFConnectingIP, false
	var reads atomic.Int64
	setting := NewSetting(func(context.Context) (string, error) {
		reads.Add(1)
		if failing {
			return "", errors.New("database down")
		}
		return stored, nil
	}, 5*time.Second)
	setting.now = func() time.Time { return now }
	ctx := context.Background()
	if got := setting.Current(ctx); got != HeaderCFConnectingIP || reads.Load() != 1 {
		t.Fatalf("first read %q (%d reads)", got, reads.Load())
	}
	stored = HeaderXRealIP
	if got := setting.Current(ctx); got != HeaderCFConnectingIP || reads.Load() != 1 {
		t.Fatalf("cached read %q (%d reads)", got, reads.Load())
	}
	setting.Store(HeaderTrueClientIP)
	if got := setting.Current(ctx); got != HeaderTrueClientIP || reads.Load() != 1 {
		t.Fatalf("after Store %q (%d reads)", got, reads.Load())
	}
	now = now.Add(5 * time.Second)
	if got := setting.Current(ctx); got != HeaderXRealIP || reads.Load() != 2 {
		t.Fatalf("after ttl %q (%d reads)", got, reads.Load())
	}
	failing, now = true, now.Add(5*time.Second)
	if got := setting.Current(ctx); got != HeaderXRealIP || reads.Load() != 3 {
		t.Fatalf("failed read %q (%d reads)", got, reads.Load())
	}
	failing, stored, now = false, "X-Client-IP", now.Add(5*time.Second)
	if got := setting.Current(ctx); got != "" {
		t.Fatalf("invalid stored value %q", got)
	}
	setting.Store("X-Client-IP")
	if got := setting.Current(ctx); got != "" {
		t.Fatalf("invalid Store %q", got)
	}
	var unset *Setting
	if unset.Current(ctx) != "" || NewSetting(nil, time.Second).Current(ctx) != "" {
		t.Fatal("unset setting not direct")
	}
	first := NewSetting(func(context.Context) (string, error) { return "", errors.New("down") }, time.Second)
	if first.Current(ctx) != "" {
		t.Fatal("failed first read not direct")
	}
}
