package site

import (
	"errors"
	"reflect"
	"testing"
)

func TestWithPrimaryOrigins(t *testing.T) {
	pool := defaultOriginPool([]Origin{{Host: "10.0.0.1", Port: 80, Weight: 3, Enabled: true},
		{Host: "10.0.0.2", Port: 8080, Weight: 1, Enabled: true},
		{Host: "10.0.0.9", Port: 80, Weight: 1, Enabled: true, Level: 1},
		{Host: "10.0.0.3", Port: 80, Weight: 1, Enabled: true, Level: 2}})
	pool.Scheme, pool.HTTPSPort, pool.FailoverTries, pool.ReadTimeoutMS = OriginSchemeHTTPS, 8443, 4, 45000
	got, err := WithPrimaryOrigins(pool, []string{"10.0.0.3", "Origin.Example:9000"})
	if err != nil {
		t.Fatal(err)
	}
	want := []Origin{{Host: "10.0.0.3", Port: 8443, Weight: 1, Enabled: true, PortInherited: true},
		{Host: "origin.example", Port: 9000, Weight: 1, Enabled: true},
		{Host: "10.0.0.9", Port: 80, Weight: 1, Enabled: true, Level: 1}}
	// The level 2 backup 10.0.0.3:80 differs from the new primary 10.0.0.3 (inherits 8443), so it stays.
	want = append(want, Origin{Host: "10.0.0.3", Port: 80, Weight: 1, Enabled: true, Level: 2})
	if !reflect.DeepEqual(got.Origins, want) {
		t.Fatalf("origins = %+v", got.Origins)
	}
	if got.Scheme != OriginSchemeHTTPS || got.HTTPSPort != 8443 || got.ReadTimeoutMS != 45000 || got.FailoverTries != 4 {
		t.Fatalf("pool settings not kept: %+v", got)
	}
	if err := normalizeOriginPool(&got); err != nil {
		t.Fatalf("result does not validate: %v", err)
	}
	if endpoints := PrimaryOriginEndpoints(got); !reflect.DeepEqual(endpoints, []string{"10.0.0.3", "origin.example:9000"}) {
		t.Fatalf("endpoints = %v", endpoints)
	}

	// A backup repeating a new primary is dropped; failover tries shrink to the enabled origins.
	got, err = WithPrimaryOrigins(pool, []string{"10.0.0.9:80"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Origins) != 2 || got.Origins[1].Host != "10.0.0.3" || got.FailoverTries != 2 {
		t.Fatalf("dedupe/failover: %+v", got)
	}

	for _, bad := range [][]string{nil, {"a b"}, {"1.2.3.4", "1.2.3.4:8443"}, {"http://x.example"}} {
		if _, err := WithPrimaryOrigins(pool, bad); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%v: err = %v", bad, err)
		}
	}
}

func TestPrimaryOriginEndpointsHTTP(t *testing.T) {
	pool := defaultOriginPool([]Origin{{Host: "10.0.0.1", Port: 80, Weight: 1, Enabled: true},
		{Host: "2001:db8::1", Port: 8080, Weight: 1, Enabled: true}, {Host: "10.0.0.2", Port: 80, Level: 1}})
	if got := PrimaryOriginEndpoints(pool); !reflect.DeepEqual(got, []string{"10.0.0.1", "[2001:db8::1]:8080"}) {
		t.Fatalf("endpoints = %v", got)
	}
}

// 客户区源站 lines may be written as http(s) URLs; anything beyond
// scheme, host and port is refused with the line and a reason.
func TestParsePrimaryOrigins(t *testing.T) {
	for _, item := range []struct {
		scheme string
		raws   []string
		want   string
		lines  []string
	}{
		{"", []string{"1.2.3.4", "Origin.Example:8080"}, "", []string{"1.2.3.4", "origin.example:8080"}},
		{"", []string{"https://1.2.3.4:443", "HTTPS://b.example/"}, "https", []string{"1.2.3.4:443", "b.example"}},
		{"https", []string{"1.2.3.4", "https://[2001:db8::1]:8443"}, "https", []string{"1.2.3.4", "[2001:db8::1]:8443"}},
		{"http", []string{"http://a.example", "[2001:db8::2]"}, "http", []string{"a.example", "2001:db8::2"}},
	} {
		scheme, lines, err := ParsePrimaryOrigins(item.scheme, item.raws)
		if err != nil || scheme != item.want || !reflect.DeepEqual(lines, item.lines) {
			t.Errorf("%q %v = %q %v %v, want %q %v", item.scheme, item.raws, scheme, lines, err, item.want, item.lines)
		}
	}
	for _, item := range []struct {
		scheme string
		raws   []string
		field  string
		index  int
		reason string
	}{
		{"ftp", []string{"1.2.3.4"}, "origin_scheme", -1, OriginReasonSchemeUnsupported},
		{"", []string{"1.2.3.4", "ftp://1.2.3.4"}, "origins", 1, OriginReasonSchemeUnsupported},
		{"http", []string{"https://1.2.3.4:443"}, "origins", 0, OriginReasonSchemeMismatch},
		{"", []string{"https://a.example", "http://b.example"}, "origins", 1, OriginReasonSchemeMismatch},
		{"", []string{"https://1.2.3.4/app"}, "origins", 0, OriginReasonHasPath},
		{"", []string{"1.2.3.4?x=1"}, "origins", 0, OriginReasonHasPath},
		{"", []string{"https://user:pw@1.2.3.4"}, "origins", 0, OriginReasonHasUserinfo},
		{"", []string{"1.2.3.4:0"}, "origins", 0, OriginReasonPortInvalid},
		{"", []string{"https://1.2.3.4:65536"}, "origins", 0, OriginReasonPortInvalid},
		{"", []string{"1.2.3.4:"}, "origins", 0, OriginReasonPortInvalid},
		{"", []string{"[2001:db8::1]:x"}, "origins", 0, OriginReasonPortInvalid},
		{"", []string{"a b.example"}, "origins", 0, OriginReasonHostInvalid},
		{"", []string{"https://"}, "origins", 0, OriginReasonHostInvalid},
		{"", []string{"1.2.3.4", "https://1.2.3.4/"}, "origins", 1, OriginReasonDuplicate},
	} {
		_, _, err := ParsePrimaryOrigins(item.scheme, item.raws)
		var refused *PrimaryOriginError
		if !errors.As(err, &refused) || !errors.Is(err, ErrInvalidInput) || refused.Field != item.field ||
			refused.Index != item.index || refused.Reason != item.reason {
			t.Errorf("%q %v: err = %v, want %s[%d] %s", item.scheme, item.raws, err, item.field, item.index, item.reason)
		}
	}
}

// A create naming a 回源协议 gets that scheme's default port for lines without one.
func TestNewPrimaryOriginPool(t *testing.T) {
	pool, fields, err := NewPrimaryOriginPool(OriginSchemeHTTPS, []string{"1.2.3.4", "b.example:8443", "1.2.3.5:443"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fields, []string{"1.2.3.4:443", "b.example:8443", "1.2.3.5:443"}) {
		t.Fatalf("fields = %v", fields)
	}
	if pool.Scheme != OriginSchemeHTTPS || pool.HTTPPort != 80 || pool.HTTPSPort != 443 || pool.FailoverTries != 1 {
		t.Fatalf("pool = %+v", pool)
	}
	normalized := pool
	normalized.BalanceMethod, normalized.ConnectTimeoutMS, normalized.ReadTimeoutMS = BalanceRoundRobin, 3000, 30000
	if err := normalizeOriginPool(&normalized); err != nil {
		t.Fatalf("pool does not validate: %v", err)
	}
	if got := PrimaryOriginEndpoints(normalized); !reflect.DeepEqual(got, []string{"1.2.3.4", "b.example:8443", "1.2.3.5"}) {
		t.Fatalf("endpoints = %v", got)
	}
	_, fields, err = NewPrimaryOriginPool(OriginSchemeHTTP, []string{"1.2.3.4", "1.2.3.4:443"})
	if err != nil || !reflect.DeepEqual(fields, []string{"1.2.3.4", "1.2.3.4:443"}) {
		t.Fatalf("http fields = %v %v", fields, err)
	}
	if _, _, err := NewPrimaryOriginPool("follow", []string{"1.2.3.4"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("follow: %v", err)
	}
}

// Switching the 回源协议 resets what the new scheme does not use, so the pool still validates.
func TestWithOriginScheme(t *testing.T) {
	pool := defaultOriginPool([]Origin{{Host: "10.0.0.1", Port: 80, Weight: 1, Enabled: true, PortInherited: true}})
	pool.HTTPPort = 8080
	https := withOriginScheme(pool, OriginSchemeHTTPS)
	if https.Scheme != OriginSchemeHTTPS || https.HTTPPort != 80 || https.HTTPSPort != 443 {
		t.Fatalf("to https: %+v", https)
	}
	https.TLS = OriginTLS{SNI: "origin.example", Trust: OriginTrustNone}
	https.HTTPSPort = 8443
	back := withOriginScheme(https, OriginSchemeHTTP)
	if back.Scheme != OriginSchemeHTTP || back.HTTPSPort != 443 || back.HTTPPort != 80 || back.TLS != (OriginTLS{Trust: OriginTrustSystem}) {
		t.Fatalf("to http: %+v", back)
	}
	follow := pool
	follow.Scheme, follow.FollowPort, follow.HTTPPort = OriginSchemeFollow, true, 80
	if got := withOriginScheme(follow, ""); got.Scheme != OriginSchemeFollow || !got.FollowPort {
		t.Fatalf("keep follow: %+v", got)
	}
	if got := withOriginScheme(follow, OriginSchemeHTTPS); got.FollowPort || got.Scheme != OriginSchemeHTTPS {
		t.Fatalf("follow to https: %+v", got)
	}
	for _, scheme := range []string{OriginSchemeHTTP, OriginSchemeHTTPS} {
		for _, from := range []OriginPool{pool, https, follow} {
			got, err := WithPrimaryOrigins(withOriginScheme(from, scheme), []string{"10.0.0.2"})
			if err == nil {
				err = normalizeOriginPool(&got)
			}
			if err != nil {
				t.Errorf("%s from %s: %v", scheme, from.Scheme, err)
			}
		}
	}
}
