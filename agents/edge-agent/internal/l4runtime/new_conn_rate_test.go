package l4runtime

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// new_conn_rate (tcp/udp v6) rides from the stream spec through the
// aggregate; unset it leaves the canonical bytes and nginx.conf unchanged.
func TestNewConnRateIsOptionalBoundedAndCarried(t *testing.T) {
	base, err := AggregateStreamRuntimeSpecsV2("l403-revision-7", 7, []StreamRuntimeSpecV2{l403StreamSpec()})
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := CanonicalV2(base)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(canonical, []byte("new_conn_rate")) {
		t.Fatalf("unset rate changed the canonical bytes: %s", canonical)
	}
	plain := mustCompileV2(t, base)
	if bytes.Contains(plain.NginxConfig, []byte("l4_v2_rate")) || bytes.Contains(plain.NginxConfig, []byte("limit_new_connections")) {
		t.Fatalf("unset rate changed nginx.conf:\n%s", plain.NginxConfig)
	}

	for _, value := range []NewConnRateV2{
		{RatePerSecond: 1},
		{RatePerSecond: 20, Burst: 10, BanSeconds: 60},
		{RatePerSecond: 100_000, Burst: 100_000, BanSeconds: 86_400},
	} {
		spec := l403StreamSpec()
		rate := value
		spec.NewConnRate = &rate
		config, err := AggregateStreamRuntimeSpecsV2("l403-revision-7", 7, []StreamRuntimeSpecV2{spec})
		if err != nil {
			t.Fatalf("%+v rejected: %v", value, err)
		}
		if got := config.Listeners[0].NewConnRate; got == nil || *got != value {
			t.Fatalf("%+v aggregated to %+v", value, got)
		}
		rate.RatePerSecond = 7 // the aggregate holds its own copy
		if config.Listeners[0].NewConnRate.RatePerSecond != value.RatePerSecond {
			t.Fatal("aggregate shares the caller's rate")
		}
		canonical, err := CanonicalV2(config)
		if err != nil || !bytes.Contains(canonical, []byte(`"new_conn_rate":{"rate_per_second":`)) {
			t.Fatalf("%+v canonical=%s err=%v", value, canonical, err)
		}
	}
	for _, invalid := range []NewConnRateV2{
		{}, {RatePerSecond: -1}, {RatePerSecond: 100_001},
		{RatePerSecond: 1, Burst: -1}, {RatePerSecond: 1, Burst: 100_001},
		{RatePerSecond: 1, BanSeconds: -1}, {RatePerSecond: 1, BanSeconds: 86_401},
	} {
		spec := l403StreamSpec()
		rate := invalid
		spec.NewConnRate = &rate
		if _, err := AggregateStreamRuntimeSpecsV2("l403-revision-7", 7, []StreamRuntimeSpecV2{spec}); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("%+v accepted: %v", invalid, err)
		}
	}
}

// Every socket of a limited stream checks the client against the stream's
// one bucket (keyed by stream, not listener) after the Geo decision, which
// names the client (the PROXY protocol address from a trusted proxy).
func TestNewConnRateRendersThePrereadLimit(t *testing.T) {
	spec := l403StreamSpec()
	spec.AdditionalListeners = []AdditionalListenerV2{{ID: "44444444-4444-4444-8444-444444444444", Protocol: ProtocolTCP, Address: "*", Port: 9444}}
	spec.NewConnRate = &NewConnRateV2{RatePerSecond: 20, Burst: 5, BanSeconds: 60}
	config, err := AggregateStreamRuntimeSpecsV2("l403-revision-7", 7, []StreamRuntimeSpecV2{spec})
	if err != nil {
		t.Fatal(err)
	}
	nginx := string(mustCompileV2(t, config).NginxConfig)
	if strings.Count(nginx, "lua_shared_dict l4_v2_rate 16m;") != 1 {
		t.Fatalf("shared dictionary not declared once:\n%s", nginx)
	}
	call := `preread_by_lua_block { local geo = require("cdnca_l4_geo"); local ok, reason, client = geo.enforce("` + l403Stream +
		`"); if not ok then ngx.log(ngx.WARN, "l4_geo ", reason) return end; geo.limit_new_connections("` + l403Stream +
		`", client, 20, 5, 60) geo.session_track("` + l403Stream + `", "`
	if strings.Count(nginx, call) != 2 {
		t.Fatalf("limit not rendered on both sockets (stream-wide key):\n%s", nginx)
	}
}
