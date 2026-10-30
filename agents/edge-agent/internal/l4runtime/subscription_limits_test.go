package l4runtime

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

const subscriptionLimitsSub = "77777777-7777-4777-8777-777777777771"

// subscription_limits (SUBSCRIPTION_LIMITS v1, ADR 0012 ML-07) ride from the
// spec into nginx.conf: the shared dictionary, the preread check after the
// per-client rate (a refused session is not counted), the log phase release
// and the bandwidth share; unset they change nothing.
func TestSubscriptionLimitsRenderPrereadLogAndRate(t *testing.T) {
	base := mustCompileV2(t, mustAggregate(t, l403StreamSpec()))
	if bytes.Contains(base.NginxConfig, []byte("subscription")) || bytes.Contains(base.CanonicalJSON, []byte("subscription")) {
		t.Fatalf("unset subscription limits changed the release:\n%s", base.NginxConfig)
	}

	spec := l403StreamSpec()
	spec.NewConnRate = &NewConnRateV2{RatePerSecond: 10, Burst: 5}
	spec.SubscriptionLimits = &SubscriptionLimitsV2{SubscriptionID: subscriptionLimitsSub, MaxConnections: 3, NewPerSecond: 5,
		BandwidthBPS: 8000, Stopped: true}
	compiled := mustCompileV2(t, mustAggregate(t, spec))
	conf := string(compiled.NginxConfig)
	for _, want := range []string{
		"    lua_shared_dict l4_v2_subscriptions 4m;\n",
		"        set $cdnca_l4_subscription \"\";\n        set $cdnca_l4_subscription_rate 0;\n",
		` geo.limit_new_connections("` + l403Stream + `", client, 10, 5, 0) if not geo.subscription_enter("` +
			subscriptionLimitsSub + `", 3, 5, 8000, true, false) then return end; geo.session_track(`,
		"        proxy_download_rate $cdnca_l4_subscription_rate;\n",
		// L4F-E02: one bucket per subscription, not a per-session share
		"        proxy_download_rate_shared l4_v2_subscription_rate:4m $cdnca_l4_subscription;\n",
		"        log_by_lua_block { local geo = require(\"cdnca_l4_geo\"); geo.subscription_leave(); geo.session_end() }\n",
	} {
		if !strings.Contains(conf, want) {
			t.Fatalf("nginx.conf lacks %q:\n%s", want, conf)
		}
	}
	if !bytes.Contains(compiled.CanonicalJSON, []byte(`"subscription_limits":{"subscription_id":"`+subscriptionLimitsSub+`"`)) {
		t.Fatalf("canonical bytes: %s", compiled.CanonicalJSON)
	}

	// with a session log the release runs before session_end, and the
	// check is the last of the preread
	spec.SessionLog, spec.NewConnRate = true, nil
	conf = string(mustCompileV2(t, mustAggregate(t, spec)).NginxConfig)
	if !strings.Contains(conf, `log_by_lua_block { local geo = require("cdnca_l4_geo"); geo.subscription_leave(); geo.session_end() }`) ||
		!strings.Contains(conf, `reason) return end; if not geo.subscription_enter("`+subscriptionLimitsSub+`", 3, 5, 8000, true, true) then return end; geo.session_track(`) {
		t.Fatalf("session log stream:\n%s", conf)
	}

	// no bandwidth: no download rate
	spec.SubscriptionLimits = &SubscriptionLimitsV2{SubscriptionID: subscriptionLimitsSub, MaxConnections: 3}
	if strings.Contains(string(mustCompileV2(t, mustAggregate(t, spec)).NginxConfig), "proxy_download_rate") {
		t.Fatal("download rate without a bandwidth limit")
	}

	for name, limits := range map[string]*SubscriptionLimitsV2{
		"nothing limited": {SubscriptionID: subscriptionLimitsSub},
		"bad id":          {SubscriptionID: "x", MaxConnections: 1},
		"negative":        {SubscriptionID: subscriptionLimitsSub, NewPerSecond: -1, Stopped: true},
	} {
		spec.SubscriptionLimits = limits
		if _, err := AggregateStreamRuntimeSpecsV2("l403-revision-7", 7, []StreamRuntimeSpecV2{spec}); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
}

func mustAggregate(t *testing.T, spec StreamRuntimeSpecV2) ConfigV2 {
	t.Helper()
	config, err := AggregateStreamRuntimeSpecsV2("l403-revision-7", 7, []StreamRuntimeSpecV2{spec})
	if err != nil {
		t.Fatal(err)
	}
	return config
}
