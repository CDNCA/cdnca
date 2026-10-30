package l4forward

import (
	"errors"
	"testing"
)

// L4-DEFAULT-01：公开契约要求显式 proxy_protocol_inbound，默认「接收 PROXY」不能覆盖
// 明确提交的 false；协议/负载方式只在缺省（空串）时带入。
func TestFieldDefaultsKeepExplicitProxyProtocolFalse(t *testing.T) {
	enabled, udp, hash := true, ProtocolUDP, BalanceWayIPHash
	defaults := FieldDefaults{ProxyProtocolInbound: &enabled, Protocol: &udp, BalanceWay: &hash}
	fields := validFields()
	fields.BalanceWay = BalanceWayRoundRobin
	applyFieldDefaults(&fields, defaults)
	if fields.ProxyProtocolInbound || fields.Protocol != ProtocolTCP || fields.BalanceWay != BalanceWayRoundRobin {
		t.Fatalf("explicit values overridden: %+v", fields)
	}
	if err := normalizeFields(&fields); err != nil {
		t.Fatalf("explicit plain TCP fields rejected after defaults: %v", err)
	}
	missing := validFields()
	missing.Protocol, missing.BalanceWay = "", ""
	applyFieldDefaults(&missing, defaults)
	if missing.Protocol != ProtocolUDP || missing.BalanceWay != BalanceWayIPHash {
		t.Fatalf("missing values not defaulted: %+v", missing)
	}
}

// L4-006：组合校验失败返回稳定字段码，不再是泛化 invalid。
func TestNormalizeFieldsLocatesCombinationErrors(t *testing.T) {
	for name, test := range map[string]struct {
		edit          func(*Fields)
		field, reason string
	}{
		"proxy without trusted source": {func(f *Fields) { f.ProxyProtocolInbound = true }, "proxy_protocol_inbound", "trusted_proxy_required"},
		"trusted source without proxy": {func(f *Fields) {
			f.Geo = GeoPolicy{Enabled: true, UnknownRegionAction: "allow", TrustedProxyCIDRs: []string{"198.51.100.0/24"},
				RegionCIDRs: []GeoRegionCIDRs{{Region: "CN", CIDRs: []string{"203.0.113.0/24"}}}}
		}, "proxy_protocol_inbound", "required_by_trusted_proxy"},
		"udp proxy inbound": {func(f *Fields) { f.Protocol, f.ProxyProtocolInbound = ProtocolUDP, true }, "proxy_protocol_inbound", "udp_unsupported"},
		"udp proxy v1":      {func(f *Fields) { f.Protocol, f.ProxyProtocolV1 = ProtocolUDP, true }, "proxy_protocol_v1", "udp_unsupported"},
		"toa udp":           {func(f *Fields) { f.Protocol, f.TOA = ProtocolUDP, true }, "toa", "tcp_only"},
		"toa proxy":         {func(f *Fields) { f.TOA, f.ProxyProtocolV1 = true, true }, "toa", "proxy_protocol_conflict"},
		"bad balance":       {func(f *Fields) { f.BalanceWay = "least_conn" }, "balance_way", "invalid"},
		"follow with pool": {func(f *Fields) {
			f.UpstreamAddress, f.UpstreamFollowPort, f.UpstreamPort = "", true, 0
			f.Origins = []Origin{{Address: "192.0.2.10", Weight: 1}, {Address: "192.0.2.11", Weight: 1}}
		}, "upstream_follow_port", "origins_conflict"},
	} {
		fields := validFields()
		test.edit(&fields)
		var located *FieldError
		if err := normalizeFields(&fields); !errors.As(err, &located) || located.Field != test.field || located.Reason != test.reason {
			t.Errorf("%s: err=%v, want %s/%s", name, err, test.field, test.reason)
		}
	}
}
