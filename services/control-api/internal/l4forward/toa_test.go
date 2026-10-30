package l4forward

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
)

// 回源携带客户端 IP: TOA (toa) and outbound PROXY protocol (proxy_protocol_v1)
// are mutually exclusive; TOA is TCP only (main and additional listeners) and
// excludes inbound PROXY too. Unset toa leaves request digests and runtime
// intents unchanged.
func TestTOAFieldsNormalizeExcludeProxyProtocolAndReachTheRuntimeIntent(t *testing.T) {
	encoded, err := json.Marshal(Fields{Protocol: ProtocolTCP})
	if err != nil || strings.Contains(string(encoded), "toa") {
		t.Fatalf("plain fields digest input changed: %s %v", encoded, err)
	}
	fields := validFields()
	fields.TOA = true
	if err := normalizeFields(&fields); err != nil {
		t.Fatalf("TCP toa rejected: %v", err)
	}
	for name, invalid := range map[string]func(*Fields){
		"UDP":            func(f *Fields) { f.Protocol = ProtocolUDP },
		"outbound PROXY": func(f *Fields) { f.ProxyProtocolV1 = true },
		"inbound PROXY": func(f *Fields) {
			f.ProxyProtocolInbound = true
			f.Geo = GeoPolicy{Enabled: true, UnknownRegionAction: GeoActionAllow, TrustedProxyCIDRs: []string{"198.51.100.0/24"},
				RegionCIDRs: []GeoRegionCIDRs{{Region: "cn-bj", CIDRs: []string{"203.0.113.0/24"}}}}
		},
		"UDP additional listener": func(f *Fields) {
			f.AdditionalListeners = &[]AdditionalListener{{ID: uuid.New(), Protocol: ProtocolUDP, Address: "*", Port: 18081}}
		},
	} {
		fields := validFields()
		invalid(&fields)
		if err := normalizeFields(&fields); err != nil {
			t.Fatalf("%s fixture without toa is invalid: %v", name, err)
		}
		fields = validFields()
		invalid(&fields)
		fields.TOA = true
		if err := normalizeFields(&fields); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("toa with %s: %v", name, err)
		}
	}

	item := Forward{ID: uuid.New(), ScopeID: uuid.New(), Protocol: ProtocolTCP, ListenAddress: "*",
		ListenPort: 9000, UpstreamAddress: "192.0.2.10", UpstreamPort: 9000, MaxConnectionsPerClient: 100, Revision: 1}
	plain, err := json.Marshal(runtimeSpec(item))
	if err != nil || strings.Contains(string(plain), "toa") {
		t.Fatalf("plain stream intent changed: %s %v", plain, err)
	}
	item.TOA = true
	intent, err := json.Marshal(runtimeSpec(item))
	if err != nil || !strings.HasSuffix(string(intent), `"toa":true}`) {
		t.Fatalf("toa stream intent: %s %v", intent, err)
	}
	var wire edgeconfig.L4StreamRuntimeV2
	if err := json.Unmarshal(intent, &wire); err != nil || !wire.TOA {
		t.Fatalf("intent does not decode into the edge contract: %+v %v", wire, err)
	}
	if encoded, err := json.Marshal(Forward{}); err != nil || !strings.Contains(string(encoded), `"toa":false`) {
		t.Fatalf("stream response must always carry toa: %s %v", encoded, err)
	}
}
