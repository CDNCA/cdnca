package waf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"testing"
)

func FuzzCompileJSONStrictAndDeterministic(f *testing.F) {
	f.Add([]byte(`{"schema_version":"cdnca.edge.waf/v1","policy_version":1,"rules":[]}`))
	f.Add([]byte(`{"schema_version":"cdnca.edge.waf/v1","policy_version":1,"policy_version":2,"rules":[]}`))
	f.Add([]byte(`{"schema_version":"cdnca.edge.waf/v1","policy_version":1,"unknown":true,"rules":[]}`))
	f.Add([]byte(`{"schema_version":"cdnca.edge.waf/v1","policy_version":1,"rules":[],"bad":"\ud800"}`))
	f.Add(append([]byte(`{"schema_version":"cdnca.edge.waf/v1","policy_version":1,"rules":[],"bad":"`), 0xff, '"', '}'))
	f.Add([]byte{0, 1, 2, 3})
	f.Fuzz(func(t *testing.T, raw []byte) {
		first, policy, firstErr := CompileJSON(raw)
		second, _, secondErr := CompileJSON(raw)
		if (firstErr == nil) != (secondErr == nil) {
			t.Fatalf("same input changed validity: first=%v second=%v", firstErr, secondErr)
		}
		if firstErr != nil {
			return
		}
		if !bytes.Equal(first, second) || !json.Valid(first) || len(first) == 0 || first[len(first)-1] != '\n' {
			t.Fatalf("non-deterministic or invalid canonical output: %q / %q", first, second)
		}
		for index := 1; index < len(policy.Rules); index++ {
			previous, current := policy.Rules[index-1], policy.Rules[index]
			if current.Priority < previous.Priority || (current.Priority == previous.Priority && current.RuleID <= previous.RuleID) {
				t.Fatalf("rules are not strictly ordered: %#v", policy.Rules)
			}
		}
	})
}

func FuzzCIDRMatcherMatchesNetip(f *testing.F) {
	f.Add([]byte{192, 0, 2, 9}, uint8(24), false, []byte{192, 0, 2, 8})
	f.Add([]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9}, uint8(127), true, []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8})
	f.Fuzz(func(t *testing.T, networkBytes []byte, bits uint8, ipv6 bool, addressBytes []byte) {
		network, address, maximum, ok := fuzzAddresses(networkBytes, addressBytes, ipv6)
		if !ok {
			return
		}
		prefixBits := int(bits) % (maximum + 1)
		prefix, err := netip.ParsePrefix(fmt.Sprintf("%s/%d", network, prefixBits))
		if err != nil || prefix.Addr().Is4In6() {
			return
		}
		compiled, err := compileCIDR(fmt.Sprintf("%s/%d", network, prefixBits))
		if err != nil {
			t.Fatal(err)
		}
		if got, want := cidrMatches(*compiled, address), prefix.Masked().Contains(address); got != want {
			t.Fatalf("cidrMatches(%s, %s) = %t, want %t", prefix, address, got, want)
		}
	})
}

func FuzzEvaluateDeterministic(f *testing.F) {
	f.Add(
		[]byte(`{"schema_version":"cdnca.edge.waf/v1","policy_version":1,"rules":[{"rule_id":"deny","priority":1,"action":"block","flow":"stop","match":{"source_cidr":"192.0.2.0/24"}}]}`),
		"192.0.2.8", "GET", "/",
	)
	f.Add([]byte(`{"schema_version":"cdnca.edge.waf/v1","policy_version":1,"rules":[]}`), "::ffff:192.0.2.1", "POST", "/bad")
	f.Fuzz(func(t *testing.T, raw []byte, source, method, requestPath string) {
		_, policy, err := CompileJSON(raw)
		if err != nil {
			return
		}
		address, err := netip.ParseAddr(source)
		if err != nil {
			return
		}
		request := Request{Host: "example.test", Port: 443, Method: method, Path: requestPath, SourceAddr: address}
		first := (&Evaluator{}).EvaluateAt(policy, request, fixedEvaluationTime())
		second := (&Evaluator{}).EvaluateAt(policy, request, fixedEvaluationTime())
		if !reflect.DeepEqual(first, second) {
			t.Fatalf("evaluation changed: first=%#v second=%#v", first, second)
		}
		if address.Is4In6() && (first.Action != ActionBlock || first.Reason != reasonInvalidRequest || first.RuleID != "" || first.Version != policy.PolicyVersion) {
			t.Fatalf("mapped IPv6 request did not fail closed: %#v", first)
		}
	})
}

func fuzzAddresses(networkBytes, addressBytes []byte, ipv6 bool) (netip.Addr, netip.Addr, int, bool) {
	if !ipv6 {
		if len(networkBytes) < 4 || len(addressBytes) < 4 {
			return netip.Addr{}, netip.Addr{}, 0, false
		}
		return netip.AddrFrom4([4]byte(networkBytes[:4])), netip.AddrFrom4([4]byte(addressBytes[:4])), 32, true
	}
	if len(networkBytes) < 16 || len(addressBytes) < 16 {
		return netip.Addr{}, netip.Addr{}, 0, false
	}
	network := netip.AddrFrom16([16]byte(networkBytes[:16]))
	address := netip.AddrFrom16([16]byte(addressBytes[:16]))
	if network.Is4In6() || address.Is4In6() {
		return netip.Addr{}, netip.Addr{}, 0, false
	}
	return network, address, 128, true
}
