package l4forward

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
)

func streamBeFields() Fields {
	return Fields{
		PackageSubscriptionID: new(uuid.New()), Name: "tcp", Protocol: ProtocolTCP, ListenAddress: "*",
		ListenPort: 9000, UpstreamAddress: "8.8.8.8", UpstreamPort: 9000, ConnectTimeoutMS: 1000, ResponseTimeoutMS: 5000,
		MaxConnectionsPerClient: 100, Enabled: true,
	}
}

// 批量添加: "监听端口|IP|回源端口", several ports (first primary), /udp, a
// domain origin, and the malformed forms.
func TestParseBatchLine(t *testing.T) {
	template := streamBeFields()
	template.Name = ""
	fields, err := ParseBatchLine(template, " 88 99/udp |1.2.3.4| 8080 ")
	if err != nil {
		t.Fatal(err)
	}
	if fields.Protocol != ProtocolTCP || fields.ListenPort != 88 || fields.UpstreamPort != 8080 || fields.Name != "TCP 88" ||
		fields.AdditionalListeners == nil || len(*fields.AdditionalListeners) != 1 ||
		(*fields.AdditionalListeners)[0].Protocol != ProtocolUDP || (*fields.AdditionalListeners)[0].Port != 99 {
		t.Fatalf("parsed %+v", fields)
	}
	if err := normalizeFields(&fields); err != nil || fields.UpstreamAddress != "1.2.3.4" || fields.Origins != nil {
		t.Fatalf("normalize = %v, %+v", err, fields)
	}
	domain, err := ParseBatchLine(template, "77/udp|www.example.com|53")
	if err != nil || domain.Protocol != ProtocolUDP {
		t.Fatalf("domain line = %+v, %v", domain, err)
	}
	domain.DNS = DNSPolicy{PositiveMinTTLSeconds: 30, PositiveMaxTTLSeconds: 300, NegativeTTLSeconds: 30, StaleIfErrorSeconds: 600}
	if err := normalizeFields(&domain); err != nil || domain.UpstreamHost != "www.example.com" || domain.UpstreamAddress != "" {
		t.Fatalf("domain normalize = %v, %+v", err, domain)
	}
	// L4-DEFAULT-01：未写 /tcp|/udp 的端口跟随模板协议（批量时即「默认设置」监听协议），写了的照写。
	udpTemplate := template
	udpTemplate.Protocol = ProtocolUDP
	if followed, err := ParseBatchLine(udpTemplate, "53 54/tcp|1.2.3.4|53"); err != nil || followed.Protocol != ProtocolUDP ||
		followed.AdditionalListeners == nil || (*followed.AdditionalListeners)[0].Protocol != ProtocolTCP {
		t.Fatalf("default protocol line = %+v, %v", followed, err)
	}
	for _, line := range []string{"", "88|1.2.3.4", "88|1.2.3.4|0", "x|1.2.3.4|80", "88/sctp|1.2.3.4|80", "88||80", "88|1.2.3.4|80|x"} {
		if _, err := ParseBatchLine(template, line); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("%q accepted: %v", line, err)
		}
	}
}

// 源站列表: several IP origins become the list (first is upstream_address);
// one origin of weight 1 is the plain single-origin stream; invalid lists
// are refused.
func TestNormalizeOrigins(t *testing.T) {
	fields := streamBeFields()
	fields.Origins = []Origin{{Address: "8.8.4.4", Weight: 3}, {Address: "1.1.1.1", Weight: 1, Down: true}}
	if err := normalizeFields(&fields); err != nil || fields.UpstreamAddress != "8.8.4.4" || len(fields.Origins) != 2 {
		t.Fatalf("multi = %v, %+v", err, fields)
	}
	single := streamBeFields()
	single.Origins = []Origin{{Address: "9.9.9.9", Weight: 1}}
	if err := normalizeFields(&single); err != nil || single.UpstreamAddress != "9.9.9.9" || single.Origins != nil {
		t.Fatalf("single = %v, %+v", err, single)
	}
	for name, origins := range map[string][]Origin{
		"empty":     {},
		"all down":  {{Address: "8.8.8.8", Weight: 1, Down: true}, {Address: "8.8.4.4", Weight: 1, Down: true}},
		"weight":    {{Address: "8.8.8.8", Weight: 101}, {Address: "8.8.4.4", Weight: 1}},
		"duplicate": {{Address: "8.8.8.8", Weight: 1}, {Address: "8.8.8.8", Weight: 2}},
		"domain":    {{Address: "a.example.com", Weight: 1}, {Address: "8.8.4.4", Weight: 1}},
		"lone down": {{Address: "8.8.8.8", Weight: 1, Down: true}},
	} {
		fields := streamBeFields()
		fields.Origins = origins
		if err := normalizeFields(&fields); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	follow := streamBeFields()
	follow.UpstreamFollowPort = true
	follow.Origins = []Origin{{Address: "8.8.8.8", Weight: 1}, {Address: "8.8.4.4", Weight: 1}}
	if err := normalizeFields(&follow); err == nil {
		t.Fatal("several origins with follow-port accepted")
	}
}

// ACL: canonical networks, default allow without rules is no ACL, bad
// actions and duplicates refused.
func TestNormalizeACL(t *testing.T) {
	fields := streamBeFields()
	fields.ACL = &ACL{DefaultAction: ACLActionDeny, Rules: []ACLRule{{CIDR: "1.2.3.4", Action: ACLActionAllow},
		{CIDR: "10.1.2.3/8", Action: ACLActionAllow}, {CIDR: "2001:db8::1", Action: ACLActionDeny}}}
	if err := normalizeFields(&fields); err != nil {
		t.Fatal(err)
	}
	want := []ACLRule{{CIDR: "1.2.3.4/32", Action: "allow"}, {CIDR: "10.0.0.0/8", Action: "allow"}, {CIDR: "2001:db8::1/128", Action: "deny"}}
	if fields.ACL == nil || fields.ACL.DefaultAction != ACLActionDeny || len(fields.ACL.Rules) != 3 ||
		fields.ACL.Rules[0] != want[0] || fields.ACL.Rules[1] != want[1] || fields.ACL.Rules[2] != want[2] {
		t.Fatalf("acl = %+v", fields.ACL)
	}
	open := streamBeFields()
	open.ACL = &ACL{DefaultAction: ACLActionAllow}
	if err := normalizeFields(&open); err != nil || open.ACL != nil {
		t.Fatalf("default allow = %v, %+v", err, open.ACL)
	}
	for name, acl := range map[string]ACL{
		"action":    {DefaultAction: "block"},
		"rule":      {Rules: []ACLRule{{CIDR: "1.2.3.4", Action: "drop"}}},
		"cidr":      {Rules: []ACLRule{{CIDR: "1.2.3", Action: "deny"}}},
		"duplicate": {Rules: []ACLRule{{CIDR: "1.2.3.4", Action: "deny"}, {CIDR: "1.2.3.4/32", Action: "allow"}}},
	} {
		fields := streamBeFields()
		value := acl
		fields.ACL = &value
		if err := normalizeFields(&fields); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

// The ACL publishes as guard rules ahead of the stream's own: consecutive
// actions merged, default deny a final catch-all drop, trailing allows
// dropped; IDs stable; the result passes the edge contract.
func TestACLGuardRules(t *testing.T) {
	id := uuid.MustParse("0e4b0000-0000-4000-8000-000000000001")
	own := GuardRule{ID: "0e4b0000-0000-4000-8000-0000000000aa", Action: edgeconfig.L4GuardActionDrop,
		FirstPacket: &edgeconfig.L4GuardFirstPacket{Match: edgeconfig.L4GuardMatchContains, Value: "x"}}
	item := Forward{ID: id, GuardRules: []GuardRule{own}, ACL: ACL{DefaultAction: ACLActionDeny, Rules: []ACLRule{
		{CIDR: "1.2.3.4/32", Action: "allow"}, {CIDR: "10.0.0.0/8", Action: "allow"}, {CIDR: "10.9.0.0/16", Action: "deny"}}}}
	rules := runtimeGuardRulesWithACL(item)
	if len(rules) != 4 || rules[0].Action != "allow" || len(rules[0].ClientIP.CIDRs) != 2 || rules[1].Action != "drop" ||
		rules[2].Action != "drop" || strings.Join(rules[2].ClientIP.CIDRs, ",") != "0.0.0.0/0,::/0" || rules[3].ID != own.ID {
		t.Fatalf("rules = %s", mustJSON(t, rules))
	}
	if again := runtimeGuardRulesWithACL(item); mustJSON(t, again) != mustJSON(t, rules) {
		t.Fatal("ACL rule IDs are not stable")
	}
	if _, err := edgeconfig.NormalizeL4GuardRules(rules, false); err != nil {
		t.Fatalf("edge contract refused: %v", err)
	}
	// default allow with only allow rules publishes nothing.
	item = Forward{ID: id, ACL: ACL{DefaultAction: ACLActionAllow, Rules: []ACLRule{{CIDR: "1.2.3.4/32", Action: "allow"}}}}
	if rules := runtimeGuardRulesWithACL(item); rules != nil {
		t.Fatalf("allow-only ACL published %s", mustJSON(t, rules))
	}
}

// The runtime spec carries origins (several), ip_hash and listen_ipv6 only
// when set, so single-origin round-robin streams publish as before.
func TestRuntimeSpecOriginsBalanceAndIPv6(t *testing.T) {
	item := Forward{ID: uuid.New(), ScopeID: uuid.New(), Revision: 1, Protocol: ProtocolTCP, ListenAddress: "*",
		ListenPort: 9000, UpstreamAddress: "8.8.8.8", UpstreamPort: 9000, BalanceWay: BalanceWayRoundRobin,
		Origins: []Origin{{Address: "8.8.8.8", Weight: 1}}}
	plain := mustJSON(t, runtimeSpec(item))
	if strings.Contains(plain, "origins") || strings.Contains(plain, "balance") || strings.Contains(plain, "listen_ipv6") {
		t.Fatalf("plain spec carries v11 keys: %s", plain)
	}
	item.Origins = []Origin{{Address: "8.8.8.8", Weight: 2}, {Address: "8.8.4.4", Weight: 1, Down: true}}
	item.BalanceWay, item.ListenIPv6 = BalanceWayIPHash, true
	spec := runtimeSpec(item)
	if len(spec.Endpoint.Origins) != 2 || spec.Endpoint.Balance != edgeconfig.L4BalanceIPHash || !spec.ListenIPv6 ||
		!spec.Endpoint.Origins[1].Down || spec.Endpoint.Origins[0].Weight != 2 {
		t.Fatalf("spec = %s", mustJSON(t, spec))
	}
	var edge edgeconfig.L4StreamRuntimeV2
	if err := json.Unmarshal([]byte(mustJSON(t, spec)), &edge); err != nil || !edgeconfig.L4OriginPoolUsed(edge) {
		t.Fatalf("edge decode = %v, %+v", err, edge.Endpoint)
	}
}

func TestBatchActionValidation(t *testing.T) {
	service := &Service{}
	platform := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform"}
	tenant := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"}
	item := BatchActionItem{ID: uuid.New(), ExpectedRevision: 1}
	request := BatchActionRequest{Action: BatchActionSetStatus, AdminStatus: AdminStatusLocked, Items: []BatchActionItem{item},
		IdempotencyKey: "k", RequestID: "r"}
	if _, err := service.BatchAction(t.Context(), tenant, request); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("tenant = %v", err)
	}
	for name, mutate := range map[string]func(*BatchActionRequest){
		"action":    func(r *BatchActionRequest) { r.Action = "cname_mode" },
		"status":    func(r *BatchActionRequest) { r.AdminStatus = "frozen" },
		"empty":     func(r *BatchActionRequest) { r.Items = nil },
		"duplicate": func(r *BatchActionRequest) { r.Items = []BatchActionItem{item, item} },
		"revision":  func(r *BatchActionRequest) { r.Items = []BatchActionItem{{ID: item.ID}} },
	} {
		value := request
		mutate(&value)
		if _, err := service.BatchAction(t.Context(), platform, value); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("%s = %v", name, err)
		}
	}
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
