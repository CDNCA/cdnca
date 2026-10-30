package edgeconfig

import (
	"bytes"
	"testing"
	"time"
)

func ccV2InitWrapper(t *testing.T, nginx []byte) ([]byte, []byte) {
	t.Helper()
	startMarker := []byte("  " + CCV2RegistryBeginMarker + "\n")
	endMarker := []byte("  " + CCV2RegistryEndMarker + "\n")
	start := bytes.Index(nginx, startMarker)
	if start < 0 {
		t.Fatal("CC v2 registry begin marker not found")
	}
	endOffset := bytes.Index(nginx[start:], endMarker)
	if endOffset < 0 {
		t.Fatal("CC v2 registry end marker not found")
	}
	end := start + endOffset + len(endMarker)
	wrapper := bytes.Clone(nginx[start:end])
	initStart := len(startMarker)
	initEnd := len(wrapper) - len(endMarker)
	return wrapper, bytes.Clone(wrapper[initStart:initEnd])
}

func TestCanonicalCCV2PolicyRejectsImpossiblePriorityAndControlPath(t *testing.T) {
	valid := testCCV2Policy("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "11111111-1111-4111-8111-111111111111")
	tests := map[string]func(*CCV2Policy){
		"zero priority":  func(value *CCV2Policy) { value.Rules[0].Priority = 0 },
		"large priority": func(value *CCV2Policy) { value.Rules[0].Priority = 1_000_001 },
		"control path": func(value *CCV2Policy) {
			value.Rules[0].Match.Path = &CCV2PathMatch{Kind: CCV2PathPrefix, Value: "/api\u0001"}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			candidate.Rules = append([]CCV2Rule(nil), valid.Rules...)
			mutate(&candidate)
			if _, err := CanonicalCCV2Policy(candidate); err == nil {
				t.Fatal("invalid policy accepted")
			}
		})
	}
}

func testCCV2Policy(tenantID, siteID string) CCV2Policy {
	return CCV2Policy{
		SchemaVersion: CCV2SchemaVersion, TenantScopeID: tenantID, SiteID: siteID,
		PolicyID: "22222222-2222-4222-8222-222222222222", PolicyVersion: 7,
		BindingID: "33333333-3333-4333-8333-333333333333", BindingRevision: 3,
		PublicationID: "44444444-4444-4444-8444-444444444444", Enabled: true,
		TrustedProxies: []string{}, Allowlist: []string{},
		Rules: []CCV2Rule{{
			RuleID: "55555555-5555-4555-8555-555555555555", Priority: 10, Flow: CCV2FlowContinue,
			Match:     CCV2Match{Host: "cc.example.test", Port: 8080, Method: "GET", Path: &CCV2PathMatch{Kind: CCV2PathPrefix, Value: "/api"}},
			Dimension: CCV2DimensionClientIP,
			Limit:     CCV2Limit{Algorithm: CCV2AlgorithmFixedWindow, Requests: 2, WindowSeconds: 60},
			Action:    CCV2Action{Kind: CCV2ActionLog},
		}},
	}
}

// ccV2TestHookPrelude is the identity line a telemetry server's CC v2 hook
// starts with (ccV2IdentityPrelude), for a site without a package.
func ccV2TestHookPrelude(tenantID, siteID, versionID string) string {
	return "      " + ccV2IdentityPrelude(&ServerTelemetryIdentity{TenantID: tenantID, SiteID: siteID, ConfigVersionID: versionID}) + "\n"
}

func testCCV2Site(siteID, domain string, port uint16, binding *CCV2SiteBinding) Site {
	return Site{ID: siteID, Domain: domain, ListenPort: port, Protocol: ProtocolHTTP,
		Origins: []Origin{{Host: "127.0.0.1", Port: 9000, Weight: 1}}, Balance: BalanceRoundRobin,
		FailoverTries: 1, ConnectTimeout: 250 * time.Millisecond, ReadTimeout: 2 * time.Second,
		ACL: ACLPolicy{DefaultAction: ACLAllow}, CCV2: binding}
}

func replaceCCV2ServerHook(t *testing.T, nginx []byte, entryID, replacement string) []byte {
	t.Helper()
	marker := []byte(`return require("cc").access("` + entryID + `")`)
	markerAt := bytes.Index(nginx, marker)
	if markerAt < 0 {
		t.Fatal("CC hook marker not found")
	}
	start := bytes.LastIndex(nginx[:markerAt], []byte("    server_rewrite_by_lua_block {\n"))
	endOffset := bytes.Index(nginx[markerAt:], []byte("\n    }\n"))
	if start < 0 || endOffset < 0 {
		t.Fatal("CC hook block not found")
	}
	end := markerAt + endOffset + len("\n    }\n")
	result := append([]byte(nil), nginx[:start]...)
	result = append(result, replacement...)
	return append(result, nginx[end:]...)
}

func moveCCV2HookAfterFirstSet(t *testing.T, nginx []byte, entryID string) []byte {
	t.Helper()
	without := replaceCCV2ServerHook(t, nginx, entryID, "")
	marker := []byte(`return require("cc").access("` + entryID + `")`)
	markerAt := bytes.Index(nginx, marker)
	start := bytes.LastIndex(nginx[:markerAt], []byte("    server_rewrite_by_lua_block {\n"))
	endOffset := bytes.Index(nginx[markerAt:], []byte("\n    }\n"))
	end := markerAt + endOffset + len("\n    }\n")
	hook := append([]byte(nil), nginx[start:end]...)
	serverName := bytes.LastIndex(without[:start], []byte("    server_name "))
	firstSetOffset := bytes.Index(without[serverName:], []byte("    set "))
	if serverName < 0 || firstSetOffset < 0 {
		t.Fatal("public server set directive not found")
	}
	firstSet := serverName + firstSetOffset
	lineEndOffset := bytes.IndexByte(without[firstSet:], '\n')
	if lineEndOffset < 0 {
		t.Fatal("set directive line is unterminated")
	}
	insertAt := firstSet + lineEndOffset + 1
	result := append([]byte(nil), without[:insertAt]...)
	result = append(result, hook...)
	return append(result, without[insertAt:]...)
}
