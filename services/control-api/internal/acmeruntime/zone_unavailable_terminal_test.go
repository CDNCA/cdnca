package acmeruntime

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/acmeworker"
)

// 所选 DNS API 没有该域名的解析域，订单的域名与 DNS API 都已冻结，
// 重试只会重复同一结果：首次即终态，原因写明域名与下一步。
func TestDNSZoneUnavailableIsTerminalWithReason(t *testing.T) {
	err := &runtimeError{code: codeDNSZoneUnavailable, err: ErrConflict, reason: "所选 DNS API 下没有托管 tenant.example.com 的解析域"}
	code, _ := classifyFailure(err)
	if code != "acme_dns_zone_unavailable" || !validateErrorCode(code) || !dispatchTerminal(err, code) {
		t.Fatalf("code=%q terminal=%v", code, dispatchTerminal(err, code))
	}
	if got := failureReason(err); got != err.reason {
		t.Fatalf("failureReason = %q", got)
	}
	if got := failureReason(codedError("acme_order_unavailable", ErrConflict)); got != "" {
		t.Fatalf("plain runtime code reason = %q", got)
	}
}

// Migration 621 fails stuck orders whose outbox failed with a terminal code;
// its list is terminalFailure's.
func TestMigration621TerminalCodesMatchDispatcher(t *testing.T) {
	raw, err := os.ReadFile("../../migrations/621_certificate_order_outbox_failure.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	list := regexp.MustCompile(`(?s)latest\.last_error_code IN \((.*?)\)`).FindSubmatch(raw)
	if list == nil {
		t.Fatal("621 terminal code list not found")
	}
	var codes []string
	for _, quoted := range regexp.MustCompile(`'([a-z0-9_]+)'`).FindAllSubmatch(list[1], -1) {
		codes = append(codes, string(quoted[1]))
	}
	for _, code := range codes {
		if !terminalFailure(code) {
			t.Errorf("621 lists %q, which the dispatcher retries", code)
		}
	}
	for _, code := range []string{codeDNSProviderPlatformManaged, codeRenewalSkipped, codeDNSZoneUnavailable,
		string(acmeworker.CodeAuthorizationInvalid), string(acmeworker.CodeOrderRejected),
		string(acmeworker.CodeHTTP01NodeAggregateRequired), string(acmeworker.CodeHTTP01NodeUnsupported),
		string(acmeworker.CodeHTTP01NoServingNode), string(acmeworker.CodeEABRequired)} {
		if !terminalFailure(code) {
			t.Fatalf("%q is no longer terminal: update this list and 621's", code)
		}
		if !slices.Contains(codes, code) {
			t.Errorf("621 misses terminal code %q", code)
		}
	}
	if !strings.Contains(string(raw), "format('所选 DNS API 下没有托管 %s 的解析域") {
		t.Fatal("621 reason text differs from dnsacme.DNSZoneUnavailableReason")
	}
}
