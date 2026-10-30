package systemsettings

import (
	"strings"
	"testing"
)

func TestDefaultSettingsRemainValidWithOptionalBaselineReferences(t *testing.T) {
	value := DefaultSettings()
	if value.SystemName != "cdnca" || value.UserTitle != "cdnca用户控制台" || value.AdminTitle != "cdnca管理员控制台" {
		t.Fatalf("DefaultSettings() branding = %#v", value)
	}
	if !validSettings(value) {
		t.Fatal("DefaultSettings() must satisfy the system settings contract")
	}
	value.Favicon = "asset://favicon-v1"
	value.Logo = "asset://logo-v1"
	value.LoginAd = "asset://login-ad-v1"
	value.PurchaseNotice = "<p>购买前说明</p>"
	value.Certificate = "vault://certificates/platform"
	value.PrivateKey = "kms-envelope://keys/platform"
	if !validSettings(value) {
		t.Fatal("controlled asset and secure references should be accepted")
	}
}

func TestSystemSettingsRejectOversizedPurchaseNotice(t *testing.T) {
	value := DefaultSettings()
	value.PurchaseNotice = strings.Repeat("x", 65537)
	if validSettings(value) {
		t.Fatal("purchase notice over 65536 runes must be rejected")
	}
}

func TestSystemSettingsRejectRawPrivateKeyReference(t *testing.T) {
	value := DefaultSettings()
	value.PrivateKey = "-----BEGIN PRIVATE KEY-----"
	if validSettings(value) {
		t.Fatal("raw private key material must be rejected")
	}
}

// 全站JS允许的上报/图片域名：只接受 https 主机名（不带协议、端口、路径、通配符、IP），最多 20 个。
func TestGlobalJSReportHostsAcceptOnlyPlainHostnames(t *testing.T) {
	value := DefaultSettings()
	value.GlobalJSReportHosts = []string{"hm.baidu.com", "stats.example.com", "a-b.c1.example.cn"}
	if !validSettings(value) {
		t.Fatal("valid report hosts rejected")
	}
	if got := CSPReportHostSources(value); got != "https://hm.baidu.com https://stats.example.com https://a-b.c1.example.cn" {
		t.Fatalf("csp sources = %q", got)
	}
	for _, host := range []string{"", "https://hm.baidu.com", "hm.baidu.com:443", "hm.baidu.com/path", "*.baidu.com",
		"192.0.2.1", "localhost", "HM.baidu.com", " hm.baidu.com", "hm..baidu.com", "-hm.baidu.com", "hm.baidu.com.",
		"hm.baidu.123", "hm baidu.com", "hm.baidu.com;script-src", "hm.baidu.com'", "xn--.example.com"} {
		value.GlobalJSReportHosts = []string{host}
		if validSettings(value) {
			t.Fatalf("report host %q accepted", host)
		}
	}
	value.GlobalJSReportHosts = []string{"a.example.com", "a.example.com"}
	if validSettings(value) {
		t.Fatal("duplicate report hosts accepted")
	}
	hosts := make([]string, 21)
	for index := range hosts {
		hosts[index] = "h" + string(rune('a'+index)) + ".example.com"
	}
	value.GlobalJSReportHosts = hosts
	if validSettings(value) {
		t.Fatal("21 report hosts accepted")
	}
	value.GlobalJSReportHosts = hosts[:20]
	if !validSettings(value) {
		t.Fatal("20 report hosts rejected")
	}
	value.GlobalJSReportHosts = nil
	if !validSettings(value) || CSPReportHostSources(value) != "" {
		t.Fatal("documents saved before the field must stay valid and add nothing")
	}
}
