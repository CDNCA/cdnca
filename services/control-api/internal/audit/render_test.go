package audit

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

var renderTime = time.Date(2026, 10, 17, 4, 35, 0, 0, time.UTC)

func TestRenderAdminChangeSummary(t *testing.T) {
	admin := uuid.New()
	got := Render(RenderInput{
		ID: uuid.New(), OccurredAt: renderTime, Action: "firewall.policy.put", ActorKind: ActorUser,
		ActorUserID: &admin, ActorName: "ops", ActorIsAdmin: true, SourceIP: "203.0.113.7",
		ResourceType: "site", ResourceID: "s-1", ResourceName: "www.example.test", Result: "success",
		Changes: []Change{{Field: "cc_enabled", Before: false, After: true}},
	}, LocaleZH, time.FixedZone("CST", 8*3600))
	want := "管理员 ops 于 2026-10-17 12:35:00 从 203.0.113.7 修改网站 www.example.test 的防火墙策略：CC 防护从「关闭」改为「开启」"
	if got.Summary != want {
		t.Fatalf("summary =\n%s\nwant\n%s", got.Summary, want)
	}
	if got.Category != string(CategorySecurity) || got.CategoryLabel != "防御策略" || !got.Catalogued {
		t.Fatalf("category = %q %q catalogued=%v", got.Category, got.CategoryLabel, got.Catalogued)
	}
	en := Render(RenderInput{
		ID: uuid.New(), OccurredAt: renderTime, Action: "firewall.policy.put", ActorKind: ActorUser,
		ActorUserID: &admin, ActorName: "ops", ActorIsAdmin: true, SourceIP: "203.0.113.7",
		ResourceType: "site", ResourceID: "s-1", ResourceName: "www.example.test", Result: "success",
		Changes: []Change{{Field: "cc_enabled", Before: false, After: true}},
	}, LocaleEN, nil)
	wantEN := `Administrator ops from 203.0.113.7 at 2026-10-17 04:35:00 updated the firewall policy of site www.example.test: CC protection from "off" to "on"`
	if en.Summary != wantEN {
		t.Fatalf("en summary =\n%s\nwant\n%s", en.Summary, wantEN)
	}
}

func TestRenderDeniedLoginWithReason(t *testing.T) {
	user := uuid.New()
	got := Render(RenderInput{
		ID: uuid.New(), OccurredAt: renderTime, Action: "auth.login", ActorKind: ActorUser, ActorUserID: &user,
		ActorName: "jason", SourceIP: "198.51.100.4", ResourceType: "user", ResourceID: user.String(),
		Result: "denied", ReasonCode: "invalid_credentials",
	}, LocaleZH, nil)
	want := "用户 jason 于 2026-10-17 04:35:00 从 198.51.100.4 登录账号，被拒绝（原因：用户名或密码错误）"
	if got.Summary != want {
		t.Fatalf("summary = %s, want %s", got.Summary, want)
	}
}

func TestRenderSystemPluginNodeAndUncatalogued(t *testing.T) {
	system := Render(RenderInput{OccurredAt: renderTime, Action: "system_cleanup.retention.archive", ActorKind: ActorSystem,
		ResourceType: "audit_chain", ResourceID: "x", Result: "success"}, LocaleZH, nil)
	if !strings.HasPrefix(system.Summary, "系统 于 2026-10-17 04:35:00 按保留期归档") {
		t.Fatalf("system summary = %s", system.Summary)
	}
	plugin := Render(RenderInput{OccurredAt: renderTime, Action: "site.update", ActorKind: ActorPlugin,
		ActorRef: "plugin:waf-pack", ResourceType: "site", ResourceID: "s-1", Result: "success"}, LocaleZH, nil)
	if !strings.HasPrefix(plugin.Summary, "插件 waf-pack 于") {
		t.Fatalf("plugin summary = %s", plugin.Summary)
	}
	unknown := Render(RenderInput{OccurredAt: renderTime, Action: "made.up.action", ActorKind: ActorSystem,
		ResourceType: "thing", ResourceID: "t-1", Result: "failure"}, LocaleZH, nil)
	if unknown.Catalogued || unknown.Category != string(CategoryOther) ||
		!strings.Contains(unknown.Summary, "执行了操作 made.up.action（对象：thing t-1），失败") {
		t.Fatalf("uncatalogued = %+v", unknown)
	}
}

func TestRenderMasksDeclaredFieldsAndHidesUndeclaredPayload(t *testing.T) {
	admin := uuid.New()
	got := Render(RenderInput{
		OccurredAt: renderTime, Action: "identity.user.update", ActorKind: ActorUser, ActorUserID: &admin,
		ActorIsAdmin: true, ResourceType: "user", ResourceID: "u-1", ResourceName: "jason", Result: "success",
		Payload: map[string]any{"email": "jason@example.test", "phone": "13800138000", "internal_revision": 7},
		Changes: []Change{{Field: "email", Before: "old@example.test", After: "new@example.test"}},
	}, LocaleZH, nil)
	for _, leaked := range []string{"jason@example.test", "13800138000", "old@example.test", "new@example.test", "internal_revision"} {
		for _, field := range got.Fields {
			if strings.Contains(field.Value, leaked) || field.Key == leaked {
				t.Fatalf("field leaked %q: %+v", leaked, got.Fields)
			}
		}
		if strings.Contains(got.Summary, leaked) {
			t.Fatalf("summary leaked %q: %s", leaked, got.Summary)
		}
	}
	if len(got.Changes) != 1 || got.Changes[0].Before != "o***@example.test" || got.Changes[0].Label != "邮箱" {
		t.Fatalf("changes = %+v", got.Changes)
	}
	if len(got.Fields) != 2 {
		t.Fatalf("fields = %+v, want masked email and phone only", got.Fields)
	}
}

func TestRenderAPIKeyActorAndResourceFallback(t *testing.T) {
	user := uuid.New()
	got := Render(RenderInput{OccurredAt: renderTime, Action: "site.delete", ActorKind: ActorUser, ActorUserID: &user,
		ActorRef: "api_key:k1", ResourceType: "site", ResourceID: "s-9", Result: "success"}, LocaleZH, nil)
	if !strings.Contains(got.Summary, "用户 "+user.String()+"（通过 API 密钥）") || !strings.Contains(got.Summary, "删除网站 s-9") {
		t.Fatalf("summary = %s", got.Summary)
	}
}

func TestMaskValue(t *testing.T) {
	for in, want := range map[string]string{
		"a@b.test": "a***@b.test", "13800138000": "138******00", "ab": "**", "abcd": "a***", "abcdefghijklmnop": "abc****mnop",
	} {
		if got := maskValue(in); got != want {
			t.Errorf("maskValue(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRenderLicenseSignerTrustPublish(t *testing.T) {
	got := Render(RenderInput{
		ID: uuid.New(), OccurredAt: renderTime, Action: "system.signer_trust.publish", ActorKind: ActorUser,
		ActorName: "ops", SourceIP: "203.0.113.7", ResourceType: "edge_signer_trust", ResourceID: "7", Result: "success",
	}, LocaleZH, nil)
	if !got.Catalogued || got.Category != string(CategorySystem) || !strings.Contains(got.Summary, "发布节点签名信任文档 第 7 版") {
		t.Fatalf("rendered = %+v", got)
	}
}

// UPLAN-07: frontend API error reports carry api_<status>_<code>; the reason is
// shown in Chinese, unknown codes fall back to a sentence with the status.
func TestReasonLabelFrontendAPIErrorCodes(t *testing.T) {
	cases := map[string]string{
		"api_400_observability_logs_invalid_request": "日志查询条件无效，请检查 IP 地址和时间范围",
		"api_403_permission_denied":                  "没有权限",
		"api_409_unmapped_code":                      "请求未能完成（HTTP 409）",
		"api_400_":                                   "api_400_",
		"plain_unknown":                              "plain_unknown",
	}
	for code, want := range cases {
		if got := reasonLabel(code, LocaleZH); got != want {
			t.Errorf("reasonLabel(%q) = %q, want %q", code, got, want)
		}
	}
	if got := reasonLabel("api_500_internal_error", LocaleEN); got != "request failed (HTTP 500)" {
		t.Errorf("en fallback = %q", got)
	}
}
