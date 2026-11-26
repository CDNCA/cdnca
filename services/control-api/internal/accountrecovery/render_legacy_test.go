package accountrecovery

import (
	"strings"
	"testing"
)

// 已保存的旧默认找回邮件按当前默认发送，管理员改过的保留原样。
func TestRenderAccountRecoveryTemplateReplacesLegacyDefault(t *testing.T) {
	subject, body := renderAccountRecoveryTemplate(legacyAccountRecoverySubject, legacyAccountRecoveryBody, "alice")
	if subject != "找回密码" || strings.Contains(body, "已完成重置") || !strings.Contains(body, "alice") ||
		!strings.Contains(body, "设置新密码") || strings.Contains(body, "<p>") {
		t.Fatalf("legacy default not replaced: %q %q", subject, body)
	}
	custom := "<p>{{.username}}，请点击链接重置。</p>"
	subject, body = renderAccountRecoveryTemplate("自定义标题", custom, "bob")
	if subject != "自定义标题" || body != "<p>bob，请点击链接重置。</p>" {
		t.Fatalf("custom template changed: %q %q", subject, body)
	}
	subject, body = renderAccountRecoveryTemplate(legacyAccountRecoverySubject, custom, "bob")
	if subject != legacyAccountRecoverySubject || body != "<p>bob，请点击链接重置。</p>" {
		t.Fatalf("partially edited template changed: %q %q", subject, body)
	}
}
