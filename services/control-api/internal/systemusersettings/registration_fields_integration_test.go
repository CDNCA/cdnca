package systemusersettings

import (
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
)

// / what the administrator saves on
// 账号与安全 reads back, and the public projection carries the QQ and
// username requirements and the terms with their version.
func TestPostgresRegistrationFieldsSaveAndPublic(t *testing.T) {
	pool := systemUserSettingsPool(t)
	scopeID, userID, _ := seedSystemUserSettingsActor(t, pool)
	service, err := NewService(pool, audit.New(pool), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{UserID: userID, ScopeID: scopeID, ScopeKind: "platform"}
	public, err := service.GetPublic(t.Context(), scopeID)
	defaults := DefaultSettings()
	if err != nil || !public.UsernameRequired || public.QQRequired || public.TermsBody != defaults.TermsBody ||
		public.TermsVersion != TermsVersion(defaults.TermsTitle, defaults.TermsBody) {
		t.Fatalf("no row: %#v %v", public, err)
	}
	settings := defaults
	settings.QQRequired, settings.UsernameRequired = true, false
	settings.TermsTitle, settings.TermsBody = "注册协议", "第一条 新正文"
	if _, err := service.Save(t.Context(), actor, SaveRequest{Value: settings, IdempotencyKey: "reg-fields-1", RequestID: "reg-fields-1"}); err != nil {
		t.Fatal(err)
	}
	loaded, err := service.Get(t.Context(), actor)
	if err != nil || !loaded.Value.QQRequired || loaded.Value.UsernameRequired ||
		loaded.Value.TermsTitle != "注册协议" || loaded.Value.TermsBody != "第一条 新正文" {
		t.Fatalf("read back: %#v %v", loaded.Value, err)
	}
	public, err = service.GetPublic(t.Context(), scopeID)
	if err != nil || !public.QQRequired || public.UsernameRequired || public.TermsTitle != "注册协议" ||
		public.TermsBody != "第一条 新正文" || public.TermsVersion != TermsVersion("注册协议", "第一条 新正文") {
		t.Fatalf("public: %#v %v", public, err)
	}
}

// an installation that saved the old default placeholder pair
// reads it as an empty body on the settings page (revision unchanged) and has
// no published terms; its version is still that of the stored pair.
func TestPostgresLegacyDefaultTermsReadAsUnpublished(t *testing.T) {
	pool := systemUserSettingsPool(t)
	scopeID, userID, _ := seedSystemUserSettingsActor(t, pool)
	service, err := NewService(pool, audit.New(pool), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{UserID: userID, ScopeID: scopeID, ScopeKind: "platform"}
	settings := DefaultSettings()
	settings.TermsTitle, settings.TermsBody = "用户协议、法律声明和隐私政策", "这里填写协议内容"
	saved, err := service.Save(t.Context(), actor, SaveRequest{Value: settings, IdempotencyKey: "reg-terms-legacy", RequestID: "reg-terms-legacy"})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		loaded, err := service.Get(t.Context(), actor)
		if err != nil || loaded.Value.TermsBody != "" || loaded.Value.TermsTitle != settings.TermsTitle || loaded.Revision != saved.Revision {
			t.Fatalf("read: %q %q revision=%d/%d %v", loaded.Value.TermsTitle, loaded.Value.TermsBody, loaded.Revision, saved.Revision, err)
		}
	}
	var stored string
	if err := pool.QueryRow(t.Context(), `SELECT settings->>'terms_body' FROM platform_system_user_settings WHERE platform_scope_id=$1`, scopeID).Scan(&stored); err != nil || stored != "这里填写协议内容" {
		t.Fatalf("stored body=%q err=%v", stored, err)
	}
	public, err := service.GetPublic(t.Context(), scopeID)
	if err != nil || public.TermsPublished || public.TermsVersion != TermsVersion(settings.TermsTitle, settings.TermsBody) {
		t.Fatalf("public: published=%v version=%q %v", public.TermsPublished, public.TermsVersion, err)
	}
}
