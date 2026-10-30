package systemusersettings

// Mail settings reuse this package's isolated database and full migration fixture.
import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/systemmailsettings"
)

func TestPostgresSystemMailSMSProviderWriteGuard(t *testing.T) {
	pool := systemUserSettingsPool(t)
	scopeID, userID, roleID := seedSystemUserSettingsActor(t, pool)
	service, err := systemmailsettings.NewService(pool, audit.New(pool), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	actor := systemmailsettings.Actor{UserID: userID, ScopeID: scopeID, ScopeKind: "platform"}
	request := systemmailsettings.SaveRequest{
		Value: systemmailsettings.DefaultSettings(), RequestID: "mail-provider-initial", IdempotencyKey: "mail-provider-initial",
	}
	initial, err := service.Save(t.Context(), actor, request)
	if err != nil || initial.Revision != 1 || initial.Value.SMSProvider != "" {
		t.Fatalf("save inherited provider=(%+v,%v)", initial, err)
	}
	replayed, err := service.Save(t.Context(), actor, request)
	if err != nil || !replayed.Replayed || replayed.Revision != initial.Revision || replayed.Value != initial.Value {
		t.Fatalf("retry=(%+v,%v)", replayed, err)
	}
	request.Value.SMSProvider = "https_json"
	if _, err := service.Save(t.Context(), actor, request); !errors.Is(err, systemmailsettings.ErrIdempotencyConflict) {
		t.Fatalf("changed retry error=%v", err)
	}
	request.IdempotencyKey = "mail-provider-stale"
	if _, err := service.Save(t.Context(), actor, request); !errors.Is(err, systemmailsettings.ErrRevisionConflict) {
		t.Fatalf("stale revision error=%v", err)
	}
	request.ExpectedRevision = initial.Revision
	request.IdempotencyKey = "mail-provider-supported"
	saved, err := service.Save(t.Context(), actor, request)
	if err != nil || saved.Revision != 2 || saved.Value.SMSProvider != "https_json" {
		t.Fatalf("save supported provider=(%+v,%v)", saved, err)
	}
	assertUnchanged := func(want systemmailsettings.Document, writes int) {
		t.Helper()
		current, err := service.Get(t.Context(), actor)
		if err != nil || current.Revision != want.Revision || current.Value != want.Value || !current.UpdatedAt.Equal(want.UpdatedAt) {
			t.Fatalf("saved settings changed=(%+v,%v), want %+v", current, err, want)
		}
		var requests, events int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM platform_system_mail_settings_write_requests WHERE target_scope_id=$1`, scopeID).Scan(&requests); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE scope_id=$1 AND action='system_mail_settings.update'`, scopeID).Scan(&events); err != nil {
			t.Fatal(err)
		}
		if requests != writes || events != writes {
			t.Fatalf("write requests=%d audit events=%d, want %d", requests, events, writes)
		}
	}
	for index, provider := range []string{"smsbao", "tencent", "disabled", "HTTPS_JSON", " https_json", "https_json\n", "unknown", "ALIYUN"} {
		request.ExpectedRevision = saved.Revision
		request.IdempotencyKey = fmt.Sprintf("mail-provider-rejected-%d", index)
		request.Value.SMSProvider = provider
		if result, err := service.Save(t.Context(), actor, request); !errors.Is(err, systemmailsettings.ErrInvalidInput) {
			t.Fatalf("unsupported provider %q saved=(%+v,%v), want ErrInvalidInput", provider, result, err)
		}
		assertUnchanged(saved, 2)
	}
	request.IdempotencyKey = "mail-provider-rejected-0"
	request.Value.SMSProvider = ""
	saved, err = service.Save(t.Context(), actor, request)
	if err != nil || saved.Revision != 3 {
		t.Fatalf("corrected rejected request=(%+v,%v)", saved, err)
	}
	// Simulate a row written by the older version, without changing read policy.
	if _, err := pool.Exec(t.Context(), `UPDATE platform_system_mail_settings
		SET settings=jsonb_set(settings,'{sms_provider}','"tencent"'::jsonb)
		WHERE platform_scope_id=$1`, scopeID); err != nil {
		t.Fatal(err)
	}
	legacy, err := service.Get(t.Context(), actor)
	if err != nil || legacy.Revision != saved.Revision || legacy.Value.SMSProvider != "tencent" {
		t.Fatalf("read legacy settings=(%+v,%v)", legacy, err)
	}
	runtimeSettings, err := systemmailsettings.ReadRuntime(t.Context(), pool)
	if err != nil || !runtimeSettings.Configured || runtimeSettings.Revision != legacy.Revision || runtimeSettings.Value != legacy.Value {
		t.Fatalf("read legacy runtime settings=(%+v,%v)", runtimeSettings, err)
	}
	request.ExpectedRevision = legacy.Revision
	request.IdempotencyKey = "mail-provider-repair-legacy"
	request.Value = legacy.Value
	request.Value.SMSProvider = "https_json"
	repaired, err := service.Save(t.Context(), actor, request)
	if err != nil || repaired.Revision != legacy.Revision+1 || repaired.Value.SMSProvider != "https_json" {
		t.Fatalf("repair legacy provider=(%+v,%v)", repaired, err)
	}
	assertUnchanged(repaired, 4)
	if _, err := pool.Exec(t.Context(), `DELETE FROM role_permissions WHERE role_id=$1 AND permission_name='system_configuration.manage'`, roleID); err != nil {
		t.Fatal(err)
	}
	request.ExpectedRevision = repaired.Revision
	request.IdempotencyKey = "mail-provider-permission-revoked"
	request.Value.SMSProvider = ""
	if _, err := service.Save(t.Context(), actor, request); !errors.Is(err, systemmailsettings.ErrPermissionDenied) {
		t.Fatalf("permission revocation error=%v", err)
	}
	assertUnchanged(repaired, 4)
	if err := audit.New(pool).VerifyScope(t.Context(), scopeID); err != nil {
		t.Fatalf("verify audit chain: %v", err)
	}
}
