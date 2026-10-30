package systemusersettings

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/systemmailsettings"
	"github.com/jackc/pgx/v5"
)

// defer-small 第 7 项（待出包前全量跑）: choosing an official mail service
// needs its module.mail.<provider>; a refused save writes nothing (no row,
// no idempotency receipt), and a saved provider whose module was revoked
// can still be saved again (RevokeKeepExisting) but not tested.
func TestPostgresSystemMailModuleGate(t *testing.T) {
	pool := systemUserSettingsPool(t)
	scopeID, userID, _ := seedSystemUserSettingsActor(t, pool)
	granted := map[string]bool{"module.mail.aliyun": true}
	service, err := systemmailsettings.NewService(pool, audit.New(pool), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	service.WithSecretCipher(xorCipher{}).WithModuleGate(func(_ context.Context, _ pgx.Tx, module string) (bool, error) {
		return granted[module], nil
	})
	actor := systemmailsettings.Actor{UserID: userID, ScopeID: scopeID, ScopeKind: "platform"}
	save := func(revision int64, value systemmailsettings.Settings, secret, key string) (systemmailsettings.Document, error) {
		return service.Save(t.Context(), actor, systemmailsettings.SaveRequest{ExpectedRevision: revision, Value: value,
			MailSecret: secret, RequestID: key, IdempotencyKey: key})
	}
	sendgrid := systemmailsettings.DefaultSettings()
	sendgrid.MailProvider, sendgrid.MailFrom = "sendgrid", "noreply@mail.example.com"
	if _, err := save(0, sendgrid, "SG.key", "mail-module-1"); !errors.Is(err, systemmailsettings.ErrModuleNotLicensed) {
		t.Fatalf("unlicensed sendgrid save = %v", err)
	}
	var rows, receipts int
	if err := pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM platform_system_mail_settings WHERE platform_scope_id=$1),
		(SELECT count(*) FROM platform_system_mail_settings_write_requests WHERE idempotency_key='mail-module-1')`, scopeID).
		Scan(&rows, &receipts); err != nil || rows != 0 || receipts != 0 {
		t.Fatalf("refused save wrote rows=%d receipts=%d err=%v", rows, receipts, err)
	}
	aliyun := systemmailsettings.DefaultSettings()
	aliyun.MailProvider, aliyun.MailAccessKeyID, aliyun.MailFrom = "aliyun", "LTAI-mail", "noreply@mail.example.com"
	saved, err := save(0, aliyun, "aliyun-secret", "mail-module-2")
	if err != nil || saved.Value.MailProvider != "aliyun" {
		t.Fatalf("licensed aliyun save=(%+v,%v)", saved, err)
	}
	// revoke: the saved choice stays and can be saved again (e.g. the sender
	// name), but a test send through it is refused
	delete(granted, "module.mail.aliyun")
	aliyun.MailFromName = "CDNCA"
	if again, err := save(1, aliyun, "", "mail-module-3"); err != nil || again.Revision != 2 {
		t.Fatalf("resave revoked provider=(%+v,%v)", again, err)
	}
	sent := false
	_, err = service.Test(t.Context(), actor, systemmailsettings.TestRequest{Value: aliyun, To: "ops@example.com", RequestID: "mail-module-4"},
		func(context.Context, systemmailsettings.TestTarget) (string, error) { sent = true; return "x", nil })
	if !errors.Is(err, systemmailsettings.ErrModuleNotLicensed) || sent {
		t.Fatalf("test with revoked module err=%v sent=%v", err, sent)
	}
}
