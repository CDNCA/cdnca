package systemusersettings

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/systemmailsettings"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresUserSettingsPersistenceAuthorizationIdempotencyAndAudit(t *testing.T) {
	pool := systemUserSettingsPool(t)
	scopeID, userID, roleID := seedSystemUserSettingsActor(t, pool)
	now := time.Date(2026, 8, 14, 1, 2, 3, 456000000, time.UTC)
	service, err := NewService(pool, audit.NewWithClock(pool, func() time.Time { return now }), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{UserID: userID, ScopeID: scopeID, ScopeKind: "platform"}
	if _, err := pool.Exec(t.Context(), `INSERT INTO platform_system_mail_settings
		(platform_scope_id,revision,settings,updated_at)
		VALUES($1,2,$2,now())`, scopeID, `{"smtp_address":"smtp.example.com","smtp_ssl":false,"smtp_port":587,"smtp_user":"mailer","smtp_password_reference":"vault://smtp/password","sms_provider":"","sms_access_key_id":"","sms_access_key_reference":"","sms_signature_name":""}`); err != nil {
		t.Fatal(err)
	}
	persistedMail, err := systemmailsettings.ReadRuntime(t.Context(), pool)
	if err != nil || !persistedMail.Configured || persistedMail.Revision != 2 ||
		persistedMail.Value.SMTPAddress != "smtp.example.com" || persistedMail.Value.SMTPPort != 587 {
		t.Fatalf("persisted runtime mail settings=(%#v,%v)", persistedMail, err)
	}

	initial, err := service.Get(t.Context(), actor)
	if err != nil || initial.Revision != 0 || initial.Schema != Schema() {
		t.Fatalf("initial document=(%#v,%v)", initial, err)
	}
	settings := initial.Value
	settings.RegistrationEnabled = true
	settings.AlipayPaymentEnabled = true
	settings.DefaultRechargeMethod = "alipay"
	settings.RechargeRestriction = "individual_verified"
	request := SaveRequest{ExpectedRevision: 0, Value: settings, IdempotencyKey: "system-user-settings-integration", RequestID: "system-user-settings-integration-request"}
	saved, err := service.Save(t.Context(), actor, request)
	if err != nil || saved.Revision != 1 || saved.Replayed {
		t.Fatalf("saved document=(%#v,%v)", saved, err)
	}
	var templateCount int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM notification_templates
		WHERE template_id IN ($1,$2,$3) AND version=1`, registrationSuccessTemplateID,
		accountRecoveryTemplateID, registrationVerificationTemplateID).Scan(&templateCount); err != nil || templateCount != 4 {
		t.Fatalf("published template count=(%d,%v), want 4", templateCount, err)
	}
	var verificationBody string
	var verificationVariables []string
	if err := pool.QueryRow(t.Context(), `SELECT body,variables FROM notification_templates
		WHERE template_id=$1 AND version=1 AND channel='sms'`, registrationVerificationTemplateID).
		Scan(&verificationBody, &verificationVariables); err != nil || verificationBody != "您的验证码为{{.captcha}}，在5分钟内有效。" ||
		len(verificationVariables) != 1 || verificationVariables[0] != "captcha" {
		t.Fatalf("published verification template=(%q,%v,%v)", verificationBody, verificationVariables, err)
	}

	loaded, err := service.Get(t.Context(), actor)
	if err != nil || loaded.Revision != 1 || !loaded.Value.RegistrationEnabled || !loaded.Value.AlipayPaymentEnabled || loaded.Value.DefaultRechargeMethod != "alipay" || loaded.Value.RechargeRestriction != "individual_verified" {
		t.Fatalf("loaded document=(%#v,%v)", loaded, err)
	}
	public, err := service.GetPublic(t.Context(), scopeID)
	if err != nil || public.SessionTTLSeconds != settings.SessionTTLSeconds || !public.RegistrationEnabled {
		t.Fatalf("public policy=(%#v,%v)", public, err)
	}
	replayed, err := service.Save(t.Context(), actor, request)
	if err != nil || !replayed.Replayed || replayed.Revision != 1 {
		t.Fatalf("replayed document=(%#v,%v)", replayed, err)
	}
	request.Value.SMSCodeLoginEnabled = true
	if _, err := service.Save(t.Context(), actor, request); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("idempotency conflict error=%v", err)
	}
	request.IdempotencyKey = "system-user-settings-stale-revision"
	if _, err := service.Save(t.Context(), actor, request); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("revision conflict error=%v", err)
	}

	if err := audit.New(pool).VerifyScope(t.Context(), scopeID); err != nil {
		t.Fatalf("verify audit chain: %v", err)
	}
	var events int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE scope_id=$1 AND action='system_user_settings.update'`, scopeID).Scan(&events); err != nil || events != 1 {
		t.Fatalf("audit events=(%d,%v)", events, err)
	}

	if _, err := pool.Exec(t.Context(), `DELETE FROM role_assignments WHERE scope_id=$1 AND user_id=$2 AND role_id=$3`, scopeID, userID, roleID); err != nil {
		t.Fatal(err)
	}
	request.ExpectedRevision = 1
	request.IdempotencyKey = "system-user-settings-permission-revoked"
	if _, err := service.Save(t.Context(), actor, request); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("permission revocation error=%v", err)
	}
}

func TestPostgresPublicSettingsResolveTenantAndGlobalScopes(t *testing.T) {
	pool := systemUserSettingsPool(t)
	platformScopeID, userID, _ := seedSystemUserSettingsActor(t, pool)
	now := time.Date(2026, 8, 14, 1, 2, 3, 456000000, time.UTC)
	service, err := NewService(pool, audit.NewWithClock(pool, func() time.Time { return now }), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{UserID: userID, ScopeID: platformScopeID, ScopeKind: "platform"}
	settings := DefaultSettings()
	settings.SessionTTLSeconds = 3600
	settings.RegistrationEnabled = true
	if _, err := service.Save(t.Context(), actor, SaveRequest{
		Value: settings, IdempotencyKey: "public-scope-resolution", RequestID: "public-scope-resolution-request",
	}); err != nil {
		t.Fatal(err)
	}
	tenantID, tenantScopeID := uuid.New(), uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO tenants(id,display_name) VALUES($1,'Public policy tenant')`, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, tenantScopeID, tenantID); err != nil {
		t.Fatal(err)
	}
	for name, scopeID := range map[string]uuid.UUID{"platform": platformScopeID, "tenant": tenantScopeID, "global": uuid.Nil} {
		public, err := service.GetPublic(t.Context(), scopeID)
		if err != nil || public.SessionTTLSeconds != 3600 || !public.RegistrationEnabled {
			t.Fatalf("public policy for %s scope=(%#v,%v)", name, public, err)
		}
	}
	for _, channel := range []notification.Channel{notification.ChannelEmail, notification.ChannelSMS} {
		ref, found, err := service.GetRegistrationVerificationTemplate(t.Context(), tenantScopeID, channel)
		if err != nil || !found || ref.ID != registrationVerificationTemplateID || ref.Version != 1 || ref.Channel != channel {
			t.Fatalf("registration template for %s=(%#v,%t,%v)", channel, ref, found, err)
		}
	}
	recovery, found, err := service.GetAccountRecoveryTemplate(t.Context(), tenantScopeID, notification.ChannelEmail)
	if err != nil || !found || recovery.ID != accountRecoveryTemplateID || recovery.Version != 1 {
		t.Fatalf("account recovery template=(%#v,%t,%v)", recovery, found, err)
	}
	registration, variables, found, err := service.GetRegistrationSuccessTemplate(t.Context(), tenantScopeID)
	if err != nil || !found || registration.ID != registrationSuccessTemplateID || registration.Version != 1 ||
		len(variables) != 1 || variables[0] != "username" {
		t.Fatalf("registration success template=(%#v,%v,%t,%v)", registration, variables, found, err)
	}
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	transactionalRegistration, transactionalVariables, found, err := service.GetRegistrationSuccessTemplateTx(t.Context(), tx, tenantScopeID)
	if err != nil || !found || transactionalRegistration != registration || len(transactionalVariables) != 1 || transactionalVariables[0] != "username" {
		t.Fatalf("transactional registration success template=(%#v,%v,%t,%v)", transactionalRegistration, transactionalVariables, found, err)
	}
	if _, found, err := service.GetAccountRecoveryTemplate(t.Context(), tenantScopeID, notification.ChannelSMS); err != nil || found {
		t.Fatalf("unexpected SMS account recovery override=(%t,%v)", found, err)
	}
}

func TestPostgresCaptchaRuntimeExposesOnlyTheAppIDPublicly(t *testing.T) {
	pool := systemUserSettingsPool(t)
	platformScopeID, userID, _ := seedSystemUserSettingsActor(t, pool)
	now := time.Date(2026, 10, 17, 1, 2, 3, 0, time.UTC)
	service, err := NewService(pool, audit.NewWithClock(pool, func() time.Time { return now }), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if runtime, err := service.CaptchaRuntime(t.Context()); err != nil || runtime.Provider != "tencent" || runtime.AppID != "" {
		t.Fatalf("default captcha runtime=(%#v,%v)", runtime, err)
	}
	settings := DefaultSettings()
	settings.SMSAntiAbuseMode = "tencent"
	settings.CaptchaProvider = "tencent"
	settings.CaptchaSecretIDReference = "vault://captcha/secret-id"
	settings.CaptchaSecretKeyReference = "vault://captcha/secret-key"
	settings.CaptchaAppID = "190000001"
	settings.CaptchaAppSecretReference = "vault://captcha/app-secret"
	if _, err := service.Save(t.Context(), Actor{UserID: userID, ScopeID: platformScopeID, ScopeKind: "platform"}, SaveRequest{
		Value: settings, IdempotencyKey: "captcha-runtime", RequestID: "captcha-runtime-request",
	}); err != nil {
		t.Fatal(err)
	}
	runtime, err := service.CaptchaRuntime(t.Context())
	if err != nil || runtime != (CaptchaRuntime{
		Provider: "tencent", SecretIDReference: "vault://captcha/secret-id", SecretKeyReference: "vault://captcha/secret-key",
		AppID: "190000001", AppSecretReference: "vault://captcha/app-secret",
	}) {
		t.Fatalf("captcha runtime=(%#v,%v)", runtime, err)
	}
	public, err := service.GetPublic(t.Context(), platformScopeID)
	if err != nil || public.SMSAntiAbuseMode != "tencent" || public.CaptchaProvider != "tencent" || public.CaptchaAppID != "190000001" {
		t.Fatalf("public captcha projection=(%#v,%v)", public, err)
	}
	if strings.Contains(fmt.Sprintf("%#v", public), "vault://") {
		t.Fatalf("public settings leaked a secret reference: %#v", public)
	}
}

func seedSystemUserSettingsActor(t *testing.T, pool *pgxpool.Pool) (uuid.UUID, uuid.UUID, uuid.UUID) {
	t.Helper()
	scopeID, userID, roleID := uuid.New(), uuid.New(), uuid.New()
	_, err := pool.Exec(t.Context(), `
		INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'platform',NULL);
		INSERT INTO users(id,username,display_name,password_hash,status) VALUES($2,'system-user-settings-owner','System user settings owner','not-used','active');
		INSERT INTO memberships(scope_id,user_id,status) VALUES($1,$2,'active');
		INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($3,$1,'platform_owner','Integration role',true);
		INSERT INTO role_permissions(role_id,permission_name)
			VALUES($3,'system_configuration.read'),($3,'system_configuration.manage')
			ON CONFLICT DO NOTHING;
		INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`,
		pgx.QueryExecModeSimpleProtocol, scopeID, userID, roleID)
	if err != nil {
		t.Fatal(err)
	}
	return scopeID, userID, roleID
}

func systemUserSettingsPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	admin, err := pgxpool.New(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := admin.Acquire(t.Context())
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	if _, err := connection.Exec(t.Context(), `SELECT pg_advisory_lock(
		hashtextextended('cdnca-jobhttp-command-external-roles',0))`); err != nil {
		connection.Release()
		admin.Close()
		t.Fatal(err)
	}
	if _, err := connection.Exec(t.Context(), `SELECT pg_advisory_lock(726491175848210)`); err != nil {
		var unlocked bool
		_ = connection.QueryRow(context.Background(), `SELECT pg_advisory_unlock(
			hashtextextended('cdnca-jobhttp-command-external-roles',0))`).Scan(&unlocked)
		connection.Release()
		admin.Close()
		t.Fatal(err)
	}
	databaseName := "system_user_settings_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{databaseName}.Sanitize()
	createdRoleOIDs := make(map[string]uint32, 2)
	databaseCreated := false
	var pool *pgxpool.Pool
	t.Cleanup(func() {
		if pool != nil {
			pool.Close()
		}
		cleanupCtx, cancel := databasetest.CleanupContext()
		defer cancel()
		if databaseCreated {
			if _, err := connection.Exec(cleanupCtx, "DROP DATABASE "+identifier+" WITH (FORCE)"); err != nil {
				t.Errorf("drop database: %v", err)
			} else if err := cleanupSystemUserSettingsMigrationRoles(cleanupCtx, connection, createdRoleOIDs); err != nil {
				t.Errorf("drop migration roles: %v", err)
			}
		} else if err := cleanupSystemUserSettingsMigrationRoles(cleanupCtx, connection, createdRoleOIDs); err != nil {
			t.Errorf("drop migration roles: %v", err)
		}
		for _, lock := range []string{
			"726491175848210",
			"hashtextextended('cdnca-jobhttp-command-external-roles',0)",
		} {
			var unlocked bool
			if err := connection.QueryRow(cleanupCtx, "SELECT pg_advisory_unlock("+lock+")").Scan(&unlocked); err != nil {
				t.Errorf("unlock migration roles: %v", err)
			} else if !unlocked {
				t.Error("migration role advisory lock was not held")
			}
		}
		connection.Release()
		admin.Close()
	})
	if !regexp.MustCompile(`^system_user_settings_[a-f0-9]{32}$`).MatchString(databaseName) {
		t.Fatalf("unsafe database name %q", databaseName)
	}
	createdRoleOIDs, err = prepareSystemUserSettingsMigrationRoles(t.Context(), connection)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(t.Context(), "CREATE DATABASE "+identifier); err != nil {
		t.Fatal(err)
	}
	databaseCreated = true
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	config.ConnConfig.Database = databaseName
	pool, err = pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `ALTER SCHEMA public OWNER TO CURRENT_USER;
		REVOKE ALL ON SCHEMA public FROM PUBLIC;
		GRANT ALL ON SCHEMA public TO CURRENT_USER`); err != nil {
		t.Fatal(err)
	}
	if err := verifySystemUserSettingsMigrationBaseline(t.Context(), pool); err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	pool.Close()
	pool = nil
	runtimeConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	runtimeConfig.ConnConfig.Database = databaseName
	pool, err = pgxpool.NewWithConfig(t.Context(), runtimeConfig)
	if err != nil {
		t.Fatal(err)
	}
	return pool
}

const (
	systemUserSettingsControlRole = "cdnca_control_app"
	systemUserSettingsRuntimeRole = "cdnca_plugin_webhook_runtime"
)

type systemUserSettingsRowQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func prepareSystemUserSettingsMigrationRoles(
	ctx context.Context,
	connection *pgxpool.Conn,
) (map[string]uint32, error) {
	tx, err := connection.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var currentUser string
	if err := tx.QueryRow(ctx, `SELECT current_user`).Scan(&currentUser); err != nil {
		return nil, err
	}
	if currentUser == systemUserSettingsControlRole || currentUser == systemUserSettingsRuntimeRole {
		return nil, errors.New("fixture user conflicts with a migration role")
	}
	existing := make(map[string]uint32, 2)
	rows, err := tx.Query(ctx, `SELECT rolname,oid FROM pg_roles WHERE rolname IN ($1,$2)`,
		systemUserSettingsControlRole, systemUserSettingsRuntimeRole)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var name string
		var oid uint32
		if err := rows.Scan(&name, &oid); err != nil {
			rows.Close()
			return nil, err
		}
		existing[name] = oid
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	created := make(map[string]uint32, 2)
	for _, role := range []string{systemUserSettingsControlRole, systemUserSettingsRuntimeRole} {
		if _, ok := existing[role]; ok {
			continue
		}
		if _, err := tx.Exec(ctx, "CREATE ROLE "+pgx.Identifier{role}.Sanitize()+
			" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"); err != nil {
			return nil, err
		}
		var oid uint32
		if err := tx.QueryRow(ctx, `SELECT oid FROM pg_roles WHERE rolname=$1`, role).Scan(&oid); err != nil {
			return nil, err
		}
		created[role] = oid
	}
	if err := verifySystemUserSettingsRoleSafety(ctx, tx); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return created, nil
}

func verifySystemUserSettingsRoleSafety(ctx context.Context, querier systemUserSettingsRowQuerier) error {
	var safe bool
	if err := querier.QueryRow(ctx, `WITH target AS (
		SELECT to_regrole($1) AS control_role,to_regrole($2) AS runtime_role
	) SELECT control_role IS NOT NULL AND runtime_role IS NOT NULL
		AND current_user<>$1 AND current_user<>$2
		AND NOT EXISTS (SELECT 1 FROM pg_roles WHERE oid IN (control_role,runtime_role)
			AND (rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls))
		AND NOT COALESCE(pg_has_role(control_role,runtime_role,'MEMBER'),true)
		AND NOT COALESCE(pg_has_role(runtime_role,control_role,'MEMBER'),true)
		AND NOT COALESCE(has_database_privilege(control_role,current_database(),'CREATE'),true)
		AND NOT COALESCE(has_database_privilege(runtime_role,current_database(),'CREATE'),true)
	FROM target`, systemUserSettingsControlRole, systemUserSettingsRuntimeRole).Scan(&safe); err != nil {
		return err
	}
	if !safe {
		return errors.New("migration roles are unavailable or unsafe")
	}
	return nil
}

func verifySystemUserSettingsMigrationBaseline(ctx context.Context, pool *pgxpool.Pool) error {
	if err := verifySystemUserSettingsRoleSafety(ctx, pool); err != nil {
		return err
	}
	var safe bool
	if err := pool.QueryRow(ctx, `WITH target AS (
		SELECT to_regrole($1) AS control_role,to_regrole($2) AS runtime_role
	), namespace AS (
		SELECT oid,nspowner,nspacl FROM pg_namespace WHERE oid=current_schema()::regnamespace
	) SELECT namespace.nspowner=current_user::regrole
		AND COALESCE(namespace.nspacl,acldefault('n',namespace.nspowner))
			IS NOT DISTINCT FROM acldefault('n',namespace.nspowner)
		AND NOT has_schema_privilege(control_role,current_schema(),'CREATE')
		AND NOT has_schema_privilege(runtime_role,current_schema(),'CREATE')
		AND NOT has_database_privilege(control_role,current_database(),'CREATE')
		AND NOT has_database_privilege(runtime_role,current_database(),'CREATE')
		AND NOT EXISTS (SELECT 1 FROM aclexplode(namespace.nspacl) acl
			WHERE acl.grantee IN (control_role,runtime_role))
		AND NOT EXISTS (SELECT 1 FROM pg_default_acl
			WHERE defaclrole=current_user::regrole
			AND defaclnamespace IN (0,namespace.oid) AND defaclobjtype IN ('r','S','f','T'))
	FROM target CROSS JOIN namespace`, systemUserSettingsControlRole, systemUserSettingsRuntimeRole).Scan(&safe); err != nil {
		return err
	}
	if !safe {
		return errors.New("migration database baseline is unavailable or unsafe")
	}
	return nil
}

func cleanupSystemUserSettingsMigrationRoles(
	ctx context.Context,
	connection *pgxpool.Conn,
	created map[string]uint32,
) error {
	var cleanupErrors []error
	for _, role := range []string{systemUserSettingsControlRole, systemUserSettingsRuntimeRole} {
		expectedOID, ok := created[role]
		if !ok {
			continue
		}
		var oid uint32
		var unsafe bool
		err := connection.QueryRow(ctx, `SELECT oid,
			rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls
			FROM pg_roles WHERE rolname=$1`, role).Scan(&oid, &unsafe)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			cleanupErrors = append(cleanupErrors, err)
			continue
		}
		if oid != expectedOID || unsafe {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("refusing to drop changed role %s", role))
			continue
		}
		peer := systemUserSettingsControlRole
		if role == systemUserSettingsControlRole {
			peer = systemUserSettingsRuntimeRole
		}
		var linked bool
		if err := connection.QueryRow(ctx, `SELECT
			EXISTS (SELECT 1 FROM pg_auth_members membership
				JOIN pg_roles member ON member.oid=membership.member
				JOIN pg_roles granted ON granted.oid=membership.roleid
				WHERE member.rolname=$1 AND granted.rolname=$2) OR
			EXISTS (SELECT 1 FROM pg_auth_members membership
				JOIN pg_roles member ON member.oid=membership.member
				JOIN pg_roles granted ON granted.oid=membership.roleid
				WHERE member.rolname=$2 AND granted.rolname=$1) OR
			COALESCE(has_database_privilege(to_regrole($1),current_database(),'CREATE'),false)`,
			role, peer).Scan(&linked); err != nil {
			cleanupErrors = append(cleanupErrors, err)
			continue
		}
		if linked {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("refusing to drop linked role %s", role))
			continue
		}
		if _, err := connection.Exec(ctx, "DROP ROLE "+pgx.Identifier{role}.Sanitize()); err != nil {
			cleanupErrors = append(cleanupErrors, err)
		}
	}
	return errors.Join(cleanupErrors...)
}
