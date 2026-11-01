//go:build integration

package theme_test

import (
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/theme"
	"github.com/jackc/pgx/v5"
)

// TestUserConsoleFollowsAdminPostgreSQL: a following user
// console shows the admin console's theme live, through later admin
// changes; a theme of its own stays when the admin console changes; and it
// can follow again. Following and leaving it are audited.
func TestUserConsoleFollowsAdminPostgreSQL(t *testing.T) {
	type step struct {
		do          string // admin:<theme>, user:<theme>, follow
		userTheme   string // theme the user console (signed out) shows after
		follows     bool
		auditAction string // follow/unfollow audit the step writes ("" none)
	}
	for _, tc := range []struct {
		name  string
		steps []step
	}{
		{"follows through admin changes", []step{
			{"admin:" + theme.OfficialThemeID, theme.OfficialThemeID, true, ""},
			{"admin:" + theme.DefaultThemeID, theme.DefaultThemeID, true, ""},
		}},
		{"own theme stays when admin changes", []step{
			{"user:" + theme.OfficialThemeID, theme.OfficialThemeID, false, theme.ActionUserUnfollow},
			{"admin:" + theme.OfficialThemeID, theme.OfficialThemeID, false, ""},
			{"admin:" + theme.DefaultThemeID, theme.OfficialThemeID, false, ""},
		}},
		{"follow, own theme, follow again", []step{
			{"admin:" + theme.OfficialThemeID, theme.OfficialThemeID, true, ""},
			{"user:" + theme.DefaultThemeID, theme.DefaultThemeID, false, theme.ActionUserUnfollow},
			{"follow", theme.OfficialThemeID, true, theme.ActionUserFollow},
			{"follow", theme.OfficialThemeID, true, ""},
			{"admin:" + theme.DefaultThemeID, theme.DefaultThemeID, true, ""},
		}},
		{"own theme equal to admin is still its own", []step{
			{"admin:" + theme.OfficialThemeID, theme.OfficialThemeID, true, ""},
			{"user:" + theme.OfficialThemeID, theme.OfficialThemeID, false, theme.ActionUserUnfollow},
			{"admin:" + theme.DefaultThemeID, theme.OfficialThemeID, false, ""},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pool := themePool(t)
			ctx := t.Context()
			actor := seedPlatformAdmin(t, pool)
			auditor := audit.New(pool)
			service, err := theme.NewService(pool, auditor, nil, theme.BuiltinCatalog(), time.Now)
			if err != nil {
				t.Fatal(err)
			}
			packages := map[string]string{}
			for _, id := range []string{theme.DefaultThemeID, theme.OfficialThemeID} {
				view, err := service.Download(ctx, actor, id)
				if err != nil {
					t.Fatalf("download %s: %v", id, err)
				}
				packages[id] = view.PackageSHA256
			}
			audits := func() int {
				return len(auditEvents(t, pool, theme.ActionUserFollow)) + len(auditEvents(t, pool, theme.ActionUserUnfollow))
			}
			for index, step := range tc.steps {
				before := audits()
				catalog, err := service.Catalog(ctx, actor)
				if err != nil {
					t.Fatal(err)
				}
				switch kind, id, _ := cut(step.do); kind {
				case "admin":
					_, err = service.ActivateSlot(ctx, actor, packages[id], catalog.ActivationRevision, theme.SlotAdmin)
				case "user":
					_, err = service.ActivateSlot(ctx, actor, packages[id], catalog.ActivationRevision, theme.SlotUser)
				default:
					err = pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
						return theme.ActivateUserTx(ctx, tx, auditor, actor.ScopeID, actor.UserID, "", actor.RequestID, time.Now().UTC())
					})
				}
				if err != nil {
					t.Fatalf("step %d %s: %v", index, step.do, err)
				}
				current, err := service.Current(ctx, theme.CurrentRequest{})
				if err != nil || current.ThemeID != step.userTheme {
					t.Fatalf("step %d %s: user console shows %q, want %q (%v)", index, step.do, current.ThemeID, step.userTheme, err)
				}
				catalog, err = service.Catalog(ctx, actor)
				if err != nil || catalog.UserFollowsAdmin != step.follows || catalog.UserPackage != packages[step.userTheme] {
					t.Fatalf("step %d %s: catalog follows=%v user=%s, want follows=%v user=%s (%v)", index, step.do,
						catalog.UserFollowsAdmin, catalog.UserPackage, step.follows, packages[step.userTheme], err)
				}
				if follows, err := theme.UserFollowsAdminTx(ctx, pool); err != nil || follows != step.follows {
					t.Fatalf("step %d: UserFollowsAdminTx = %v %v", index, follows, err)
				}
				wrote := audits() - before
				if (step.auditAction != "") != (wrote == 1) || wrote > 1 {
					t.Fatalf("step %d %s: %d follow audits, want %q", index, step.do, wrote, step.auditAction)
				}
				if step.auditAction != "" {
					rows := auditEvents(t, pool, step.auditAction)
					if last := rows[len(rows)-1]; last.Result != "success" || last.Payload["slot"] != theme.SlotUser {
						t.Fatalf("step %d audit = %+v", index, last)
					}
				}
			}
		})
	}
}

func cut(value string) (string, string, bool) {
	for index := range value {
		if value[index] == ':' {
			return value[:index], value[index+1:], true
		}
	}
	return value, "", false
}
