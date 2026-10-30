package main

import (
	"context"
	"encoding/base64"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/announcement"
	"github.com/cdnca/cdnca/services/control-api/internal/rbacmanager"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestLoadAnnouncementRuntimeConfigRequiresExplicitInboxOnlyBoundary(t *testing.T) {
	lookup := func(values map[string]string) func(string) (string, bool) {
		return func(key string) (string, bool) { value, ok := values[key]; return value, ok }
	}
	if _, err := loadAnnouncementRuntimeConfig(lookup(map[string]string{"ANNOUNCEMENT_ENABLED": "true"})); err == nil {
		t.Fatal("enabled runtime accepted missing external channel")
	}
	cursorKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	config, err := loadAnnouncementRuntimeConfig(lookup(map[string]string{
		"ANNOUNCEMENT_ENABLED": "true", "ANNOUNCEMENT_EXTERNAL_CHANNEL": "disabled",
		"ANNOUNCEMENT_POLL_INTERVAL": "2s", "ANNOUNCEMENT_BATCH_SIZE": "12",
		"ANNOUNCEMENT_CURSOR_ACTIVE_KEY_ID": "active",
		"ANNOUNCEMENT_CURSOR_KEYS_JSON":     `{"active":"` + cursorKey + `"}`,
	}))
	if err != nil || !config.Enabled || config.ExternalChannel != "disabled" || config.PollInterval != 2*time.Second || config.BatchSize != 12 || config.CursorKeyring.ActiveKID != "active" {
		t.Fatalf("config = %+v, err=%v", config, err)
	}
	if disabled, err := loadAnnouncementRuntimeConfig(lookup(map[string]string{"ANNOUNCEMENT_ENABLED": "false"})); err != nil || disabled.Enabled {
		t.Fatalf("disabled config = %+v, err=%v", disabled, err)
	}
}

func TestLoadAnnouncementRuntimeConfigRejectsInvalidCursorAndTimeoutConfiguration(t *testing.T) {
	lookup := func(values map[string]string) func(string) (string, bool) {
		return func(key string) (string, bool) { value, ok := values[key]; return value, ok }
	}
	base := map[string]string{
		"ANNOUNCEMENT_ENABLED": "true", "ANNOUNCEMENT_EXTERNAL_CHANNEL": "disabled",
		"ANNOUNCEMENT_CURSOR_ACTIVE_KEY_ID": "active",
		"ANNOUNCEMENT_CURSOR_KEYS_JSON":     `{"active":"` + base64.StdEncoding.EncodeToString(make([]byte, 32)) + `"}`,
	}
	for name, value := range map[string]string{
		"ANNOUNCEMENT_CURSOR_KEYS_JSON":  `{"active":"c2hvcnQ="}`,
		"ANNOUNCEMENT_OPERATION_TIMEOUT": "0s",
		"ANNOUNCEMENT_SHUTDOWN_TIMEOUT":  "31s",
	} {
		values := make(map[string]string, len(base)+1)
		for key, item := range base {
			values[key] = item
		}
		values[name] = value
		if _, err := loadAnnouncementRuntimeConfig(lookup(values)); err == nil {
			t.Fatalf("invalid %s was accepted", name)
		}
	}
}

func TestLoadAnnouncementRuntimeConfigFromEnvRejectsUnknownDuplicateAndDuplicateCursorKeys(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	valid := []string{
		"UNRELATED=value",
		"ANNOUNCEMENT_ENABLED=true",
		"ANNOUNCEMENT_EXTERNAL_CHANNEL=disabled",
		"ANNOUNCEMENT_CURSOR_ACTIVE_KEY_ID=active",
		"ANNOUNCEMENT_CURSOR_KEYS_JSON={\"active\":\"" + key + "\"}",
	}
	for _, test := range []struct {
		name        string
		environment []string
	}{
		{name: "unknown", environment: append(slices.Clone(valid), "ANNOUNCEMENT_CURSOR_ACTVE_KEY_ID=active")},
		{name: "duplicate environment", environment: append(slices.Clone(valid), "ANNOUNCEMENT_ENABLED=true")},
		{name: "duplicate cursor key", environment: []string{
			"ANNOUNCEMENT_ENABLED=true",
			"ANNOUNCEMENT_EXTERNAL_CHANNEL=disabled",
			"ANNOUNCEMENT_CURSOR_ACTIVE_KEY_ID=active",
			"ANNOUNCEMENT_CURSOR_KEYS_JSON={\"active\":\"" + key + "\",\"active\":\"" + key + "\"}",
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := loadAnnouncementRuntimeConfigFromEnvEntries(test.environment); err == nil {
				t.Fatal("invalid announcement environment was accepted")
			}
		})
	}
}

func TestLoadAnnouncementRuntimeConfigSupportsStableVerifyOnlyCursorRotation(t *testing.T) {
	oldKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	newKey := base64.StdEncoding.EncodeToString(make([]byte, 64))
	environment := []string{
		"ANNOUNCEMENT_ENABLED=true",
		"ANNOUNCEMENT_EXTERNAL_CHANNEL=disabled",
		"ANNOUNCEMENT_CURSOR_ACTIVE_KEY_ID=new",
		"ANNOUNCEMENT_CURSOR_KEYS_JSON={\"old\":\"" + oldKey + "\",\"new\":\"" + newKey + "\"}",
	}
	first, err := loadAnnouncementRuntimeConfigFromEnvEntries(environment)
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadAnnouncementRuntimeConfigFromEnvEntries(environment)
	if err != nil {
		t.Fatal(err)
	}
	if first.CursorKeyring.ActiveKID != "new" || len(first.CursorKeyring.Keys) != 2 ||
		!slices.Equal(first.CursorKeyring.Keys["old"], second.CursorKeyring.Keys["old"]) ||
		!slices.Equal(first.CursorKeyring.Keys["new"], second.CursorKeyring.Keys["new"]) {
		t.Fatalf("cursor keyring rotation is not replica-stable: first=%q/%d second=%q/%d",
			first.CursorKeyring.ActiveKID, len(first.CursorKeyring.Keys),
			second.CursorKeyring.ActiveKID, len(second.CursorKeyring.Keys))
	}
	first.clearSecrets()
	second.clearSecrets()
}

func TestAnnouncementRBACAuthorizerUsesAuthenticatedSessionAndMapsOnlyDenial(t *testing.T) {
	actor := announcement.Actor{ScopeID: uuid.New(), UserID: uuid.New(), SessionID: uuid.New()}
	denied := &recordingTenantSessionAuthorizer{err: rbacmanager.ErrPermissionDenied}
	err := (announcementRBACAuthorizer{service: denied}).Authorize(t.Context(), nil, actor, "announcements.manage")
	if !errors.Is(err, announcement.ErrPermissionDenied) {
		t.Fatalf("denied authorization error = %v", err)
	}
	if denied.session != (rbacmanager.AuthenticatedSessionReference{
		UserID: actor.UserID, ScopeID: actor.ScopeID, SessionID: actor.SessionID,
	}) || denied.permission != "announcements.manage" {
		t.Fatalf("authorization input = %+v %q", denied.session, denied.permission)
	}
	databaseFailure := errors.New("database unavailable")
	failed := &recordingTenantSessionAuthorizer{err: databaseFailure}
	if err := (announcementRBACAuthorizer{service: failed}).Authorize(t.Context(), nil, actor, "announcements.read"); !errors.Is(err, databaseFailure) {
		t.Fatalf("database authorization error = %v", err)
	}
}

type recordingTenantSessionAuthorizer struct {
	session    rbacmanager.AuthenticatedSessionReference
	permission string
	err        error
}

func (authorizer *recordingTenantSessionAuthorizer) AuthorizeTenantSessionTx(
	_ context.Context,
	_ pgx.Tx,
	session rbacmanager.AuthenticatedSessionReference,
	permission string,
) (uuid.UUID, error) {
	authorizer.session = session
	authorizer.permission = permission
	return uuid.Nil, authorizer.err
}

func TestAnnouncementRuntimeHealthAndClose(t *testing.T) {
	runtime := &announcementRuntime{config: announcementRuntimeConfig{Enabled: true, ExternalChannel: "disabled"}, done: make(chan struct{}), cancel: func() {}}
	close(runtime.done)
	runtime.closed.Store(true)
	if err := runtime.Ready(); err == nil {
		t.Fatal("ready after close succeeded")
	}
	if got := runtime.Health().ExternalChannel; got != "disabled" {
		t.Fatalf("external channel = %q", got)
	}
}
