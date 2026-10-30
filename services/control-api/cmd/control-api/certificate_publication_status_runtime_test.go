package main

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCertificatePublicationStatusRuntimeConfigRequiresCanonicalIndependentKeys(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x71}, 32))
	valid := map[string]string{
		certificatePublicationCursorActiveKeyIDEnv: "current",
		certificatePublicationCursorKeysJSONEnv:    `{"current":"` + key + `"}`,
	}
	lookup := func(values map[string]string) func(string) (string, bool) {
		return func(name string) (string, bool) {
			value, ok := values[name]
			return value, ok
		}
	}

	disabled, err := loadCertificatePublicationStatusRuntimeConfigFromLookup(false, nil)
	if err != nil || disabled.Enabled || len(disabled.Keys) != 0 {
		t.Fatalf("disabled config = %#v, error = %v", disabled, err)
	}
	configured, err := loadCertificatePublicationStatusRuntimeConfigFromLookup(true, lookup(valid))
	if err != nil || !configured.Enabled || configured.ActiveKeyID != "current" ||
		!bytes.Equal(configured.Keys["current"], bytes.Repeat([]byte{0x71}, 32)) {
		t.Fatalf("configured runtime = %#v, error = %v", configured, err)
	}
	configured.clearSecrets()

	invalid := []map[string]string{
		{},
		{certificatePublicationCursorActiveKeyIDEnv: "current"},
		{
			certificatePublicationCursorActiveKeyIDEnv: "current",
			certificatePublicationCursorKeysJSONEnv:    `{"old":"` + key + `"}`,
		},
		{
			certificatePublicationCursorActiveKeyIDEnv: "current",
			certificatePublicationCursorKeysJSONEnv:    `{"current":"not-base64"}`,
		},
		{
			certificatePublicationCursorActiveKeyIDEnv: "current",
			certificatePublicationCursorKeysJSONEnv:    `{"current":"` + key + `","current":"` + key + `"}`,
		},
	}
	for index, values := range invalid {
		if config, err := loadCertificatePublicationStatusRuntimeConfigFromLookup(true, lookup(values)); err == nil || config.Enabled {
			t.Errorf("invalid config %d = %#v, error = %v", index, config, err)
		}
	}
}

func TestCertificatePublicationStatusRuntimeBuildsHandlerAndClearsTemporaryKeys(t *testing.T) {
	poolConfig, err := pgxpool.ParseConfig("postgresql://certificate:certificate@127.0.0.1:1/certificate?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	tokens, err := identity.NewTokenManager(strings.Repeat("certificate-publication-status-", 2), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x72}, 32)
	config := certificatePublicationStatusRuntimeConfig{
		Enabled: true, ActiveKeyID: "current", Keys: map[string][]byte{"current": key},
	}
	factory, err := buildAndClearCertificatePublicationStatusHandlerFactory(
		&config, certificatePublicationStatusRuntimeDependencies{Pool: pool, Identity: identityService},
	)
	if err != nil || factory == nil {
		t.Fatalf("factory = %v, error = %v", factory, err)
	}
	if len(config.Keys) != 0 || !bytes.Equal(key, make([]byte, len(key))) {
		t.Fatal("temporary cursor key material was not cleared")
	}
	handler, err := factory()
	if err != nil || handler == nil {
		t.Fatalf("handler = %T, error = %v", handler, err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/certificate-publications", nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want 401", response.Code)
	}
}

func TestCertificatePublicationStatusRuntimeRejectsIncompleteDependencies(t *testing.T) {
	config := certificatePublicationStatusRuntimeConfig{
		Enabled: true, ActiveKeyID: "current",
		Keys: map[string][]byte{"current": bytes.Repeat([]byte{0x73}, 32)},
	}
	factory, err := buildAndClearCertificatePublicationStatusHandlerFactory(
		&config, certificatePublicationStatusRuntimeDependencies{},
	)
	if err == nil || factory != nil || !strings.Contains(err.Error(), "dependencies") {
		t.Fatalf("factory = %v, error = %v", factory, err)
	}
	if len(config.Keys) != 0 {
		t.Fatal("failed composition retained cursor keys")
	}
	if factory, err := buildAndClearCertificatePublicationStatusHandlerFactory(
		nil, certificatePublicationStatusRuntimeDependencies{},
	); err == nil || factory != nil {
		t.Fatalf("nil config factory = %v, error = %v", factory, err)
	}
}
