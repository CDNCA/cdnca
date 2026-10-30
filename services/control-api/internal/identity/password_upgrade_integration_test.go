//go:build integration

package identity_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/argon2"
)

func TestLoginAtomicallyUpgradesWeakArgon2idHash(t *testing.T) {
	const (
		username = "legacy-password-user"
		password = "Legacy-password-value"
	)
	pool := newPasswordUpgradePool(t)
	weakHash := legacyPasswordHash(password)
	bootstrap, err := identity.NewStore(pool).BootstrapPlatformUser(
		t.Context(), username, "Legacy Password User", weakHash, "legacy-password-bootstrap",
	)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := identity.NewTokenManager("password-upgrade-test-secret-at-least-32-bytes", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	service, err := identity.NewService(identity.NewStore(pool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := service.Login(t.Context(), identity.LoginInput{
		Username: username, Password: "Wrong-password-value", ScopeID: &bootstrap.ScopeID,
	}, identity.RequestInfo{RequestID: "legacy-password-wrong"}); !errors.Is(err, identity.ErrInvalidCredentials) {
		t.Fatalf("wrong password error = %v", err)
	}
	assertStoredPasswordHash(t, pool, bootstrap.UserID, weakHash, 0)

	start := make(chan struct{})
	errorsByLogin := make(chan error, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	for index := range 2 {
		go func() {
			ready.Done()
			<-start
			_, loginErr := service.Login(t.Context(), identity.LoginInput{
				Username: username, Password: password, ScopeID: &bootstrap.ScopeID,
			}, identity.RequestInfo{RequestID: fmt.Sprintf("legacy-password-login-%d", index)})
			errorsByLogin <- loginErr
		}()
	}
	ready.Wait()
	close(start)
	for range 2 {
		if err := <-errorsByLogin; err != nil {
			t.Fatalf("concurrent login error = %v", err)
		}
	}
	var upgraded string
	if err := pool.QueryRow(t.Context(), `SELECT password_hash FROM users WHERE id=$1`, bootstrap.UserID).Scan(&upgraded); err != nil {
		t.Fatal(err)
	}
	if upgraded == weakHash || !identity.VerifyPassword(upgraded, password) {
		t.Fatalf("stored password was not upgraded: %q", upgraded)
	}
	assertCanonicalPasswordHash(t, upgraded)
	assertStoredPasswordHash(t, pool, bootstrap.UserID, upgraded, 2)

	for index, invalid := range []string{
		"not-a-password-hash",
		"$argon2id$v=19$m=1048576,t=10,p=16$" + strings.Repeat("A", 300),
	} {
		if _, err := pool.Exec(t.Context(), `UPDATE users SET password_hash=$2 WHERE id=$1`, bootstrap.UserID, invalid); err != nil {
			t.Fatal(err)
		}
		if _, err := service.Login(t.Context(), identity.LoginInput{
			Username: username, Password: password, ScopeID: &bootstrap.ScopeID,
		}, identity.RequestInfo{RequestID: fmt.Sprintf("invalid-password-hash-%d", index)}); !errors.Is(err, identity.ErrInvalidCredentials) {
			t.Fatalf("invalid hash %d error = %v", index, err)
		}
		assertStoredPasswordHash(t, pool, bootstrap.UserID, invalid, 2)
	}
}

func newPasswordUpgradePool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	admin, err := pgxpool.New(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "identity_password_upgrade_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
	})
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		var version int
		if !strings.Contains(err.Error(), "apply migration 157:") ||
			pool.QueryRow(t.Context(), "SELECT max(version) FROM schema_migrations").Scan(&version) != nil || version != 156 {
			t.Fatal(err)
		}
	}
	return pool
}

func legacyPasswordHash(password string) string {
	salt := []byte("12345678")
	digest := argon2.IDKey([]byte(password), salt, 1, 8*1024, 1, 16)
	return fmt.Sprintf("$argon2id$v=%d$m=8192,t=1,p=1$%s$%s", argon2.Version,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(digest))
}

func assertCanonicalPasswordHash(t *testing.T, hash string) {
	t.Helper()
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" || parts[3] != "m=65536,t=3,p=2" {
		t.Fatalf("non-canonical password hash %q", hash)
	}
	salt, saltErr := base64.RawStdEncoding.DecodeString(parts[4])
	digest, digestErr := base64.RawStdEncoding.DecodeString(parts[5])
	if saltErr != nil || digestErr != nil || len(salt) != 16 || len(digest) != 32 {
		t.Fatalf("canonical hash lengths salt=%d key=%d errors=(%v,%v)", len(salt), len(digest), saltErr, digestErr)
	}
}

func assertStoredPasswordHash(t *testing.T, pool interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, userID uuid.UUID, wantHash string, wantSessions int) {
	t.Helper()
	var hash string
	var sessions int
	if err := pool.QueryRow(t.Context(), `SELECT password_hash,
		(SELECT count(*) FROM auth_sessions WHERE user_id=$1) FROM users WHERE id=$1`, userID).
		Scan(&hash, &sessions); err != nil {
		t.Fatal(err)
	}
	if hash != wantHash || sessions != wantSessions {
		t.Fatalf("stored facts hashMatch=%t sessions=%d, want sessions=%d", hash == wantHash, sessions, wantSessions)
	}
}
