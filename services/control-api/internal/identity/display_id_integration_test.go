package identity

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestDisplayIDSurvivesLoginRefreshAndAuthenticatePostgres(t *testing.T) {
	databaseURL := os.Getenv("TEST_IDENTITY_DISPLAY_ID_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_IDENTITY_DISPLAY_ID_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("open display ID test database: %v", err)
	}
	defer pool.Close()

	// The platform scope is a singleton written at install time; a fresh
	// migrated database (the template clone) has none yet.
	var scopeID uuid.UUID
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind) VALUES(gen_random_uuid(),'platform')
		ON CONFLICT DO NOTHING`); err != nil {
		t.Fatalf("ensure platform scope: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform' LIMIT 1`).Scan(&scopeID); err != nil {
		t.Fatalf("find platform scope: %v", err)
	}
	userID := uuid.New()
	username := "display-id-" + userID.String()[:8]
	password := "display-id-fixture-password"
	passwordHash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("hash fixture password: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO users(id,username,display_name,password_hash,status)
		VALUES ($1,$2,'Display ID integration', $3,'active')`, userID, username, passwordHash); err != nil {
		t.Fatalf("insert fixture user: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO memberships(scope_id,user_id) VALUES ($1,$2)`, scopeID, userID); err != nil {
		t.Fatalf("insert fixture membership: %v", err)
	}

	tokens, err := NewTokenManager("display-id-integration-secret-at-least-thirty-two-bytes", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(NewStore(pool), tokens, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	login, err := service.Login(ctx, LoginInput{Username: username, Password: password, ScopeID: &scopeID}, RequestInfo{RequestID: "display-id-login"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if login.Principal.DisplayID == "" || login.Principal.DisplayID == userID.String() {
		t.Fatalf("login display ID = %q", login.Principal.DisplayID)
	}
	refreshed, err := service.Refresh(ctx, login.RefreshToken, RequestInfo{RequestID: "display-id-refresh"})
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if refreshed.Principal.DisplayID != login.Principal.DisplayID {
		t.Fatalf("refresh display ID = %q, want %q", refreshed.Principal.DisplayID, login.Principal.DisplayID)
	}
	authenticated, err := service.Authenticate(ctx, refreshed.AccessToken)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if authenticated.DisplayID != login.Principal.DisplayID {
		t.Fatalf("authenticated display ID = %q, want %q", authenticated.DisplayID, login.Principal.DisplayID)
	}
}
