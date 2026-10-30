//go:build integration

package migrations_test

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestSiteOriginParity494 (tp-b3a-be): existing pools keep their behaviour
// (http_port 80, origin auth on, origins not inheriting); the CHECKs take
// 跟随协议和端口, 访问域名+端口 and the pool ports and refuse the
// combinations the service refuses; down refuses while those are in use.
func TestSiteOriginParity494(t *testing.T) {
	const version = 494
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	siteID := uuid.New()
	code := func(err error) string {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			return pgErr.Code
		}
		return ""
	}
	// FKs are triggers: replica role lets the pool and origin stand alone, CHECKs still apply.
	exec := func(sql string, args ...any) error {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, sql, args...); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	if err := exec(`INSERT INTO site_origin_pools(site_id) VALUES($1)`, siteID); err != nil {
		t.Fatal(err)
	}
	if err := exec(`INSERT INTO site_origins(site_id,position,host,port) VALUES($1,1,'192.0.2.10',8080)`, siteID); err != nil {
		t.Fatal(err)
	}
	// before 494: follow + follow_port and https on another port are refused
	if err := exec(`UPDATE site_origin_pools SET origin_scheme='follow',follow_port=true WHERE site_id=$1`, siteID); err != nil {
		t.Fatalf("before 494 follow + follow_port: %v", err)
	}
	if err := exec(`UPDATE site_origin_pools SET origin_scheme='https',follow_port=false,https_port=8443 WHERE site_id=$1`, siteID); code(err) != "23514" {
		t.Fatalf("before 494 https on 8443 error = %v, want 23514", err)
	}
	if err := exec(`UPDATE site_origin_pools SET origin_scheme='http' WHERE site_id=$1`, siteID); err != nil {
		t.Fatal(err)
	}

	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	pool.Reset()
	var httpPort int
	var authOn, inherited bool
	if err := pool.QueryRow(ctx, `SELECT pool.http_port,pool.origin_auth_enabled,origin.port_inherited
		FROM site_origin_pools pool JOIN site_origins origin ON origin.site_id=pool.site_id WHERE pool.site_id=$1`,
		siteID).Scan(&httpPort, &authOn, &inherited); err != nil {
		t.Fatal(err)
	}
	if httpPort != 80 || !authOn || inherited {
		t.Fatalf("existing rows: http_port=%d origin_auth_enabled=%v port_inherited=%v", httpPort, authOn, inherited)
	}

	for name, sql := range map[string]string{
		"follow protocol and port": `origin_scheme='follow',follow_port=true,http_port=80,https_port=443`,
		"visitor host with port":   `origin_scheme='http',follow_port=false,request_host_mode='visitor_port'`,
		"pool HTTP port":           `origin_scheme='http',request_host_mode='visitor',http_port=8080,https_port=443`,
		"HTTPS on another port":    `origin_scheme='https',http_port=80,https_port=8443`,
		"follow with both ports":   `origin_scheme='follow',follow_port=false,http_port=8080,https_port=8443`,
		"origin auth off":          `origin_scheme='http',http_port=80,https_port=443,origin_auth_enabled=false`,
	} {
		if err := exec(`UPDATE site_origin_pools SET `+sql+` WHERE site_id=$1`, siteID); err != nil {
			t.Errorf("%s refused: %v", name, err)
		}
	}
	for name, sql := range map[string]string{
		"http with https port":           `origin_scheme='http',follow_port=false,http_port=80,https_port=8443`,
		"https with http port":           `origin_scheme='https',http_port=8080,https_port=443`,
		"follow port with own ports":     `origin_scheme='follow',follow_port=true,http_port=8080,https_port=443`,
		"http port out of range":         `origin_scheme='http',http_port=0,https_port=443`,
		"unknown request host mode":      `origin_scheme='http',http_port=80,https_port=443,request_host_mode='visitor_host'`,
		"visitor_port with a host value": `origin_scheme='http',http_port=80,https_port=443,request_host_mode='visitor_port',request_host='a.test'`,
	} {
		if err := exec(`UPDATE site_origin_pools SET `+sql+` WHERE site_id=$1`, siteID); code(err) != "23514" {
			t.Errorf("%s error = %v, want 23514", name, err)
		}
	}

	// down refuses while 494-only settings are in use (origin auth is off now), then goes once cleared
	if err := migrateVersionIsolated(ctx, pool, "down", version); code(err) != "P4942" {
		t.Fatalf("down with 494-only settings error = %v, want P4942", err)
	}
	if err := exec(`UPDATE site_origin_pools SET origin_scheme='http',follow_port=false,request_host_mode='visitor',
		http_port=80,https_port=443,origin_auth_enabled=true WHERE site_id=$1`, siteID); err != nil {
		t.Fatal(err)
	}
	if err := exec(`UPDATE site_origins SET port_inherited=true WHERE site_id=$1`, siteID); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); code(err) != "P4942" {
		t.Fatalf("down with inherited origin ports error = %v, want P4942", err)
	}
	if err := exec(`UPDATE site_origins SET port_inherited=false WHERE site_id=$1`, siteID); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down: %v", err)
	}
}
