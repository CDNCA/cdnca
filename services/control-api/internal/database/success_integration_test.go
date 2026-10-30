//go:build integration

package database

import (
	"os"
	"testing"
)

// B05: a pool from Open marks the attempt ctx on a real successful query and
// leaves it unmarked when the query fails.
func TestOpenPoolMarksQuerySuccessOnAttemptContext(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	pool, err := Open(t.Context(), url)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	failed, failedFlag := WithQuerySuccess(t.Context())
	if _, err := pool.Exec(failed, `SELECT * FROM b05_no_such_table`); err == nil {
		t.Fatal("query on a missing table succeeded")
	}
	if failedFlag.Load() {
		t.Fatal("failed query marked the attempt as succeeded")
	}
	ok, okFlag := WithQuerySuccess(t.Context())
	var one int
	if err := pool.QueryRow(ok, `SELECT 1`).Scan(&one); err != nil || one != 1 {
		t.Fatalf("SELECT 1 = (%d, %v)", one, err)
	}
	if !okFlag.Load() {
		t.Fatal("successful query did not mark the attempt")
	}
}
