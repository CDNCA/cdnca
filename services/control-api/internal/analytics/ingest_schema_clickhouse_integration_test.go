package analytics

import (
	"net/http"
	"testing"
	"time"
)

// The ingest writer's expected column order (accessIngestSchema,
// securityIngestSchema) matches the schema every migration builds.
func TestCheckIngestMatchesMigratedClickHouseSchema(t *testing.T) {
	database := newRankTestDatabase(t)
	database.reset(t)
	applyAllClickHouseMigrations(t, database)
	client, err := NewClient(Config{Endpoint: database.endpoint, Database: database.name, Username: database.username,
		Password: database.password, QueryTimeout: 5 * time.Second}, &http.Client{Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.CheckIngest(t.Context()); err != nil {
		t.Fatalf("CheckIngest: %v", err)
	}
}
