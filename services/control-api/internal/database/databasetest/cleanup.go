package databasetest

import (
	"context"
	"time"
)

// CleanupTimeout bounds dropping a test-owned schema or database. A
// release-head schema holds ~1600 objects; on a loaded server DROP SCHEMA ...
// CASCADE measured 16.6s, so short budgets cancelled the drop and left the
// schema behind in the shared database, slowing every later run.
const CleanupTimeout = 5 * time.Minute

// CleanupContext returns the context a test cleanup uses to drop the schema
// or database it created.
func CleanupContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), CleanupTimeout)
}
