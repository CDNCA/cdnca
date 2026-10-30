package eventspool

import (
	"context"
	"testing"
)

func TestConnectionsV2SpoolsObservedZeroButRequiresActivatedConfig(t *testing.T) {
	spool := newTestSpool(t, testConfig(t.TempDir()))
	observation := connectionsEnvelope(0, "observed-zero-v2", 1)
	observation.SchemaVersion = 2
	observation.ConfigVersionId = "77777777-7777-4777-8777-777777777777"
	observation.PackageSubscriptionId = ""
	if _, err := spool.AppendConnections(context.Background(), observation); err != nil {
		t.Fatal(err)
	}
	if result, err := spool.AppendConnections(context.Background(), observation); err != nil || !result.Duplicate {
		t.Fatalf("replay=%+v %v", result, err)
	}
	observation.ConfigVersionId = ""
	if _, err := spool.AppendConnections(context.Background(), observation); err == nil {
		t.Fatal("unbound observed zero accepted")
	}
}
