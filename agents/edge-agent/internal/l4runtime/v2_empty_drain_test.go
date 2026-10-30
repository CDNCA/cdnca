package l4runtime

import (
	"context"
	"errors"
	"testing"
	"time"
)

type emptyDrainRuntime struct {
	v2LifecycleRuntime
	drains    []time.Duration
	failDrain bool
}

func (r *emptyDrainRuntime) Drain(_ context.Context, duration time.Duration) error {
	r.drains = append(r.drains, duration)
	if r.failDrain {
		return errInjectedRuntime
	}
	return nil
}

func TestV2EmptySnapshotDrainsPreviousListeners(t *testing.T) {
	for _, operation := range []string{"apply", "rollback", "drain failure"} {
		t.Run(operation, func(t *testing.T) {
			ctx := context.Background()
			runtime := &emptyDrainRuntime{}
			manager, _ := testManager(t, runtime)
			config := v2LifecycleConfig(t, "before-empty", 9, 3)
			config.Listeners[0].Endpoint = EndpointV2{Address: "127.0.0.1", Port: 8080}
			config.Listeners[0].DNS = DNSPolicyV2{}
			dns, err := NewDNSCoordinator(t.TempDir(), &l403Resolver{}, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			first, err := manager.ApplyV2(ctx, config, dns)
			if err != nil {
				t.Fatal(err)
			}
			empty := Config{SchemaVersion: SchemaVersionV1, VersionID: "empty"}
			var result Result
			if operation == "rollback" {
				removed, err := manager.Apply(ctx, empty)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := manager.Rollback(ctx, first.VersionID, first.Digest); err != nil {
					t.Fatal(err)
				}
				runtime.drains = nil
				result, err = manager.Rollback(ctx, removed.VersionID, removed.Digest)
			} else {
				runtime.drains = nil
				runtime.failDrain = operation == "drain failure"
				result, err = manager.Apply(ctx, empty)
			}
			if len(runtime.drains) != 1 || runtime.drains[0] != 30*time.Second {
				t.Fatalf("empty snapshot skipped previous listener drain: %v", runtime.drains)
			}
			if operation == "drain failure" {
				status, statusErr := manager.Status()
				if !errors.Is(err, ErrActivation) || result.ErrorCode != "DRAIN_FAILED" || statusErr != nil || status.VersionID != first.VersionID {
					t.Fatalf("failed removal drain lost baseline: result=%+v status=%+v err=%v/%v", result, status, err, statusErr)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}
