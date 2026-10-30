package deployment

import (
	"context"
	"testing"
)

func TestActiveIdentityPointerFactsSurviveRestart(t *testing.T) {
	runtime := &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}}
	manager, root := newTestManager(t, &fakePrechecker{failFor: map[string]error{}}, runtime)
	current := testCommand(t, "active-identity-v1", 1, "25d72e9e-c92a-48c2-91bf-69a15ed0ef87", "", map[string][]byte{"site.conf": []byte("v1")})
	if result, err := manager.Process(context.Background(), current); err != nil || result.State != StateHealthy {
		t.Fatalf("Process(current) = (%+v, %v)", result, err)
	}
	next := testCommand(t, "active-identity-v2", 1, "e03991ce-9502-4c18-abd6-c80349165e7f", current.ConfigVersionID, map[string][]byte{"site.conf": []byte("v2")})
	if result, err := manager.Process(context.Background(), next); err != nil || result.State != StateHealthy {
		t.Fatalf("Process(next) = (%+v, %v)", result, err)
	}

	restarted, err := NewManager(root, &fakePrechecker{failFor: map[string]error{}}, runtime)
	if err != nil {
		t.Fatal(err)
	}
	pointers, err := restarted.Pointers()
	if err != nil {
		t.Fatal(err)
	}
	want := Pointers{
		Current: next.ConfigVersionID, CurrentDigest: next.Bundle.ManifestSHA256,
		Previous: current.ConfigVersionID, PreviousDigest: current.Bundle.ManifestSHA256,
	}
	if pointers != want {
		t.Fatalf("Pointers() = %+v, want %+v", pointers, want)
	}
	if pointers.CurrentDigest == pointers.Current || pointers.PreviousDigest == pointers.Previous {
		t.Fatal("release manifest digest was confused with a configuration UUID")
	}
}
