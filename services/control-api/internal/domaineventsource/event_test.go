package domaineventsource

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func deploymentInput() DeploymentStatus {
	return DeploymentStatus{
		EventID:       uuid.MustParse("10000000-0000-0000-0000-000000000001"),
		TenantScopeID: uuid.MustParse("20000000-0000-0000-0000-000000000002"),
		DeploymentID:  uuid.MustParse("40000000-0000-0000-0000-000000000004"),
		NodeID:        uuid.MustParse("50000000-0000-0000-0000-000000000005"),
		RolloutID:     uuid.MustParse("60000000-0000-0000-0000-000000000006"),
		Attempt:       2, TransitionSequence: 9, State: "healthy",
		OccurredAt: time.Date(2026, 8, 10, 1, 2, 3, 456789000, time.FixedZone("CST", 8*60*60)),
	}
}

func TestDeploymentStatusFactHasClosedCanonicalPayload(t *testing.T) {
	fact, err := NewDeploymentStatusFact(deploymentInput())
	if err != nil {
		t.Fatal(err)
	}
	payload, err := fact.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"attempt":2,"deployment_id":"40000000-0000-0000-0000-000000000004","node_id":"50000000-0000-0000-0000-000000000005","rollout_id":"60000000-0000-0000-0000-000000000006","state":"healthy","transition_sequence":9}`
	if string(payload) != want {
		t.Fatalf("payload changed:\n got %s\nwant %s", payload, want)
	}
	if fact.Subject != "deployment/40000000-0000-0000-0000-000000000004" ||
		fact.DedupKey != "io.cdnca.deployment.v1.status_changed/40000000-0000-0000-0000-000000000004/2/9" {
		t.Fatalf("subject %q dedup %q", fact.Subject, fact.DedupKey)
	}
}

func TestDeploymentStatusFactRejectsInvalidIdentityAndBounds(t *testing.T) {
	tests := map[string]func(*DeploymentStatus){
		"nil event":        func(v *DeploymentStatus) { v.EventID = uuid.Nil },
		"nil deployment":   func(v *DeploymentStatus) { v.DeploymentID = uuid.Nil },
		"nil node":         func(v *DeploymentStatus) { v.NodeID = uuid.Nil },
		"nil rollout":      func(v *DeploymentStatus) { v.RolloutID = uuid.Nil },
		"zero attempt":     func(v *DeploymentStatus) { v.Attempt = 0 },
		"large attempt":    func(v *DeploymentStatus) { v.Attempt = ^uint32(0) },
		"zero transition":  func(v *DeploymentStatus) { v.TransitionSequence = 0 },
		"large transition": func(v *DeploymentStatus) { v.TransitionSequence = ^uint64(0) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input := deploymentInput()
			mutate(&input)
			if _, err := NewDeploymentStatusFact(input); err == nil {
				t.Fatal("expected invalid deployment status")
			}
		})
	}
	// Contract-level checks run when the fact is canonicalised.
	for name, mutate := range map[string]func(*DeploymentStatus){
		"unknown state":   func(v *DeploymentStatus) { v.State = "running" },
		"nil tenant":      func(v *DeploymentStatus) { v.TenantScopeID = uuid.Nil },
		"zero occurrence": func(v *DeploymentStatus) { v.OccurredAt = time.Time{} },
	} {
		t.Run(name, func(t *testing.T) {
			input := deploymentInput()
			mutate(&input)
			fact, err := NewDeploymentStatusFact(input)
			if err == nil {
				_, err = fact.Canonical()
			}
			if !errors.Is(err, ErrInvalidEvent) {
				t.Fatalf("error = %v, want ErrInvalidEvent", err)
			}
		})
	}
}

func TestCanonicalRejectsFieldsOutsideTheContract(t *testing.T) {
	base, err := NewDeploymentStatusFact(deploymentInput())
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*Fact){
		"extra field":       func(v *Fact) { v.Data["command"] = "secret" },
		"missing required":  func(v *Fact) { delete(v.Data, "state") },
		"wrong kind":        func(v *Fact) { v.Data["attempt"] = "2" },
		"reserved field":    func(v *Fact) { v.Data[FieldSubscriptionID] = uuid.NewString() },
		"subject kind":      func(v *Fact) { v.Subject = "site/" + uuid.NewString() },
		"subject not uuid":  func(v *Fact) { v.Subject = "deployment/abc" },
		"unknown type":      func(v *Fact) { v.EventType = "io.cdnca.dns.v1.changed" },
		"site on unbound":   func(v *Fact) { v.SiteID = uuid.New() },
		"empty dedup":       func(v *Fact) { v.DedupKey = "" },
		"padded dedup":      func(v *Fact) { v.DedupKey = " x" },
		"negative integer":  func(v *Fact) { v.Data["attempt"] = -1 },
		"fractional number": func(v *Fact) { v.Data["attempt"] = 1.5 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fact := base
			fact.Data = make(map[string]any, len(base.Data))
			for key, value := range base.Data {
				fact.Data[key] = value
			}
			mutate(&fact)
			tx := &recordingTx{}
			if _, err := EnqueueTx(t.Context(), tx, fact); !errors.Is(err, ErrInvalidEvent) {
				t.Fatalf("error = %v, want ErrInvalidEvent", err)
			}
			if tx.called {
				t.Fatal("invalid fact reached PostgreSQL")
			}
		})
	}
}

func TestValidWebhookDataRequiresDeliveryFields(t *testing.T) {
	fact, _ := NewDeploymentStatusFact(deploymentInput())
	payload, _ := fact.Canonical()
	subscription := uuid.NewString()
	build := func(extra map[string]any) map[string]json.RawMessage {
		data := map[string]json.RawMessage{}
		_ = json.Unmarshal(payload, &data)
		for key, value := range extra {
			raw, _ := json.Marshal(value)
			data[key] = raw
		}
		return data
	}
	if !ValidWebhookData(DeploymentStatusChangedType, subscription,
		build(map[string]any{FieldSubscriptionID: subscription, FieldSubjectSequence: 3})) {
		t.Fatal("valid webhook data rejected")
	}
	for name, extra := range map[string]map[string]any{
		"no sequence":        {FieldSubscriptionID: subscription},
		"zero sequence":      {FieldSubscriptionID: subscription, FieldSubjectSequence: 0},
		"other subscription": {FieldSubscriptionID: uuid.NewString(), FieldSubjectSequence: 1},
		"extension field":    {FieldSubscriptionID: subscription, FieldSubjectSequence: 1, "x_note": "a"},
	} {
		if ValidWebhookData(DeploymentStatusChangedType, subscription, build(extra)) {
			t.Fatalf("%s accepted", name)
		}
	}
}

type recordingTx struct {
	pgx.Tx
	called bool
}

func (tx *recordingTx) QueryRow(context.Context, string, ...any) pgx.Row {
	tx.called = true
	return nil
}
