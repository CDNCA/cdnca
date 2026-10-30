package dnssettings

import (
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
)

func TestActorRequiresTenantIdentity(t *testing.T) {
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform", TenantID: uuid.New()}
	if actor.valid() {
		t.Fatal("platform actor must not access tenant-scoped DNS settings")
	}
	actor.ScopeKind = "tenant"
	if !actor.valid() {
		t.Fatal("complete tenant actor should be valid")
	}
}

func TestActorReadAcceptsPlatformWithoutTenantIdentity(t *testing.T) {
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform"}
	if !actor.validForRead() {
		t.Fatal("complete platform actor should be valid for settings reads")
	}
	if actor.valid() {
		t.Fatal("platform actor must remain invalid for settings writes and operations")
	}
	actor.TenantID = uuid.New()
	if actor.validForRead() {
		t.Fatal("platform actor with a tenant identity should be rejected as inconsistent")
	}
}

func TestValidMetadataRejectsAmbiguousRequestIdentity(t *testing.T) {
	for _, value := range []string{"", " leading", "line\nfeed", "a/b", string(make([]byte, 129))} {
		if validMetadata(value) {
			t.Fatalf("validMetadata(%q) accepted", value)
		}
	}
	for _, value := range []string{"dns-settings-1", "request_2026.08"} {
		if !validMetadata(value) {
			t.Fatalf("validMetadata(%q) rejected", value)
		}
	}
}

func TestOperationFromJobKeepsDurableStateAndTimestamps(t *testing.T) {
	created := time.Date(2026, 8, 23, 4, 0, 0, 0, time.UTC)
	started := created.Add(time.Minute)
	completed := started.Add(time.Minute)
	job := jobstate.StoredJob{
		ID: uuid.New(), Kind: repairJobKind, Subject: "dns repair", State: jobstate.StateRunning,
		Attempt: 1, MaxAttempts: 3, Progress: jobstate.Progress{Total: 1, Pending: 1},
		CreatedAt: created, StartedAt: started, UpdatedAt: started, CompletedAt: completed,
	}
	result := operationFromJob(job)
	if result.ID != job.ID || result.State != string(jobstate.StateRunning) || result.Progress.Pending != 1 {
		t.Fatalf("operation mapping lost state: %+v", result)
	}
	if result.StartedAt == nil || !result.StartedAt.Equal(started) || result.CompletedAt == nil || !result.CompletedAt.Equal(completed) {
		t.Fatalf("operation mapping lost timestamps: %+v", result)
	}
}
