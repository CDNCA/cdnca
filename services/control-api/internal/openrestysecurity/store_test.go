package openrestysecurity

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestOverrideRequestDigestsIgnoreTransportMetadata(t *testing.T) {
	targetScopeID, actorScopeID := uuid.New(), uuid.New()
	actor := Actor{UserID: uuid.New(), ScopeID: actorScopeID, ScopeKind: ScopePlatform, Permissions: []string{PermissionManage}}
	otherActor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: ScopePlatform, Permissions: []string{"platform.admin"}}

	t.Run("create", func(t *testing.T) {
		request := CreateOverrideRequest{Actor: actor, TargetScopeID: targetScopeID, ScopeType: ScopeRegion, ScopeID: "华东",
			IdempotencyKey: "create-1", RequestID: "request-1", Config: mustConfig(map[string]any{"cc_enable": true})}
		digest, err := createOverrideRequestDigest(request)
		if err != nil {
			t.Fatal(err)
		}
		retry := request
		retry.Actor, retry.IdempotencyKey, retry.RequestID = otherActor, "create-2", "request-2"
		retryDigest, err := createOverrideRequestDigest(retry)
		if err != nil {
			t.Fatal(err)
		}
		if digest != retryDigest {
			t.Fatal("transport metadata changed create override digest")
		}
		request.Config = mustConfig(map[string]any{"cc_enable": false})
		changedDigest, err := createOverrideRequestDigest(request)
		if err != nil {
			t.Fatal(err)
		}
		if digest == changedDigest {
			t.Fatal("business payload did not change create override digest")
		}
	})

	t.Run("patch", func(t *testing.T) {
		request := PatchOverrideRequest{Actor: actor, TargetScopeID: targetScopeID, ID: uuid.New(), ExpectedRevision: 3,
			IdempotencyKey: "patch-1", RequestID: "request-1", Patch: mustConfig(map[string]any{"cc_enable": false}),
			RemovedFields: []string{"icmp_drop", "key"}}
		digest, err := patchOverrideRequestDigest(request)
		if err != nil {
			t.Fatal(err)
		}
		retry := request
		retry.Actor, retry.IdempotencyKey, retry.RequestID = otherActor, "patch-2", "request-2"
		retry.RemovedFields = []string{"key", "icmp_drop"}
		retryDigest, err := patchOverrideRequestDigest(retry)
		if err != nil {
			t.Fatal(err)
		}
		if digest != retryDigest {
			t.Fatal("transport metadata or removed-field order changed patch override digest")
		}
		request.ExpectedRevision++
		changedDigest, err := patchOverrideRequestDigest(request)
		if err != nil {
			t.Fatal(err)
		}
		if digest == changedDigest {
			t.Fatal("business payload did not change patch override digest")
		}
	})

	t.Run("delete", func(t *testing.T) {
		request := DeleteOverrideRequest{Actor: actor, TargetScopeID: targetScopeID, ID: uuid.New(), ExpectedRevision: 4,
			IdempotencyKey: "delete-1", RequestID: "request-1"}
		digest, err := deleteOverrideRequestDigest(request)
		if err != nil {
			t.Fatal(err)
		}
		retry := request
		retry.Actor, retry.IdempotencyKey, retry.RequestID = otherActor, "delete-2", "request-2"
		retryDigest, err := deleteOverrideRequestDigest(retry)
		if err != nil {
			t.Fatal(err)
		}
		if digest != retryDigest {
			t.Fatal("transport metadata changed delete override digest")
		}
		request.ExpectedRevision++
		changedDigest, err := deleteOverrideRequestDigest(request)
		if err != nil {
			t.Fatal(err)
		}
		if digest == changedDigest {
			t.Fatal("business payload did not change delete override digest")
		}
	})
}

func TestRequireSingleRevisionWrite(t *testing.T) {
	if err := requireSingleRevisionWrite(1); err != nil {
		t.Fatalf("one affected row: %v", err)
	}
	for _, rows := range []int64{0, 2} {
		if err := requireSingleRevisionWrite(rows); !errors.Is(err, ErrRevisionConflict) {
			t.Fatalf("rows=%d error=%v", rows, err)
		}
	}
}
