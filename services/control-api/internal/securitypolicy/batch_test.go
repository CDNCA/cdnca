package securitypolicy

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/packageaddon"
	"github.com/google/uuid"
)

func TestValidBatchRequest(t *testing.T) {
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"}
	id := uuid.New()
	good := BatchRequest{Action: BatchDisable, Items: []BatchItem{{ID: id, Version: 1}}, IdempotencyKey: "k", RequestID: "r"}
	if !validBatch(actor, good) {
		t.Fatal("valid batch refused")
	}
	tooMany := make([]BatchItem, maxBatchItems+1)
	for index := range tooMany {
		tooMany[index] = BatchItem{ID: uuid.New(), Version: 1}
	}
	for name, request := range map[string]BatchRequest{
		"action":    {Action: "rename", Items: good.Items, IdempotencyKey: "k", RequestID: "r"},
		"empty":     {Action: BatchDelete, IdempotencyKey: "k", RequestID: "r"},
		"too many":  {Action: BatchDelete, Items: tooMany, IdempotencyKey: "k", RequestID: "r"},
		"duplicate": {Action: BatchDelete, Items: []BatchItem{{ID: id, Version: 1}, {ID: id, Version: 2}}, IdempotencyKey: "k", RequestID: "r"},
		"version":   {Action: BatchDelete, Items: []BatchItem{{ID: id}}, IdempotencyKey: "k", RequestID: "r"},
		"nil id":    {Action: BatchDelete, Items: []BatchItem{{Version: 1}}, IdempotencyKey: "k", RequestID: "r"},
		"no key":    {Action: BatchDelete, Items: good.Items, RequestID: "r"},
	} {
		if validBatch(actor, request) {
			t.Fatalf("%s accepted", name)
		}
	}
}

// Item keys are stable per batch and item, valid idempotency keys, and differ
// across batches and items.
func TestBatchItemKey(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	key := batchItemKey("batch-1", a)
	if key != batchItemKey("batch-1", a) || key == batchItemKey("batch-1", b) || key == batchItemKey("batch-2", a) ||
		!idempotencyPattern.MatchString(key) || !strings.HasPrefix(key, "batch-") {
		t.Fatalf("item key %q", key)
	}
}

func TestBatchRefusalStatuses(t *testing.T) {
	for err, want := range map[error]string{
		ErrRevisionConflict:                      "version_conflict",
		ErrNotFound:                              "not_found",
		ErrPermissionDenied:                      "forbidden",
		&InUseError{Domains: []string{"a.test"}}: "in_use",
		ErrIdempotencyConflict:                   "idempotency_conflict",
		ErrInvalidInput:                          "rejected",
		fmt.Errorf("x: %w", packageaddon.ErrFeatureDenied): "rejected",
	} {
		result, stop := batchRefusal(BatchItemResult{}, err)
		if stop != nil || result.Status != want {
			t.Fatalf("%v -> %q, %v want %q", err, result.Status, stop, want)
		}
	}
	if _, stop := batchRefusal(BatchItemResult{}, errors.New("database down")); stop == nil {
		t.Fatal("store errors must stop the batch")
	}
}

func TestListWhereScope(t *testing.T) {
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"}
	for scope, fragments := range map[string][]string{
		ScopeSystem: {"starts_with(p.description,$3)"},
		ScopeSite:   {"NOT starts_with(p.description,$3)", " AND EXISTS (SELECT 1 FROM security_policy_site_bindings"},
		ScopeGlobal: {"NOT starts_with(p.description,$3)", "NOT EXISTS (SELECT 1 FROM security_policy_site_bindings"},
	} {
		where, args := listWhere(actor, ListFilter{Kind: KindWAF, Scope: scope})
		for _, fragment := range fragments {
			if !strings.Contains(where, fragment) {
				t.Fatalf("scope %s where %q missing %q", scope, where, fragment)
			}
		}
		if len(args) != 3 || args[2] != licensedWAFDescriptionPrefix {
			t.Fatalf("scope %s args %v", scope, args)
		}
	}
}
