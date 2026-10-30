package rulepackcontrol

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
)

func TestAuditActionsAreCatalogued(t *testing.T) {
	for _, action := range []string{AuditPackUpdate, AuditVersionDelete, AuditOverridePut, AuditSitePublish} {
		if entry, ok := audit.Lookup(action); !ok || entry.Category != audit.CategoryRule {
			t.Fatalf("%s: catalog entry %+v %v", action, entry, ok)
		}
	}
}

func TestDeniedReason(t *testing.T) {
	for err, want := range map[error]string{
		ErrPermissionDenied:                    "permission_denied",
		fmt.Errorf("%w: bad", ErrInvalidInput): "invalid_input",
		ErrNotFound:                            "not_found",
		ErrLocked:                              "locked_by_upper_level",
		ErrInUse:                               "in_use",
		&ConflictError{}:                       "mounts_conflict",
		errors.New("connection reset"):         "",
	} {
		if got := deniedReason(err); got != want {
			t.Errorf("deniedReason(%v) = %q, want %q", err, got, want)
		}
	}
}

func TestOverrideChanges(t *testing.T) {
	priority := 200
	before := Override{State: rulepack.StateInherit}
	after := Override{State: rulepack.StateEnabled, AllowLower: true, Priority: &priority,
		Params: rulepack.Params{"action": json.RawMessage(`"log"`)}}
	changes := overrideChanges(before, after)
	for _, field := range []string{"state", "allow_lower", "priority", "params"} {
		if _, ok := changes[field]; !ok {
			t.Fatalf("missing %s in %+v", field, changes)
		}
	}
	if got := overrideChanges(after, after); len(got) != 0 {
		t.Fatalf("no-op changes = %+v", got)
	}
	if got := overrideResourceID(OverrideInput{Level: rulepack.LevelPlatform, PackID: "system/x", RuleID: "r1"}); got != "platform/system/x#r1" {
		t.Fatalf("resource id = %s", got)
	}
}
