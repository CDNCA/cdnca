package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 583 (fix-finrefund CFIN-01): the 435 redefinition of
// validate_recharge_payment_approval_171() reads the approved decision with an
// unqualified "decision" column while a record variable of the same name is in
// scope (SQLSTATE 42702), so every approved refund/void failed before the
// provider was called. 583 rolls the function forward with a table alias; the
// released 435 stays byte-identical. The 582 predecessor is pinned by checksum.
const (
	migration583Version         = 583
	migration583PreviousVersion = 582
	migration583PreviousID      = "582_node_deployment_frozen_refusals"
	migration583PreviousUpSHA   = "9f6f4fb87a5ded956990bcd9e5c1bbca22e1826ac6e877c1e4e9d091da299038"
	migration583PreviousDownSHA = "dd80b8d1057da31098896541327dc1ecf34cd43f70b31533a4e10a697c43f1bf"
	migration583ID              = "583_recharge_approval_decision_alias"
)

func TestRechargeApprovalDecisionAlias583Contract(t *testing.T) {
	read := func(name string) string {
		t.Helper()
		raw, err := FS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	up, down := read(migration583ID+".up.sql"), read(migration583ID+".down.sql")
	for _, required := range []string{
		fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration583PreviousVersion),
		fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration583PreviousVersion),
		fmt.Sprintf("WHERE version=%d AND", migration583PreviousVersion),
		"migration_id='" + migration583PreviousID + "'",
		"checksum_sha256='" + migration583PreviousUpSHA + "'",
		"down_checksum_sha256='" + migration583PreviousDownSHA + "'",
		"ERRCODE='P5830'",
		"CREATE OR REPLACE FUNCTION validate_recharge_payment_approval_171()",
		"SELECT approved_row.* INTO decision FROM recharge_payment_approval_decisions_v1 approved_row",
		"WHERE approved_row.approval_request_id=NEW.approval_request_id AND approved_row.decision='approved' FOR SHARE;",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("%s.up.sql missing %q", migration583ID, required)
		}
	}
	if strings.Contains(approval171Body(t, up), "AND decision='approved'") {
		t.Errorf("%s.up.sql still reads the ambiguous decision column", migration583ID)
	}
	for _, required := range []string{
		fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration583Version),
		"migration_id='" + migration583ID + "'", "ERRCODE='P5831'",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("%s.down.sql missing %q", migration583ID, required)
		}
	}

	// The new body differs from 435 only in the aliased decision query, and
	// down restores the 435 body verbatim.
	released := approval171Body(t, read("435_admin_self_approval.up.sql"))
	fixed := strings.Replace(strings.Replace(released,
		"SELECT * INTO decision FROM recharge_payment_approval_decisions_v1\n",
		"SELECT approved_row.* INTO decision FROM recharge_payment_approval_decisions_v1 approved_row\n", 1),
		"WHERE approval_request_id=NEW.approval_request_id AND decision='approved' FOR SHARE;",
		"WHERE approved_row.approval_request_id=NEW.approval_request_id AND approved_row.decision='approved' FOR SHARE;", 1)
	if fixed == released {
		t.Fatal("435 function body no longer contains the released decision query")
	}
	if got := approval171Body(t, up); got != fixed {
		t.Errorf("583 up body is not the 435 body with only the decision query aliased")
	}
	if got := approval171Body(t, down); got != released {
		t.Errorf("583 down body is not the 435 body")
	}

	for suffix, want := range map[string]string{".up.sql": migration583PreviousUpSHA, ".down.sql": migration583PreviousDownSHA} {
		if got := fmt.Sprintf("%x", sha256.Sum256([]byte(read(migration583PreviousID+suffix)))); got != want {
			t.Errorf("%s%s checksum %s, guard pins %s", migration583PreviousID, suffix, got, want)
		}
	}
}

func approval171Body(t *testing.T, script string) string {
	t.Helper()
	const head = "CREATE OR REPLACE FUNCTION validate_recharge_payment_approval_171()"
	start := strings.Index(script, head)
	if start < 0 {
		t.Fatal("validate_recharge_payment_approval_171 definition not found")
	}
	end := strings.Index(script[start:], "\n$$;")
	if end < 0 {
		t.Fatal("validate_recharge_payment_approval_171 definition is not terminated")
	}
	return script[start : start+end]
}
