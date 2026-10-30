package systemconfigpublish

import (
	"os"
	"strings"
	"testing"
)

func TestLoadTargetsClosesScopeRowsBeforeNestedNodeQueries(t *testing.T) {
	body, err := os.ReadFile("service.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	start := strings.Index(source, "func loadTargets(")
	if start < 0 {
		t.Fatal("loadTargets source boundary not found")
	}
	end := strings.Index(source[start:], "\nfunc projectNginx(")
	if end < 0 {
		t.Fatal("loadTargets source boundary not found")
	}
	loadTargets := source[start : start+end]
	closeBeforeNestedQuery := strings.Index(loadTargets, "\n\trows.Close()\n\tfor index := range targets {")
	if closeBeforeNestedQuery < 0 {
		t.Fatal("loadTargets must close scope rows before querying per-scope nodes")
	}
	nestedQuery := strings.Index(loadTargets[closeBeforeNestedQuery+1:], "tx.Query(ctx, `SELECT node.id,node_scope.kind FROM nodes node")
	if nestedQuery < 0 {
		t.Fatal("loadTargets node query not found")
	}
}
