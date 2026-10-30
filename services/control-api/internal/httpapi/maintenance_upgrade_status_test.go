package httpapi

import (
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestMaintenanceUpgradeNodeQueryRejectsAmbiguousInputs(t *testing.T) {
	id := uuid.NewString()
	for _, value := range []string{"page=1", "node_id=", "node_id=" + uuid.Nil.String(), "node_id=" + id + "&node_id=" + id, "node_id=" + strings.ToUpper(id), "node_id=%zz", "node_id=" + id + ";other=x"} {
		if _, err := parseMaintenanceUpgradeNodes(value); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
	values := url.Values{}
	for range 100 {
		values.Add("node_id", uuid.NewString())
	}
	if ids, err := parseMaintenanceUpgradeNodes(values.Encode()); err != nil || len(ids) != 100 {
		t.Fatalf("100 nodes: %d %v", len(ids), err)
	}
	values.Add("node_id", uuid.NewString())
	if _, err := parseMaintenanceUpgradeNodes(values.Encode()); err == nil {
		t.Fatal("accepted 101 nodes")
	}
	if ids, err := parseMaintenanceUpgradeNodes(""); err != nil || len(ids) != 0 {
		t.Fatal("control-only read requires nodes")
	}
}
