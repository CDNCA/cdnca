package certificateasset

import (
	"os"
	"strings"
	"testing"
)

func TestDeleteFailsClosedForLiveCertificateOrderReference(t *testing.T) {
	source, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	start := strings.Index(text, "func (s *Store) delete(")
	end := strings.Index(text, "func (s *Store) Get(")
	if start < 0 || end <= start {
		t.Fatal("locate certificate asset delete implementation")
	}
	deleteSource := text[start:end]
	for _, required := range []string{
		"FROM certificate_asset_versions AS version",
		"JOIN certificate_orders AS certificate_order",
		"certificate_order.scope_id=version.tenant_scope_id",
		"certificate_order.id=version.acme_order_id",
		"version.tenant_scope_id=$1 AND version.asset_id=$2",
		"certificate_order.status IN ('issued','deploying','active','renewal_due')",
		"return ErrReferenced",
	} {
		if !strings.Contains(deleteSource, required) {
			t.Fatalf("certificate asset delete lacks live order reference fence %q", required)
		}
	}
	orderFence := strings.Index(deleteSource, "JOIN certificate_orders AS certificate_order")
	tombstone := strings.Index(deleteSource, "UPDATE certificate_assets")
	if orderFence < 0 || tombstone < 0 || orderFence > tombstone {
		t.Fatal("live order reference fence must precede certificate asset tombstone")
	}
}
