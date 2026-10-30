package analyticsconnections

import "testing"

func TestObservedConnectionsV2RetainsConfigAndZeroInReceipt(t *testing.T) {
	delivery := runtimeRedeliveryDelivery(t, 1, 8)
	delivery.Envelope.SchemaVersion = 2
	delivery.Envelope.Connections = 0
	delivery.Envelope.PackageSubscriptionId = ""
	delivery.Envelope.ConfigVersionId = "77777777-7777-4777-8777-777777777777"
	receipt, err := ValidateDelivery(delivery)
	if err != nil || receipt.SchemaVersion != 2 || receipt.Connections != 0 || receipt.ConfigVersionID != delivery.Envelope.ConfigVersionId {
		t.Fatalf("receipt=%+v err=%v", receipt, err)
	}
	row, ok := newReceiptInsertRow(receipt)
	if !ok || row.Connections != 0 || row.ConfigVersionID != receipt.ConfigVersionID || row.PackageSubscriptionID != "00000000-0000-0000-0000-000000000000" {
		t.Fatalf("row=%+v", row)
	}
	delivery.Envelope.ConfigVersionId = ""
	if _, err := ValidateDelivery(delivery); err == nil {
		t.Fatal("missing config accepted")
	}
}
