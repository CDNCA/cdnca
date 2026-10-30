package ruleintel

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

// pack_receipts（RI-12 自动暂停）只加字段：省略时报告字节与加字段前一致；出现则非空、升序、只报官方包。
func TestPackReceiptsSection(t *testing.T) {
	r := empty()
	_, before, _ := Digest(r)
	if bytes.Contains(before, []byte("pack_receipts")) {
		t.Fatal("omitted pack_receipts changed the report bytes")
	}
	if _, found := r.Counts()["pack_receipts"]; found {
		t.Fatal("omitted pack_receipts counted")
	}
	r.PackReceipts = []PackReceipt{{PackID: "system/crs-pl2", Version: "1.0.1", Applied: 3, Rejected: 1},
		{PackID: "system/crs-tuning", Version: "1.0.0", Applied: 4}, {PackID: "system/crs-tuning", Version: "1.0.1", Rejected: 2}}
	if err := Validate(r); err != nil {
		t.Fatal(err)
	}
	if r.Counts()["pack_receipts"] != 3 {
		t.Fatal("pack_receipts not counted")
	}
	var decoded Report
	_, encoded, _ := Digest(r)
	if err := json.Unmarshal(encoded, &decoded); err != nil || len(decoded.PackReceipts) != 3 || decoded.PackReceipts[2].Rejected != 2 {
		t.Fatalf("round trip %+v %v", decoded.PackReceipts, err)
	}
	for name, receipts := range map[string][]PackReceipt{
		"empty":       {},
		"tenant pack": {{PackID: "user/0f0e/x", Version: "1.0.0", Applied: 1}},
		"dev pack":    {{PackID: "dev/acme/x", Version: "1.0.0", Applied: 1}},
		"version":     {{PackID: "system/crs-tuning", Version: "latest", Applied: 1}},
		"negative":    {{PackID: "system/crs-tuning", Version: "1.0.0", Applied: -1, Rejected: 2}},
		"zero":        {{PackID: "system/crs-tuning", Version: "1.0.0"}},
		"order": {{PackID: "system/crs-tuning", Version: "1.0.1", Applied: 1},
			{PackID: "system/crs-tuning", Version: "1.0.0", Applied: 1}},
		"duplicate": {{PackID: "system/crs-tuning", Version: "1.0.0", Applied: 1},
			{PackID: "system/crs-tuning", Version: "1.0.0", Rejected: 1}},
	} {
		r.PackReceipts = receipts
		if err := Validate(r); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
	r.PackReceipts = make([]PackReceipt, SectionLimits["pack_receipts"]+1)
	if err := Validate(r); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("over limit: %v", err)
	}
}
