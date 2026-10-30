package rulepack

import (
	"errors"
	"testing"
)

// PA-18: a developer pack lives in its market publisher's namespace
// (dev/<publisher id>/<name>); publisher ids are dotted (io.cdnca.examples).
func TestDeveloperPackNamespace(t *testing.T) {
	err := mutate(t, "system-sqli.json", func(d map[string]any) {
		d["pack_id"], d["layer"] = "dev/io.cdnca.examples/sqli-extra", "developer"
	})
	if err != nil {
		t.Fatalf("dotted publisher namespace rejected: %v", err)
	}
	if publisher, ok := DeveloperPackPublisher("dev/io.cdnca.examples/sqli-extra"); !ok || publisher != "io.cdnca.examples" {
		t.Fatalf("publisher=%q ok=%v", publisher, ok)
	}
	for _, id := range []string{"dev/io..x/a", "dev/.io/a", "dev/io./a", "dev/IO.x/a", "system/x"} {
		if _, ok := DeveloperPackPublisher(id); ok {
			t.Errorf("%s accepted as a developer pack", id)
		}
	}
	err = mutate(t, "system-sqli.json", func(d map[string]any) {
		d["pack_id"], d["layer"] = "dev/io..x/sqli", "developer"
	})
	if !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("malformed namespace: %v", err)
	}
}
