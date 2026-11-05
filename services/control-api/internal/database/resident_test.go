package database

import "testing"

func TestHoldResidentListsUntilReleased(t *testing.T) {
	before := len(Residents())
	b := HoldResident("resident-test-b", true)
	a := HoldResident("resident-test-a", false)
	got := Residents()
	if len(got) != before+2 {
		t.Fatalf("residents = %+v", got)
	}
	var names []string
	for _, r := range got {
		if r.Name == "resident-test-a" || r.Name == "resident-test-b" {
			names = append(names, r.Name)
			if r.Since.IsZero() || r.InPool != (r.Name == "resident-test-b") {
				t.Fatalf("resident %+v", r)
			}
		}
	}
	if len(names) != 2 || names[0] != "resident-test-a" {
		t.Fatalf("not sorted by name: %v", names)
	}
	a()
	a() // idempotent
	b()
	if len(Residents()) != before {
		t.Fatalf("released residents still listed: %+v", Residents())
	}
}
