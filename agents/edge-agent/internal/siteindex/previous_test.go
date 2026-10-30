package siteindex

import "testing"

func TestFilesPrevious(t *testing.T) {
	files := Files{Root: t.TempDir(), Access: Access{GID: -1}}
	if _, ok := files.Previous(5); ok {
		t.Fatal("previous without files")
	}
	for _, generation := range []uint64{3, 5} {
		if err := files.Write(Index{Generation: generation, Ports: []uint16{80}}); err != nil {
			t.Fatal(err)
		}
	}
	if previous, ok := files.Previous(5); !ok || previous != 3 {
		t.Fatalf("previous %d %v", previous, ok)
	}
	if _, ok := files.Previous(3); ok {
		t.Fatal("previous of the oldest")
	}
}
