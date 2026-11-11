package edgepublish

import "testing"

// rotation keeps the previous key, so older versions stay a safe
// fallback; a revocation or any other change ends the fallback range.
func TestURLAuthFloorFromSnapshots(t *testing.T) {
	snapshot := func(version int, current, previous, algorithm string) []byte {
		document := `{"policy_version":` + string(rune('0'+version)) + `,"algorithm":"` + algorithm + `","current_key":{"key_id":"` + current + `","key_file":"f"}`
		if previous != "" {
			document += `,"previous_key":{"key_id":"` + previous + `","key_file":"f"}`
		}
		return []byte(document + "}")
	}
	for _, tc := range []struct {
		name      string
		version   int64
		snapshots map[int64][]byte
		want      int64
	}{
		{"first version", 1, map[int64][]byte{1: snapshot(1, "a", "", "x")}, 0},
		{"one rotation", 2, map[int64][]byte{1: snapshot(1, "a", "", "x"), 2: snapshot(2, "b", "a", "x")}, 1},
		{"revoked previous key", 3, map[int64][]byte{1: snapshot(1, "a", "", "x"), 2: snapshot(2, "b", "a", "x"), 3: snapshot(3, "b", "", "x")}, 0},
		{"second rotation revokes the oldest key", 3, map[int64][]byte{1: snapshot(1, "a", "", "x"), 2: snapshot(2, "b", "a", "x"), 3: snapshot(3, "c", "b", "x")}, 0},
		{"parameter changed", 2, map[int64][]byte{1: snapshot(1, "a", "", "y"), 2: snapshot(2, "b", "a", "x")}, 0},
		{"same keys over two versions", 3, map[int64][]byte{1: snapshot(1, "a", "", "x"), 2: snapshot(2, "b", "a", "x"), 3: snapshot(3, "b", "a", "x")}, 1},
		{"missing snapshot ends the walk", 3, map[int64][]byte{2: snapshot(2, "b", "a", "x"), 3: snapshot(3, "b", "a", "x")}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := urlAuthFloorFromSnapshots(tc.version, tc.snapshots)
			if err != nil || got != tc.want {
				t.Fatalf("floor = %d, %v; want %d", got, err, tc.want)
			}
		})
	}
}
