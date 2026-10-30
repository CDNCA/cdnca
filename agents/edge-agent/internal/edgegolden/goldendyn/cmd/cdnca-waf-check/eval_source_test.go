package main

import "testing"

// waf-gap7: the evaluation's raw requests come from rotating local source
// addresses (127.2.y.z, z 1-254), so no source reaches the repeated grey zone
// threshold (edgeconfig DynamicWAFRepeat: 20 per site x address a minute).
func TestRawSourceRotates(t *testing.T) {
	seen := map[string]int{}
	for range 254 * 256 {
		ip := rawSource().To4()
		if ip[0] != 127 || ip[1] != 2 || ip[3] == 0 || ip[3] == 255 {
			t.Fatalf("source %s outside 127.2.0.0/16 hosts", ip)
		}
		seen[ip.String()]++
	}
	if len(seen) != 254*256 {
		t.Fatalf("%d distinct sources in one cycle", len(seen))
	}
}
