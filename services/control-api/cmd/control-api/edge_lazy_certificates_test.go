package main

import (
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

func TestLoadEdgeLazyCertificateCacheMax(t *testing.T) {
	env := func(value string, present bool) func(string) (string, bool) {
		return func(name string) (string, bool) {
			if name != edgeLazyCertificateCacheMaxEnv {
				t.Fatalf("read %s", name)
			}
			return value, present
		}
	}
	for _, test := range []struct {
		value   string
		present bool
		want    int64
	}{{"", false, edgeconfig.DefaultLazyCertificateCacheMax}, {"", true, edgeconfig.DefaultLazyCertificateCacheMax}, {"50000", true, 50000}} {
		if got, err := loadEdgeLazyCertificateCacheMax(env(test.value, test.present)); err != nil || got != test.want {
			t.Fatalf("%q: %d %v", test.value, got, err)
		}
	}
	for _, value := range []string{"0", "-1", "1000001", "1e3", "+5", " 5", "x"} {
		if _, err := loadEdgeLazyCertificateCacheMax(env(value, true)); err == nil {
			t.Fatalf("%q accepted", value)
		}
	}
}
