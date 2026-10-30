package httpapi

import (
	"net/http/httptest"
	"testing"
)

func TestNodeNetworkScopeQueryIsExplicitAndStrict(t *testing.T) {
	for _, test := range []struct {
		query string
		want  bool
		valid bool
	}{
		{"", false, true}, {"external_only=true", true, true}, {"external_only=false", false, true},
		{"external_only=1", false, false}, {"external_only=", false, false},
		{"external_only=true&external_only=false", false, false},
	} {
		got, err := networkScopeQuery(httptest.NewRequest("GET", "/?"+test.query, nil))
		if (err == nil) != test.valid || got != test.want {
			t.Fatalf("%s = %t, %v", test.query, got, err)
		}
	}
}
