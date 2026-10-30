package dynroute

import "testing"

func TestParseSiteConnections(t *testing.T) {
	got, evidence, err := parseSiteConnections([]byte(`{"b|443":1,"a|80":3,"a|443":2}`))
	if err != nil || len(got) != 3 || got[0] != (SiteConnection{"a", 80, 3}) || got[2] != (SiteConnection{"b", 443, 1}) || evidence == ([32]byte{}) {
		t.Fatalf("%+v %v", got, err)
	}
	if got, _, err := parseSiteConnections([]byte(`{}`)); err != nil || len(got) != 0 {
		t.Fatalf("empty: %+v %v", got, err)
	}
	for _, bad := range []string{`{"a":1}`, `{"a|0":1}`, `{"|80":1}`, `[]`} {
		if _, _, err := parseSiteConnections([]byte(bad)); err == nil {
			t.Fatalf("%s accepted", bad)
		}
	}
}
