package databasetest

import "testing"

func TestWithDatabaseReplacesOnlyTheDatabase(t *testing.T) {
	for _, tc := range []struct{ base, want string }{
		{"postgres://u:p@127.0.0.1:5432/cdnca_integration?sslmode=disable&search_path=x",
			"postgres://u:p@127.0.0.1:5432/fresh_abc?sslmode=disable&search_path=x"},
		{"postgresql://u@h/db", "postgresql://u@h/fresh_abc"},
		{"postgres://u@h:1", "postgres://u@h:1/fresh_abc"},
		{"host=h user=u dbname=db sslmode=disable", "host=h user=u dbname=db sslmode=disable dbname=fresh_abc"},
	} {
		got, err := WithDatabase(tc.base, "fresh_abc")
		if err != nil || got != tc.want {
			t.Fatalf("WithDatabase(%q) = %q, %v; want %q", tc.base, got, err, tc.want)
		}
	}
}
