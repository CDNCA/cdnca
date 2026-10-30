package ruleintel

import (
	"strings"
	"testing"
)

func TestParamConds(t *testing.T) {
	in := ParamConds("ARGS", "Q[]")
	if len(in) != 3 || in[0] != [2]string{"param.loc", "args"} || in[1] != [2]string{"param.name", "q"} || in[2][1] != ParamClassDict {
		t.Fatalf("dictionary param = %v", in)
	}
	out := ParamConds("cookie", "acme_shop_owner")
	if len(out) != 3 || out[1] != [2]string{"param.class", ParamClassOther} || out[2][0] != "param.hash" || len(out[2][1]) != 64 {
		t.Fatalf("out-of-dictionary param = %v", out)
	}
	if again := ParamConds("cookie", "ACME_shop_owner"); again[2] != out[2] {
		t.Fatal("hash must follow the normalized name")
	}
	for _, c := range append(in, out...) {
		if err := validateCond(c[0], c[1]); err != nil {
			t.Fatalf("%v: %v", c, err)
		}
	}
	if ParamConds("args", "") != nil {
		t.Fatal("empty name must yield nothing")
	}
}

func TestSignatureConds(t *testing.T) {
	conds, dropped := SignatureConds([][2]string{{"cidr", "203.0.113.0/24"}, {"method", "GET"}, {"path_template", "/user/9/x"},
		{"path_template", "/a.example.com/private"}, {"header_order_hash", "0011223344556677"}, {"ua_hash", "0011223344556677"},
		{"query_names_hash", "0011223344556677"}, {"ip_tag", "tor"}, {"static_ratio_bucket", "none"}, {"asn", "13335"}})
	if dropped != 5 {
		t.Fatalf("dropped = %d (%v)", dropped, conds)
	}
	joined := ""
	for _, c := range conds {
		joined += c[0] + "=" + c[1] + ";"
		if err := validateCond(c[0], c[1]); err != nil {
			t.Fatalf("%v: %v", c, err)
		}
	}
	for _, leak := range []string{"203.0.113", "example", "private", "0011223344556677", "tor"} {
		if strings.Contains(joined, leak) {
			t.Fatalf("leaks %q: %s", leak, joined)
		}
	}
	if !strings.Contains(joined, "path.class=/user/*;") || !strings.Contains(joined, "bucket.static_ratio=none;") {
		t.Fatalf("conds = %s", joined)
	}
}

func TestPathClass(t *testing.T) {
	for path, want := range map[string]string{"/wp-admin/x.php": "/wp-admin/*", "/API/v1/users/7": "/api/*", "/graphql": "/graphql",
		"/secret-tenant/path": "", "/apix": ""} {
		if got := PathClass(path); got != want {
			t.Errorf("PathClass(%q) = %q, want %q", path, got, want)
		}
	}
}
