package domaintrust

import (
	"slices"
	"testing"
)

func TestNormalizeApexFamily(t *testing.T) {
	for _, item := range []struct {
		raw, canonical, apex, family string
		wildcard                     bool
	}{
		{"WWW.Example.COM.", "www.example.com", "example.com", "example.com", false},
		{"*.Shop.Example.co.uk", "*.shop.example.co.uk", "example.co.uk", "shop.example.co.uk", true},
		{"例子.测试", "xn--fsqu00a.xn--0zwm56d", "xn--fsqu00a.xn--0zwm56d", "xn--0zwm56d", false},
		{"example.com", "example.com", "example.com", "com", false},
	} {
		got, err := Normalize(item.raw, item.wildcard)
		if err != nil || got != item.canonical {
			t.Fatalf("Normalize(%q) = %q, %v", item.raw, got, err)
		}
		if apex, err := Apex(got); err != nil || apex != item.apex {
			t.Fatalf("Apex(%q) = %q, %v", got, apex, err)
		}
		if family := Family(got); family != item.family {
			t.Fatalf("Family(%q) = %q", got, family)
		}
	}
	for _, raw := range []string{"", "*.x.com", "com", "a..com", "-a.com", "a_b.com", "a.com/x"} {
		if _, err := Normalize(raw, false); err == nil {
			t.Fatalf("Normalize(%q) accepted", raw)
		}
	}
	if _, err := Apex("co.uk"); err == nil {
		t.Fatal("a public suffix has no apex")
	}
}

func TestSuffixesStopAtTwoLabels(t *testing.T) {
	if got := suffixes("a.b.example.com"); !slices.Equal(got, []string{"a.b.example.com", "b.example.com", "example.com"}) {
		t.Fatalf("suffixes = %v", got)
	}
	if got := suffixes("example.com"); !slices.Equal(got, []string{"example.com"}) {
		t.Fatalf("suffixes = %v", got)
	}
}

func TestValidPolicy(t *testing.T) {
	for _, value := range []string{"off", "wildcard_only", "all"} {
		if !ValidPolicy(value) {
			t.Fatalf("%s rejected", value)
		}
	}
	if ValidPolicy("") || ValidPolicy("ALL") || DefaultPolicy != PolicyWildcardOnly {
		t.Fatal("policy validation")
	}
}
