package cnameallocation

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestValidateLabel(t *testing.T) {
	for _, ok := range []string{"shop", "a", "gd-1", "a1b2", strings.Repeat("a", 63)} {
		if err := ValidateLabel(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "-a", "a-", "A", "a_b", "a.b", "a b", "中文", strings.Repeat("a", 64)} {
		if err := ValidateLabel(bad); !errors.Is(err, ErrLabelInvalid) {
			t.Errorf("%q: %v, want invalid", bad, err)
		}
	}
	for _, reserved := range []string{"www", "ns", "ns1", "ns2", "mail", "_acme-challenge"} {
		err := ValidateLabel(reserved)
		// "_acme-challenge" also fails the character set; either code refuses it.
		if !errors.Is(err, ErrLabelReserved) && !errors.Is(err, ErrLabelInvalid) {
			t.Errorf("%q: %v, want refused", reserved, err)
		}
	}
	if err := ValidateLabel("www"); !errors.Is(err, ErrLabelReserved) {
		t.Fatalf("www: %v", err)
	}
}

func TestValidatePrefixLength(t *testing.T) {
	if err := ValidatePrefix(strings.Repeat("a", MaxPrefixLength)); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePrefix(strings.Repeat("a", MaxPrefixLength+1)); !errors.Is(err, ErrLabelInvalid) {
		t.Fatalf("over-long prefix: %v", err)
	}
	// "www" is only reserved as a complete name.
	if err := ValidatePrefix("www"); err != nil {
		t.Fatal(err)
	}
	if MaxPrefixLength != 54 {
		t.Fatalf("MaxPrefixLength = %d", MaxPrefixLength)
	}
}

func TestPrefixedLabelLengthAndShape(t *testing.T) {
	prefix := strings.Repeat("a", MaxPrefixLength)
	hostname, err := freeGeneratedHostnamePrefixed(labelTestKey, prefix, uuid.New(), uuid.New(), uuid.New(),
		ModeSite, "cdn86.com", 1, func(string) (bool, error) { return false, nil })
	if err != nil {
		t.Fatal(err)
	}
	label := strings.TrimSuffix(hostname, ".cdn86.com")
	if len(label) != MaxLabelLength || !strings.HasPrefix(label, prefix+"-") || ValidateLabel(label) != nil {
		t.Fatalf("label %q (%d)", label, len(label))
	}
	short, _ := freeGeneratedHostnamePrefixed(labelTestKey, "gd", uuid.New(), uuid.New(), uuid.New(),
		ModeSite, "cdn86.com", 1, func(string) (bool, error) { return false, nil })
	if rest := strings.TrimPrefix(strings.TrimSuffix(short, ".cdn86.com"), "gd-"); len(rest) != LabelLength {
		t.Fatalf("random part of %q is %d long", short, len(rest))
	}
}

func TestPrefixedLabelRetriesOnCollision(t *testing.T) {
	tenant, provider, owner := uuid.New(), uuid.New(), uuid.New()
	first, _ := freeGeneratedHostnamePrefixed(labelTestKey, "gd", tenant, provider, owner, ModeSite, "cdn86.com", 1,
		func(string) (bool, error) { return false, nil })
	second, err := freeGeneratedHostnamePrefixed(labelTestKey, "gd", tenant, provider, owner, ModeSite, "cdn86.com", 1,
		func(candidate string) (bool, error) { return candidate == first, nil })
	if err != nil || second == first || !strings.HasPrefix(second, "gd-") {
		t.Fatalf("first=%q second=%q err=%v", first, second, err)
	}
	_, err = freeGeneratedHostnamePrefixed(labelTestKey, "gd", tenant, provider, owner, ModeSite, "cdn86.com", 1,
		func(string) (bool, error) { return true, nil })
	if failureCode(err) != FailureLabelExhausted {
		t.Fatalf("exhausted: %v", err)
	}
}

func TestEffectiveLabelOrder(t *testing.T) {
	cases := []struct {
		name           string
		source         labelSource
		legacy         bool
		custom, prefix string
	}{
		{"own name wins", labelSource{custom: "shop", linePrefix: "line"}, false, "shop", ""},
		{"own name beats explicit hostname", labelSource{custom: "shop"}, true, "shop", ""},
		{"line prefix", labelSource{linePrefix: "line"}, false, "", "line"},
		{"explicit hostname beats line prefix", labelSource{linePrefix: "line"}, true, "", ""},
		{"nothing set: random", labelSource{}, false, "", ""},
	}
	for _, tc := range cases {
		custom, prefix := tc.source.effectiveLabel(tc.legacy)
		if custom != tc.custom || prefix != tc.prefix {
			t.Errorf("%s: got (%q,%q) want (%q,%q)", tc.name, custom, prefix, tc.custom, tc.prefix)
		}
	}
}
