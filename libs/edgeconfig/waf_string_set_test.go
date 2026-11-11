package edgeconfig

import (
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

const testStringSetID = "0190a000-0000-7000-8000-0000000000c7"

func TestCanonicalStringSetMembers(t *testing.T) {
	members, size, err := CanonicalStringSetMembers(StringSetExact, true, []string{" b ", "a", "b", "B"})
	if err != nil || !reflect.DeepEqual(members, []string{"B", "a", "b"}) || size != 3 {
		t.Fatalf("case sensitive %v %d %v", members, size, err)
	}
	// Case insensitive folds A-Z only, then deduplicates; non-ASCII stays.
	members, size, err = CanonicalStringSetMembers(StringSetContains, false, []string{"Bot", "bot", "ÄBC", "äbc"})
	if err != nil || !reflect.DeepEqual(members, []string{"bot", "Äbc", "äbc"}) || size != 3+4+4 {
		t.Fatalf("case insensitive %v %d %v", members, size, err)
	}
	members, _, err = CanonicalStringSetMembers(StringSetWildcard, true, []string{"*.example.com", "a?c"})
	if err != nil || !reflect.DeepEqual(members, []string{"*.example.com", "a?c"}) {
		t.Fatalf("wildcard %v %v", members, err)
	}
	if _, _, err := CanonicalStringSetMembers("regex", true, []string{"a"}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("unknown mode: %v", err)
	}
}

func TestCanonicalStringSetMembersRejects(t *testing.T) {
	long := strings.Repeat("a", MaxStringSetMemberBytes+1)
	for _, test := range []struct {
		mode    string
		entries []string
		index   int
		reason  string
	}{
		{StringSetExact, []string{"ok", "  "}, 1, StringSetReasonEmpty},
		{StringSetExact, []string{long}, 0, StringSetReasonTooLong},
		{StringSetExact, []string{"a\x01b"}, 0, StringSetReasonControl},
		{StringSetExact, []string{"a\u0085b"}, 0, StringSetReasonControl},
		{StringSetExact, []string{"\xff"}, 0, StringSetReasonInvalidUTF8},
		{StringSetWildcard, []string{"a*b*c*d*"}, 0, StringSetReasonWildcardStars},
		{StringSetWildcard, []string{"x", "*?*"}, 1, StringSetReasonWildcardOnly},
		{StringSetExact, nil, -1, StringSetReasonCount},
	} {
		_, _, err := CanonicalStringSetMembers(test.mode, true, test.entries)
		var entry *StringSetEntryError
		if !errors.As(err, &entry) || !errors.Is(err, ErrInvalidConfig) || entry.Index != test.index || entry.Reason != test.reason {
			t.Errorf("%s %q: %v", test.mode, test.entries, err)
		}
	}
	// Exactly the limits pass; one more fails.
	many := make([]string, MaxStringSetMembers)
	for index := range many {
		many[index] = strings.Repeat("x", 5) + string(rune('a'+index%26)) + strings.Repeat("y", index/26%10) + strconv.Itoa(index)
	}
	if _, _, err := CanonicalStringSetMembers(StringSetExact, true, many); err != nil {
		t.Fatalf("%d members rejected: %v", MaxStringSetMembers, err)
	}
	if _, _, err := CanonicalStringSetMembers(StringSetExact, true, append(many, "extra")); !reasonIs(err, StringSetReasonCount) {
		t.Fatalf("%d members accepted: %v", MaxStringSetMembers+1, err)
	}
	if _, _, err := CanonicalStringSetMembers(StringSetWildcard, true, many[:MaxStringSetWildcardMembers+1]); !reasonIs(err, StringSetReasonCount) {
		t.Fatalf("too many wildcard members accepted: %v", err)
	}
	big := make([]string, 0, MaxStringSetBytes/MaxStringSetMemberBytes+1)
	for index := 0; index <= MaxStringSetBytes/MaxStringSetMemberBytes; index++ {
		big = append(big, strconv.Itoa(index)+strings.Repeat("z", MaxStringSetMemberBytes-len(strconv.Itoa(index))))
	}
	if _, _, err := CanonicalStringSetMembers(StringSetExact, true, big[:len(big)-1]); err != nil {
		t.Fatalf("exactly %d bytes rejected: %v", MaxStringSetBytes, err)
	}
	if _, _, err := CanonicalStringSetMembers(StringSetExact, true, big); !reasonIs(err, StringSetReasonTooLarge) {
		t.Fatalf("over %d bytes accepted: %v", MaxStringSetBytes, err)
	}
}

func reasonIs(err error, reason string) bool {
	var entry *StringSetEntryError
	return errors.As(err, &entry) && entry.Reason == reason
}

func TestValidateWAFStringSet(t *testing.T) {
	set := WAFStringSet{ID: testStringSetID, Revision: 2, Mode: StringSetPrefix, CaseSensitive: true, Members: []string{"/admin", "/api/"}}
	if err := ValidateWAFStringSet(set); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]WAFStringSet{
		"id":        {ID: "x", Revision: 1, Mode: StringSetExact, CaseSensitive: true, Members: []string{"a"}},
		"revision":  {ID: testStringSetID, Revision: 0, Mode: StringSetExact, CaseSensitive: true, Members: []string{"a"}},
		"mode":      {ID: testStringSetID, Revision: 1, Mode: "regex", CaseSensitive: true, Members: []string{"a"}},
		"empty":     {ID: testStringSetID, Revision: 1, Mode: StringSetExact, CaseSensitive: true},
		"unsorted":  {ID: testStringSetID, Revision: 1, Mode: StringSetExact, CaseSensitive: true, Members: []string{"b", "a"}},
		"duplicate": {ID: testStringSetID, Revision: 1, Mode: StringSetExact, CaseSensitive: true, Members: []string{"a", "a"}},
		"upper":     {ID: testStringSetID, Revision: 1, Mode: StringSetExact, CaseSensitive: false, Members: []string{"A"}},
		"spaces":    {ID: testStringSetID, Revision: 1, Mode: StringSetExact, CaseSensitive: true, Members: []string{" a"}},
	} {
		if err := ValidateWAFStringSet(bad); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
}

func TestStringSetTargetAccepts(t *testing.T) {
	ja4 := "t13d1516h2_8daaf6152771_02713d6af862"
	exact := WAFStringSet{ID: testStringSetID, Revision: 1, Mode: StringSetExact, CaseSensitive: true, Members: []string{ja4}}
	if !StringSetTargetAccepts(StringSetTargetJA4, exact) || !StringSetTargetAccepts(StringSetTargetUserAgent, exact) {
		t.Fatal("exact JA4 set refused")
	}
	for _, bad := range []WAFStringSet{
		{ID: testStringSetID, Revision: 1, Mode: StringSetPrefix, CaseSensitive: true, Members: []string{ja4}},
		{ID: testStringSetID, Revision: 1, Mode: StringSetExact, CaseSensitive: false, Members: []string{ja4}},
		{ID: testStringSetID, Revision: 1, Mode: StringSetExact, CaseSensitive: true, Members: []string{"curl"}},
	} {
		if StringSetTargetAccepts(StringSetTargetJA4, bad) {
			t.Errorf("ja4 accepted %+v", bad)
		}
	}
}

func TestNormalizeWAFMatchStringSets(t *testing.T) {
	refs := []WAFStringSetRef{
		{SetID: testStringSetID, Revision: 3, Target: StringSetTargetHeader, Key: "x-client"},
		{SetID: testStringSetID, Revision: 3, Target: StringSetTargetPath, Negate: true},
	}
	match, err := normalizeWAFMatch(WAFMatch{StringSets: refs})
	if err != nil || !reflect.DeepEqual(match.StringSets, refs) {
		t.Fatalf("%+v %v", match, err)
	}
	for _, bad := range []WAFStringSetRef{
		{SetID: "x", Revision: 1, Target: StringSetTargetPath},
		{SetID: testStringSetID, Revision: 0, Target: StringSetTargetPath},
		{SetID: testStringSetID, Revision: 1 << 53, Target: StringSetTargetPath},
		{SetID: testStringSetID, Revision: 1, Target: "cookie"},
		{SetID: testStringSetID, Revision: 1, Target: StringSetTargetHeader},
		{SetID: testStringSetID, Revision: 1, Target: StringSetTargetHeader, Key: "X-Upper"},
		{SetID: testStringSetID, Revision: 1, Target: StringSetTargetPath, Key: "x"},
	} {
		if _, err := normalizeWAFMatch(WAFMatch{StringSets: []WAFStringSetRef{bad}}); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%+v accepted", bad)
		}
	}
	five := make([]WAFStringSetRef, MaxWAFStringSetsPerRule+1)
	for index := range five {
		five[index] = refs[1]
	}
	if _, err := normalizeWAFMatch(WAFMatch{StringSets: five}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatal("too many string set conditions accepted")
	}
	if _, err := normalizeWAFMatch(WAFMatch{StringSets: []WAFStringSetRef{}}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatal("empty string set list accepted")
	}
}

// The rule plan value of a string set condition.
func TestStringSetConditionSpec(t *testing.T) {
	spec := StringSetConditionSpec(WAFStringSetRef{SetID: testStringSetID, Revision: 2, Target: StringSetTargetHeader, Key: "x-a", Negate: true})
	if spec != `{"id":"`+testStringSetID+`","revision":2,"target":"header","key":"x-a","negate":true}` {
		t.Fatalf("spec %s", spec)
	}
	spec = StringSetConditionSpec(WAFStringSetRef{SetID: testStringSetID, Revision: 2, Target: StringSetTargetPath})
	if spec != `{"id":"`+testStringSetID+`","revision":2,"target":"path","key":"","negate":false}` {
		t.Fatalf("spec %s", spec)
	}
	if RuleOpStringSet != "string_set" {
		t.Fatal(RuleOpStringSet)
	}
}
