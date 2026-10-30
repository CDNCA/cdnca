package httpapi

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/apikey"
)

func TestParseAPIKeyListRawQueryContract(t *testing.T) {
	valid := []struct {
		name string
		raw  string
		want apikey.APIKeyListInput
	}{
		{name: "legacy default", want: apikey.APIKeyListInput{Limit: 50}},
		{name: "minimum", raw: "limit=1", want: apikey.APIKeyListInput{Limit: 1}},
		{name: "maximum", raw: "limit=100", want: apikey.APIKeyListInput{Limit: 100}},
		{
			name: "complete filter",
			raw:  "limit=25&status=active&name=Alpha+Key&key_id=cfk_AAAAAAAAAAAAAAAAAAAAAA&cursor=opaque.cursor",
			want: apikey.APIKeyListInput{
				Limit: 25, Status: "active", Name: "Alpha Key",
				KeyID: "cfk_AAAAAAAAAAAAAAAAAAAAAA", Cursor: "opaque.cursor",
			},
		},
		{name: "offset", raw: "limit=10&offset=20", want: apikey.APIKeyListInput{Limit: 10, Offset: 20}},
		{name: "zero offset", raw: "offset=0", want: apikey.APIKeyListInput{Limit: 50}},
		{name: "maximum offset", raw: "offset=10000", want: apikey.APIKeyListInput{Limit: 50, Offset: 10000}},
		{name: "maximum cursor", raw: "cursor=" + strings.Repeat("a", 4096), want: apikey.APIKeyListInput{Limit: 50, Cursor: strings.Repeat("a", 4096)}},
	}
	for _, test := range valid {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseAPIKeyListRawQuery(test.raw)
			if err != nil || !reflect.DeepEqual(got, test.want) {
				t.Fatalf("parseAPIKeyListRawQuery(%q) = (%#v, %v), want %#v", test.raw, got, err, test.want)
			}
		})
	}

	invalid := []string{
		"limit=0", "limit=101", "limit=-1", "limit=1.0", "limit=%2B1", "limit=01", "limit=",
		"limit=1&limit=2", "status=active&status=revoked", "name=a&name=b", "key_id=a&key_id=b",
		"cursor=a&cursor=b", "status=", "name=", "key_id=", "cursor=", "unknown=value",
		"cursor=" + strings.Repeat("a", 4097), "limit=%zz", "limit=1;status=active",
		"offset=", "offset=-1", "offset=01", "offset=1.0", "offset=10001", "offset=100000", "offset=1&offset=2",
	}
	for _, raw := range invalid {
		if _, err := parseAPIKeyListRawQuery(raw); err == nil {
			t.Errorf("parseAPIKeyListRawQuery(%q) succeeded", raw)
		}
	}
}

func TestAPIKeyListResponseContract(t *testing.T) {
	for _, test := range []struct {
		name       string
		items      []apikey.Key
		nextCursor string
		hasMore    bool
	}{
		{name: "nil terminal page"},
		{name: "empty terminal page", items: []apikey.Key{}},
		{name: "continuation", items: []apikey.Key{}, nextCursor: "opaque.cursor", hasMore: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := json.Marshal(newAPIKeyListResponse(apikey.APIKeyListPage{
				Items: test.items, NextCursor: test.nextCursor,
			}))
			if err != nil {
				t.Fatal(err)
			}
			var body map[string]any
			if err := json.Unmarshal(encoded, &body); err != nil {
				t.Fatal(err)
			}
			if len(body) != 3 || body["next_cursor"] != test.nextCursor || body["has_more"] != test.hasMore {
				t.Fatalf("response = %s", encoded)
			}
			if _, ok := body["items"].([]any); !ok {
				t.Fatalf("items missing from %s", encoded)
			}
			for _, forbidden := range []string{"snapshot_at", "secret", "matched_prefix", "matched_key_prefix"} {
				if _, ok := body[forbidden]; ok {
					t.Fatalf("response exposes %q: %s", forbidden, encoded)
				}
			}
		})
	}
}
