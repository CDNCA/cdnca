package apikey

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestIPAllowlistStrictCanonicalContract(t *testing.T) {
	input := []string{"2001:db8::/48", "192.0.2.0/24", "10.0.0.0/8", "2001:db8:1::/48"}
	want := append([]string(nil), input...)
	sort.Strings(want)
	got, err := normalizeIPAllowlist(input)
	if err != nil {
		t.Fatalf("normalizeIPAllowlist(valid) error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalized allowlist = %v, want %v", got, want)
	}
	if empty, err := normalizeIPAllowlist(nil); err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("empty allowlist = %#v, %v; want non-nil unrestricted list", empty, err)
	}

	tooMany := make([]string, 33)
	for index := range tooMany {
		tooMany[index] = fmt.Sprintf("198.51.100.%d/32", index)
	}
	invalid := [][]string{
		{"192.0.2.1/24"},
		{" 192.0.2.0/24"},
		{"2001:DB8::/32"},
		{"fe80::%en0/64"},
		{"::ffff:192.0.2.0/120"},
		{"192.0.2.0/24", "192.0.2.0/24"},
		{"192.0.2.0/24", "192.0.2.128/25"},
		tooMany,
	}
	for _, values := range invalid {
		if _, err := normalizeIPAllowlist(values); err == nil {
			t.Fatalf("normalizeIPAllowlist(%v) unexpectedly succeeded", values)
		}
	}
}

func TestIPAllowlistDigestReplayAndMigrationContract(t *testing.T) {
	allowlist := []string{"10.0.0.0/8", "2001:db8::/32"}
	key := Key{
		ID:          uuid.MustParse("019c7a66-4dd8-7a45-a9d1-923e9545a7f0"),
		IPAllowlist: allowlist,
	}
	encoded, err := json.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(bytes.ToLower(encoded), []byte("secret")) {
		t.Fatalf("idempotent response exposed secret field: %s", encoded)
	}
	var replay Key
	if err := json.Unmarshal(encoded, &replay); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(replay.IPAllowlist, allowlist) {
		t.Fatalf("replayed allowlist = %v, want %v", replay.IPAllowlist, allowlist)
	}

	service := NewService(nil, bytes.Repeat([]byte{0x42}, 32), time.Now)
	type requestFacts struct {
		Revision    int64    `json:"revision"`
		IPAllowlist []string `json:"ip_allowlist"`
	}
	withList := service.requestDigest("self.rotate", requestFacts{Revision: 3, IPAllowlist: allowlist})
	withoutList := service.requestDigest("self.rotate", requestFacts{Revision: 3, IPAllowlist: []string{}})
	_, withDigest, withOK := withList.active()
	_, withoutDigest, withoutOK := withoutList.active()
	if !withOK || !withoutOK || bytes.Equal(withDigest[:], withoutDigest[:]) {
		t.Fatal("request digest did not bind the exact IP allowlist")
	}

	for name, required := range map[string][]string{
		"117_api_key_ip_allowlist.up.sql": {
			"ADD COLUMN ip_allowlist text[]", "CREATE FUNCTION api_key_ip_allowlist_is_valid(allowlist_values text[])",
			"cardinality(allowlist_values)", "FOREACH item IN ARRAY allowlist_values LOOP",
			"NEW.ip_allowlist IS DISTINCT FROM OLD.ip_allowlist",
		},
		"117_api_key_ip_allowlist.down.sql": {
			"DROP COLUMN ip_allowlist", "DROP FUNCTION api_key_ip_allowlist_is_valid",
		},
	} {
		content, err := os.ReadFile(filepath.Join("..", "..", "migrations", name))
		if err != nil {
			t.Fatalf("read migration %s: %v", name, err)
		}
		for _, snippet := range required {
			if !strings.Contains(string(content), snippet) {
				t.Errorf("migration %s missing %q", name, snippet)
			}
		}
	}
}
