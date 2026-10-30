package siteobject

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// L4_TRAFFIC_STOP: the key document may name the scope's traffic stopped
// forwards (sorted unique UUIDs, at most MaxTrafficStopStreams); without
// them it encodes as before.
func TestKeyDocumentTrafficStopStreams(t *testing.T) {
	base := KeyDocument{Schema: KeySchema, ConfigurationScopeID: "11111111-1111-4111-8111-111111111111",
		ConfigVersionID: "22222222-2222-4222-8222-222222222222", RootSHA256: strings.Repeat("a", 64), KeyEpoch: 1,
		ContentKey: bytes.Repeat([]byte{7}, ContentKeySize)}
	plain, err := Encode(base)
	if err != nil || bytes.Contains(plain, []byte("traffic_stop")) {
		t.Fatalf("without streams: %s %v", plain, err)
	}
	if parsed, err := ParseKeyDocument(plain); err != nil || parsed.TrafficStopStreams != nil {
		t.Fatalf("parse without streams: %+v %v", parsed, err)
	}
	withStreams := base
	withStreams.TrafficStopStreams = []string{"33333333-3333-4333-8333-333333333331", "33333333-3333-4333-8333-333333333332"}
	encoded, err := Encode(withStreams)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseKeyDocument(encoded)
	if err != nil || len(parsed.TrafficStopStreams) != 2 || parsed.TrafficStopStreams[1] != withStreams.TrafficStopStreams[1] {
		t.Fatalf("parse with streams: %+v %v", parsed, err)
	}
	many := base
	for index := 0; index < MaxTrafficStopStreams; index++ {
		many.TrafficStopStreams = append(many.TrafficStopStreams, fmt.Sprintf("44444444-4444-4444-8444-%012d", index))
	}
	if encoded, err := Encode(many); err != nil {
		t.Fatal(err)
	} else if _, err := ParseKeyDocument(encoded); err != nil {
		t.Fatalf("at the limit: %v", err)
	}
	for name, streams := range map[string][]string{
		"empty":     {},
		"unsorted":  {"33333333-3333-4333-8333-333333333332", "33333333-3333-4333-8333-333333333331"},
		"duplicate": {"33333333-3333-4333-8333-333333333331", "33333333-3333-4333-8333-333333333331"},
		"not uuid":  {"stream"},
		"too many":  append(append([]string{}, many.TrafficStopStreams...), "ffffffff-ffff-4fff-8fff-ffffffffffff"),
	} {
		bad := base
		bad.TrafficStopStreams = streams
		encoded, err := Encode(bad)
		if err != nil {
			t.Fatal(err)
		}
		if name == "empty" {
			// omitempty drops it: encoded as without streams, still valid
			if _, err := ParseKeyDocument(encoded); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if _, err := ParseKeyDocument(bytes.Replace(plain, []byte(`}`), []byte(`,"traffic_stop_streams":[]}`), 1)); err == nil {
				t.Fatal("explicit empty list accepted")
			}
			continue
		}
		if _, err := ParseKeyDocument(encoded); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}
