package sitegroup

import (
	"strings"
	"testing"
)

func TestNormalizeName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
		valid bool
	}{
		{name: "trim unicode whitespace", input: "\u3000默认分组\u00a0", want: "默认分组", valid: true},
		{name: "case sensitive exact", input: "Group", want: "Group", valid: true},
		{name: "empty", input: " \t\n", valid: false},
		{name: "invalid utf8", input: string([]byte{0xff, 'a'}), valid: false},
		{name: "control", input: "bad\u0085name", valid: false},
		{name: "too long", input: strings.Repeat("界", 129), valid: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := normalizeName(test.input)
			if test.valid && err != nil {
				t.Fatalf("normalizeName error = %v", err)
			}
			if !test.valid && err == nil {
				t.Fatalf("normalizeName(%q) = %q, want error", test.input, got)
			}
			if test.valid && got != test.want {
				t.Fatalf("normalizeName(%q) = %q, want %q", test.input, got, test.want)
			}
		})
	}
}

func TestWriteMetadataValidation(t *testing.T) {
	valid := WriteMetadata{IdempotencyKey: "site-group-key", RequestID: "request-1"}
	if !validWriteMetadata(valid) {
		t.Fatal("valid metadata rejected")
	}
	for _, metadata := range []WriteMetadata{
		{},
		{IdempotencyKey: strings.Repeat("k", 129), RequestID: "request-1"},
		{IdempotencyKey: "bad\nkey", RequestID: "request-1"},
		{IdempotencyKey: "key", RequestID: "bad request"},
	} {
		if validWriteMetadata(metadata) {
			t.Fatalf("invalid metadata accepted: %#v", metadata)
		}
	}
}
