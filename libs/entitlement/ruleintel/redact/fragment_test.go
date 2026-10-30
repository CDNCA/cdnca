package redact

import (
	"strings"
	"testing"
)

func TestRedactFragment(t *testing.T) {
	cases := []struct{ name, raw, fragment, encoding string }{
		{"sqli", "' OR 1=1--", "' OR 1=1--", EncodingText},
		{"traversal keeps encoding layer", "%2e%2e%2f%2e%2e%2fetc%2fpasswd", "%2e%2e%2f%2e%2e%2fetc%2fpasswd", EncodingText},
		{"encoded email is decoded then redacted", "' OR u='bob%40corp.example'", "' OR u='<email>'", EncodingText},
		{"double encoded ip", "x=203%252E0%252E113%252E7", "x=<ip>", EncodingText},
		{"null byte", "../../etc/passwd\x00.png", "../../etc/passwd%00.png", EncodingPercent},
		{"invalid utf8 and percent", "\xff%' OR 1", "%FF%25' OR 1", EncodingPercent},
		{"ssti with phone", "{{7*7}}13800138000", "{{7*7}}<phone>", EncodingText},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fragment, encoding, _ := RedactFragment([]byte(tc.raw))
			if fragment != tc.fragment || encoding != tc.encoding {
				t.Fatalf("RedactFragment(%q) = %q %s, want %q %s", tc.raw, fragment, encoding, tc.fragment, tc.encoding)
			}
			if !CleanFragment(fragment, encoding) {
				t.Fatal("result not clean")
			}
		})
	}
}

func TestRedactFragmentTruncates(t *testing.T) {
	raw := strings.Repeat("' OR 1=1 ", 20) + "admin@example.com" + strings.Repeat("x", 300)
	fragment, encoding, _ := RedactFragment([]byte(raw))
	if len(fragment) > MaxFragmentBytes || !CleanFragment(fragment, encoding) {
		t.Fatalf("%d bytes, clean %v", len(fragment), CleanFragment(fragment, encoding))
	}
	// 占位符不被切开
	raw = strings.Repeat("a", MaxFragmentBytes-3) + " 203.0.113.7"
	fragment, _, _ = RedactFragment([]byte(raw))
	if strings.HasSuffix(fragment, "<") || strings.HasSuffix(fragment, "<i") || strings.HasSuffix(fragment, "<ip") {
		t.Fatalf("placeholder cut: %q", fragment[len(fragment)-8:])
	}
	// percent 编码不切开 %XX
	fragment, encoding, _ = RedactFragment([]byte(strings.Repeat("\x01", 200)))
	if encoding != EncodingPercent || len(fragment)%3 != 0 || !CleanFragment(fragment, encoding) {
		t.Fatalf("percent truncation: %d %s", len(fragment), encoding)
	}
}

func TestCleanFragmentRejects(t *testing.T) {
	for _, tc := range []struct{ fragment, encoding string }{
		{"", EncodingText},
		{strings.Repeat("a", MaxFragmentBytes+1), EncodingText},
		{"bob@corp.example", EncodingText},
		{"bob%40corp.example", EncodingText},   // 解码视图里是邮箱
		{"bob%2540corp.example", EncodingText}, // 两轮解码
		{"' OR 1=1", "base64"},
		{"a\x00b", EncodingText},
		{"%2E", EncodingPercent},    // 能用 text 表示却用 percent
		{"%ff", EncodingPercent},    // 小写十六进制
		{"%4", EncodingPercent},     // 截断的 %XX
		{"%41%00", EncodingPercent}, // 'A' 不需要转义
		{"13800138000%00", EncodingPercent},
	} {
		if CleanFragment(tc.fragment, tc.encoding) {
			t.Errorf("CleanFragment(%q, %q) = true", tc.fragment, tc.encoding)
		}
	}
	if !CleanFragment("%00' OR 1", EncodingPercent) || !CleanFragment("<email>' OR 1=1", EncodingText) {
		t.Error("clean fragments refused")
	}
}
