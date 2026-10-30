package redact

import (
	"strings"
	"testing"
)

// fuzzSeeds 是种子个人信息：嵌在任意上下文里（两侧以空白隔开）都必须被打掉。
var fuzzSeeds = []string{
	"admin@example.com", "13800138000", "+1 (415) 555-2671", "11010519491231002X", "4111111111111111",
	"4111 1111 1111 1111", "203.0.113.7", "2001:db8:85a3::8a2e:370:7334",
	"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk",
	"3f2504e0-4f89-11d3-9a0c-0305e82c3301", "tkn_9fQ2xLp7Wm4ZbR8vKc3NdTy6", "20261020123456",
}

// FuzzRedact：任意输入不 panic、结果是不动点（Clean）；种子个人信息不会残留。
func FuzzRedact(f *testing.F) {
	for i, attack := range []string{"' OR 1=1--", "{{7*7}}", "../../etc/passwd", "<script>", "", "\x00\xff", "http://a/?q="} {
		f.Add(attack, attack, uint8(i))
	}
	f.Fuzz(func(t *testing.T, prefix, suffix string, which uint8) {
		seed := fuzzSeeds[int(which)%len(fuzzSeeds)]
		for _, in := range []string{prefix + suffix, prefix + " " + seed + " " + suffix} {
			out, _ := Redact(in)
			if !Clean(out) {
				t.Fatalf("not a fixed point: %q -> %q", in, out)
			}
		}
		out, _ := Redact(prefix + " " + seed + " " + suffix)
		if strings.Contains(out, seed) {
			t.Fatalf("seed %q survived: %q", seed, out)
		}
	})
}

// FuzzRedactFragment：任意字节不 panic；非空结果都过复核、在长度界内；种子个人信息不残留
// （原文与 URL 解码视图都查）。
func FuzzRedactFragment(f *testing.F) {
	for _, attack := range []string{"' OR 1=1--", "%2e%2e%2f", "\x00\xff", "bob%40corp.example", strings.Repeat("{{7*7}}", 50)} {
		f.Add([]byte(attack), uint8(0))
	}
	f.Fuzz(func(t *testing.T, raw []byte, which uint8) {
		seed := fuzzSeeds[int(which)%len(fuzzSeeds)]
		for _, in := range [][]byte{raw, append(append([]byte(" "+seed+" "), raw...), ' ')} {
			fragment, encoding, _ := RedactFragment(in)
			if fragment == "" {
				continue
			}
			if !CleanFragment(fragment, encoding) {
				t.Fatalf("RedactFragment(%q) = %q %s not clean", in, fragment, encoding)
			}
			decoded, _ := DecodeFragment(fragment, encoding)
			if strings.Contains(decoded, seed) || strings.Contains(decodedView(decoded), seed) {
				t.Fatalf("seed %q survived in %q", seed, fragment)
			}
		}
	})
}
