package redact

import (
	"strings"
	"unicode/utf8"
)

// 攻击片段（ADR 0011 §4.4）：被强信号拦下的请求里触发规则的那一段，打码后上报。
const (
	// MaxFragmentBytes 是一条片段序列化后（Encoding 形式）的上限。
	MaxFragmentBytes = 256
	// EncodingText：片段是合法 UTF-8，除 \t \n \r 外无控制字符，原样上报。
	EncodingText = "text"
	// EncodingPercent：其它字节（控制字符、0x7f、非 UTF-8 / 非 ASCII）与 '%' 本身写成 %XX，
	// 其余原样；解码是精确逆运算。
	EncodingPercent = "percent"
	maxURLDecode    = 2
)

// RedactFragment 把规则匹配到的原始字节打码、选编码、截断到 MaxFragmentBytes。
// 节点 agent 上报前调用（Lua 只截取匹配段，不打码）；结果恒满足 CleanFragment。
//
// 先在原文上打码（保留 %2e%2e 这类编码层，样本更有用）；若 URL 解码后的视图里仍检出
// 个人信息（如 bob%40corp.example），改用解码视图打码，宁可丢掉编码层也不漏。
func RedactFragment(raw []byte) (fragment, encoding string, classes []Class) {
	seen := map[Class]bool{}
	add := func(cs []Class) {
		for _, c := range cs {
			seen[c] = true
		}
	}
	text, cs := Redact(string(raw))
	add(cs)
	if !Clean(decodedView(text)) {
		text, cs = Redact(decodedView(text))
		add(cs)
	}
	fragment, encoding = "", EncodingText
	for range maxPasses {
		candidate, enc := encode(text)
		if len(candidate) > MaxFragmentBytes {
			// 截断可能去掉了唯一需要转义的字节：重新选编码（text 不会比 percent 长）。
			candidate, enc = encode(percentBytes(truncate(candidate, enc), enc))
		}
		decoded, _ := decode(candidate, enc)
		if Clean(decoded) && Clean(decodedView(decoded)) {
			fragment, encoding = candidate, enc
			break
		}
		// 截断边界或解码视图上出现新的可检出串：在解码视图上再打一次码。始终不收敛则不报（空片段）。
		text, cs = Redact(decodedView(decoded))
		add(cs)
	}
	for c := range seen {
		classes = append(classes, c)
	}
	sortClasses(classes)
	return fragment, encoding, classes
}

// CleanFragment 是授权端（及主控）复核：编码合法、长度在界内、非空，且原文与 URL 解码视图
// 再跑一遍打码都不变。false = 未按本库打码（整份拒收）。
func CleanFragment(fragment, encoding string) bool {
	if fragment == "" || len(fragment) > MaxFragmentBytes {
		return false
	}
	decoded, ok := decode(fragment, encoding)
	return ok && Clean(decoded) && Clean(decodedView(decoded))
}

// DecodeFragment 返回片段的原始字节（复现请求用）。
func DecodeFragment(fragment, encoding string) (string, bool) { return decode(fragment, encoding) }

func textSafe(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if b := s[i]; (b < 0x20 && b != '\t' && b != '\n' && b != '\r') || b == 0x7f {
			return false
		}
	}
	return true
}

func encode(s string) (string, string) {
	if textSafe(s) {
		return s, EncodingText
	}
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < 0x20 || b >= 0x7f || b == '%' {
			out.WriteByte('%')
			out.WriteByte("0123456789ABCDEF"[b>>4])
			out.WriteByte("0123456789ABCDEF"[b&15])
			continue
		}
		out.WriteByte(b)
	}
	return out.String(), EncodingPercent
}

func decode(fragment, encoding string) (string, bool) {
	switch encoding {
	case EncodingText:
		return fragment, textSafe(fragment)
	case EncodingPercent:
		var out strings.Builder
		for i := 0; i < len(fragment); i++ {
			b := fragment[i]
			if b == '%' {
				if i+2 >= len(fragment) || !isHex(fragment[i+1]) || !isHex(fragment[i+2]) || isUpperHexLower(fragment[i+1:i+3]) {
					return "", false
				}
				out.WriteByte(unhex(fragment[i+1])<<4 | unhex(fragment[i+2]))
				i += 2
				continue
			}
			if b < 0x20 || b >= 0x7f {
				return "", false
			}
			out.WriteByte(b)
		}
		decoded := out.String()
		// 规范形式：能用 text 表示的不得用 percent，且只转义必须转义的字节（同一字节串只有一种写法）。
		if again, enc := encode(decoded); enc != EncodingPercent || again != fragment {
			return "", false
		}
		return decoded, true
	}
	return "", false
}

// percentBytes 是 encode 产物的逆运算（不做规范性检查）。
func percentBytes(fragment, encoding string) string {
	if encoding != EncodingPercent {
		return fragment
	}
	var out strings.Builder
	for i := 0; i < len(fragment); i++ {
		if fragment[i] == '%' && i+2 < len(fragment) {
			out.WriteByte(unhex(fragment[i+1])<<4 | unhex(fragment[i+2]))
			i += 2
			continue
		}
		out.WriteByte(fragment[i])
	}
	return out.String()
}

// isUpperHexLower：%XX 必须大写十六进制。
func isUpperHexLower(pair string) bool {
	return pair[0] >= 'a' && pair[0] <= 'f' || pair[1] >= 'a' && pair[1] <= 'f'
}

func unhex(b byte) byte {
	switch {
	case b >= '0' && b <= '9':
		return b - '0'
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10
	}
	return b - 'A' + 10
}

// decodedView 是至多两轮 URL 解码（%XX 与 '+' 不动；非法 %XX 原样保留）的视图，只用于检出。
func decodedView(s string) string {
	for range maxURLDecode {
		if !strings.Contains(s, "%") {
			break
		}
		var out strings.Builder
		for i := 0; i < len(s); i++ {
			if s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
				out.WriteByte(unhex(s[i+1])<<4 | unhex(s[i+2]))
				i += 2
				continue
			}
			out.WriteByte(s[i])
		}
		if out.String() == s {
			break
		}
		s = out.String()
	}
	return s
}

// truncate 截到 MaxFragmentBytes：不切开 %XX、UTF-8 字符或占位符 <…>。
func truncate(fragment, encoding string) string {
	cut := MaxFragmentBytes
	if encoding == EncodingPercent {
		for i := max(0, cut-2); i < cut; i++ {
			if fragment[i] == '%' {
				cut = i
				break
			}
		}
	} else {
		for cut > 0 && !utf8.RuneStart(fragment[cut]) {
			cut--
		}
	}
	head := fragment[:cut]
	if open := strings.LastIndexByte(head, '<'); open >= 0 && !strings.Contains(head[open:], ">") {
		rest := fragment[open:]
		for _, c := range allClasses {
			if strings.HasPrefix(rest, c.Placeholder()) {
				head = head[:open]
				break
			}
		}
	}
	return head
}

var allClasses = []Class{Email, Phone, IDCard, Card, IP, Token, JWT, UUID, Number, QueryValue, Credential}
