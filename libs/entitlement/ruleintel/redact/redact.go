// Package redact 是攻击片段打码库（ADR 0011 §4.4，ri-frag）：节点 agent、主控汇总、授权端复核
// 共用同一套规则。个人信息与凭据替换为类型占位符（<email>、<phone>、<ip>…），攻击结构
// （引号、运算符、模板括号、路径穿越等）原样保留。
//
// 打码结果是不动点：Clean(Redact(s)) 恒为真。授权端据此复核——片段再跑一遍仍有改动，
// 说明上游没有按本库打码，整份拒收。
//
// 偏向多打：边界不确定时宁可把相邻字符一起替换，也不留下可识别的个人信息。
package redact

import (
	"math"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

// Class 是检出的个人信息类型；占位符为 "<" + Class + ">"。
type Class string

const (
	Email  Class = "email"
	Phone  Class = "phone"
	IDCard Class = "idcard"
	Card   Class = "card"
	IP     Class = "ip"
	Token  Class = "token"
	JWT    Class = "jwt"
	UUID   Class = "uuid"
	Number Class = "num"
	// QueryValue 是 URL 中 query 参数的值（host 保留）。
	QueryValue Class = "val"
	// Credential 是 URL 中 userinfo（user:pass@）。
	Credential Class = "cred"
)

// Placeholder 返回类型占位符。
func (c Class) Placeholder() string { return "<" + string(c) + ">" }

const (
	// LongDigits 是“长数字串”的下限：连续 ≥ 8 位数字一律替换。
	LongDigits = 8
	// TokenMinLen 是长令牌下限（[A-Za-z0-9+/_=-] 连续 ≥ 20 位且高熵）。
	TokenMinLen = 20
	// maxPasses 是求不动点的最多轮数（实际一轮即收敛，留余量）。
	maxPasses = 4
)

var (
	urlPattern   = regexp.MustCompile(`(?i)[a-z][a-z0-9+.-]{0,15}://[^\s'"<>()\[\]{}\\]*`)
	jwtPattern   = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*`)
	emailPattern = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}`)
	uuidPattern  = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	idPattern    = regexp.MustCompile(`[0-9]{17}[0-9Xx]`)
	// 国际格式电话：+国家码，可带括号区号与空格/横线/点分组。
	intlPhone = regexp.MustCompile(`\+[0-9]{1,3}[ .-]?(?:\([0-9]{1,4}\)[ .-]?)?[0-9]{2,}(?:[ .-][0-9]{2,})*`)
	// 分组数字（卡号 4111 1111 …、手机号 138 0013 8000）：每组 ≥ 3 位，避免误伤 "1 OR 1 2 3"。
	groupedDigits = regexp.MustCompile(`[0-9]{3,}(?:[ -][0-9]{3,})+`)
	longDigits    = regexp.MustCompile(`[0-9]{8,}`)
	tokenRun      = regexp.MustCompile(`[A-Za-z0-9+/_=-]{20,}`)
	cnMobile      = regexp.MustCompile(`^1[3-9][0-9]{9}$`)
)

// Redact 打码 s，返回结果与检出的类型（去重、升序）。
func Redact(s string) (string, []Class) {
	found := map[Class]bool{}
	for range maxPasses {
		next := pass(s, found)
		if next == s {
			break
		}
		s = next
	}
	classes := make([]Class, 0, len(found))
	for c := range found {
		classes = append(classes, c)
	}
	sortClasses(classes)
	return s, classes
}

func sortClasses(classes []Class) {
	sort.Slice(classes, func(i, j int) bool { return classes[i] < classes[j] })
}

// Clean 报告 s 是否已打码（再跑一遍不变）。
func Clean(s string) bool {
	return pass(s, map[Class]bool{}) == s
}

func pass(s string, found map[Class]bool) string {
	s = urlPattern.ReplaceAllStringFunc(s, func(u string) string { return redactURL(u, found) })
	s = replace(s, jwtPattern, JWT, found)
	s = replace(s, emailPattern, Email, found)
	s = replace(s, uuidPattern, UUID, found)
	s = scanIPv6(s, found)
	s = scanIPv4(s, found)
	s = intlPhone.ReplaceAllStringFunc(s, func(m string) string { return redactIntlPhone(m, found) })
	s = groupedDigits.ReplaceAllStringFunc(s, func(m string) string { return redactGrouped(m, found) })
	s = idPattern.ReplaceAllStringFunc(s, func(m string) string {
		if idChecksum(m) {
			found[IDCard] = true
			return IDCard.Placeholder()
		}
		return m
	})
	s = longDigits.ReplaceAllStringFunc(s, func(m string) string {
		switch {
		case len(m) >= 13 && len(m) <= 19 && luhn(m):
			found[Card] = true
			return Card.Placeholder()
		case cnMobile.MatchString(m):
			found[Phone] = true
			return Phone.Placeholder()
		}
		found[Number] = true
		return Number.Placeholder()
	})
	s = tokenRun.ReplaceAllStringFunc(s, func(m string) string { return redactTokenRun(m, found) })
	return s
}

func replace(s string, re *regexp.Regexp, c Class, found map[Class]bool) string {
	return re.ReplaceAllStringFunc(s, func(string) string {
		found[c] = true
		return c.Placeholder()
	})
}

// redactURL：scheme 与 host 保留，userinfo → <cred>，query 每个值 → <val>（参数名保留）。
// 路径与 fragment 交给后续规则（其中的邮箱、令牌、长数字照常替换）。
func redactURL(u string, found map[Class]bool) string {
	schemeEnd := strings.Index(u, "://") + 3
	rest := u[schemeEnd:]
	authorityEnd := strings.IndexAny(rest, "/?#")
	if authorityEnd < 0 {
		authorityEnd = len(rest)
	}
	authority := rest[:authorityEnd]
	if at := strings.LastIndex(authority, "@"); at >= 0 {
		found[Credential] = true
		authority = Credential.Placeholder() + "@" + authority[at+1:]
	}
	tail := rest[authorityEnd:]
	if q := strings.IndexByte(tail, '?'); q >= 0 {
		query, fragment := tail[q+1:], ""
		if h := strings.IndexByte(query, '#'); h >= 0 {
			query, fragment = query[:h], query[h:]
		}
		pairs := strings.Split(query, "&")
		for i, pair := range pairs {
			if eq := strings.IndexByte(pair, '='); eq >= 0 && eq < len(pair)-1 && pair[eq+1:] != QueryValue.Placeholder() {
				found[QueryValue] = true
				pairs[i] = pair[:eq+1] + QueryValue.Placeholder()
			}
		}
		tail = tail[:q+1] + strings.Join(pairs, "&") + fragment
	}
	return u[:schemeEnd] + authority + tail
}

func isHex(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'f' || b >= 'A' && b <= 'F'
}

// scanIPv6：在每个位置尝试最长的合法 IPv6（含内嵌 IPv4），十六进制位 ≥ 6 才算
// （"a::b"、"::1"、"fe80::1" 这类短地址不是个人信息，也常见于代码片段）。
func scanIPv6(s string, found map[Class]bool) string {
	if strings.Count(s, ":") < 2 {
		return s
	}
	var out strings.Builder
	for i := 0; i < len(s); {
		if isHex(s[i]) || s[i] == ':' {
			if end := longestIPv6(s, i); end > 0 {
				found[IP] = true
				out.WriteString(IP.Placeholder())
				i = end
				continue
			}
		}
		out.WriteByte(s[i])
		i++
	}
	return out.String()
}

func longestIPv6(s string, start int) int {
	limit := start
	for limit < len(s) && limit-start < 45 && (isHex(s[limit]) || s[limit] == ':' || s[limit] == '.') {
		limit++
	}
	for end := limit; end >= start+3; end-- {
		if candidate := s[start:end]; strings.Count(candidate, ":") >= 2 && validIPv6(candidate) {
			return end
		}
	}
	return 0
}

func validIPv6(s string) bool {
	hexDigits := 0
	for i := 0; i < len(s); i++ {
		if isHex(s[i]) {
			hexDigits++
		}
	}
	if hexDigits < 6 {
		return false
	}
	addr, err := netip.ParseAddr(s)
	return err == nil && addr.Is6() && addr.Zone() == ""
}

// scanIPv4：在每个数字位置尝试点分四段（每段 1–3 位、≤ 255），末段取最长合法长度。
// 左边界不能是数字或点（"999.1.1.1" 不是地址）；右边取最长合法长度（宁多勿漏）。
func scanIPv4(s string, found map[Class]bool) string {
	if strings.Count(s, ".") < 3 {
		return s
	}
	var out strings.Builder
	for i := 0; i < len(s); {
		if s[i] >= '0' && s[i] <= '9' && (i == 0 || !(s[i-1] >= '0' && s[i-1] <= '9' || s[i-1] == '.')) {
			if end := ipv4At(s, i); end > 0 {
				found[IP] = true
				out.WriteString(IP.Placeholder())
				i = end
				continue
			}
		}
		out.WriteByte(s[i])
		i++
	}
	return out.String()
}

func ipv4At(s string, start int) int {
	for end := min(len(s), start+15); end >= start+7; end-- {
		if validIPv4(s[start:end]) {
			return end
		}
	}
	return 0
}

func validIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > 3 {
			return false
		}
		value := 0
		for j := 0; j < len(part); j++ {
			if part[j] < '0' || part[j] > '9' {
				return false
			}
			value = value*10 + int(part[j]-'0')
		}
		if value > 255 {
			return false
		}
	}
	return true
}

// redactGrouped：空格/横线分组的数字。任意连续若干组凑成 13–19 位且过 Luhn → <card>；
// 凑成 11 位大陆手机号 → <phone>；身份证 18 位（含校验）→ <idcard>。其余不动
// （每组 < 8 位的普通数字列表不是个人信息；≥ 8 位的组由长数字规则处理）。
func redactGrouped(m string, found map[Class]bool) string {
	groups := strings.FieldsFunc(m, func(r rune) bool { return r == ' ' || r == '-' })
	for i := range groups {
		digits := ""
		for j := i; j < len(groups); j++ {
			digits += groups[j]
			if len(digits) > 19 {
				break
			}
			class := Class("")
			switch {
			case len(digits) >= 13 && len(digits) <= 19 && luhn(digits):
				class = Card
			case cnMobile.MatchString(digits):
				class = Phone
			case len(digits) == 18 && idChecksum(digits):
				class = IDCard
			}
			if class != "" && j > i {
				found[class] = true
				return class.Placeholder()
			}
		}
	}
	return m
}

// redactIntlPhone：E.164 至多 15 位。匹配过长（后面紧跟别的数字组）时逐个去掉尾部分组，
// 找到 8–15 位的前缀就替换前缀、保留其余（其余再由长数字规则处理）。
func redactIntlPhone(m string, found map[Class]bool) string {
	for end := len(m); end > 0; {
		if n := countDigits(m[:end]); n >= 8 && n <= 15 {
			found[Phone] = true
			return Phone.Placeholder() + m[end:]
		}
		cut := strings.LastIndexAny(m[:end], " .-")
		if cut <= 0 {
			break
		}
		end = cut
	}
	return m
}

func countDigits(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			n++
		}
	}
	return n
}

func luhn(digits string) bool {
	sum := 0
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if (len(digits)-1-i)%2 == 1 {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return sum%10 == 0
}

// idChecksum 是 GB 11643 公民身份号码校验位。
func idChecksum(id string) bool {
	weights := [17]int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}
	sum := 0
	for i := range 17 {
		sum += int(id[i]-'0') * weights[i]
	}
	check := "10X98765432"[sum%11]
	last := id[17]
	if last == 'x' {
		last = 'X'
	}
	return last == check
}

// redactTokenRun：整段看一次，再按 _ - + / = 拆开的长段各看一次；判为令牌的部分替换为 <token>。
func redactTokenRun(run string, found map[Class]bool) string {
	if highEntropyToken(run) {
		found[Token] = true
		return Token.Placeholder()
	}
	segments := strings.FieldsFunc(run, func(r rune) bool { return strings.ContainsRune("_-+/=", r) })
	for _, segment := range segments {
		if len(segment) >= 16 && highEntropyToken(segment) {
			found[Token] = true
			run = strings.ReplaceAll(run, segment, Token.Placeholder())
		}
	}
	return run
}

// highEntropyToken：字母 ≥ 2、数字 ≥ 2、香农熵 ≥ 3.0 bit/字符，且大小写/数字类别交替次数
// ≥ max(4, 字母数字个数/6)。随机令牌（base64、hex、API key）交替频繁；SQL/路径等
// 由单词拼成的攻击串（UNION_SELECT_1_2_3、/var/www/html/index_2023）交替很少，不会被打掉。
func highEntropyToken(s string) bool {
	letters, digits, transitions, alnum := 0, 0, 0, 0
	previous := byte(0)
	counts := map[byte]int{}
	for i := 0; i < len(s); i++ {
		b := s[i]
		counts[b]++
		class := byte(0)
		switch {
		case b >= '0' && b <= '9':
			digits++
			class = 'd'
		case b >= 'a' && b <= 'z':
			letters++
			class = 'l'
		case b >= 'A' && b <= 'Z':
			letters++
			class = 'u'
		default:
			continue
		}
		alnum++
		if previous != 0 && class != previous {
			transitions++
		}
		previous = class
	}
	if letters < 2 || digits < 2 || transitions < max(4, alnum/6) {
		return false
	}
	entropy := 0.0
	for _, n := range counts {
		p := float64(n) / float64(len(s))
		entropy -= p * math.Log2(p)
	}
	return entropy >= 3.0
}
