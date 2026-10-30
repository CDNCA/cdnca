package redact

import (
	"reflect"
	"strings"
	"testing"
)

func TestRedactPersonalData(t *testing.T) {
	cases := []struct {
		name, in, want string
		classes        []Class
	}{
		{"email", "x=admin@example.com' OR 1=1", "x=<email>' OR 1=1", []Class{Email}},
		{"cn mobile", "tel=13800138000", "tel=<phone>", []Class{Phone}},
		{"cn mobile grouped", "138 0013 8000", "<phone>", []Class{Phone}},
		{"intl phone", "call +1 (415) 555-2671 now", "call <phone> now", []Class{Phone}},
		{"intl phone compact", "+8613800138000", "<phone>", []Class{Phone}},
		{"idcard", "id=11010519491231002X;--", "id=<idcard>;--", []Class{IDCard}},
		{"bank card", "4111111111111111' UNION SELECT", "<card>' UNION SELECT", []Class{Card}},
		{"bank card spaced", "pan=4111 1111 1111 1111", "pan=<card>", []Class{Card}},
		{"bank card dashed", "5500-0000-0000-0004", "<card>", []Class{Card}},
		{"ipv4", "x' AND host='203.0.113.7'--", "x' AND host='<ip>'--", []Class{IP}},
		{"ipv6", "from 2001:db8:85a3::8a2e:370:7334 end", "from <ip> end", []Class{IP}},
		{"ipv6 mapped", "::ffff:192.0.2.1", "<ip>", []Class{IP}},
		{"jwt", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			"Bearer <jwt>", []Class{JWT}},
		{"uuid", "sid=3f2504e0-4f89-11d3-9a0c-0305e82c3301", "sid=<uuid>", []Class{UUID}},
		// 令牌字符集含 "="，紧贴的参数名一起替换（宁多勿漏）。
		{"api key", "key=tkn_9fQ2xLp7Wm4ZbR8vKc3NdTy6", "<token>", []Class{Token}},
		{"api key quoted", "'tkn_9fQ2xLp7Wm4ZbR8vKc3NdTy6' OR 1=1", "'<token>' OR 1=1", []Class{Token}},
		{"base64 secret", "Zm9vYmFyMTIzNDU2Nzg5MGFiY2RlZg==", "<token>", []Class{Token}},
		{"url query values", "http://evil.example/cb?user=bob&id=7#x", "http://evil.example/cb?user=<val>&id=<val>#x", []Class{QueryValue}},
		{"url userinfo", "gopher://root:hunter2@127.0.0.1:6379/_", "gopher://<cred>@<ip>:6379/_", []Class{Credential, IP}},
		{"long number", "order=20261020123456", "order=<num>", []Class{Number}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, classes := Redact(tc.in)
			if got != tc.want {
				t.Fatalf("Redact(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if !reflect.DeepEqual(classes, tc.classes) {
				t.Fatalf("classes = %v, want %v", classes, tc.classes)
			}
			if !Clean(got) || Clean(tc.in) {
				t.Fatalf("Clean: redacted %v, original %v", Clean(got), Clean(tc.in))
			}
		})
	}
}

// 攻击片段不含个人信息时原样保留（结构不被打坏）。
func TestRedactKeepsAttackStructure(t *testing.T) {
	for _, in := range []string{
		"' OR 1=1--", "' OR '1'='1", "1 UNION SELECT 1,2,3,4,5--", "admin'/**/AND/**/SLEEP(5)#",
		"{{7*7}}", "${7*7}", "<%= 7*7 %>", "${jndi:ldap://x/a}",
		"../../etc/passwd", "....//....//etc/shadow", "%2e%2e%2f%2e%2e%2fetc%2fpasswd", "/proc/self/environ",
		"<script>alert(document.cookie)</script>", "<img src=x onerror=alert(1)>", "javascript:alert(1)",
		"; cat /etc/passwd | nc", "$(id)", "`uname -a`", "O:8:\"stdClass\":0:{}",
		"UNION_SELECT_NULL_NULL_NULL", "/var/www/html/index_2023.php", "a::b", "::1", "fe80::1",
		"CHAR(0x41,0x42)", "1 AND 1=CONVERT(int,@@version)", "SELECT * FROM users WHERE id IN (1, 2, 3)",
	} {
		if got, classes := Redact(in); got != in || len(classes) != 0 {
			t.Errorf("Redact(%q) = %q %v, attack structure must stay", in, got, classes)
		}
	}
}

// 攻击片段里夹带个人信息：只替换个人信息，攻击结构仍在。
func TestRedactMixedKeepsStructure(t *testing.T) {
	cases := map[string]string{
		"' OR email='bob@corp.example' --":                    "' OR email='<email>' --",
		"{{config.items()}}&u=13900001111":                    "{{config.items()}}&u=<phone>",
		"../../etc/passwd?ip=198.51.100.23":                   "../../etc/passwd?ip=<ip>",
		"http://169.254.169.254/latest/meta-data/?token=abcd": "http://<ip>/latest/meta-data/?token=<val>",
		"1' AND card='4012888888881881' AND '1'='1":           "1' AND card='<card>' AND '1'='1",
	}
	for in, want := range cases {
		if got, _ := Redact(in); got != want {
			t.Errorf("Redact(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRedactNotFooledByNearMisses(t *testing.T) {
	// 不过 Luhn 的 16 位数字仍按长数字串替换；校验位错的身份证同理。
	for in, want := range map[string]string{
		"4111111111111112":   "<num>",
		"110105194912310021": "<num>",
		"999.1.1.1":          "999.1.1.1",
		"v1.2.3.4":           "v<ip>",
		"1.2.3":              "1.2.3",
		"1234567":            "1234567",
	} {
		if got, _ := Redact(in); got != want {
			t.Errorf("Redact(%q) = %q, want %q", in, got, want)
		}
	}
}

// Java 序列化等 base64 载荷与随机令牌不可区分，按令牌打掉（攻击类别仍由规则号与 attack_class 表达）。
func TestRedactBase64PayloadIsToken(t *testing.T) {
	if got, _ := Redact("rO0ABXNyABFqYXZhLnV0aWw"); got != "<token>" {
		t.Fatalf("got %q", got)
	}
}

func TestRedactIsFixedPoint(t *testing.T) {
	in := strings.Repeat("a@b.co 10.0.0.1 ", 20) + "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.x1y2z3w4"
	once, _ := Redact(in)
	twice, classes := Redact(once)
	if once != twice || len(classes) != 0 {
		t.Fatalf("not a fixed point: %q -> %q %v", once, twice, classes)
	}
}
