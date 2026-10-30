package analyticslog

import (
	"regexp"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
)

// CRS rule names (retest-n4): a managed WAF block event carries the first
// OWASP CRS detection rule that matched (node cdnca_managed_waf.lua), a
// six digit 9xxxxx ID no policy names. Its row shows "OWASP CRS #<id>",
// with the rule's msg from the CRS text the control binary embeds (the
// signed catalog's, rulecatalog.CRSRulesBundle) when the rule has one.

var crsEventRuleID = regexp.MustCompile(`^9[0-9]{5}$`)

var (
	crsMessagesOnce sync.Once
	crsMessages     map[string]string
)

// crsRuleDirective: one SecRule/SecAction with its id and msg actions (CRS
// writes id first, msg later in the same quoted action list; a chained
// rule's links carry neither).
var (
	crsDirective = regexp.MustCompile(`(?m)^[ \t]*(?:SecRule|SecAction)\b`)
	crsIDAction  = regexp.MustCompile(`\bid:(\d+)`)
	crsMsgAction = regexp.MustCompile(`\bmsg:'((?:[^'\\]|\\.)*)'`)
)

// parseCRSMessages maps rule ID to msg over CRS rule files.
func parseCRSMessages(files map[string][]byte) map[string]string {
	messages := map[string]string{}
	for name, content := range files {
		if !strings.HasSuffix(name, ".conf") {
			continue
		}
		text := strings.ReplaceAll(string(content), "\\\r\n", " ")
		text = strings.ReplaceAll(text, "\\\n", " ")
		starts := crsDirective.FindAllStringIndex(text, -1)
		for index, start := range starts {
			end := len(text)
			if index+1 < len(starts) {
				end = starts[index+1][0]
			}
			directive := text[start[0]:end]
			id := crsIDAction.FindStringSubmatch(directive)
			msg := crsMsgAction.FindStringSubmatch(directive)
			if id != nil && msg != nil && messages[id[1]] == "" {
				messages[id[1]] = strings.Join(strings.Fields(msg[1]), " ")
			}
		}
	}
	return messages
}

// crsMessage is the embedded CRS text's msg of a rule ("" when none or the
// bundle cannot be read).
func crsMessage(id string) string {
	crsMessagesOnce.Do(func() {
		files, err := rulecatalog.DecodeWAFEngineBundle(*rulecatalog.CRSRulesBundle())
		if err == nil {
			crsMessages = parseCRSMessages(files)
		}
	})
	return crsMessages[id]
}

// crsRuleName is a CRS rule ID's display name, "" for other IDs; at most
// 128 bytes (the page's rule_name bound), cut on a rune boundary.
func crsRuleName(ruleID string) string {
	if !crsEventRuleID.MatchString(ruleID) {
		return ""
	}
	name := "OWASP CRS #" + ruleID
	if msg := crsMessage(ruleID); msg != "" {
		name += " · " + msg
	}
	for len(name) > 128 {
		_, size := utf8.DecodeLastRuneInString(name)
		name = name[:len(name)-size]
	}
	return name
}
