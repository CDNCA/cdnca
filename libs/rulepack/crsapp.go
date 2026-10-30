package rulepack

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// CRS application exclusion packs: the
// OWASP CRS official rule exclusion plugins (WordPress, Drupal, Nextcloud…,
// coreruleset/plugin-registry) as system/app-<key> packs of engine crs_app.
// A site selects them as its "应用类型"; they are never part of a CRS
// profile. Each pack carries the plugin's own ModSecurity text verbatim
// (stage "config" and "before"; "after" files are configuration-time
// SecRuleUpdateTargetById and would apply node-wide, so they are refused),
// restricted to exclusions: the node loads the text node-wide behind a
// per-site gate (edgeconfig renderManagedWAFMain), so the text may only
// narrow CRS for the requests of sites that selected it.

// EngineCRSApp is the engine of application exclusion packs.
const EngineCRSApp Engine = "crs_app"

// CRSAppRules is the body of one crs_app pack rule: one plugin file.
// FirstID..LastID is the plugin's registered rule ID range; every rule of
// the text has its ID there.
type CRSAppRules struct {
	Stage   string `json:"stage"`
	FirstID int    `json:"first_id"`
	LastID  int    `json:"last_id"`
	Text    string `json:"text"`
}

const (
	CRSAppStageConfig = "config"
	CRSAppStageBefore = "before"
	maxCRSAppText     = 512 << 10
)

var (
	crsAppPackID   = regexp.MustCompile(`^system/app-([a-z0-9][a-z0-9-]{0,47})$`)
	crsAppMarker   = regexp.MustCompile(`^[A-Z0-9][A-Z0-9_-]{0,127}$`)
	crsAppTXVar    = regexp.MustCompile(`^tx\.([a-z0-9_-]{1,128})$`)
	crsAppTag      = regexp.MustCompile(`^(?:OWASP_CRS(?:/[A-Z0-9_-]{1,64})*|attack-[a-z-]{1,32})$`)
	crsAppTarget   = regexp.MustCompile(`^(?:[A-Z_]{2,32})(?::[^,;'"\s]{1,256})?$`)
	crsAppCRSTXVar = map[string]bool{"allowed_methods": true, "allowed_request_content_type": true, "enforce_bodyproc_urlencoded": true}
	crsAppOperator = map[string]bool{"rx": true, "streq": true, "eq": true, "le": true, "ge": true, "lt": true, "gt": true,
		"endsWith": true, "beginsWith": true, "contains": true, "unconditionalMatch": true, "ipMatch": true, "pm": true, "within": true}
	crsAppBodyProcessor = map[string]bool{"URLENCODED": true, "JSON": true, "XML": true, "MULTIPART": true}
)

// IsCRSAppPack reports whether a pack ID names an application exclusion pack.
func IsCRSAppPack(packID string) bool { return crsAppPackID.MatchString(packID) }

// CRSAppKey is the application key of system/app-<key>.
func CRSAppKey(packID string) (string, bool) {
	match := crsAppPackID.FindStringSubmatch(packID)
	if match == nil {
		return "", false
	}
	return match[1], true
}

func normalizeCRSAppRule(rule Rule) (Rule, error) {
	if rule.App == nil || rule.WAF != nil || rule.CC != nil || rule.CRS != nil {
		return Rule{}, errors.New("needs exactly an app body")
	}
	app := *rule.App
	if app.Stage != rule.ID || app.Stage != CRSAppStageConfig && app.Stage != CRSAppStageBefore {
		return Rule{}, errors.New("rule id and stage must both be config or before")
	}
	if app.FirstID < 9500000 || app.LastID > 9999999 || app.LastID-app.FirstID != 999 || app.FirstID%1000 != 0 {
		return Rule{}, errors.New("first_id..last_id must be one registered plugin range of 1000 IDs")
	}
	if len(app.Text) > maxCRSAppText {
		return Rule{}, errors.New("text is too large")
	}
	if _, err := ValidateCRSAppText(app.Text, app.FirstID, app.LastID); err != nil {
		return Rule{}, err
	}
	return Rule{ID: rule.ID, Name: rule.Name, App: &app}, nil
}

// ValidateCRSAppText accepts ModSecurity text that only narrows CRS: rules
// (SecRule, SecAction, SecMarker) whose IDs are in first..last and whose
// actions are pass/nolog flow control, rule and target removals of CRS and
// plugin rules, request body processor choices and the CRS policy
// variables the official plugins widen. It returns the SecMarker names.
func ValidateCRSAppText(text string, first, last int) ([]string, error) {
	directives, err := crsAppDirectives(text)
	if err != nil {
		return nil, err
	}
	markers := map[string]bool{}
	var names []string
	var skips []string
	chained := false
	for _, directive := range directives {
		args, err := crsAppArgs(directive)
		if err != nil {
			return nil, err
		}
		var actions string
		switch args[0] {
		case "SecMarker":
			if len(args) != 2 || chained || !crsAppMarker.MatchString(args[1]) || markers[args[1]] {
				return nil, fmt.Errorf("invalid SecMarker %q", directive)
			}
			markers[args[1]] = true
			names = append(names, args[1])
			continue
		case "SecAction":
			if len(args) != 2 || chained {
				return nil, fmt.Errorf("invalid SecAction %q", directive)
			}
			actions = args[1]
		case "SecRule":
			if len(args) != 4 && !(chained && len(args) == 3) {
				return nil, fmt.Errorf("invalid SecRule %q", directive)
			}
			if err := checkCRSAppOperator(args[2]); err != nil {
				return nil, err
			}
			if len(args) == 4 {
				actions = args[3]
			}
		default:
			return nil, fmt.Errorf("directive %s is not allowed in an application exclusion pack", args[0])
		}
		parsed, err := checkCRSAppActions(actions, first, last, chained, &skips)
		if err != nil {
			return nil, fmt.Errorf("%v in %.120q", err, directive)
		}
		chained = parsed
	}
	if chained {
		return nil, errors.New("text ends inside a rule chain")
	}
	for _, target := range skips {
		if !markers[target] {
			return nil, fmt.Errorf("skipAfter %s names no marker of the text", target)
		}
	}
	return names, nil
}

// crsAppDirectives joins continuation lines and drops comments and blank
// lines. A text that ends in a continuation is refused (it would swallow
// the next line of the node configuration).
func crsAppDirectives(text string) ([]string, error) {
	if strings.ContainsAny(text, "\r\x00") {
		return nil, errors.New("text has CR or NUL")
	}
	var directives []string
	var current strings.Builder
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if current.Len() == 0 && (trimmed == "" || strings.HasPrefix(trimmed, "#")) {
			continue
		}
		if strings.HasSuffix(line, "\\") {
			current.WriteString(strings.TrimSuffix(line, "\\"))
			continue
		}
		current.WriteString(line)
		directives = append(directives, strings.TrimSpace(current.String()))
		current.Reset()
	}
	if current.Len() != 0 {
		return nil, errors.New("text ends in a line continuation")
	}
	return directives, nil
}

// crsAppArgs splits a directive into whitespace separated arguments; double
// quoted arguments may contain \" and \\.
func crsAppArgs(directive string) ([]string, error) {
	var args []string
	for index := 0; index < len(directive); {
		switch directive[index] {
		case ' ', '\t':
			index++
			continue
		case '"':
			var value strings.Builder
			index++
			for ; index < len(directive) && directive[index] != '"'; index++ {
				if directive[index] == '\\' && index+1 < len(directive) {
					value.WriteByte(directive[index])
					index++
				}
				value.WriteByte(directive[index])
			}
			if index >= len(directive) {
				return nil, fmt.Errorf("unterminated quote in %.120q", directive)
			}
			index++
			args = append(args, value.String())
		default:
			end := strings.IndexAny(directive[index:], " \t")
			if end < 0 {
				end = len(directive) - index
			}
			if strings.Contains(directive[index:index+end], "\"") {
				return nil, fmt.Errorf("stray quote in %.120q", directive)
			}
			args = append(args, directive[index:index+end])
			index += end
		}
	}
	if len(args) == 0 {
		return nil, errors.New("empty directive")
	}
	return args, nil
}

func checkCRSAppOperator(operator string) error {
	value := strings.TrimPrefix(operator, "!")
	if !strings.HasPrefix(value, "@") {
		return nil // an implicit @rx
	}
	name, _, _ := strings.Cut(value[1:], " ")
	if !crsAppOperator[name] {
		return fmt.Errorf("operator @%s is not allowed", name)
	}
	return nil
}

// splitCRSAppActions splits an action list at commas outside single quotes.
func splitCRSAppActions(actions string) ([]string, error) {
	var parts []string
	var current strings.Builder
	quoted := false
	for _, char := range actions {
		switch {
		case char == '\'':
			quoted = !quoted
		case char == ',' && !quoted:
			parts = append(parts, strings.TrimSpace(current.String()))
			current.Reset()
			continue
		}
		current.WriteRune(char)
	}
	if quoted {
		return nil, errors.New("unterminated single quote")
	}
	return append(parts, strings.TrimSpace(current.String())), nil
}

// checkCRSAppActions checks one rule's actions and reports whether the rule
// starts (or continues) a chain.
func checkCRSAppActions(actions string, first, last int, continuation bool, skips *[]string) (bool, error) {
	parts, err := splitCRSAppActions(actions)
	if err != nil {
		return false, err
	}
	hasID, chain, pass := false, false, false
	for _, part := range parts {
		if part == "" && actions == "" {
			continue
		}
		name, value, _ := strings.Cut(part, ":")
		value = strings.Trim(value, "'")
		switch name {
		case "id":
			id, err := strconv.Atoi(value)
			if err != nil || id < first || id > last || continuation {
				return false, fmt.Errorf("rule id %s is outside %d..%d or in a chain", value, first, last)
			}
			hasID = true
		case "phase":
			if continuation || value < "1" || value > "4" || len(value) != 1 {
				return false, fmt.Errorf("phase %s is not 1..4", value)
			}
		case "pass":
			pass = true
		case "nolog", "noauditlog", "capture":
		case "chain":
			chain = true
		case "t", "ver", "tag", "msg":
		case "skipAfter":
			*skips = append(*skips, value)
		case "setvar":
			if err := checkCRSAppSetvar(value); err != nil {
				return false, err
			}
		case "ctl":
			if err := checkCRSAppCtl(value, first, last); err != nil {
				return false, err
			}
		default:
			return false, fmt.Errorf("action %s is not allowed", name)
		}
	}
	if !continuation && !hasID {
		return false, errors.New("rule has no id")
	}
	if !continuation && !pass {
		return false, errors.New("rule is not pass")
	}
	return chain, nil
}

func checkCRSAppSetvar(value string) error {
	target, _, _ := strings.Cut(value, "=")
	match := crsAppTXVar.FindStringSubmatch(strings.ToLower(target))
	if match == nil || !crsAppCRSTXVar[match[1]] && !strings.Contains(match[1], "-plugin_") {
		return fmt.Errorf("setvar %s is not a CRS policy or plugin variable", target)
	}
	return nil
}

func checkCRSAppCtl(value string, first, last int) error {
	name, argument, _ := strings.Cut(value, "=")
	switch name {
	case "ruleRemoveById":
		for _, part := range strings.Fields(argument) {
			low, high, isRange := strings.Cut(part, "-")
			if !isRange {
				high = low
			}
			from, err1 := strconv.Atoi(low)
			to, err2 := strconv.Atoi(high)
			parser := from == to && crsAppParserRule(from)
			if err1 != nil || err2 != nil || from > to || !parser && (!crsAppRemovable(from, first, last) || !crsAppRemovable(to, first, last)) {
				return fmt.Errorf("ctl:ruleRemoveById=%s removes rules outside CRS and the plugin", argument)
			}
		}
	case "ruleRemoveTargetById":
		// "low-high" is upstream spelling; libmodsecurity 3 reads only low.
		id, target, ok := strings.Cut(argument, ";")
		low, high, isRange := strings.Cut(id, "-")
		if !isRange {
			high = low
		}
		from, err1 := strconv.Atoi(low)
		to, err2 := strconv.Atoi(high)
		if !ok || err1 != nil || err2 != nil || from > to || !crsAppRemovable(from, first, last) ||
			!crsAppRemovable(to, first, last) || !crsAppTarget.MatchString(target) {
			return fmt.Errorf("ctl:ruleRemoveTargetById=%s is not a CRS rule target", argument)
		}
	case "ruleRemoveTargetByTag":
		tag, target, ok := strings.Cut(argument, ";")
		if !ok || !crsAppTag.MatchString(tag) || !crsAppTarget.MatchString(target) {
			return fmt.Errorf("ctl:ruleRemoveTargetByTag=%s is not a CRS tag target", argument)
		}
	case "ruleRemoveByTag":
		if !crsAppTag.MatchString(argument) {
			return fmt.Errorf("ctl:ruleRemoveByTag=%s is not a CRS tag", argument)
		}
	case "requestBodyProcessor":
		if !crsAppBodyProcessor[argument] {
			return fmt.Errorf("ctl:requestBodyProcessor=%s", argument)
		}
	case "requestBodyAccess":
		if argument != "Off" && argument != "off" {
			return fmt.Errorf("ctl:requestBodyAccess=%s", argument)
		}
	default:
		return fmt.Errorf("ctl:%s is not allowed", name)
	}
	return nil
}

// CRSAppParserRuleIDs maps libmodsecurity's recommended request body rules
// (modsecurity.conf-recommended) that the plugins remove for known bodies
// to the node's same rules (edgeconfig renderManagedWAFMain 10000+N):
// 200002 parse error, 200003 multipart strict, 200004 unmatched boundary,
// 200007 too many arguments. The converter rewrites only these IDs.
var CRSAppParserRuleIDs = map[int]int{200002: 10001, 200003: 10004, 200004: 10005, 200007: 10003}

func crsAppParserRule(id int) bool {
	for _, node := range CRSAppParserRuleIDs {
		if node == id {
			return true
		}
	}
	return false
}

// crsAppRemovable: a CRS rule (900000-999999) or one of the plugin's own.
func crsAppRemovable(id, first, last int) bool {
	return id >= 900000 && id <= 999999 || id >= first && id <= last
}

// CRSAppOf turns a compiled application exclusion pack into the node
// compiler's form.
func CRSAppOf(compiled *CompiledPack) (edgeconfig.CRSApp, error) {
	if compiled == nil {
		return edgeconfig.CRSApp{}, fmt.Errorf("%w: no pack", ErrInvalidPack)
	}
	pack := compiled.Pack
	key, ok := CRSAppKey(pack.PackID)
	if pack.Layer != LayerSystem || pack.Engine != EngineCRSApp || !ok || len(pack.ParamsSchema) != 0 ||
		len(pack.Exports) != 0 || len(pack.Defaults) != 1 {
		return edgeconfig.CRSApp{}, fmt.Errorf("%w: %s is not an application exclusion pack", ErrInvalidPack, pack.PackID)
	}
	app := edgeconfig.CRSApp{Ref: edgeconfig.CRSAppRef{PackID: pack.PackID, Version: pack.Version, SHA256: compiled.SHA256},
		Key: key, Name: pack.Name}
	for _, rule := range pack.Rules {
		if app.FirstID != 0 && (app.FirstID != rule.App.FirstID || app.LastID != rule.App.LastID) {
			return edgeconfig.CRSApp{}, fmt.Errorf("%w: %s stages disagree on the rule range", ErrInvalidPack, pack.PackID)
		}
		app.FirstID, app.LastID = rule.App.FirstID, rule.App.LastID
		if rule.App.Stage == CRSAppStageConfig {
			app.Config = rule.App.Text
		} else {
			app.Before = rule.App.Text
		}
	}
	markers, err := ValidateCRSAppText(app.Config+"\n"+app.Before, app.FirstID, app.LastID)
	if app.Before == "" || err != nil {
		return edgeconfig.CRSApp{}, fmt.Errorf("%w: %s has no before stage or its stages do not fit together", ErrInvalidPack, pack.PackID)
	}
	app.Markers = markers
	return app, nil
}

// LoadCRSApp is Load + CRSAppOf.
func LoadCRSApp(content []byte, wantSHA256 string) (*CompiledPack, edgeconfig.CRSApp, error) {
	compiled, err := Load(content, wantSHA256)
	if err != nil {
		return nil, edgeconfig.CRSApp{}, err
	}
	app, err := CRSAppOf(compiled)
	if err != nil {
		return nil, edgeconfig.CRSApp{}, err
	}
	return compiled, app, nil
}
