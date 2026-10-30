package edgeconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// CRSManifest describes the OWASP CRS request rules of one CRS rule text
// (DeriveCRSManifest). Nothing about CRS is pinned in this binary: the rule
// text arrives as the signed catalog's CRS rule package (crs_profile/crs_rules,
// trusted through the catalog signature and the package digest), and the
// manifest the compiler resolves rule sets, profiles and exclusions against
// is derived from that text. A CRS minor release is a new package, never a
// new control-plane or agent binary.
//   - Files: REQUEST-9xx rule files (Uses: the @pmFromFile data files each
//     loads); Data: those data files.
//   - Rules: the scoring rules, by ID.
type CRSManifest struct {
	Version string    `json:"version"`
	Files   []CRSFile `json:"files"`
	Data    []CRSFile `json:"data"`
	Rules   []CRSRule `json:"rules"`
	index   map[int]CRSRule
}

type CRSFile struct {
	Name   string   `json:"name"`
	SHA256 string   `json:"sha256"`
	Uses   []string `json:"uses,omitempty"`
}

// CRSRule is one scoring rule (a rule, or rule chain, that adds to
// tx.inbound_anomaly_score_pl<N>). Control rules (paranoia skips,
// initialisation) are not listed: they never score and are never removed.
type CRSRule struct {
	ID       int    `json:"id"`
	File     string `json:"file"`
	Phase    int    `json:"phase"`
	Paranoia int    `json:"paranoia"`
	Severity string `json:"severity"`
}

const (
	// crsRulesDir is where the release carries the CRS rule text, relative
	// to managedWAFMainPath (libmodsecurity resolves relative Include and
	// @pmFromFile against the including file's directory).
	crsRulesDir   = "crs"
	crsReleaseDir = "security/modsecurity/" + crsRulesDir
	// CRSLicenseFile and CRSNoticeFile are the Apache-2.0 LICENSE of OWASP
	// CRS and the redistribution NOTICE every CRS rule package (and every
	// release that carries its text) ships with.
	CRSLicenseFile = "LICENSE"
	CRSNoticeFile  = "NOTICE"
	crsMaxFiles    = 64
)

// crsBaseFiles always load with any managed rule set: initialisation,
// common exceptions and the CRS paranoia/score bookkeeping.
var crsBaseFiles = []string{
	"REQUEST-901-INITIALIZATION.conf", "REQUEST-905-COMMON-EXCEPTIONS.conf",
}

var (
	crsRuleFileName = regexp.MustCompile(`^REQUEST-9[0-9]{2}-[A-Z0-9-]{1,64}\.conf$`)
	crsDataFileName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}\.data$`)
	crsVersionTag   = regexp.MustCompile(`ver:'OWASP_CRS/([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})'`)
	// crsDirective is a line's leading ModSecurity directive; a CRS request
	// rule file may only declare rules (crsRuleDirectives), never engine
	// settings (SecRuleEngine, SecAuditLog, Include, ...).
	crsDirective      = regexp.MustCompile(`(?m)^[ \t]*(Sec[A-Za-z]+|Include[A-Za-z]*)\b`)
	crsRuleDirectives = map[string]bool{"SecRule": true, "SecAction": true, "SecMarker": true,
		"SecComponentSignature": true, "SecRuleUpdateTargetById": true}
)

// DeriveCRSManifest derives the manifest of a CRS rule text: every REQUEST-9xx
// rule file is parsed for its scoring rules and data references, the CRS
// version is the one every rule file's ver: tag names (and must equal
// text.Version when that is set), and the text must carry the base files,
// every data file a rule file references, LICENSE and NOTICE, and nothing
// else.
func DeriveCRSManifest(text *CRSRuleText) (*CRSManifest, error) {
	if text == nil || len(text.Files) == 0 || len(text.Files) > crsMaxFiles {
		return nil, ErrInvalidConfig
	}
	names := make([]string, 0, len(text.Files))
	for name := range text.Files {
		names = append(names, name)
	}
	sort.Strings(names)
	manifest := &CRSManifest{Files: []CRSFile{}, Data: []CRSFile{}, Rules: []CRSRule{}, index: map[int]CRSRule{}}
	data := map[string]CRSFile{}
	version := ""
	for _, name := range names {
		content := text.Files[name]
		if len(content) == 0 {
			return nil, ErrInvalidConfig
		}
		sum := sha256.Sum256(content)
		digest := hex.EncodeToString(sum[:])
		switch {
		case name == CRSLicenseFile || name == CRSNoticeFile:
		case crsDataFileName.MatchString(name):
			data[name] = CRSFile{Name: name, SHA256: digest}
		case crsRuleFileName.MatchString(name):
			for _, directive := range crsDirective.FindAllStringSubmatch(string(content), -1) {
				if !crsRuleDirectives[directive[1]] {
					return nil, ErrInvalidConfig
				}
			}
			for _, tag := range crsVersionTag.FindAllStringSubmatch(string(content), -1) {
				found := tag[1] + "." + tag[2] + "." + tag[3]
				if version != "" && version != found {
					return nil, ErrInvalidConfig // one CRS release per text
				}
				version = found
			}
			rules, err := ParseCRSRules(name, content)
			if err != nil {
				return nil, ErrInvalidConfig
			}
			for _, rule := range rules {
				if _, duplicate := manifest.index[rule.ID]; duplicate {
					return nil, ErrInvalidConfig
				}
				manifest.index[rule.ID] = rule
				manifest.Rules = append(manifest.Rules, rule)
			}
			manifest.Files = append(manifest.Files, CRSFile{Name: name, SHA256: digest, Uses: CRSDataReferences(content)})
		default:
			return nil, ErrInvalidConfig
		}
	}
	used := map[string]bool{}
	for _, file := range manifest.Files {
		for _, name := range file.Uses {
			if _, ok := data[name]; !ok {
				return nil, ErrInvalidConfig
			}
			used[name] = true
		}
	}
	for name, file := range data {
		if !used[name] {
			return nil, ErrInvalidConfig
		}
		manifest.Data = append(manifest.Data, file)
	}
	sort.Slice(manifest.Data, func(i, j int) bool { return manifest.Data[i].Name < manifest.Data[j].Name })
	sort.Slice(manifest.Rules, func(i, j int) bool { return manifest.Rules[i].ID < manifest.Rules[j].ID })
	if version == "" || text.Version != "" && text.Version != version ||
		len(text.Files[CRSLicenseFile]) == 0 || len(text.Files[CRSNoticeFile]) == 0 {
		return nil, ErrInvalidConfig
	}
	for _, base := range crsBaseFiles {
		if text.Files[base] == nil {
			return nil, ErrInvalidConfig
		}
	}
	manifest.Version = version
	return manifest, nil
}

// SetupVersion is the tx.crs_setup_version value of the manifest's CRS
// release (4.30.0 -> 4300, CRS crs-setup.conf convention: major, minor,
// patch digits concatenated).
func (manifest *CRSManifest) SetupVersion() string {
	return strings.ReplaceAll(manifest.Version, ".", "")
}

// Rule returns the scoring rule with id.
func (manifest *CRSManifest) Rule(id int) (CRSRule, bool) {
	rule, ok := manifest.index[id]
	return rule, ok
}

// crsDataReference finds @pmFromFile data file names in a rule file.
var crsDataReference = regexp.MustCompile(`@pmFromFile ([a-z0-9][a-z0-9-]*\.data)\b`)

// CRSDataReferences lists the data files a rule file loads (sorted, unique).
func CRSDataReferences(content []byte) []string {
	seen := map[string]bool{}
	result := make([]string, 0)
	for _, match := range crsDataReference.FindAllSubmatch(content, -1) {
		if name := string(match[1]); !seen[name] {
			seen[name] = true
			result = append(result, name)
		}
	}
	sort.Strings(result)
	return result
}

var (
	crsDirectiveStart = regexp.MustCompile(`(?m)^[ \t]*(SecRule|SecAction|SecMarker)\b`)
	crsRuleID         = regexp.MustCompile(`"id:(\d+)`)
	crsPhase          = regexp.MustCompile(`\bphase:(\d)`)
	crsChain          = regexp.MustCompile(`(?:^|[,"\s])chain\s*"?\s*$`)
	crsScore          = regexp.MustCompile(`setvar:'tx\.inbound_anomaly_score_pl([1-4])=\+%\{tx\.(critical|error|warning|notice)_anomaly_score\}'`)
)

// ParseCRSRules extracts the scoring rules of one CRS rule file. A rule chain
// is attributed to its starting rule (the only one that carries id/phase);
// its score setvar may sit on any link and only fires when the chain matches.
func ParseCRSRules(name string, content []byte) ([]CRSRule, error) {
	text := strings.ReplaceAll(string(content), "\\\r\n", " ")
	text = strings.ReplaceAll(text, "\\\n", " ")
	starts := crsDirectiveStart.FindAllStringIndex(text, -1)
	rules := make([]CRSRule, 0)
	var current *CRSRule
	scored := false
	for index, start := range starts {
		end := len(text)
		if index+1 < len(starts) {
			end = starts[index+1][0]
		}
		block := text[start[0]:end]
		if lines := strings.Split(strings.TrimRight(block, " \t\r\n"), "\n"); len(lines) > 1 {
			// drop trailing comments that belong to the next directive
			kept := lines[:0]
			for _, line := range lines {
				if !strings.HasPrefix(strings.TrimSpace(line), "#") {
					kept = append(kept, line)
				}
			}
			block = strings.Join(kept, "\n")
		}
		if current == nil {
			match := crsRuleID.FindStringSubmatch(block)
			if match == nil {
				continue
			}
			id, _ := strconv.Atoi(match[1])
			phase := 0
			if phaseMatch := crsPhase.FindStringSubmatch(block); phaseMatch != nil {
				phase, _ = strconv.Atoi(phaseMatch[1])
			}
			current, scored = &CRSRule{ID: id, File: name, Phase: phase}, false
		}
		for _, score := range crsScore.FindAllStringSubmatch(block, -1) {
			paranoia, _ := strconv.Atoi(score[1])
			if scored && (current.Paranoia != paranoia || current.Severity != score[2]) {
				return nil, fmt.Errorf("%s: rule %d scores twice", name, current.ID)
			}
			current.Paranoia, current.Severity, scored = paranoia, score[2], true
		}
		if crsChain.MatchString(strings.TrimSpace(block)) {
			continue
		}
		if scored {
			if current.Phase != 1 && current.Phase != 2 {
				return nil, fmt.Errorf("%s: scoring rule %d has phase %d", name, current.ID, current.Phase)
			}
			rules = append(rules, *current)
		}
		current = nil
	}
	if current != nil {
		return nil, fmt.Errorf("%s: unterminated chain at rule %d", name, current.ID)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	return rules, nil
}
