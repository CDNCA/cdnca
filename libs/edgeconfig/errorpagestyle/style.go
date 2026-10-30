// Package errorpagestyle is the only stylesheet grammar an error page may
// carry (ADR 0007 §7.2): the control plane renders it from theme tokens, and
// both the control plane and the edge agent accept a page's single <style>
// only when it parses here and re-renders byte for byte. The grammar has no
// url(), @-rules, comments, escapes or functions, so a page can never load an
// external resource through its stylesheet.
package errorpagestyle

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"regexp"
	"strconv"
	"strings"
)

const (
	MaxRules           = 64
	MaxDeclarations    = 16
	MaxStylesheetBytes = 16 << 10
)

var ErrInvalidStyle = errors.New("error page style is not in the canonical grammar")

type Declaration struct {
	Property string `json:"property"`
	Value    string `json:"value"`
}

type Rule struct {
	Selector     string        `json:"selector"`
	Declarations []Declaration `json:"declarations"`
}

type Sheet struct {
	Rules []Rule `json:"rules"`
}

var (
	classSelectorPattern = regexp.MustCompile(`^\.[a-z][a-z0-9-]{0,47}$`)
	classNamePattern     = regexp.MustCompile(`^[a-z][a-z0-9-]{0,47}$`)
	colorPattern         = regexp.MustCompile(`^#[0-9a-f]{6}$`)
	numberPattern        = regexp.MustCompile(`^(0|[1-9][0-9]{0,3})(\.[0-9]{1,2})?$`)
	quotedFontPattern    = regexp.MustCompile(`^"[\p{L}\p{N} -]{1,64}"$`)
	bareFontPattern      = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,63}$`)
	elementSelectors     = map[string]struct{}{
		"html": {}, "body": {}, "main": {}, "header": {}, "footer": {}, "section": {}, "article": {},
		"h1": {}, "h2": {}, "h3": {}, "p": {}, "small": {}, "code": {}, "pre": {}, "hr": {},
	}
)

type valueKind int

const (
	kindColor valueKind = iota
	kindLength
	kindFontSize
	kindBox
	kindLineHeight
	kindFontWeight
	kindFontFamily
	kindKeyword
)

type propertyRule struct {
	kind     valueKind
	keywords []string
}

var properties = map[string]propertyRule{
	"color":               {kind: kindColor},
	"background-color":    {kind: kindColor},
	"border-color":        {kind: kindColor},
	"border-top-color":    {kind: kindColor},
	"border-bottom-color": {kind: kindColor},
	"border-radius":       {kind: kindLength},
	"border-width":        {kind: kindLength},
	"font-size":           {kind: kindFontSize},
	"max-width":           {kind: kindLength},
	"min-height":          {kind: kindLength},
	"gap":                 {kind: kindLength},
	"padding":             {kind: kindBox},
	"margin":              {kind: kindBox},
	"line-height":         {kind: kindLineHeight},
	"font-weight":         {kind: kindFontWeight},
	"font-family":         {kind: kindFontFamily},
	"text-align":          {kind: kindKeyword, keywords: []string{"left", "center", "right"}},
	"display":             {kind: kindKeyword, keywords: []string{"block", "flex", "inline-block", "none"}},
	"border-style":        {kind: kindKeyword, keywords: []string{"solid", "dashed", "none"}},
	"align-items":         {kind: kindKeyword, keywords: []string{"center", "flex-start", "flex-end"}},
	"justify-content":     {kind: kindKeyword, keywords: []string{"center", "flex-start", "flex-end", "space-between"}},
	"flex-direction":      {kind: kindKeyword, keywords: []string{"row", "column"}},
}

// ValidSelector reports whether selector is a class selector or one of the
// plain element selectors.
func ValidSelector(selector string) bool {
	if classSelectorPattern.MatchString(selector) {
		return true
	}
	_, ok := elementSelectors[selector]
	return ok
}

// ValidClassName reports whether name may be declared as a theme class.
func ValidClassName(name string) bool { return classNamePattern.MatchString(name) }

// ValidDeclaration reports whether value is allowed for property.
func ValidDeclaration(property, value string) bool {
	rule, ok := properties[property]
	if !ok || value == "" || len(value) > 256 {
		return false
	}
	switch rule.kind {
	case kindColor:
		return colorPattern.MatchString(value)
	case kindLength:
		return validLength(value, false)
	case kindFontSize:
		// 8px–96px, or 0.5–6 rem/em.
		return validLength(value, false) && value != "0" && !strings.HasSuffix(value, "%") && fontSizeInRange(value)
	case kindBox:
		parts := strings.Split(value, " ")
		if len(parts) > 4 {
			return false
		}
		for _, part := range parts {
			if !validLength(part, property == "margin") {
				return false
			}
		}
		return true
	case kindLineHeight:
		if validLength(value, false) {
			return true
		}
		number, err := strconv.ParseFloat(value, 64)
		return err == nil && numberPattern.MatchString(value) && number >= 0.5 && number <= 3
	case kindFontWeight:
		switch value {
		case "normal", "bold", "100", "200", "300", "400", "500", "600", "700", "800", "900":
			return true
		}
		return false
	case kindFontFamily:
		return ValidFontStack(value)
	case kindKeyword:
		for _, keyword := range rule.keywords {
			if value == keyword {
				return true
			}
		}
	}
	return false
}

// ValidFontStack accepts a comma-separated list of quoted family names or
// bare identifiers ("PingFang SC", Arial, sans-serif).
func ValidFontStack(value string) bool {
	if value == "" || len(value) > 256 {
		return false
	}
	items := strings.Split(value, ", ")
	if len(items) > 12 {
		return false
	}
	for _, item := range items {
		if !quotedFontPattern.MatchString(item) && !bareFontPattern.MatchString(item) {
			return false
		}
	}
	return true
}

func validLength(value string, allowAuto bool) bool {
	if value == "0" || allowAuto && value == "auto" {
		return true
	}
	for _, unit := range []struct {
		suffix string
		max    float64
	}{{"px", 2000}, {"rem", 20}, {"em", 20}, {"%", 100}} {
		if !strings.HasSuffix(value, unit.suffix) {
			continue
		}
		number := strings.TrimSuffix(value, unit.suffix)
		if !numberPattern.MatchString(number) {
			return false
		}
		parsed, err := strconv.ParseFloat(number, 64)
		return err == nil && parsed <= unit.max
	}
	return false
}

// Render writes the canonical text of sheet. Every value is validated first,
// so Render never emits anything outside the grammar.
func Render(sheet Sheet) (string, error) {
	if len(sheet.Rules) == 0 || len(sheet.Rules) > MaxRules {
		return "", ErrInvalidStyle
	}
	var output strings.Builder
	for _, rule := range sheet.Rules {
		if !ValidSelector(rule.Selector) || len(rule.Declarations) == 0 || len(rule.Declarations) > MaxDeclarations {
			return "", ErrInvalidStyle
		}
		output.WriteString(rule.Selector)
		output.WriteString(" { ")
		for _, declaration := range rule.Declarations {
			if !ValidDeclaration(declaration.Property, declaration.Value) {
				return "", ErrInvalidStyle
			}
			output.WriteString(declaration.Property)
			output.WriteString(": ")
			output.WriteString(declaration.Value)
			output.WriteString("; ")
		}
		output.WriteString("}\n")
	}
	if output.Len() > MaxStylesheetBytes {
		return "", ErrInvalidStyle
	}
	return output.String(), nil
}

// Parse accepts only text that Render would produce.
func Parse(text string) (Sheet, error) {
	if text == "" || len(text) > MaxStylesheetBytes || !strings.HasSuffix(text, "}\n") {
		return Sheet{}, ErrInvalidStyle
	}
	var sheet Sheet
	for _, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		selector, rest, found := strings.Cut(line, " { ")
		if !found || !strings.HasSuffix(rest, "; }") {
			return Sheet{}, ErrInvalidStyle
		}
		rule := Rule{Selector: selector}
		for _, raw := range strings.Split(strings.TrimSuffix(rest, "; }"), "; ") {
			property, value, ok := strings.Cut(raw, ": ")
			if !ok {
				return Sheet{}, ErrInvalidStyle
			}
			rule.Declarations = append(rule.Declarations, Declaration{Property: property, Value: value})
		}
		sheet.Rules = append(sheet.Rules, rule)
	}
	rendered, err := Render(sheet)
	if err != nil || rendered != text {
		return Sheet{}, ErrInvalidStyle
	}
	return sheet, nil
}

// Classes returns the class names the sheet declares.
func (sheet Sheet) Classes() map[string]struct{} {
	result := make(map[string]struct{})
	for _, rule := range sheet.Rules {
		if strings.HasPrefix(rule.Selector, ".") {
			result[rule.Selector[1:]] = struct{}{}
		}
	}
	return result
}

// CheckClassAttribute accepts a class attribute whose single-space separated
// tokens are all declared.
func CheckClassAttribute(value string, declared map[string]struct{}) error {
	if value == "" {
		return ErrInvalidStyle
	}
	for _, token := range strings.Split(value, " ") {
		if !classNamePattern.MatchString(token) {
			return ErrInvalidStyle
		}
		if _, ok := declared[token]; !ok {
			return ErrInvalidStyle
		}
	}
	return nil
}

// SourceHash is the CSP source expression ('sha256-…' without quotes) for an
// inline <style> whose text is source.
func SourceHash(source string) string {
	digest := sha256.Sum256([]byte(source))
	return "sha256-" + base64.StdEncoding.EncodeToString(digest[:])
}

func fontSizeInRange(value string) bool {
	if number, ok := strings.CutSuffix(value, "px"); ok {
		parsed, err := strconv.ParseFloat(number, 64)
		return err == nil && parsed >= 8 && parsed <= 96
	}
	number := strings.TrimSuffix(strings.TrimSuffix(value, "rem"), "em")
	parsed, err := strconv.ParseFloat(number, 64)
	return err == nil && parsed >= 0.5 && parsed <= 6
}
