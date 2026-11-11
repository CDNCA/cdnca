package contentrewrite

import (
	"errors"
	"fmt"
	"regexp"
	"regexp/syntax"
	"strings"
)

const (
	MaxPatternBytes = 256
	MaxMatchBytes   = 512
	MaxRepeat       = 64
)

// pattern is a restricted regular expression in its canonical
// ASCII byte form: every atom matches exactly one ASCII byte, so Go (runes)
// and the node's PCRE (bytes, no UTF-8 mode) agree on any input.
type pattern struct {
	source string // canonical, for both engines
	maxLen int
	groups int
	re     *regexp.Regexp
}

// compilePattern parses, checks and re-emits a restricted pattern.
func compilePattern(source string, ignoreCase bool) (pattern, error) {
	if len(source) > MaxPatternBytes {
		return pattern{}, errors.New("pattern is longer than 256 bytes")
	}
	for index := 0; index < len(source); index++ {
		if source[index] >= 0x80 {
			return pattern{}, errors.New("pattern must be ASCII")
		}
	}
	flags := syntax.Perl &^ syntax.UnicodeGroups
	if ignoreCase {
		flags |= syntax.FoldCase
	}
	tree, err := syntax.Parse(source, flags)
	if err != nil {
		return pattern{}, fmt.Errorf("pattern does not parse: %s", errorCode(err))
	}
	// not Simplify: it expands {m,n} into nested ?, which bounds refuses
	minLen, maxLen, err := bounds(tree, false)
	if err != nil {
		return pattern{}, err
	}
	if minLen < 1 {
		return pattern{}, errors.New("pattern can match an empty string")
	}
	if maxLen > MaxMatchBytes {
		return pattern{}, errors.New("pattern can match more than 512 bytes")
	}
	var out strings.Builder
	emit(&out, tree)
	canonical := out.String()
	re, err := regexp.Compile(canonical)
	if err != nil {
		return pattern{}, fmt.Errorf("pattern does not compile: %v", err)
	}
	return pattern{source: canonical, maxLen: maxLen, groups: tree.MaxCap(), re: re}, nil
}

func errorCode(err error) string {
	var parse *syntax.Error
	if errors.As(err, &parse) {
		return string(parse.Code)
	}
	return "invalid"
}

// bounds is the shortest and longest match in bytes; it refuses what the
// restricted grammar leaves out.
func bounds(node *syntax.Regexp, inRepeat bool) (int, int, error) {
	switch node.Op {
	case syntax.OpLiteral:
		return len(node.Rune), len(node.Rune), nil
	case syntax.OpCharClass, syntax.OpAnyCharNotNL:
		if node.Op == syntax.OpCharClass && len(asciiRanges(node.Rune)) == 0 {
			return 0, 0, errors.New("character class matches no ASCII byte")
		}
		return 1, 1, nil
	case syntax.OpAnyChar:
		return 0, 0, errors.New("(?s) is not supported")
	case syntax.OpEmptyMatch:
		return 0, 0, nil
	case syntax.OpCapture:
		return bounds(node.Sub[0], inRepeat)
	case syntax.OpConcat:
		low, high := 0, 0
		for _, sub := range node.Sub {
			a, b, err := bounds(sub, inRepeat)
			if err != nil {
				return 0, 0, err
			}
			low, high = low+a, high+b
		}
		return low, high, nil
	case syntax.OpAlternate:
		low, high := -1, 0
		for _, sub := range node.Sub {
			a, b, err := bounds(sub, inRepeat)
			if err != nil {
				return 0, 0, err
			}
			if low < 0 || a < low {
				low = a
			}
			high = max(high, b)
		}
		return max(low, 0), high, nil
	case syntax.OpQuest, syntax.OpRepeat:
		if inRepeat {
			return 0, 0, errors.New("nested repetition is not supported")
		}
		minCount, maxCount := 0, 1
		if node.Op == syntax.OpRepeat {
			minCount, maxCount = node.Min, node.Max
			if maxCount < 0 {
				return 0, 0, errors.New("unbounded repetition {n,} is not supported, use {m,n}")
			}
			if maxCount > MaxRepeat {
				return 0, 0, errors.New("repetition above 64 is not supported")
			}
		}
		a, b, err := bounds(node.Sub[0], true)
		if err != nil {
			return 0, 0, err
		}
		return a * minCount, b * maxCount, nil
	case syntax.OpStar, syntax.OpPlus:
		return 0, 0, errors.New("* and + are not supported, use {m,n}")
	case syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText, syntax.OpEndText,
		syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return 0, 0, errors.New("anchors (^ $ \\b \\A \\z) are not supported")
	}
	return 0, 0, fmt.Errorf("%s is not supported", node.Op)
}

// asciiRanges clips rune ranges to 0x00-0x7F.
func asciiRanges(ranges []rune) []rune {
	out := []rune{}
	for index := 0; index+1 < len(ranges); index += 2 {
		low, high := ranges[index], ranges[index+1]
		if low > 0x7f {
			continue
		}
		out = append(out, low, min(high, 0x7f))
	}
	return out
}

func emitByte(out *strings.Builder, value rune) {
	fmt.Fprintf(out, `\x%02X`, value)
}

func emitClass(out *strings.Builder, ranges []rune) {
	out.WriteByte('[')
	for index := 0; index+1 < len(ranges); index += 2 {
		emitByte(out, ranges[index])
		if ranges[index+1] != ranges[index] {
			out.WriteByte('-')
			emitByte(out, ranges[index+1])
		}
	}
	out.WriteByte(']')
}

// emit writes the canonical form: bytes as \xHH, folded letters as [Aa],
// classes clipped to ASCII, explicit (?:) groups, no flags.
func emit(out *strings.Builder, node *syntax.Regexp) {
	switch node.Op {
	case syntax.OpLiteral:
		for _, value := range node.Rune {
			if node.Flags&syntax.FoldCase != 0 && ('a' <= value && value <= 'z' || 'A' <= value && value <= 'Z') {
				lower, upper := value|0x20, value&^0x20
				out.WriteByte('[')
				emitByte(out, upper)
				emitByte(out, lower)
				out.WriteByte(']')
				continue
			}
			emitByte(out, value)
		}
	case syntax.OpCharClass:
		emitClass(out, asciiRanges(node.Rune))
	case syntax.OpAnyCharNotNL:
		emitClass(out, []rune{0x00, 0x09, 0x0b, 0x7f})
	case syntax.OpEmptyMatch:
		out.WriteString("(?:)")
	case syntax.OpCapture:
		out.WriteByte('(')
		emit(out, node.Sub[0])
		out.WriteByte(')')
	case syntax.OpConcat:
		for _, sub := range node.Sub {
			emitAtom(out, sub, sub.Op == syntax.OpAlternate)
		}
	case syntax.OpAlternate:
		for index, sub := range node.Sub {
			if index > 0 {
				out.WriteByte('|')
			}
			emit(out, sub)
		}
	case syntax.OpQuest, syntax.OpRepeat:
		emitAtom(out, node.Sub[0], true)
		if node.Op == syntax.OpQuest {
			out.WriteByte('?')
		} else if node.Min == node.Max {
			fmt.Fprintf(out, "{%d}", node.Min)
		} else {
			fmt.Fprintf(out, "{%d,%d}", node.Min, node.Max)
		}
		if node.Flags&syntax.NonGreedy != 0 {
			out.WriteByte('?')
		}
	}
}

// emitAtom wraps a node in (?:) when group is set and it is not one atom.
func emitAtom(out *strings.Builder, node *syntax.Regexp, group bool) {
	single := node.Op == syntax.OpCapture || node.Op == syntax.OpCharClass || node.Op == syntax.OpAnyCharNotNL ||
		node.Op == syntax.OpLiteral && len(node.Rune) == 1
	if group && !single {
		out.WriteString("(?:")
		emit(out, node)
		out.WriteByte(')')
		return
	}
	emit(out, node)
}

// template is a replacement split into literal text and group numbers
// ($0-$9; $$ is "$"; any other $ is itself). The node parses it alike.
type segment struct {
	text  string
	group int // -1: text
}

func parseTemplate(value string) []segment {
	out := []segment{}
	var text strings.Builder
	for index := 0; index < len(value); index++ {
		if value[index] == '$' && index+1 < len(value) {
			next := value[index+1]
			if next == '$' {
				text.WriteByte('$')
				index++
				continue
			}
			if next >= '0' && next <= '9' {
				if text.Len() > 0 {
					out = append(out, segment{text: text.String(), group: -1})
					text.Reset()
				}
				out = append(out, segment{group: int(next - '0')})
				index++
				continue
			}
		}
		text.WriteByte(value[index])
	}
	if text.Len() > 0 {
		out = append(out, segment{text: text.String(), group: -1})
	}
	return out
}

func checkTemplate(value string, groups int) string {
	for _, part := range parseTemplate(value) {
		if part.group > groups {
			return fmt.Sprintf("$%d names a group the pattern does not have", part.group)
		}
	}
	return ""
}

// escapeTemplate makes text a template that expands to itself.
func escapeTemplate(value string) string { return strings.ReplaceAll(value, "$", "$$") }
