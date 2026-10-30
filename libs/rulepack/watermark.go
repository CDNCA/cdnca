package rulepack

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Watermarks (ADR 0007 §6.1 "可追溯"): every installation's copy of an
// encrypted pack carries a 64-bit tag, HMAC-SHA256 of the installation ID
// under the pack version's watermark key, written as zero-width characters
// at the end of every rule name and of the description. Names and
// descriptions do not affect execution; the characters are invisible in the
// page and survive copy-paste of the JSON (encoding/json keeps them as
// UTF-8). A leaked pack (plaintext JSON, or a manifest / node rule list
// carrying names) is traced with ExtractWatermark + MatchWatermark.
const (
	WatermarkSize = 8
	watermarkRuns = WatermarkSize * 4 // 2 bits per zero-width character

	watermarkDomain = "cdnca-rule-pack-watermark/v1\x00"
	maxNameRunes    = 128
	maxDescRunes    = 1000
)

// watermarkAlphabet: zero-width space, non-joiner, joiner, word joiner
// (format characters: not whitespace, not control, invisible).
var watermarkAlphabet = [4]rune{'\u200b', '\u200c', '\u200d', '\u2060'}

var ErrNoWatermark = errors.New("rule pack carries no watermark")

// WatermarkTag is the tag of installationID for pack (pack_id, version)
// under key.
func WatermarkTag(key []byte, installationID, packID, version string) [WatermarkSize]byte {
	mac := hmac.New(sha256.New, key)
	for _, field := range []string{watermarkDomain, installationID, packID, version} {
		mac.Write([]byte(fmt.Sprintf("%08x", len(field))))
		mac.Write([]byte(field))
	}
	var tag [WatermarkSize]byte
	copy(tag[:], mac.Sum(nil))
	return tag
}

// Watermark returns the canonical bytes of the pack with tag written into
// every rule name and the description (any earlier watermark is replaced;
// visible text is shortened when needed to stay within the field limits).
func Watermark(canonical []byte, tag [WatermarkSize]byte) ([]byte, error) {
	compiled, err := Compile(canonical)
	if err != nil {
		return nil, err
	}
	mark := encodeWatermark(tag)
	pack := compiled.Pack
	pack.Description = withMark(pack.Description, mark, maxDescRunes)
	rules := make([]Rule, len(pack.Rules))
	for index, rule := range pack.Rules {
		rule.Name = withMark(rule.Name, mark, maxNameRunes)
		rules[index] = rule
	}
	pack.Rules = rules
	marked, err := CompilePack(pack)
	if err != nil {
		return nil, err
	}
	return marked.Canonical, nil
}

// ExtractWatermark finds the tag in any text that carries a watermarked
// field (pack JSON, a manifest, a rule name). All tags found must agree.
func ExtractWatermark(text []byte) ([WatermarkSize]byte, error) {
	var found *[WatermarkSize]byte
	run := make([]byte, 0, watermarkRuns)
	flush := func() error {
		if len(run) == watermarkRuns {
			tag := decodeWatermark(run)
			if found != nil && *found != tag {
				return fmt.Errorf("%w: conflicting watermarks", ErrNoWatermark)
			}
			found = &tag
		}
		run = run[:0]
		return nil
	}
	for _, r := range string(text) {
		if symbol := watermarkSymbol(r); symbol >= 0 {
			run = append(run, byte(symbol))
			continue
		}
		if err := flush(); err != nil {
			return [WatermarkSize]byte{}, err
		}
	}
	if err := flush(); err != nil {
		return [WatermarkSize]byte{}, err
	}
	if found == nil {
		return [WatermarkSize]byte{}, ErrNoWatermark
	}
	return *found, nil
}

// MatchWatermark returns the candidate installation whose tag is tag
// ("" if none). The comparison is constant-time per candidate.
func MatchWatermark(key []byte, tag [WatermarkSize]byte, packID, version string, installationIDs []string) string {
	for _, id := range installationIDs {
		want := WatermarkTag(key, id, packID, version)
		if hmac.Equal(want[:], tag[:]) {
			return id
		}
	}
	return ""
}

func encodeWatermark(tag [WatermarkSize]byte) string {
	var builder strings.Builder
	for _, value := range tag {
		for shift := 6; shift >= 0; shift -= 2 {
			builder.WriteRune(watermarkAlphabet[(value>>shift)&3])
		}
	}
	return builder.String()
}

func decodeWatermark(symbols []byte) [WatermarkSize]byte {
	var tag [WatermarkSize]byte
	for index, symbol := range symbols {
		tag[index/4] |= symbol << (6 - 2*(index%4))
	}
	return tag
}

func watermarkSymbol(r rune) int {
	for index, candidate := range watermarkAlphabet {
		if r == candidate {
			return index
		}
	}
	return -1
}

// withMark strips earlier watermark characters from text and appends mark,
// shortening the visible text to fit limit runes.
func withMark(text, mark string, limit int) string {
	visible := strings.Map(func(r rune) rune {
		if watermarkSymbol(r) >= 0 {
			return -1
		}
		return r
	}, text)
	room := limit - utf8.RuneCountInString(mark)
	if runes := []rune(visible); len(runes) > room {
		visible = strings.TrimSpace(string(runes[:room]))
	}
	return visible + mark
}
