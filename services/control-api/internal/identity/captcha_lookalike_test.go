package identity

import (
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/logincaptcha"
)

// an answer read with a look-alike of a glyph (8 read as B, 5 as S, a space
// typed between glyphs) still matches; the alphabet itself never changes under the mapping.
func TestNormalizeCaptchaAnswerForgivesLookAlikesOnly(t *testing.T) {
	if got := normalizeCaptchaAnswer(logincaptcha.Alphabet); got != logincaptcha.Alphabet {
		t.Fatalf("alphabet changed under normalisation: %q", got)
	}
	for typed, want := range map[string]string{
		"b5s2z": "85522", " 6g u v ": "66UU", "dOq0": "DDDD", "xy7": "XX7", "ab3": "A83",
	} {
		if got := normalizeCaptchaAnswer(typed); got != want {
			t.Fatalf("%q: got %q want %q", typed, got, want)
		}
	}
	for _, glyph := range logincaptcha.Alphabet {
		if strings.ContainsRune("BSZGVYOQ0 ", glyph) {
			t.Fatalf("alphabet holds look-alike %q", glyph)
		}
	}
}
