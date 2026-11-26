package dnspupprobe

import (
	"testing"
	"unicode"
)

// TestNotificationEnglishTexts: every Chinese notice text has an
// English text without Chinese characters.
func TestNotificationEnglishTexts(t *testing.T) {
	checkEnglishTexts(t, "FailureTexts", FailureTexts, FailureTextsEN)
	checkEnglishTexts(t, "reasonTexts", reasonTexts, reasonTextsEN)
}

func checkEnglishTexts[K comparable](t *testing.T, name string, chinese, english map[K]string) {
	t.Helper()
	if len(english) != len(chinese) {
		t.Errorf("%s: %d English texts for %d Chinese", name, len(english), len(chinese))
	}
	for key := range chinese {
		text, ok := english[key]
		if !ok || text == "" {
			t.Errorf("%s[%v] has no English text", name, key)
		}
		for _, r := range text {
			if unicode.Is(unicode.Han, r) {
				t.Errorf("%s[%v] English text has Chinese: %q", name, key, text)
				break
			}
		}
	}
}
