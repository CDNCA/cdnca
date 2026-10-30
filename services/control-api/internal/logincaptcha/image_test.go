package logincaptcha

import (
	"bytes"
	"image/png"
	"testing"
)

func TestRenderPNGCoversAlphabetAndRejectsOthers(t *testing.T) {
	alphabet := "23456789ABCDEFGHJKMNPQRSTUVWXZ"
	for start := 0; start < len(alphabet); start += 5 {
		answer := alphabet[start:min(start+5, len(alphabet))]
		raw, err := RenderPNG(answer)
		if err != nil {
			t.Fatalf("%s: %v", answer, err)
		}
		decoded, err := png.Decode(bytes.NewReader(raw))
		if err != nil || decoded.Bounds().Dx() != Width || decoded.Bounds().Dy() != Height {
			t.Fatalf("%s: decoded=%v err=%v", answer, decoded, err)
		}
	}
	for _, answer := range []string{"", "ABC0", "abcde", "ABCDEFGHJ"} {
		if _, err := RenderPNG(answer); err == nil {
			t.Fatalf("%q accepted", answer)
		}
	}
}
