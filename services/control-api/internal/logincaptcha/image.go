// Package logincaptcha renders the built-in sign-in CAPTCHA (identity
// login throttle) as a PNG with the standard library only: a 5x7 bitmap font,
// per-glyph jitter and scale, interference lines and dot noise.
package logincaptcha

import (
	"bytes"
	"crypto/rand"
	"errors"
	"image"
	"image/color"
	"image/png"
	"math/big"
)

const (
	Width  = 150
	Height = 50
)

var ErrUnsupportedAnswer = errors.New("captcha answer contains an unsupported character")

// glyphs covers the identity CAPTCHA alphabet (no 0/1/I/L/O, and no Y, which reads like X under noise).
var glyphs = map[byte][7]string{
	'2': {"01110", "10001", "00001", "00010", "00100", "01000", "11111"},
	'3': {"11110", "00001", "00001", "01110", "00001", "00001", "11110"},
	'4': {"00010", "00110", "01010", "10010", "11111", "00010", "00010"},
	'5': {"11111", "10000", "11110", "00001", "00001", "10001", "01110"},
	'6': {"00110", "01000", "10000", "11110", "10001", "10001", "01110"},
	'7': {"11111", "00001", "00010", "00100", "01000", "01000", "01000"},
	'8': {"01110", "10001", "10001", "01110", "10001", "10001", "01110"},
	'9': {"01110", "10001", "10001", "01111", "00001", "00010", "01100"},
	'A': {"01110", "10001", "10001", "11111", "10001", "10001", "10001"},
	'B': {"11110", "10001", "10001", "11110", "10001", "10001", "11110"},
	'C': {"01110", "10001", "10000", "10000", "10000", "10001", "01110"},
	'D': {"11100", "10010", "10001", "10001", "10001", "10010", "11100"},
	'E': {"11111", "10000", "10000", "11110", "10000", "10000", "11111"},
	'F': {"11111", "10000", "10000", "11110", "10000", "10000", "10000"},
	'G': {"01110", "10001", "10000", "10111", "10001", "10001", "01111"},
	'H': {"10001", "10001", "10001", "11111", "10001", "10001", "10001"},
	'J': {"00111", "00010", "00010", "00010", "00010", "10010", "01100"},
	'K': {"10001", "10010", "10100", "11000", "10100", "10010", "10001"},
	'M': {"10001", "11011", "10101", "10101", "10001", "10001", "10001"},
	'N': {"10001", "10001", "11001", "10101", "10011", "10001", "10001"},
	'P': {"11110", "10001", "10001", "11110", "10000", "10000", "10000"},
	'Q': {"01110", "10001", "10001", "10001", "10101", "10010", "01101"},
	'R': {"11110", "10001", "10001", "11110", "10100", "10010", "10001"},
	'S': {"01111", "10000", "10000", "01110", "00001", "00001", "11110"},
	'T': {"11111", "00100", "00100", "00100", "00100", "00100", "00100"},
	'U': {"10001", "10001", "10001", "10001", "10001", "10001", "01110"},
	'V': {"10001", "10001", "10001", "10001", "10001", "01010", "00100"},
	'W': {"10001", "10001", "10001", "10101", "10101", "10101", "01010"},
	'X': {"10001", "10001", "01010", "00100", "01010", "10001", "10001"},
	'Z': {"11111", "00001", "00010", "00100", "01000", "10000", "11111"},
}

func randomInt(limit int) int {
	value, err := rand.Int(rand.Reader, big.NewInt(int64(limit)))
	if err != nil {
		return 0
	}
	return int(value.Int64())
}

// RenderPNG draws answer and returns the PNG bytes.
func RenderPNG(answer string) ([]byte, error) {
	if answer == "" || len(answer) > 8 {
		return nil, ErrUnsupportedAnswer
	}
	for index := range len(answer) {
		if _, ok := glyphs[answer[index]]; !ok {
			return nil, ErrUnsupportedAnswer
		}
	}
	canvas := image.NewRGBA(image.Rect(0, 0, Width, Height))
	background := color.RGBA{R: uint8(235 + randomInt(20)), G: uint8(235 + randomInt(20)), B: uint8(235 + randomInt(20)), A: 255}
	for y := range Height {
		for x := range Width {
			canvas.Set(x, y, background)
		}
	}
	for range 4 {
		line := color.RGBA{R: uint8(100 + randomInt(120)), G: uint8(100 + randomInt(120)), B: uint8(100 + randomInt(120)), A: 255}
		drawLine(canvas, randomInt(Width/3), randomInt(Height), Width-randomInt(Width/3), randomInt(Height), line)
	}
	slot := (Width - 10) / len(answer)
	for index := range len(answer) {
		glyph := glyphs[answer[index]]
		scale := 4 + randomInt(2)
		ink := color.RGBA{R: uint8(randomInt(110)), G: uint8(randomInt(110)), B: uint8(randomInt(110)), A: 255}
		left := 5 + index*slot + randomInt(max(1, slot-5*scale))
		top := 3 + randomInt(max(1, Height-6-7*scale))
		shear := randomInt(3) - 1
		for row := range 7 {
			for column := range 5 {
				if glyph[row][column] != '1' {
					continue
				}
				offset := shear * (3 - row)
				for dy := range scale {
					for dx := range scale {
						canvas.Set(left+column*scale+offset+dx, top+row*scale+dy, ink)
					}
				}
			}
		}
	}
	for range Width * Height / 12 {
		noise := color.RGBA{R: uint8(randomInt(256)), G: uint8(randomInt(256)), B: uint8(randomInt(256)), A: 255}
		canvas.Set(randomInt(Width), randomInt(Height), noise)
	}
	var buffer bytes.Buffer
	if err := png.Encode(&buffer, canvas); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func drawLine(canvas *image.RGBA, x0, y0, x1, y1 int, ink color.Color) {
	dx, dy := abs(x1-x0), -abs(y1-y0)
	sx, sy := sign(x1-x0), sign(y1-y0)
	err := dx + dy
	for {
		canvas.Set(x0, y0, ink)
		canvas.Set(x0, y0+1, ink)
		if x0 == x1 && y0 == y1 {
			return
		}
		doubled := 2 * err
		if doubled >= dy {
			err += dy
			x0 += sx
		}
		if doubled <= dx {
			err += dx
			y0 += sy
		}
	}
}

func abs(value int) int {
	if value < 0 {
		return -value
	}
	return value
}

func sign(value int) int {
	switch {
	case value > 0:
		return 1
	case value < 0:
		return -1
	}
	return 0
}
