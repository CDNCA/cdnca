package main

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"time"
)

// ---------------------------------------------------------------- scrape
//
// A client that never runs the page's JavaScript: it reads every answer the
// page carries as markup (button ids, the "拖到 N%" label, the arrow's
// data-base angle, the captcha's SVG dot matrix), computes the proof of work
// itself and submits. The interactive modes (click, rotate, slider, captcha)
// must refuse it: their answer may only be in a picture. -scrape-expect
// bypass checks the opposite (the pre-fix proof). The easy modes have no
// secret by design (their strength is the proof of work) and are reported.

// svgGlyphs mirrors ccv2/engine.lua GLYPHS (the scraper knows the font).
var svgGlyphs = map[byte][7]string{
	'A': {"01110", "10001", "10001", "11111", "10001", "10001", "10001"},
	'C': {"01111", "10000", "10000", "10000", "10000", "10000", "01111"},
	'E': {"11111", "10000", "10000", "11110", "10000", "10000", "11111"},
	'F': {"11111", "10000", "10000", "11110", "10000", "10000", "10000"},
	'H': {"10001", "10001", "10001", "11111", "10001", "10001", "10001"},
	'K': {"10001", "10010", "10100", "11000", "10100", "10010", "10001"},
	'L': {"10000", "10000", "10000", "10000", "10000", "10000", "11111"},
	'M': {"10001", "11011", "10101", "10101", "10001", "10001", "10001"},
	'N': {"10001", "11001", "10101", "10011", "10001", "10001", "10001"},
	'P': {"11110", "10001", "10001", "11110", "10000", "10000", "10000"},
	'R': {"11110", "10001", "10001", "11110", "10100", "10010", "10001"},
	'T': {"11111", "00100", "00100", "00100", "00100", "00100", "00100"},
	'X': {"10001", "10001", "01010", "00100", "01010", "10001", "10001"},
	'Y': {"10001", "10001", "01010", "00100", "00100", "00100", "00100"},
	'3': {"11110", "00001", "00001", "01110", "00001", "00001", "11110"},
	'4': {"00010", "00110", "01010", "10010", "11111", "00010", "00010"},
}

var svgRect = regexp.MustCompile(`<rect x="(\d+)" y="(\d+)" width="6" height="6"`)

// decodeSVGCaptcha reads the 4 characters back from the page's SVG cells
// (cell = 6x7 grid step, jitter 0..2, glyph origin 14+46i+0..6, 10+0..8).
func decodeSVGCaptcha(page string) string {
	var points [4][][2]int
	for _, match := range svgRect.FindAllStringSubmatch(page, -1) {
		x, _ := strconv.Atoi(match[1])
		y, _ := strconv.Atoi(match[2])
		if index := (x - 14) / 46; x >= 14 && index < 4 {
			points[index] = append(points[index], [2]int{x, y})
		}
	}
	text := ""
	for index, cells := range points {
		best, bestScore := byte('?'), math.MaxInt
		for ox := 0; ox <= 6; ox++ {
			for oy := 0; oy <= 8; oy++ {
				var grid [7][5]bool
				for _, p := range cells {
					column, row := (p[0]-14-46*index-ox)/6, (p[1]-10-oy)/7
					if column >= 0 && column < 5 && row >= 0 && row < 7 {
						grid[row][column] = true
					}
				}
				for character, rows := range svgGlyphs {
					score := 0
					for row := 0; row < 7; row++ {
						for column := 0; column < 5; column++ {
							if (rows[row][column] == '1') != grid[row][column] {
								score++
							}
						}
					}
					if score < bestScore {
						best, bestScore = character, score
					}
				}
			}
		}
		text += string(best)
	}
	return text
}

func scrapeAnswer(mode, page string) string {
	if mode == "captcha" {
		return decodeSVGCaptcha(page)
	}
	return answerFor(mode, page)
}

func scrapeRun() {
	want := 403
	note := "只读页面、自己算工作量证明、不执行页面脚本的客户端被拒绝（答案只在图片里）"
	if *scrapeWant == "bypass" {
		want, note = 303, "修前：只读页面的客户端能从标记里读出答案并通过"
	}
	for index, group := range []struct{ id, name string }{{"S10000", "g10000"}, {"S10003", "g10003"}, {"S2", "g2"}, {"S4", "g4"}} {
		H := host(group.name)
		c := newClient(fmt.Sprintf("127.0.0.%d", 60+index))
		page := c.get(H, "/p?x=1")
		mode := page.header.Get("X-Cdnca-Challenge")
		answer := scrapeAnswer(mode, page.body)
		time.Sleep(600 * time.Millisecond)
		result := verify(c, H, "token="+token(page.body)+"&answer="+answer+"&pow="+pagePoW(page.body))
		check(group.id+"-"+mode, want, result.status, note+"（读出 "+strconv.Quote(answer)+"）")
	}
	for index, group := range []struct{ name, mode string }{{"g10004", "easy_click"}, {"g10005", "easy_slider"}} {
		H := host(group.name)
		c := newClient(fmt.Sprintf("127.0.0.%d", 70+index))
		page := c.get(H, "/p?x=1").body
		time.Sleep(600 * time.Millisecond)
		status := verify(c, H, "token="+token(page)+"&answer="+answerFor(group.mode, page)+"&pow="+pagePoW(page)).status
		fmt.Printf("INFO scrape %s status=%d（简单模式没有秘密，防护强度等于工作量证明）\n", group.mode, status)
	}
}
