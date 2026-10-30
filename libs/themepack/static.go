package themepack

import (
	"bytes"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/cdnca/cdnca/libs/edgeconfig/errorpagestyle"
	"golang.org/x/net/html"
)

// Static page and brand image rules shared by the control plane (error page
// system, brand assets) and the market review worker, so a theme accepted at
// review is exactly a theme the control plane renders.

// MaxStaticPageBytes bounds one rendered page (errorpagecontrol
// MaxEdgeResourceBytes).
const MaxStaticPageBytes = 1 << 20

// MaxBrandAssetBytes bounds one brand image.
const MaxBrandAssetBytes = 2 << 20

// Node default error page categories a theme renders.
const (
	CategoryEdgeConnect = "edge_connect"
	// CategoryEdgeRoute pages are the node's own block responses (403 WAF /
	// ACL / ban, 429 CC / rate limit; migration 471).
	CategoryEdgeRoute   = "edge_route"
	CategoryNoHost      = "no_host"
	CategoryUnknownSite = "unknown_site"
)

// ErrUnsafePage: the page is not static HTML of the allowed shape.
var ErrUnsafePage = errors.New("unsafe static page")

// TemplateMarkers are server-side template markers no static page may carry.
var TemplateMarkers = [][]byte{
	[]byte("{{"), []byte("}}"), []byte("{%"), []byte("%}"),
	[]byte("<%"), []byte("%>"), []byte("${"), []byte("<!--#"),
}

// BrandSlots lists every brand slot in display order.
var BrandSlots = []string{"favicon", "logo", "login_ad", "logo_dark", "login_background", "app_icon"}

// ValidBrandSlot reports a known brand slot.
func ValidBrandSlot(slot string) bool {
	for _, known := range BrandSlots {
		if slot == known {
			return true
		}
	}
	return false
}

// ValidBrandMedia reports whether slot accepts mimeType.
func ValidBrandMedia(slot, mimeType string) bool {
	switch slot {
	case "favicon":
		return mimeType == "image/x-icon" || mimeType == "image/vnd.microsoft.icon" || mimeType == "image/png"
	case "logo", "logo_dark", "app_icon":
		return mimeType == "image/png"
	case "login_ad", "login_background":
		return mimeType == "image/jpeg"
	}
	return false
}

// ValidBrandBody checks the body's magic bytes against mimeType.
func ValidBrandBody(slot, mimeType string, body []byte) bool {
	if len(body) == 0 || len(body) > MaxBrandAssetBytes {
		return false
	}
	switch {
	case mimeType == "image/png":
		return len(body) >= 8 && string(body[:8]) == "\x89PNG\r\n\x1a\n"
	case mimeType == "image/jpeg":
		return len(body) >= 3 && body[0] == 0xff && body[1] == 0xd8 && body[2] == 0xff
	case slot == "favicon" && (mimeType == "image/x-icon" || mimeType == "image/vnd.microsoft.icon"):
		return len(body) >= 4 && body[0] == 0x00 && body[1] == 0x00 && (body[2] == 0x01 || body[2] == 0x02) && body[3] == 0x00
	}
	return false
}

// ValidBrandAsset applies the brand upload checks to an image.
func ValidBrandAsset(slot, mimeType string, body []byte) bool {
	return ValidBrandSlot(slot) && ValidBrandMedia(slot, mimeType) && ValidBrandBody(slot, mimeType, body)
}

// ValidateStaticHTML accepts attribute-free static HTML of the allowed
// elements (uploaded error page assets).
func ValidateStaticHTML(body []byte) error {
	if err := checkStaticBytes(body); err != nil {
		return err
	}
	document, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return ErrUnsafePage
	}
	return inspectStaticHTML(document, nil)
}

// ValidateThemedHTML validates a theme-rendered page (ADR 0007 §7.2): the
// static rule plus one attribute-free <style> directly in <head> whose text is
// in the errorpagestyle canonical grammar, and class attributes that name only
// classes that style declares.
func ValidateThemedHTML(body []byte) error {
	if err := checkStaticBytes(body); err != nil {
		return err
	}
	document, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return ErrUnsafePage
	}
	theme := &themedPage{}
	if err := inspectStaticHTML(document, theme); err != nil {
		return err
	}
	if theme.styles != 1 {
		return ErrUnsafePage
	}
	declared := theme.sheet.Classes()
	for _, class := range theme.classes {
		if errorpagestyle.CheckClassAttribute(class, declared) != nil {
			return ErrUnsafePage
		}
	}
	return nil
}

// ThemeStyleHash is the CSP source of a theme-rendered page's one <style>
// (errorpagestyle.SourceHash of its text), the value the node puts in the
// page's style-src (agents/edge-agent errorpage, dynamic routing D9); ""
// for a page that is not valid themed HTML (uploaded static pages have no
// style).
func ThemeStyleHash(body []byte) string {
	if ValidateThemedHTML(body) != nil {
		return ""
	}
	document, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return ""
	}
	var style string
	var find func(*html.Node)
	find = func(node *html.Node) {
		if node.Type == html.ElementNode && node.Data == "style" && node.FirstChild != nil {
			style = node.FirstChild.Data
			return
		}
		for child := node.FirstChild; child != nil && style == ""; child = child.NextSibling {
			find(child)
		}
	}
	find(document)
	if style == "" {
		return ""
	}
	return errorpagestyle.SourceHash(style)
}

func checkStaticBytes(body []byte) error {
	if len(body) == 0 || len(body) > MaxStaticPageBytes || !utf8.Valid(body) || bytes.IndexByte(body, 0) >= 0 {
		return ErrUnsafePage
	}
	for _, marker := range TemplateMarkers {
		if bytes.Contains(body, marker) {
			return ErrUnsafePage
		}
	}
	return nil
}

type themedPage struct {
	styles  int
	sheet   errorpagestyle.Sheet
	classes []string
}

func (theme *themedPage) acceptStyle(node *html.Node) error {
	theme.styles++
	if theme.styles > 1 || len(node.Attr) != 0 || node.Parent == nil || node.Parent.Data != "head" ||
		node.FirstChild == nil || node.FirstChild != node.LastChild || node.FirstChild.Type != html.TextNode {
		return ErrUnsafePage
	}
	sheet, err := errorpagestyle.Parse(node.FirstChild.Data)
	if err != nil {
		return ErrUnsafePage
	}
	theme.sheet = sheet
	return nil
}

var allowedStaticElements = map[string]struct{}{
	"html": {}, "head": {}, "body": {}, "title": {}, "main": {},
	"section": {}, "article": {}, "header": {}, "footer": {}, "div": {},
	"p": {}, "h1": {}, "h2": {}, "h3": {}, "h4": {}, "h5": {}, "h6": {},
	"span": {}, "strong": {}, "em": {}, "b": {}, "i": {}, "small": {},
	"br": {}, "hr": {}, "ul": {}, "ol": {}, "li": {}, "dl": {}, "dt": {},
	"dd": {}, "pre": {}, "code": {}, "blockquote": {}, "table": {},
	"thead": {}, "tbody": {}, "tfoot": {}, "tr": {}, "th": {}, "td": {}, "caption": {},
}

func inspectStaticHTML(document *html.Node, theme *themedPage) error {
	var inspect func(*html.Node) error
	inspect = func(node *html.Node) error {
		switch node.Type {
		case html.DocumentNode, html.TextNode:
		case html.DoctypeNode:
			if strings.ToLower(node.Data) != "html" || len(node.Attr) != 0 {
				return ErrUnsafePage
			}
		case html.ElementNode:
			if node.Namespace != "" {
				return ErrUnsafePage
			}
			if theme != nil && node.Data == "style" {
				return theme.acceptStyle(node)
			}
			if _, ok := allowedStaticElements[strings.ToLower(node.Data)]; !ok {
				return ErrUnsafePage
			}
			for _, attribute := range node.Attr {
				if theme == nil || attribute.Namespace != "" || attribute.Key != "class" {
					return ErrUnsafePage
				}
				theme.classes = append(theme.classes, attribute.Val)
			}
		default:
			return ErrUnsafePage
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			if err := inspect(child); err != nil {
				return err
			}
		}
		return nil
	}
	return inspect(document)
}
