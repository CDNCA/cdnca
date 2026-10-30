package sitetheme

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	// AuthStyleMaxCSS caps auth_style.css.
	AuthStyleMaxCSS = 256 << 10
	// AuthStyleMaxImages caps auth_style.images.
	AuthStyleMaxImages = 32
)

var (
	// forbiddenCSS are refused anywhere in auth_style.css (lowercased).
	forbiddenCSS = []string{"</style", "<script", "@import", "javascript:", "vbscript:", "behavior:",
		"-moz-binding", "image-set(", "src("}
	// cssFunction matches the function forms that load or run something,
	// whitespace before "(" included.
	cssFunction = regexp.MustCompile(`(?:expression|image-set|-webkit-image-set|src)\s*\(`)
	dataImage   = regexp.MustCompile(`^data:image/(?:png|jpeg|webp|gif|svg\+xml)(?:;base64)?,`)
)

func parseAuthStyle(wire v2AuthStyle) (*AuthStyle, error) {
	if code := checkAuthCSS(wire.CSS); code != "" {
		return nil, invalid(code, "auth_style.css")
	}
	if len(wire.Images) > AuthStyleMaxImages {
		return nil, invalid("auth_style_images", "auth_style.images")
	}
	style := &AuthStyle{CSS: wire.CSS}
	slots := make([]string, 0, len(wire.Images))
	for slot := range wire.Images {
		slots = append(slots, slot)
	}
	sort.Strings(slots)
	for _, slot := range slots {
		field := "auth_style.images." + slot
		// "preview" is the theme card's screenshot (top-level preview); the
		// control plane keeps both in one image table keyed by slot.
		if !slotPattern.MatchString(slot) || slot == PreviewSlot {
			return nil, invalid("image_slot", field)
		}
		body, err := base64.StdEncoding.Strict().DecodeString(wire.Images[slot])
		mime := ""
		if err == nil {
			mime = detectImage(body)
		}
		if mime == "" {
			return nil, invalid("image_body", field)
		}
		sum := sha256.Sum256(body)
		style.Images = append(style.Images, Image{Slot: slot, MIMEType: mime, SHA256: hex.EncodeToString(sum[:]), Body: body})
	}
	return style, nil
}

// checkAuthCSS returns the error code (without prefix) of unsafe CSS, or "".
// Backslash escapes are refused outright so that no keyword can be spelled
// around the checks.
func checkAuthCSS(css string) string {
	if len(css) > AuthStyleMaxCSS {
		return "auth_style_size"
	}
	if !utf8.ValidString(css) || strings.ContainsRune(css, '\\') {
		return "auth_style_css"
	}
	for _, r := range css {
		if r < 0x20 && r != '\n' && r != '\r' && r != '\t' || r == 0x7f {
			return "auth_style_css"
		}
	}
	lower := strings.ToLower(css)
	for _, fragment := range forbiddenCSS {
		if strings.Contains(lower, fragment) {
			return "auth_style_css"
		}
	}
	if cssFunction.MatchString(lower) {
		return "auth_style_css"
	}
	if adminRoleSelector.MatchString(lower) {
		return "admin_forbidden"
	}
	for rest := lower; ; {
		index := strings.Index(rest, "url(")
		if index < 0 {
			break
		}
		rest = rest[index+4:]
		end := strings.IndexByte(rest, ')')
		if end < 0 {
			return "auth_style_url"
		}
		if !allowedCSSURL(rest[:end]) {
			return "auth_style_url"
		}
		rest = rest[end+1:]
	}
	// A string that names another origin is refused even outside url():
	// some properties take bare strings as URLs.
	if strings.Contains(lower, "://") || strings.Contains(lower, `"//`) || strings.Contains(lower, `'//`) {
		return "auth_style_url"
	}
	return ""
}

// allowedCSSURL accepts a same-origin relative path or a data: image.
func allowedCSSURL(argument string) bool {
	value := strings.Trim(strings.TrimSpace(argument), `"'`)
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	if strings.HasPrefix(value, "data:") {
		return dataImage.MatchString(value)
	}
	if strings.HasPrefix(value, "//") || strings.Contains(value, "..") || strings.ContainsAny(value, `"'`) {
		return false
	}
	return relativeRef(value)
}
