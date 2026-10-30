package sitetheme

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// cdnca.site-theme/v1: a declarative plugin naming one of the layout
// renderers apps/control-site ships, with whitelisted tokens (colors,
// radius, font), illustrations by slot and default content. It carries no
// script and changes no CSP. Moved unchanged from controlsite/themes.go.
const V1MaxImages = 64

var (
	// themeIDPattern: official.site-<name>, custom.<name>, market.<plugin id>.
	themeIDPattern  = regexp.MustCompile(`^(official\.site-[a-z][a-z0-9-]{0,31}|custom\.[a-z][a-z0-9-]{0,31}|market\.[a-z][a-z0-9]*(?:[.-][a-z0-9]+)+)$`)
	versionPattern  = regexp.MustCompile(`^(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})$`)
	slotPattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,47}$`)
	themeRef        = regexp.MustCompile(`^theme:([a-z0-9][a-z0-9-]{0,47})$`)
	colorPattern    = regexp.MustCompile(`^#[0-9a-f]{6}$`)
	radiusPattern   = regexp.MustCompile(`^(?:[0-9]|1[0-9]|2[0-4])px$`)
	fontPattern     = regexp.MustCompile(`^[\p{L}\p{N} ,"'-]{1,200}$`)
	themeLocales    = map[string]bool{"zh-CN": true, "zh-TW": true, "en-US": true}
	layoutRenderers = map[string]bool{"jidun": true, "xmf": true}
)

// V1Theme is a cdnca.site-theme/v1 package.
type V1Theme struct {
	Schema      string                `json:"schema"`
	ID          string                `json:"id"`
	Version     string                `json:"version"`
	Name        I18nText              `json:"name"`
	Description I18nText              `json:"description,omitempty"`
	Layout      string                `json:"layout"`
	Tokens      map[string]string     `json:"tokens,omitempty"`
	Images      map[string]ThemeImage `json:"images,omitempty"`
	Seed        SeedContent           `json:"seed"`
}

type ThemeImage struct {
	MIMEType   string `json:"mime_type"`
	BodyBase64 string `json:"body_base64"`
}

// TokenSpec is one whitelisted token of a layout: the CSS custom property the
// website sets (--site-<name>) and the layout's own value when unset.
type TokenSpec struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Default string `json:"default"`
}

// layoutTokens lists, per layout, the tokens its stylesheet reads; the
// defaults are the values the layout used before plugins existed.
var layoutTokens = map[string][]TokenSpec{
	"jidun": {
		{"colorPrimary", "color", "#2b78f6"}, {"colorPrimaryDeep", "color", "#0058e7"}, {"colorAccent", "color", "#22d0ff"},
		{"colorHeading", "color", "#253554"}, {"colorText", "color", "#6b7592"}, {"colorMuted", "color", "#9fa6b1"},
		{"colorDark", "color", "#0a1f4f"}, {"colorPrimaryVivid", "color", "#1a5dff"}, {"colorTextBody", "color", "#566073"},
		{"colorTextSoft", "color", "#5a6885"}, {"colorSuccess", "color", "#00c853"}, {"borderRadius", "length", "4px"},
		{"fontFamily", "font_family", `"PingFang SC", "Microsoft YaHei", sans-serif`},
	},
	"xmf": {
		{"colorPrimary", "color", "#f6821f"}, {"colorPrimaryDeep", "color", "#e06d0b"}, {"colorPrimarySoft", "color", "#fff7ed"},
		{"colorHeading", "color", "#0f172a"}, {"colorText", "color", "#171717"}, {"colorMuted", "color", "#64748b"},
		{"colorBorder", "color", "#dfe5ee"}, {"borderRadius", "length", "6px"},
		{"fontFamily", "font_family", `Arial, "PingFang SC", "Microsoft YaHei", "Noto Sans SC", sans-serif`},
	},
}

// LayoutTokens returns the token whitelist of a layout.
func LayoutTokens(layout string) []TokenSpec {
	return append([]TokenSpec(nil), layoutTokens[layout]...)
}

// LayoutToken returns one whitelisted token of a layout.
func LayoutToken(layout, name string) (TokenSpec, bool) {
	for _, spec := range layoutTokens[layout] {
		if spec.Name == name {
			return spec, true
		}
	}
	return TokenSpec{}, false
}

// ValidLayout reports whether a layout renderer exists.
func ValidLayout(layout string) bool { return layoutRenderers[layout] }

// ValidV1ID reports whether a v1 theme id is well formed.
func ValidV1ID(id string) bool { return len(id) <= 128 && themeIDPattern.MatchString(id) }

// ValidToken reports whether value is accepted for a layout's token.
func ValidToken(layout, name, value string) bool {
	spec, ok := LayoutToken(layout, name)
	if !ok {
		return false
	}
	switch spec.Kind {
	case "color":
		return colorPattern.MatchString(value)
	case "length":
		return radiusPattern.MatchString(value)
	case "font_family":
		return fontPattern.MatchString(value) && strings.TrimSpace(value) == value
	}
	return false
}

func validI18n(text I18nText, max int, required bool, field string) error {
	if len(text) == 0 {
		if required {
			return invalid("i18n_required", field)
		}
		return nil
	}
	if text["zh-CN"] == "" {
		return invalid("i18n_required", field+".zh-CN")
	}
	for locale, value := range text {
		if !themeLocales[locale] || value == "" || utf8.RuneCountInString(value) > max || strings.TrimSpace(value) != value ||
			markup.MatchString(value) || strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return invalid("i18n_value", field+"."+locale)
		}
	}
	return nil
}

// checkEnvelope applies the checks shared by every schema: size, UTF-8 and
// duplicate keys / trailing data.
func checkEnvelope(raw []byte) error {
	if len(raw) == 0 || len(raw) > MaxContentBytes || !utf8.Valid(raw) {
		return invalid("package_size", "")
	}
	if err := edgeconfig.RejectDuplicateJSONKeys(raw); err != nil {
		return invalid("package_json", "")
	}
	return nil
}

// decodeStrict decodes one JSON value, refusing unknown fields and trailing
// data.
func decodeStrict(raw []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return invalid("package_json", "")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return invalid("package_json", "")
	}
	return nil
}

// ParseV1 decodes and validates a cdnca.site-theme/v1 package and its
// illustrations. It rejects unknown fields, duplicate keys, trailing data,
// images that are not embedded (or are unsafe SVG), and seed content that
// references anything but the package's own image slots. This is exactly
// what controlsite.ParseTheme did before the move.
func ParseV1(raw []byte) (V1Theme, []Image, error) {
	if err := checkEnvelope(raw); err != nil {
		return V1Theme{}, nil, err
	}
	var pkg V1Theme
	if err := decodeStrict(raw, &pkg); err != nil {
		return V1Theme{}, nil, err
	}
	images, err := pkg.validate()
	if err != nil {
		return V1Theme{}, nil, err
	}
	return pkg, images, nil
}

func (pkg V1Theme) validate() ([]Image, error) {
	switch {
	case pkg.Schema != SchemaV1:
		return nil, invalid("schema", "schema")
	case !ValidV1ID(pkg.ID):
		return nil, invalid("id", "id")
	case !versionPattern.MatchString(pkg.Version):
		return nil, invalid("version", "version")
	case !layoutRenderers[pkg.Layout]:
		return nil, invalid("layout", "layout")
	}
	if err := validI18n(pkg.Name, 64, true, "name"); err != nil {
		return nil, err
	}
	if err := validI18n(pkg.Description, 512, false, "description"); err != nil {
		return nil, err
	}
	for name, value := range pkg.Tokens {
		if !ValidToken(pkg.Layout, name, value) {
			return nil, invalid("token", "tokens."+name)
		}
	}
	if len(pkg.Images) > V1MaxImages {
		return nil, invalid("images", "images")
	}
	slots := make([]string, 0, len(pkg.Images))
	for slot := range pkg.Images {
		slots = append(slots, slot)
	}
	sort.Strings(slots)
	images := make([]Image, 0, len(slots))
	known := map[string]bool{}
	for _, slot := range slots {
		image := pkg.Images[slot]
		field := "images." + slot
		if !slotPattern.MatchString(slot) {
			return nil, invalid("image_slot", field)
		}
		body, err := base64.StdEncoding.Strict().DecodeString(image.BodyBase64)
		if slot == PreviewSlot {
			// The theme card's screenshot: raster only, at most PreviewMaxBytes.
			if err != nil || len(body) == 0 {
				return nil, invalid("preview", field)
			}
			preview, err := checkPreview(body, image.MIMEType, field)
			if err != nil {
				return nil, err
			}
			images = append(images, *preview)
			known[slot] = true
			continue
		}
		if err != nil || SniffImage(image.MIMEType, body) == "" {
			// Not embedded, not an image of its declared type, or an SVG
			// with script, handlers or external references.
			return nil, invalid("image_body", field)
		}
		sum := sha256.Sum256(body)
		images = append(images, Image{Slot: slot, MIMEType: image.MIMEType, SHA256: hex.EncodeToString(sum[:]), Body: body})
		known[slot] = true
	}
	if !ValidateSeed(pkg.Seed, known) {
		return nil, invalid("seed", "seed")
	}
	return images, nil
}
