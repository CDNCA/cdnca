package sitetheme

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The website content model of cdnca.site-theme/v1 (the seed a v1 plugin
// carries and the content controlsite stores). Moved here unchanged from
// services/control-api/internal/controlsite (model.go / validate.go).

// I18nText maps a locale to text; zh-CN is required.
type I18nText map[string]string

// LayoutContent is the part of the content bound to one layout: its links
// point at that layout's pages, and its sections are that layout's blocks.
type LayoutContent struct {
	Nav     []NavItem `json:"nav"`
	Actions []Link    `json:"actions"`
	Footer  Footer    `json:"footer"`
	Pages   []Page    `json:"pages"`
}

// SeedContent is a plugin's default content: the shared blocks used when an
// installation has no content yet, and the layout blocks filled in where
// the content has none.
type SeedContent struct {
	Brand   Brand   `json:"brand"`
	Contact Contact `json:"contact"`
	LayoutContent
}

type Brand struct {
	Name        string `json:"name"`
	Logo        string `json:"logo"`
	LogoDark    string `json:"logo_dark"`
	Favicon     string `json:"favicon"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Keywords    string `json:"keywords"`
}

// Link: Href is a site path ("/waf/"), an https URL, mailto:, tel:, or one of
// the reserved targets "#login" / "#register" (the console's own sign-in and
// sign-up pages) and "#contact" (the floating contact rail).
type Link struct {
	Label string `json:"label"`
	Href  string `json:"href"`
}

type NavItem struct {
	Label    string     `json:"label"`
	Href     string     `json:"href"`
	Children []NavChild `json:"children"`
}

type NavChild struct {
	Label       string `json:"label"`
	Href        string `json:"href"`
	Icon        string `json:"icon"`
	Title       string `json:"title"`
	Description string `json:"description"`
}

type Footer struct {
	Columns   []FooterColumn `json:"columns"`
	About     string         `json:"about"`
	QRCode    string         `json:"qr_code"`
	Links     []Link         `json:"links"`
	Copyright string         `json:"copyright"`
	Records   []Link         `json:"records"`
}

type FooterColumn struct {
	Title string `json:"title"`
	Links []Link `json:"links"`
}

// Contact is the floating customer-service rail (右侧悬浮客服).
type Contact struct {
	Enabled bool          `json:"enabled"`
	Items   []ContactItem `json:"items"`
}

type ContactItem struct {
	Kind   string `json:"kind"`
	Label  string `json:"label"`
	Detail string `json:"detail"`
	Href   string `json:"href"`
}

type Page struct {
	Key         string    `json:"key"`
	Path        string    `json:"path"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Sections    []Section `json:"sections"`
}

// Section is one block of a page. Type names the layout block ("hero",
// "pricing", "features", "faq", "cta", "timeline", "legal", ...). The fields
// are shared: a block uses the ones it needs.
type Section struct {
	Type     string   `json:"type"`
	Badge    string   `json:"badge"`
	Title    string   `json:"title"`
	Accent   string   `json:"accent"`
	Subtitle string   `json:"subtitle"`
	Body     string   `json:"body"`
	Image    string   `json:"image"`
	Actions  []Link   `json:"actions"`
	Tabs     []Tab    `json:"tabs"`
	Items    []Item   `json:"items"`
	Meta     []string `json:"meta"`
	// Source (fix-sitepricing) of a plan block ("plans"/"pricing"): "" or
	// "packages" lists the platform's purchasable packages, "manual" keeps
	// the items edited here.
	Source string `json:"source,omitempty"`
}

type Tab struct {
	Label    string `json:"label"`
	Subtitle string `json:"subtitle"`
	Icon     string `json:"icon"`
	Items    []Item `json:"items"`
}

// Item is a card, plan, list entry, FAQ, timeline entry or slide.
type Item struct {
	Kind     string   `json:"kind"`
	Badge    string   `json:"badge"`
	Title    string   `json:"title"`
	Accent   string   `json:"accent"`
	Subtitle string   `json:"subtitle"`
	Body     string   `json:"body"`
	Value    string   `json:"value"`
	Unit     string   `json:"unit"`
	Image    string   `json:"image"`
	Icon     string   `json:"icon"`
	Date     string   `json:"date"`
	Featured bool     `json:"featured"`
	Points   []string `json:"points"`
	Specs    []Spec   `json:"specs"`
	Actions  []Link   `json:"actions"`
}

type Spec struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

var (
	assetRef     = regexp.MustCompile(`^asset:([0-9a-f]{64})$`)
	pageKey      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	pagePath     = regexp.MustCompile(`^/(?:[A-Za-z0-9_-][A-Za-z0-9._-]{0,63}/?)*$`)
	sectionType  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	iconName     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	sitePath     = regexp.MustCompile(`^/(?:[A-Za-z0-9._~%-]+/?)*(?:\?[A-Za-z0-9._~%=&-]*)?(?:#[A-Za-z0-9_-]*)?$`)
	anchorHref   = regexp.MustCompile(`^#[a-z][a-z0-9-]{0,31}$`)
	externalHref = regexp.MustCompile(`^(?:https://[A-Za-z0-9.-]+(?::[0-9]{1,5})?(?:/[^\s<>"'\\]*)?|mailto:[^\s<>"'@\\]+@[A-Za-z0-9.-]+|tel:\+?[0-9 ()-]{3,32})$`)
	// The website prints every value as text; refusing tag-like input is
	// defence in depth, not escaping.
	markup = regexp.MustCompile(`<[A-Za-z/!?]`)
)

// Paths the controller already serves; a website page may not shadow them.
var reservedPrefixes = []string{"/dashboard", "/operator", "/console", "/v1", "/api", "/auth", "/control", "/public",
	"/portal", "/installation", "/activation", "/payments", "/downloads", "/assets", "/site", "/health", "/healthz",
	"/runtime-config.js"}

var reservedHrefs = map[string]bool{"#login": true, "#register": true, "#contact": true}

type limits struct{ short, long int }

var (
	short = limits{0, 120}
	mid   = limits{0, 400}
	long  = limits{0, 8000}
)

// validator collects the uploaded image digests ("asset:<sha256>") a value
// references. Plugin images ("theme:<slot>") are accepted by slot name; with
// themeSlots set (a plugin's seed) only those slots are.
type validator struct {
	ok         bool
	refs       map[string]bool
	themeSlots map[string]bool
}

func (v *validator) text(value string, limit limits) {
	if !v.ok {
		return
	}
	n := utf8.RuneCountInString(value)
	if !utf8.ValidString(value) || n < limit.short || n > limit.long || markup.MatchString(value) {
		v.ok = false
		return
	}
	for _, r := range value {
		if r == '\n' && limit.long >= long.long {
			continue
		}
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			v.ok = false
			return
		}
	}
}

func (v *validator) image(value string) {
	if value == "" || !v.ok {
		return
	}
	if slot := themeRef.FindStringSubmatch(value); slot != nil {
		v.ok = v.themeSlots == nil || v.themeSlots[slot[1]]
		return
	}
	match := assetRef.FindStringSubmatch(value)
	if match == nil {
		v.ok = false
		return
	}
	v.refs[match[1]] = true
}

func (v *validator) href(value string) {
	if !v.ok || value == "" || reservedHrefs[value] || anchorHref.MatchString(value) || externalHref.MatchString(value) {
		return
	}
	if !sitePath.MatchString(value) || strings.Contains(value, "..") || strings.HasPrefix(value, "//") || len(value) > 512 {
		v.ok = false
	}
}

func (v *validator) count(n, max int) {
	if n > max {
		v.ok = false
	}
}

func (v *validator) links(values []Link, max int) {
	v.count(len(values), max)
	for _, link := range values {
		v.text(link.Label, short)
		v.href(link.Href)
	}
}

func (v *validator) icon(value string) {
	if value == "" || iconName.MatchString(value) {
		return
	}
	if !assetRef.MatchString(value) && !themeRef.MatchString(value) {
		v.ok = false
		return
	}
	v.image(value)
}

func (v *validator) item(item Item) {
	for _, value := range []string{item.Kind, item.Badge, item.Title, item.Accent, item.Value, item.Unit, item.Date} {
		v.text(value, short)
	}
	v.text(item.Subtitle, mid)
	v.text(item.Body, long)
	v.image(item.Image)
	v.icon(item.Icon)
	v.count(len(item.Points), 40)
	for _, point := range item.Points {
		v.text(point, mid)
	}
	v.count(len(item.Specs), 60)
	for _, spec := range item.Specs {
		v.text(spec.Label, short)
		v.text(spec.Value, mid)
	}
	v.links(item.Actions, 4)
}

func (v *validator) section(section Section) {
	if !sectionType.MatchString(section.Type) || (section.Source != "" && section.Source != "packages" && section.Source != "manual") {
		v.ok = false
		return
	}
	for _, value := range []string{section.Badge, section.Title, section.Accent} {
		v.text(value, short)
	}
	v.text(section.Subtitle, mid)
	v.text(section.Body, long)
	v.image(section.Image)
	v.links(section.Actions, 4)
	v.count(len(section.Meta), 40)
	for _, value := range section.Meta {
		v.text(value, short)
	}
	v.count(len(section.Tabs), 12)
	for _, tab := range section.Tabs {
		v.text(tab.Label, short)
		v.text(tab.Subtitle, short)
		v.icon(tab.Icon)
		v.count(len(tab.Items), 60)
		for _, item := range tab.Items {
			v.item(item)
		}
	}
	v.count(len(section.Items), 120)
	for _, item := range section.Items {
		v.item(item)
	}
}

func (v *validator) brand(value Brand) {
	v.text(value.Name, limits{1, 40})
	v.text(value.Title, short)
	v.text(value.Description, mid)
	v.text(value.Keywords, mid)
	v.image(value.Logo)
	v.image(value.LogoDark)
	v.image(value.Favicon)
}

func (v *validator) contact(value Contact) {
	v.count(len(value.Items), 8)
	for _, item := range value.Items {
		v.text(item.Kind, short)
		v.text(item.Label, limits{1, 20})
		v.text(item.Detail, mid)
		v.href(item.Href)
	}
}

// layout checks one layout's navigation, footer and pages; the pages must
// include the root page "/".
func (v *validator) layout(value LayoutContent) {
	v.count(len(value.Nav), 10)
	for _, item := range value.Nav {
		v.text(item.Label, limits{1, 40})
		v.href(item.Href)
		v.count(len(item.Children), 12)
		for _, child := range item.Children {
			v.text(child.Label, limits{1, 40})
			v.href(child.Href)
			v.icon(child.Icon)
			v.text(child.Title, short)
			v.text(child.Description, mid)
		}
	}
	v.links(value.Actions, 3)
	v.count(len(value.Footer.Columns), 6)
	for _, column := range value.Footer.Columns {
		v.text(column.Title, short)
		v.links(column.Links, 12)
	}
	v.text(value.Footer.About, mid)
	v.image(value.Footer.QRCode)
	v.links(value.Footer.Links, 30)
	v.text(value.Footer.Copyright, mid)
	v.links(value.Footer.Records, 6)
	v.count(len(value.Pages), 40)
	keys, paths, root := map[string]bool{}, map[string]bool{}, false
	for _, page := range value.Pages {
		if !pageKey.MatchString(page.Key) || !validPagePath(page.Path) || keys[page.Key] || paths[page.Path] {
			v.ok = false
			return
		}
		keys[page.Key], paths[page.Path] = true, true
		root = root || page.Path == "/"
		v.text(page.Title, limits{1, 120})
		v.text(page.Description, mid)
		v.count(len(page.Sections), 30)
		for _, section := range page.Sections {
			v.section(section)
		}
	}
	v.ok = v.ok && root
}

func validPagePath(value string) bool {
	if value == "/" {
		return true
	}
	if len(value) > 128 || !pagePath.MatchString(value) || strings.Contains(value, "..") {
		return false
	}
	lower := strings.ToLower(value)
	for _, prefix := range reservedPrefixes {
		if lower == prefix || strings.HasPrefix(lower, prefix+"/") || strings.HasPrefix(lower, prefix+".") {
			return false
		}
	}
	return true
}

// ValidateContent checks stored website content (controlsite's draft): the
// shared brand and contact blocks and, per layout renderer, its layout
// content. It returns the uploaded asset digests ("asset:<sha256>") the
// content references. A layout key that is not a known renderer fails.
func ValidateContent(brand Brand, contact Contact, layouts map[string]LayoutContent) (map[string]bool, bool) {
	v := &validator{ok: true, refs: map[string]bool{}}
	v.brand(brand)
	v.contact(contact)
	for layout, content := range layouts {
		if !layoutRenderers[layout] {
			return nil, false
		}
		v.layout(content)
	}
	return v.refs, v.ok
}

// ValidateSeed checks a v1 plugin's default content: valid content whose
// images are only "theme:<slot>" references to the plugin's own slots.
func ValidateSeed(seed SeedContent, slots map[string]bool) bool {
	v := &validator{ok: true, refs: map[string]bool{}, themeSlots: slots}
	v.brand(seed.Brand)
	v.contact(seed.Contact)
	v.layout(seed.LayoutContent)
	return v.ok && len(v.refs) == 0
}

// ValidHref reports whether a content link target is accepted.
func ValidHref(value string) bool {
	v := &validator{ok: true, refs: map[string]bool{}}
	v.href(value)
	return v.ok
}
