package themepack

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/libs/edgeconfig/errorpagestyle"
	"golang.org/x/net/html"
)

// RenderedAsset is a brand image a package carries.
type RenderedAsset struct {
	Slot     string
	MIMEType string
	SHA256   string
	Body     []byte
}

// ErrorPage is a node default error page the theme renders (static HTML).
type ErrorPage struct {
	Category string
	Status   int
	SHA256   string
	Body     []byte
}

// Rendered is everything the control plane serves or publishes for one
// package. CSS and JSON are content-addressed: theme.<CSSSHA256>.css and
// theme.<JSONSHA256>.json.
type Rendered struct {
	Package       Package
	Raw           []byte
	PackageSHA256 string
	Tokens        map[string]any
	// RoleTokens are the tokens_by_role overrides (role → token → value).
	RoleTokens map[string]map[string]any
	CSS        []byte
	CSSSHA256  string
	JSON       []byte
	JSONSHA256 string
	Assets     []RenderedAsset
	ErrorPages []ErrorPage
	StyleText  string

	email     compiledTemplate
	errorPage compiledTemplate
	declared  map[string]struct{}
}

// DefaultErrorPages are the node default pages a theme renders: the edge's
// own connect failures, its own block responses (edge_route 403/429: the
// node's security modules refused the request; sec-followup P13) and the
// requests no site answers. A page carries Chinese and English. Origin responses
// and per-site rules stay with the error page system (ADR 0007 §7.3).
var DefaultErrorPages = []struct {
	Category string
	Status   int
	Title    string
	Message  string
}{
	{CategoryEdgeConnect, 502, "502 网关错误", "节点暂时无法连接源站，请稍后重试。"},
	{CategoryEdgeConnect, 503, "503 服务暂不可用", "源站暂时无法提供服务，请稍后重试。"},
	{CategoryEdgeConnect, 504, "504 网关超时", "节点等待源站响应超时，请稍后重试。"},
	{CategoryEdgeRoute, 403, "403 访问被拦截 / Access blocked",
		"您的请求触发了站点的安全策略，已被拦截。如有疑问请联系站点管理员。 Your request was blocked by the site's security policy. Contact the site administrator if you believe this is a mistake."},
	{CategoryEdgeRoute, 429, "429 请求过于频繁 / Too many requests",
		"您的请求过于频繁，请稍后重试。 Too many requests. Please wait a moment and try again."},
	{CategoryNoHost, 400, "400 请求无效", "请求缺少有效的 Host，节点无法处理。"},
	{CategoryUnknownSite, 404, "404 站点不存在", "该域名未接入本平台或尚未生效。"},
}

var (
	errorPageVariables = templateVariables{"status": false, "title": false, "message": false, "footer_text": false}
	emailVariables     = templateVariables{"subject": false, "lines": true, "footer_text": false}
)

type renderedBrand struct {
	URL      string `json:"url"`
	MIMEType string `json:"mime_type"`
	SHA256   string `json:"sha256"`
}

// renderedLayout.BrandName is omitted when the package sets none, so
// documents of packages without it render byte for byte as before.
type renderedLayout struct {
	LoginLayout    string       `json:"login_layout"`
	Sidebar        string       `json:"sidebar"`
	HeaderLinks    []HeaderLink `json:"header_links"`
	FooterText     I18nText     `json:"footer_text"`
	BrandName      I18nText     `json:"brand_name,omitempty"`
	UserHomeBlocks []string     `json:"user_home_blocks"`
	Look           string       `json:"look"`
	Motion         string       `json:"motion"`
}

type renderedDocument struct {
	Schema        string         `json:"schema"`
	ID            string         `json:"id"`
	Version       string         `json:"version"`
	PackageSHA256 string         `json:"package_sha256"`
	Name          I18nText       `json:"name"`
	AntdTokens    map[string]any `json:"antd_tokens"`
	// AntdTokensByRole holds only the antd tokens a role overrides.
	AntdTokensByRole map[string]map[string]any `json:"antd_tokens_by_role,omitempty"`
	CSSVariables     map[string]string         `json:"css_variables"`
	Layout           renderedLayout            `json:"layout"`
	Brand            map[string]renderedBrand  `json:"brand"`
}

// Render parses raw and renders it. Any failure is a *ValidationError.
func Render(raw []byte) (Rendered, error) {
	pkg, err := Parse(raw)
	if err != nil {
		return Rendered{}, err
	}
	tokens, err := resolveTokens(pkg.Tokens)
	if err != nil {
		return Rendered{}, err
	}
	roleTokens, err := resolveRoleTokens(pkg.TokensByRole)
	if err != nil {
		return Rendered{}, err
	}
	digest := sha256.Sum256(raw)
	result := Rendered{Package: pkg, Raw: bytes.Clone(raw), PackageSHA256: hex.EncodeToString(digest[:]), Tokens: tokens, RoleTokens: roleTokens}
	if result.Assets, err = renderAssets(pkg.BrandSlots); err != nil {
		return Rendered{}, err
	}
	result.CSS = renderCSS(tokens, roleTokens)
	result.CSSSHA256 = digestHex(result.CSS)
	if result.JSON, err = renderJSON(pkg, result); err != nil {
		return Rendered{}, err
	}
	result.JSONSHA256 = digestHex(result.JSON)
	templates := pkg.Templates
	if templates == nil {
		templates = defaultTemplates()
	}
	if err := result.renderTemplates(*templates); err != nil {
		return Rendered{}, err
	}
	return result, nil
}

func digestHex(body []byte) string {
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}

func renderAssets(slots map[string]BrandSlot) ([]RenderedAsset, error) {
	names := make([]string, 0, len(slots))
	for name := range slots {
		names = append(names, name)
	}
	sort.Strings(names)
	assets := make([]RenderedAsset, 0, len(names))
	total := 0
	for _, name := range names {
		slot := slots[name]
		field := "brand_slots." + name
		if !ValidBrandSlot(name) {
			return nil, invalid("brand_slot", field)
		}
		body, err := base64.StdEncoding.Strict().DecodeString(slot.BodyBase64)
		if err != nil || len(body) == 0 || len(body) > MaxAssetSize {
			return nil, invalid("brand_asset", field)
		}
		if !ValidBrandAsset(name, slot.MIMEType, body) {
			return nil, invalid("brand_asset_media", field)
		}
		total += len(body)
		assets = append(assets, RenderedAsset{Slot: name, MIMEType: slot.MIMEType, SHA256: digestHex(body), Body: body})
	}
	if total > MaxPackageSize {
		return nil, invalid("brand_asset", "brand_slots")
	}
	return assets, nil
}

// renderCSS writes only custom properties, each from a validated token, so the
// stylesheet can carry nothing but colors, lengths, numbers, font stacks and
// shadows. A role's overrides follow in their own block, which the SPA
// selects with html[data-cdnca-role].
func renderCSS(tokens map[string]any, roleTokens map[string]map[string]any) []byte {
	var output bytes.Buffer
	writeBlock(&output, ":root[data-cdnca-theme]", cssVariables(tokens))
	for _, role := range themeRoles {
		if overrides := roleTokens[role]; len(overrides) > 0 {
			writeBlock(&output, `:root[data-cdnca-theme][data-cdnca-role="`+role+`"]`, cssVariables(overrides))
		}
	}
	return output.Bytes()
}

func writeBlock(output *bytes.Buffer, selector string, variables map[string]string) {
	names := make([]string, 0, len(variables))
	for name := range variables {
		names = append(names, name)
	}
	sort.Strings(names)
	output.WriteString(selector + " {\n")
	for _, name := range names {
		fmt.Fprintf(output, "  %s: %s;\n", name, variables[name])
	}
	output.WriteString("}\n")
}

// cssVariables renders the tokens present in tokens (all of them for a
// resolved set, only the overrides for a role).
func cssVariables(tokens map[string]any) map[string]string {
	variables := make(map[string]string)
	for _, spec := range tokenSpecs {
		raw, ok := tokens[spec.Name]
		if !ok {
			continue
		}
		value := cssValue(spec, raw)
		variables[CSSVariable(spec.Name)] = value
		// The older names stay as aliases so existing stylesheets keep working.
		for _, name := range spec.CSSVariables {
			variables[name] = value
		}
	}
	return variables
}

// CSSVariable is the shared custom property every front end reads for a
// token: --cdnca-<kebab-case name>, e.g. colorPrimary → --cdnca-color-primary
// (packages/cdnca-ui/src/styles.css).
func CSSVariable(token string) string {
	var output strings.Builder
	output.WriteString("--cdnca-")
	for _, r := range token {
		if r >= 'A' && r <= 'Z' {
			output.WriteByte('-')
			r += 'a' - 'A'
		}
		output.WriteRune(r)
	}
	return output.String()
}

func renderJSON(pkg Package, result Rendered) ([]byte, error) {
	antd := make(map[string]any)
	for _, spec := range tokenSpecs {
		if spec.Antd {
			antd[spec.Name] = result.Tokens[spec.Name]
		}
	}
	var antdByRole map[string]map[string]any
	for role, overrides := range result.RoleTokens {
		for _, spec := range tokenSpecs {
			if value, ok := overrides[spec.Name]; ok && spec.Antd {
				if antdByRole == nil {
					antdByRole = make(map[string]map[string]any)
				}
				if antdByRole[role] == nil {
					antdByRole[role] = make(map[string]any)
				}
				antdByRole[role][spec.Name] = value
			}
		}
	}
	layout := renderedLayout{
		LoginLayout: pkg.Layout.LoginLayout, Sidebar: pkg.Layout.Sidebar,
		HeaderLinks: pkg.Layout.HeaderLinks, FooterText: pkg.Layout.FooterText, BrandName: pkg.Layout.BrandName, UserHomeBlocks: pkg.Layout.UserHome,
		Look: pkg.Layout.Look, Motion: pkg.Layout.Motion,
	}
	if layout.Look == "" {
		layout.Look = "classic"
	}
	if layout.Motion == "" {
		layout.Motion = "off"
	}
	if layout.HeaderLinks == nil {
		layout.HeaderLinks = []HeaderLink{}
	}
	if layout.FooterText == nil {
		layout.FooterText = I18nText{}
	}
	if layout.UserHomeBlocks == nil {
		layout.UserHomeBlocks = append([]string(nil), UserHomeBlocks...)
	}
	brand := make(map[string]renderedBrand, len(result.Assets))
	for _, asset := range result.Assets {
		brand[asset.Slot] = renderedBrand{URL: AssetPath(asset.SHA256), MIMEType: asset.MIMEType, SHA256: asset.SHA256}
	}
	encoded, err := json.Marshal(renderedDocument{
		Schema: RenderedSchema, ID: pkg.ID, Version: pkg.Version, PackageSHA256: result.PackageSHA256,
		Name: pkg.Name, AntdTokens: antd, AntdTokensByRole: antdByRole, CSSVariables: cssVariables(result.Tokens), Layout: layout, Brand: brand,
	})
	if err != nil {
		return nil, invalid("render", "")
	}
	return encoded, nil
}

// Public paths, all same-origin and immutable.
func StylesheetPath(sha string) string { return "/v1/theme/theme." + sha + ".css" }
func TokensPath(sha string) string     { return "/v1/theme/theme." + sha + ".json" }
func AssetPath(sha string) string      { return "/v1/theme/assets/" + sha }

func (result *Rendered) renderTemplates(templates Templates) error {
	sheet := errorpagestyle.Sheet{}
	if len(templates.Styles) == 0 {
		return invalid("style_required", "templates.styles")
	}
	for index, rule := range templates.Styles {
		field := fmt.Sprintf("templates.styles[%d]", index)
		if !errorpagestyle.ValidSelector(rule.Selector) {
			return invalid("style_selector", field+".selector")
		}
		properties := make([]string, 0, len(rule.Declarations))
		for property := range rule.Declarations {
			properties = append(properties, property)
		}
		sort.Strings(properties)
		compiled := errorpagestyle.Rule{Selector: rule.Selector}
		for _, property := range properties {
			value := rule.Declarations[property]
			if name, ok := strings.CutPrefix(value, "token:"); ok {
				if value, ok = tokenStyleValue(result.Tokens, name); !ok {
					return invalid("style_token", field+".declarations."+property)
				}
			}
			if !errorpagestyle.ValidDeclaration(property, value) {
				return invalid("style_value", field+".declarations."+property)
			}
			compiled.Declarations = append(compiled.Declarations, errorpagestyle.Declaration{Property: property, Value: value})
		}
		sheet.Rules = append(sheet.Rules, compiled)
	}
	style, err := errorpagestyle.Render(sheet)
	if err != nil {
		return invalid("style_value", "templates.styles")
	}
	result.StyleText = style
	declared := sheet.Classes()
	errorPage, err := compileTemplate(templates.ErrorPage, errorPageVariables)
	if err != nil {
		return withField(err, "templates.error_page")
	}
	result.errorPage, result.declared = errorPage, declared
	footer := result.Package.Layout.FooterText["zh-CN"]
	for _, page := range DefaultErrorPages {
		body, err := finishPage(errorPage.render(TemplateContext{
			"status": strconv.Itoa(page.Status), "title": page.Title, "message": page.Message, "footer_text": footer,
		}), style, declared, "templates.error_page")
		if err != nil {
			return err
		}
		result.ErrorPages = append(result.ErrorPages, ErrorPage{Category: page.Category, Status: page.Status, SHA256: digestHex(body), Body: body})
	}
	if result.email, err = compileTemplate(templates.Email, emailVariables); err != nil {
		return withField(err, "templates.email")
	}
	if _, err := result.RenderEmail("通知", []string{"示例正文"}); err != nil {
		return err
	}
	return nil
}

// RenderErrorPage renders one page with the theme's error page template, as
// the DefaultErrorPages are (errpage-content: the built-in content of an
// error page slot the theme has no default page for).
func (result Rendered) RenderErrorPage(status, title, message string) ([]byte, error) {
	if len(result.errorPage.nodes) == 0 {
		return nil, invalid("template_missing", "templates.error_page")
	}
	return finishPage(result.errorPage.render(TemplateContext{
		"status": status, "title": title, "message": message, "footer_text": result.Package.Layout.FooterText["zh-CN"],
	}), result.StyleText, result.declared, "templates.error_page")
}

// RenderEmail renders the theme's email layout around a plain-text message.
func (result Rendered) RenderEmail(subject string, lines []string) ([]byte, error) {
	if len(result.email.nodes) == 0 {
		return nil, invalid("template_missing", "templates.email")
	}
	return finishPage(result.email.render(TemplateContext{
		"subject": subject, "lines": lines, "footer_text": result.Package.Layout.FooterText["zh-CN"],
	}), result.StyleText, nil, "templates.email")
}

// finishPage inserts the generated <style> before the template's single
// </head> and validates the page as the edge will.
func finishPage(page, style string, declared map[string]struct{}, field string) ([]byte, error) {
	if strings.Count(page, "</head>") != 1 || strings.Contains(strings.ToLower(page), "<style") {
		return nil, invalid("template_head", field)
	}
	page = strings.Replace(page, "</head>", "<style>"+style+"</style></head>", 1)
	if declared != nil {
		if err := checkDeclaredClasses(page, declared); err != nil {
			return nil, withField(err, field)
		}
	}
	if err := ValidateThemedHTML([]byte(page)); err != nil {
		return nil, invalid("template_unsafe", field)
	}
	return []byte(page), nil
}

func checkDeclaredClasses(page string, declared map[string]struct{}) error {
	tokenizer := html.NewTokenizer(strings.NewReader(page))
	for {
		switch tokenizer.Next() {
		case html.ErrorToken:
			return nil
		case html.StartTagToken, html.SelfClosingTagToken:
			for _, attribute := range tokenizer.Token().Attr {
				if attribute.Key == "class" && errorpagestyle.CheckClassAttribute(attribute.Val, declared) != nil {
					return invalid("class_undeclared", "")
				}
			}
		}
	}
}

func withField(err error, field string) error {
	if validation, ok := err.(*ValidationError); ok && validation.Field == "" {
		return &ValidationError{Code: validation.Code, Field: field}
	}
	return err
}
