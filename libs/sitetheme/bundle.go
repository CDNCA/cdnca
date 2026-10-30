package sitetheme

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/net/html"
)

const (
	// BundleMaxFiles caps the files of one page bundle.
	BundleMaxFiles = 2000
	// DefaultEntry is the entry page when site_bundle.entry is left out.
	DefaultEntry  = "index.html"
	maxPathLength = 256
)

// BundleExtensions are the file extensions a page bundle may hold.
var BundleExtensions = map[string]bool{"html": true, "css": true, "js": true, "mjs": true, "json": true, "svg": true,
	"png": true, "jpg": true, "jpeg": true, "webp": true, "gif": true, "ico": true, "woff": true, "woff2": true,
	"ttf": true, "txt": true, "map": true}

// textExtensions are scanned for forbidden references; the others are
// served as images or fonts and never interpreted as markup or script.
var textExtensions = map[string]bool{"html": true, "css": true, "js": true, "mjs": true, "json": true, "svg": true,
	"txt": true, "map": true}

var (
	segmentPattern = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}$`)
	shaPattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// adminRoleSelector matches a selector or attribute that targets the
	// admin console: data-cdnca-role="admin" (any quoting, any case).
	adminRoleSelector = regexp.MustCompile(`(?i)data-cdnca-role\s*[~|^$*]?=\s*["']?\s*admin\b`)
	// externalImport matches a module import of an absolute or
	// protocol-relative URL in script.
	externalImport = regexp.MustCompile(`(?i)\bimport\b[^;"'` + "`" + `]{0,200}?["'` + "`" + `]\s*(?:[a-z][a-z0-9+.-]*:|//|\\\\)`)
	// baseTag catches <base the tokenizer could miss (e.g. inside a
	// template literal that is later written into the document).
	baseTag = regexp.MustCompile(`(?i)<\s*base[\s/>]`)
)

// allowedV1 are the only /v1/ routes a page bundle may reference: the
// public website content and its images.
var allowedV1 = []string{"/v1/control-site/content", "/v1/control-site/assets/"}

// allowedDashboard are the only /dashboard routes a page bundle may link to:
// the platform's own sign-in, sign-up and password reset pages. Each may be
// followed by ?query or #hash, never by a further path segment.
var allowedDashboard = []string{"/dashboard/login", "/dashboard/register", "/dashboard/forgot-password"}

// ValidBundlePath reports whether p is a safe relative bundle path: no
// absolute path, drive letter, backslash, "." or ".." segment, hidden file,
// or character outside [A-Za-z0-9._-] per segment.
func ValidBundlePath(p string) bool {
	if p == "" || len(p) > maxPathLength || strings.HasPrefix(p, "/") {
		return false
	}
	for _, segment := range strings.Split(p, "/") {
		if !segmentPattern.MatchString(segment) || segment == "." || segment == ".." {
			return false
		}
	}
	return path.Clean(p) == p
}

func extension(p string) string { return strings.ToLower(strings.TrimPrefix(path.Ext(p), ".")) }

func parseBundle(wire v2Bundle) (*Bundle, error) {
	bundle := &Bundle{Entry: wire.Entry}
	if bundle.Entry == "" {
		bundle.Entry = DefaultEntry
	}
	if len(wire.Files) == 0 || len(wire.Files) > BundleMaxFiles {
		return nil, invalid("bundle_files", "site_bundle.files")
	}
	seen := map[string]bool{}
	for index, file := range wire.Files {
		field := "site_bundle.files[" + strconv.Itoa(index) + "]"
		if !ValidBundlePath(file.Path) {
			return nil, invalid("bundle_path", field+".path")
		}
		ext := extension(file.Path)
		if !BundleExtensions[ext] {
			return nil, invalid("bundle_extension", field+".path")
		}
		folded := strings.ToLower(file.Path)
		if seen[folded] {
			return nil, invalid("bundle_duplicate", field+".path")
		}
		seen[folded] = true
		if !shaPattern.MatchString(file.SHA256) {
			return nil, invalid("bundle_sha256", field+".sha256")
		}
		data, err := base64.StdEncoding.Strict().DecodeString(file.DataBase64)
		if err != nil {
			return nil, invalid("bundle_data", field+".data_base64")
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != file.SHA256 {
			return nil, invalid("bundle_sha256_mismatch", field+".sha256")
		}
		if code := scanFile(ext, data); code != "" {
			return nil, invalid(code, field+".data_base64")
		}
		bundle.Files = append(bundle.Files, File{Path: file.Path, SHA256: file.SHA256, Size: int64(len(data)), Data: data})
	}
	if !ValidBundlePath(bundle.Entry) || extension(bundle.Entry) != "html" || !seen[strings.ToLower(bundle.Entry)] {
		return nil, invalid("bundle_entry", "site_bundle.entry")
	}
	if !hasExact(bundle.Files, bundle.Entry) {
		return nil, invalid("bundle_entry", "site_bundle.entry")
	}
	sort.Slice(bundle.Files, func(i, j int) bool { return bundle.Files[i].Path < bundle.Files[j].Path })
	return bundle, nil
}

func hasExact(files []File, p string) bool {
	for _, file := range files {
		if file.Path == p {
			return true
		}
	}
	return false
}

// normalizeText folds the spellings a reference can hide behind: case,
// JSON/JS escaped slashes and percent-encoded slashes.
func normalizeText(data []byte) string {
	text := strings.ToLower(string(data))
	return strings.NewReplacer(`\/`, "/", `\x2f`, "/", "\\u002f", "/", "%2f", "/", "&#47;", "/", "&#x2f;", "/", "&sol;", "/").Replace(text)
}

// scanFile returns the error code (without prefix) of the first forbidden
// content in a bundle file, or "".
func scanFile(ext string, data []byte) string {
	if !textExtensions[ext] {
		return ""
	}
	text := normalizeText(data)
	if forbiddenDashboard(text) {
		return "bundle_dashboard"
	}
	if forbiddenV1(text) {
		return "bundle_api"
	}
	if strings.Contains(text, "serviceworker") {
		return "bundle_service_worker"
	}
	if adminRoleSelector.MatchString(text) {
		return "bundle_admin"
	}
	switch ext {
	case "html":
		if code := scanHTML(data); code != "" {
			return code
		}
		if baseTag.MatchString(text) {
			return "bundle_base"
		}
		if externalImport.MatchString(text) {
			return "bundle_external_script"
		}
	case "js", "mjs":
		if baseTag.MatchString(text) {
			return "bundle_base"
		}
		if externalImport.MatchString(text) {
			return "bundle_external_script"
		}
	}
	return ""
}

// forbiddenV1 reports a /v1 reference other than the two public routes.
// "/v1" is a reference when it is not followed by a letter or digit (so
// "/v10" or "/v1beta" are not).
func forbiddenV1(text string) bool {
	for rest := text; ; {
		index := strings.Index(rest, "/v1")
		if index < 0 {
			return false
		}
		tail := rest[index:]
		rest = rest[index+3:]
		if len(tail) > 3 && isWordByte(tail[3]) {
			continue
		}
		if !allowedV1Ref(tail) {
			return true
		}
	}
}

// forbiddenDashboard reports a /dashboard reference other than the three
// platform auth pages (exactly, optionally followed by ?query or #hash).
func forbiddenDashboard(text string) bool {
	for rest := text; ; {
		index := strings.Index(rest, "/dashboard")
		if index < 0 {
			return false
		}
		tail := rest[index:]
		rest = rest[index+len("/dashboard"):]
		if !allowedDashboardRef(tail) {
			return true
		}
	}
}

func allowedDashboardRef(tail string) bool {
	for _, route := range allowedDashboard {
		if strings.HasPrefix(tail, route) {
			after := tail[len(route):]
			return after == "" || !isPathByte(after[0])
		}
	}
	return false
}

func allowedV1Ref(tail string) bool {
	for _, prefix := range allowedV1 {
		if !strings.HasPrefix(tail, prefix) {
			continue
		}
		after := tail[len(prefix):]
		if strings.HasSuffix(prefix, "/") {
			// An asset digest (or a relative continuation) must not climb.
			end := strings.IndexAny(after, "\"'` ()<>?#\n\r\t")
			if end < 0 {
				end = len(after)
			}
			return !strings.Contains(after[:end], "..") && !strings.Contains(after[:end], "/")
		}
		return after == "" || !isPathByte(after[0])
	}
	return false
}

func isWordByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '_'
}

func isPathByte(b byte) bool {
	return isWordByte(b) || b == '-' || b == '.' || b == '/' || b == '%' || b == '~'
}

// scanHTML tokenizes a page and refuses <base> and <script src> that is not
// a relative path of the bundle.
func scanHTML(data []byte) string {
	tokenizer := html.NewTokenizer(bytes.NewReader(data))
	for {
		switch tokenizer.Next() {
		case html.ErrorToken:
			return ""
		case html.StartTagToken, html.SelfClosingTagToken:
			token := tokenizer.Token()
			switch token.Data {
			case "base":
				return "bundle_base"
			case "script":
				for _, attribute := range token.Attr {
					if attribute.Key == "src" && !relativeRef(attribute.Val) {
						return "bundle_external_script"
					}
				}
			case "link":
				// <link rel=modulepreload|preload as=script> loads script too.
				if linkLoadsScript(token.Attr) {
					for _, attribute := range token.Attr {
						if attribute.Key == "href" && !relativeRef(attribute.Val) {
							return "bundle_external_script"
						}
					}
				}
			}
		}
	}
}

func linkLoadsScript(attributes []html.Attribute) bool {
	for _, attribute := range attributes {
		value := strings.ToLower(attribute.Val)
		if attribute.Key == "rel" && strings.Contains(value, "modulepreload") ||
			attribute.Key == "as" && strings.TrimSpace(value) == "script" {
			return true
		}
	}
	return false
}

// relativeRef reports whether a URL stays on the page's own origin: no
// scheme, not protocol-relative, no backslash.
func relativeRef(value string) bool {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "//") || strings.Contains(value, `\`) {
		return false
	}
	if colon := strings.IndexByte(value, ':'); colon >= 0 {
		slash := strings.IndexAny(value, "/?#")
		if slash < 0 || colon < slash {
			return false
		}
	}
	return true
}
