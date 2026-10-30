package main

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// With the portal mounted, / itself is the unified sign-in page (统一登录, the
// portal index renders it for /), and the old per-app login pages redirect
// there, keeping a same-site return path.
var legacyLoginPaths = map[string]bool{"/console/login": true, "/operator/login": true}

// unifiedLoginLocation builds the unified sign-in URL for a legacy login
// request, keeping its next parameter only when it is a safe in-app path.
func unifiedLoginLocation(rawQuery string) string {
	values, _ := url.ParseQuery(rawQuery)
	if next := safeNext(values.Get("next")); next != "" {
		return "/?" + url.Values{"next": {next}}.Encode()
	}
	return "/"
}

// safeNext accepts only an absolute path inside the portal (/console/) or
// the operator console (/operator/): no scheme, host, "//", backslash,
// control character or login page, so it can never redirect off-site.
func safeNext(value string) string {
	if len(value) == 0 || len(value) > 2048 || !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") ||
		strings.ContainsAny(value, "\\") {
		return ""
	}
	for _, character := range value {
		if character < 0x21 || character == 0x7f {
			return ""
		}
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "" || parsed.Host != "" || parsed.User != nil {
		return ""
	}
	cleaned := path.Clean(parsed.Path)
	if !strings.HasPrefix(cleaned+"/", "/console/") && !strings.HasPrefix(cleaned+"/", "/operator/") ||
		legacyLoginPaths[cleaned] {
		return ""
	}
	return value
}

func (site *portalSite) serveEntry(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	http.ServeFile(response, request, site.index)
}

// portalSite serves the customer portal SPA (apps/license-portal, base
// /console/) with the same routes as apps/license-portal/nginx-console.conf:
// /console → 308 /console/, /console/assets/* from disk (404 when missing),
// every other /console/* path → the portal index.html.
type portalSite struct {
	root  string
	index string
	files http.Handler
}

func newPortalSite(root string) (*portalSite, error) {
	if root == "" {
		return nil, nil
	}
	index := filepath.Join(root, "index.html")
	if info, err := os.Stat(index); err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("portal index.html is unavailable")
	}
	return &portalSite{root: root, index: index, files: http.FileServer(http.Dir(root))}, nil
}

// serve handles /console and /console/*; it reports false for other paths.
func (site *portalSite) serve(response http.ResponseWriter, request *http.Request) bool {
	requestPath := request.URL.Path
	if requestPath == "/console" {
		location := "/console/"
		if request.URL.RawQuery != "" {
			location += "?" + request.URL.RawQuery
		}
		http.Redirect(response, request, location, http.StatusPermanentRedirect)
		return true
	}
	if !strings.HasPrefix(requestPath, "/console/") {
		return false
	}
	relative := path.Clean("/" + strings.TrimPrefix(requestPath, "/console/"))
	if strings.HasPrefix(requestPath, "/console/assets/") {
		// Missing or escaping assets 404 instead of returning HTML.
		candidate := filepath.Join(site.root, filepath.FromSlash(relative))
		info, err := os.Stat(candidate)
		if !strings.HasPrefix(relative, "/assets/") || err != nil || !info.Mode().IsRegular() {
			response.Header().Set("Cache-Control", "no-store")
			http.NotFound(response, request)
			return true
		}
		serveStatic(response, request, site.files, site.root, relative, false)
		return true
	}
	response.Header().Set("Cache-Control", "no-store")
	http.ServeFile(response, request, site.index)
	return true
}
