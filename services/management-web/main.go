package main

import (
	"bytes"
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/mtlstunnel"
)

var immutableAssetPattern = regexp.MustCompile(`(?:^|/)[^/]+-[A-Za-z0-9_-]{8,}\.[^/]+$`)

func isAPIPath(path string) bool {
	for _, prefix := range []string{"/api/", "/activation/", "/auth/", "/control/", "/installation/", "/portal/v1/", "/public/", "/v1/"} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return path == "/operator/v1" || strings.HasPrefix(path, "/operator/v1/")
}

// Payment gateway notifications (/payments/v1/notify/{channel_id}) go to the
// upstream (license-service on the authorization host, control-api on a
// controller) byte for byte: the signature covers the raw body, query and
// headers. Bodies are capped like the upstream handlers (256 KiB).
const (
	paymentNotifyPrefix   = "/payments/v1/notify/"
	maxPaymentNotifyBytes = 256 << 10
)

// forwardPaymentNotify buffers the body (refusing oversized ones with 413
// before anything reaches the upstream) and proxies the request unchanged.
func forwardPaymentNotify(response http.ResponseWriter, request *http.Request, proxy http.Handler) {
	if request.Method != http.MethodGet && request.Method != http.MethodPost {
		response.Header().Set("Allow", "GET, POST")
		http.Error(response, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if request.ContentLength > maxPaymentNotifyBytes {
		http.Error(response, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, maxPaymentNotifyBytes+1))
	if err != nil {
		http.Error(response, "bad request", http.StatusBadRequest)
		return
	}
	if len(body) > maxPaymentNotifyBytes {
		http.Error(response, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	request.ContentLength = int64(len(body))
	request.TransferEncoding = nil
	proxy.ServeHTTP(response, request)
}

func staticAssetPath(path string) string {
	for _, base := range []string{"/dashboard", "/operator"} {
		if path == base {
			return "/"
		}
		if strings.HasPrefix(path, base+"/") {
			return strings.TrimPrefix(path, base)
		}
	}
	return path
}

func canonicalRootRedirect(staticRoot string) string {
	if filepath.Base(staticRoot) == "operator-console" {
		return "/operator/"
	}
	return "/dashboard/"
}

func dashboardRouteRedirect(path, rawQuery string) string {
	switch path {
	case "/recover", "/forgot-password", "/reset-password", "/forget-password":
		location := "/dashboard" + path
		if rawQuery != "" {
			location += "?" + rawQuery
		}
		return location
	default:
		return ""
	}
}

func acceptsGzip(request *http.Request) bool {
	if request.Method != http.MethodGet || request.Header.Get("Range") != "" {
		return false
	}
	for _, value := range strings.Split(request.Header.Get("Accept-Encoding"), ",") {
		parts := strings.Split(strings.TrimSpace(value), ";")
		if !strings.EqualFold(strings.TrimSpace(parts[0]), "gzip") {
			continue
		}
		for _, parameter := range parts[1:] {
			keyValue := strings.SplitN(strings.TrimSpace(parameter), "=", 2)
			if len(keyValue) == 2 && strings.EqualFold(keyValue[0], "q") && strings.TrimSpace(keyValue[1]) == "0" {
				return false
			}
		}
		return true
	}
	return false
}

func compressibleAsset(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".css", ".csv", ".html", ".js", ".json", ".mjs", ".map", ".svg", ".txt", ".xml":
		return true
	default:
		return false
	}
}

type gzipResponseWriter struct {
	http.ResponseWriter
	writer *gzip.Writer
}

func (response *gzipResponseWriter) Write(payload []byte) (int, error) {
	return response.writer.Write(payload)
}

// servePrecompressed sends root+path+".gz" when the build produced one. The
// .gz name is derived only from the cleaned request path, so it stays inside
// root. Content-Type follows the original extension.
func servePrecompressed(response http.ResponseWriter, request *http.Request, root, staticPath string) bool {
	if root == "" || strings.Contains("/"+staticPath+"/", "/../") {
		return false
	}
	cleaned := path.Clean("/" + staticPath)
	file, err := os.Open(filepath.Join(root, filepath.FromSlash(cleaned)) + ".gz")
	if err != nil {
		return false
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	if contentType := mime.TypeByExtension(filepath.Ext(cleaned)); contentType != "" {
		response.Header().Set("Content-Type", contentType)
	}
	response.Header().Add("Vary", "Accept-Encoding")
	response.Header().Set("Content-Encoding", "gzip")
	http.ServeContent(response, request, cleaned, info.ModTime(), file)
	return true
}

func serveStatic(response http.ResponseWriter, request *http.Request, files http.Handler, root, path string, noStore bool) {
	if !noStore && immutableAssetPattern.MatchString(path) {
		response.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		response.Header().Set("Cache-Control", "no-store")
	}
	staticRequest := request.Clone(request.Context())
	staticRequest.URL.Path = path
	if acceptsGzip(request) && compressibleAsset(path) {
		if servePrecompressed(response, request, root, path) {
			return
		}
		response.Header().Add("Vary", "Accept-Encoding")
		response.Header().Set("Content-Encoding", "gzip")
		response.Header().Del("Content-Length")
		writer := gzip.NewWriter(response)
		files.ServeHTTP(&gzipResponseWriter{ResponseWriter: response, writer: writer}, staticRequest)
		if err := writer.Close(); err != nil {
			log.Printf("static gzip close: %v", err)
		}
		return
	}
	files.ServeHTTP(response, staticRequest)
}

func newHandler(staticRoot string, upstream *url.URL) (http.Handler, error) {
	return newHandlerWithOptions(staticRoot, upstream, handlerOptions{})
}

func newHandlerWithOptions(staticRoot string, upstream *url.URL, options handlerOptions) (http.Handler, error) {
	var gate *masterDownloadGate
	if options.MasterDownloadAuthorization != nil {
		gate = newMasterDownloadGate(options.MasterDownloadAuthorization, options.AuthorizationTimeout)
	}
	index := filepath.Join(staticRoot, "index.html")
	if info, err := os.Stat(index); err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("frontend index.html is unavailable")
	}
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	director := proxy.Director
	proxy.Director = func(request *http.Request) {
		forwardedHost := request.Host
		director(request)
		request.Header.Set("X-Forwarded-Proto", "https")
		request.Header.Set("X-Forwarded-Host", forwardedHost)
		clientIP, _, err := net.SplitHostPort(request.RemoteAddr)
		if err != nil {
			clientIP = request.RemoteAddr
		}
		if clientIP != "" {
			request.Header.Set("X-Forwarded-For", clientIP)
			request.Header.Set("X-Real-IP", clientIP)
		} else {
			request.Header.Del("X-Forwarded-For")
			request.Header.Del("X-Real-IP")
		}
	}
	files := http.FileServer(http.Dir(staticRoot))
	artifactFiles := http.FileServer(http.Dir(options.ReleaseArtifactRoot))
	rootRedirect := canonicalRootRedirect(staticRoot)
	portal, err := newPortalSite(options.PortalStaticRoot)
	if err != nil {
		return nil, err
	}
	site := withSecurityHeaders(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		// With the customer portal mounted, / is the unified sign-in page for
		// customers and operators, and the old login pages redirect to it.
		// Both apps keep their own session cookie and path.
		if portal != nil && (request.Method == http.MethodGet || request.Method == http.MethodHead) {
			if request.URL.Path == "/" {
				portal.serveEntry(response, request)
				return
			}
			if legacyLoginPaths[request.URL.Path] {
				response.Header().Set("Cache-Control", "no-store")
				http.Redirect(response, request, unifiedLoginLocation(request.URL.RawQuery), http.StatusFound)
				return
			}
		}
		if request.Method == http.MethodGet && request.URL.Path == "/" {
			http.Redirect(response, request, rootRedirect, http.StatusFound)
			return
		}
		if request.Method == http.MethodGet && (request.URL.Path == "/health/live" || request.URL.Path == "/health/ready") {
			response.Header().Set("Content-Type", "application/json")
			response.Header().Set("Cache-Control", "no-store")
			response.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintln(response, `{"status":"ready"}`)
			return
		}
		if strings.HasPrefix(request.URL.Path, paymentNotifyPrefix) {
			forwardPaymentNotify(response, request, proxy)
			return
		}
		if isAPIPath(request.URL.Path) {
			proxy.ServeHTTP(response, request)
			return
		}
		if portal != nil && portal.serve(response, request) {
			return
		}
		if request.Method == http.MethodGet {
			if location := dashboardRouteRedirect(request.URL.Path, request.URL.RawQuery); location != "" {
				http.Redirect(response, request, location, http.StatusFound)
				return
			}
		}
		staticPath := staticAssetPath(request.URL.Path)
		// Gate on the cleaned path (what the file server will open) before
		// revealing whether the artifact exists.
		gated := gate != nil && masterDownloadPath(cleanStaticPath(staticPath))
		if gated && !gate.allow(response, request) {
			return
		}
		candidate := filepath.Join(staticRoot, filepath.Clean("/"+staticPath))
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			serveStatic(response, request, files, staticRoot, staticPath, gated)
			return
		}
		if artifactPath, ok := releaseArtifactPath(options.ReleaseArtifactRoot, staticPath); ok {
			serveStatic(response, request, artifactFiles, "", artifactPath, true)
			return
		}
		response.Header().Set("Cache-Control", "no-store")
		// A missing Vite asset (an old tab asking for a chunk the upgrade removed)
		// is a 404, not index.html: the page's chunk-load handler then reloads to
		// the new build. Same as the portal's /console/assets/ and the nginx sites.
		if strings.HasPrefix(cleanStaticPath(staticPath), "/assets/") {
			http.NotFound(response, request)
			return
		}
		http.ServeFile(response, request, index)
	}))
	resolver, tunnel := options.ClientIP, options.Tunnel
	// Resolve the client first (T2): RemoteAddr then carries it into the proxy
	// headers, the download gate and the tunnel limits. The tunnel is served
	// outside withSecurityHeaders, whose writer cannot be hijacked.
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		source := resolver.apply(request)
		if tunnel != nil && strings.HasPrefix(request.URL.Path, mtlstunnel.PathPrefix) {
			tunnel.serve(response, request, source)
			return
		}
		site.ServeHTTP(response, request)
	}), nil
}

// securityHeaders apply to every response: this server terminates TLS itself on
// the authorization host, with no nginx in front to add them.
var securityHeaders = [][2]string{
	{"Strict-Transport-Security", "max-age=31536000"},
	{"X-Content-Type-Options", "nosniff"},
	{"X-Frame-Options", "DENY"},
	{"Referrer-Policy", "strict-origin-when-cross-origin"},
}

// withSecurityHeaders fills in each default when the response headers are
// written, so a value the upstream set on a proxied response is kept as is
// (the reverse proxy copies upstream headers with Add, which would duplicate).
func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		next.ServeHTTP(&securityHeaderWriter{ResponseWriter: response}, request)
	})
}

type securityHeaderWriter struct {
	http.ResponseWriter
	written bool
}

func (writer *securityHeaderWriter) apply() {
	if writer.written {
		return
	}
	writer.written = true
	header := writer.ResponseWriter.Header()
	for _, value := range securityHeaders {
		if header.Get(value[0]) == "" {
			header.Set(value[0], value[1])
		}
	}
}

func (writer *securityHeaderWriter) WriteHeader(status int) {
	writer.apply()
	writer.ResponseWriter.WriteHeader(status)
}

func (writer *securityHeaderWriter) Write(payload []byte) (int, error) {
	writer.apply()
	return writer.ResponseWriter.Write(payload)
}

// Unwrap lets http.ResponseController (used by the reverse proxy to flush)
// reach the underlying writer.
func (writer *securityHeaderWriter) Unwrap() http.ResponseWriter { return writer.ResponseWriter }

// releaseArtifactPath maps /downloads/<component>/<version>/<file> to an
// uploaded package. Hidden segments (the private .incoming staging directory)
// and anything but a regular file are never served.
func releaseArtifactPath(root, staticPath string) (string, bool) {
	cleaned := cleanStaticPath(staticPath)
	if root == "" || !strings.HasPrefix(cleaned, "/downloads/") {
		return "", false
	}
	relative := strings.TrimPrefix(cleaned, "/downloads")
	segments := strings.Split(strings.TrimPrefix(relative, "/"), "/")
	if len(segments) != 3 {
		return "", false
	}
	for _, segment := range segments {
		if segment == "" || strings.HasPrefix(segment, ".") {
			return "", false
		}
	}
	info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(relative)))
	if err != nil || !info.Mode().IsRegular() {
		return "", false
	}
	return relative, true
}

func main() {
	staticDir := flag.String("static-dir", "", "directory containing the built frontend")
	listen := flag.String("listen", ":443", "HTTPS listen address")
	upstreamText := flag.String("upstream", "", "control service origin")
	portalStaticDir := flag.String("portal-static-dir", "", "optional customer portal build served under /console/")
	authorizationText := flag.String("master-download-authorization-url", "",
		"license-service master download authorization endpoint; empty serves master artifacts without an IP check")
	releaseArtifactDir := flag.String("release-artifact-dir", "",
		"optional directory of operator-uploaded release packages served under /downloads/<component>/<version>/")
	originAuthHeader := flag.String("origin-auth-header", defaultOriginAuthHeader,
		"request header carrying the CDN origin-auth secret")
	originAuthSecretFile := flag.String("origin-auth-secret-file", "",
		"0600 file with the CDN origin-auth secret (>= 32 bytes); missing file uses the TCP peer only")
	realIPHeader := flag.String("real-ip-header", "",
		"header naming the client on origin-authenticated requests (CF-Connecting-IP, X-Forwarded-For, True-Client-IP, X-Real-IP)")
	tunnelTargets := flag.String("mtls-tunnel-targets", defaultTunnelTargets,
		"mTLS tunnel targets name=ip:port,...; empty disables /mtls/v1/tunnel/")
	tunnelMax := flag.Int("mtls-tunnel-max-connections", mtlstunnel.DefaultTotalLimit, "concurrent mTLS tunnel connections")
	flag.Parse()
	if *staticDir == "" || *upstreamText == "" {
		log.Fatal("static-dir and upstream are required")
	}
	upstream, err := url.Parse(*upstreamText)
	if err != nil || upstream.Scheme != "http" || upstream.Host == "" {
		log.Fatal("upstream must be an http origin")
	}
	root, err := filepath.Abs(*staticDir)
	if err != nil {
		log.Fatal(err)
	}
	options := handlerOptions{}
	if *portalStaticDir != "" {
		portalRoot, err := filepath.Abs(*portalStaticDir)
		if err != nil {
			log.Fatal(err)
		}
		options.PortalStaticRoot = portalRoot
	}
	if *releaseArtifactDir != "" {
		artifactRoot, err := filepath.Abs(*releaseArtifactDir)
		if err != nil {
			log.Fatal(err)
		}
		options.ReleaseArtifactRoot = artifactRoot
	}
	if *authorizationText != "" {
		authorization, err := url.Parse(*authorizationText)
		if err != nil || authorization.Scheme != "http" || authorization.Host == "" || authorization.User != nil {
			log.Fatal("master-download-authorization-url must be an http URL")
		}
		options.MasterDownloadAuthorization = authorization
	}
	if strings.TrimSpace(*originAuthHeader) == "" {
		log.Fatal("origin-auth-header must not be empty")
	}
	options.ClientIP = clientIPResolver{authHeader: http.CanonicalHeaderKey(strings.TrimSpace(*originAuthHeader))}
	if *originAuthSecretFile != "" {
		secret, enabled, err := loadOriginAuthSecret(*originAuthSecretFile)
		if err != nil {
			log.Fatal(err)
		}
		if enabled {
			if strings.TrimSpace(*realIPHeader) == "" {
				log.Fatal("real-ip-header is required with an origin-auth secret")
			}
			options.ClientIP.secret = secret
			options.ClientIP.realIPHeader = http.CanonicalHeaderKey(strings.TrimSpace(*realIPHeader))
			log.Printf("origin auth enabled: header %s, client from %s", options.ClientIP.authHeader, options.ClientIP.realIPHeader)
		} else {
			log.Printf("origin auth secret %s not present: clients identified by TCP peer", *originAuthSecretFile)
		}
	}
	targets, err := parseTunnelTargets(*tunnelTargets)
	if err != nil {
		log.Fatal(err)
	}
	if len(targets) > 0 {
		options.Tunnel = newMTLSTunnel(targets, *tunnelMax)
		log.Printf("mtls tunnel enabled: %s", options.Tunnel.names())
	}
	handler, err := newHandlerWithOptions(root, upstream, options)
	if err != nil {
		log.Fatal(err)
	}
	certFile, keyFile := os.Getenv("CDNCA_TLS_CERT"), os.Getenv("CDNCA_TLS_KEY")
	if certFile == "" || keyFile == "" {
		log.Fatal("CDNCA_TLS_CERT and CDNCA_TLS_KEY are required")
	}
	server := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}
	log.Fatal(server.ListenAndServeTLS(certFile, keyFile))
}
