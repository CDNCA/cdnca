package httpapi

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"net/textproto"
	"os"
	"sync/atomic"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/clientip"
)

// CDN-ORIGIN-AUTH-HINT: a console behind a CDN sees the CDN node as the
// source of every visitor unless the visitor address is taken from a header:
// the 源IP请求头 setting (withVisitorIP), or on
// hosts that applied it, the origin authentication of install-control.sh
// origin-auth. Otherwise the per-source CAPTCHA, sign-in and code limits put
// the visitors sharing a node together.
//
// Two separate observations:
// - a CDN clue: a header CDNs write the visitor address into, which the
// console nginx passes through (it always rewrites X-Real-IP /
// X-Forwarded-For, so those say nothing here);
// - the visitor address is confirmed: the 源IP请求头 setting gave one
// (clientip.Visitor), or the console nginx with origin authentication
// set X-Cdnca-Origin-Verified to 1: the request carried the origin key
// and the chosen header gave the visitor address (the condition its
// client address takes), key_only when the key matched but the header
// did not, 0 otherwise, overwriting what the client sent. Without origin
// authentication nginx passes a client's header through, so it is
// believed only while the installer's origin-auth.conf exists.
//
// A CDN request whose visitor address is not confirmed raises the hint; a
// confirmed request clears it. One atomic store per request with a clue or a
// confirmation; no header value is kept. Memory of this process: with several
// control-api instances each reports the requests it answered (they share
// the console nginx and see the same kind of traffic); a restart starts empty.

// controlOriginAuthHeaders are headers CDNs write the visitor address into,
// as the CDNs document them. The first two (and X-Forwarded-For / X-Real-IP,
// which nginx rewrites) are what 源IP请求头 offers (clientip.Headers).
var controlOriginAuthHeaders = []string{
	"CF-Connecting-IP", // Cloudflare
	"True-Client-IP",   // Akamai, Cloudflare Enterprise
	"Ali-Cdn-Real-Ip",  // Alibaba Cloud CDN
	"EO-Connecting-IP", // Tencent Cloud EdgeOne
	"Fastly-Client-IP", // Fastly
	"Cdn-Src-Ip",       // Wangsu and other CDNs
}

// controlOriginAuthKeys are controlOriginAuthHeaders as http.Header keys.
var controlOriginAuthKeys = func() []string {
	keys := make([]string, len(controlOriginAuthHeaders))
	for index, name := range controlOriginAuthHeaders {
		keys[index] = textproto.CanonicalMIMEHeaderKey(name)
	}
	return keys
}()

const (
	// controlOriginAuthVerifiedHeader is set by the console nginx with origin
	// authentication (origin_auth_apply_nginx): 1 when the origin key matched.
	controlOriginAuthVerifiedHeader = "X-Cdnca-Origin-Verified"
	// defaultControlOriginAuthConf is written by install-control.sh origin-auth
	// (and --origin-auth) and removed again when enabling it fails.
	defaultControlOriginAuthConf = "/etc/cdnca-control/origin-auth.conf"
	// defaultControlHostPortsFile is the host profile install-control.sh writes
	// on a BaoTa host (nativebackup.HostPortsFile): ENV=bt there.
	defaultControlHostPortsFile = "/etc/cdnca-native-dependencies/runtime.env"
	// controlOriginAuthWindow: what came within it is reported.
	controlOriginAuthWindow = time.Hour
	// controlOriginAuthConfCheck: how long the existence of the conf is reused.
	controlOriginAuthConfCheck = 30 * time.Second
	// defaultControlNginxConf is the console nginx install-control.sh writes.
	defaultControlNginxConf = "/etc/cdnca-control/nginx.conf"
	// controlNginxClientHeaders is the line with which the console nginx passes
	// the client's own X-Forwarded-For (clientip.ForwardedXForwardedFor; the
	// X-Real-IP copy is written next to it). Installs and converged consoles
	// from this release on have it.
	controlNginxClientHeaders = "proxy_set_header " + clientip.ForwardedXForwardedFor + " $http_x_forwarded_for;"
	// controlNginxReadLimit bounds the read of nginx.conf.
	controlNginxReadLimit = 1 << 20
)

type controlOriginAuthObserver struct {
	unconfirmedAt atomic.Int64 // unix nanoseconds of the last CDN request not confirmed, 0 never
	confirmedAt   atomic.Int64 // of the last confirmed request
	header        atomic.Int32 // index into controlOriginAuthHeaders of the last unconfirmed one, -1 none
	keyOnly       atomic.Bool  // the last unconfirmed one carried the key, the chosen header no address
	confPath      string
	hostPortsPath string
	nginxPath     string
	confCheckedAt atomic.Int64
	confPresent   atomic.Bool
	realIPHeader  atomic.Value // string: the --real-ip-header origin-auth.conf names
	baota         atomic.Bool
	// clientHeaders: nginx.conf passes the client's X-Real-IP / X-Forwarded-For (controlNginxClientHeaders)
	clientHeaders atomic.Bool
}

// controlNginxPassesClientHeaders reports whether the console nginx at path
// passes the client's X-Real-IP / X-Forwarded-For to control-api.
func controlNginxPassesClientHeaders(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, controlNginxReadLimit))
	return err == nil && bytes.Contains(content, []byte(controlNginxClientHeaders))
}

// controlOriginAuthConfHeader reads the "# real-ip-header: H" comment of the
// installer's origin-auth.conf. The conf also holds the origin key, after its
// leading comments: reading stops at the first line that is not a comment, so
// the key never enters this process.
func controlOriginAuthConfHeader(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()
	scanner := bufio.NewScanner(io.LimitReader(file, 4096))
	for scanner.Scan() {
		line := scanner.Bytes()
		if !bytes.HasPrefix(line, []byte("#")) {
			return ""
		}
		if name, found := bytes.CutPrefix(line, []byte("# real-ip-header: ")); found && controlOriginAuthRealIPHeaders[string(name)] {
			return string(name)
		}
	}
	return ""
}

// controlOriginAuthRealIPHeaders are what install-control.sh origin-auth --real-ip-header takes.
var controlOriginAuthRealIPHeaders = map[string]bool{"CF-Connecting-IP": true, "True-Client-IP": true, "X-Forwarded-For": true, "X-Real-IP": true}

// enabled: origin authentication is configured on this host (the conf
// exists), checked at most every controlOriginAuthConfCheck together with
// whether this is a BaoTa host (whose installer takes fewer headers).
func (observer *controlOriginAuthObserver) enabled(now time.Time) bool {
	if checked := observer.confCheckedAt.Load(); checked != 0 && now.UnixNano() >= checked &&
		now.Sub(time.Unix(0, checked)) < controlOriginAuthConfCheck {
		return observer.confPresent.Load()
	}
	info, err := os.Stat(observer.confPath)
	present := err == nil && info.Mode().IsRegular()
	realIPHeader := ""
	if present {
		realIPHeader = controlOriginAuthConfHeader(observer.confPath)
	}
	observer.realIPHeader.Store(realIPHeader)
	profile, _ := os.ReadFile(observer.hostPortsPath)
	baota := false
	for _, line := range bytes.Split(profile, []byte("\n")) {
		baota = baota || string(line) == "ENV=bt"
	}
	observer.baota.Store(baota)
	observer.clientHeaders.Store(controlNginxPassesClientHeaders(observer.nginxPath))
	observer.confPresent.Store(present)
	observer.confCheckedAt.Store(now.UnixNano())
	return present
}

// verified is what the console nginx with origin authentication reported
// for this request: "1" (key and visitor address), "key_only", or "" (no
// origin authentication here, or the key did not match).
func (observer *controlOriginAuthObserver) verified(header http.Header, now time.Time) string {
	if values := header[controlOriginAuthVerifiedHeader]; len(values) == 1 && (values[0] == "1" || values[0] == "key_only") && observer.enabled(now) {
		return values[0]
	}
	return ""
}

// observe records a request; resolved: the 源IP请求头 setting gave its visitor address.
func (observer *controlOriginAuthObserver) observe(header http.Header, resolved bool, now time.Time) {
	verified := observer.verified(header, now)
	if verified == "1" || resolved {
		observer.confirmedAt.Store(now.UnixNano())
		return
	}
	clue := int32(-1)
	for index, key := range controlOriginAuthKeys {
		if len(header[key]) != 0 {
			clue = int32(index)
			break
		}
	}
	// key_only is a CDN request too (it carried the origin key), whatever its other headers
	if clue < 0 && verified == "" {
		return
	}
	observer.header.Store(clue)
	observer.keyOnly.Store(verified == "key_only")
	observer.unconfirmedAt.Store(now.UnixNano())
}

type controlOriginAuthStatus struct {
	// CDNWithoutOriginAuth: within the last hour a request came through a CDN
	// (a visitor address header) without a confirmed visitor address (neither
	// 源IP请求头 nor origin authentication gave one), and no confirmed one came since.
	CDNWithoutOriginAuth bool `json:"cdn_without_origin_auth"`
	// OriginAuthEnabled: install-control.sh origin-auth is configured here.
	OriginAuthEnabled bool `json:"origin_auth_enabled"`
	// BaoTa: a BaoTa host, whose site proxy rewrites X-Real-IP / X-Forwarded-For
	// with the CDN node: 源IP请求头 reads only CF-Connecting-IP or True-Client-IP there.
	BaoTa bool `json:"baota"`
	// ClientHeadersForwarded: the console nginx passes the client's X-Real-IP
	// and X-Forwarded-For to control-api, so 源IP请求头 can read those two.
	ClientHeadersForwarded bool `json:"client_headers_forwarded"`
	// RealIPHeader is the --real-ip-header origin authentication uses ("" when off).
	RealIPHeader string `json:"real_ip_header"`
	// KeyOnly: the last unconfirmed CDN request carried the origin key but the
	// chosen header held no visitor address (the CDN does not write it there).
	KeyOnly bool `json:"key_only"`
	// VisitorIPConfirmed: within the last hour a request's visitor address was
	// confirmed, and no unconfirmed CDN request came since.
	VisitorIPConfirmed bool `json:"visitor_ip_confirmed"`
	// Header is the visitor address header of the last unconfirmed CDN request ("" when none).
	Header string `json:"header"`
	// LastSeenAt is when that request came (null when none).
	LastSeenAt *time.Time `json:"last_seen_at"`
	// LastConfirmedAt is when the last confirmed request came (null when none).
	LastConfirmedAt *time.Time `json:"last_confirmed_at"`
}

func (observer *controlOriginAuthObserver) status(now time.Time) controlOriginAuthStatus {
	status := controlOriginAuthStatus{OriginAuthEnabled: observer.enabled(now), BaoTa: observer.baota.Load(),
		ClientHeadersForwarded: observer.clientHeaders.Load()}
	if status.OriginAuthEnabled {
		status.RealIPHeader, _ = observer.realIPHeader.Load().(string)
	}
	unconfirmed, confirmed := observer.unconfirmedAt.Load(), observer.confirmedAt.Load()
	recent := func(at int64) bool { return at != 0 && now.Sub(time.Unix(0, at)) < controlOriginAuthWindow }
	if unconfirmed != 0 {
		at := time.Unix(0, unconfirmed).UTC()
		status.LastSeenAt, status.KeyOnly = &at, observer.keyOnly.Load()
		if index := observer.header.Load(); index >= 0 {
			status.Header = controlOriginAuthHeaders[index]
		}
		status.CDNWithoutOriginAuth = recent(unconfirmed) && unconfirmed > confirmed
	}
	if confirmed != 0 {
		at := time.Unix(0, confirmed).UTC()
		status.LastConfirmedAt = &at
		status.VisitorIPConfirmed = recent(confirmed) && confirmed >= unconfirmed
	}
	return status
}

// withControlOriginAuthObserver records the 源IP请求头 visitor address (for
// Handler served without WithClientSourceIP) and feeds every request to
// the observer.
func (s *Server) withControlOriginAuthObserver(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = s.withVisitorIP(r)
		_, resolved := clientip.Visitor(r.Context())
		s.controlOriginAuth.observe(r.Header, resolved, s.controlOriginAuthNow())
		next.ServeHTTP(w, r)
	})
}

// withVisitorIP records the visitor address the 源IP请求头 setting names
// (clientip.FromHeader), which every source IP
// resolver returns first. A request the console nginx confirmed with the
// origin key keeps the address nginx already wrote into X-Forwarded-For;
// no setting, or no valid address in the header, keeps the connection's.
func (s *Server) withVisitorIP(r *http.Request) *http.Request {
	if s.sourceIPHeader == nil {
		return r
	}
	if _, ok := clientip.Visitor(r.Context()); ok {
		return r
	}
	setting := s.sourceIPHeader.Current(r.Context())
	if setting == "" || s.controlOriginAuth.verified(r.Header, s.controlOriginAuthNow()) == "1" {
		return r
	}
	address, ok := clientip.FromHeader(r.Header, setting)
	if !ok {
		return r
	}
	return r.WithContext(clientip.WithVisitor(r.Context(), address))
}

// handleControlOriginAuthStatus answers GET /v1/admin/control-origin-auth.
func (s *Server) handleControlOriginAuthStatus(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.adminAccessPrincipal(w, r, "system_configuration.read"); !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, s.controlOriginAuth.status(s.controlOriginAuthNow()))
}

// controlOriginAuthNow is the wall clock of the observation window. Not
// Config.Now: the observer runs on every request before the handlers, and a
// test clock answering per call (api_key_usage_integration_test boundary)
// would see its first value taken here.
func (s *Server) controlOriginAuthNow() time.Time {
	return time.Now()
}
