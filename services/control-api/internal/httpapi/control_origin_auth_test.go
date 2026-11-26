package httpapi

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// CDN-ORIGIN-AUTH-HINT: a CDN visitor header raises the hint unless the
// console nginx confirmed the origin key (X-Cdnca-Origin-Verified: 1), which
// is believed only while origin-auth.conf exists; a confirmed request clears
// it, whatever other CDN headers it carries.
func TestControlOriginAuthObserver(t *testing.T) {
	now := time.Date(2026, 11, 22, 8, 0, 0, 0, time.UTC)
	conf, profile := filepath.Join(t.TempDir(), "origin-auth.conf"), filepath.Join(t.TempDir(), "runtime.env")
	observer := &controlOriginAuthObserver{confPath: conf, hostPortsPath: profile}
	request := func(headers ...string) http.Header {
		header := http.Header{"X-Forwarded-For": {"104.23.1.10"}, "X-Real-Ip": {"104.23.1.10"}}
		for index := 0; index < len(headers); index += 2 {
			header.Set(headers[index], headers[index+1])
		}
		return header
	}

	// direct access: no clue, nothing to show
	observer.observe(request(), false, now)
	if status := observer.status(now); status.CDNWithoutOriginAuth || status.OriginAuthEnabled || status.VisitorIPConfirmed ||
		status.LastSeenAt != nil || status.LastConfirmedAt != nil {
		t.Fatalf("direct access: %+v", status)
	}
	// through a CDN without origin authentication; a forged confirmation is not believed
	observer.observe(request("CF-Connecting-IP", "203.0.113.9", controlOriginAuthVerifiedHeader, "1"), false, now)
	status := observer.status(now.Add(time.Minute))
	if !status.CDNWithoutOriginAuth || status.VisitorIPConfirmed || status.Header != "CF-Connecting-IP" ||
		status.LastSeenAt == nil || !status.LastSeenAt.Equal(now) || status.LastConfirmedAt != nil {
		t.Fatalf("CDN without origin authentication: %+v", status)
	}
	if observer.status(now.Add(controlOriginAuthWindow)).CDNWithoutOriginAuth {
		t.Fatal("the hint outlived its window")
	}

	if observer.status(now).BaoTa {
		t.Fatal("no host profile is not BaoTa")
	}
	// origin authentication configured on a BaoTa host (read again once the cached check lapses)
	if err := os.WriteFile(conf, []byte("# real-ip-header: True-Client-IP\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(profile, []byte("ENV=bt\nWEB_PORT=18443\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	later := now.Add(2 * time.Minute)
	// the origin key did not match (0): still unconfirmed, the clue is the vendor header
	observer.observe(request("Ali-Cdn-Real-Ip", "203.0.113.9", controlOriginAuthVerifiedHeader, "0"), false, later)
	if status := observer.status(later); !status.OriginAuthEnabled || !status.BaoTa || !status.CDNWithoutOriginAuth || status.Header != "Ali-Cdn-Real-Ip" {
		t.Fatalf("key not matched: %+v", status)
	}
	// matched, with True-Client-IP chosen and other CDN headers present: confirmed, the hint goes
	observer.observe(request("True-Client-IP", "203.0.113.9", "CF-Connecting-IP", "203.0.113.9",
		controlOriginAuthVerifiedHeader, "1"), false, later.Add(time.Second))
	status = observer.status(later.Add(time.Second))
	if status.CDNWithoutOriginAuth || !status.VisitorIPConfirmed || status.LastConfirmedAt == nil {
		t.Fatalf("key matched: %+v", status)
	}
	// only the generic forwarding headers (a CDN writing X-Forwarded-For alone): confirmed or not is visible
	observer.observe(request(controlOriginAuthVerifiedHeader, "1"), false, later.Add(2*time.Second))
	if status := observer.status(later.Add(2 * time.Second)); !status.VisitorIPConfirmed || status.CDNWithoutOriginAuth {
		t.Fatalf("generic headers, confirmed: %+v", status)
	}
	// a CDN node without the key afterwards raises it again
	observer.observe(request("CF-Connecting-IP", "203.0.113.9"), false, later.Add(3*time.Second))
	if status := observer.status(later.Add(3 * time.Second)); !status.CDNWithoutOriginAuth || status.VisitorIPConfirmed || status.KeyOnly {
		t.Fatalf("unconfirmed after confirmed: %+v", status)
	}
	// the key matched but True-Client-IP held no address (the CDN wrote
	// only EO-Connecting-IP, or nothing): not confirmed, key_only, the chosen header from the conf
	for index, headers := range [][]string{{"EO-Connecting-IP", "203.0.113.9"}, nil} {
		at := later.Add(time.Duration(4+index) * time.Second)
		observer.observe(request(append(headers, controlOriginAuthVerifiedHeader, "key_only")...), false, at)
		status := observer.status(at)
		if !status.CDNWithoutOriginAuth || status.VisitorIPConfirmed || !status.KeyOnly || status.RealIPHeader != "True-Client-IP" {
			t.Fatalf("key only %v: %+v", headers, status)
		}
		if want := map[int]string{0: "EO-Connecting-IP", 1: ""}[index]; status.Header != want {
			t.Fatalf("key only %v: header %q", headers, status.Header)
		}
	}
	// without origin authentication key_only is a client's own header and means nothing
	plain := &controlOriginAuthObserver{confPath: filepath.Join(t.TempDir(), "absent.conf"), hostPortsPath: profile}
	plain.observe(request(controlOriginAuthVerifiedHeader, "key_only"), false, now)
	if status := plain.status(now); status.CDNWithoutOriginAuth || status.LastSeenAt != nil || status.RealIPHeader != "" {
		t.Fatalf("forged key_only: %+v", status)
	}
}
