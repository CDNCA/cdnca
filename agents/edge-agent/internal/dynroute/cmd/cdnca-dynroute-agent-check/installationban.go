package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/installationban"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgeskeleton"
	contract "github.com/cdnca/cdnca/libs/entitlement/installationban"
)

// Installation ban (ADR 0014 LIC-BAN-05) on the real OpenResty: the node's
// installationban.Runtime with license service signed documents stops the
// node (every site server 503 with the fixed page and Retry-After, the L4
// forwards refused), a forged lift is refused, an expired ticket stops it,
// and a lift restores the previous configuration (sites, cache HITs, L4).

const (
	banInstallation = "0d130000-0000-4000-8000-0000000005a1"
	banCustomer     = "0d130000-0000-4000-8000-0000000005a2"
	banID           = "0d130000-0000-4000-8000-0000000005a3"
	banLicense      = "0d130000-0000-4000-8000-0000000005a4"
)

type banSigner struct{ private ed25519.PrivateKey }

func (banSigner) KeyID() string { return "license-installation-ban" }
func (signer banSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(signer.private, payload), nil
}

func newBanSigner(label string) banSigner {
	seed := sha256.Sum256([]byte(label))
	return banSigner{private: ed25519.NewKeyFromSeed(seed[:])}
}

// banServing drives the harness like the daemon's installationBanServing:
// SetMaintenance, then the same input applied again.
type banServing struct{ h *harness }

func (serving banServing) Stop(_ context.Context, retryAfter time.Time) error {
	serving.h.runtime.SetMaintenance(&edgeskeleton.Maintenance{RetryAfter: installationban.RetryAfterHeader(retryAfter)})
	_, err := serving.h.runtime.Apply(serving.h.ctx, serving.h.input)
	return err
}

func (serving banServing) Resume(context.Context) error {
	serving.h.runtime.SetMaintenance(nil)
	_, err := serving.h.runtime.Apply(serving.h.ctx, serving.h.input)
	return err
}

func getHeader(port int, host, path, header string) (int, string, string) {
	request, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(port)+path, nil)
	request.Host = host
	response, err := (&http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}).Do(request)
	if err != nil {
		return 0, "", err.Error()
	}
	defer response.Body.Close()
	body := make([]byte, 4096)
	n, _ := response.Body.Read(body)
	return response.StatusCode, response.Header.Get(header), string(body[:n])
}

func checkInstallationBan(h *harness, secureHost string, roots *x509.CertPool) {
	ctx := h.ctx
	now := time.Now().UTC().Truncate(time.Second)
	clock := now
	trusted, forged := newBanSigner("license"), newBanSigner("forged")
	notice := func(by banSigner, revision uint64, state string, until *int64) []byte {
		encoded, err := contract.SignNotice(ctx, contract.BanNotice{Schema: contract.NoticeSchema, InstallationID: banInstallation,
			CustomerID: banCustomer, BanID: banID, Revision: revision, State: state, ReasonCode: "abuse", ReasonText: "滥用",
			StartsAt: now.Unix(), Until: until, IssuedAt: now.Unix()}, by)
		check("ban-sign-notice", err == nil, "%v", err)
		return encoded
	}
	ticket := func(revision uint64, issued time.Time, validity time.Duration) []byte {
		encoded, err := contract.SignTicket(ctx, contract.ServiceTicket{Schema: contract.TicketSchema, InstallationID: banInstallation,
			CustomerID: banCustomer, LicenseID: banLicense, Revision: revision, IssuedAt: issued.Unix(),
			NotAfter: issued.Add(validity).Unix()}, trusted)
		check("ban-sign-ticket", err == nil, "%v", err)
		return encoded
	}
	runtime, err := installationban.New(installationban.Config{Dir: filepath.Join(*state, "installation-ban"),
		InstallationID: banInstallation, Serving: banServing{h: h}, Now: func() time.Time { return clock },
		Keys: func() map[string]ed25519.PublicKey {
			return map[string]ed25519.PublicKey{trusted.KeyID(): trusted.private.Public().(ed25519.PublicKey)}
		}})
	if err == nil {
		err = runtime.Restore(ctx)
	}
	check("ban-runtime", err == nil, "%v", err)
	if err != nil {
		return
	}
	result := runtime.Apply(ctx, nil, ticket(1, now, contract.DefaultNodeOfflineTolerance))
	check("ban-ticket-serving", result.Applied && result.Status == contract.StatusServing, "%+v", result)
	// the node's cache files are kept while stopped (resuming serves from them)
	cacheRoot := filepath.Join(h.config.SharedRoot, "cache")
	warm := get(portPlain, "shop.d13.test", "/ban-cache.css")
	cached := cacheFiles(cacheRoot)
	check("ban-before-site", warm.status == 200, "status %d cache %q files %d", warm.status, warm.cache, cached)

	// banned until a time: every site 503 with the page and Retry-After; L4 refused
	until := now.Add(48 * time.Hour).Unix()
	result = runtime.Apply(ctx, notice(trusted, 2, contract.StateBanned, &until), nil)
	check("ban-applied", result.Applied && result.Status == contract.StatusBanned, "%+v", result)
	status, retryAfter, body := getHeader(portPlain, "shop.d13.test", "/index.html", "Retry-After")
	check("ban-http-503", status == http.StatusServiceUnavailable && strings.Contains(body, "服务已暂停") &&
		retryAfter == time.Unix(until, 0).UTC().Format(http.TimeFormat), "status %d retry-after %q body %q", status, retryAfter, body)
	status, _, _ = getHeader(portPlain, "unknown.d13.test", "/", "Retry-After")
	check("ban-unknown-host-503", status == http.StatusServiceUnavailable, "status %d", status)
	secure := getTLS(secureHost, "/ban", roots)
	check("ban-https-503-own-certificate", secure.status == http.StatusServiceUnavailable && secure.serial != 0 &&
		strings.Contains(secure.body, "服务已暂停"), "status %d serial %d %s", secure.status, secure.serial, secure.err)
	_, l4Err := tcpExchange(portL4TCP, "banned", nil)
	check("ban-l4-refused", l4Err != nil, "%v", l4Err)
	_, udpErr := udpExchange(portL4UDP, "banned")
	check("ban-l4-udp-refused", udpErr != nil, "%v", udpErr)

	// a forged lift is refused: still stopped
	result = runtime.Apply(ctx, notice(forged, 3, contract.StateLifted, nil), nil)
	status, _, _ = getHeader(portPlain, "shop.d13.test", "/index.html", "")
	check("ban-forged-lift-refused", !result.Applied && result.Reason == installationban.ReasonUntrusted &&
		status == http.StatusServiceUnavailable, "%+v status %d", result, status)

	// agent restart: a new runtime over the same state stops again
	restarted, err := installationban.New(installationban.Config{Dir: filepath.Join(*state, "installation-ban"),
		InstallationID: banInstallation, Serving: banServing{h: h}, Now: func() time.Time { return clock },
		Keys: func() map[string]ed25519.PublicKey {
			return map[string]ed25519.PublicKey{trusted.KeyID(): trusted.private.Public().(ed25519.PublicKey)}
		}})
	if err == nil {
		h.runtime.SetMaintenance(nil) // a new process: the node runtime forgot it
		err = restarted.Restore(ctx)
	}
	status, _, _ = getHeader(portPlain, "shop.d13.test", "/index.html", "")
	check("ban-restart-still-stopped", err == nil && restarted.Status() == contract.StatusBanned &&
		status == http.StatusServiceUnavailable, "%v status %d", err, status)
	runtime = restarted

	// lifted (higher revision) with a new ticket: the previous configuration
	result = runtime.Apply(ctx, notice(trusted, 3, contract.StateLifted, nil), ticket(4, now, contract.DefaultNodeOfflineTolerance))
	check("ban-lifted", result.Applied && result.Status == contract.StatusServing, "%+v", result)
	kept := cacheFiles(cacheRoot)
	back := get(portPlain, "shop.d13.test", "/ban-cache.css")
	check("ban-lifted-site-and-cache-kept", back.status == 200 && strings.Contains(back.body, "/ban-cache.css") && kept >= cached,
		"status %d cache %q files %d -> %d %s", back.status, back.cache, cached, kept, back.err)
	secure = getTLS(secureHost, "/after-ban", roots)
	check("ban-lifted-https", secure.status == 200, "status %d %s", secure.status, secure.err)
	got, err := tcpExchange(portL4TCP, "back", nil)
	check("ban-lifted-l4", err == nil && got == "tcp:back", "%q %v", got, err)

	// the ticket is not renewed within the offline tolerance (commercial expiry,
	// license service or control plane unreachable): frozen, existing HTTP,
	// HTTPS and L4 keep serving
	clock = now.Add(contract.DefaultNodeOfflineTolerance + time.Minute)
	status2, err := runtime.Tick(ctx)
	frozen := get(portPlain, "shop.d13.test", "/index.html")
	check("ban-ticket-expired-keeps-serving", err == nil && status2 == contract.StatusTicketExpired && runtime.Frozen() &&
		frozen.status == 200, "%s %v status %d", status2, err, frozen.status)
	secure = getTLS(secureHost, "/frozen", roots)
	check("ban-ticket-expired-https", secure.status == 200, "status %d %s", secure.status, secure.err)
	got, err = tcpExchange(portL4TCP, "frozen", nil)
	check("ban-ticket-expired-l4", err == nil && got == "tcp:frozen", "%q %v", got, err)
	result = runtime.Apply(ctx, nil, ticket(5, clock, contract.DefaultNodeOfflineTolerance))
	a := get(portPlain, "shop.d13.test", "/index.html")
	check("ban-ticket-renewed-unfreezes", result.Status == contract.StatusServing && !runtime.Frozen() && a.status == 200,
		"%+v status %d", result, a.status)

	// frozen, then a signed ban: only now traffic stops
	clock = clock.Add(contract.DefaultNodeOfflineTolerance + time.Minute)
	_, _ = runtime.Tick(ctx)
	result = runtime.Apply(ctx, notice(trusted, 6, contract.StateBanned, nil), nil)
	status, retryAfter, _ = getHeader(portPlain, "shop.d13.test", "/index.html", "Retry-After")
	check("ban-while-frozen-stops", result.Applied && result.Status == contract.StatusBanned &&
		status == http.StatusServiceUnavailable && retryAfter == "", "%+v status %d retry-after %q", result, status, retryAfter)
	result = runtime.Apply(ctx, notice(trusted, 7, contract.StateLifted, nil), ticket(8, clock, contract.DefaultNodeOfflineTolerance))
	a = get(portPlain, "shop.d13.test", "/index.html")
	check("ban-while-frozen-lifted-resumes", result.Status == contract.StatusServing && a.status == 200, "%+v status %d", result, a.status)
}
