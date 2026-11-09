package main

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"slices"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/certstore"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewayclient"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
)

// Per-node websites (SITE_SELECTION): one release carries a
// plain website and a TLS website of another line group. The node whose key
// document withholds them applies what gatewayclient selects: both answer
// as a host the node does not know (plain 421, TLS no handshake, like an
// unknown SNI), their certificate leaves the node's pool, and the node's
// other websites keep answering 200. The node that serves them gets 200.
const (
	selPlainHost   = "sel-plain.d13.test"
	selTLSHost     = "sel-tls.d13.test"
	selTLSVersion  = "0d130000-0000-4000-8000-0000000c0050"
	selUnknownHost = "sel-unknown.d13.test"
)

func checkSiteSelection(h *harness, ca *authority, store *certstore.Manager, roots *x509.CertPool, base ...edgesite.Site) {
	var plainKept, tlsKept string
	for _, site := range base {
		for _, listener := range site.Listeners {
			switch {
			case listener.TLS == nil && listener.Port == portPlain && plainKept == "":
				plainKept = site.Hosts.Primary
			case listener.TLS != nil && listener.Port == portTLS && tlsKept == "":
				tlsKept = site.Hosts.Primary
			}
		}
	}
	check("sitesel-fixture", plainKept != "" && tlsKept != "", "plain %q tls %q among %d websites", plainKept, tlsKept, len(base))
	plain := withCache(makeSite(50, selPlainHost, 1, portPlain), 64<<20)
	secure := withTLS(makeSite(51, selTLSHost, 1, portTLS), selTLSVersion, false)
	chain, key, _ := ca.issue(selTLSHost)
	if err := deliver(store, secure, selTLSVersion, chain, key); err != nil {
		check("sitesel-certificate-deliver", false, "%v", err)
	}
	root := append(slices.Clone(base), plain, secure)
	entries := make([]siteobject.BucketEntry, len(root))
	bySHA := map[string]edgesite.Site{}
	for index, site := range root {
		raw, err := edgesite.Encode(site)
		if err != nil {
			check("sitesel-encode", false, "%s: %v", site.Hosts.Primary, err)
			return
		}
		digest := edgesite.Digest(raw)
		entries[index] = siteobject.BucketEntry{SiteID: site.SiteID, Revision: site.Revision, SHA256: digest}
		bySHA[digest] = site
	}
	ids := make([]string, len(entries))
	for index, entry := range entries {
		ids[index] = entry.SiteID
	}
	selected := func(withheld ...string) []edgesite.Site {
		skip := map[string]bool{}
		for _, id := range withheld {
			skip[id] = true
		}
		digests, err := gatewayclient.SelectNodeSites(entries, siteobject.NewSiteBitmap(ids, skip))
		check("sitesel-select", err == nil, "%v", err)
		sites := make([]edgesite.Site, 0, len(digests))
		for _, digest := range digests {
			sites = append(sites, bySHA[digest])
		}
		return sites
	}
	pool := filepath.Join(h.config.StateRoot, "tls-pool", selTLSVersion+".crt")

	// the node of their line group serves them
	h.apply("sitesel-serving-apply", selected()...)
	a := get(portPlain, selPlainHost, "/sel")
	check("sitesel-serving-plain-200", a.status == 200, "%d %s", a.status, a.err)
	a = getTLS(selTLSHost, "/sel", roots)
	check("sitesel-serving-tls-200", a.status == 200, "%d %s", a.status, a.err)
	_, statErr := os.Stat(pool)
	check("sitesel-serving-certificate-pooled", statErr == nil, "%s: %v", pool, statErr)

	// the node of another line group: both withheld
	h.apply("sitesel-withheld-apply", selected(plain.SiteID, secure.SiteID)...)
	h.apply("sitesel-withheld-settle-apply", selected(plain.SiteID, secure.SiteID)...) // the pool keeps one previous generation
	unknown := get(portPlain, selUnknownHost, "/sel")
	a = get(portPlain, selPlainHost, "/sel")
	check("sitesel-withheld-plain-like-unknown", a.status == unknown.status && (a.status == 421 || a.status == 0),
		"withheld %d unknown host %d", a.status, unknown.status)
	unknownTLS := getTLS(selUnknownHost, "/sel", roots)
	a = getTLS(selTLSHost, "/sel", roots)
	check("sitesel-withheld-tls-like-unknown", a.status == unknownTLS.status && a.status != 200 && (a.err == "") == (unknownTLS.err == ""),
		"withheld %d %q unknown SNI %d %q", a.status, a.err, unknownTLS.status, unknownTLS.err)
	_, statErr = os.Stat(pool)
	check("sitesel-withheld-certificate-dropped", os.IsNotExist(statErr), "%s: %v", pool, statErr)
	a = get(portPlain, plainKept, "/sel")
	check("sitesel-other-plain-200", a.status == 200, "%s %d %s", plainKept, a.status, a.err)
	a = getTLS(tlsKept, "/sel", roots)
	check("sitesel-other-tls-200", a.status == 200, "%s %d %s", tlsKept, a.status, a.err)

	// back to the websites the parts that follow expect
	h.apply("sitesel-restore-apply", base...)
}
