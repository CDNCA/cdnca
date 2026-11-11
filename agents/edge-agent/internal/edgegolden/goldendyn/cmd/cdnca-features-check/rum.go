package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

const (
	rumTag    = "/.cdnca/rum/v1.js"
	rumHost   = "rum.feat.test"
	rumCache  = "rumc.feat.test"
	rumSource = "127.0.0.1"
)

var document = map[string]string{"Sec-Fetch-Dest": "document", "Accept": "text/html", "Accept-Encoding": "gzip"}

const beacon = `{"v":1,"p":"/page.html","n":"navigate","m":{"lcp":1200,"ttfb":80}}`

func rumRun(origin *originServer) {
	plain, cached := baseSite(1, rumHost), withCache(baseSite(2, rumCache))
	plain.RUM, cached.RUM = &edgeconfig.SiteRUM{SamplePercent: 100}, &edgeconfig.SiteRUM{SamplePercent: 100}
	n, err := start(*state+"/rum", []edgesite.Site{plain, cached}, true, nil, nil, "")
	if err != nil {
		check("RUM-start", false, "%v", err)
		return
	}
	defer n.stop()
	v := newVisitor(rumSource)

	// sampled document: tag injected, origin asked without Accept-Encoding
	r := v.get(rumHost, "/page.html", document)
	ae, _ := origin.seen("/page.html")
	check("RUM-inject", r.status == 200 && strings.Contains(r.body, `src="`+rumTag) && strings.Contains(r.body, "page.html-marker"), "status=%d", r.status)
	check("RUM-origin-no-ae", ae == "", "origin saw Accept-Encoding=%q", ae)
	// not a document navigation (Sec-Fetch-Dest: image): untouched, AE passes on
	r = v.get(rumHost, "/page.html", map[string]string{"Sec-Fetch-Dest": "image", "Accept-Encoding": "gzip"})
	ae, _ = origin.seen("/page.html")
	check("RUM-unsampled-intact", r.status == 200 && !strings.Contains(r.body, rumTag) && ae == "gzip", "status=%d ae=%q", r.status, ae)
	r = v.get(rumHost, "/plain.txt", document)
	check("RUM-text-intact", r.status == 200 && !strings.Contains(r.body, rumTag), "status=%d", r.status)
	r = v.get(rumHost, "/missing.html", document)
	check("RUM-404-intact", r.status == 404 && !strings.Contains(r.body, rumTag), "status=%d", r.status)
	// the script itself
	r = v.get(rumHost, rumTag, nil)
	etag := r.header.Get("ETag")
	check("RUM-script", r.status == 200 && strings.Contains(r.header.Get("Content-Type"), "javascript") && etag != "" && len(r.body) > 100, "status=%d len=%d", r.status, len(r.body))
	r = v.get(rumHost, rumTag, map[string]string{"If-None-Match": etag})
	check("RUM-script-304", r.status == 304, "status=%d", r.status)

	// cache: the stored object is the origin's bytes, the tag only on the way out
	first := v.get(rumCache, "/cached.html", document)
	second := v.get(rumCache, "/cached.html", document)
	_, hits := origin.seen("/cached.html")
	check("RUM-cache-hit", hits == 1 && first.status == 200 && second.status == 200, "origin hits=%d", hits)
	check("RUM-cache-served-tag", strings.Contains(first.body, rumTag) && strings.Contains(second.body, rumTag), "tag in responses")
	stored, tagged := cacheFiles(n.root)
	check("RUM-cache-raw-bytes", stored >= 1 && tagged == 0, "cache files with marker=%d with tag=%d", stored, tagged)

	collect(v, n)
	if log := n.errorLog(); strings.Contains(log, "[error]") || strings.Contains(log, "[crit]") {
		check("RUM-error-log", false, "%s", firstLine(log, "[error]"))
	}
}

func firstLine(text, needle string) string {
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, needle) {
			return line
		}
	}
	return ""
}

// cacheFiles counts cached objects holding the page marker and, of those,
// the ones that also hold the RUM tag.
func cacheFiles(root string) (stored, tagged int) {
	_ = filepath.Walk(filepath.Join(root, "shared", "cache"), func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || info.Size() > 1<<20 {
			return nil
		}
		raw, _ := os.ReadFile(path)
		if strings.Contains(string(raw), "cached.html-marker") {
			stored++
			if strings.Contains(string(raw), rumTag) {
				tagged++
			}
		}
		return nil
	})
	return
}

// collect: the beacon endpoint. It answers 204 either way; the finished
// minute (control socket) says what was recorded and what was dropped.
func collect(v *visitor, n *node) {
	send := func(c *visitor, body string, headers map[string]string) int {
		h := map[string]string{"Origin": "http://" + rumHost, "Content-Type": "text/plain"}
		for k, val := range headers {
			h[k] = val
		}
		return c.send("POST", rumHost, "/.cdnca/rum/collect", body, h).status
	}
	check("RUM-collect-get", v.get(rumHost, "/.cdnca/rum/collect", nil).status == 405, "GET refused with 405")
	// start inside a fresh minute: the per IP limit counts per minute
	if wait := 61 - time.Now().Second(); wait < 60 {
		time.Sleep(time.Duration(wait) * time.Second)
	}
	minute := time.Now().Unix() / 60 * 60
	for i := 0; i < 40; i++ {
		send(v, beacon, nil)
	}
	send(v, beacon, map[string]string{"Origin": "http://evil.example"})
	send(v, strings.Repeat("x", 4000), nil)
	send(v, `{"v":2}`, nil)
	other := newVisitor("127.0.0.9")
	send(other, beacon, nil)
	time.Sleep(time.Duration(61-time.Now().Second()) * time.Second)
	views, dropped := rumMinute(n, minute)
	check("RUM-collect-limit", views == 31, "recorded views=%d (30 from one address + 1 from another)", views)
	check("RUM-collect-refused", dropped >= 13, "dropped=%d (10 over the limit, wrong Origin, oversize, bad beacon)", dropped)
}

func rumMinute(n *node, minute int64) (views, dropped int64) {
	transport := &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
		return net.Dial("unix", filepath.Join(n.root, "run", "cdnca-site-admin.sock"))
	}}
	response, err := (&http.Client{Transport: transport, Timeout: 5 * time.Second}).Get("http://control/rum-minutes")
	if err != nil {
		check("RUM-minutes", false, "%v", err)
		return
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)
	var result struct {
		Minutes []struct {
			Minute  int64  `json:"minute"`
			SiteID  string `json:"site_id"`
			Dropped int64  `json:"dropped"`
			Series  []struct {
				Dimension string `json:"dimension"`
				Views     int64  `json:"views"`
			} `json:"series"`
		} `json:"minutes"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		check("RUM-minutes", false, "%v %.200s", err, raw)
		return
	}
	for _, m := range result.Minutes {
		if m.SiteID != siteID(1) || m.Minute != minute {
			continue
		}
		dropped += m.Dropped
		for _, s := range m.Series {
			if s.Dimension == "all" {
				views += s.Views
			}
		}
	}
	return
}
