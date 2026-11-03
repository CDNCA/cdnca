package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

// chunkCorrectness: ADR 0021 goal 5. A response is one object version
// (ETag, Last-Modified and total length agree on every chunk; a disagreeing
// chunk ends the response and renews the chunks); If-Range, 416, an origin
// without Range and encoded or validator-less responses.
func chunkCorrectness(o *rangeOrigin, n *node, site edgesite.Site, c int64) {
	host := site.Hosts.Primary
	// mixed versions: chunk 0 cached as v0, the origin moves to v1 (same
	// TTL window); a whole download must never mix them
	for _, kind := range []struct{ name, prefix string }{
		{"ETAG", "/mix/"},             // nginx slice catches this one too
		{"LAST-MODIFIED", "/noetag/"}, // no ETag: only ADR 0021's check
		{"LENGTH", "/grow/"},          // same validators, longer object
	} {
		path := kind.prefix + "mixed.bin"
		uri := path + "?size=33554432"
		first := rangeGet(host, uri, rangeHeader(0, 9))
		o.quiet(30 * time.Second)
		o.setVersion(path, 1)
		broken := rangeGet(host, uri, nil)
		o.quiet(30 * time.Second)
		size, version := int64(32*mib), 1
		if kind.prefix == "/grow/" {
			size, version = 33*mib, 0
		}
		// what was sent of the broken response is the old version only
		sentOld := broken.err != nil && int64(len(broken.body)) < 32*mib && patternMatches(broken.body, 0, 0)
		retry := rangeGet(host, uri, nil)
		o.quiet(30 * time.Second)
		again := rangeGet(host, uri, nil)
		o.quiet(30 * time.Second)
		before := o.of(path)
		hit := rangeGet(host, uri, nil)
		requests, _ := delta(o, path, before)
		check("CHUNK-MIXED-VERSION-"+kind.name, first.part(0, 10, 0, 32*mib) && sentOld && retry.whole(size, version) &&
			again.whole(size, version) && hit.whole(size, version) && hit.cache == "HIT" && requests == 0,
			"first %v / broken %v err %v / retry %v / again %v / hit %v origin %d", first, broken, broken.err, retry, again, hit, requests)
	}

	// stale metadata: the origin changed, a Range of an uncached chunk gets
	// the new version, and so does a chunk cached before (new generation)
	path := "/mix/meta.bin"
	uri := path + "?size=33554432"
	rangeGet(host, uri, rangeHeader(0, 9))
	o.quiet(30 * time.Second)
	o.setVersion(path, 1)
	a := rangeGet(host, uri, rangeHeader(20*mib, 20*mib+9))
	o.quiet(30 * time.Second)
	b := rangeGet(host, uri, rangeHeader(0, 9))
	check("CHUNK-CHANGED-OBJECT-NEW-GENERATION", a.part(20*mib, 10, 1, 32*mib) && b.part(0, 10, 1, 32*mib), "%v / %v", a, b)

	// If-Range: matching -> the Range; stale -> the whole object
	path = "/ifr/a.bin"
	uri = path + "?size=8388608"
	rangeGet(host, uri, nil) // learns chunks
	rangeGet(host, uri, nil) // stores both
	o.quiet(30 * time.Second)
	before := o.of(path)
	match := rangeGet(host, uri, map[string]string{"Range": "bytes=5000000-5000099", "If-Range": `"v0"`})
	stale := rangeGet(host, uri, map[string]string{"Range": "bytes=5000000-5000099", "If-Range": `"v9"`})
	date := rangeGet(host, uri, map[string]string{"Range": "bytes=5000000-5000099",
		"If-Range": time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Format(http.TimeFormat)})
	oldDate := rangeGet(host, uri, map[string]string{"Range": "bytes=5000000-5000099",
		"If-Range": time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC).Format(http.TimeFormat)})
	requests, _ := delta(o, path, before)
	parts := []bool{match.part(5000000, 100, 0, 8*mib), stale.whole(8*mib, 0), date.part(5000000, 100, 0, 8*mib), oldDate.whole(8*mib, 0), requests == 0}
	check("CHUNK-IF-RANGE", !strings.Contains(fmt.Sprint(parts), "false"), "%v match %v etag %q / stale %v / date %v / old date %v origin %d",
		parts, match, match.etag, stale, date, oldDate, requests)

	// conditional requests on a chunked object: 304 (the origin's ETag is
	// hidden from nginx and put back by cdnca_cache before not_modified)
	inm := rangeGet(host, uri, map[string]string{"If-None-Match": `"v0"`})
	ims := rangeGet(host, uri, map[string]string{"If-Modified-Since": time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Format(http.TimeFormat)})
	changed := rangeGet(host, uri, map[string]string{"If-None-Match": `"v9"`})
	check("CHUNK-CONDITIONAL-304", inm.status == 304 && ims.status == 304 && changed.whole(8*mib, 0) && changed.etag == `"v0"`,
		"inm %v / ims %v / changed %v etag %q", inm, ims, changed, changed.etag)

	// 416: past the end, known and unknown objects; never cached
	for _, known := range []bool{true, false} {
		path = fmt.Sprintf("/416/%t.bin", known)
		uri = path + "?size=8388608"
		if known {
			rangeGet(host, uri, rangeHeader(0, 9))
			o.quiet(30 * time.Second)
		}
		before = o.of(path)
		a = rangeGet(host, uri, map[string]string{"Range": "bytes=99999999-"})
		b = rangeGet(host, uri, map[string]string{"Range": "bytes=99999999-"})
		after := rangeGet(host, uri, rangeHeader(8*mib-10, 8*mib-1))
		requests, _ = delta(o, path, before)
		check(fmt.Sprintf("CHUNK-416-KNOWN-%t", known), a.status == 416 && b.status == 416 && a.contentRange == "bytes */8388608" &&
			after.part(8*mib-10, 10, 0, 8*mib) && requests >= 2, "%v / %v / %v origin %d", a, b, after, requests)
	}

	// an origin without Range: the edge cuts the Range from the whole
	// object, which is then cached whole (not as chunks)
	path = "/norange/a.bin"
	uri = path + "?size=8388608"
	a = rangeGet(host, uri, rangeHeader(5*mib, 5*mib+99))
	b = rangeGet(host, uri, rangeHeader(6*mib, 6*mib+99))
	d := rangeGet(host, uri, rangeHeader(7*mib, 7*mib+99))
	requests, _ = delta(o, path, rangeStats{})
	check("CHUNK-ORIGIN-WITHOUT-RANGE", a.part(5*mib, 100, 0, 8*mib) && b.part(6*mib, 100, 0, 8*mib) && d.part(7*mib, 100, 0, 8*mib) &&
		d.cache == "HIT" && requests == 2, "%v / %v / %v origin %d", a, b, d, requests)

	// encoded and validator-less responses are not assembled from chunks:
	// stored whole (nginx answers an encoded whole object's Range with the
	// whole object, as before: no chunk node change)
	for _, prefix := range []string{"/gzip/", "/novalid/"} {
		path = prefix + "a.bin"
		uri = path + "?size=8388608"
		a = rangeGet(host, uri, rangeHeader(5*mib, 5*mib+99))
		b = rangeGet(host, uri, rangeHeader(6*mib, 6*mib+99))
		d = rangeGet(host, uri, rangeHeader(7*mib, 7*mib+99))
		ok := func(answer rangeAnswer, start int64) bool {
			return answer.part(start, 100, 0, 8*mib) || prefix == "/gzip/" && answer.whole(8*mib, 0)
		}
		requests, _ := delta(o, path, rangeStats{})
		keys := objectKeys(n, site, path)
		check("CHUNK-NOT-CHUNKED-"+prefix, ok(a, 5*mib) && ok(b, 6*mib) && ok(d, 7*mib) && d.cache == "HIT" && requests == 2 &&
			len(keys) == 1 && keys[0] == "?size=8388608|", "%v / %v / %v origin %d keys %v", a, b, d, requests, keys)
	}
}
