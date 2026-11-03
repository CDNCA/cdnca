package main

// Range origin of the large-object runs (rangebase, chunk): deterministic
// bodies of any size (byte i of version v is patternByte(i, v)), Range served
// by net/http ServeContent, every response's bytes counted per path.
//   ?size=<bytes>   object size (default 1 MiB)
//   ?rate=<bytes/s> per-response send rate (0 = unthrottled)
//   /norange/...    ignores Range (always 200, whole object)
//   ?delay=<ms>     wait before the response (origin round trip)
//   /gzip/...       Content-Encoding: gzip (body unchanged, the edge must not cut it)
//   /noetag/...     no ETag (Last-Modified only)
//   /novalid/...    neither ETag nor Last-Modified
//   /grow/...       size + version MiB, validators of version 0 (only the length changes)
//   /e404/...       404
// The test sets a path's version (ETag "v<n>", Last-Modified per version);
// fail makes every response a 502.

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const rangeOriginAddress = "127.0.0.1:19802"

type rangeStats struct {
	Requests int
	Bytes    int64
	Ranges   []string
}

type rangeOrigin struct {
	mu       sync.Mutex
	stats    map[string]*rangeStats
	versions map[string]int
	active   atomic.Int64
	written  atomic.Int64
	fail     atomic.Bool
}

func startRangeOrigin() (*rangeOrigin, error) {
	o := &rangeOrigin{stats: map[string]*rangeStats{}, versions: map[string]int{}}
	listener, err := net.Listen("tcp", rangeOriginAddress)
	if err != nil {
		return nil, err
	}
	go func() { _ = http.Serve(listener, o) }()
	return o, nil
}

func patternByte(index int64, version int) byte {
	return byte(index ^ index>>11 ^ index>>19 ^ int64(version)*31)
}

type patternReader struct {
	size, position int64
	version        int
}

func (reader *patternReader) Read(buffer []byte) (int, error) {
	if reader.position >= reader.size {
		return 0, io.EOF
	}
	count := int64(len(buffer))
	if left := reader.size - reader.position; count > left {
		count = left
	}
	for index := int64(0); index < count; index++ {
		buffer[index] = patternByte(reader.position+index, reader.version)
	}
	reader.position += count
	return int(count), nil
}

func (reader *patternReader) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
		reader.position = offset
	case io.SeekCurrent:
		reader.position += offset
	case io.SeekEnd:
		reader.position = reader.size + offset
	}
	if reader.position < 0 {
		return 0, errors.New("negative position")
	}
	return reader.position, nil
}

// countingWriter counts the body bytes written and throttles them to rate.
type countingWriter struct {
	http.ResponseWriter
	origin *rangeOrigin
	stats  *rangeStats
	rate   int64
	start  time.Time
	sent   int64
}

func (writer *countingWriter) Write(data []byte) (int, error) {
	total := 0
	for len(data) > 0 {
		piece := data
		if len(piece) > 64<<10 {
			piece = piece[:64<<10]
		}
		if writer.rate > 0 {
			due := writer.start.Add(time.Duration(float64(writer.sent) / float64(writer.rate) * float64(time.Second)))
			if wait := time.Until(due); wait > 0 {
				time.Sleep(wait)
			}
		}
		count, err := writer.ResponseWriter.Write(piece)
		writer.sent += int64(count)
		writer.origin.written.Add(int64(count))
		writer.origin.mu.Lock()
		writer.stats.Bytes += int64(count)
		writer.origin.mu.Unlock()
		total += count
		if err != nil {
			return total, err
		}
		data = data[count:]
	}
	return total, nil
}

func (o *rangeOrigin) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	o.active.Add(1)
	defer o.active.Add(-1)
	path := request.URL.Path
	o.mu.Lock()
	stats := o.stats[path]
	if stats == nil {
		stats = &rangeStats{}
		o.stats[path] = stats
	}
	stats.Requests++
	stats.Ranges = append(stats.Ranges, request.Header.Get("Range"))
	version := o.versions[path]
	o.mu.Unlock()
	query := request.URL.Query()
	size, _ := strconv.ParseInt(query.Get("size"), 10, 64)
	if size <= 0 {
		size = 1 << 20
	}
	rate, _ := strconv.ParseInt(query.Get("rate"), 10, 64)
	if delay, _ := strconv.Atoi(query.Get("delay")); delay > 0 {
		time.Sleep(time.Duration(delay) * time.Millisecond)
	}
	if o.fail.Load() {
		writer.WriteHeader(http.StatusBadGateway)
		return
	}
	if strings.HasPrefix(path, "/e404/") {
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	if strings.HasPrefix(path, "/grow/") {
		size += int64(version) << 20
		version = 0
	}
	if strings.HasPrefix(path, "/norange/") {
		request.Header.Del("Range")
		request.Header.Del("If-Range")
	}
	if strings.HasPrefix(path, "/gzip/") {
		writer.Header().Set("Content-Encoding", "gzip")
	}
	writer.Header().Set("Content-Type", "application/octet-stream")
	modified := time.Date(2026, 1, 1, 0, 0, version, 0, time.UTC)
	switch {
	case strings.HasPrefix(path, "/novalid/"):
		modified = time.Time{}
	case strings.HasPrefix(path, "/noetag/"):
	default:
		writer.Header().Set("ETag", fmt.Sprintf(`"v%d"`, version))
	}
	counting := &countingWriter{ResponseWriter: writer, origin: o, stats: stats, rate: rate, start: time.Now()}
	http.ServeContent(counting, request, "", modified, &patternReader{size: size, version: version})
}

func (o *rangeOrigin) setVersion(path string, version int) {
	o.mu.Lock()
	o.versions[path] = version
	o.mu.Unlock()
}

func (o *rangeOrigin) of(path string) rangeStats {
	o.mu.Lock()
	defer o.mu.Unlock()
	if stats := o.stats[path]; stats != nil {
		copied := *stats
		copied.Ranges = append([]string(nil), stats.Ranges...)
		return copied
	}
	return rangeStats{}
}

// quiet waits until the origin has no response in flight and wrote nothing
// for 500 ms (the edge may keep filling the cache after the client is done).
func (o *rangeOrigin) quiet(limit time.Duration) {
	deadline := time.Now().Add(limit)
	last, stable := o.written.Load(), time.Now()
	for time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
		if now := o.written.Load(); now != last || o.active.Load() != 0 {
			last, stable = now, time.Now()
			continue
		}
		if time.Since(stable) >= 500*time.Millisecond {
			return
		}
	}
}

// patternMatches: body is bytes [start, start+len(body)) of the version.
func patternMatches(body string, start int64, version int) bool {
	for index := 0; index < len(body); index++ {
		if body[index] != patternByte(start+int64(index), version) {
			return false
		}
	}
	return true
}
