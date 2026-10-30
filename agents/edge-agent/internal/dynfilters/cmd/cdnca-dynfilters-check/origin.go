package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const originPort = 19390

// bigBody is the bandwidth test object (400 KB).
const bigBody = 400_000

// The PoC §4 origin fixtures (tests/dynroute-poc/probe errorigin) plus the
// headers a replaced page must not leak, and a request echo.
func startOrigin() {
	headers := func(w http.ResponseWriter) {
		w.Header().Set("X-Origin-Header", "yes")
		w.Header().Set("ETag", `"origin-etag"`)
		w.Header().Set("Set-Cookie", "origin=1; Path=/")
		w.Header().Set("Content-Type", "text/plain")
	}
	plain := func(status int, body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			headers(w)
			w.Header().Set("Content-Length", fmt.Sprint(len(body)))
			w.WriteHeader(status)
			_, _ = io.WriteString(w, body)
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", plain(200, "origin-ok-body\n"))
	mux.HandleFunc("/404", plain(404, "origin-404-body\n"))
	mux.HandleFunc("/404empty", plain(404, ""))
	mux.HandleFunc("/403", plain(403, "origin-403-body\n"))
	mux.HandleFunc("/500", plain(500, "origin-500-body\n"))
	mux.HandleFunc("/502", plain(502, "origin-502-body\n"))
	mux.HandleFunc("/503", plain(503, "origin-503-body\n"))
	mux.HandleFunc("/410", plain(410, "origin-410-body-passthrough\n"))
	mux.HandleFunc("/404chunked", func(w http.ResponseWriter, r *http.Request) {
		headers(w)
		w.WriteHeader(404)
		_, _ = io.WriteString(w, "origin-404-chunk-1\n")
		w.(http.Flusher).Flush()
		time.Sleep(50 * time.Millisecond)
		_, _ = io.WriteString(w, "origin-404-chunk-2\n")
	})
	mux.HandleFunc("/404gzip", func(w http.ResponseWriter, r *http.Request) {
		var compressed bytes.Buffer
		zw := gzip.NewWriter(&compressed)
		_, _ = zw.Write([]byte(strings.Repeat("origin-404-gzip-body\n", 20)))
		_ = zw.Close()
		headers(w)
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Vary", "Accept-Encoding")
		w.Header().Set("Content-Length", fmt.Sprint(compressed.Len()))
		w.WriteHeader(404)
		_, _ = w.Write(compressed.Bytes())
	})
	raw := func(head, first string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			conn, buffered, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			_, _ = buffered.WriteString(head)
			if r.Method != http.MethodHead {
				_, _ = buffered.WriteString(first)
			}
			_ = buffered.Flush()
			time.Sleep(100 * time.Millisecond)
		}
	}
	mux.HandleFunc("/404partial", raw("HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nX-Origin-Header: yes\r\nContent-Length: 1000\r\n\r\n", "0123456789"))
	mux.HandleFunc("/200partial", raw("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 1000\r\n\r\n", "0123456789"))
	mux.HandleFunc("/404chunkcut", raw("HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n", "a\r\n0123456789\r\n"))
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(1500 * time.Millisecond)
		_, _ = io.WriteString(w, "late")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "origin %s %s %d", r.Host, r.URL.Path, len(body))
	})
	mux.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(bigBody))
		_, _ = w.Write(bytes.Repeat([]byte("b"), bigBody))
	})
	// Response rules: status ?s= (default 200) and headers
	// ?h=Name:Value (repeatable), cacheable for a minute.
	controlled := func(w http.ResponseWriter, r *http.Request) {
		status, _ := strconv.Atoi(r.URL.Query().Get("s"))
		if status == 0 {
			status = 200
		}
		for _, header := range r.URL.Query()["h"] {
			if name, value, ok := strings.Cut(header, ":"); ok {
				w.Header().Add(name, value)
			}
		}
		body := "resp-body " + r.URL.Path + "\n"
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Cache-Control", "max-age=60")
		w.Header().Set("X-Origin-Header", "yes")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
	mux.HandleFunc("/resp/", controlled)
	mux.HandleFunc("/cached/", controlled)
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", originPort))
	if err != nil {
		panic(err)
	}
	go func() { _ = http.Serve(listener, mux) }()
}
