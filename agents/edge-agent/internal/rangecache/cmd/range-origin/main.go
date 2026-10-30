package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var fixedModTime = time.Unix(1_700_000_000, 0).UTC()

type origin struct {
	payload    []byte
	compressed []byte
	mu         sync.Mutex
	counts     map[string]int
}

func main() {
	listen := flag.String("listen", "0.0.0.0:18090", "listen address")
	fixture := flag.String("fixture", "", "fixed payload file")
	verifyMultipart := flag.String("verify-multipart", "", "multipart response file to verify")
	verifyContentType := flag.String("verify-content-type", "", "multipart response Content-Type")
	verifyRanges := flag.String("verify-ranges", "", "expected explicit byte ranges")
	flag.Parse()
	if *fixture == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: range-origin -fixture /data/payload.bin [-listen 0.0.0.0:18090]")
		os.Exit(2)
	}
	payload, err := os.ReadFile(*fixture)
	if err != nil || len(payload) < 1<<20 {
		fmt.Fprintf(os.Stderr, "read fixture: %v (size=%d)\n", err, len(payload))
		os.Exit(1)
	}
	if *verifyMultipart != "" {
		if err := verifyMultipartResponse(payload, *verifyMultipart, *verifyContentType, *verifyRanges); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	compressed, err := gzipBytes(payload)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	server := &http.Server{
		Addr: *listen, Handler: (&origin{payload: payload, compressed: compressed, counts: make(map[string]int)}).handler(),
		ReadHeaderTimeout: 2 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 10 * time.Second,
		MaxHeaderBytes: 16 << 10,
	}
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func (server *origin) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/counts", server.serveCounts)
	mux.HandleFunc("/payload", server.counted(server.servePayload))
	mux.HandleFunc("/vary", server.counted(server.serveVary))
	mux.HandleFunc("/changing", server.counted(server.serveChanging))
	mux.HandleFunc("/ignore", server.counted(server.serveIgnoredRange))
	mux.HandleFunc("/unknown", server.counted(server.serveUnknownLength))
	mux.HandleFunc("/encoded", server.counted(server.serveEncoded))
	mux.HandleFunc("/conflict", server.counted(server.serveConflictingRange))
	mux.HandleFunc("/bad-length", server.counted(server.serveConflictingLength))
	mux.HandleFunc("/large-header", server.counted(server.serveLargeHeader))
	mux.HandleFunc("/truncate", server.counted(server.serveTruncatedOnce))
	return mux
}

func (server *origin) serveVary(response http.ResponseWriter, request *http.Request) {
	payload := bytes.Clone(server.payload)
	language := request.Header.Get("Accept-Language")
	if language == "zh-CN" {
		payload[0] ^= 0xff
	}
	response.Header().Set("Vary", "Accept-Language")
	setValidators(response, `"vary-`+language+`"`)
	http.ServeContent(response, request, "vary.bin", fixedModTime, bytes.NewReader(payload))
}

func (server *origin) serveChanging(response http.ResponseWriter, request *http.Request) {
	server.mu.Lock()
	count := server.counts[request.URL.Path]
	server.mu.Unlock()
	payload := server.payload
	etag := `"changing-v1"`
	if count == 2 {
		payload = bytes.Clone(server.payload)
		payload[1<<16] ^= 0xff
		etag = `"changing-v2"`
	}
	setValidators(response, etag)
	http.ServeContent(response, request, "changing.bin", fixedModTime, bytes.NewReader(payload))
}

func (server *origin) counted(next http.HandlerFunc) http.HandlerFunc {
	return func(response http.ResponseWriter, request *http.Request) {
		server.mu.Lock()
		server.counts[request.URL.Path]++
		server.mu.Unlock()
		next(response, request)
	}
}

func (server *origin) serveCounts(response http.ResponseWriter, _ *http.Request) {
	server.mu.Lock()
	copy := make(map[string]int, len(server.counts))
	for path, count := range server.counts {
		copy[path] = count
	}
	server.mu.Unlock()
	response.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(response).Encode(copy)
}

func (server *origin) servePayload(response http.ResponseWriter, request *http.Request) {
	setValidators(response, `"range-v1"`)
	http.ServeContent(response, request, "payload.bin", fixedModTime, bytes.NewReader(server.payload))
}

func (server *origin) serveIgnoredRange(response http.ResponseWriter, request *http.Request) {
	setValidators(response, `"ignore-v1"`)
	response.Header().Set("Content-Type", "application/octet-stream")
	response.Header().Set("Content-Length", strconv.Itoa(len(server.payload)))
	response.WriteHeader(http.StatusOK)
	if request.Method != http.MethodHead {
		_, _ = response.Write(server.payload)
	}
}

func (server *origin) serveUnknownLength(response http.ResponseWriter, request *http.Request) {
	setValidators(response, `"unknown-v1"`)
	response.Header().Set("Content-Type", "application/octet-stream")
	response.WriteHeader(http.StatusOK)
	if flusher, ok := response.(http.Flusher); ok {
		flusher.Flush()
	}
	if request.Method != http.MethodHead {
		for offset := 0; offset < len(server.payload); offset += 8192 {
			end := offset + 8192
			if end > len(server.payload) {
				end = len(server.payload)
			}
			_, _ = response.Write(server.payload[offset:end])
		}
	}
}

func (server *origin) serveEncoded(response http.ResponseWriter, request *http.Request) {
	setValidators(response, `"encoded-v1"`)
	response.Header().Set("Content-Type", "application/octet-stream")
	response.Header().Set("Content-Encoding", "gzip")
	response.Header().Set("Content-Length", strconv.Itoa(len(server.compressed)))
	response.WriteHeader(http.StatusOK)
	if request.Method != http.MethodHead {
		_, _ = response.Write(server.compressed)
	}
}

func (server *origin) serveConflictingRange(response http.ResponseWriter, request *http.Request) {
	first, last := requestedRange(request.Header.Get("Range"), len(server.payload))
	body := server.payload[first : last+1]
	connection, buffer, err := response.(http.Hijacker).Hijack()
	if err != nil {
		http.Error(response, "hijack unavailable", http.StatusInternalServerError)
		return
	}
	defer connection.Close()
	fmt.Fprintf(buffer, "HTTP/1.1 206 Partial Content\r\n")
	fmt.Fprintf(buffer, "Content-Range: bytes %d-%d/%d\r\n", first, last, len(server.payload))
	fmt.Fprintf(buffer, "Content-Range: bytes %d-%d/%d\r\n", first+1, last, len(server.payload))
	fmt.Fprintf(buffer, "Content-Length: %d\r\nETag: \"conflict-v1\"\r\nConnection: close\r\n\r\n", len(body))
	_, _ = buffer.Write(body)
	_ = buffer.Flush()
}

func (server *origin) serveConflictingLength(response http.ResponseWriter, request *http.Request) {
	first, last := requestedRange(request.Header.Get("Range"), len(server.payload))
	body := server.payload[first : last+1]
	connection, buffer, err := response.(http.Hijacker).Hijack()
	if err != nil {
		http.Error(response, "hijack unavailable", http.StatusInternalServerError)
		return
	}
	defer connection.Close()
	fmt.Fprintf(buffer, "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes %d-%d/%d\r\n", first, last, len(server.payload))
	fmt.Fprintf(buffer, "Content-Length: %d\r\nETag: \"bad-length-v1\"\r\nConnection: close\r\n\r\n", len(body)+1)
	_, _ = buffer.Write(body)
	_ = buffer.Flush()
}

func (server *origin) serveLargeHeader(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("X-Oversized-Origin-Header", strings.Repeat("x", 9000))
	server.servePayload(response, request)
}

func (server *origin) serveTruncatedOnce(response http.ResponseWriter, request *http.Request) {
	server.mu.Lock()
	count := server.counts[request.URL.Path]
	server.mu.Unlock()
	if count > 1 {
		setValidators(response, `"truncate-v1"`)
		http.ServeContent(response, request, "truncate.bin", fixedModTime, bytes.NewReader(server.payload))
		return
	}
	first, last := requestedRange(request.Header.Get("Range"), len(server.payload))
	body := server.payload[first : last+1]
	connection, buffer, err := response.(http.Hijacker).Hijack()
	if err != nil {
		http.Error(response, "hijack unavailable", http.StatusInternalServerError)
		return
	}
	defer connection.Close()
	fmt.Fprintf(buffer, "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes %d-%d/%d\r\n", first, last, len(server.payload))
	fmt.Fprintf(buffer, "Content-Length: %d\r\nETag: \"truncate-v1\"\r\nConnection: close\r\n\r\n", len(body))
	_, _ = buffer.Write(body[:len(body)/2])
	_ = buffer.Flush()
}

func requestedRange(value string, size int) (int, int) {
	first, last := 0, size-1
	if _, err := fmt.Sscanf(value, "bytes=%d-%d", &first, &last); err != nil || first < 0 || first >= size {
		return 0, min(size-1, 65535)
	}
	if last < first || last >= size {
		last = size - 1
	}
	return first, last
}

func setValidators(response http.ResponseWriter, etag string) {
	response.Header().Set("ETag", etag)
	response.Header().Set("Last-Modified", fixedModTime.Format(http.TimeFormat))
	response.Header().Set("Content-Type", "application/octet-stream")
}

func verifyMultipartResponse(payload []byte, path, contentType, ranges string) error {
	mediaType, parameters, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "multipart/byteranges" || parameters["boundary"] == "" {
		return fmt.Errorf("invalid multipart Content-Type %q", contentType)
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	expected, err := explicitRanges(ranges, len(payload))
	if err != nil {
		return err
	}
	reader := multipart.NewReader(file, parameters["boundary"])
	for index, item := range expected {
		part, err := reader.NextPart()
		if err != nil {
			return fmt.Errorf("read multipart range %d: %w", index, err)
		}
		wantHeader := fmt.Sprintf("bytes %d-%d/%d", item[0], item[1], len(payload))
		if part.Header.Get("Content-Range") != wantHeader {
			return fmt.Errorf("multipart range %d Content-Range = %q, want %q", index, part.Header.Get("Content-Range"), wantHeader)
		}
		body, err := io.ReadAll(io.LimitReader(part, int64(item[1]-item[0]+2)))
		if err != nil || !bytes.Equal(body, payload[item[0]:item[1]+1]) {
			return fmt.Errorf("multipart range %d body mismatch", index)
		}
	}
	if _, err := reader.NextPart(); err != io.EOF {
		return fmt.Errorf("multipart response has unexpected trailing part: %v", err)
	}
	return nil
}

func explicitRanges(value string, size int) ([][2]int, error) {
	if !strings.HasPrefix(value, "bytes=") {
		return nil, errors.New("expected ranges must use bytes unit")
	}
	parts := strings.Split(strings.TrimPrefix(value, "bytes="), ",")
	result := make([][2]int, 0, len(parts))
	for _, part := range parts {
		var first, last int
		if _, err := fmt.Sscanf(strings.TrimSpace(part), "%d-%d", &first, &last); err != nil || first < 0 || last < first || last >= size {
			return nil, fmt.Errorf("invalid expected range %q", part)
		}
		result = append(result, [2]int{first, last})
	}
	return result, nil
}

func gzipBytes(payload []byte) ([]byte, error) {
	var builder bytes.Buffer
	writer := gzip.NewWriter(&builder)
	if _, err := writer.Write(payload); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return builder.Bytes(), nil
}
