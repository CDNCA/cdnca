package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"
)

type origin struct {
	mu       sync.Mutex
	count    map[string]int
	delay    time.Duration
	status   int
	body     string
	version  int
	truncate bool
}

func main() {
	address := flag.String("listen", ":18090", "fixture listen address")
	flag.Parse()
	fixture := &origin{count: make(map[string]int), status: http.StatusOK, body: "version-1\n", version: 1}
	server := &http.Server{Addr: *address, Handler: fixture, ReadHeaderTimeout: 2 * time.Second}
	if err := server.ListenAndServe(); err != nil {
		panic(err)
	}
}

func (origin *origin) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	switch request.URL.Path {
	case "/control":
		origin.control(response, request)
	case "/counts":
		origin.mu.Lock()
		defer origin.mu.Unlock()
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(origin.count)
	default:
		origin.serveObject(response, request)
	}
}

func (origin *origin) control(response http.ResponseWriter, request *http.Request) {
	delay, err := strconv.Atoi(request.URL.Query().Get("delay_ms"))
	if err != nil || delay < 0 || delay > 30_000 {
		http.Error(response, "invalid delay", http.StatusBadRequest)
		return
	}
	status, err := strconv.Atoi(request.URL.Query().Get("status"))
	if err != nil || status < 100 || status > 599 {
		http.Error(response, "invalid status", http.StatusBadRequest)
		return
	}
	truncate := false
	if value := request.URL.Query().Get("truncate"); value != "" {
		truncate, err = strconv.ParseBool(value)
		if err != nil {
			http.Error(response, "invalid truncate", http.StatusBadRequest)
			return
		}
	}
	origin.mu.Lock()
	origin.delay = time.Duration(delay) * time.Millisecond
	origin.status = status
	origin.truncate = truncate
	if body := request.URL.Query().Get("body"); body != "" {
		origin.body = body + "\n"
		origin.version++
	}
	origin.mu.Unlock()
	response.WriteHeader(http.StatusNoContent)
}

func (origin *origin) serveObject(response http.ResponseWriter, request *http.Request) {
	origin.mu.Lock()
	origin.count[request.URL.Path]++
	delay, status, body, version, truncate := origin.delay, origin.status, origin.body, origin.version, origin.truncate
	origin.mu.Unlock()
	if headerDelay := request.Header.Get("X-CDNCA-Fixture-Delay-Milliseconds"); headerDelay != "" {
		milliseconds, err := strconv.Atoi(headerDelay)
		if err != nil || milliseconds < 0 || milliseconds > 30_000 {
			http.Error(response, "invalid fixture delay", http.StatusBadRequest)
			return
		}
		delay = time.Duration(milliseconds) * time.Millisecond
	}
	if delay > 0 {
		time.Sleep(delay)
	}
	noValidator := request.URL.Path == "/no-validator"
	switch request.URL.Path {
	case "/private":
		response.Header().Set("Cache-Control", "private, max-age=60")
	case "/no-store":
		response.Header().Set("Cache-Control", "no-store")
	case "/no-cache":
		response.Header().Set("Cache-Control", "no-cache")
	case "/cookie":
		response.Header().Set("Set-Cookie", "fixture=redacted; HttpOnly")
		response.Header().Set("Cache-Control", "public, max-age=60")
	case "/vary-star":
		response.Header().Set("Vary", "*")
		response.Header().Set("Cache-Control", "public, max-age=60")
	case "/vary-language":
		response.Header().Set("Vary", "Accept-Language")
		response.Header().Set("Cache-Control", "public, max-age=60")
		body = request.Header.Get("Accept-Language") + "\n"
	case "/spoof-internal-headers":
		response.Header().Set("Cache-Control", "public, max-age=1")
		response.Header().Set("X-CDNCA-Cache-Reason", "origin-forged")
		response.Header().Set("X-CDNCA-Cache-State", "origin-forged")
	case "/reload-generation":
		response.Header().Set("Cache-Control", "public, max-age=60")
	case "/no-validator":
		response.Header().Set("Cache-Control", "public, max-age=1")
		response.Header()["Date"] = nil
	default:
		response.Header().Set("Cache-Control", "public, max-age=1")
	}
	if !noValidator {
		response.Header().Set("ETag", fmt.Sprintf("\"fixture-%d\"", version))
	}
	if truncate {
		response.Header().Set("Content-Length", strconv.Itoa(len(body)+128))
	}
	response.WriteHeader(status)
	if noValidator {
		response.(http.Flusher).Flush()
	}
	_, _ = response.Write([]byte(body))
}
