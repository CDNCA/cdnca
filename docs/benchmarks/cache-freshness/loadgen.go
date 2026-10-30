package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"
)

type configuration struct {
	baseURL     *url.URL
	host        string
	mode        string
	phase       string
	rounds      int
	concurrency int
	prepareWait time.Duration
	timeout     time.Duration
}

type observation struct {
	duration time.Duration
	status   int
	reason   string
	err      error
}

type benchmarkResult struct {
	Mode                string         `json:"mode"`
	Phase               string         `json:"phase"`
	Rounds              int            `json:"rounds"`
	Concurrency         int            `json:"concurrency"`
	PrepareRequests     int            `json:"prepare_requests"`
	Requests            int            `json:"requests"`
	Successful          int            `json:"successful"`
	Errors              int            `json:"errors"`
	ErrorRatio          float64        `json:"error_ratio"`
	P50Milliseconds     float64        `json:"p50_ms"`
	P95Milliseconds     float64        `json:"p95_ms"`
	P99Milliseconds     float64        `json:"p99_ms"`
	StaleRatio          float64        `json:"stale_ratio"`
	CoalescedCount      int            `json:"coalesced_count"`
	LockTimeoutFallback int            `json:"lock_timeout_fallback_count"`
	StatusCounts        map[string]int `json:"status_counts"`
	ReasonCounts        map[string]int `json:"reason_counts"`
}

func main() {
	rawURL := flag.String("url", "", "edge URL including benchmark path")
	host := flag.String("host", "cache.example.test", "HTTP Host header")
	mode := flag.String("mode", "", "baseline or enhancement")
	phase := flag.String("phase", "", "cold or stale")
	rounds := flag.Int("rounds", 8, "number of distinct cache keys")
	concurrency := flag.Int("concurrency", 32, "requests per cache key")
	prepareWait := flag.Duration("prepare-wait", 1300*time.Millisecond, "wait after stale fixtures are populated")
	timeout := flag.Duration("timeout", 5*time.Second, "per-request timeout")
	flag.Parse()

	parsedURL, err := url.Parse(*rawURL)
	if err != nil || parsedURL.Scheme != "http" || parsedURL.Host == "" || parsedURL.RawQuery != "" || parsedURL.Fragment != "" {
		fmt.Fprintln(os.Stderr, "-url must be an absolute HTTP URL without query or fragment")
		os.Exit(2)
	}
	if (*mode != "baseline" && *mode != "enhancement") || (*phase != "cold" && *phase != "stale") ||
		*rounds < 1 || *rounds > 100 || *concurrency < 1 || *concurrency > 512 || *prepareWait < 0 || *timeout <= 0 {
		fmt.Fprintln(os.Stderr, "invalid benchmark mode, phase, rounds, concurrency, or duration")
		os.Exit(2)
	}

	config := configuration{
		baseURL: parsedURL, host: *host, mode: *mode, phase: *phase,
		rounds: *rounds, concurrency: *concurrency, prepareWait: *prepareWait, timeout: *timeout,
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          config.concurrency + 8,
		MaxIdleConnsPerHost:   config.concurrency + 8,
		MaxConnsPerHost:       config.concurrency + 8,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: config.timeout,
		DisableCompression:    true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}

	prepareRequests := 0
	if config.phase == "stale" {
		for round := 0; round < config.rounds; round++ {
			observation := measureRequest(context.Background(), client, config, round)
			if observation.err != nil || observation.status != http.StatusOK {
				fmt.Fprintf(os.Stderr, "prepare round %d failed: status=%d error=%v\n", round, observation.status, observation.err)
				os.Exit(1)
			}
			prepareRequests++
		}
		time.Sleep(config.prepareWait)
	}

	observations := runBurst(context.Background(), client, config)
	result := summarize(config, prepareRequests, observations)
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(result); err != nil {
		fmt.Fprintf(os.Stderr, "encode benchmark result: %v\n", err)
		os.Exit(1)
	}
	if result.Errors != 0 || result.Successful != result.Requests {
		os.Exit(1)
	}
}

func runBurst(ctx context.Context, client *http.Client, config configuration) []observation {
	result := make([]observation, 0, config.rounds*config.concurrency)
	for round := 0; round < config.rounds; round++ {
		start := make(chan struct{})
		observations := make(chan observation, config.concurrency)
		var waitGroup sync.WaitGroup
		waitGroup.Add(config.concurrency)
		for requestIndex := 0; requestIndex < config.concurrency; requestIndex++ {
			go func() {
				defer waitGroup.Done()
				<-start
				observations <- measureRequest(ctx, client, config, round)
			}()
		}
		close(start)
		waitGroup.Wait()
		close(observations)
		for observation := range observations {
			result = append(result, observation)
		}
	}
	return result
}

func measureRequest(parent context.Context, client *http.Client, config configuration, round int) observation {
	requestURL := buildRequestURL(config, round)
	ctx, cancel := context.WithTimeout(parent, config.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return observation{err: err}
	}
	request.Host = config.host
	startedAt := time.Now()
	response, err := client.Do(request)
	duration := time.Since(startedAt)
	if err != nil {
		return observation{duration: duration, err: err}
	}
	_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
	closeErr := response.Body.Close()
	if readErr != nil {
		return observation{duration: duration, status: response.StatusCode, err: readErr}
	}
	if closeErr != nil {
		return observation{duration: duration, status: response.StatusCode, err: closeErr}
	}
	return observation{
		duration: duration,
		status:   response.StatusCode,
		reason:   response.Header.Get("X-CDNCA-Cache-Reason"),
	}
}

func buildRequestURL(config configuration, round int) string {
	requestURL := *config.baseURL
	query := requestURL.Query()
	query.Set("phase", config.phase)
	query.Set("round", strconv.Itoa(round))
	requestURL.RawQuery = query.Encode()
	return requestURL.String()
}

func summarize(config configuration, prepareRequests int, observations []observation) benchmarkResult {
	durations := make([]time.Duration, 0, len(observations))
	result := benchmarkResult{
		Mode: config.mode, Phase: config.phase, Rounds: config.rounds, Concurrency: config.concurrency,
		PrepareRequests: prepareRequests, Requests: len(observations),
		StatusCounts: make(map[string]int), ReasonCounts: make(map[string]int),
	}
	for _, observation := range observations {
		durations = append(durations, observation.duration)
		if observation.err != nil {
			result.Errors++
			continue
		}
		result.StatusCounts[strconv.Itoa(observation.status)]++
		if observation.status == http.StatusOK {
			result.Successful++
		}
		reason := observation.reason
		if reason == "" {
			reason = "missing"
		}
		result.ReasonCounts[reason]++
	}
	result.ErrorRatio = ratio(result.Requests-result.Successful, result.Requests)
	result.P50Milliseconds = latencyPercentile(durations, 0.50)
	result.P95Milliseconds = latencyPercentile(durations, 0.95)
	result.P99Milliseconds = latencyPercentile(durations, 0.99)
	result.StaleRatio = ratio(result.ReasonCounts["stale_served_revalidate"], result.Requests)
	result.CoalescedCount = result.ReasonCounts["coalesced_follower"]
	result.LockTimeoutFallback = result.ReasonCounts["coalesce_timeout_fallback"]
	return result
}

func latencyPercentile(values []time.Duration, quantile float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sort.Slice(values, func(left, right int) bool { return values[left] < values[right] })
	index := int(float64(len(values)-1) * quantile)
	return float64(values[index].Microseconds()) / 1000
}

func ratio(numerator, denominator int) float64 {
	if denominator == 0 {
		return 0
	}
	return float64(numerator) / float64(denominator)
}
