// bench: fixed-count HTTP latency probe for the ADR 0017 PoC (not product
// code). Prints status counts and p50/p99/max latency.
//
//	bench -url http://127.0.0.1:8080/p/x -n 20000 -c 16
package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"
)

func main() {
	url := flag.String("url", "", "target")
	total := flag.Int("n", 10000, "requests")
	workers := flag.Int("c", 8, "concurrency")
	flag.Parse()
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{MaxIdleConnsPerHost: *workers}}
	latencies := make([]time.Duration, *total)
	statuses := make([]string, *total)
	var next int
	var mu sync.Mutex
	var wg sync.WaitGroup
	started := time.Now()
	for range *workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				mu.Lock()
				index := next
				next++
				mu.Unlock()
				if index >= *total {
					return
				}
				begin := time.Now()
				resp, err := client.Get(*url)
				latencies[index] = time.Since(begin)
				if err != nil {
					statuses[index] = "err"
					continue
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				statuses[index] = fmt.Sprintf("%d/%s", resp.StatusCode, resp.Header.Get("x-plugin"))
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(started)
	counts := map[string]int{}
	for _, status := range statuses {
		counts[status]++
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	pick := func(q float64) time.Duration { return latencies[int(q*float64(len(latencies)-1))] }
	fmt.Printf("n=%d c=%d rps=%.0f p50=%s p99=%s max=%s statuses=%v\n", *total, *workers,
		float64(*total)/elapsed.Seconds(), pick(0.5).Round(time.Microsecond), pick(0.99).Round(time.Microsecond),
		latencies[len(latencies)-1].Round(time.Microsecond), counts)
}
