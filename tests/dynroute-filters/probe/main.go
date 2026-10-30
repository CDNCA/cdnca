// Command probe is the HTTP/2 and HTTP/3 client of the dynamic routing D9/D10
// acceptance (tests/dynroute-filters/run.sh): one request, JSON out.
// It is built in its own module with the HTTP/3 client pins of
// edge/openresty/http3/client (client.mod / client.sum).
//
//	probe -proto h2|h3 -url https://127.0.0.1:18443/path -host a.test
//	      [-method POST] [-body-bytes N] [-stream] [-header k:v]... [-full]
package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

type headers []string

func (h *headers) String() string     { return strings.Join(*h, ",") }
func (h *headers) Set(v string) error { *h = append(*h, v); return nil }

// hidden hides the length so the client streams the body without one.
type hidden struct{ io.Reader }

type result struct {
	Status  int               `json:"status"`
	Proto   string            `json:"proto"`
	Headers map[string]string `json:"headers"`
	BodyLen int               `json:"body_len"`
	BodySHA string            `json:"body_sha"`
	Body    string            `json:"body"`
	Reset   bool              `json:"reset"`
	Err     string            `json:"err,omitempty"`
	// -full (tests/edge-golden): every header value and the whole body
	HeaderValues map[string][]string `json:"header_values,omitempty"`
	BodyBase64   string              `json:"body_base64,omitempty"`
}

func main() {
	proto := flag.String("proto", "h2", "h2 | h3")
	target := flag.String("url", "", "https URL")
	host := flag.String("host", "", "Host / SNI")
	method := flag.String("method", "GET", "method")
	size := flag.Int("body-bytes", 0, "request body of this many 'x'")
	stream := flag.Bool("stream", false, "send the body without Content-Length")
	full := flag.Bool("full", false, "also emit every header value and the whole body (base64)")
	var extra headers
	flag.Var(&extra, "header", "request header k:v (repeatable)")
	flag.Parse()

	config := &tls.Config{ServerName: *host, InsecureSkipVerify: true} // the acceptance's own test certificates
	var transport http.RoundTripper
	switch *proto {
	case "h2":
		transport = &http2.Transport{TLSClientConfig: config, DisableCompression: true}
	case "h3":
		transport = &http3.Transport{TLSClientConfig: config, DisableCompression: true}
	default:
		fail(fmt.Errorf("unknown -proto %q", *proto))
	}
	var body io.Reader
	if *size > 0 {
		body = strings.NewReader(strings.Repeat("x", *size))
		if *stream {
			body = hidden{body}
		}
	}
	request, err := http.NewRequest(*method, *target, body)
	if err != nil {
		fail(err)
	}
	request.Host = *host
	if *size > 0 && *stream {
		request.ContentLength = -1
	}
	for _, header := range extra {
		name, value, _ := strings.Cut(header, ":")
		request.Header.Set(strings.TrimSpace(name), strings.TrimSpace(value))
	}
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	out := result{Headers: map[string]string{}}
	if err != nil {
		out.Err = err.Error()
		emit(out)
		return
	}
	defer response.Body.Close()
	raw, readErr := io.ReadAll(response.Body)
	sum := sha256.Sum256(raw)
	out.Status, out.Proto, out.BodyLen, out.BodySHA = response.StatusCode, response.Proto, len(raw), hex.EncodeToString(sum[:])
	out.Body = string(raw[:min(len(raw), 2048)])
	out.Reset = readErr != nil
	for name, values := range response.Header {
		out.Headers[strings.ToLower(name)] = strings.Join(values, ", ")
	}
	if *full {
		out.HeaderValues, out.BodyBase64 = response.Header, base64.StdEncoding.EncodeToString(raw)
	}
	emit(out)
}

func emit(value result) {
	encoded, _ := json.Marshal(value)
	fmt.Println(string(encoded))
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(2)
}
