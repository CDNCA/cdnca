// wafbodyprobe sends one request body over HTTP/1.1, HTTP/2 or HTTP/3 and
// prints "<status> <X-Seen header> <body>" on one line. With -stream the body
// length is hidden from the transport, so HTTP/1.1 uses chunked encoding and
// HTTP/2 / HTTP/3 send DATA frames without a Content-Length header: the case
// the WAF body inspection once skipped (scripts/security/waf-body-stream-smoke.sh).
// Built with edge/openresty/http3/client/client.mod (same dependencies).
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/quic-go/qpack"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/net/http2"
)

type hiddenLength struct{ io.Reader }

func main() {
	proto := flag.String("proto", "h2", "h1 | h2 | h3 | h3split")
	target := flag.String("url", "", "https URL")
	method := flag.String("method", "POST", "request method")
	body := flag.String("body", "", "request body")
	repeat := flag.Int("repeat", 1, "repeat the body this many times")
	pad := flag.Int("pad", 0, "prefix the body with a form field of this many bytes")
	contentType := flag.String("content-type", "application/x-www-form-urlencoded", "Content-Type")
	stream := flag.Bool("stream", false, "send the body without Content-Length")
	flag.Parse()

	if *proto == "h3split" {
		answer, err := splitUnknownFrame(*target, *body)
		if err != nil {
			fail(err)
		}
		fmt.Println(answer)
		return
	}
	payload := strings.Repeat(*body, *repeat)
	if *pad > 0 {
		payload = "pad=" + strings.Repeat("a", *pad) + "&" + payload
	}
	tlsConfig := &tls.Config{InsecureSkipVerify: true, ServerName: "waf.body.test"} // ephemeral self-signed smoke certificate
	var transport http.RoundTripper
	switch *proto {
	case "h1":
		transport = &http.Transport{TLSClientConfig: tlsConfig, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}}
	case "h2":
		transport = &http2.Transport{TLSClientConfig: tlsConfig}
	case "h3":
		transport = &http3.Transport{TLSClientConfig: tlsConfig}
	default:
		fail(fmt.Errorf("unknown proto %q", *proto))
	}
	var reader io.Reader = strings.NewReader(payload)
	if *stream {
		reader = hiddenLength{reader}
	}
	request, err := http.NewRequest(*method, *target, reader)
	if err != nil {
		fail(err)
	}
	if *stream {
		request.ContentLength = -1
	} else {
		request.ContentLength = int64(len(payload))
	}
	if payload == "" {
		request.Body, request.ContentLength = nil, 0
	}
	request.Header.Set("Content-Type", *contentType)
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		fail(err)
	}
	defer response.Body.Close()
	answer, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	text := ""
	if response.StatusCode == http.StatusOK {
		text = " " + strings.Join(strings.Fields(string(answer)), " ")
	}
	fmt.Printf("%d %s%s\n", response.StatusCode, response.Header.Get("X-Seen"), text)
}

// splitUnknownFrame reproduces CVE-2026-95101 on a raw HTTP/3 request stream:
// DATA "A=1", an unknown (reserved) frame whose payload arrives in two
// separate writes, then DATA "&B=2". A fixed server skips the whole unknown
// frame; an affected one passes the second part (inject) on as request body.
// Prints "<status> <response body>".
func splitUnknownFrame(rawURL, inject string) (string, error) {
	target, err := url.Parse(rawURL)
	if err != nil || inject == "" {
		return "", fmt.Errorf("invalid url or empty inject")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	tlsConfig := &tls.Config{InsecureSkipVerify: true, ServerName: "waf.body.test", NextProtos: []string{http3.NextProtoH3}} // smoke certificate
	conn, err := quic.DialAddr(ctx, target.Host, tlsConfig, &quic.Config{})
	if err != nil {
		return "", err
	}
	defer conn.CloseWithError(0, "")
	(&http3.Transport{}).NewClientConn(conn) // control stream + SETTINGS
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return "", err
	}
	var block bytes.Buffer
	encoder := qpack.NewEncoder(&block)
	for _, field := range [][2]string{{":method", "POST"}, {":scheme", "https"}, {":authority", "waf.body.test"},
		{":path", target.Path}, {"content-type", "text/plain"}} {
		if err := encoder.WriteField(qpack.HeaderField{Name: field[0], Value: field[1]}); err != nil {
			return "", err
		}
	}
	frame := func(kind uint64, payload []byte) []byte {
		out := quicvarint.Append(quicvarint.Append(nil, kind), uint64(len(payload)))
		return append(out, payload...)
	}
	const unknown = 0x21 // reserved (grease) frame type
	lead := strings.Repeat("X", 8)
	first := append(frame(0x01, block.Bytes()), frame(0x00, []byte("A=1"))...)
	first = append(first, quicvarint.Append(quicvarint.Append(nil, unknown), uint64(len(lead)+len(inject)))...)
	first = append(first, lead...)
	for _, part := range [][]byte{first, []byte(inject), frame(0x00, []byte("&B=2"))} {
		if _, err := stream.Write(part); err != nil {
			return "", err
		}
		time.Sleep(300 * time.Millisecond) // separate packets, so the parser sees the frame split
	}
	if err := stream.Close(); err != nil {
		return "", err
	}
	status, answer := "", []byte(nil)
	reader := quicvarint.NewReader(stream)
	for {
		kind, err := quicvarint.Read(reader)
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		length, err := quicvarint.Read(reader)
		if err != nil || length > 1<<20 {
			return "", fmt.Errorf("bad frame length")
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(reader, payload); err != nil {
			return "", err
		}
		switch kind {
		case 0x01:
			fields, err := qpack.NewDecoder(nil).DecodeFull(payload)
			if err != nil {
				return "", err
			}
			for _, field := range fields {
				if field.Name == ":status" {
					status = field.Value
				}
			}
		case 0x00:
			answer = append(answer, payload...)
		}
	}
	return status + " " + strings.Join(strings.Fields(string(answer)), " "), nil
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "wafbodyprobe:", err)
	os.Exit(1)
}
