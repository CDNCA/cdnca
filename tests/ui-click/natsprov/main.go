// natsprov creates the JetStream streams/consumers control-api expects, from the same
// JSON payloads scripts/local-stack.sh feeds nats-box (raw $JS.API requests).
// Usage: go run ./natsprov <nats-url> <stream.json|consumer.json>...
// A file with "stream_name" is a consumer request; otherwise a stream config.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/nats-io/nats.go"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: natsprov <nats-url> <json>...")
		os.Exit(2)
	}
	conn, err := nats.Connect(os.Args[1], nats.MaxReconnects(0))
	if err != nil {
		fail(err)
	}
	defer conn.Close()
	for _, file := range os.Args[2:] {
		payload, err := os.ReadFile(file)
		if err != nil {
			fail(err)
		}
		var probe struct {
			Name       string `json:"name"`
			StreamName string `json:"stream_name"`
			Config     struct {
				Durable string `json:"durable_name"`
			} `json:"config"`
		}
		if err := json.Unmarshal(payload, &probe); err != nil {
			fail(fmt.Errorf("%s: %w", file, err))
		}
		subject := "$JS.API.STREAM.CREATE." + probe.Name
		if probe.StreamName != "" {
			subject = "$JS.API.CONSUMER.CREATE." + probe.StreamName + "." + probe.Config.Durable
		}
		reply, err := conn.Request(subject, payload, 5*time.Second)
		if err != nil {
			fail(fmt.Errorf("%s: %w", subject, err))
		}
		var answer struct {
			Error *struct {
				Code int    `json:"err_code"`
				Desc string `json:"description"`
			} `json:"error"`
		}
		_ = json.Unmarshal(reply.Data, &answer)
		// 10058 stream name already in use: apply the file's config with STREAM.UPDATE.
		if answer.Error != nil && answer.Error.Code == 10058 && probe.StreamName == "" {
			subject = "$JS.API.STREAM.UPDATE." + probe.Name
			if reply, err = conn.Request(subject, payload, 5*time.Second); err != nil {
				fail(fmt.Errorf("%s: %w", subject, err))
			}
			answer.Error = nil
			_ = json.Unmarshal(reply.Data, &answer)
		}
		// 10148 consumer already exists: idempotent re-run.
		if answer.Error != nil && answer.Error.Code != 10058 && answer.Error.Code != 10148 {
			fail(fmt.Errorf("%s: %d %s", subject, answer.Error.Code, answer.Error.Desc))
		}
		fmt.Println("ok", subject)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "natsprov:", err)
	os.Exit(1)
}
