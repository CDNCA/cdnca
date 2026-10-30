package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/waf"
)

const maxRequestLineBytes = 1 << 20

type requestInput struct {
	CaseID     string              `json:"case_id"`
	Host       string              `json:"host"`
	Port       uint16              `json:"port"`
	Method     string              `json:"method"`
	Path       string              `json:"path"`
	Query      map[string][]string `json:"query,omitempty"`
	Header     map[string][]string `json:"header,omitempty"`
	SourceAddr string              `json:"source_addr"`
	Now        string              `json:"now,omitempty"`
}

type decisionOutput struct {
	CaseID        string        `json:"case_id"`
	Action        waf.Action    `json:"action"`
	Reason        string        `json:"reason"`
	RuleID        string        `json:"rule_id,omitempty"`
	PolicyVersion uint64        `json:"policy_version"`
	Events        []eventOutput `json:"events"`
}

type eventOutput struct {
	Reason string `json:"reason"`
	RuleID string `json:"rule_id"`
}

func main() {
	inputPath := flag.String("input", "", "path to an uncompiled WAF policy")
	flag.Parse()
	if *inputPath == "" || flag.NArg() != 0 {
		fail(errors.New("-input is required and positional arguments are not accepted"))
	}
	raw, err := os.ReadFile(*inputPath)
	if err != nil {
		fail(fmt.Errorf("read policy: %w", err))
	}
	_, policy, err := waf.CompileJSON(raw)
	if err != nil {
		fail(err)
	}

	evaluator := &waf.Evaluator{}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), maxRequestLineBytes)
	encoder := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		input, err := decodeRequest(scanner.Bytes())
		if err != nil {
			fail(err)
		}
		address, err := netip.ParseAddr(input.SourceAddr)
		if err != nil {
			fail(fmt.Errorf("case %q source_addr: %w", input.CaseID, err))
		}
		now := time.Now()
		if input.Now != "" {
			now, err = time.Parse(time.RFC3339, input.Now)
			if err != nil || now.Format("2006-01-02T15:04:05Z") != input.Now {
				fail(fmt.Errorf("case %q now must be canonical RFC3339 UTC with second precision", input.CaseID))
			}
		}
		decision := evaluator.EvaluateAt(policy, waf.Request{
			Host: input.Host, Port: input.Port, Method: input.Method, Path: input.Path,
			Query: input.Query, Header: input.Header, SourceAddr: address,
		}, now)
		output := decisionOutput{
			CaseID: input.CaseID, Action: decision.Action, Reason: decision.Reason,
			RuleID: decision.RuleID, PolicyVersion: decision.Version,
			Events: make([]eventOutput, len(decision.Events)),
		}
		for index, event := range decision.Events {
			output.Events[index] = eventOutput{Reason: event.Reason, RuleID: event.RuleID}
		}
		if err := encoder.Encode(output); err != nil {
			fail(fmt.Errorf("encode decision: %w", err))
		}
	}
	if err := scanner.Err(); err != nil {
		fail(fmt.Errorf("read requests: %w", err))
	}
}

func decodeRequest(raw []byte) (requestInput, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var input requestInput
	if err := decoder.Decode(&input); err != nil {
		return requestInput{}, fmt.Errorf("decode request: %w", err)
	}
	if input.CaseID == "" {
		return requestInput{}, errors.New("case_id is required")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return requestInput{}, errors.New("request must contain exactly one JSON value")
	}
	return input, nil
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
